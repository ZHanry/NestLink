use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_storage::{StorageError, Store};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn schema_twenty_two_upgrade_preserves_existing_management_login() -> Result {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("control.sqlite3");
    let deployment = random_id();
    let vault = VaultKey::from_bytes([38; 32]);
    let dummy = hash_password("upgrade-dummy-password")?;
    let mut store = Store::open(&path, &deployment)?;
    let account = store.bootstrap_admin("owner", "upgrade-test-password")?;
    let login = store.login("owner", "upgrade-test-password", None, 1000, &vault, &dummy)?;
    drop(store);
    let old = rusqlite::Connection::open(&path)?;
    old.execute_batch("DROP TABLE offline_service_reservations; DROP TABLE offline_bundles; DROP TABLE offline_settings; DROP TABLE network_wireguard_bindings; DROP TABLE network_wireguard_clients; DROP TABLE network_subnet_packet_bindings; DROP TABLE network_subnet_installations; ALTER TABLE network_packet_access DROP COLUMN subnet_binding_count; DROP TABLE network_subnet_mappings; DROP TABLE service_edge_group_ingress; DROP TABLE service_edge_groups; DROP INDEX service_definition_member_owner; DROP INDEX service_definition_owner; ALTER TABLE service_publications DROP COLUMN edge_group_id; ALTER TABLE service_publications DROP COLUMN edge_group_revision; CREATE UNIQUE INDEX service_definition_owner ON service_publications(service_id) WHERE state IN(0,1);")?;
    old.execute_batch("DROP TABLE network_packet_access; DROP VIEW all_relay_capacity; DROP TABLE private_service_relay_hops; DROP TABLE private_service_usage_reports; DROP TABLE private_service_leases; DROP TABLE private_service_hosts; DROP TABLE private_service_acl; DROP TABLE service_exposures; DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; DROP TABLE network_remote_chain_topology_bindings; DROP TABLE network_topology_publisher_exports; DROP TABLE network_route_exports; DROP TABLE network_remote_route_set_members; DROP TABLE network_remote_route_sets; DROP TABLE network_remote_chain_hops; DROP TABLE network_remote_chains; DROP TABLE network_topology_changes; DROP TABLE network_topology_cursors; DROP TABLE network_topology_heads; DROP TABLE network_topology_publishers; DROP TABLE node_relay_attributes; DROP TABLE space_service_rules; DROP TABLE space_service_bindings; DROP TABLE network_space_audit; DROP TABLE network_space_invitations; DROP TABLE network_space_members; DROP TABLE network_spaces; DROP TABLE network_remote_relays; DROP TABLE network_remote_paths; DROP TABLE network_grant_revocations; DROP TABLE network_grants; DROP TABLE network_memberships; DROP TABLE network_authority_key_history; DROP TABLE network_authorities; DROP TABLE remote_media_scopes; DROP TABLE device_media_announcements; ALTER TABLE browser_host_readiness DROP COLUMN protocol_features; DROP TABLE management_refresh_receipts; DROP INDEX remote_pending_inbox; PRAGMA user_version=22;")?;
    drop(old);
    let mut upgraded = Store::open(&path, &deployment)?;
    assert_eq!(
        upgraded
            .authenticate(login.access_token.expose(), 1001)?
            .account_id,
        account
    );
    let rotated = upgraded.refresh_login_recoverable(
        login.refresh_token.expose(),
        login.generation,
        1001,
        &vault,
    )?;
    assert_eq!(rotated.principal.account_id, account);
    assert_eq!(rotated.generation, login.generation + 1);
    Ok(())
}

#[test]
fn lost_rotation_response_is_idempotent_but_never_extends_the_retry_window() -> Result {
    let mut store = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([37; 32]);
    let dummy = hash_password("dummy-test-password")?;
    store.bootstrap_admin("owner", "initial-test-password")?;
    let initial = store.login("owner", "initial-test-password", None, 1000, &vault, &dummy)?;
    // Access has expired, while the independent refresh qualification remains live.
    assert!(
        store
            .authenticate(initial.access_token.expose(), 1301)
            .is_err()
    );
    let rotated = store.refresh_login_recoverable(
        initial.refresh_token.expose(),
        initial.generation,
        1301,
        &vault,
    )?;
    let recovered = store.refresh_login_recoverable(
        initial.refresh_token.expose(),
        initial.generation,
        1329,
        &vault,
    )?;
    assert_eq!(
        rotated.access_token.expose(),
        recovered.access_token.expose()
    );
    assert_eq!(
        rotated.refresh_token.expose(),
        recovered.refresh_token.expose()
    );
    assert_eq!(rotated.refresh_expires, recovered.refresh_expires);
    assert_eq!(rotated.generation, recovered.generation);
    assert!(matches!(
        store.refresh_login_recoverable(
            initial.refresh_token.expose(),
            initial.generation,
            1331,
            &vault
        ),
        Err(StorageError::Unauthorized)
    ));
    let next = store.refresh_login_recoverable(
        rotated.refresh_token.expose(),
        rotated.generation,
        1332,
        &vault,
    )?;
    assert!(
        store
            .refresh_login_recoverable(
                initial.refresh_token.expose(),
                initial.generation,
                1333,
                &vault
            )
            .is_err()
    );
    store.logout(&next.principal)?;
    assert!(
        store
            .refresh_login_recoverable(
                rotated.refresh_token.expose(),
                rotated.generation,
                1333,
                &vault
            )
            .is_err()
    );
    assert!(
        store
            .refresh_login_recoverable(next.refresh_token.expose(), next.generation, 1333, &vault)
            .is_err()
    );
    Ok(())
}

#[test]
fn browser_restore_is_session_bound_and_concurrent_retry_reuses_the_same_grant() -> Result {
    let mut store = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([38; 32]);
    let dummy = hash_password("dummy-test-password")?;
    store.bootstrap_admin("owner", "initial-test-password")?;
    let initial = store.login("owner", "initial-test-password", None, 1000, &vault, &dummy)?;
    assert!(
        store
            .restore_browser_login(&random_id(), initial.refresh_token.expose(), 1001, &vault)
            .is_err()
    );
    let first = store.restore_browser_login(
        &initial.principal.session_id,
        initial.refresh_token.expose(),
        1001,
        &vault,
    )?;
    let retry = store.restore_browser_login(
        &initial.principal.session_id,
        initial.refresh_token.expose(),
        1002,
        &vault,
    )?;
    assert_eq!(first.generation, retry.generation);
    assert_eq!(first.refresh_token.expose(), retry.refresh_token.expose());
    assert!(
        store
            .restore_browser_login(
                &initial.principal.session_id,
                initial.refresh_token.expose(),
                1031,
                &vault
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn expired_inbox_and_signal_backlogs_make_bounded_forward_progress() -> Result {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("control.sqlite");
    let mut store = Store::open(&path, &random_id())?;
    let owner = random_id();
    let controller = random_id();
    let host = random_id();
    store.add_account(&owner, "owner")?;
    store.add_device(&controller, &owner, &[1; 32])?;
    store.add_device(&host, &owner, &[2; 32])?;
    let connection = rusqlite::Connection::open(&path)?;
    let actor = nestlink_storage::accounts::Principal {
        account_id: owner.clone(),
        session_id: random_id(),
        name: "owner".into(),
        is_admin: false,
        access_expires: 2000,
    };
    let tx = connection.unchecked_transaction()?;
    for index in 0..1530 {
        let id = random_id();
        let expires = if index < 1300 { 1000 } else { 1060 };
        tx.execute("INSERT INTO remote_requests(id,controller_device_id,host_device_id,controller_account_id,permissions_json,paths_json,request_json,capability_sha256,nonce,policy_revision,expires,status) VALUES(?1,?2,?3,?4,'[1]','[1]','{}',?5,?5,1,?6,'pending')", rusqlite::params![id,controller,host,owner,[0u8;32].as_slice(),expires])?;
        if index < 1300 {
            tx.execute(
                "INSERT INTO remote_signals VALUES(?1,?2,1,1,1,1,'{}')",
                rusqlite::params![id, controller],
            )?;
        }
    }
    tx.commit()?;
    let mut cursor = None;
    let mut found = std::collections::BTreeSet::new();
    loop {
        let page = store.pending_remote_page(&actor, 1000, cursor.as_deref())?;
        assert!(page.len() <= 100);
        if page.is_empty() {
            break;
        }
        for item in &page {
            assert!(found.insert(item.id.clone()));
            assert_eq!(item.expires_at_unix_ms, 1060000);
        }
        cursor = page.last().map(|item| item.id.clone());
    }
    assert_eq!(found.len(), 230);
    assert!(store.pending_remote(&actor, 1060)?.is_empty());
    for _ in 0..6 {
        assert!(store.cleanup_remote_signals(1000)? <= 256);
    }
    assert_eq!(
        connection.query_row("SELECT count(*) FROM remote_signals", [], |row| row
            .get::<_, u64>(0))?,
        0
    );
    Ok(())
}
