use nestlink_auth::random_id;
use nestlink_storage::{APPLICATION_ID, Store};
use rusqlite::{Connection, MAIN_DB};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn online_snapshot_contains_committed_wal_and_excludes_open_transactions() -> Result {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("control.sqlite3");
    let deployment = random_id();
    let mut store = Store::open(&path, &deployment)?;
    store.add_account(&random_id(), "first")?;
    let mut writer = Connection::open(&path)?;
    let tx = writer.transaction()?;
    tx.execute(
        "INSERT INTO accounts(id,name) VALUES(?1,'uncommitted')",
        [random_id()],
    )?;
    let bytes = store.snapshot()?;
    let restored = Store::from_snapshot(&bytes, &deployment)?;
    assert_eq!(restored.security_epoch()?, store.security_epoch()?);
    assert!(
        temporary
            .path()
            .join("control.sqlite3-wal")
            .metadata()?
            .len()
            > 0
    );
    let mut view = Connection::open_in_memory()?;
    view.deserialize_read_exact(MAIN_DB, &bytes[..], bytes.len(), true)?;
    assert_eq!(
        view.query_row("SELECT count(*) FROM accounts", [], |r| r.get::<_, u64>(0))?,
        1
    );
    tx.commit()?;
    let newer = store.snapshot()?;
    let mut view = Connection::open_in_memory()?;
    view.deserialize_read_exact(MAIN_DB, &newer[..], newer.len(), true)?;
    assert_eq!(
        view.query_row("SELECT count(*) FROM accounts", [], |r| r.get::<_, u64>(0))?,
        2
    );
    assert!(Store::from_snapshot(&bytes, &random_id()).is_err());
    assert!(Store::from_snapshot(&bytes[..bytes.len() / 2], &deployment).is_err());
    Ok(())
}

#[test]
fn snapshot_refuses_foreign_version_and_missing_existing_database() -> Result {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing.sqlite3");
    assert!(Store::open_existing(&missing, &random_id()).is_err());
    assert!(!missing.exists());
    std::fs::write(&missing, [])?;
    assert!(Store::open_existing(&missing, &random_id()).is_err());
    assert_eq!(missing.metadata()?.len(), 0);
    let foreign = Connection::open_in_memory()?;
    foreign.execute_batch("CREATE TABLE foreign_data(id INTEGER);")?;
    foreign.pragma_update(None, "application_id", APPLICATION_ID)?;
    foreign.pragma_update(None, "user_version", 99)?;
    let bytes = foreign.serialize(MAIN_DB)?;
    assert!(Store::from_snapshot(&bytes, &random_id()).is_err());
    Ok(())
}

#[test]
fn pre_fence_schema_twenty_snapshot_migrates_the_quota_restore_fence() -> Result {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("control.sqlite3");
    let deployment = random_id();
    drop(Store::open(&path, &deployment)?);

    // Model a development v20 database created before restore_fenced existed.
    let legacy = Connection::open(&path)?;
    legacy.execute_batch("DROP VIEW all_relay_capacity; DROP TABLE network_topology_changes; DROP TABLE network_topology_cursors; DROP TABLE network_topology_heads; DROP TABLE network_topology_publishers; DROP TABLE node_relay_attributes; DROP TABLE space_service_rules; DROP TABLE space_service_bindings; DROP TABLE network_space_audit; DROP TABLE network_space_invitations; DROP TABLE network_space_members; DROP TABLE network_spaces; DROP TABLE network_remote_relays; DROP TABLE network_remote_paths; DROP TABLE network_grant_revocations; DROP TABLE network_grants; DROP TABLE network_memberships; DROP TABLE network_authority_key_history; DROP TABLE network_authorities; DROP TABLE remote_media_scopes; DROP TABLE device_media_announcements; ALTER TABLE service_quota_settings DROP COLUMN restore_fenced; DROP TABLE browser_host_readiness; DROP TABLE management_refresh_receipts; DROP INDEX remote_pending_inbox;")?;
    legacy.pragma_update(None, "user_version", 20)?;
    drop(legacy);
    let old_snapshot = Store::snapshot_existing(&path, &deployment, 20)?;
    let restored = Store::from_snapshot(&old_snapshot, &deployment)?;
    let migrated = restored.snapshot()?;
    let mut probe = Connection::open_in_memory()?;
    probe.deserialize_read_exact(MAIN_DB, &migrated[..], migrated.len(), true)?;
    assert!(!probe.query_row(
        "SELECT restore_fenced FROM service_quota_settings WHERE singleton=1",
        [],
        |row| row.get::<_, bool>(0),
    )?);
    Ok(())
}

#[test]
fn version_five_migrates_to_empty_explicit_trust_without_reinterpreting_old_authority() -> Result {
    migrate_authorization_schema(5)
}
#[test]
fn version_six_migrates_without_enabling_remote_password_access() -> Result {
    migrate_authorization_schema(6)
}
#[test]
fn version_seven_preserves_audit_cursor_through_retention_migration() -> Result {
    migrate_authorization_schema(7)
}
#[test]
fn version_eight_marks_historical_actors_unknown_without_guessing_identity() -> Result {
    migrate_authorization_schema(8)
}
#[test]
fn version_nine_seeds_relay_limits_without_authorizing_forwarding() -> Result {
    migrate_authorization_schema(9)
}
#[test]
fn version_ten_adds_no_runtime_or_meter_authority() -> Result {
    migrate_authorization_schema(10)
}
#[test]
fn version_eleven_adds_no_relay_reservation_or_forwarding_authority() -> Result {
    migrate_authorization_schema(11)
}
#[test]
fn version_twelve_adds_no_node_address_authority() -> Result {
    migrate_authorization_schema(12)
}
#[test]
fn version_thirteen_adds_empty_reconnection_state_without_changing_consent() -> Result {
    migrate_authorization_schema(13)
}
#[test]
fn version_fourteen_adds_empty_close_receipts_without_releasing_promises() -> Result {
    migrate_authorization_schema(14)
}
#[test]
fn version_fifteen_adds_browser_endpoint_expiry_without_migrating_permanent_devices() -> Result {
    migrate_authorization_schema(15)
}
#[test]
fn version_sixteen_round_trips_current_browser_endpoint_expiry_schema() -> Result {
    migrate_authorization_schema(16)
}
#[test]
fn version_seventeen_adds_empty_service_registry_without_authorizing_targets() -> Result {
    migrate_authorization_schema(17)
}
fn migrate_authorization_schema(version: u32) -> Result {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(format!("version-{version}.sqlite3"));
    let deployment = random_id();
    let connection = Connection::open(&path)?;
    for sql in [
        include_str!("../migrations/001_initial.sql"),
        include_str!("../migrations/002_control.sql"),
        include_str!("../migrations/003_policy_scopes.sql"),
        include_str!("../migrations/004_signaling.sql"),
        include_str!("../migrations/005_data_nodes.sql"),
        include_str!("../migrations/006_device_trust.sql"),
        include_str!("../migrations/007_remote_password.sql"),
        include_str!("../migrations/008_audit_retention.sql"),
        include_str!("../migrations/009_audit_actor.sql"),
        include_str!("../migrations/010_relay_quotas.sql"),
        include_str!("../migrations/011_node_usage.sql"),
        include_str!("../migrations/012_relay_reservations.sql"),
        include_str!("../migrations/013_node_endpoints.sql"),
        include_str!("../migrations/014_reconnections.sql"),
        include_str!("../migrations/015_relay_close.sql"),
        include_str!("../migrations/016_browser_endpoint_expiry.sql"),
        include_str!("../migrations/017_managed_turn.sql"),
    ]
    .into_iter()
    .take(version as usize)
    {
        connection.execute_batch(sql)?;
    }
    connection.execute(
        "INSERT INTO deployment VALUES(1,?1,1,1,?2)",
        rusqlite::params![
            deployment,
            serde_json::to_string(&nestlink_policy::NetworkPolicy::default())?
        ],
    )?;
    connection.execute(
        "INSERT INTO accounts(id,name) VALUES(?1,'existing')",
        [random_id()],
    )?;
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.execute("INSERT INTO audit(sequence,event,resource_id,security_epoch,created_at) VALUES(5000,'old_metadata','deployment',1,1)",[])?;
    if version >= 8 {
        connection.execute("UPDATE audit_settings SET high_watermark=5000", [])?;
    }
    connection.pragma_update(None, "user_version", version)?;
    drop(connection);
    let mut store = Store::open_existing(&path, &deployment)?;
    let bytes = store.snapshot()?;
    let mut view = Connection::open_in_memory()?;
    view.deserialize_read_exact(MAIN_DB, &bytes[..], bytes.len(), true)?;
    assert_eq!(
        view.pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))?,
        nestlink_storage::SCHEMA_VERSION as u64
    );
    assert_eq!(
        view.query_row("SELECT count(*) FROM node_endpoints", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    for table in [
        "reconnection_offers",
        "reconnection_receipts",
        "relay_close_receipts",
        "services",
        "service_target_approvals",
        "service_approval_challenges",
    ] {
        assert_eq!(
            view.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))?,
            0
        );
    }
    assert_eq!(
        view.query_row("SELECT count(*) FROM relay_reservations", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        view.query_row("SELECT count(*) FROM node_runtimes", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        view.query_row("SELECT count(*) FROM trusted_devices", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        view.query_row("SELECT name FROM accounts", [], |r| r.get::<_, String>(0))?,
        "existing"
    );
    assert_eq!(
        view.query_row("SELECT count(*) FROM remote_passwords", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    Store::from_snapshot(&bytes, &deployment)?;
    assert_eq!(
        view.query_row("SELECT high_watermark FROM audit_settings", [], |r| r
            .get::<_, u64>(0))?,
        5000
    );
    assert_eq!(
        view.query_row(
            "SELECT actor_json FROM audit WHERE sequence=5000",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "{\"kind\":\"legacy\"}"
    );
    store.invalidate_after_restore()?;
    let bytes = store.snapshot()?;
    let mut current = Connection::open_in_memory()?;
    current.deserialize_read_exact(MAIN_DB, &bytes[..], bytes.len(), true)?;
    assert_eq!(
        current.query_row("SELECT max(sequence) FROM audit", [], |r| r
            .get::<_, u64>(0))?,
        5001
    );
    let actor: nestlink_protocol::api::AuditActor = serde_json::from_str(&current.query_row(
        "SELECT actor_json FROM audit WHERE sequence=5001",
        [],
        |r| r.get::<_, String>(0),
    )?)?;
    assert_eq!(actor, nestlink_protocol::api::AuditActor::LocalOperator);
    Ok(())
}
