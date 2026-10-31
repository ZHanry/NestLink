use super::*;

fn change(state: &NetworkAuthorityState) -> NetworkAuthorityChange {
    NetworkAuthorityChange {
        space_id: state.space_id.clone(),
        expected_revision: state.revision,
        expected_policy_epoch: state.policy_epoch,
    }
}

#[test]
fn managed_rotation_keeps_retired_keys_and_current_generation_across_restart() -> Result {
    let mut f = Fixture::new()?;
    let old_id = random_id();
    let old = f.issue(&old_id)?;
    let initial = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    assert_eq!(initial.signing_generation, 0);
    assert_eq!(
        f.signer.for_space_generation(&f.space, 0)?.public_key(),
        initial.public_key
    );
    let rotated =
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS)?;
    assert_eq!(
        (
            rotated.revision,
            rotated.policy_epoch,
            rotated.signing_generation
        ),
        (initial.revision + 1, initial.policy_epoch + 1, 1)
    );
    assert_ne!(rotated.public_key, initial.public_key);
    assert_ne!(
        f.signer.for_space_generation(&random_id(), 1)?.public_key(),
        rotated.public_key
    );
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &old, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .network_membership_grant(&f.admin, &f.space, &old_id, NOW_MS)
            .is_err()
    );
    let request = f.request(&random_id())?;
    assert!(
        f.store
            .issue_network_membership(&f.admin, &f.signer, request, NOW_MS)
            .is_err()
    );
    let current = f
        .store
        .network_authority_signer(&f.signer, &f.space, NOW_MS)?;
    let request = f.request(&random_id())?;
    let fresh = f
        .store
        .issue_network_membership(&f.admin, &current, request, NOW_MS)?;
    f.store
        .verify_network_membership(&f.space, &f.installation, &fresh, NOW_MS)?;
    let reused = f.request(&old_id)?;
    assert!(
        f.store
            .issue_network_membership(&f.admin, &current, reused, NOW_MS)
            .is_err()
    );
    for key in [
        initial.public_key,
        NetworkAuthoritySigner::from_master_seed(&[91; 32])?.public_key(),
    ] {
        assert!(matches!(
            f.store.configure_network_authority(
                &f.admin,
                NetworkAuthorityUpdate {
                    space_id: f.space.clone(),
                    expected_revision: rotated.revision,
                    public_key: key
                },
                NOW_MS
            ),
            Err(StorageError::Forbidden)
        ));
    }
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS),
        Err(StorageError::Conflict)
    ));
    let mut stale_epoch = change(&rotated);
    stale_epoch.expected_policy_epoch -= 1;
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.admin, &f.signer, stale_epoch, NOW_MS),
        Err(StorageError::Conflict)
    ));
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert_eq!(
        f.store
            .network_authority_signer(&f.signer, &f.space, NOW_MS)?
            .public_key(),
        rotated.public_key
    );
    let second = f
        .store
        .rotate_network_authority(&f.admin, &f.signer, change(&rotated), NOW_MS)?;
    assert_eq!(second.signing_generation, 2);
    assert_ne!(second.public_key, rotated.public_key);
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &fresh, NOW_MS)
            .is_err()
    );
    let probe = Connection::open(&f.path)?;
    let (count,retired):(u64,u64)=probe.query_row("SELECT count(*),sum(retired_at_ms IS NOT NULL) FROM network_authority_key_history WHERE space_id=?1",[&f.space],|r|Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!((count, retired), (3, 2));
    Ok(())
}

#[test]
fn external_key_configuration_cannot_reinstall_a_retired_key_with_a_current_revision() -> Result {
    let mut f = Fixture::new()?;
    let initial = f.snapshot()?;
    let next = NetworkAuthoritySigner::from_master_seed(&[94; 32])?;
    let update = f.store.configure_network_authority(
        &f.admin,
        NetworkAuthorityUpdate {
            space_id: f.space.clone(),
            expected_revision: initial.revision(),
            public_key: next.public_key(),
        },
        NOW_MS,
    )?;
    assert!(matches!(
        f.store.configure_network_authority(
            &f.admin,
            NetworkAuthorityUpdate {
                space_id: f.space.clone(),
                expected_revision: update.revision(),
                public_key: f.signer.public_key()
            },
            NOW_MS
        ),
        Err(StorageError::Forbidden)
    ));
    assert_eq!(
        f.snapshot()?.verification().authority_key,
        &next.public_key()
    );
    Ok(())
}

#[test]
fn policy_advance_and_permanent_revoke_never_reenable_credentials_or_authority() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.issue(&random_id())?;
    let initial = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    let advanced = f
        .store
        .advance_network_policy_epoch(&f.admin, change(&initial), NOW_MS)?;
    assert_eq!(advanced.policy_epoch(), initial.policy_epoch + 1);
    assert_eq!(advanced.verification().authority_key, &initial.public_key);
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)
            .is_err()
    );
    let fresh = f.issue(&random_id())?;
    let current = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    let revoked = f
        .store
        .revoke_network_authority(&f.admin, change(&current), NOW_MS)?;
    assert!(revoked.revoked);
    assert_eq!(
        (revoked.revision, revoked.policy_epoch),
        (current.revision + 1, current.policy_epoch + 1)
    );
    let repeat = f
        .store
        .revoke_network_authority(&f.admin, change(&revoked), NOW_MS)?;
    assert_eq!(
        (repeat.revision, repeat.policy_epoch),
        (revoked.revision, revoked.policy_epoch)
    );
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert!(
        f.store
            .network_authority_state(&f.admin, &f.space, NOW_MS)?
            .revoked
    );
    assert!(f.snapshot().is_err());
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &fresh, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .network_authority_signer(&f.signer, &f.space, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&revoked), NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .advance_network_policy_epoch(&f.admin, change(&revoked), NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .configure_network_authority(
                &f.admin,
                NetworkAuthorityUpdate {
                    space_id: f.space.clone(),
                    expected_revision: revoked.revision,
                    public_key: f.signer.public_key()
                },
                NOW_MS
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn authority_changes_recheck_admin_clock_root_and_atomic_audit_commit() -> Result {
    let mut f = Fixture::new()?;
    let initial = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.member, &f.signer, change(&initial), NOW_MS),
        Err(StorageError::Forbidden)
    ));
    assert!(matches!(
        f.store
            .revoke_network_authority(&f.member, change(&initial), NOW_MS),
        Err(StorageError::Forbidden)
    ));
    assert!(matches!(
        f.store
            .advance_network_policy_epoch(&f.member, change(&initial), NOW_MS),
        Err(StorageError::Forbidden)
    ));
    let wrong_root = NetworkAuthoritySigner::from_master_seed(&[99; 32])?;
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.admin, &wrong_root, change(&initial), NOW_MS),
        Err(StorageError::Forbidden)
    ));
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS - 1),
        Err(StorageError::Conflict)
    ));
    let probe = Connection::open(&f.path)?;
    probe.execute_batch("CREATE TRIGGER reject_authority_rotation BEFORE INSERT ON audit WHEN NEW.event='network_authority_rotated' BEGIN SELECT RAISE(ABORT,'injected audit commit failure'); END;")?;
    assert!(
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS)
            .is_err()
    );
    let unchanged = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    assert_eq!(
        (
            unchanged.revision,
            unchanged.policy_epoch,
            unchanged.public_key
        ),
        (initial.revision, initial.policy_epoch, initial.public_key)
    );
    let history:(u64,u64)=probe.query_row("SELECT count(*),sum(retired_at_ms IS NOT NULL) FROM network_authority_key_history WHERE space_id=?1",[&f.space],|r|Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!(history, (1, 0));
    probe.execute_batch("DROP TRIGGER reject_authority_rotation;")?;
    f.store
        .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS)?;
    assert!(f.signer.for_space_generation("invalid", 1).is_err());
    assert!(f.signer.for_space_generation(&f.space, u64::MAX).is_err());
    Ok(())
}

#[test]
fn schema_twenty_nine_upgrade_keeps_the_existing_authority_key_and_grant() -> Result {
    let mut f = Fixture::new()?;
    let grant = f.issue(&random_id())?;
    let initial = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    drop(f.store);
    let probe = Connection::open(&f.path)?;
    // Reconstruct the populated pre-lifecycle schema, retaining the original
    // authority, memberships, credentials and restore/security fences.
    probe.execute_batch(
        "DROP TABLE network_subnet_packet_bindings; DROP TABLE network_subnet_installations; ALTER TABLE network_packet_access DROP COLUMN subnet_binding_count; DROP TABLE network_subnet_mappings; DROP TABLE service_edge_group_ingress; DROP TABLE service_edge_groups; DROP INDEX service_definition_member_owner; DROP INDEX service_definition_owner; ALTER TABLE service_publications DROP COLUMN edge_group_id; ALTER TABLE service_publications DROP COLUMN edge_group_revision; CREATE UNIQUE INDEX service_definition_owner ON service_publications(service_id) WHERE state IN(0,1); DROP TABLE network_packet_access; DROP VIEW all_relay_capacity; DROP TABLE private_service_relay_hops; DROP TABLE private_service_usage_reports; DROP TABLE private_service_leases; DROP TABLE private_service_hosts; DROP TABLE private_service_acl; DROP TABLE service_exposures; DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; DROP TABLE network_remote_chain_topology_bindings; DROP TABLE network_topology_publisher_exports; DROP TABLE network_route_exports; DROP TABLE network_remote_route_set_members; DROP TABLE network_remote_route_sets;
         DROP TABLE network_remote_chain_hops;
         DROP TABLE network_remote_chains;
         CREATE VIEW all_relay_capacity AS
          SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
          UNION ALL
          SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays;
         DROP TABLE network_topology_changes;
         DROP TABLE network_topology_cursors;
         DROP TABLE network_topology_heads;
         DROP TABLE network_topology_publishers;
         DROP TABLE node_relay_attributes;
         DROP TABLE space_service_rules;
         DROP TABLE space_service_bindings;
         DROP TABLE network_authority_key_history;
         ALTER TABLE network_authorities DROP COLUMN signing_generation;
         ALTER TABLE network_authorities DROP COLUMN authority_revoked;
         PRAGMA user_version=29;",
    )?;
    drop(probe);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    let migrated = f
        .store
        .network_authority_state(&f.admin, &f.space, NOW_MS)?;
    assert_eq!(
        (
            migrated.public_key,
            migrated.revision,
            migrated.policy_epoch,
            migrated.signing_generation,
            migrated.revoked
        ),
        (
            initial.public_key,
            initial.revision,
            initial.policy_epoch,
            0,
            false
        )
    );
    f.store
        .verify_network_membership(&f.space, &f.installation, &grant, NOW_MS)?;
    let probe = Connection::open(&f.path)?;
    let history:(Vec<u8>,u64,u64,u64,Option<u64>)=probe.query_row("SELECT public_key,signing_generation,activated_policy_epoch,activated_at_ms,retired_at_ms FROM network_authority_key_history WHERE space_id=?1",[&f.space],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    assert_eq!(
        history,
        (
            initial.public_key.to_vec(),
            0,
            initial.policy_epoch,
            NOW_MS,
            None
        )
    );
    let rotated =
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&migrated), NOW_MS)?;
    assert_eq!(rotated.signing_generation, 1);
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &grant, NOW_MS)
            .is_err()
    );
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert_eq!(
        f.store
            .network_authority_signer(&f.signer, &f.space, NOW_MS)?
            .public_key(),
        rotated.public_key
    );
    assert!(matches!(
        f.store.configure_network_authority(
            &f.admin,
            NetworkAuthorityUpdate {
                space_id: f.space.clone(),
                expected_revision: rotated.revision,
                public_key: initial.public_key
            },
            NOW_MS
        ),
        Err(StorageError::Forbidden)
    ));
    Ok(())
}

#[test]
fn new_product_space_seeds_key_history_but_owner_cannot_manage_deployment_authority() -> Result {
    let mut f = Fixture::new()?;
    let created = f.store.create_space(
        &f.member,
        nestlink_protocol::spaces::SpaceCreateRequest {
            name: "Owned product space".into(),
        },
        f.signer.public_key(),
        NOW_MS,
    )?;
    let initial = f
        .store
        .network_authority_state(&f.admin, &created.space_id, NOW_MS)?;
    assert_eq!(
        (
            initial.revision,
            initial.policy_epoch,
            initial.signing_generation
        ),
        (1, 1, 0)
    );
    assert!(matches!(
        f.store
            .rotate_network_authority(&f.member, &f.signer, change(&initial), NOW_MS),
        Err(StorageError::Forbidden)
    ));
    let rotated =
        f.store
            .rotate_network_authority(&f.admin, &f.signer, change(&initial), NOW_MS)?;
    assert_ne!(initial.public_key, rotated.public_key);
    assert_eq!(
        f.store
            .network_policy_snapshot(&created.space_id, NOW_MS)?
            .verification()
            .authority_key,
        &rotated.public_key
    );
    assert_eq!(
        f.store
            .network_authority_state(&f.admin, &created.space_id, NOW_MS)?
            .signing_generation,
        1
    );
    let details = f
        .store
        .space_details(&f.member, &created.space_id, NOW_MS)?;
    assert_eq!(
        details.space.authority_public_key,
        URL_SAFE_NO_PAD.encode(rotated.public_key)
    );
    let revoked = f
        .store
        .revoke_network_authority(&f.admin, change(&rotated), NOW_MS)?;
    assert!(revoked.revoked);
    assert!(
        f.store
            .network_policy_snapshot(&created.space_id, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .space_details(&f.member, &created.space_id, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .network_authority_state(&f.admin, &created.space_id, NOW_MS)?
            .revoked
    );
    let probe = Connection::open(&f.path)?;
    let history:(u64,u64)=probe.query_row("SELECT count(*),sum(retired_at_ms IS NOT NULL) FROM network_authority_key_history WHERE space_id=?1",[&created.space_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!(history, (2, 2));
    Ok(())
}
