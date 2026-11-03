use super::*;
use nestlink_identity::reconnection;
use nestlink_protocol::api::{ReconnectionChoice, ReconnectionSubmission};
use nestlink_storage::reconnection::ReconnectionReceipt;
use prost::Message;

fn advance(f: &mut Setup, nonce: u8) -> Result<ReconnectionReceipt> {
    let old = f
        .store
        .current_permit(&f.controller, &f.request, NOW / 1000)?;
    let choice = ReconnectionChoice {
        previous_permit_sha256: URL_SAFE_NO_PAD.encode(digest(&old.encode_to_vec())),
        connection_generation: old.connection_generation + 1,
        lease_sequence: old.lease_sequence + 1,
        nonce: URL_SAFE_NO_PAD.encode([nonce; 32]),
        network_recovery: None,
    };
    let submission = ReconnectionSubmission {
        controller_signature: URL_SAFE_NO_PAD.encode(f.controller_identity.sign_action(
            &reconnection::transcript(&old, &old.controller_device_id, &choice)?,
        )?),
        host_signature: URL_SAFE_NO_PAD.encode(f.host_identity.sign_action(
            &reconnection::transcript(&old, &old.host_device_id, &choice)?,
        )?),
        choice,
    };
    Ok(f.store
        .reconnect_permit_at_ms(&f.controller, &f.request, submission, NOW)?)
}
fn request(
    f: &Setup,
    parent: &NetworkRemotePathBundle,
    receipt: &ReconnectionReceipt,
) -> Result<NetworkRemotePathIssuance> {
    let hash = reconnection::direct_recovery_fingerprint(
        &parent.path.claims,
        &parent.connectivity.claims,
        [&parent.memberships[0].claims, &parent.memberships[1].claims],
    );
    Ok(NetworkRemotePathIssuance {
        space_id: f.space.clone(),
        request_id: f.request.clone(),
        request: NetworkRemotePathRequest {
            path_grant_id: reconnection::direct_recovery_id(
                &receipt.previous,
                &receipt.submission.choice,
                hash,
                1,
            )?,
            connectivity_grant_id: reconnection::direct_recovery_id(
                &receipt.previous,
                &receipt.submission.choice,
                hash,
                2,
            )?,
            controller_membership_grant_id: f.controller_member.clone(),
            host_membership_grant_id: f.host_member.clone(),
            expected_policy_epoch: parent.verified().claims().scope.policy_epoch,
            expires_at_unix_ms: parent.verified().claims().scope.expires_at_ms,
        },
    })
}
fn initial(f: &mut Setup) -> Result<NetworkRemotePathBundle> {
    let request = f.issuance();
    Ok(f.store
        .issue_network_remote_path(&f.controller, &f.signer, request, NOW)?)
}
fn issue(f: &mut Setup, issuance: NetworkRemotePathIssuance) -> Result<NetworkRemotePathBundle> {
    Ok(f.store
        .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?)
}

#[test]
fn direct_successor_is_bound_to_exact_dual_signed_receipt_and_lost_post_readback_is_immutable()
-> Result {
    let mut f = Setup::new(true)?;
    let old = initial(&mut f)?;
    let receipt = advance(&mut f, 21)?;
    let issuance = request(&f, &old, &receipt)?;
    let retry = request(&f, &old, &receipt)?;
    let id = issuance.request.path_grant_id.clone();
    let next = issue(&mut f, issuance)?;
    assert!(
        f.store
            .network_remote_path(
                &f.controller,
                &f.space,
                &old.verified().claims().scope.grant_id,
                NOW
            )
            .is_err()
    );
    assert_eq!(
        next.verified().claims().scope.expires_at_ms,
        old.verified().claims().scope.expires_at_ms
    );
    assert_ne!(
        next.verified().transport_group_id(),
        old.verified().transport_group_id()
    );
    let GrantClaims::Connectivity(connectivity) =
        GrantClaims::decode_canonical(&next.connectivity.claims)?
    else {
        return Err("connectivity".into());
    };
    assert_eq!(
        connectivity.business_grant_digest,
        digest(&receipt.next.encode_to_vec())
    );
    assert_eq!(
        receipt.next.connection_generation,
        receipt.previous.connection_generation + 1
    );
    assert_eq!(
        receipt.next.lease_sequence,
        receipt.previous.lease_sequence + 1
    );
    let before = f.store.audit_count()?;
    for actor in [&f.controller, &f.host, &f.controller] {
        let read = f.store.network_remote_path(actor, &f.space, &id, NOW)?;
        assert_eq!(read.path.claims, next.path.claims);
        assert_eq!(read.path.signature, next.path.signature);
        assert_eq!(read.connectivity.claims, next.connectivity.claims);
    }
    assert!(matches!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, retry, NOW),
        Err(StorageError::Conflict)
    ));
    assert_eq!(f.store.audit_count()?, before);
    f.store.revoke_network_remote_path(
        &f.host,
        &f.space,
        &old.verified().claims().scope.grant_id,
        NOW,
    )?;
    assert!(
        f.store
            .network_remote_path(&f.controller, &f.space, &id, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn direct_recovery_rejects_old_grant_same_scope_substitutions_changed_scope_and_expiry() -> Result {
    for fault in 0..8 {
        let mut f = Setup::new(true)?;
        let old = initial(&mut f)?;
        let receipt = advance(&mut f, 22)?;
        let mut issuance = request(&f, &old, &receipt)?;
        match fault {
            0 => issuance.request.path_grant_id = old.verified().claims().scope.grant_id.clone(),
            1 => issuance.request.path_grant_id = random_id(),
            2 => issuance.request.connectivity_grant_id = random_id(),
            3 => issuance.request.controller_membership_grant_id = f.host_member.clone(),
            4 => issuance.request.expected_policy_epoch += 1,
            5 => issuance.request.expires_at_unix_ms += 1,
            6 => issuance.space_id = random_id(),
            _ => f.store.revoke_network_remote_path(
                &f.host,
                &f.space,
                &old.verified().claims().scope.grant_id,
                NOW,
            )?,
        }
        assert!(
            f.store
                .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)
                .is_err(),
            "fault {fault}"
        );
    }
    Ok(())
}

#[test]
fn valid_same_scope_parent_cannot_replace_the_exact_withdrawn_parent_or_its_connectivity() -> Result
{
    let mut f = Setup::new(true)?;
    let first = initial(&mut f)?;
    let other = initial(&mut f)?;
    let receipt = advance(&mut f, 25)?;
    let mut mixed = request(&f, &first, &receipt)?;
    mixed.request.connectivity_grant_id =
        request(&f, &other, &receipt)?.request.connectivity_grant_id;
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, mixed, NOW)
            .is_err()
    );
    f.store.revoke_network_remote_path(
        &f.host,
        &f.space,
        &first.verified().claims().scope.grant_id,
        NOW,
    )?;
    let exact = request(&f, &first, &receipt)?;
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, exact, NOW)
            .is_err()
    );
    // Another live grant with identical members/expiry does not satisfy the
    // first grant's immutable IDs. It needs its own distinct derived child.
    let alternate = request(&f, &other, &receipt)?;
    issue(&mut f, alternate)?;
    Ok(())
}

#[test]
fn current_third_successor_stops_when_the_root_ancestor_is_withdrawn() -> Result {
    let mut f = Setup::new(true)?;
    let root = initial(&mut f)?;
    let root_id = root.verified().claims().scope.grant_id.clone();
    let mut parent = root;
    for generation in 1..=3 {
        let receipt = advance(&mut f, generation + 30)?;
        let issuance = request(&f, &parent, &receipt)?;
        parent = issue(&mut f, issuance)?;
    }
    let leaf = parent.verified().claims().scope.grant_id.clone();
    // There is no subsequent business transition to confound this refusal:
    // only withdrawal of the root changes between the two current leaf reads.
    f.store.network_remote_path(&f.host, &f.space, &leaf, NOW)?;
    f.store
        .revoke_network_remote_path(&f.host, &f.space, &root_id, NOW)?;
    assert!(
        f.store
            .network_remote_path(&f.controller, &f.space, &leaf, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn excessive_parent_candidates_fail_closed_before_unbounded_lineage_search() -> Result {
    let mut f = Setup::new(true)?;
    let parent = initial(&mut f)?;
    for _ in 0..64 {
        initial(&mut f)?;
    }
    let receipt = advance(&mut f, 26)?;
    let issuance = request(&f, &parent, &receipt)?;
    assert!(matches!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}

#[test]
fn repeated_direct_recovery_checks_every_ancestor_and_has_fixed_depth_and_original_expiry() -> Result
{
    let mut f = Setup::new(true)?;
    let root = initial(&mut f)?;
    let root_id = root.verified().claims().scope.grant_id.clone();
    let expires = root.verified().claims().scope.expires_at_ms;
    let mut parent = root;
    for generation in 1..=16 {
        let receipt = advance(&mut f, generation)?;
        let issuance = request(&f, &parent, &receipt)?;
        parent = issue(&mut f, issuance)?;
        assert_eq!(parent.verified().claims().scope.expires_at_ms, expires);
        f.store.network_remote_path(
            &f.host,
            &f.space,
            &parent.verified().claims().scope.grant_id,
            NOW,
        )?;
    }
    let leaf = parent.verified().claims().scope.grant_id.clone();
    assert!(
        f.store
            .network_remote_path(&f.host, &f.space, &leaf, expires)
            .is_err()
    );
    let receipt = advance(&mut f, 17)?;
    let issuance = request(&f, &parent, &receipt)?;
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)
            .is_err()
    );
    f.store
        .revoke_network_remote_path(&f.host, &f.space, &root_id, NOW)?;
    // The latest generation cannot issue another child after root withdrawal.
    let issuance = request(&f, &parent, &receipt)?;
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn direct_lineage_persists_after_reopen_and_revoked_ancestor_cannot_be_forgotten() -> Result {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("lineage.sqlite");
    let deployment = random_id();
    let mut store = Store::open(&path, &deployment)?;
    let vault = VaultKey::from_bytes([7; 32]);
    let dummy = hash_password("dummy-only-password")?;
    store.bootstrap_admin("Admin", PASSWORD)?;
    let controller = store
        .login("admin", PASSWORD, None, 1000, &vault, &dummy)?
        .principal;
    store.create_member(&controller, "member", PASSWORD)?;
    let host = store
        .login("member", PASSWORD, None, 1000, &vault, &dummy)?
        .principal;
    let mut f = Setup::with_actors(store, controller, host, true, true)?;
    let root = initial(&mut f)?;
    let receipt = advance(&mut f, 24)?;
    let issuance = request(&f, &root, &receipt)?;
    let next = issue(&mut f, issuance)?;
    let id = next.verified().claims().scope.grant_id.clone();
    drop(f.store);
    f.store = Store::open_existing(&path, &deployment)?;
    f.store.network_remote_path(&f.host, &f.space, &id, NOW)?;
    f.store.revoke_network_remote_path(
        &f.host,
        &f.space,
        &root.verified().claims().scope.grant_id,
        NOW,
    )?;
    drop(f.store);
    f.store = Store::open_existing(&path, &deployment)?;
    assert!(
        f.store
            .network_remote_path(&f.host, &f.space, &id, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "explicit GitHub-hosted schema-50 Store compatibility producer only"]
fn schema_fixture_role() -> Result {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    let directory = std::path::PathBuf::from(std::env::var("NESTLINK_DIRECT_SCHEMA_DIRECTORY")?);
    let deployment = std::env::var("NESTLINK_DIRECT_SCHEMA_DEPLOYMENT")?;
    assert!(directory.is_absolute());
    assert!(!directory.starts_with(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))));
    let database = directory.join("control.sqlite3");
    let vault = VaultKey::from_bytes([7; 32]);
    let dummy = hash_password("dummy-only-password")?;
    if std::env::var("NESTLINK_DIRECT_SCHEMA_MODE")? == "create" {
        assert!(!database.exists());
        let mut store = Store::open(&database, &deployment)?;
        store.bootstrap_admin("Admin", PASSWORD)?;
        let controller = store
            .login("admin", PASSWORD, None, 1000, &vault, &dummy)?
            .principal;
        store.create_member(&controller, "member", PASSWORD)?;
        let host = store
            .login("member", PASSWORD, None, 1000, &vault, &dummy)?
            .principal;
        let mut f = Setup::with_actors(store, controller, host, true, true)?;
        let root = initial(&mut f)?;
        let receipt = advance(&mut f, 29)?;
        let issuance = request(&f, &root, &receipt)?;
        let child = issue(&mut f, issuance)?;
        let metadata = serde_json::json!({"space":f.space,
            "root":root.verified().claims().scope.grant_id,
            "child":child.verified().claims().scope.grant_id});
        std::fs::write(
            directory.join("private-fixture.json"),
            serde_json::to_vec(&metadata)?,
        )?;
        drop(f.store);
    } else {
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("private-fixture.json"))?)?;
        let mut store = Store::open_existing(&database, &deployment)?;
        let controller = store
            .login("admin", PASSWORD, None, 1000, &vault, &dummy)?
            .principal;
        let space = metadata["space"].as_str().ok_or("space")?;
        let child = metadata["child"].as_str().ok_or("child")?;
        store.network_remote_path(&controller, space, child, NOW)?;
        store.revoke_network_remote_path(
            &controller,
            space,
            metadata["root"].as_str().ok_or("root")?,
            NOW,
        )?;
        assert!(
            store
                .network_remote_path(&controller, space, child, NOW)
                .is_err()
        );
    }
    Ok(())
}
