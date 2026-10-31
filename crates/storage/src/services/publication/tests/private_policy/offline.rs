//! Real SQLite original-ledger interleaving, atomic approval and durable consume.
use super::*;
use nestlink_identity::offline::{offline_consume_transcript, offline_draft_digest};
use nestlink_protocol::offline::{management::*, *};
use rusqlite::Connection;

#[test]
fn offline_distinct_accounts_cannot_approve_or_consume_the_other_endpoint() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let password = "offline-distinct-account-password";
    f.store
        .create_member(&f.creator, "offline-consumer", password)?;
    let vault = VaultKey::from_bytes([19; 32]);
    let dummy = hash_password("offline-distinct-dummy-password")?;
    let guest = f
        .store
        .login(
            "offline-consumer",
            password,
            None,
            now()? / 1000,
            &vault,
            &dummy,
        )?
        .principal;
    let space = &access.exposure.space_id;
    let revision = f.store.network_policy_snapshot(space, now()?)?.revision();
    let invitation = f.store.invite_to_space(
        &f.creator,
        space,
        SpaceInvitationRequest {
            expected_revision: revision,
            role: nestlink_protocol::network::SpaceRole::Member,
            target_account_id: Some(guest.account_id.clone()),
            expires_at_unix_ms: now()? + 60_000,
        },
        now()?,
    )?;
    f.store.accept_space_invitation(
        &guest,
        space,
        &invitation.invitation.invitation_id,
        SpaceInvitationAcceptance {
            token: invitation.token,
        },
        now()?,
    )?;
    let identity = InstallationIdentity::generate();
    let consumer = random_id();
    let challenge = f.store.enrollment_challenge(&guest, now()? / 1000)?;
    let mut registration = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: consumer.clone(),
            name: "separate account consumer".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["host".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    registration.signature =
        URL_SAFE_NO_PAD.encode(identity.sign_action(&f.store.registration_transcript(
            &guest,
            &registration,
            now()? / 1000,
        )?)?);
    f.store
        .register_device(&guest, registration, now()? / 1000)?;
    let revision = f.store.network_policy_snapshot(space, now()?)?.revision();
    f.store.join_space_device(
        &guest,
        space,
        SpaceDeviceJoin {
            expected_revision: revision,
            expected_membership_epoch: 0,
            installation_id: consumer.clone(),
        },
        now()?,
    )?;
    f.store.grant_private_service(
        &f.creator,
        &f.view.id,
        PrivateServiceAclUpdate {
            expected_exposure_revision: access.exposure.revision,
            subject: PrivateServiceSubject::Installation {
                installation_id: consumer.clone(),
            },
            expires_at_unix_ms: now()? + 30_000,
        },
        now()?,
    )?;
    f.store.set_offline_enabled(
        &f.creator,
        space,
        OfflineEnableUpdate {
            expected_revision: 0,
            enabled: true,
        },
        now()?,
    )?;
    assert!(
        f.store
            .set_offline_enabled(
                &guest,
                space,
                OfflineEnableUpdate {
                    expected_revision: 1,
                    enabled: false
                },
                now()?
            )
            .is_err()
    );
    let revision = f.store.network_policy_snapshot(space, now()?)?.revision();
    let view = f.store.create_offline_private_draft(
        &guest,
        space,
        OfflinePrivateDraftRequest {
            consumer_device_id: consumer,
            service_id: f.view.id.clone(),
            process_nonces: [[31; 32], [32; 32]],
            expected_policy_revision: revision,
            expected_service_revision: f.view.revision,
            expected_exposure_revision: access.exposure.revision,
            direct_transports: vec![OfflineDirectTransport::Quic],
            maximum_bytes: 4096,
            maximum_connections: 1,
            expires_at_ms: now()? + 20_000,
        },
        now()?,
    )?;
    assert_eq!(view.claims.members[0].account_id, guest.account_id);
    assert_eq!(view.claims.members[1].account_id, f.creator.account_id);
    let source = identity.sign_offline_endpoint_approval(
        &access.network.public_key(),
        &view.claims,
        0,
        view.draft_digest,
    )?;
    let target = f.host.sign_offline_endpoint_approval(
        &access.network.public_key(),
        &view.claims,
        1,
        view.draft_digest,
    )?;
    assert!(
        f.store
            .approve_offline_bundle(
                &f.creator,
                &access.network,
                space,
                &view.claims.bundle_id,
                source.clone(),
                now()?
            )
            .is_err()
    );
    assert!(
        f.store
            .approve_offline_bundle(
                &guest,
                &access.network,
                space,
                &view.claims.bundle_id,
                target.clone(),
                now()?
            )
            .is_err()
    );
    f.store.approve_offline_bundle(
        &guest,
        &access.network,
        space,
        &view.claims.bundle_id,
        source,
        now()?,
    )?;
    f.store.approve_offline_bundle(
        &f.creator,
        &access.network,
        space,
        &view.claims.bundle_id,
        target,
        now()?,
    )?;
    let challenge =
        f.store
            .offline_consume_challenge(&guest, space, &view.claims.bundle_id, 0, now()?)?;
    let request = OfflineConsumeRequest {
        endpoint: 0,
        draft_digest: view.draft_digest,
        process_nonce: view.claims.members[0].process_nonce,
        signature: identity.sign_action(&offline_consume_transcript(&view.claims, &challenge)?)?,
    };
    assert!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                space,
                &view.claims.bundle_id,
                request.clone(),
                now()?
            )
            .is_err()
    );
    assert!(
        f.store
            .consume_offline_bundle(&guest, space, &view.claims.bundle_id, request, now()?)?
            .consumed[0]
    );
    assert!(
        f.store
            .offline_consume_challenge(&guest, space, &view.claims.bundle_id, 1, now()?)
            .is_err()
    );
    ledgers(&mut f, 4096, 0)?;
    Ok(())
}

fn draft(f: &mut Fixture, access: &PrivateAccess, bytes: u64) -> Result<OfflineBundleView> {
    let space = &access.exposure.space_id;
    let policy = f.store.offline_policy(&f.creator, space, now()?)?;
    if !policy.enabled {
        f.store.set_offline_enabled(
            &f.creator,
            space,
            OfflineEnableUpdate {
                expected_revision: policy.revision,
                enabled: true,
            },
            now()?,
        )?;
    }
    let revision = f.store.network_policy_snapshot(space, now()?)?.revision();
    Ok(f.store.create_offline_private_draft(
        &f.creator,
        space,
        OfflinePrivateDraftRequest {
            consumer_device_id: access.consumer.clone(),
            service_id: f.view.id.clone(),
            process_nonces: [[21; 32], [22; 32]],
            expected_policy_revision: revision,
            expected_service_revision: f.view.revision,
            expected_exposure_revision: access.exposure.revision,
            direct_transports: vec![OfflineDirectTransport::Quic, OfflineDirectTransport::Tls],
            maximum_bytes: bytes,
            maximum_connections: 2,
            expires_at_ms: now()? + 20_000,
        },
        now()?,
    )?)
}
fn approve(
    f: &mut Fixture,
    access: &PrivateAccess,
    view: &OfflineBundleView,
    endpoint: u8,
) -> Result<OfflineBundleView> {
    let identity = if endpoint == 0 {
        &access.consumer_identity
    } else {
        &f.host
    };
    let approval = identity.sign_offline_endpoint_approval(
        &access.network.public_key(),
        &view.claims,
        endpoint,
        view.draft_digest,
    )?;
    Ok(f.store.approve_offline_bundle(
        &f.creator,
        &access.network,
        &view.claims.space_id,
        &view.claims.bundle_id,
        approval,
        now()?,
    )?)
}
fn issued(f: &mut Fixture, access: &PrivateAccess, bytes: u64) -> Result<OfflineBundleView> {
    let view = draft(f, access, bytes)?;
    approve(f, access, &view, 0)?;
    approve(f, access, &view, 1)
}
fn consume_request(
    f: &mut Fixture,
    access: &PrivateAccess,
    view: &OfflineBundleView,
) -> Result<OfflineConsumeRequest> {
    let challenge = f.store.offline_consume_challenge(
        &f.creator,
        &view.claims.space_id,
        &view.claims.bundle_id,
        0,
        now()?,
    )?;
    Ok(OfflineConsumeRequest {
        endpoint: 0,
        draft_digest: view.draft_digest,
        process_nonce: view.claims.members[0].process_nonce,
        signature: access
            .consumer_identity
            .sign_action(&offline_consume_transcript(&view.claims, &challenge)?)?,
    })
}

#[test]
fn offline_exact_both_approvals_charge_original_online_ledgers_without_refund() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = draft(&mut f, &access, 4096)?;
    assert_eq!(view.approved, [false, false]);
    assert!(view.signed.is_none());
    let first = approve(&mut f, &access, &view, 0)?;
    assert_eq!(first.approved, [true, false]);
    assert!(first.signed.is_none());
    ledgers(&mut f, 0, 0)?;
    let mut wrong = f.host.sign_offline_endpoint_approval(
        &access.network.public_key(),
        &view.claims,
        1,
        view.draft_digest,
    )?;
    wrong.draft_digest[0] ^= 1;
    assert!(
        f.store
            .approve_offline_bundle(
                &f.creator,
                &access.network,
                &view.claims.space_id,
                &view.claims.bundle_id,
                wrong,
                now()?
            )
            .is_err()
    );
    let complete = approve(&mut f, &access, &view, 1)?;
    assert!(complete.signed.is_some());
    ledgers(&mut f, 4096, 0)?;
    approve(&mut f, &access, &view, 1)?;
    ledgers(&mut f, 4096, 0)?;
    let mut body = request(&f, &access);
    body.maximum_bytes = access.exposure.private_maximum_bytes;
    let lease =
        f.store
            .issue_private_service(&f.creator, &f.view.id, body, &f.service_signer, now()?)?;
    let lease = verify_private_service_lease(&lease, &f.service_signer.public_key())?;
    let usage: ServiceUsageBudgetGrantClaims = decode_service_message(
        &lease.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?;
    assert_eq!(
        usage.byte_ceiling,
        access.exposure.private_maximum_bytes - 4096
    );
    f.store.revoke_offline_bundle(
        &f.creator,
        &view.claims.space_id,
        &view.claims.bundle_id,
        now()?,
    )?;
    ledgers(&mut f, 4096, usage.byte_ceiling)?;
    Ok(())
}

#[test]
fn offline_outstanding_online_promise_blocks_second_approval_without_partial_spend() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = draft(&mut f, &access, 1)?;
    approve(&mut f, &access, &view, 0)?;
    f.store.issue_private_service(
        &f.creator,
        &f.view.id,
        request(&f, &access),
        &f.service_signer,
        now()?,
    )?;
    assert!(approve(&mut f, &access, &view, 1).is_err());
    let current = f.store.offline_bundle(
        &f.creator,
        &view.claims.space_id,
        &view.claims.bundle_id,
        now()?,
    )?;
    assert_eq!(current.approved, [true, false]);
    assert!(current.signed.is_none());
    ledgers(&mut f, 0, access.exposure.private_maximum_bytes)?;
    Ok(())
}

#[test]
fn offline_failed_audit_rolls_back_both_approval_and_all_original_budget_debits() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = draft(&mut f, &access, 4096)?;
    approve(&mut f, &access, &view, 0)?;
    f.store.connection.execute_batch("CREATE TRIGGER offline_audit_failure BEFORE INSERT ON audit WHEN NEW.event='offline_endpoint_approved' BEGIN SELECT RAISE(ABORT,'offline audit unavailable'); END;")?;
    assert!(approve(&mut f, &access, &view, 1).is_err());
    f.store
        .connection
        .execute_batch("DROP TRIGGER offline_audit_failure")?;
    let current = f.store.offline_bundle(
        &f.creator,
        &view.claims.space_id,
        &view.claims.bundle_id,
        now()?,
    )?;
    assert_eq!(current.approved, [true, false]);
    assert!(current.signed.is_none());
    let count: u64 = f.store.connection.query_row(
        "SELECT count(*) FROM offline_service_reservations",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    approve(&mut f, &access, &view, 1)?;
    ledgers(&mut f, 4096, 0)?;
    Ok(())
}

#[test]
fn offline_consume_binds_exact_process_digest_and_device_then_burns_durably() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = issued(&mut f, &access, 4096)?;
    let body = consume_request(&mut f, &access, &view)?;
    let mut bad = body.clone();
    bad.process_nonce[0] ^= 1;
    assert!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                bad,
                now()?
            )
            .is_err()
    );
    let mut bad = body.clone();
    bad.draft_digest[0] ^= 1;
    assert!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                bad,
                now()?
            )
            .is_err()
    );
    let mut bad = body.clone();
    bad.signature[0] ^= 1;
    assert!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                bad,
                now()?
            )
            .is_err()
    );
    assert_eq!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                body.clone(),
                now()?
            )?
            .consumed,
        [true, false]
    );
    assert!(
        f.store
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                body.clone(),
                now()?
            )
            .is_err()
    );
    let snapshot = f.store.snapshot()?;
    let mut reopened = Store::from_snapshot(&snapshot, &f.store.deployment_id()?)?;
    assert!(
        reopened
            .consume_offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                body,
                now()?
            )
            .is_err()
    );
    ledgers(&mut f, 4096, 0)?;
    Ok(())
}

#[test]
fn offline_sqlite_two_connections_can_consume_original_endpoint_only_once() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = issued(&mut f, &access, 4096)?;
    let request = consume_request(&mut f, &access, &view)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("offline.sqlite3");
    std::fs::write(&path, f.store.snapshot()?.as_slice())?;
    let deployment = f.store.deployment_id()?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let mut store = Store::open_existing(&path, &deployment)?;
        let actor = f.creator.clone();
        let claims = view.claims.clone();
        let body = request.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .consume_offline_bundle(
                    &actor,
                    &claims.space_id,
                    &claims.bundle_id,
                    body,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as u64),
                )
                .is_ok()
        }));
    }
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap_or(false))
        .filter(|v| *v)
        .count();
    assert_eq!(successes, 1);
    let raw = Connection::open(&path)?;
    assert!(!raw.prepare("PRAGMA foreign_key_check")?.exists([])?);
    assert!(raw.query_row(
        "SELECT consumed0 FROM offline_bundles WHERE bundle_id=?1",
        [&view.claims.bundle_id],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}

#[test]
fn offline_recovery_applies_acl_revocation_and_cannot_revive_after_regrant() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = issued(&mut f, &access, 4096)?;
    let rule = f
        .store
        .private_service_policy(&f.creator, &f.view.id, now()?)?
        .rules[0]
        .rule_id
        .clone();
    f.store.revoke_private_service(
        &f.creator,
        &f.view.id,
        &rule,
        access.exposure.revision,
        now()?,
    )?;
    // No intermediate observation: a new rule cannot repair the old grant.
    f.store.grant_private_service(
        &f.creator,
        &f.view.id,
        PrivateServiceAclUpdate {
            expected_exposure_revision: access.exposure.revision,
            subject: PrivateServiceSubject::Installation {
                installation_id: access.consumer.clone(),
            },
            expires_at_unix_ms: now()? + 30_000,
        },
        now()?,
    )?;
    assert!(
        !f.store
            .offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                now()?
            )?
            .live
    );
    ledgers(&mut f, 4096, 0)?;
    Ok(())
}

#[test]
fn offline_restore_fence_and_administrator_disable_fail_closed_without_refund() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let view = draft(&mut f, &access, 4096)?;
    approve(&mut f, &access, &view, 0)?;
    f.store
        .connection
        .execute("UPDATE service_quota_settings SET restore_fenced=1", [])?;
    assert!(approve(&mut f, &access, &view, 1).is_err());
    f.store
        .connection
        .execute("UPDATE service_quota_settings SET restore_fenced=0", [])?;
    approve(&mut f, &access, &view, 1)?;
    let before = f
        .store
        .offline_policy(&f.creator, &view.claims.space_id, now()?)?;
    let after = f.store.set_offline_enabled(
        &f.creator,
        &view.claims.space_id,
        OfflineEnableUpdate {
            expected_revision: before.revision,
            enabled: false,
        },
        now()?,
    )?;
    assert!(after.highest_revocation_epoch > before.highest_revocation_epoch);
    assert!(
        !f.store
            .offline_bundle(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                now()?
            )?
            .live
    );
    assert!(
        f.store
            .offline_consume_challenge(
                &f.creator,
                &view.claims.space_id,
                &view.claims.bundle_id,
                0,
                now()?
            )
            .is_err()
    );
    ledgers(&mut f, 4096, 0)?;
    assert_eq!(
        offline_draft_digest(&view.authority_public_key, &view.claims)?,
        view.draft_digest
    );
    Ok(())
}
