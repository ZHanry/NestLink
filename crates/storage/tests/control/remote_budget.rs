use super::*;
use nestlink_protocol::{Path, remote_budget::*};

fn enrolled(
    store: &mut Store,
    actor: &Principal,
    identity: &InstallationIdentity,
    supports: bool,
) -> Result<String> {
    let challenge = store.enrollment_challenge(actor, 1000)?;
    let mut capabilities = vec!["host".into(), "controller".into(), "vp8".into()];
    if supports {
        capabilities.push(CAPABILITY.into());
    }
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: "original remote budget".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities,
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    body.signature = URL_SAFE_NO_PAD
        .encode(identity.sign_action(&store.registration_transcript(actor, &body, 1000)?)?);
    let id = body.device.id.clone();
    store.register_device(actor, body, 1000)?;
    Ok(id)
}
fn approved(
    store: &mut Store,
    c: &Principal,
    h: &Principal,
    controller: &str,
    host: &str,
    identity: &InstallationIdentity,
) -> Result<String> {
    let request = store.create_remote(
        c,
        RemoteRequest {
            id: random_id(),
            controller_device_id: controller.into(),
            host_device_id: host.into(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1000,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![Path::Direct as i32],
    };
    let proof = store.approval_transcript(h, &request.id, &choice, 1001)?;
    store.approve_remote(
        h,
        &request.id,
        choice,
        &URL_SAFE_NO_PAD.encode(identity.sign_action(&proof)?),
        1001,
    )?;
    Ok(request.id)
}
#[test]
fn remote_budget_online_reservation_is_permanent_same_owner_across_reads_and_renewal() -> Result {
    let (mut store, _, _, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enrolled(&mut store, &admin, &controller, true)?;
    let h = enrolled(&mut store, &member, &host, true)?;
    let id = approved(&mut store, &admin, &member, &c, &h, &host)?;
    let first = store.initial_permit(&admin, &id, 1002)?;
    let budget = store
        .remote_usage_budget(&admin, &first, 1002)?
        .ok_or("missing original budget")?;
    assert_eq!(budget.maximum_bytes, ONLINE_PROMISE_BYTES);
    assert_eq!(budget.maximum_file_write_bytes, 0);
    let usage = store
        .remote_budget_quota(&admin, "account", &admin.account_id, 1002)?
        .ok_or("missing original ledger")?;
    assert_eq!(usage.promised_bytes, ONLINE_PROMISE_BYTES);
    for _ in 0..2 {
        let repeat = store.initial_permit(&admin, &id, 1003)?;
        assert_eq!(
            store.remote_usage_budget(&admin, &repeat, 1003)?,
            Some(budget.clone())
        );
    }
    let cp = store.renewal_transcript(&admin, &id, 2, false, 1004)?;
    let hp = store.renewal_transcript(&admin, &id, 2, true, 1004)?;
    let renewed = store.renew_permit(
        &admin,
        &id,
        RenewalSubmission {
            lease_sequence: 2,
            controller_signature: URL_SAFE_NO_PAD.encode(controller.sign_action(&cp)?),
            host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&hp)?),
        },
        1004,
    )?;
    assert_eq!(
        store.remote_usage_budget(&admin, &renewed, 1004)?,
        Some(budget)
    );
    store.revoke_remote(&member, &id)?;
    assert_eq!(
        store
            .remote_budget_quota(&admin, "account", &admin.account_id, 1004)?
            .ok_or("missing ledger")?,
        usage
    );
    assert!(store.remote_usage_budget(&admin, &renewed, 1004).is_err());
    Ok(())
}
#[test]
fn remote_budget_account_exhaustion_and_failed_issuance_are_atomic_and_restore_fenced() -> Result {
    let (mut store, _, _, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enrolled(&mut store, &admin, &controller, true)?;
    let h = enrolled(&mut store, &member, &host, true)?;
    store.set_remote_budget_quota(
        &admin,
        "account",
        &admin.account_id,
        RemoteBudgetQuotaUpdate {
            expected_revision: 0,
            maximum_bytes: ONLINE_PROMISE_BYTES,
            maximum_file_write_bytes: 0,
            maximum_connection_attempts: 64,
        },
        1001,
    )?;
    let id = approved(&mut store, &admin, &member, &c, &h, &host)?;
    store.initial_permit(&admin, &id, 1002)?;
    let second = approved(&mut store, &admin, &member, &c, &h, &host)?;
    assert!(matches!(
        store.initial_permit(&admin, &second, 1002),
        Err(StorageError::RateLimited)
    ));
    assert_eq!(store.remote(&admin, &second)?.lease_sequence, 0);
    assert!(
        store
            .remote_budget_quota(&admin, "resource", &second, 1002)?
            .is_none()
    );
    assert_eq!(
        store
            .remote_budget_quota(&admin, "device", &h, 1002)?
            .ok_or("missing host ledger")?
            .promised_bytes,
        ONLINE_PROMISE_BYTES
    );
    assert!(
        store
            .set_remote_budget_quota(
                &member,
                "account",
                &member.account_id,
                RemoteBudgetQuotaUpdate {
                    expected_revision: 0,
                    maximum_bytes: 1,
                    maximum_file_write_bytes: 0,
                    maximum_connection_attempts: 1
                },
                1002
            )
            .is_err()
    );
    store.invalidate_after_restore()?;
    assert!(store.initial_permit(&admin, &second, 1003).is_err());
    Ok(())
}
#[test]
fn remote_budget_requires_both_declared_native_endpoints() -> Result {
    for supports in [false, true] {
        let (mut store, _, _, admin, member) = fixture()?;
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let c = enrolled(&mut store, &admin, &controller, true)?;
        let h = enrolled(&mut store, &member, &host, supports)?;
        let id = approved(&mut store, &admin, &member, &c, &h, &host)?;
        let permit = store.initial_permit(&admin, &id, 1002)?;
        assert_eq!(
            store.remote_usage_budget(&admin, &permit, 1002)?.is_some(),
            supports
        );
    }
    Ok(())
}

struct OfflineSetup {
    store: Store,
    controller: Principal,
    host: Principal,
    identities: [InstallationIdentity; 2],
    processes: [nestlink_identity::offline::OfflineProcess; 2],
    signer: nestlink_identity::network::NetworkAuthoritySigner,
    space: String,
    draft: nestlink_protocol::offline::management::OfflineBundleView,
}
impl OfflineSetup {
    fn new() -> Result<Self> {
        use nestlink_protocol::{
            api::{TrustChoice, TrustSubmission},
            network::SpaceRole,
            offline::{management::*, *},
        };
        use nestlink_storage::network_policy::{NetworkAuthorityUpdate, NetworkMembershipUpdate};
        let (mut store, _, _, controller, host) = fixture()?;
        let c = InstallationIdentity::generate();
        let h = InstallationIdentity::generate();
        let cid = enrolled(&mut store, &controller, &c, true)?;
        let hid = enrolled(&mut store, &host, &h, true)?;
        let initial = approved(&mut store, &controller, &host, &cid, &hid, &h)?;
        let permit = store.initial_permit(&controller, &initial, 1002)?;
        let choice = TrustChoice {
            expected_revision: 0,
            expires_at_unix_ms: 2_000_000,
        };
        let proof = nestlink_identity::trust_transcript(&permit, &host.account_id, &choice)?;
        store.trust_remote(
            &host,
            &initial,
            TrustSubmission {
                choice,
                signature: URL_SAFE_NO_PAD.encode(h.sign_action(&proof)?),
            },
            1003,
        )?;
        let trusted = store.create_trusted_remote(
            &controller,
            RemoteRequest {
                id: random_id(),
                controller_device_id: cid.clone(),
                host_device_id: hid.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "direct_only".into(),
            },
            1004,
        )?;
        let permit = store.initial_permit(&controller, &trusted.id, 1004)?;
        let signer =
            nestlink_identity::network::NetworkAuthoritySigner::from_master_seed(&[56; 32])?;
        let space = random_id();
        store.configure_network_authority(
            &controller,
            NetworkAuthorityUpdate {
                space_id: space.clone(),
                expected_revision: 0,
                public_key: signer.public_key(),
            },
            1_004_000,
        )?;
        for (revision, id) in [(1, &cid), (2, &hid)] {
            store.set_network_membership(
                &controller,
                NetworkMembershipUpdate {
                    space_id: space.clone(),
                    installation_id: id.clone(),
                    expected_policy_revision: revision,
                    expected_membership_epoch: 0,
                    role: SpaceRole::Member,
                },
                1_004_000,
            )?;
        }
        let policy = store.set_offline_enabled(
            &controller,
            &space,
            OfflineEnableUpdate {
                expected_revision: 0,
                enabled: true,
            },
            1_004_000,
        )?;
        let processes = [
            nestlink_identity::offline::OfflineProcess::new(
                cid,
                c.public_key(),
                1_004_000,
                policy.highest_revocation_epoch,
            )?,
            nestlink_identity::offline::OfflineProcess::new(
                hid,
                h.public_key(),
                1_004_000,
                policy.highest_revocation_epoch,
            )?,
        ];
        let draft = store.create_offline_remote_draft(
            &controller,
            &space,
            OfflineRemoteDraftRequest {
                session_id: trusted.id,
                expected_policy_revision: 3,
                expected_connection_generation: permit.connection_generation,
                expected_lease_sequence: permit.lease_sequence,
                process_nonces: [processes[0].nonce(), processes[1].nonce()],
                operations: vec![OfflineRemoteOperation::View],
                direct_transports: vec![OfflineDirectTransport::Quic],
                maximum_bytes: 4096,
                maximum_file_write_bytes: 0,
                maximum_connections: 4,
                expires_at_ms: 1_064_000,
            },
            1_004_000,
        )?;
        assert!(draft.live);
        Ok(Self {
            store,
            controller,
            host,
            identities: [c, h],
            processes,
            signer,
            space,
            draft,
        })
    }
    fn approve(
        &mut self,
        endpoint: u8,
    ) -> Result<nestlink_protocol::offline::management::OfflineBundleView> {
        let proof = self.identities[usize::from(endpoint)].sign_offline_endpoint_approval(
            &self.signer.public_key(),
            &self.draft.claims,
            endpoint,
            self.draft.draft_digest,
        )?;
        Ok(self.store.approve_offline_bundle(
            if endpoint == 0 {
                &self.controller
            } else {
                &self.host
            },
            &self.signer,
            &self.space,
            &self.draft.claims.bundle_id,
            proof,
            1_004_000,
        )?)
    }
}
#[test]
fn remote_budget_offline_second_approval_uses_online_total_once_and_revoke_never_refunds() -> Result
{
    use nestlink_protocol::offline::management::OfflineConsumeRequest;
    let mut f = OfflineSetup::new()?;
    let before = f
        .store
        .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
        .ok_or("ledger")?;
    assert_eq!(before.promised_bytes, 2 * ONLINE_PROMISE_BYTES);
    assert!(f.approve(0)?.signed.is_none());
    assert_eq!(
        f.store
            .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
            .ok_or("ledger")?,
        before
    );
    let signed = f.approve(1)?;
    assert!(signed.signed.is_some());
    let after = f
        .store
        .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
        .ok_or("ledger")?;
    assert_eq!(after.promised_bytes, before.promised_bytes + 4096);
    assert_eq!(
        after.promised_connection_attempts,
        before.promised_connection_attempts + 4
    );
    f.approve(1)?;
    assert_eq!(
        f.store
            .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
            .ok_or("ledger")?,
        after
    );
    let challenge = f.store.offline_consume_challenge(
        &f.controller,
        &f.space,
        &f.draft.claims.bundle_id,
        0,
        1_004_000,
    )?;
    let proof =
        nestlink_identity::offline::offline_consume_transcript(&f.draft.claims, &challenge)?;
    let request = OfflineConsumeRequest {
        endpoint: 0,
        draft_digest: f.draft.draft_digest,
        process_nonce: f.processes[0].nonce(),
        signature: f.identities[0].sign_action(&proof)?,
    };
    f.store.consume_offline_bundle(
        &f.controller,
        &f.space,
        &f.draft.claims.bundle_id,
        request.clone(),
        1_004_000,
    )?;
    assert!(
        f.store
            .consume_offline_bundle(
                &f.controller,
                &f.space,
                &f.draft.claims.bundle_id,
                request,
                1_004_000
            )
            .is_err()
    );
    let nestlink_protocol::offline::OfflineBusiness::RemoteControl { resource_id, .. } =
        &f.draft.claims.business
    else {
        return Err("business".into());
    };
    f.store.revoke_remote(&f.host, resource_id)?;
    assert!(
        !f.store
            .offline_bundle(
                &f.controller,
                &f.space,
                &f.draft.claims.bundle_id,
                1_004_001
            )?
            .live
    );
    assert_eq!(
        f.store
            .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
            .ok_or("ledger")?,
        after
    );
    Ok(())
}
#[test]
fn remote_budget_offline_failed_second_approval_rolls_back_and_original_online_expiry_does_not_extend()
-> Result {
    let mut f = OfflineSetup::new()?;
    f.approve(0)?;
    let before = f
        .store
        .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
        .ok_or("ledger")?;
    f.store.set_remote_budget_quota(
        &f.controller,
        "account",
        &f.controller.account_id,
        RemoteBudgetQuotaUpdate {
            expected_revision: before.revision,
            maximum_bytes: before.promised_bytes + 4095,
            maximum_file_write_bytes: 0,
            maximum_connection_attempts: before.promised_connection_attempts + 4,
        },
        1004,
    )?;
    assert!(
        matches!(f.approve(1),Err(e) if e.downcast_ref::<StorageError>().is_some_and(|e|matches!(e,StorageError::RateLimited)))
    );
    let view = f.store.offline_bundle(
        &f.controller,
        &f.space,
        &f.draft.claims.bundle_id,
        1_004_000,
    )?;
    assert_eq!(view.approved, [true, false]);
    assert!(view.signed.is_none());
    let usage = f
        .store
        .remote_budget_quota(&f.controller, "account", &f.controller.account_id, 1004)?
        .ok_or("ledger")?;
    assert_eq!(usage.promised_bytes, before.promised_bytes);
    // The original durable approval remains current after the short online
    // permit ends. This reads independent offline authority, never an old lease.
    assert!(
        f.store
            .offline_bundle(
                &f.controller,
                &f.space,
                &f.draft.claims.bundle_id,
                1_020_000
            )?
            .live
    );
    let nestlink_protocol::offline::OfflineBusiness::RemoteControl { resource_id, .. } =
        &f.draft.claims.business
    else {
        return Err("business".into());
    };
    assert!(
        f.store
            .current_permit(&f.controller, resource_id, 1020)
            .is_err()
    );
    Ok(())
}
