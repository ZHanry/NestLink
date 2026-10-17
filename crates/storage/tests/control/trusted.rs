use super::*;
use nestlink_protocol::{
    PermitClaims,
    api::{TrustChoice, TrustSubmission},
};

struct Setup {
    store: Store,
    vault: VaultKey,
    dummy: String,
    controller: Principal,
    host: Principal,
    c: InstallationIdentity,
    h: InstallationIdentity,
    permit: PermitClaims,
}
impl Setup {
    fn new() -> Result<Self> {
        let (mut store, vault, dummy, controller, host) = fixture()?;
        let c = InstallationIdentity::generate();
        let h = InstallationIdentity::generate();
        let controller_id = enroll(&mut store, &controller, &c, "controller")?;
        let host_id = enroll(&mut store, &host, &h, "host")?;
        let view = store.create_remote(
            &controller,
            RemoteRequest {
                id: random_id(),
                controller_device_id: controller_id,
                host_device_id: host_id,
                permissions: vec![Permission::View as i32, Permission::Input as i32],
                path_mode: "direct_preferred".into(),
            },
            1000,
        )?;
        let choice = ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![1],
        };
        let proof = store.approval_transcript(&host, &view.id, &choice, 1001)?;
        store.approve_remote(
            &host,
            &view.id,
            choice,
            &URL_SAFE_NO_PAD.encode(h.sign_action(&proof)?),
            1001,
        )?;
        let permit = store.initial_permit(&controller, &view.id, 1002)?;
        Ok(Self {
            store,
            vault,
            dummy,
            controller,
            host,
            c,
            h,
            permit,
        })
    }
    fn request(&self) -> RemoteRequest {
        RemoteRequest {
            id: random_id(),
            controller_device_id: self.permit.controller_device_id.clone(),
            host_device_id: self.permit.host_device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_preferred".into(),
        }
    }
    fn submission(
        &self,
        expected_revision: u64,
        expires_at_unix_ms: u64,
    ) -> Result<TrustSubmission> {
        let choice = TrustChoice {
            expected_revision,
            expires_at_unix_ms,
        };
        let proof =
            nestlink_identity::trust_transcript(&self.permit, &self.host.account_id, &choice)?;
        Ok(TrustSubmission {
            choice,
            signature: URL_SAFE_NO_PAD.encode(self.h.sign_action(&proof)?),
        })
    }
    fn grant(&mut self, expires: u64) -> Result {
        let submission = self.submission(0, expires)?;
        assert_eq!(
            self.store
                .trust_remote(&self.host, &self.permit.session_id, submission, 1003)?
                .revision,
            1
        );
        Ok(())
    }
}

#[test]
fn explicit_host_signature_pins_device_and_only_the_approved_permissions() -> Result {
    let mut f = Setup::new()?;
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1003)
            .is_err()
    );
    let submission = f.submission(0, 2_000_000)?;
    assert!(
        f.store
            .trust_remote(
                &f.controller,
                &f.permit.session_id,
                submission.clone(),
                1003
            )
            .is_err()
    );
    let proof =
        nestlink_identity::trust_transcript(&f.permit, &f.host.account_id, &submission.choice)?;
    let mut wrong_action = proof.clone();
    wrong_action.action = nestlink_protocol::DeviceAction::Approve as i32;
    let mut replayed_approval = submission.clone();
    replayed_approval.signature = URL_SAFE_NO_PAD.encode(f.h.sign_action(&wrong_action)?);
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, replayed_approval, 1003)
            .is_err()
    );
    let mut forged = submission.clone();
    forged.signature = URL_SAFE_NO_PAD.encode(f.c.sign_action(&proof)?);
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, forged, 1003)
            .is_err()
    );
    let mut widened = submission.clone();
    widened.choice.expires_at_unix_ms += 1000;
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, widened, 1003)
            .is_err()
    );
    let too_long = f.submission(0, 1_003_000 + nestlink_storage::trusted::MAX_TRUST_MS + 1)?;
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, too_long, 1003)
            .is_err()
    );
    assert!(
        f.store
            .trusted_devices(&f.host, &f.permit.host_device_id, 1003)?
            .is_empty()
    );
    f.grant(2_000_000)?;
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, submission, 1003)
            .is_err()
    );
    assert!(
        f.store
            .trusted_devices(&f.controller, &f.permit.host_device_id, 1003)
            .is_err()
    );
    let list = f
        .store
        .trusted_devices(&f.host, &f.permit.host_device_id, 1003)?;
    assert_eq!(list.len(), 1);
    assert!(list[0].active);
    assert_eq!(
        list[0].controller_key_sha256,
        URL_SAFE_NO_PAD.encode(f.c.fingerprint())
    );
    let request = f.request();
    let view = f
        .store
        .create_trusted_remote(&f.controller, request.clone(), 1004)?;
    assert_eq!(view.status, "approved");
    assert_eq!(view.paths, vec![1]);
    assert_eq!(
        f.store
            .create_trusted_remote(&f.controller, request.clone(), 1004)?
            .id,
        view.id
    );
    assert!(f.store.create_remote(&f.controller, request, 1004).is_err());
    let permit = f.store.initial_permit(&f.controller, &view.id, 1004)?;
    assert_eq!(permit.permissions, vec![Permission::View as i32]);
    assert_eq!(permit.controller_key_sha256, f.c.fingerprint());
    let mut extra = f.request();
    extra.permissions.push(Permission::Input as i32);
    assert!(
        f.store
            .create_trusted_remote(&f.controller, extra, 1004)
            .is_err()
    );
    let mut other = f.request();
    other.controller_device_id = enroll(
        &mut f.store,
        &f.controller,
        &InstallationIdentity::generate(),
        "other",
    )?;
    assert!(
        f.store
            .create_trusted_remote(&f.controller, other, 1004)
            .is_err()
    );
    assert_eq!(
        f.store
            .create_remote(&f.controller, f.request(), 1004)?
            .status,
        "pending"
    );
    Ok(())
}

#[test]
fn revoke_tombstone_defeats_delayed_grants_and_regrant_cannot_revive_sessions() -> Result {
    let mut f = Setup::new()?;
    f.grant(2_000_000)?;
    let delayed = f.submission(1, 2_000_000)?;
    let view = f
        .store
        .create_trusted_remote(&f.controller, f.request(), 1004)?;
    f.store.initial_permit(&f.controller, &view.id, 1004)?;
    assert!(
        f.store
            .revoke_device_trust(
                &f.controller,
                &f.permit.host_device_id,
                &f.permit.controller_device_id,
                1,
                1005
            )
            .is_err()
    );
    let revoked = f.store.revoke_device_trust(
        &f.host,
        &f.permit.host_device_id,
        &f.permit.controller_device_id,
        1,
        1005,
    )?;
    assert_eq!(revoked, vec![view.id.clone()]);
    assert!(
        f.store
            .current_permit(&f.controller, &view.id, 1005)
            .is_err()
    );
    assert!(
        f.store
            .renewal_transcript(&f.controller, &view.id, 2, false, 1005)
            .is_err()
    );
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1005)
            .is_err()
    );
    assert!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, delayed, 1005)
            .is_err()
    );
    let tombstone = f
        .store
        .trusted_devices(&f.host, &f.permit.host_device_id, 1005)?;
    assert!(!tombstone[0].active);
    assert_eq!(tombstone[0].revision, 2);
    let fresh = f.submission(2, 2_000_000)?;
    assert_eq!(
        f.store
            .trust_remote(&f.host, &f.permit.session_id, fresh, 1006)?
            .revision,
        3
    );
    assert!(
        f.store
            .revoke_device_trust(
                &f.host,
                &f.permit.host_device_id,
                &f.permit.controller_device_id,
                1,
                1006
            )
            .is_err()
    );
    assert!(!f.store.session_is_active(&view.id)?);
    assert!(
        f.store
            .current_permit(&f.controller, &view.id, 1006)
            .is_err()
    );
    let new = f
        .store
        .create_trusted_remote(&f.controller, f.request(), 1006)?;
    f.store.initial_permit(&f.controller, &new.id, 1006)?;
    f.store.revoke_device(
        &random_id(),
        &f.permit.controller_device_id,
        &f.controller.account_id,
    )?;
    assert!(f.store.current_permit(&f.host, &new.id, 1007).is_err());
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1007)
            .is_err()
    );
    Ok(())
}

#[test]
fn expiry_caps_signed_leases_and_renewal_proofs_without_starting_a_new_lifetime() -> Result {
    let mut f = Setup::new()?;
    f.grant(1_010_000)?;
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1002)
            .is_err()
    );
    let view = f
        .store
        .create_trusted_remote(&f.controller, f.request(), 1004)?;
    let permit = f.store.initial_permit(&f.controller, &view.id, 1004)?;
    assert_eq!(permit.expires_at_unix_ms, 1_010_000);
    let cp = f
        .store
        .renewal_transcript(&f.controller, &view.id, 2, false, 1006)?;
    let hp = f
        .store
        .renewal_transcript(&f.controller, &view.id, 2, true, 1006)?;
    assert_eq!(hp.expires_at_unix_ms, permit.expires_at_unix_ms);
    let renewal = RenewalSubmission {
        lease_sequence: 2,
        controller_signature: URL_SAFE_NO_PAD.encode(f.c.sign_action(&cp)?),
        host_signature: URL_SAFE_NO_PAD.encode(f.h.sign_action(&hp)?),
    };
    let renewed = f
        .store
        .renew_permit(&f.controller, &view.id, renewal, 1006)?;
    assert_eq!(renewed.expires_at_unix_ms, permit.expires_at_unix_ms);
    assert!(f.store.current_permit(&f.host, &view.id, 1010).is_err());
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1010)
            .is_err()
    );
    Ok(())
}

#[test]
fn restored_epoch_and_changed_keys_cannot_inherit_trust() -> Result {
    use rusqlite::{Connection, MAIN_DB, params};
    let mut f = Setup::new()?;
    f.grant(2_000_000)?;
    let bytes = f.store.snapshot()?;
    let mut changed = Connection::open_in_memory()?;
    changed.deserialize_read_exact(MAIN_DB, &bytes[..], bytes.len(), false)?;
    changed.execute(
        "UPDATE device_details SET public_key=?1 WHERE device_id=?2",
        params![
            InstallationIdentity::generate().public_key(),
            f.permit.controller_device_id
        ],
    )?;
    let image = changed.serialize(MAIN_DB)?;
    let mut substituted = Store::from_snapshot(&image, &f.store.deployment_id()?)?;
    assert!(
        substituted
            .create_trusted_remote(&f.controller, f.request(), 1004)
            .is_err()
    );
    f.store.invalidate_after_restore()?;
    let controller = f
        .store
        .login("admin", PASSWORD, None, 1004, &f.vault, &f.dummy)?
        .principal;
    let host = f
        .store
        .login("member", PASSWORD, None, 1004, &f.vault, &f.dummy)?
        .principal;
    assert!(
        !f.store
            .trusted_devices(&host, &f.permit.host_device_id, 1004)?[0]
            .active
    );
    assert!(
        f.store
            .create_trusted_remote(&controller, f.request(), 1004)
            .is_err()
    );
    let old = f.submission(1, 2_000_000)?;
    assert!(
        f.store
            .trust_remote(&host, &f.permit.session_id, old, 1004)
            .is_err()
    );
    Ok(())
}

#[test]
fn trusted_sessions_remain_inside_current_policy_login_and_capacity_limits() -> Result {
    use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
    let mut f = Setup::new()?;
    f.grant(2_000_000)?;
    let old = f
        .store
        .create_trusted_remote(&f.controller, f.request(), 1004)?;
    f.store.initial_permit(&f.controller, &old.id, 1004)?;
    let replacement = f.submission(1, 2_000_000)?;
    let updated = f
        .store
        .trust_remote(&f.host, &f.permit.session_id, replacement, 1004)?;
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.revoked_sessions, vec![old.id.clone()]);
    f.store.apply_policy(
        1,
        NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            peer_path_mode: PeerPathMode::RelayOnly,
            public_ingress: PublicIngress::Disabled,
        },
    )?;
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1004)
            .is_err()
    );
    f.store.apply_policy(2, NetworkPolicy::default())?;
    assert!(
        f.store
            .current_permit(&f.controller, &old.id, 1004)
            .is_err()
    );
    for _ in 0..32 {
        let new = f
            .store
            .create_trusted_remote(&f.controller, f.request(), 1004)?;
        assert_eq!(new.paths, vec![1]);
        assert_eq!(new.policy_revision, 3);
    }
    assert!(matches!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1004),
        Err(StorageError::RateLimited)
    ));
    f.store.logout(&f.controller)?;
    assert!(
        f.store
            .create_trusted_remote(&f.controller, f.request(), 1005)
            .is_err()
    );
    assert!(
        f.store
            .create_trusted_remote(&f.host, f.request(), 1005)
            .is_err()
    );
    let controller = f
        .store
        .login("admin", PASSWORD, None, 1005, &f.vault, &f.dummy)?
        .principal;
    f.store.disable_account(&controller, &f.host.account_id)?;
    assert!(
        f.store
            .create_trusted_remote(&controller, f.request(), 1005)
            .is_err()
    );
    Ok(())
}
