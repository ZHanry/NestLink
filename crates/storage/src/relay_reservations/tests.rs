use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password};
use nestlink_identity::{InstallationIdentity, nodes::NodeIdentity, relay_transcript};
use nestlink_policy::{NetworkPolicy, PeerPathMode, ServerForwarding};
use nestlink_protocol::api::{
    ApprovalChoice, DeviceDescriptor, DeviceRegistration, NodeRegistration, RelayQuotaUpdate,
    RemoteRequest, RenewalSubmission,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_001_002;
mod closes;
mod discovery;
mod resources;
mod turn;
struct Fixture {
    s: Store,
    lifecycle: RelayLifecycle,
    c: InstallationIdentity,
    h: InstallationIdentity,
    admin: Principal,
    host: Principal,
    permit: PermitClaims,
    node: NodeIdentity,
    node_id: String,
    node_runtime: String,
}
impl Fixture {
    fn new(same_account: bool, node_max: u32) -> Result<Self> {
        let mut s = Store::in_memory(&random_id())?;
        let vault = VaultKey::from_bytes([7; 32]);
        let dummy = hash_password("relay-reservation-dummy")?;
        s.bootstrap_admin("admin", "relay-reservation-test-password")?;
        let admin = s
            .login(
                "admin",
                "relay-reservation-test-password",
                None,
                1000,
                &vault,
                &dummy,
            )?
            .principal;
        let host = if same_account {
            admin.clone()
        } else {
            s.create_member(&admin, "host", "relay-reservation-test-password")?;
            s.login(
                "host",
                "relay-reservation-test-password",
                None,
                1000,
                &vault,
                &dummy,
            )?
            .principal
        };
        s.apply_policy(
            1,
            NetworkPolicy {
                server_forwarding: ServerForwarding::Allow,
                peer_path_mode: PeerPathMode::DirectPreferred,
                ..NetworkPolicy::default()
            },
        )?;
        let c = InstallationIdentity::generate();
        let h = InstallationIdentity::generate();
        let controller = enroll(&mut s, &admin, &c)?;
        let host_device = enroll(&mut s, &host, &h)?;
        let permit = approve(&mut s, &admin, &host, &h, &controller, &host_device, 1001)?;
        let node = NodeIdentity::generate();
        let node_id = random_id();
        let node_runtime = random_id();
        s.register_node(
            &admin,
            NodeRegistration {
                id: node_id.clone(),
                name: "relay".into(),
                public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
                roles: vec![NodeRole::NodeRelay as i32],
                max_connections: node_max,
                bytes_per_second: 100000,
            },
        )?;
        let challenge = s.node_challenge(&node_id, NOW - 2)?;
        s.issue_node_lease(&node.prove(&challenge, &node_runtime)?, NOW - 1)?;
        let lifecycle = s.relay_lifecycle(NOW)?;
        Ok(Self {
            s,
            lifecycle,
            c,
            h,
            admin,
            host,
            permit,
            node,
            node_id,
            node_runtime,
        })
    }
    fn request(&self, id: &str) -> Result<RelayAllocationRequest> {
        Ok(RelayAllocationRequest {
            allocation_id: id.into(),
            node_id: self.node_id.clone(),
            device_id: self.permit.controller_device_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(self.c.sign_action(&allocation_transcript(
                &self.permit,
                &self.admin.account_id,
                &self.permit.controller_device_id,
                id,
                &self.node_id,
            )?)?),
        })
    }
    fn combined(&mut self, host: bool, now: u64) -> Result<CombinedReservation> {
        let (p, key, device) = if host {
            (&self.host, &self.h, &self.permit.host_device_id)
        } else {
            (&self.admin, &self.c, &self.permit.controller_device_id)
        };
        let nonce = [9; 32];
        let hello = RelayHello {
            device_id: device.clone(),
            signature: URL_SAFE_NO_PAD.encode(key.sign_action(&relay_transcript(
                &self.permit,
                &p.account_id,
                device,
                &nonce,
            )?)?),
        };
        Ok(self
            .s
            .reserve_combined_relay(
                &self.lifecycle,
                p,
                &self.permit.session_id,
                (&hello, &nonce),
                now,
            )?
            .1)
    }
    fn at(&mut self, now: u64) {
        self.lifecycle.started =
            Instant::now() - Duration::from_millis(now - self.lifecycle.started_unix);
    }
    fn renew(&mut self, now: u64) -> Result {
        self.at(now);
        let sequence = self.permit.lease_sequence + 1;
        let controller = self.s.renewal_transcript(
            &self.admin,
            &self.permit.session_id,
            sequence,
            false,
            now / 1000,
        )?;
        let host = self.s.renewal_transcript(
            &self.admin,
            &self.permit.session_id,
            sequence,
            true,
            now / 1000,
        )?;
        self.permit = self.s.renew_permit(
            &self.admin,
            &self.permit.session_id,
            RenewalSubmission {
                lease_sequence: sequence,
                controller_signature: URL_SAFE_NO_PAD.encode(self.c.sign_action(&controller)?),
                host_signature: URL_SAFE_NO_PAD.encode(self.h.sign_action(&host)?),
            },
            now / 1000,
        )?;
        let challenge = self.s.node_challenge(&self.node_id, now)?;
        self.s
            .issue_node_lease(&self.node.prove(&challenge, &self.node_runtime)?, now)?;
        Ok(())
    }
    fn usage(&self, now: u64) -> Result<RelayReservationUsage> {
        Ok(self.s.relay_reservation_usage(&self.admin, now)?)
    }
    fn quota(&mut self, allocations: u16, endpoints: u16) -> Result {
        let old = self.s.relay_quota_current()?;
        self.s.set_relay_quota(
            &self.admin,
            RelayQuotaUpdate {
                expected_revision: old.revision,
                limits: nestlink_protocol::api::RelayQuotaLimits {
                    max_allocations: allocations,
                    max_account_endpoints: endpoints,
                    ..old.limits
                },
            },
            1001,
        )?;
        Ok(())
    }
}
fn enroll(s: &mut Store, p: &Principal, key: &InstallationIdentity) -> Result<String> {
    let challenge = s.enrollment_challenge(p, 1000)?;
    let mut request = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: "endpoint".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key()),
            capabilities: vec!["vp8".into(), "host".into(), "controller".into()],
            path_mode: "direct_preferred".into(),
        },
        signature: String::new(),
    };
    request.signature =
        URL_SAFE_NO_PAD.encode(key.sign_action(&s.registration_transcript(p, &request, 1000)?)?);
    let id = request.device.id.clone();
    s.register_device(p, request, 1000)?;
    Ok(id)
}
fn approve(
    s: &mut Store,
    c: &Principal,
    h: &Principal,
    key: &InstallationIdentity,
    controller: &str,
    host: &str,
    now: u64,
) -> Result<PermitClaims> {
    let view = s.create_remote(
        c,
        RemoteRequest {
            id: random_id(),
            controller_device_id: controller.into(),
            host_device_id: host.into(),
            permissions: vec![nestlink_protocol::Permission::View as i32],
            path_mode: "relay_only".into(),
        },
        now,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![nestlink_protocol::Permission::View as i32],
        paths: vec![Path::Relay as i32],
    };
    let signature = URL_SAFE_NO_PAD
        .encode(key.sign_action(&s.approval_transcript(h, &view.id, &choice, now)?)?);
    s.approve_remote(h, &view.id, choice, &signature, now)?;
    if s.is_browser_controller(controller)? {
        let proof = s.browser_host_readiness_transcript(h, &view.id, now)?;
        s.mark_browser_host_ready(
            h,
            &view.id,
            nestlink_protocol::api::BrowserHostReadinessSubmission {
                protocol_features: Vec::new(),
                signature: URL_SAFE_NO_PAD.encode(key.sign_action(&proof)?),
            },
            now,
        )?;
    }
    Ok(s.initial_permit(c, &view.id, now)?)
}
#[test]
fn independent_and_combined_share_capacity_and_revocation_keeps_old_promises() -> Result {
    let mut f = Fixture::new(false, 8)?;
    f.quota(1, 2)?;
    let request = f.request(&random_id())?;
    let claims = f.s.reserve_node_relay(
        &f.lifecycle,
        &f.admin,
        &f.permit.session_id,
        request.clone(),
        NOW,
    )?;
    assert_eq!(
        claims,
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, NOW)?
    );
    assert!(f.combined(false, NOW).is_err());
    assert_eq!(f.usage(NOW)?.held_endpoint_slots, 2);
    f.s.revoke_remote(&f.admin, &f.permit.session_id)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    f.permit = approve(
        &mut f.s,
        &f.admin,
        &f.host,
        &f.h,
        &f.permit.controller_device_id,
        &f.permit.host_device_id,
        1001,
    )?;
    assert!(f.combined(false, NOW).is_err());
    let later = claims.expires_at_unix_ms + HOLD_MARGIN_MS;
    f.at(later);
    assert_eq!(f.usage(later)?.held_allocations, 0);
    assert!(f.combined(false, later).is_ok());
    Ok(())
}
#[test]
fn waiting_peer_already_reserves_both_accounts_and_last_close_is_idempotent() -> Result {
    let mut f = Fixture::new(false, 8)?;
    f.quota(2, 1)?;
    let controller = f.combined(false, NOW)?;
    assert!(f.combined(false, NOW).is_err());
    let original = f.permit.clone();
    f.permit = approve(
        &mut f.s,
        &f.admin,
        &f.host,
        &f.h,
        &original.controller_device_id,
        &original.host_device_id,
        1001,
    )?;
    assert!(f.combined(true, NOW).is_err());
    f.permit = original;
    let host = f.combined(true, NOW)?;
    assert_eq!(controller.allocation_id, host.allocation_id);
    f.s.close_combined_relay(&controller, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    f.s.close_combined_relay(&controller, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    f.s.close_combined_relay(&host, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    Ok(())
}
#[test]
fn two_endpoints_owned_by_one_account_consume_two_reserved_slots() -> Result {
    let mut f = Fixture::new(true, 8)?;
    f.quota(2, 1)?;
    assert!(f.combined(false, NOW).is_err());
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    f.quota(2, 2)?;
    assert!(f.combined(false, NOW).is_ok());
    assert_eq!(f.usage(NOW)?.held_endpoint_slots, 2);
    Ok(())
}
#[test]
fn node_capacity_and_runtime_takeover_do_not_refund_the_old_runtime() -> Result {
    let mut f = Fixture::new(false, 2)?;
    let request = f.request(&random_id())?;
    let old_id = request.allocation_id.clone();
    f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, NOW)?;
    let now = NOW + 3000;
    f.at(now);
    let challenge = f.s.node_challenge(&f.node_id, now)?;
    let replacement = random_id();
    f.s.issue_node_lease(&f.node.prove(&challenge, &replacement)?, now)?;
    assert!(
        f.s.reserve_node_relay(
            &f.lifecycle,
            &f.admin,
            &f.permit.session_id,
            f.request(&old_id)?,
            now
        )
        .is_err()
    );
    let request = f.request(&random_id())?;
    assert!(matches!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, now),
        Err(StorageError::RateLimited)
    ));
    assert_eq!(f.usage(now)?.held_allocations, 1);
    let mut small = Fixture::new(false, 1)?;
    let request = small.request(&random_id())?;
    assert!(matches!(
        small.s.reserve_node_relay(
            &small.lifecycle,
            &small.admin,
            &small.permit.session_id,
            request,
            NOW
        ),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}
#[test]
fn retries_and_unchanged_permits_never_extend_a_capacity_promise() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let request = f.request(&random_id())?;
    let first = f.s.reserve_node_relay(
        &f.lifecycle,
        &f.admin,
        &f.permit.session_id,
        request.clone(),
        NOW,
    )?;
    let now = NOW + 6000;
    f.at(now);
    let unchanged = f.s.reserve_node_relay(
        &f.lifecycle,
        &f.admin,
        &f.permit.session_id,
        request.clone(),
        now,
    )?;
    assert_eq!(unchanged, first);
    f.renew(now)?;
    // The complete current permit digest is part of the device request proof.
    assert!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, now)
            .is_err()
    );
    let second = f.s.reserve_node_relay(
        &f.lifecycle,
        &f.admin,
        &f.permit.session_id,
        f.request(&first.allocation_id)?,
        now,
    )?;
    assert_eq!(second.grant_sequence, 2);
    assert!(second.expires_at_unix_ms > first.expires_at_unix_ms);
    assert_eq!(f.usage(now)?.held_allocations, 1);
    let combined = f.combined(false, now)?;
    let before: u64 = f.s.connection.query_row(
        "SELECT promised_until FROM relay_reservations WHERE id=?1",
        [&combined.allocation_id],
        |r| r.get(0),
    )?;
    f.s.renew_combined_relay(&f.lifecycle, &f.admin, &combined, now)?;
    let after: u64 = f.s.connection.query_row(
        "SELECT promised_until FROM relay_reservations WHERE id=?1",
        [&combined.allocation_id],
        |r| r.get(0),
    )?;
    assert_eq!(before, after);
    Ok(())
}
#[test]
fn expired_allocation_ids_do_not_revive_and_stale_connection_cleanup_cannot_release_a_replacement()
-> Result {
    let mut f = Fixture::new(false, 8)?;
    let old = f.combined(false, NOW)?;
    let request = f.request(&random_id())?;
    let id = request.allocation_id.clone();
    let node =
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, NOW)?;
    f.renew(NOW + 6000)?;
    let now = 1_016_001;
    f.at(now);
    let replacement = f.combined(false, now)?;
    assert_eq!(old.allocation_id, replacement.allocation_id);
    assert_ne!(old.connection_id, replacement.connection_id);
    f.s.close_combined_relay(&old, now)?;
    assert_eq!(f.usage(now)?.combined_allocations, 1);
    f.s.renew_combined_relay(&f.lifecycle, &f.admin, &replacement, now)?;
    assert!(node.expires_at_unix_ms < now);
    assert!(
        f.s.reserve_node_relay(
            &f.lifecycle,
            &f.admin,
            &f.permit.session_id,
            f.request(&id)?,
            now
        )
        .is_err()
    );
    f.s.close_combined_relay(&replacement, now)?;
    assert_eq!(f.usage(now)?.combined_allocations, 0);
    Ok(())
}
#[test]
fn invalid_device_proofs_and_failed_audit_transactions_leave_no_reservation() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let mut request = f.request(&random_id())?;
    request.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, NOW)
            .is_err()
    );
    f.s.connection.execute_batch("CREATE TRIGGER reject_reservation BEFORE INSERT ON audit WHEN NEW.event='relay_allocation_reserved' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")?;
    assert!(f.combined(false, NOW).is_err());
    let request = f.request(&random_id())?;
    assert!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, NOW)
            .is_err()
    );
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    Ok(())
}
#[test]
fn sqlite_reopen_fences_old_promises_and_monotonic_wait_expires_them() -> Result {
    let mut f = Fixture::new(false, 8)?;
    f.combined(false, NOW)?;
    let snapshot = f.s.snapshot()?;
    let deployment = f.s.deployment_id()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control.sqlite3");
    std::fs::write(&path, &snapshot[..])?;
    let mut reopened = Store::open_existing(&path, &deployment)?;
    let mut lifecycle = reopened.relay_lifecycle(NOW)?;
    assert!(matches!(
        reopened.resume_relay_reservations(&lifecycle, NOW),
        Err(StorageError::RateLimited)
    ));
    assert!(f.combined(false, NOW).is_err()); // duplicate cannot bypass held capacity
    // Simulated monotonic clock, not a production sleep bypass.
    lifecycle.started = Instant::now() - Duration::from_millis(SESSION_LEASE_MS + HOLD_MARGIN_MS);
    let later = NOW + SESSION_LEASE_MS + HOLD_MARGIN_MS;
    reopened.resume_relay_reservations(&lifecycle, later)?;
    assert_eq!(
        reopened
            .relay_reservation_usage(&f.admin, later)?
            .held_allocations,
        0
    );
    assert!(
        !reopened
            .relay_reservation_usage(&f.admin, later)?
            .restore_fenced
    );
    f.at(later);
    assert!(matches!(
        reopened.resume_relay_reservations(&f.lifecycle, later),
        Err(StorageError::Conflict)
    ));
    Ok(())
}
#[test]
fn restoring_an_empty_snapshot_still_fences_unknown_post_snapshot_promises() -> Result {
    let f = Fixture::new(false, 8)?;
    let mut restored = Store::from_snapshot(&f.s.snapshot()?, &f.s.deployment_id()?)?;
    restored.invalidate_after_restore()?;
    let mut lifecycle = restored.relay_lifecycle(NOW)?;
    assert!(restored.resume_relay_reservations(&lifecycle, NOW).is_err());
    lifecycle.started = Instant::now() - Duration::from_millis(SESSION_LEASE_MS + HOLD_MARGIN_MS);
    restored.resume_relay_reservations(&lifecycle, NOW + SESSION_LEASE_MS + HOLD_MARGIN_MS)?;
    assert!(
        restored
            .resume_relay_reservations(&f.lifecycle, NOW + SESSION_LEASE_MS + HOLD_MARGIN_MS)
            .is_err()
    );
    Ok(())
}
#[test]
fn a_new_control_runtime_prevents_the_previous_runtime_from_admitting() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let replacement = f.s.relay_lifecycle(NOW)?;
    assert!(f.combined(false, NOW).is_err());
    f.lifecycle = replacement;
    assert!(f.combined(false, NOW).is_ok());
    Ok(())
}
#[test]
fn combined_renewal_extends_only_with_new_authority_and_checks_each_role() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let c = f.combined(false, NOW)?;
    let h = f.combined(true, NOW)?;
    let before: u64 = f.s.connection.query_row(
        "SELECT promised_until FROM relay_reservations WHERE id=?1",
        [&c.allocation_id],
        |r| r.get(0),
    )?;
    let now = NOW + 3000;
    f.renew(now)?;
    assert!(
        f.s.renew_combined_relay(&f.lifecycle, &f.host, &c, now)
            .is_err()
    );
    f.s.renew_combined_relay(&f.lifecycle, &f.admin, &c, now)?;
    f.s.renew_combined_relay(&f.lifecycle, &f.host, &h, now)?;
    let after: u64 = f.s.connection.query_row(
        "SELECT promised_until FROM relay_reservations WHERE id=?1",
        [&c.allocation_id],
        |r| r.get(0),
    )?;
    assert!(after > before);
    f.s.revoke_remote(&f.admin, &f.permit.session_id)?;
    assert!(
        f.s.renew_combined_relay(&f.lifecycle, &f.admin, &c, now)
            .is_err()
    );
    assert_eq!(f.usage(now)?.held_allocations, 1);
    Ok(())
}
#[test]
fn wall_clock_jumps_latch_closed_until_a_new_runtime_is_created() -> Result {
    let mut f = Fixture::new(false, 8)?;
    assert!(f.lifecycle.check_clock(NOW + HOLD_MARGIN_MS + 2).is_err());
    assert!(f.lifecycle.check_clock(NOW).is_err());
    f.lifecycle = f.s.relay_lifecycle(NOW)?;
    assert!(f.lifecycle.check_clock(NOW - 1).is_err());
    assert!(f.lifecycle.check_clock(NOW).is_err());
    f.lifecycle = f.s.relay_lifecycle(NOW)?;
    f.lifecycle.started = Instant::now() - Duration::from_millis(HOLD_MARGIN_MS + 2);
    assert!(f.lifecycle.check_clock(NOW).is_err());
    Ok(())
}
