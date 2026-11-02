//! Regress the original producer notification against real signed/proved leases.
use super::notify_native_capture_failure;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims};
use nestlink_remote::{CleanupStatus, LeaseControl, RuntimeClock, SessionLifecycle};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use prost::Message;
use tokio::sync::watch;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn proved_lease() -> Result<(LeaseControl, watch::Sender<Option<StopReason>>)> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        media: None,
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: random_id(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: 1,
        deployment_id: binding.deployment_id.clone(),
        security_epoch: 1,
        session_id: binding.session_id.clone(),
        account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(),
        host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: binding.resource_id.clone(),
        permissions: vec![Permission::View as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15_000,
        capability_sha256: vec![9; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let signer = PermitSigner::generate();
    let mut session = Session::activate(
        verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
        binding,
        Path::Direct,
        now.monotonic_ms,
        now,
    )?;
    let transcript = session.proof_transcript();
    for (role, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
    ] {
        session.confirm_endpoint(
            role,
            &identity.public_key(),
            &identity.prove(&transcript)?,
            clock.monotonic_ms(),
        )?;
    }
    let (stop, receiver) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock,
        SessionLifecycle::new(receiver),
    )?;
    Ok((lease, stop))
}

#[tokio::test]
async fn old_capture_failure_preserves_transport_recovery_and_live_capture_failure_is_terminal()
-> Result {
    let (retired, _retired_stop) = proved_lease()?;
    let reports = retired.subscribe_stopped();
    retired.stop(StopReason::TransportLost)?;
    assert!(retired.reconnection_budget().is_ok());
    notify_native_capture_failure(&retired)?;
    let report = (*reports.borrow()).ok_or("original transport-stop receipt missing")?;
    assert_eq!(report.reason, StopReason::TransportLost);
    assert!(matches!(report.cleanup, CleanupStatus::NotAttached));
    // The old unconditional stop preserves the historical reason too, but
    // silently forbids recovery. This assertion catches that actual defect.
    assert!(retired.reconnection_budget().is_ok());
    // A new explicit platform change still fences even this historical stop.
    retired.stop(StopReason::PlatformChanged)?;
    assert!(retired.reconnection_budget().is_err());

    let (running, _running_stop) = proved_lease()?;
    let reports = running.subscribe_stopped();
    assert!(running.remaining().is_ok());
    notify_native_capture_failure(&running)?;
    let report = (*reports.borrow()).ok_or("live capture-failure receipt missing")?;
    assert_eq!(report.reason, StopReason::PlatformChanged);
    assert!(running.remaining().is_err());
    assert!(running.reconnection_budget().is_err());
    Ok(())
}
