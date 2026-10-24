use super::Result;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims};
use nestlink_remote::{AuthorizedConnection, ChannelRuntime, RuntimeClock, SessionLifecycle};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use prost::Message;
use tokio::{io::split, sync::watch};
pub struct Runtime {
    pub channels: ChannelRuntime,
    _stop: watch::Sender<Option<StopReason>>,
    _peer: tokio::io::DuplexStream,
}
pub fn runtime(control: bool) -> Result<Runtime> {
    let permissions = if control {
        vec![Permission::View, Permission::Input]
    } else {
        vec![Permission::View]
    };
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
        granted_permissions: permissions.clone(),
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
        permissions: permissions.iter().map(|p| *p as i32).collect(),
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
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
    for (role, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
    ] {
        let transcript = session.proof_transcript();
        session.confirm_endpoint(
            role,
            &identity.public_key(),
            &identity.prove(&transcript)?,
            clock.monotonic_ms(),
        )?;
    }
    let (stop, stopped) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let runtime = AuthorizedConnection::with_lifecycle(
        read,
        write,
        session,
        Path::Direct,
        clock,
        SessionLifecycle::new(stopped),
    )?
    .into_channels();
    Ok(Runtime {
        channels: runtime,
        _stop: stop,
        _peer: peer,
    })
}
