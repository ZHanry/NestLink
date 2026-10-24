use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims};
use nestlink_remote::{AuthorizedConnection, RuntimeClock, controller_proof, host_proof};
use nestlink_session::{Session, SessionBinding, StopReason};
use nestlink_transport_quic::{connect, connector, listener};
use nestlink_transport_stream::Channel;
use prost::Message;
use std::time::{Duration, Instant};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn session(
    controller: &InstallationIdentity,
    host: &InstallationIdentity,
    clock: &RuntimeClock,
) -> Result<(Vec<u8>, PermitSigner, SessionBinding)> {
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
        connection_generation: 1,
        capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    let now = clock.sample()?;
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
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
        capability_sha256: vec![9; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let signer = PermitSigner::generate();
    Ok((signer.sign(&claims)?.encode_to_vec(), signer, binding))
}
#[tokio::test]
async fn permit_proof_on_real_quic_and_revocation_stops_blocked_receive() -> Result {
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let (bytes, signer, binding) = session(&controller, &host, &clock)?;
    let issuer = signer.public_key();
    let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
    let client = connector("127.0.0.1:0".parse()?, &controller, host.fingerprint())?;
    let address = server.local_addr()?;
    let host_key = host.public_key();
    let controller_key = controller.public_key();
    let (revoke, host_stop) = watch::channel(None);
    let (_controller_stop, stop) = watch::channel(None);
    let host_bytes = bytes.clone();
    let host_binding = binding.clone();
    let task = tokio::spawn(async move {
        let connection = server.accept().await.ok_or("no QUIC request")?.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;
        let clock = RuntimeClock::default();
        let mut session = Session::activate(
            verify_permit(&host_bytes, &issuer)?,
            host_binding,
            Path::Direct,
            0,
            clock.sample()?,
        )?;
        host_proof(
            &mut receive,
            &mut send,
            &mut session,
            &host,
            &controller_key,
            &clock,
        )
        .await?;
        let mut authorized =
            AuthorizedConnection::new(receive, send, session, Path::Direct, clock, host_stop)?;
        authorized
            .send(Channel::Video, b"measured-frame-payload")
            .await?;
        assert!(authorized.receive().await.is_err());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = connect(&client, address, Duration::from_secs(3)).await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    let mut session = Session::activate(
        verify_permit(&bytes, &issuer)?,
        binding,
        Path::Direct,
        0,
        clock.sample()?,
    )?;
    controller_proof(
        &mut receive,
        &mut send,
        &mut session,
        &controller,
        &host_key,
        &clock,
    )
    .await?;
    let mut authorized =
        AuthorizedConnection::new(receive, send, session, Path::Direct, clock, stop)?;
    assert_eq!(
        authorized.receive().await?.payload,
        b"measured-frame-payload"
    );
    assert!(
        authorized
            .send(Channel::Input, b"forbidden-input")
            .await
            .is_err()
    );
    let start = Instant::now();
    revoke.send(Some(StopReason::Revoked))?;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    assert!(start.elapsed() < Duration::from_secs(2));
    connection.close(0_u8.into(), b"test-complete");
    Ok(())
}

#[tokio::test]
async fn renewal_during_partial_frame_preserves_io_and_extends_only_current_lease() -> Result {
    use nestlink_session::EndpointRole;
    use tokio::io::{AsyncWriteExt, split};
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let (bytes, signer, binding) = session(&controller, &host, &clock)?;
    let mut claims = verify_permit(&bytes, &signer.public_key())?
        .claims()
        .clone();
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 1200;
    let bytes = signer.sign(&claims)?.encode_to_vec();
    let mut session = Session::activate(
        verify_permit(&bytes, &signer.public_key())?,
        binding,
        Path::Direct,
        0,
        clock.sample()?,
    )?;
    let proof = session.proof_transcript();
    session.confirm_endpoint(
        EndpointRole::Controller,
        &controller.public_key(),
        &controller.prove(&proof)?,
        clock.monotonic_ms(),
    )?;
    session.confirm_endpoint(
        EndpointRole::Host,
        &host.public_key(),
        &host.prove(&proof)?,
        clock.monotonic_ms(),
    )?;
    let (mut sender, receiver) = tokio::io::duplex(32);
    let (read, write) = split(receiver);
    let (_stop, stop) = watch::channel(None);
    let mut authorized =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock.clone(), stop)?;
    let lease = authorized.lease_control();
    let task = tokio::spawn(async move { authorized.receive().await });
    sender.write_all(&[1, 3, 0, 0, 0, 6]).await?;
    sender.write_all(b"abc").await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let request_started = clock.monotonic_ms();
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms = clock.sample()?.unix_ms;
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 1500;
    lease.renew(
        verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
        request_started,
    )?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    sender.write_all(b"def").await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), task).await???;
    assert_eq!(frame.payload, b"abcdef");
    Ok(())
}
