use super::*;
use crate::RuntimeClock;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_session::{EndpointRole, Session, SessionBinding};
use prost::Message;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn expired_or_partially_written_video_ends_the_generation() -> Result {
    let (mut peer, mut writer) = tokio::io::duplex(16);
    let stale = Instant::now() - VIDEO_WRITE_AGE;
    assert!(
        matches!(write_media_bounded(&mut writer, Channel::Video, &[7; 80], stale)
        .await, Err(error) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            tokio::io::AsyncReadExt::read_u8(&mut peer)
        )
        .await
        .is_err()
    );
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    let (read, write) = tokio::io::split(writer);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stopped)?
            .into_channels();
    runtime.send(Channel::Video, &[7; 80]).await?;
    let report = tokio::time::timeout(Duration::from_secs(2), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::TransportLost);
    assert!(runtime.send(Channel::Video, &[8; 80]).await.is_err());
    Ok(())
}

fn active() -> Result<(Session, RuntimeClock)> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let claims = PermitClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: random_id(),
        permissions: vec![
            Permission::View as i32,
            Permission::FileRead as i32,
            Permission::FileWrite as i32,
            Permission::ClipboardRead as i32,
            Permission::ClipboardWrite as i32,
        ],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
        capability_sha256: vec![9; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let binding = SessionBinding {
        deployment_id: claims.deployment_id.clone(),
        security_epoch: 1,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: claims.resource_id.clone(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [9; 32],
        granted_permissions: vec![
            Permission::View,
            Permission::FileRead,
            Permission::FileWrite,
            Permission::ClipboardRead,
            Permission::ClipboardWrite,
        ],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
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
    Ok((session, clock))
}
struct Guard {
    approved: AtomicBool,
    calls: AtomicUsize,
    deadline: Option<Instant>,
}
impl crate::files::FileReadConsent for Guard {
    fn check(&self) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.approved.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "page disclosure stopped",
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original page deadline expired",
            ));
        }
        Ok(())
    }
}
impl DeliveryGuard for Guard {
    fn check(&self) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.approved.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard disclosure stopped",
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original clipboard deadline expired",
            ));
        }
        Ok(())
    }
}
async fn held_frame(channel: Channel, expiry: bool) -> Result {
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    // A first frame fills this real AsyncWrite buffer and holds the sole framed
    // writer. The guarded page must remain queued until the peer consumes it.
    let (mut peer, transport) = tokio::io::duplex(16);
    let (read, write) = tokio::io::split(transport);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stopped)?
            .into_channels();
    runtime.send(channel, &[7; 80]).await?;
    let check = Arc::new(Guard {
        approved: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
        deadline: expiry.then(|| Instant::now() + Duration::from_millis(10)),
    });
    if channel == Channel::FileWrite {
        runtime
            .sender()
            .send_checked_file_write(
                b"sensitive source chunk",
                check.clone(),
                b"cancelled".to_vec(),
            )
            .await?;
    } else {
        runtime
            .sender()
            .send_checked_file_read(
                b"sensitive page",
                check.clone(),
                b"denied".to_vec(),
                b"expired".to_vec(),
            )
            .await?;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        check.calls.load(Ordering::SeqCst) >= 1,
        "original approval was not checked before enqueue"
    );
    if !expiry {
        check.approved.store(false, Ordering::Release);
    }
    assert_eq!(read_frame(&mut peer).await?.payload, vec![7; 80]);
    let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
    assert_eq!(frame.channel, channel);
    assert_eq!(
        frame.payload.as_slice(),
        if channel == Channel::FileWrite {
            &b"cancelled"[..]
        } else if expiry {
            &b"expired"[..]
        } else {
            &b"denied"[..]
        }
    );
    assert!(
        check.calls.load(Ordering::SeqCst) >= 2,
        "original approval was not rechecked before writing"
    );
    runtime.send(Channel::Video, b"viewing").await?;
    assert_eq!(read_frame(&mut peer).await?.payload, b"viewing");
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn queued_file_page_rechecks_revocation_after_transport_backpressure() -> Result {
    held_frame(Channel::FileRead, false).await
}
#[tokio::test]
async fn queued_file_page_rechecks_its_original_deadline_after_transport_backpressure() -> Result {
    held_frame(Channel::FileRead, true).await
}
#[tokio::test]
async fn queued_upload_chunk_is_cancelled_after_source_revocation_under_backpressure() -> Result {
    held_frame(Channel::FileWrite, false).await
}
#[tokio::test]
async fn queued_upload_chunk_is_cancelled_after_its_original_deadline_under_backpressure() -> Result
{
    held_frame(Channel::FileWrite, true).await
}
async fn held_clipboard_frame(channel: Channel, expiry: bool) -> Result {
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    let (mut peer, transport) = tokio::io::duplex(16);
    let (read, write) = tokio::io::split(transport);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stopped)?
            .into_channels();
    runtime.send(Channel::Video, &[7; 80]).await?;
    let check = Arc::new(Guard {
        approved: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
        deadline: expiry.then(|| Instant::now() + Duration::from_millis(10)),
    });
    let fallback: &[u8] = if expiry { b"expired" } else { b"cancelled" };
    runtime
        .sender()
        .send_checked_delivery(
            channel,
            b"secret clipboard text",
            check.clone(),
            fallback.to_vec(),
            b"expired".to_vec(),
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(check.calls.load(Ordering::SeqCst) >= 1);
    if !expiry {
        check.approved.store(false, Ordering::Release);
    }
    assert_eq!(read_frame(&mut peer).await?.payload, vec![7; 80]);
    let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
    assert_eq!(frame.channel, channel);
    assert_eq!(frame.payload.as_slice(), fallback);
    assert!(check.calls.load(Ordering::SeqCst) >= 2);
    runtime.send(Channel::Video, b"viewing").await?;
    assert_eq!(read_frame(&mut peer).await?.payload, b"viewing");
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn queued_clipboard_text_rechecks_consent_and_deadline_under_transport_backpressure() -> Result
{
    for channel in [Channel::ClipboardRead, Channel::ClipboardWrite] {
        for expiry in [false, true] {
            held_clipboard_frame(channel, expiry).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn file_client_closed_transport_queue_keeps_transport_loss_reason() -> Result {
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    let (_peer, transport) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(transport);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stopped)?
            .into_channels();
    let mut client = crate::files::FileReadClient::attach(&mut runtime, 9)?;
    // This closure runs before the background writer observes it. The file
    // request itself must classify the queue's real BrokenPipe correctly.
    runtime.outgoing.close();
    assert!(
        client
            .open(&random_id(), &random_id(), "file", 0, None)
            .await
            .is_err()
    );
    assert_eq!(
        runtime.wait_stopped().await?.reason,
        StopReason::TransportLost
    );
    assert!(runtime.lease_control().reconnection_budget().is_ok());
    Ok(())
}
struct NoFiles;
impl crate::files::FileReadDevice for NoFiles {
    fn open(&mut self, _: &str, _: &str) -> io::Result<Box<dyn crate::files::FileReadSource>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no approved file"))
    }
}
#[tokio::test]
async fn file_server_closed_receive_queue_is_not_a_protocol_violation() -> Result {
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    let (_peer, transport) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(transport);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stopped)?
            .into_channels();
    let mut server = crate::files::FileReadServer::start(&mut runtime, 9, NoFiles)?;
    runtime.incoming.close();
    assert_eq!(runtime.wait_stopped().await?.reason, StopReason::Revoked);
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        crate::files::FileShutdown::Finished
    );
    Ok(())
}
#[tokio::test]
async fn late_file_stop_observations_and_synthetic_drops_preserve_network_recovery() -> Result {
    let (session, clock) = active()?;
    let (_keep, stopped) = watch::channel(None);
    let lease = LeaseControl::new(
        session,
        Path::Direct,
        clock,
        crate::SessionLifecycle::new(stopped),
    )?;
    lease.stop(StopReason::NetworkChanged)?;
    assert!(lease.reconnection_budget().is_ok());
    let results = [
        Err(RemoteError::Stopped),
        Err(RemoteError::Authorization(
            nestlink_protocol::ContractError::new(
                nestlink_protocol::ErrorCode::PermissionRequired,
                "stopped lease",
            ),
        )),
        Err(RemoteError::Io(io::Error::new(
            io::ErrorKind::Interrupted,
            "caller cancelled I/O",
        ))),
        Ok(()),
    ];
    for result in results {
        stop_io_result(&lease, &result);
        assert!(lease.reconnection_budget().is_ok());
    }
    drop(StopOnDrop(lease.clone()));
    let receiver = ChannelReceiver {
        lease: lease.clone(),
        incoming: Queue::new(),
        channel: Channel::FileRead,
        stop_on_drop: true,
    };
    drop(receiver);
    assert!(lease.reconnection_budget().is_ok());
    assert_eq!(
        lease
            .subscribe_stopped()
            .borrow()
            .as_ref()
            .ok_or("stop report missing")?
            .reason,
        StopReason::NetworkChanged
    );
    // A new explicit revocation still supersedes eligibility, even though the
    // diagnostic first stop remains NetworkChanged.
    lease.stop(StopReason::Revoked)?;
    assert!(lease.reconnection_budget().is_err());
    Ok(())
}
#[tokio::test]
async fn genuine_live_file_permission_and_protocol_failures_forbid_recovery() -> Result {
    for protocol in [false, true] {
        let (session, clock) = active()?;
        let (_keep, stopped) = watch::channel(None);
        let lease = LeaseControl::new(
            session,
            Path::Direct,
            clock,
            crate::SessionLifecycle::new(stopped),
        )?;
        let result: std::result::Result<(), RemoteError> = if protocol {
            Err(io::Error::new(io::ErrorKind::InvalidData, "invalid authenticated frame").into())
        } else {
            Err(nestlink_protocol::ContractError::new(
                nestlink_protocol::ErrorCode::PermissionRequired,
                "FileRead denied",
            )
            .into())
        };
        stop_io_result(&lease, &result);
        assert_eq!(
            lease
                .subscribe_stopped()
                .borrow()
                .as_ref()
                .ok_or("stop report missing")?
                .reason,
            if protocol {
                StopReason::ProtocolViolation
            } else {
                StopReason::Revoked
            }
        );
        assert!(lease.reconnection_budget().is_err());
    }
    Ok(())
}
