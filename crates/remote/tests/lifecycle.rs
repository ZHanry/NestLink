use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_platform_network::{NetworkState, Reason};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims};
use nestlink_remote::{
    AuthorizedConnection, CleanupStatus, LeaseControl, NetworkBinding, RemoteError, RuntimeClock,
    SessionLifecycle,
    input::{
        Button, InputAction, InputController, InputDevice, InputEpoch, InputEvent, InputLayout,
        PlatformInput,
    },
    video::{CaptureDevice, Display, RawFrame, VideoController, VideoEpoch},
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_stream::{Channel, read_frame, write_frame};
use prost::Message;
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, split},
    sync::watch,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn active(lifetime: u64) -> Result<(Session, RuntimeClock, PermitSigner, PermitClaims)> {
    active_with_permissions(
        lifetime,
        vec![
            Permission::View,
            Permission::Input,
            Permission::Audio,
            Permission::FileRead,
            Permission::FileWrite,
            Permission::ClipboardRead,
            Permission::ClipboardWrite,
        ],
    )
}
fn active_with_permissions(
    lifetime: u64,
    permissions: Vec<Permission>,
) -> Result<(Session, RuntimeClock, PermitSigner, PermitClaims)> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
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
        expires_at_unix_ms: now.unix_ms + lifetime,
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
    Ok((session, clock, signer, claims))
}

#[tokio::test]
async fn input_permit_observer_publishes_only_accepted_signed_renewals() -> Result {
    let (session, clock, signer, mut claims) = active(15000)?;
    let (_stop, receiver) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock.clone(),
        SessionLifecycle::new(receiver),
    )?;
    let mut permits = lease.subscribe_input_permits()?;
    let initial = permits
        .borrow_and_update()
        .clone()
        .ok_or("missing initial input permit")?;
    let original = verify_permit(initial.signed_envelope(), &signer.public_key())?;
    assert_eq!(original.claims().lease_sequence, 1);
    let deadline = lease.input_permit_deadline(&initial)?;
    assert!(lease.renew(initial.clone(), clock.monotonic_ms()).is_err());
    assert!(!permits.has_changed()?);
    assert_eq!(lease.input_permit_deadline(&initial)?, deadline);
    tokio::time::sleep(Duration::from_millis(3)).await;
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms = clock.sample()?.unix_ms;
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 15000;
    let envelope = signer.sign(&claims)?.encode_to_vec();
    lease.renew(
        verify_permit(&envelope, &signer.public_key())?,
        clock.monotonic_ms(),
    )?;
    permits.changed().await?;
    let renewed = permits
        .borrow_and_update()
        .clone()
        .ok_or("missing accepted renewal")?;
    assert_eq!(renewed.signed_envelope(), envelope);
    assert_eq!(renewed.claims().lease_sequence, 2);
    lease.stop(StopReason::ExplicitExit)?;
    permits.changed().await?;
    assert!(permits.borrow_and_update().is_none());
    assert!(lease.renew(renewed, clock.monotonic_ms()).is_err());
    assert!(lease.subscribe_input_permits().is_err());
    assert!(permits.borrow().is_none());
    Ok(())
}

struct InputPermitCleanupObserver {
    permits: watch::Receiver<Option<nestlink_identity::VerifiedPermit>>,
    revoked_before_cleanup: Arc<std::sync::atomic::AtomicBool>,
}
impl InputDevice for InputPermitCleanupObserver {
    fn inject(&mut self, _: PlatformInput<'_>) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.revoked_before_cleanup.store(
            self.permits.borrow().is_none(),
            std::sync::atomic::Ordering::Release,
        );
        Ok(())
    }
}

#[tokio::test]
async fn input_permit_revocation_precedes_synchronous_platform_cleanup() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_stop, receiver) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock,
        SessionLifecycle::new(receiver),
    )?;
    let permits = lease.subscribe_input_permits()?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _controller = InputController::attach(
        lease.clone(),
        InputPermitCleanupObserver {
            permits,
            revoked_before_cleanup: observed.clone(),
        },
        epoch(),
        layout(),
    )?;
    lease.stop(StopReason::Revoked)?;
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn input_permit_observation_cannot_extend_the_original_local_deadline() -> Result {
    let (mut session, clock, _, _) = active(15000)?;
    session.cap_deadline_ms(clock.monotonic_ms() + 100)?;
    let (_stop, receiver) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock,
        SessionLifecycle::new(receiver),
    )?;
    let mut permits = lease.subscribe_input_permits()?;
    let initial = permits
        .borrow_and_update()
        .clone()
        .ok_or("missing initial input permit")?;
    let deadline = lease.input_permit_deadline(&initial)?;
    for _ in 0..3 {
        let observed = lease.subscribe_input_permits()?;
        assert_eq!(
            lease
                .input_permit_deadline(observed.borrow().as_ref().ok_or("missing input permit")?)?,
            deadline
        );
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if permits.borrow_and_update().is_none() {
                break Ok::<_, watch::error::RecvError>(());
            }
            permits.changed().await?;
        }
    })
    .await??;
    assert!(lease.subscribe_input_permits().is_err());
    assert!(lease.input_permit_deadline(&initial).is_err());
    assert!(permits.borrow().is_none());
    Ok(())
}

#[tokio::test]
async fn view_only_session_cannot_observe_an_input_permit() -> Result {
    let (session, clock, _, _) = active_with_permissions(15000, vec![Permission::View])?;
    let (_stop, receiver) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock,
        SessionLifecycle::new(receiver),
    )?;
    assert!(lease.subscribe_input_permits().is_err());
    lease.stop(StopReason::ExplicitExit)?;
    Ok(())
}

#[tokio::test]
async fn claimed_audio_is_exclusive_and_does_not_enter_the_fallback_receiver() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (mut peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let mut audio = runtime.claim_channel(Channel::Audio)?;
    assert!(runtime.claim_channel(Channel::Audio).is_err());
    assert!(runtime.claim_channel(Channel::Control).is_err());
    write_frame(&mut peer, Channel::Audio, b"exclusive-audio").await?;
    write_frame(&mut peer, Channel::FileRead, b"fallback-file").await?;
    let fallback = tokio::time::timeout(Duration::from_secs(1), runtime.receive()).await??;
    assert_eq!(
        (fallback.channel, fallback.payload.as_slice()),
        (Channel::FileRead, &b"fallback-file"[..])
    );
    let claimed = tokio::time::timeout(Duration::from_secs(1), audio.receive()).await??;
    assert_eq!(
        (claimed.channel, claimed.payload.as_slice()),
        (Channel::Audio, &b"exclusive-audio"[..])
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), runtime.receive())
            .await
            .is_err()
    );
    drop(audio);
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::ExplicitExit);
    assert!(runtime.claim_channel(Channel::Audio).is_err());
    Ok(())
}

// A gate in the actual InputDevice fact check holds the real managed + input
// state locks. Only the designated calling thread blocks; the gate cannot be
// accidentally consumed by the lease supervisor before the operation starts.
struct OriginalInputWindowGate {
    target: Arc<Mutex<Option<std::thread::ThreadId>>>,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    actions: Arc<std::sync::atomic::AtomicUsize>,
}

impl InputDevice for OriginalInputWindowGate {
    fn check(&mut self) -> io::Result<()> {
        let block = {
            let mut target = self
                .target
                .lock()
                .map_err(|_| io::Error::other("gate poisoned"))?;
            if *target == Some(std::thread::current().id()) {
                target.take();
                true
            } else {
                false
            }
        };
        if block {
            self.entered.send(()).map_err(io::Error::other)?;
            self.release
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        if matches!(input, PlatformInput::Action(_)) {
            self.actions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}

fn original_input_deadline_after_lock_wait(wall_expiry: bool) -> Result {
    let (mut session, clock, signer, mut claims) = active(if wall_expiry { 1000 } else { 15000 })?;
    if !wall_expiry {
        session.cap_deadline_ms(clock.monotonic_ms() + 1000)?;
    }
    let original = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
    let (_stop_owner, stop) = watch::channel(None);
    let lease = LeaseControl::from_proved_session(
        session,
        Path::Direct,
        clock.clone(),
        SessionLifecycle::new(stop),
    )?;
    let old_deadline = lease.input_permit_deadline(&original)?;
    let old_wall_expiry = claims.expires_at_unix_ms;
    // Install a genuine signed renewal while the original window is still live.
    std::thread::sleep(Duration::from_millis(3));
    claims.lease_sequence += 1;
    claims.issued_at_unix_ms = clock.sample()?.unix_ms;
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 15000;
    let current = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
    lease.renew(current.clone(), clock.monotonic_ms())?;
    let current_deadline = lease.input_permit_deadline(&current)?;
    assert!(current_deadline > old_deadline);

    let target = Arc::new(Mutex::new(None));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let actions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let input = Arc::new(InputController::attach(
        lease.clone(),
        OriginalInputWindowGate {
            target: target.clone(),
            entered: entered_tx,
            release: release_rx,
            actions: actions.clone(),
        },
        epoch(),
        layout(),
    )?);
    // The second case independently exercises the signed wall limit, even if a
    // caller supplies a longer monotonic horizon. It still cannot extend the
    // current lease's own authorization or monotonic deadline.
    let retained_deadline = if wall_expiry {
        current_deadline
    } else {
        old_deadline
    };
    let worker_input = input.clone();
    let worker_clock = clock.clone();
    let worker = std::thread::spawn(move || {
        assert!(std::time::Instant::now() < retained_deadline);
        assert!(worker_clock.sample()?.unix_ms < old_wall_expiry);
        *target
            .lock()
            .map_err(|_| io::Error::other("gate poisoned"))? = Some(std::thread::current().id());
        worker_input.apply_with_deadline(
            &InputEvent {
                epoch: epoch(),
                sequence: 1,
                action: InputAction::Text("expired queued input".into()),
            },
            retained_deadline,
            old_wall_expiry,
        )
    });
    // The worker has passed its initial time checks and is now blocked inside
    // the real operation's platform locks while the newer permit stays active.
    entered_rx.recv_timeout(Duration::from_secs(2))?;
    if wall_expiry {
        while clock.sample()?.unix_ms < old_wall_expiry {
            std::thread::sleep(Duration::from_millis(5));
        }
    } else {
        std::thread::sleep(
            old_deadline.saturating_duration_since(std::time::Instant::now())
                + Duration::from_millis(5),
        );
    }
    release_tx.send(())?;
    let result = worker
        .join()
        .map_err(|_| io::Error::other("input worker panicked"))?;
    assert!(
        matches!(result, Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(actions.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(lease.subscribe_stopped().borrow().is_none());
    assert!(lease.input_permit_deadline(&current)? > std::time::Instant::now());
    // Rejection must not consume sequence one. The same live controller can
    // still accept the next frame under the actually installed current permit.
    assert!(input.apply_with_deadline(
        &InputEvent {
            epoch: epoch(),
            sequence: 1,
            action: InputAction::Text("current input".into()),
        },
        current_deadline,
        current.claims().expires_at_unix_ms
    )?);
    assert_eq!(actions.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn input_original_monotonic_deadline_is_rechecked_after_platform_lock_wait() -> Result {
    original_input_deadline_after_lock_wait(false)
}

#[tokio::test]
async fn input_original_wall_expiry_is_rechecked_after_platform_lock_wait() -> Result {
    original_input_deadline_after_lock_wait(true)
}

#[tokio::test]
async fn actual_idle_eof_retains_local_budget_and_a_later_external_revoke_prevents_reconnection()
-> Result {
    let (mut session, clock, _, _) = active(15000)?;
    session.cap_deadline_ms(clock.monotonic_ms() + 200)?;
    let (revoke, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let sender = runtime.sender();
    drop(peer);
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::TransportLost);
    let budget = runtime.lease_control().reconnection_budget()?;
    assert!(budget.deadline() <= std::time::Instant::now() + Duration::from_millis(200));
    assert!(
        sender
            .send(Channel::Video, b"closed generation")
            .await
            .is_err()
    );
    revoke.send_replace(Some(StopReason::Revoked));
    assert!(runtime.lease_control().reconnection_budget().is_err());
    Ok(())
}
#[tokio::test]
async fn malformed_real_stream_and_failed_platform_cleanup_cannot_reconnect() -> Result {
    for failure in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (mut peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut lifecycle = SessionLifecycle::new(stop);
        if failure {
            lifecycle.resources = Some(Box::new(FailedRecoveryCleanup));
        }
        let mut runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            Path::Direct,
            clock,
            lifecycle,
        )?
        .into_channels();
        if failure {
            drop(peer);
        } else {
            tokio::io::AsyncWriteExt::write_all(&mut peer, &[9]).await?;
        }
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(
            report.reason,
            if failure {
                StopReason::TransportLost
            } else {
                StopReason::ProtocolViolation
            }
        );
        assert!(runtime.lease_control().reconnection_budget().is_err());
    }
    Ok(())
}
struct FailedRecoveryCleanup;
impl nestlink_remote::StopHandler for FailedRecoveryCleanup {
    fn stop(&mut self, _: StopReason, _: nestlink_session::StopEffects) -> io::Result<()> {
        Err(io::Error::other("owned test cleanup failed"))
    }
}

#[tokio::test]
async fn later_resume_or_closed_network_observer_invalidates_an_existing_reconnection_budget()
-> Result {
    for resumed in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (facts, network) = watch::channel(NetworkState {
            generation: 5,
            available: true,
            reason: Reason::Started,
        });
        let (_keep, stop) = watch::channel(None);
        let mut lifecycle = SessionLifecycle::new(stop);
        lifecycle.network = Some(NetworkBinding::new(network, 5)?);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            Path::Direct,
            clock,
            lifecycle,
        )?
        .into_channels();
        facts.send_replace(NetworkState {
            generation: 6,
            available: true,
            reason: Reason::Address,
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped())
                .await??
                .reason,
            StopReason::NetworkChanged
        );
        runtime.lease_control().reconnection_budget()?;
        if resumed {
            facts.send_replace(NetworkState {
                generation: 7,
                available: true,
                reason: Reason::Resumed,
            });
        } else {
            drop(facts);
        }
        assert!(runtime.lease_control().reconnection_budget().is_err());
        // New facts invalidate retry but cannot rewrite the first stop receipt.
        assert_eq!(
            runtime.wait_stopped().await?.reason,
            StopReason::NetworkChanged
        );
    }
    Ok(())
}

#[tokio::test]
async fn later_carrier_protocol_failure_or_observer_close_invalidates_retry_budget() -> Result {
    for failure in [
        Some(io::ErrorKind::InvalidData),
        Some(io::ErrorKind::InvalidInput),
        Some(io::ErrorKind::PermissionDenied),
        None,
    ] {
        let (session, clock, _, _) = active(15000)?;
        let (facts, network) = watch::channel(NetworkState {
            generation: 5,
            available: true,
            reason: Reason::Started,
        });
        let (_keep, stop) = watch::channel(None);
        let (carrier_sender, carrier) = watch::channel(None);
        let mut lifecycle = SessionLifecycle::new(stop);
        lifecycle.network = Some(NetworkBinding::new(network, 5)?);
        lifecycle.carrier = Some(carrier);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            Path::Direct,
            clock,
            lifecycle,
        )?
        .into_channels();
        facts.send_replace(NetworkState {
            generation: 6,
            available: true,
            reason: Reason::Address,
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped())
                .await??
                .reason,
            StopReason::NetworkChanged
        );
        runtime.lease_control().reconnection_budget()?;
        if let Some(kind) = failure {
            carrier_sender.send_replace(Some(kind));
        } else {
            drop(carrier_sender);
        }
        assert!(runtime.lease_control().reconnection_budget().is_err());
        assert_eq!(
            runtime.wait_stopped().await?.reason,
            StopReason::NetworkChanged
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_current_transport_loss_remains_reconnectable_while_its_observer_is_live() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (carrier_sender, carrier) = watch::channel(None);
    let mut lifecycle = SessionLifecycle::new(stop);
    lifecycle.carrier = Some(carrier);
    let (_peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::with_lifecycle(read, write, session, Path::Direct, clock, lifecycle)?
            .into_channels();
    carrier_sender.send_replace(Some(io::ErrorKind::ConnectionReset));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped())
            .await??
            .reason,
        StopReason::TransportLost
    );
    runtime.lease_control().reconnection_budget()?;
    Ok(())
}

#[tokio::test]
async fn later_direct_revocation_forbids_reconnect_without_rewriting_first_report() -> Result {
    let (session, clock, _, claims) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let control = runtime.lease_control();
    let mut stopped = control.subscribe_stopped();
    control.stop(StopReason::NetworkChanged)?;
    stopped.changed().await?;
    assert_eq!(
        stopped.borrow().as_ref().map(|report| report.reason),
        Some(StopReason::NetworkChanged)
    );
    assert!(
        control
            .check_channel_binding(Channel::Video, claims.connection_generation)
            .is_err()
    );
    control.reconnection_budget()?;
    control.stop(StopReason::Revoked)?;
    assert!(control.reconnection_budget().is_err());
    assert_eq!(
        stopped.borrow().as_ref().map(|report| report.reason),
        Some(StopReason::NetworkChanged)
    );
    Ok(())
}

#[tokio::test]
async fn idle_file_retirement_discards_late_file_frames_and_preserves_viewing() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (mut peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    nestlink_remote::files::FileReadClient::attach(&mut runtime, 9)?.retire()?;
    assert!(runtime.claim_channel(Channel::FileRead).is_err());
    for _ in 0..16 {
        write_frame(&mut peer, Channel::FileRead, b"retired-file-reply").await?;
    }
    write_frame(&mut peer, Channel::Video, b"still-viewing").await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), runtime.receive()).await??;
    assert_eq!(frame.channel, Channel::Video);
    assert_eq!(frame.payload, b"still-viewing");
    runtime
        .lease_control()
        .check_media_binding(Channel::Video, 9)?;
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn independent_revoke_interrupts_both_claimed_and_fallback_waiters() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (revoke, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let mut audio = runtime.claim_channel(Channel::Audio)?;
    let cancelling = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        revoke.send_replace(Some(StopReason::Revoked));
    };
    let (claimed, fallback, ()) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), audio.receive()),
        tokio::time::timeout(Duration::from_secs(1), runtime.receive()),
        cancelling
    );
    assert!(claimed?.is_err());
    assert!(fallback?.is_err());
    assert_eq!(runtime.wait_stopped().await?.reason, StopReason::Revoked);
    Ok(())
}

#[tokio::test]
async fn claimed_audio_queue_retains_eight_latest_packets_and_expires_old_ones() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (mut peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let mut audio = runtime.claim_channel(Channel::Audio)?;
    for value in 1..=12 {
        write_frame(&mut peer, Channel::Audio, &[value]).await?;
    }
    write_frame(&mut peer, Channel::FileRead, b"queue-barrier").await?;
    // The ordered stream reader must have inserted all previous audio before
    // this separate fallback message is available. No arbitrary sleep races.
    assert_eq!(runtime.receive().await?.payload, b"queue-barrier");
    for value in 5..=12 {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), audio.receive())
                .await??
                .payload,
            [value]
        );
    }
    write_frame(&mut peer, Channel::Audio, b"expires").await?;
    write_frame(&mut peer, Channel::FileRead, b"age-barrier").await?;
    assert_eq!(runtime.receive().await?.payload, b"age-barrier");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), audio.receive())
            .await
            .is_err()
    );
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[derive(Default)]
struct AudioLog {
    polls: usize,
    enqueued_pts: Vec<u64>,
    resets: usize,
    pending: std::collections::VecDeque<nestlink_remote::audio::CapturedAudio>,
}
struct AudioDevice {
    log: Arc<Mutex<AudioLog>>,
    healthy: Arc<std::sync::atomic::AtomicBool>,
    reset_failure: bool,
    panic_enqueue: bool,
}
impl nestlink_remote::audio::AudioDevice for AudioDevice {
    fn check(&mut self) -> io::Result<()> {
        if self.healthy.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            Err(io::Error::other("owned audio endpoint changed"))
        }
    }
    fn reset(&mut self) -> io::Result<()> {
        let mut log = self
            .log
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        log.resets += 1;
        log.pending.clear();
        if self.reset_failure {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned reset timeout",
            ))
        } else {
            Ok(())
        }
    }
}
impl nestlink_remote::audio::AudioCaptureDevice for AudioDevice {
    fn poll_chunk(&mut self) -> io::Result<Option<nestlink_remote::audio::CapturedAudio>> {
        let mut log = self
            .log
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        log.polls += 1;
        Ok(log.pending.pop_front())
    }
}
impl nestlink_remote::audio::AudioPlaybackDevice for AudioDevice {
    fn enqueue(&mut self, chunk: &nestlink_remote::audio::AudioChunk) -> io::Result<()> {
        if self.panic_enqueue {
            panic!("owned platform enqueue failure");
        }
        self.log
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .enqueued_pts
            .push(chunk.pts_48khz);
        Ok(())
    }
}
fn audio_device(log: &Arc<Mutex<AudioLog>>) -> AudioDevice {
    AudioDevice {
        log: log.clone(),
        healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        reset_failure: false,
        panic_enqueue: false,
    }
}
fn audio_binding() -> nestlink_remote::audio::AudioBinding {
    nestlink_remote::audio::AudioBinding {
        connection: 9,
        source: 42,
        channels: 2,
    }
}
fn audio_chunk(pts: u64) -> nestlink_remote::audio::AudioChunk {
    nestlink_remote::audio::AudioChunk {
        source: 42,
        channels: 2,
        pts_48khz: pts,
        samples: vec![123; 1920],
    }
}

#[tokio::test]
async fn audio_requires_permission_generation_and_one_owner_per_direction() -> Result {
    use nestlink_remote::audio::{AudioCaptureController, AudioPlaybackController};
    for permitted in [false, true] {
        let permissions = if permitted {
            vec![Permission::View, Permission::Audio]
        } else {
            vec![Permission::View]
        };
        let (session, clock, _, _) = active_with_permissions(15000, permissions)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let capture_log = Arc::new(Mutex::new(AudioLog::default()));
        let playback_log = Arc::new(Mutex::new(AudioLog::default()));
        let lease = runtime.lease_control();
        if !permitted {
            assert!(runtime.claim_channel(Channel::Audio).is_err());
            assert!(
                AudioCaptureController::attach(
                    lease.clone(),
                    audio_device(&capture_log),
                    audio_binding(),
                )
                .is_err()
            );
            assert!(
                AudioPlaybackController::attach(
                    lease,
                    audio_device(&playback_log),
                    audio_binding(),
                )
                .is_err()
            );
            for log in [&capture_log, &playback_log] {
                let state = log.lock().map_err(|_| "poisoned")?;
                assert_eq!(state.polls, 0);
                assert!(state.enqueued_pts.is_empty());
                assert_eq!(state.resets, 1, "a denied device must still be reset");
            }
        } else {
            let wrong_log = Arc::new(Mutex::new(AudioLog::default()));
            let duplicate_capture_log = Arc::new(Mutex::new(AudioLog::default()));
            let duplicate_playback_log = Arc::new(Mutex::new(AudioLog::default()));
            let mut wrong = audio_binding();
            wrong.connection = 8;
            assert!(
                AudioCaptureController::attach(lease.clone(), audio_device(&wrong_log), wrong)
                    .is_err()
            );
            let capture = AudioCaptureController::attach(
                lease.clone(),
                audio_device(&capture_log),
                audio_binding(),
            )?;
            let playback = AudioPlaybackController::attach(
                lease.clone(),
                audio_device(&playback_log),
                audio_binding(),
            )?;
            assert!(
                AudioCaptureController::attach(
                    lease.clone(),
                    audio_device(&duplicate_capture_log),
                    audio_binding(),
                )
                .is_err()
            );
            assert!(
                AudioPlaybackController::attach(
                    lease,
                    audio_device(&duplicate_playback_log),
                    audio_binding(),
                )
                .is_err()
            );
            for log in [&wrong_log, &duplicate_capture_log, &duplicate_playback_log] {
                let state = log.lock().map_err(|_| "poisoned")?;
                assert_eq!(state.resets, 1, "each rejected owner resets its own device");
                assert_eq!(state.polls, 0);
                assert!(state.enqueued_pts.is_empty());
            }
            assert_eq!(capture_log.lock().map_err(|_| "poisoned")?.resets, 0);
            assert_eq!(playback_log.lock().map_err(|_| "poisoned")?.resets, 0);
            playback.play(&audio_chunk(0))?;
            drop(capture);
            assert!(playback.play(&audio_chunk(960)).is_err());
            assert_eq!(
                runtime.wait_stopped().await?.cleanup,
                CleanupStatus::Succeeded
            );
            assert_eq!(capture_log.lock().map_err(|_| "poisoned")?.resets, 1);
            let playback_state = playback_log.lock().map_err(|_| "poisoned")?;
            assert_eq!(playback_state.resets, 1);
            assert_eq!(playback_state.enqueued_pts, [0]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn audio_drops_old_capture_but_clock_change_and_endpoint_loss_are_terminal() -> Result {
    use nestlink_remote::audio::{AudioCaptureController, CapturedAudio};
    use std::time::Instant;
    for invalid_clock in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let log = Arc::new(Mutex::new(AudioLog::default()));
        log.lock().map_err(|_| "poisoned")?.pending.extend([
            CapturedAudio {
                captured_at: Instant::now() - Duration::from_millis(150),
                chunk: audio_chunk(0),
            },
            CapturedAudio {
                captured_at: Instant::now(),
                chunk: audio_chunk(960),
            },
        ]);
        let device = audio_device(&log);
        let healthy = device.healthy.clone();
        let capture =
            AudioCaptureController::attach(runtime.lease_control(), device, audio_binding())?;
        assert!(capture.poll()?.is_none());
        assert_eq!(capture.poll()?.ok_or("missing PCM")?.chunk.pts_48khz, 960);
        if invalid_clock {
            log.lock()
                .map_err(|_| "poisoned")?
                .pending
                .push_back(CapturedAudio {
                    captured_at: Instant::now(),
                    chunk: audio_chunk(960),
                });
            assert!(capture.poll().is_err());
        } else {
            healthy.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged);
        healthy.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(capture.poll().is_err());
        assert_eq!(log.lock().map_err(|_| "poisoned")?.resets, 1);
    }
    Ok(())
}

#[tokio::test]
async fn audio_enqueue_panic_and_invalid_pcm_keep_cleanup_available_and_errors_visible() -> Result {
    use nestlink_remote::audio::AudioPlaybackController;
    for panic_enqueue in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let log = Arc::new(Mutex::new(AudioLog::default()));
        let mut device = audio_device(&log);
        device.panic_enqueue = panic_enqueue;
        device.reset_failure = true;
        let playback =
            AudioPlaybackController::attach(runtime.lease_control(), device, audio_binding())?;
        let mut chunk = audio_chunk(0);
        if !panic_enqueue {
            chunk.samples.pop();
        }
        assert!(playback.play(&chunk).is_err());
        let report = runtime.wait_stopped().await?;
        assert_eq!(
            report.cleanup,
            CleanupStatus::Failed(io::ErrorKind::TimedOut)
        );
        assert_eq!(log.lock().map_err(|_| "poisoned")?.resets, 1);
        assert!(playback.play(&audio_chunk(960)).is_err());
        assert!(log.lock().map_err(|_| "poisoned")?.enqueued_pts.is_empty());
    }
    Ok(())
}
struct Device {
    log: Arc<Mutex<Vec<String>>>,
    fail_release: bool,
    fail_press: bool,
}
impl InputDevice for Device {
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let value = match input {
            PlatformInput::Action(action) => format!("action:{action:?}"),
            PlatformInput::Release(button) => format!("release:{button:?}"),
        };
        self.log
            .lock()
            .map_err(|_| io::Error::other("test log poisoned"))?
            .push(value);
        if matches!(input, PlatformInput::Release(_)) && self.fail_release
            || matches!(input, PlatformInput::Action(_)) && self.fail_press
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "simulated OS rejection",
            ));
        }
        Ok(())
    }
}
fn epoch() -> InputEpoch {
    InputEpoch {
        input: 1,
        layout: 1,
        connection: 9,
    }
}
fn layout() -> InputLayout {
    InputLayout {
        left: -100,
        top: 0,
        width: 1920,
        height: 1080,
    }
}

struct Capture {
    frames: Arc<Mutex<std::collections::VecDeque<RawFrame>>>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    changed: Arc<std::sync::atomic::AtomicBool>,
    panic_poll: bool,
}
impl CaptureDevice for Capture {
    fn check(&mut self) -> io::Result<()> {
        if self.changed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(io::Error::other("capture format/permission changed"));
        }
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        assert!(!self.panic_poll, "platform capture panic");
        Ok(self
            .frames
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .pop_front())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.frames
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .clear();
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
fn raw_frame(width: u32, height: u32) -> RawFrame {
    RawFrame {
        source: 42,
        width,
        height,
        captured_at: std::time::Instant::now(),
        pixels: vec![255; (width * height * 4) as usize],
    }
}

struct RejectedCapture {
    resets: Arc<std::sync::atomic::AtomicUsize>,
    fail_reset: bool,
}

fn recovery_business_owners(lease: &LeaseControl) -> Result<Vec<Box<dyn std::any::Any>>> {
    use nestlink_remote::audio::{AudioCaptureController, AudioPlaybackController};
    let input = InputController::attach(
        lease.clone(),
        Device {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_release: false,
            fail_press: false,
        },
        epoch(),
        layout(),
    )?;
    let video = VideoController::attach(
        lease.clone(),
        RejectedCapture {
            resets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail_reset: false,
        },
        VideoEpoch {
            connection: 9,
            layout: 1,
        },
        vec![Display {
            source: 42,
            logical: layout(),
        }],
    )?;
    let capture_log = Arc::new(Mutex::new(AudioLog::default()));
    let playback_log = Arc::new(Mutex::new(AudioLog::default()));
    let capture =
        AudioCaptureController::attach(lease.clone(), audio_device(&capture_log), audio_binding())?;
    let playback = AudioPlaybackController::attach(
        lease.clone(),
        audio_device(&playback_log),
        audio_binding(),
    )?;
    Ok(vec![
        Box::new(input),
        Box::new(video),
        Box::new(capture),
        Box::new(playback),
    ])
}

#[tokio::test]
async fn dropping_cleaned_business_owners_preserves_the_original_recovery_budget() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let lease = runtime.lease_control();
    let owners = recovery_business_owners(&lease)?;
    drop(peer);
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::TransportLost);
    assert_eq!(report.cleanup, CleanupStatus::Succeeded);
    let original = lease.reconnection_budget()?;
    for owner in owners {
        drop(owner);
        let retained = lease.reconnection_budget()?;
        assert_eq!(retained.deadline(), original.deadline());
        assert_eq!(retained.permit().digest(), original.permit().digest());
    }
    lease.stop(StopReason::ExplicitExit)?;
    assert!(lease.reconnection_budget().is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_any_running_business_owner_still_forbids_recovery() -> Result {
    for index in 0..4 {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(4096);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let lease = runtime.lease_control();
        let mut owners = recovery_business_owners(&lease)?;
        drop(owners.remove(index));
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::ExplicitExit);
        assert_eq!(report.cleanup, CleanupStatus::Succeeded);
        assert!(lease.reconnection_budget().is_err());
    }
    Ok(())
}

impl CaptureDevice for RejectedCapture {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        Ok(None)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_reset {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "capture reset did not finish",
            ))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn rejected_capture_is_reset_and_failed_cleanup_is_reported() -> Result {
    for mode in 0..3 {
        for fail_reset in [false, true] {
            let (session, clock, _, _) = active(15000)?;
            let (_keep, stop) = watch::channel(None);
            let (_peer, stream) = tokio::io::duplex(64);
            let (read, write) = split(stream);
            let runtime =
                AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                    .into_channels();
            let lease = runtime.lease_control();
            if mode == 2 {
                // The OS device finished opening after this lease stopped.
                lease.stop(StopReason::Revoked)?;
            }
            let resets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let result = VideoController::attach(
                lease,
                RejectedCapture {
                    resets: resets.clone(),
                    fail_reset,
                },
                VideoEpoch {
                    layout: if mode == 0 { 0 } else { 1 },
                    connection: if mode == 1 { 8 } else { 9 },
                },
                vec![Display {
                    source: 42,
                    logical: layout(),
                }],
            );
            assert!(result.is_err());
            assert_eq!(resets.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(matches!(result, Err(RemoteError::Cleanup(_))), fail_reset);
        }
    }
    Ok(())
}

#[tokio::test]
async fn capture_lease_binding_logical_scaling_expired_frames_and_revocation() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (revoke, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let frames = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let display = Display {
        source: 42,
        logical: InputLayout {
            left: -100,
            top: -20,
            width: 4,
            height: 2,
        },
    };
    let wrong = VideoController::attach(
        runtime.lease_control(),
        Capture {
            frames: frames.clone(),
            stopped: stopped.clone(),
            changed: changed.clone(),
            panic_poll: false,
        },
        VideoEpoch {
            layout: 1,
            connection: 8,
        },
        vec![display],
    );
    assert!(wrong.is_err());
    assert!(stopped.swap(false, std::sync::atomic::Ordering::SeqCst));
    let capture = VideoController::attach(
        runtime.lease_control(),
        Capture {
            frames: frames.clone(),
            stopped: stopped.clone(),
            changed: changed.clone(),
            panic_poll: false,
        },
        VideoEpoch {
            layout: 1,
            connection: 9,
        },
        vec![display],
    )?;
    let mut expired = raw_frame(8, 4);
    expired.captured_at -= Duration::from_secs(1);
    frames.lock().map_err(|_| "poisoned")?.push_back(expired);
    assert!(capture.poll()?.is_none());
    frames
        .lock()
        .map_err(|_| "poisoned")?
        .push_back(raw_frame(8, 4));
    let video = capture.poll()?.ok_or("frame missing")?;
    assert_eq!(video.logical_point(4, 2)?, (-98, -19));
    assert_eq!(video.logical_point(7, 3)?, (-97, -19));
    assert!(video.logical_point(8, 0).is_err());
    assert_eq!(
        video.epoch,
        VideoEpoch {
            layout: 1,
            connection: 9
        }
    );
    frames
        .lock()
        .map_err(|_| "poisoned")?
        .push_back(raw_frame(8, 4));
    revoke.send_replace(Some(StopReason::Revoked));
    assert!(capture.poll().is_err());
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::Revoked);
    assert_eq!(report.cleanup, CleanupStatus::Succeeded);
    assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
    assert!(frames.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn idle_capture_change_poll_panic_and_pixel_geometry_failure_preserve_cleanup() -> Result {
    for mode in 0..3 {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(64);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let frames = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let capture = VideoController::attach(
            runtime.lease_control(),
            Capture {
                frames: frames.clone(),
                stopped: stopped.clone(),
                changed: changed.clone(),
                panic_poll: mode == 1,
            },
            VideoEpoch {
                layout: 1,
                connection: 9,
            },
            vec![Display {
                source: 42,
                logical: layout(),
            }],
        )?;
        if mode == 0 {
            changed.store(true, std::sync::atomic::Ordering::SeqCst);
        } else if mode == 1 {
            assert!(capture.poll().is_err());
        } else {
            frames
                .lock()
                .map_err(|_| "poisoned")?
                .push_back(raw_frame(2, 2));
            assert!(capture.poll()?.is_some());
            frames
                .lock()
                .map_err(|_| "poisoned")?
                .push_back(raw_frame(4, 2));
            assert!(capture.poll().is_err());
        }
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged);
        assert_eq!(report.cleanup, CleanupStatus::Succeeded);
        assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
    }
    Ok(())
}

struct ChangingDevice {
    device: Device,
    changed: Arc<std::sync::atomic::AtomicBool>,
    panic_check: bool,
}
impl InputDevice for ChangingDevice {
    fn check(&mut self) -> io::Result<()> {
        if self.changed.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(!self.panic_check, "simulated platform fact panic");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "platform permission revoked",
            ));
        }
        Ok(())
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        self.device.inject(input)
    }
}

#[tokio::test]
async fn idle_platform_error_or_panic_releases_input_without_poisoning_state() -> Result {
    for panic_check in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (_stop, stopped) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(64);
        let (read, write) = split(stream);
        let mut runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            Path::Direct,
            clock,
            SessionLifecycle::new(stopped),
        )?
        .into_channels();
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let input = InputController::attach(
            runtime.lease_control(),
            ChangingDevice {
                device: Device {
                    log: log.clone(),
                    fail_release: false,
                    fail_press: false,
                },
                changed: changed.clone(),
                panic_check,
            },
            epoch(),
            layout(),
        )?;
        input.apply(&InputEvent {
            epoch: epoch(),
            sequence: 1,
            action: InputAction::Key {
                code: 4,
                down: true,
            },
        })?;
        changed.store(true, std::sync::atomic::Ordering::SeqCst);
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged);
        assert_eq!(report.cleanup, CleanupStatus::Succeeded);
        assert!(
            log.lock()
                .map_err(|_| "test log poisoned")?
                .contains(&"release:Key(4)".into())
        );
        assert!(
            input
                .apply(&InputEvent {
                    epoch: epoch(),
                    sequence: 2,
                    action: InputAction::Key {
                        code: 4,
                        down: true
                    }
                })
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn idle_resume_releases_keys_and_pointer_and_closes_owned_transport() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (facts, network) = watch::channel(NetworkState {
        generation: 5,
        available: true,
        reason: Reason::Started,
    });
    let (stop, stopped) = watch::channel(None);
    let mut lifecycle = SessionLifecycle::new(stopped);
    lifecycle.network = Some(NetworkBinding::new(network, 5)?);
    let (mut peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::with_lifecycle(read, write, session, Path::Direct, clock, lifecycle)?
            .into_channels();
    let log = Arc::new(Mutex::new(Vec::new()));
    let input = InputController::attach(
        runtime.lease_control(),
        Device {
            log: log.clone(),
            fail_release: false,
            fail_press: false,
        },
        epoch(),
        layout(),
    )?;
    for (sequence, action) in [
        (
            1,
            InputAction::Key {
                code: 4,
                down: true,
            },
        ),
        (
            2,
            InputAction::Pointer {
                button: Some(1),
                down: true,
                x: -5,
                y: 10,
            },
        ),
    ] {
        assert!(input.apply(&InputEvent {
            epoch: epoch(),
            sequence,
            action
        })?);
    }
    facts.send_replace(NetworkState {
        generation: 6,
        available: true,
        reason: Reason::Resumed,
    });
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::Suspended);
    assert_eq!(report.cleanup, CleanupStatus::Succeeded);
    {
        let entries = log.lock().map_err(|_| "test log poisoned")?;
        assert!(entries.contains(&"release:Key(4)".into()));
        assert!(entries.contains(&"release:Pointer(1)".into()));
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
            .await?
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    stop.send_replace(Some(StopReason::ExplicitExit));
    assert_eq!(runtime.wait_stopped().await?.reason, StopReason::Suspended);
    assert!(
        input
            .apply(&InputEvent {
                epoch: epoch(),
                sequence: 3,
                action: InputAction::Text("旧会话".into())
            })
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn partial_file_backpressure_does_not_block_receive_renewal_or_revoke() -> Result {
    let (session, clock, signer, mut claims) = active(15000)?;
    let (revoke, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock.clone(), stop)?
            .into_channels();
    let (mut peer_read, mut peer_write) = split(peer);
    let sender = runtime.sender();
    let (progress, mut count) = watch::channel(0);
    let queued = tokio::spawn(async move {
        for n in 1..100 {
            sender.send(Channel::FileWrite, &[7; 65536]).await?;
            progress.send_replace(n);
        }
        Ok::<_, nestlink_remote::RemoteError>(())
    });
    // Wait until the writer is inside a partial file frame and the reliable
    // outgoing queue is full, without draining its payload.
    assert_eq!(peer_read.read_u8().await?, 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while *count.borrow_and_update() < 5 {
            count.changed().await?;
        }
        Ok::<_, watch::error::RecvError>(())
    })
    .await??;
    write_frame(&mut peer_write, Channel::Input, b"opposite-direction-input").await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), runtime.receive())
            .await??
            .payload,
        b"opposite-direction-input"
    );
    let started = clock.monotonic_ms().max(1);
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms = clock.sample()?.unix_ms;
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 15000;
    runtime.lease_control().renew(
        verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
        started,
    )?;
    revoke.send_replace(Some(StopReason::Revoked));
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::Revoked);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), queued)
            .await??
            .is_err()
    );
    let mut remaining = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        peer_read.read_to_end(&mut remaining),
    )
    .await??;
    assert!(remaining.len() <= 64);
    assert!(runtime.receive().await.is_err());
    assert!(runtime.send(Channel::Input, b"after-revoke").await.is_err());
    Ok(())
}

#[tokio::test]
async fn encoded_video_backpressure_preserves_reference_chain_and_fairness() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let (mut peer_read, _peer_write) = split(peer);
    runtime.send(Channel::FileWrite, &[2; 1024]).await?;
    let mut header = [0; 6];
    peer_read.read_exact(&mut header).await?;
    assert_eq!(header[1], Channel::FileWrite as u8);
    runtime.send(Channel::Video, b"keyframe-1").await?;
    let sender = runtime.sender();
    let (sent, mut progress) = watch::channel(0);
    let producer = tokio::spawn(async move {
        for (index, frame) in [b"delta-2", b"delta-3"].into_iter().enumerate() {
            sender.send(Channel::Video, frame).await?;
            sent.send_replace(index + 1);
        }
        Ok::<_, nestlink_remote::RemoteError>(())
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), progress.changed())
            .await
            .is_err(),
        "a full reference-dependent video queue must backpressure its producer"
    );
    runtime.send(Channel::Input, b"reliable-button").await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut file = [0; 1024];
    peer_read.read_exact(&mut file).await?;
    assert_eq!(file, [2; 1024]);
    let input = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer_read)).await??;
    assert_eq!(input.channel, Channel::Input);
    assert_eq!(input.payload, b"reliable-button");
    for expected in [&b"keyframe-1"[..], b"delta-2", b"delta-3"] {
        let frame =
            tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer_read)).await??;
        assert_eq!(frame.channel, Channel::Video);
        assert_eq!(frame.payload, expected);
    }
    tokio::time::timeout(Duration::from_secs(1), producer).await???;
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn incoming_video_retains_order_and_references_when_consumer_is_slow() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(4096);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let (_peer_read, mut peer_write) = split(peer);
    for payload in [&b"keyframe-1"[..], b"delta-2", b"delta-3"] {
        write_frame(&mut peer_write, Channel::Video, payload).await?;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    for expected in [&b"keyframe-1"[..], b"delta-2", b"delta-3"] {
        let frame = tokio::time::timeout(Duration::from_secs(1), runtime.receive()).await??;
        assert_eq!(frame.channel, Channel::Video);
        assert_eq!(frame.payload, expected);
    }
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn revoke_interrupts_reference_video_backpressure() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (revoke, stop) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let (mut peer_read, _peer_write) = split(peer);
    runtime.send(Channel::FileWrite, &[2; 1024]).await?;
    let mut header = [0; 6];
    peer_read.read_exact(&mut header).await?;
    runtime.send(Channel::Video, b"keyframe-1").await?;
    let sender = runtime.sender();
    let (finished, mut completion) = watch::channel(false);
    let waiting = tokio::spawn(async move {
        let result = sender.send(Channel::Video, b"delta-2").await;
        finished.send_replace(true);
        result
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), completion.changed())
            .await
            .is_err()
    );
    revoke.send_replace(Some(StopReason::Revoked));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await??
            .is_err()
    );
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::Revoked);
    assert!(runtime.receive().await.is_err());
    Ok(())
}

#[tokio::test]
async fn input_epochs_text_idempotency_and_os_failures_cannot_leave_pressed_keys() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (mut peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let log = Arc::new(Mutex::new(Vec::new()));
    let input = InputController::attach(
        runtime.lease_control(),
        Device {
            log: log.clone(),
            fail_release: false,
            fail_press: false,
        },
        epoch(),
        layout(),
    )?;
    let text = InputEvent {
        epoch: epoch(),
        sequence: 1,
        action: InputAction::Text("中文提交".into()),
    };
    for expected in [true, false] {
        write_frame(&mut peer, Channel::Input, &text.encode()?).await?;
        let frame = runtime.receive().await?;
        assert_eq!(input.apply_frame(&frame)?, expected);
    }
    assert!(
        input
            .apply_frame(&nestlink_transport_stream::Frame {
                channel: Channel::Input,
                payload: vec![0xff]
            })
            .is_err()
    );
    assert!(
        input
            .apply(&InputEvent {
                epoch: epoch(),
                sequence: 1,
                action: InputAction::Text("换内容".into())
            })
            .is_err()
    );
    assert!(
        input
            .apply(&InputEvent {
                epoch: epoch(),
                sequence: 2,
                action: InputAction::Pointer {
                    button: Some(1),
                    down: true,
                    x: 99999,
                    y: 10
                }
            })
            .is_err()
    );
    input.apply(&InputEvent {
        epoch: epoch(),
        sequence: 2,
        action: InputAction::Key {
            code: 4,
            down: true,
        },
    })?;
    let new_epoch = input.change_layout(layout())?;
    assert_ne!(new_epoch, epoch());
    assert!(
        !input.apply(&text)?,
        "retired input cannot inject into the new layout"
    );
    assert!(input.apply(&InputEvent {
        epoch: new_epoch,
        sequence: 1,
        action: InputAction::Text("新布局".into())
    })?);
    runtime.shutdown(StopReason::ExplicitExit).await?;
    let log = log.lock().map_err(|_| "test log poisoned")?;
    assert_eq!(log.iter().filter(|v| v.contains("中文提交")).count(), 1);
    assert_eq!(log.iter().filter(|v| *v == "release:Key(4)").count(), 1);
    Ok(())
}

#[tokio::test]
async fn ordered_release_all_is_idempotent_and_cannot_release_a_newer_input_epoch() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (mut peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let log = Arc::new(Mutex::new(Vec::new()));
    let input = InputController::attach(
        runtime.lease_control(),
        Device {
            log: log.clone(),
            fail_release: false,
            fail_press: false,
        },
        epoch(),
        layout(),
    )?;
    input.apply(&InputEvent {
        epoch: epoch(),
        sequence: 1,
        action: InputAction::Key {
            code: 4,
            down: true,
        },
    })?;
    let release = nestlink_protocol::InputCommand {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        input_epoch: epoch().input,
        layout_epoch: epoch().layout,
        connection_generation: epoch().connection,
        sequence: 2,
        action: Some(nestlink_protocol::input_command::Action::ReleaseAll(true)),
    }
    .encode_to_vec();
    for expected in [true, false] {
        write_frame(&mut peer, Channel::Input, &release).await?;
        let frame = runtime.receive().await?;
        assert_eq!(input.apply_frame(&frame)?, expected);
    }
    assert!(
        input
            .apply(&InputEvent {
                epoch: epoch(),
                sequence: 2,
                action: InputAction::Text("sequence collision".into())
            })
            .is_err()
    );
    input.apply(&InputEvent {
        epoch: epoch(),
        sequence: 3,
        action: InputAction::Key {
            code: 5,
            down: true,
        },
    })?;
    let replacement = input.change_layout(layout())?;
    input.apply(&InputEvent {
        epoch: replacement,
        sequence: 1,
        action: InputAction::Key {
            code: 6,
            down: true,
        },
    })?;
    write_frame(&mut peer, Channel::Input, &release).await?;
    let frame = runtime.receive().await?;
    assert!(
        !input.apply_frame(&frame)?,
        "late retired ReleaseAll must be harmless"
    );
    assert!(
        !log.lock()
            .map_err(|_| "input log poisoned")?
            .iter()
            .any(|event| event == "release:Key(6)"),
        "old release must not release a held key in the current epoch"
    );
    runtime.shutdown(StopReason::ExplicitExit).await?;
    let events = log.lock().map_err(|_| "input log poisoned")?;
    for key in [4, 5, 6] {
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &format!("release:Key({key})"))
                .count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_os_press_stops_and_failed_release_is_reported_without_false_success() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    let log = Arc::new(Mutex::new(Vec::new()));
    let input = InputController::attach(
        runtime.lease_control(),
        Device {
            log: log.clone(),
            fail_release: true,
            fail_press: true,
        },
        epoch(),
        layout(),
    )?;
    assert!(
        input
            .apply(&InputEvent {
                epoch: epoch(),
                sequence: 1,
                action: InputAction::Key {
                    code: 4,
                    down: true
                }
            })
            .is_err()
    );
    let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::Revoked);
    assert_eq!(
        report.cleanup,
        CleanupStatus::Failed(io::ErrorKind::PermissionDenied)
    );
    assert!(
        log.lock()
            .map_err(|_| "test log poisoned")?
            .contains(&format!("release:{:?}", Button::Key(4)))
    );
    Ok(())
}

#[tokio::test]
async fn idle_expiry_and_closed_control_observer_stop_without_business_polling() -> Result {
    for expire in [true, false] {
        let (session, clock, _, _) = active(if expire { 400 } else { 15000 })?;
        let (keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(64);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        if !expire {
            drop(keep);
        }
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(
            report.reason,
            if expire {
                StopReason::Expired
            } else {
                StopReason::Revoked
            }
        );
        assert_eq!(report.cleanup, CleanupStatus::NotAttached);
    }
    Ok(())
}

#[tokio::test]
async fn stale_network_baseline_and_wrong_input_connection_are_rejected() -> Result {
    let (facts, network) = watch::channel(NetworkState {
        generation: 6,
        available: true,
        reason: Reason::Started,
    });
    assert!(NetworkBinding::new(network.clone(), 5).is_err());
    drop(facts);
    assert!(NetworkBinding::new(network, 6).is_err());
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, write) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?.into_channels();
    assert!(
        InputController::attach(
            runtime.lease_control(),
            Device {
                log: Arc::new(Mutex::new(Vec::new())),
                fail_release: false,
                fail_press: false
            },
            InputEpoch {
                connection: 10,
                ..epoch()
            },
            layout()
        )
        .is_err()
    );
    runtime.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

struct PanickingWriter;
impl tokio::io::AsyncWrite for PanickingWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        panic!("simulated transport task failure")
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn a_panicking_transport_stops_the_session_and_repeat_wait_preserves_failure() -> Result {
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, _unused) = split(stream);
    let mut runtime =
        AuthorizedConnection::new(read, PanickingWriter, session, Path::Direct, clock, stop)?
            .into_channels();
    runtime.send(Channel::Input, b"trigger").await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped())
            .await?
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped())
            .await?
            .is_err()
    );
    let report =
        (*runtime.lease_control().subscribe_stopped().borrow()).ok_or("missing stop report")?;
    assert_eq!(report.reason, StopReason::Revoked);
    assert!(
        runtime
            .send(Channel::Input, b"after-failure")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_cleanup_wait_keeps_ownership_until_transport_drop() -> Result {
    struct SlowShutdown(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for SlowShutdown {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl tokio::io::AsyncWrite for SlowShutdown {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (session, clock, _, _) = active(15000)?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, _unused) = split(stream);
    let mut runtime = AuthorizedConnection::new(
        read,
        SlowShutdown(dropped.clone()),
        session,
        Path::Direct,
        clock,
        stop,
    )?
    .into_channels();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(5),
            runtime.shutdown(StopReason::ExplicitExit)
        )
        .await
        .is_err()
    );
    assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

struct SwitchingDevice(Device);
impl InputDevice for SwitchingDevice {
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        self.0.inject(input)
    }
    fn select_source(&mut self, source: u32, _layout: InputLayout) -> io::Result<()> {
        self.0
            .log
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .push(format!("source:{source}"));
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0
            .log
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .push("reset".into());
        Ok(())
    }
}
#[tokio::test]
async fn source_handoff_releases_before_select_without_terminal_reset_and_fails_closed() -> Result {
    for fail_release in [false, true] {
        let (session, clock, _, _) = active(15000)?;
        let (_keep, stop) = watch::channel(None);
        let (_peer, stream) = tokio::io::duplex(64);
        let (read, write) = split(stream);
        let mut runtime =
            AuthorizedConnection::new(read, write, session, Path::Direct, clock, stop)?
                .into_channels();
        let log = Arc::new(Mutex::new(Vec::new()));
        let input = InputController::attach(
            runtime.lease_control(),
            SwitchingDevice(Device {
                log: log.clone(),
                fail_release,
                fail_press: false,
            }),
            epoch(),
            layout(),
        )?;
        for (sequence, action) in [
            (
                1,
                InputAction::Key {
                    code: 4,
                    down: true,
                },
            ),
            (
                2,
                InputAction::Pointer {
                    button: Some(1),
                    down: true,
                    x: 0,
                    y: 0,
                },
            ),
        ] {
            input.apply(&InputEvent {
                epoch: epoch(),
                sequence,
                action,
            })?;
        }
        let selected = input.select_source(77, layout());
        if fail_release {
            assert!(selected.is_err());
            let report =
                tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
            assert_eq!(report.reason, StopReason::Revoked);
            assert_eq!(
                report.cleanup,
                CleanupStatus::Failed(io::ErrorKind::PermissionDenied)
            );
            assert!(
                !log.lock()
                    .map_err(|_| "fixture poisoned")?
                    .iter()
                    .any(|v| v == "source:77")
            );
            continue;
        }
        let selected = selected?;
        assert_eq!(
            selected,
            InputEpoch {
                input: 2,
                layout: 2,
                connection: 9
            }
        );
        {
            let events = log.lock().map_err(|_| "fixture poisoned")?;
            let select = events
                .iter()
                .position(|v| v == "source:77")
                .ok_or("no source handoff")?;
            for button in ["release:Key(4)", "release:Pointer(1)"] {
                assert!(
                    events
                        .iter()
                        .position(|v| v == button)
                        .ok_or("missing release")?
                        < select
                );
            }
            assert!(!events.iter().any(|v| v == "reset"));
        }
        assert!(!input.apply(&InputEvent {
            epoch: epoch(),
            sequence: 3,
            action: InputAction::Text("retired".into())
        })?);
        assert!(
            input
                .apply(&InputEvent {
                    epoch: InputEpoch {
                        layout: 1,
                        ..selected
                    },
                    sequence: 1,
                    action: InputAction::Text("mixed".into())
                })
                .is_err()
        );
        input.apply(&InputEvent {
            epoch: selected,
            sequence: 1,
            action: InputAction::Key {
                code: 5,
                down: true,
            },
        })?;
        runtime.shutdown(StopReason::ExplicitExit).await?;
        let events = log.lock().map_err(|_| "fixture poisoned")?;
        assert_eq!(events.iter().filter(|v| v.as_str() == "reset").count(), 1);
        assert_eq!(
            events
                .iter()
                .filter(|v| v.as_str() == "release:Key(5)")
                .count(),
            1
        );
    }
    Ok(())
}
