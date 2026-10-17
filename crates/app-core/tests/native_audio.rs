#![allow(clippy::unwrap_used)]
mod support;

use nestlink_app_core::*;
use nestlink_protocol::{Path, Permission, api::*};
use nestlink_remote::audio::{
    AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice, CHUNK_FRAMES, CapturedAudio,
};
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{
    io,
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use support::*;
use tokio::sync::oneshot;

struct AudioPair {
    _server: Server,
    controller_core: AppCore,
    host_core: AppCore,
    controller: CoreHandle,
    host: CoreHandle,
    host_id: String,
    request_id: String,
}

fn routed_ipv4() -> Result<std::net::Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    // UDP connect selects the OS route without sending a packet.
    socket.connect("192.0.2.1:9")?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() => Ok(address),
        _ => Err("no non-loopback IPv4 route is available for the audio session test".into()),
    }
}

fn native_core(identity: DeviceIdentity, prefix: String) -> Result<AppCore> {
    let monitor = Arc::new(NetworkMonitor::start()?);
    let mut config = NativeSessionConfig::new(monitor);
    config.private_network_prefixes.push(prefix);
    Ok(AppCore::with_identity_and_native_session(
        Limits::default(),
        identity,
        config,
    )?)
}

async fn session_success(ticket: Ticket) -> Result<Completion> {
    let completion = tokio::time::timeout(Duration::from_secs(20), ticket.wait()).await??;
    assert_eq!(
        completion.result.status,
        OperationStatus::Succeeded,
        "{:?}",
        completion.result
    );
    Ok(completion)
}

fn remote_request_failure_category(completion: &Completion) -> &'static str {
    let Some(failure) = completion.result.failure.as_ref() else {
        return "missing_failure";
    };
    match failure.kind {
        FailureKind::Rejected
            if failure.status == Some(400)
                && failure.code == Some(nestlink_protocol::ErrorCode::InvalidMessage) =>
        {
            "http_400_invalid_message"
        }
        FailureKind::Rejected => "rejected",
        FailureKind::Transport => "transport",
        FailureKind::Timeout => "timeout",
        FailureKind::SignInRequired => "sign_in_required",
        FailureKind::Trust => "trust",
        FailureKind::Invalid => "invalid",
        FailureKind::Capacity => "capacity",
        FailureKind::NativeSessionUnavailable => "native_session_unavailable",
        FailureKind::NativeSessionCancelled => "native_session_cancelled",
        FailureKind::NetworkChanged => "network_changed",
        FailureKind::PermitExpired => "permit_expired",
        FailureKind::LocalIdentityRequired => "local_identity_required",
        FailureKind::CoreStopped => "core_stopped",
        FailureKind::StaleGeneration => "stale_generation",
        FailureKind::Superseded => "superseded",
    }
}

/// Reports only fixed booleans and error labels. Device IDs, names, capabilities,
/// HTTP bodies, and credentials stay out of the test log.
fn remote_request_failure_diagnostic(
    controller: &CoreHandle,
    host: &CoreHandle,
    host_id: &str,
    permissions: &[i32],
    path_mode: &str,
    completion: &Completion,
) -> String {
    let controller_snapshot = controller.snapshot();
    let host_snapshot = host.snapshot();
    let controller_device = controller_snapshot
        .installation
        .as_ref()
        .and_then(|installation| {
            controller_snapshot
                .devices
                .data
                .as_deref()?
                .iter()
                .find(|v| v.device.id == installation.device_id)
        });
    let host_device = host_snapshot
        .devices
        .data
        .as_deref()
        .and_then(|devices| devices.iter().find(|v| v.device.id == host_id));
    let has_capability = |device: Option<&DeviceView>, expected: &str| {
        device.is_some_and(|v| v.device.capabilities.iter().any(|value| value == expected))
    };
    let permissions_valid = !permissions.is_empty()
        && permissions.len() <= 7
        && permissions.iter().enumerate().all(|(index, permission)| {
            matches!(
                Permission::try_from(*permission),
                Ok(value) if value != Permission::Unspecified
            ) && !permissions[..index].contains(permission)
        });
    let path_mode_valid = matches!(path_mode, "direct_only" | "direct_preferred" | "relay_only");
    let controller_capability = has_capability(controller_device, "controller");
    let host_capability = has_capability(host_device, "host");
    let shared_vp8 = has_capability(controller_device, "vp8") && has_capability(host_device, "vp8");
    let shared_opus =
        has_capability(controller_device, "opus") && has_capability(host_device, "opus");
    format!(
        "native_audio_request_diag failure={} controller_signed_in={} host_signed_in={} controller_devices_loaded={} host_devices_loaded={} controller_registered={} host_registered={} permissions_valid={} path_mode_valid={} controller_capability={} host_capability={} shared_vp8={} shared_opus={}",
        remote_request_failure_category(completion),
        controller_snapshot.authentication == Authentication::SignedIn,
        host_snapshot.authentication == Authentication::SignedIn,
        controller_snapshot.devices.data.is_some(),
        host_snapshot.devices.data.is_some(),
        controller_device.is_some(),
        host_device.is_some(),
        permissions_valid,
        path_mode_valid,
        controller_capability,
        host_capability,
        shared_vp8,
        shared_opus,
    )
}

async fn wait_audio_binding(handle: &CoreHandle) -> Result<NativeAudioBinding> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(binding) = handle.native_audio_binding() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(binding);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

async fn approve_audio_request(
    controller: &CoreHandle,
    host: &CoreHandle,
    host_id: &str,
) -> Result<String> {
    let permissions = vec![Permission::View as i32, Permission::Audio as i32];
    let path_mode = "direct_only";
    let completion = done(controller.submit(Action::RequestRemote {
        host_device_id: host_id.to_owned(),
        permissions: permissions.clone(),
        path_mode: path_mode.into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    if completion.result.status != OperationStatus::Succeeded {
        eprintln!(
            "{}",
            remote_request_failure_diagnostic(
                controller,
                host,
                host_id,
                &permissions,
                path_mode,
                &completion,
            )
        );
    }
    assert_eq!(
        completion.result.status,
        OperationStatus::Succeeded,
        "{:?}",
        completion.result
    );
    let request = controller
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .ok_or("audio request was not selected")?
        .clone();
    success(host.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32, Permission::Audio as i32],
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    success(controller.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    Ok(request.id.clone())
}

async fn start_audio_session(
    controller: &CoreHandle,
    host: &CoreHandle,
    request_id: &str,
) -> Result {
    let controller_start = controller.submit(Action::StartNativeSession {
        request_id: request_id.to_owned(),
    })?;
    let host_start = host.submit(Action::StartNativeSession {
        request_id: request_id.to_owned(),
    })?;
    let (controller_started, host_started) = tokio::try_join!(
        session_success(controller_start),
        session_success(host_start)
    )?;
    assert_eq!(
        controller_started.result.kind,
        OperationKind::StartNativeSession
    );
    assert_eq!(host_started.result.kind, OperationKind::StartNativeSession);
    Ok(())
}

async fn audio_pair() -> Result<AudioPair> {
    let server = Server::start(None).await?;
    let controller_identity = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let host_id = host_identity.device_id.clone();
    let prefix = format!("{}/32", routed_ipv4()?);
    let controller_core = native_core(controller_identity, prefix.clone())?;
    let host_core = native_core(host_identity, prefix)?;
    let controller = connect(&controller_core, &server).await?;
    let host = connect(&host_core, &server).await?;

    for (handle, role) in [(&controller, "controller"), (&host, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "linux-x11".into(),
            capabilities: vec![role.into(), "vp8".into(), "opus".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    let request_id = approve_audio_request(&controller, &host, &host_id).await?;
    start_audio_session(&controller, &host, &request_id).await?;
    assert_eq!(
        wait_audio_binding(&host).await?.role,
        NativeAudioRole::HostCapture
    );
    assert_eq!(
        wait_audio_binding(&controller).await?.role,
        NativeAudioRole::ControllerPlayback
    );

    Ok(AudioPair {
        _server: server,
        controller_core,
        host_core,
        controller,
        host,
        host_id,
        request_id,
    })
}

struct CaptureProbe {
    resets: Arc<AtomicUsize>,
    pts: u64,
    next_chunk: Instant,
}

impl AudioDevice for CaptureProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl AudioCaptureDevice for CaptureProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        if self.pts >= 20 * CHUNK_FRAMES as u64 || Instant::now() < self.next_chunk {
            return Ok(None);
        }
        let pts = self.pts;
        self.pts += CHUNK_FRAMES as u64;
        self.next_chunk = Instant::now() + Duration::from_millis(20);
        let samples = (0..CHUNK_FRAMES)
            .flat_map(|frame| {
                let phase = (pts + frame as u64) as f64 / 48_000.0;
                [440.0, 880.0]
                    .map(|hz| (12_000.0 * (phase * hz * std::f64::consts::TAU).sin()) as i16)
            })
            .collect();
        Ok(Some(CapturedAudio {
            captured_at: Instant::now(),
            chunk: AudioChunk {
                source: 0,
                channels: 2,
                pts_48khz: pts,
                samples,
            },
        }))
    }
}

struct BlockingPlaybackProbe {
    resets: Arc<AtomicUsize>,
    played: Arc<AtomicUsize>,
    reset_entered: Option<oneshot::Sender<()>>,
    release: mpsc::Receiver<()>,
    fail_reset: bool,
}

impl AudioDevice for BlockingPlaybackProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        let first_reset = self.resets.fetch_add(1, Ordering::SeqCst) == 0;
        if first_reset {
            if let Some(entered) = self.reset_entered.take() {
                let _ = entered.send(());
            }
            self.release
                .recv_timeout(Duration::from_secs(8))
                .map_err(io::Error::other)?;
        }
        if self.fail_reset {
            Err(io::Error::other("fixture playback reset failed"))
        } else {
            Ok(())
        }
    }
}

impl AudioPlaybackDevice for BlockingPlaybackProbe {
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        assert_eq!(chunk.samples.len(), CHUNK_FRAMES * 2);
        self.played.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct AudioWorkers {
    host_binding: NativeAudioBinding,
    controller_binding: NativeAudioBinding,
    capture: nestlink_media_session::WorkerMonitor,
    playback: nestlink_media_session::WorkerMonitor,
    capture_resets: Arc<AtomicUsize>,
}

async fn attach_audio(pair: &AudioPair, playback: BlockingPlaybackProbe) -> Result<AudioWorkers> {
    let host_binding = wait_audio_binding(&pair.host).await?;
    let controller_binding = wait_audio_binding(&pair.controller).await?;
    let capture_resets = Arc::new(AtomicUsize::new(0));
    let capture = pair.host.attach_native_audio_capture(
        &host_binding,
        CaptureProbe {
            resets: capture_resets.clone(),
            pts: 0,
            next_chunk: Instant::now(),
        },
    )?;
    let played = playback.played.clone();
    let playback = pair
        .controller
        .attach_native_audio_playback(&controller_binding, playback)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while played.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(AudioWorkers {
        host_binding,
        controller_binding,
        capture,
        playback,
        capture_resets,
    })
}

async fn revoke(pair: &AudioPair) -> Result {
    success(pair.controller.submit(Action::RevokeRemote {
        request_id: pair.request_id.clone(),
    })?)
    .await?;
    Ok(())
}

async fn wait_stopped(handle: &CoreHandle, request_id: &str, stage: &str) -> Result {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let stopped = handle
                .snapshot()
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.request_id == request_id
                        && matches!(
                            session.status,
                            NativeSessionStatus::Stopped | NativeSessionStatus::Failed
                        )
                        && session.cleanup.is_some()
                });
            if stopped {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if result.is_err() {
        let snapshot = handle.snapshot();
        let session = snapshot.native_session.data.as_ref();
        return Err(format!(
            "audio stop timed out at {stage}: request_matches={}, status={:?}, cleanup={:?}, binding_present={}",
            session.is_some_and(|session| session.request_id == request_id),
            session.map(|session| session.status),
            session.and_then(|session| session.cleanup),
            handle.native_audio_binding().is_some(),
        )
        .into());
    }
    Ok(())
}

struct StaleCaptureProbe(Arc<AtomicUsize>);

impl AudioDevice for StaleCaptureProbe {
    fn check(&mut self) -> io::Result<()> {
        panic!("stale audio device must not be attached")
    }

    fn reset(&mut self) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("stale device reset failed"))
    }
}

impl AudioCaptureDevice for StaleCaptureProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        panic!("stale audio device must not capture")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_same_generation_binding_cannot_attach_or_poison_new_audio_route() -> Result {
    let mut pair = audio_pair().await?;
    let old_request = pair.request_id.clone();
    let old_host_binding = wait_audio_binding(&pair.host).await?;
    revoke(&pair).await?;
    wait_stopped(&pair.host, &old_request, "first host").await?;
    wait_stopped(&pair.controller, &old_request, "first controller").await?;

    let next_request = approve_audio_request(&pair.controller, &pair.host, &pair.host_id).await?;
    assert_ne!(next_request, old_request);
    start_audio_session(&pair.controller, &pair.host, &next_request).await?;
    pair.request_id = next_request;
    let current_host_binding = wait_audio_binding(&pair.host).await?;
    assert_eq!(
        old_host_binding.connection_generation,
        current_host_binding.connection_generation
    );
    assert_ne!(old_host_binding.request_id, current_host_binding.request_id);

    let stale_resets = Arc::new(AtomicUsize::new(0));
    let stale_error = pair
        .host
        .attach_native_audio_capture(&old_host_binding, StaleCaptureProbe(stale_resets.clone()))
        .err()
        .ok_or("old request binding attached to the new Audio route")?;
    assert!(matches!(stale_error, NativeAudioError::Cleanup(_)));
    assert_eq!(stale_resets.load(Ordering::SeqCst), 1);
    assert_eq!(
        pair.host.native_audio_binding().as_ref(),
        Some(&current_host_binding),
        "old device cleanup must not retire or poison the new request"
    );

    let capture_resets = Arc::new(AtomicUsize::new(0));
    let current_capture = pair.host.attach_native_audio_capture(
        &current_host_binding,
        CaptureProbe {
            resets: capture_resets.clone(),
            pts: 0,
            next_chunk: Instant::now(),
        },
    )?;
    revoke(&pair).await?;
    wait_stopped(&pair.host, &pair.request_id, "replacement host").await?;
    wait_stopped(&pair.controller, &pair.request_id, "replacement controller").await?;
    assert_eq!(
        pair.host
            .snapshot()
            .native_session
            .data
            .as_ref()
            .and_then(|session| session.cleanup),
        Some(NativeSessionCleanup::Succeeded)
    );
    assert_eq!(capture_resets.load(Ordering::SeqCst), 1);
    assert!(current_capture.status().finished);
    assert_eq!(
        pair.controller_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        pair.host_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn playback_reset_failure_stays_in_receipt_and_shutdown_waits_for_worker_join() -> Result {
    let mut pair = audio_pair().await?;
    let played = Arc::new(AtomicUsize::new(0));
    let resets = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let workers = attach_audio(
        &pair,
        BlockingPlaybackProbe {
            resets: resets.clone(),
            played: played.clone(),
            reset_entered: Some(entered_tx),
            release: release_rx,
            fail_reset: true,
        },
    )
    .await?;
    assert!(
        played.load(Ordering::SeqCst) > 0,
        "no real QUIC audio reached playback"
    );

    // Reset runs in the lease stop handler. Keep the revoke completion owned
    // without waiting for that handler before observing the blocked cleanup.
    let revocation = pair.controller.submit(Action::RevokeRemote {
        request_id: pair.request_id.clone(),
    })?;
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await??;
    assert_eq!(resets.load(Ordering::SeqCst), 1);

    let shutdown_generation = pair.controller.snapshot().generation;
    assert_eq!(
        pair.controller_core
            .shutdown(Duration::from_millis(100))
            .await,
        ShutdownState::Pending,
        "AppCore must retain the session while playback reset blocks"
    );
    release_tx.send(())?;
    wait_view(&pair.controller, |snapshot| {
        snapshot.generation > shutdown_generation && snapshot.lifecycle != Lifecycle::Running
    })
    .await?;
    let completion = done(revocation).await?;
    // Shutdown retires the operation's generation even though the server's
    // revoke committed before playback cleanup started. Preserve both facts.
    assert_eq!(completion.result.status, OperationStatus::Superseded);
    assert_eq!(completion.result.remote_effect, RemoteEffect::Committed);
    assert!(completion.result.failure.is_none());
    assert_eq!(
        pair.controller_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        pair.host_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );

    let snapshot = pair.controller.snapshot();
    let session = snapshot
        .native_session
        .data
        .as_ref()
        .ok_or("missing controller session stop receipt")?
        .clone();
    assert_eq!(session.status, NativeSessionStatus::Failed);
    assert_eq!(session.stop_reason, Some(NativeSessionStopReason::Revoked));
    assert_eq!(session.cleanup, Some(NativeSessionCleanup::Failed));
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert_eq!(workers.capture_resets.load(Ordering::SeqCst), 1);
    assert!(workers.capture.status().finished);
    assert!(workers.playback.status().finished);
    assert!(
        pair.controller
            .native_audio_worker_monitor(&workers.controller_binding)
            .is_none()
    );
    assert!(
        pair.host
            .native_audio_worker_monitor(&workers.host_binding)
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_shutdown_waiter_does_not_detach_late_audio_owner() -> Result {
    let mut pair = audio_pair().await?;
    let played = Arc::new(AtomicUsize::new(0));
    let resets = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let workers = attach_audio(
        &pair,
        BlockingPlaybackProbe {
            resets: resets.clone(),
            played,
            reset_entered: Some(entered_tx),
            release: release_rx,
            fail_reset: false,
        },
    )
    .await?;

    let revocation = pair.controller.submit(Action::RevokeRemote {
        request_id: pair.request_id.clone(),
    })?;
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await??;

    let shutdown_generation = pair.controller.snapshot().generation;
    let mut cancelled_waiter = Box::pin(pair.controller_core.shutdown(Duration::from_secs(10)));
    // Poll the actual shutdown future to Pending before dropping the caller.
    // This requests shutdown without guessing how far a sleep advanced it.
    let polled = std::future::poll_fn(|context| {
        std::task::Poll::Ready(std::future::Future::poll(
            cancelled_waiter.as_mut(),
            context,
        ))
    })
    .await;
    assert!(
        polled.is_pending(),
        "shutdown completed before blocked reset was released: {polled:?}"
    );
    drop(cancelled_waiter);

    // reset runs inside lease cleanup. channels.wait_stopped() has not yielded
    // its receipt, so runtime has not begun audio.shutdown's join budget yet.
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert!(!workers.playback.status().finished);
    assert!(!workers.playback.status().cleanup_timed_out);
    assert!(pair.controller.native_audio_binding().is_none());
    assert_eq!(
        pair.controller_core
            .shutdown(Duration::from_millis(100))
            .await,
        ShutdownState::Pending,
        "a cancelled waiter must leave AppCore's shutdown owner intact"
    );
    assert!(!*pair.controller_core.finished().borrow());

    release_tx.send(())?;
    let mut snapshots = pair.controller.observe();
    tokio::time::timeout(Duration::from_secs(2), async {
        while {
            let snapshot = snapshots.borrow_and_update();
            snapshot.generation <= shutdown_generation || snapshot.lifecycle == Lifecycle::Running
        } {
            snapshots.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    let completion = done(revocation).await?;
    // Shutdown retires the operation's generation while its committed revoke
    // still owns the blocked playback reset. It must retain both facts.
    assert_eq!(completion.result.status, OperationStatus::Superseded);
    assert_eq!(completion.result.remote_effect, RemoteEffect::Committed);
    assert!(completion.result.failure.is_none());
    assert_eq!(
        pair.controller_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        pair.host_core.shutdown(Duration::from_secs(10)).await,
        ShutdownState::Complete
    );
    assert!(workers.capture.status().finished);
    assert!(workers.playback.status().finished);
    assert!(!workers.playback.status().cleanup_timed_out);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    let snapshot = pair.controller.snapshot();
    let session = snapshot
        .native_session
        .data
        .as_ref()
        .ok_or("missing controller session stop receipt")?;
    assert_eq!(session.cleanup, Some(NativeSessionCleanup::Succeeded));
    Ok(())
}
