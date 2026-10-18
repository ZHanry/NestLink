#![allow(clippy::unwrap_used)]
mod support;

use nestlink_app_core::*;
use nestlink_protocol::{Path, Permission, api::ApprovalChoice};
use nestlink_remote::{
    audio::{AudioCaptureDevice, AudioDevice, CapturedAudio},
    input::{Button, InputDevice, InputLayout, PlatformInput},
    video::{CaptureDevice, Display, RawFrame},
};
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{
    io,
    net::UdpSocket,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use support::*;

async fn stage<T>(
    name: &'static str,
    action: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    action
        .await
        .map_err(|error| io::Error::other(format!("{name}: {error}")).into())
}

fn timeout_error(stage: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out waiting for {stage}"),
    )
}

#[derive(Default)]
struct ResetGate {
    armed: AtomicBool,
    entered: AtomicBool,
    entered_notification: tokio::sync::Notify,
    fail: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
    timed_out: AtomicBool,
}
impl ResetGate {
    fn arm(&self, fail: bool) {
        self.fail.store(fail, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }
    fn reset(&self) -> io::Result<()> {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        self.entered.store(true, Ordering::Release);
        self.entered_notification.notify_one();
        let released = self
            .released
            .lock()
            .map_err(|_| io::Error::other("reset gate poisoned"))?;
        let (released, _) = self
            .changed
            .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
            .map_err(|_| io::Error::other("reset gate poisoned"))?;
        self.timed_out.store(!*released, Ordering::Release);
        if !*released || self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("platform reset did not complete"));
        }
        Ok(())
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
    async fn wait_entered(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.entered.load(Ordering::Acquire) {
                self.entered_notification.notified().await;
            }
        })
        .await
        .map_err(|_| timeout_error("host input cleanup entry"))?;
        Ok(())
    }
}

struct InputProbe {
    events: Arc<Mutex<Vec<String>>>,
    reset: Arc<ResetGate>,
}
impl InputDevice for InputProbe {
    fn reset(&mut self) -> io::Result<()> {
        self.reset.reset()?;
        self.events
            .lock()
            .map_err(|_| io::Error::other("input log poisoned"))?
            .push("reset".into());
        Ok(())
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let event = match input {
            PlatformInput::Release(Button::Key(code)) => format!("release:{code}"),
            PlatformInput::Release(Button::Pointer(button)) => format!("release-pointer:{button}"),
            PlatformInput::Action(action) => format!("{action:?}"),
        };
        self.events
            .lock()
            .map_err(|_| io::Error::other("input log poisoned"))?
            .push(event);
        Ok(())
    }
}
struct CaptureProbe(Arc<AtomicUsize>);
impl CaptureDevice for CaptureProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        Ok(None)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
struct AudioProbe(Arc<AtomicUsize>);
impl AudioDevice for AudioProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
impl AudioCaptureDevice for AudioProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        Ok(None)
    }
}

struct Pair {
    _server: Server,
    controller: AppCore,
    host: AppCore,
    controller_handle: CoreHandle,
    host_handle: CoreHandle,
    controller_network: Arc<NetworkMonitor>,
    request_id: String,
    binding: NativeSessionBinding,
    input_binding: NativeInputBinding,
    events: Arc<Mutex<Vec<String>>>,
    reset: Arc<ResetGate>,
}

async fn pair() -> Result<Pair> {
    pair_with_gate(None).await
}

async fn pair_with_gate(gate: Option<Arc<Gate>>) -> Result<Pair> {
    let server = Server::start(gate).await?;
    let controller_identity = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let host_id = host_identity.device_id.clone();
    let route = UdpSocket::bind("0.0.0.0:0")?;
    route.connect("192.0.2.1:9")?;
    let ip = route.local_addr()?.ip();
    if !ip.is_ipv4() || ip.is_loopback() {
        return Err("no routed non-loopback IPv4 test interface".into());
    }
    let controller_network = Arc::new(NetworkMonitor::start()?);
    let config = |network| {
        let mut config = NativeSessionConfig::new(network);
        config.use_deployment_stun = false;
        config.private_network_prefixes = vec![format!("{ip}/32")];
        config
    };
    let controller = AppCore::with_identity_and_native_session(
        Limits::default(),
        controller_identity,
        config(controller_network.clone()),
    )?;
    let host = AppCore::with_identity_and_native_session(
        Limits::default(),
        host_identity,
        config(Arc::new(NetworkMonitor::start()?)),
    )?;
    let controller_handle = stage(
        "controller management connection",
        connect(&controller, &server),
    )
    .await?;
    let host_handle = stage("host management connection", connect(&host, &server)).await?;
    for (handle, role) in [(&controller_handle, "controller"), (&host_handle, "host")] {
        stage(
            "local device enrollment",
            success(handle.submit(Action::EnrollLocalDevice {
                name: role.into(),
                platform: "linux-x11".into(),
                capabilities: vec![role.into(), "vp8".into(), "opus".into()],
                path_mode: "direct_only".into(),
            })?),
        )
        .await?;
    }
    let permissions = vec![
        Permission::View as i32,
        Permission::Input as i32,
        Permission::Audio as i32,
    ];
    stage(
        "remote request",
        success(controller_handle.submit(Action::RequestRemote {
            host_device_id: host_id,
            permissions: permissions.clone(),
            path_mode: "direct_only".into(),
            access: RemoteAccess::LocalApproval,
        })?),
    )
    .await?;
    let request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .clone();
    stage(
        "host remote approval",
        success(host_handle.submit(Action::ApproveRemote {
            request_id: request.id.clone(),
            expected_nonce: request.nonce.clone(),
            expected_policy_revision: request.policy_revision,
            choice: ApprovalChoice {
                approved: true,
                permissions,
                paths: vec![Path::Direct as i32],
            },
        })?),
    )
    .await?;
    stage(
        "initial permit issuance",
        success(controller_handle.submit(Action::IssueRemotePermit {
            request_id: request.id.clone(),
        })?),
    )
    .await?;
    let controller_start = controller_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    let host_start = host_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    tokio::try_join!(
        stage(
            "controller initial native connection",
            success(controller_start)
        ),
        stage("host initial native connection", success(host_start)),
    )?;
    let binding = host_handle
        .native_host_session_binding()
        .ok_or("proved host binding missing")?;
    let layout = InputLayout {
        left: 0,
        top: 0,
        width: 64,
        height: 48,
    };
    host_handle.publish_native_display_candidates(
        &binding,
        vec![DisplayDescriptor {
            source: 0,
            left: 0,
            top: 0,
            width: 64,
            height: 48,
            label: "Main".into(),
        }],
        false,
    )?;
    let catalog = host_handle
        .native_displays(&binding)?
        .catalog
        .ok_or("display catalogue missing")?;
    host_handle.approve_native_displays(&binding, &catalog, vec![0], 0)?;
    host_handle
        .configure_native_video_stream(&binding, 0, 64, 48, 1)
        .await?;
    let reset = Arc::new(ResetGate::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    host_handle
        .attach_native_input_device(
            &binding,
            0,
            1,
            InputProbe {
                events: events.clone(),
                reset: reset.clone(),
            },
            layout,
        )
        .await?;
    host_handle.advertise_native_displays(&binding).await?;
    confirm_initial_display(&host_handle, &controller_handle, &binding).await?;
    let input_binding = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(layout) = controller_handle.native_input_layout()? {
                return Ok::<_, NativeInputError>(layout.binding);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| timeout_error("controller initial input layout"))??;
    controller_handle
        .send_native_input(
            &input_binding,
            NativeInputAction::Key {
                code: 4,
                down: true,
            },
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event == "Key { code: 4, down: true }")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| timeout_error("host receipt of the held key"))?;
    Ok(Pair {
        _server: server,
        controller,
        host,
        controller_handle,
        host_handle,
        controller_network,
        request_id: request.id.clone(),
        binding,
        input_binding,
        events,
        reset,
    })
}

async fn confirm_initial_display(
    host: &CoreHandle,
    controller: &CoreHandle,
    binding: &NativeSessionBinding,
) -> Result {
    // CatalogAck queues the locally approved initial source. The fixture owns
    // the capture worker's commit duty, including the exact SelectionAck.
    let request = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(request) = host.native_display_switch_request(binding)? {
                return Ok::<_, io::Error>(request);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| timeout_error("host initial display request after CatalogAck"))??;
    assert_eq!(
        request,
        NativeDisplayRequest {
            catalog: host
                .native_displays(binding)?
                .catalog
                .ok_or("approved display catalogue missing")?,
            sequence: 1,
            source: 0,
        },
    );
    let selected = host.commit_native_display_switch(binding, &request).await?;
    assert_eq!(
        (
            selected.source,
            selected.sequence,
            selected.layout_epoch,
            selected.input_epoch,
        ),
        (0, 1, 1, 1),
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let host = host.native_displays(binding)?;
            let controller = controller.native_displays(binding)?;
            if host.pending.is_none()
                && controller.pending.is_none()
                && host.selected.as_ref() == Some(&selected)
                && controller.selected.as_ref() == Some(&selected)
                && host.catalog_acknowledged
                && controller.catalog_acknowledged
            {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| timeout_error("both endpoints to confirm initial display SelectionAck"))??;
    Ok(())
}

async fn connected_generation(handle: &CoreHandle, generation: u64) -> Result {
    let mut changes = handle.observe();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if changes
                .borrow_and_update()
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Connected
                        && session.connection_generation == generation
                })
            {
                return Ok::<_, tokio::sync::watch::error::RecvError>(());
            }
            changes.changed().await?;
        }
    })
    .await
    .map_err(|_| timeout_error(&format!("proved native generation {generation}")))??;
    Ok(())
}

async fn connected_generations(
    controller: &CoreHandle,
    host: &CoreHandle,
    server: &Server,
    generation: u64,
) -> Result {
    tokio::try_join!(
        connected_generation(controller, generation),
        connected_generation(host, generation),
    )
    .map_err(|error| {
        let controller = controller.snapshot();
        let host = host.snapshot();
        // NativeSessionView and Failure contain sanitized lifecycle facts only.
        io::Error::other(format!(
            "{error}; controller core_generation={} session={:?} loading={:?} error={:?}; \
             host core_generation={} session={:?} loading={:?} error={:?}; server_forbidden={:?}",
            controller.generation,
            controller.native_session.data,
            controller.native_session.loading,
            controller.native_session.error,
            host.generation,
            host.native_session.data,
            host.native_session.loading,
            host.native_session.error,
            server.forbidden_responses(),
        ))
    })?;
    Ok(())
}

impl Pair {
    async fn wait_reconnect_offer(&self, gate: &Gate) -> Result {
        gate.entered().await.map_err(|error| {
            let controller = self.controller_handle.snapshot();
            let host = self.host_handle.snapshot();
            io::Error::other(format!(
                "{error}; controller session={:?} error={:?}; host session={:?} error={:?}; \
                 server_forbidden={:?}",
                controller.native_session.data,
                controller.native_session.error,
                host.native_session.data,
                host.native_session.error,
                self._server.forbidden_responses(),
            ))
        })?;
        Ok(())
    }

    async fn shutdown(&mut self) {
        let (controller, host) = tokio::join!(
            self.controller.shutdown(Duration::from_secs(5)),
            self.host.shutdown(Duration::from_secs(5)),
        );
        assert_eq!(controller, ShutdownState::Complete);
        assert_eq!(host, ShutdownState::Complete);
    }
}

// Keep the executor small: channel checks contending with held platform
// cleanup must leave capacity for the driver and the Core control actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_waits_for_held_input_and_media_cleanup_then_proves_a_fresh_generation() -> Result
{
    let mut pair = pair().await?;
    let video_resets = Arc::new(AtomicUsize::new(0));
    let capture = pair.host_handle.attach_native_video_capture(
        &pair.binding,
        1,
        CaptureProbe(video_resets.clone()),
        Display {
            source: 0,
            logical: InputLayout {
                left: 0,
                top: 0,
                width: 64,
                height: 48,
            },
        },
    )?;
    let audio_resets = Arc::new(AtomicUsize::new(0));
    let audio_binding = pair
        .host_handle
        .native_audio_binding()
        .ok_or("audio binding missing")?;
    let audio = pair
        .host_handle
        .attach_native_audio_capture(&audio_binding, AudioProbe(audio_resets.clone()))?;
    let old = pair.binding.connection_generation;
    assert_eq!(
        pair.controller_handle
            .configure_native_network(
                pair.controller_handle.snapshot().generation,
                pair.controller_handle.snapshot().native_network_revision,
                NativeNetworkSettings::default(),
            )
            .await,
        Err(NativeNetworkError::Busy),
    );
    pair.reset.arm(false);
    let cleanup_started = Instant::now();
    pair.controller_network.invalidate_generation()?;
    pair.reset.wait_entered().await?;
    assert_eq!(
        pair.controller_handle
            .configure_native_network(
                pair.controller_handle.snapshot().generation,
                pair.controller_handle.snapshot().native_network_revision,
                NativeNetworkSettings::default(),
            )
            .await,
        Err(NativeNetworkError::Busy),
    );
    for handle in [&pair.controller_handle, &pair.host_handle] {
        assert!(
            !handle
                .snapshot()
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Connected
                        && session.connection_generation > old
                })
        );
    }
    assert!(
        pair.controller_handle
            .send_native_input(
                &pair.input_binding,
                NativeInputAction::Key {
                    code: 4,
                    down: false
                }
            )
            .await
            .is_err()
    );
    pair.reset.release();
    assert!(
        !pair.reset.timed_out.load(Ordering::Acquire),
        "test cleanup gate expired before release after {:?}",
        cleanup_started.elapsed(),
    );
    // Drop a stopped external capture owner too: cleanup must not be treated
    // as new ExplicitExit consent that vetoes the retained transport budget.
    tokio::time::timeout(Duration::from_secs(3), async {
        while video_resets.load(Ordering::Acquire) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| timeout_error("stopped video capture reset"))?;
    drop(capture);
    connected_generations(
        &pair.controller_handle,
        &pair.host_handle,
        &pair._server,
        old + 1,
    )
    .await?;
    assert_eq!(video_resets.load(Ordering::Acquire), 1);
    assert_eq!(audio_resets.load(Ordering::Acquire), 1);
    assert!(audio.status().finished);
    let events = pair.events.lock().unwrap().clone();
    let release = events
        .iter()
        .position(|event| event == "release:4")
        .ok_or("held key was not released")?;
    assert!(
        events
            .iter()
            .skip(release + 1)
            .any(|event| event == "reset")
    );
    let replacement = pair
        .host_handle
        .native_host_session_binding()
        .ok_or("replacement proof missing")?;
    assert_eq!(replacement.request_id, pair.request_id);
    assert_eq!(replacement.connection_generation, old + 1);
    assert!(!pair.host_handle.native_host_input_authorized(&pair.binding));
    assert!(pair.controller_handle.native_input_layout()?.is_none());
    assert!(
        pair.host_handle
            .native_displays(&replacement)?
            .catalog
            .is_none()
    );
    assert!(pair.host_handle.native_displays(&pair.binding).is_err());
    assert!(
        pair.host_handle
            .attach_native_audio_capture(&audio_binding, AudioProbe(Arc::new(AtomicUsize::new(0))))
            .is_err()
    );
    // A second outage remains part of the same original request lifetime.
    pair.controller_network.invalidate_generation()?;
    connected_generations(
        &pair.controller_handle,
        &pair.host_handle,
        &pair._server,
        old + 2,
    )
    .await?;
    pair.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_stop_during_recovery_cancels_exchange_and_never_attaches_successor_routes() -> Result
{
    let gate = Gate::suffix("/reconnect/offer", "POST");
    let mut pair = pair_with_gate(Some(gate.clone())).await?;
    gate.arm();
    pair.controller_network.invalidate_generation()?;
    // Hold a real reconnect response after its server transaction. The actor
    // has completed old-session cleanup and cannot commit a successor yet.
    stage(
        "controller reconnect offer",
        pair.wait_reconnect_offer(&gate),
    )
    .await?;
    assert_eq!(
        pair.controller_handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .unwrap()
            .status,
        NativeSessionStatus::Establishing,
    );
    let stopped = stage(
        "user stop during recovery",
        success(pair.controller_handle.submit(Action::StopNativeSession {
            request_id: pair.request_id.clone(),
            connection_generation: pair.binding.connection_generation,
        })?),
    )
    .await;
    gate.unblock();
    stopped?;
    stage(
        "controller terminal state after user stop",
        wait_view(&pair.controller_handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Stopped
                        || session.status == NativeSessionStatus::Failed
                })
        }),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        pair.controller_handle
            .native_host_session_binding()
            .is_none()
    );
    assert!(pair.controller_handle.native_audio_binding().is_none());
    assert!(pair.controller_handle.native_input_layout().is_err());
    assert_eq!(
        pair.controller_handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .unwrap()
            .connection_generation,
        pair.binding.connection_generation
    );
    pair.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_recovery_retains_completed_cleanup_without_attaching_successor_routes() -> Result {
    let gate = Gate::suffix("/reconnect/offer", "POST");
    let mut pair = pair_with_gate(Some(gate.clone())).await?;
    let mut revoker = AppCore::start(Limits::default())?;
    let revoke_handle = stage(
        "independent revocation client",
        connect(&revoker, &pair._server),
    )
    .await?;
    gate.arm();
    pair.controller_network.invalidate_generation()?;
    stage(
        "controller reconnect offer after cleanup",
        pair.wait_reconnect_offer(&gate),
    )
    .await?;
    let previous = pair
        .controller_handle
        .snapshot()
        .native_session
        .data
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(previous.status, NativeSessionStatus::Establishing);
    assert_eq!(previous.cleanup, Some(NativeSessionCleanup::Succeeded));

    // The controller cannot commit a successor until this real HTTP response
    // returns. A separate management client revokes on the real server; neither
    // endpoint's single SDK client must leave recovery to perform the revoke.
    let revoked = stage(
        "server revocation during recovery",
        success(revoke_handle.submit(Action::RevokeRemote {
            request_id: pair.request_id.clone(),
        })?),
    )
    .await;
    gate.unblock();
    revoked?;
    stage(
        "controller rejected recovery with retained cleanup",
        wait_view(&pair.controller_handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Failed
                        && session.cleanup == Some(NativeSessionCleanup::Succeeded)
                })
        }),
    )
    .await?;
    let snapshot = pair.controller_handle.snapshot();
    let session = snapshot.native_session.data.as_ref().unwrap();
    assert_eq!(session.request_id, previous.request_id);
    assert_eq!(
        session.connection_generation,
        previous.connection_generation
    );
    assert_eq!(session.lease_sequence, previous.lease_sequence);
    assert_eq!(session.stop_effects, previous.stop_effects);
    assert!(session.stop_effects.is_some());
    assert!(session.failure.is_some());
    assert!(!session.host_view_authorized);
    assert!(session.path.is_none());
    assert!(pair.controller_handle.native_audio_binding().is_none());
    assert!(pair.controller_handle.native_input_layout().is_err());
    assert!(pair.controller_handle.poll_native_video().is_err());
    pair.shutdown().await;
    assert_eq!(
        revoker.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_platform_cleanup_does_not_offer_a_replacement_generation() -> Result {
    let mut pair = pair().await?;
    pair.reset.arm(true);
    pair.controller_network.invalidate_generation()?;
    pair.reset.wait_entered().await?;
    pair.reset.release();
    stage(
        "host failed platform cleanup state",
        wait_view(&pair.host_handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Failed
                        && session.cleanup == Some(NativeSessionCleanup::Failed)
                })
        }),
    )
    .await?;
    assert!(pair.host_handle.native_host_session_binding().is_none());
    assert_eq!(
        pair.host_handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .unwrap()
            .connection_generation,
        pair.binding.connection_generation
    );
    pair.shutdown().await;
    Ok(())
}
