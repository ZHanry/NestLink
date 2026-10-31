//! Native desktop host capture and VP8 uplink.
//!
//! This actor is separate from the browser host: it observes the product-owned
//! native session and only opens a local screen source after a connected View
//! lease has been published by AppCore.

use crate::capture::SystemInput;
use crate::native_clipboard::InstalledClipboardFactory;
#[cfg(target_os = "linux")]
use nestlink_app_core::NativeClipboardBinding;
use nestlink_app_core::{
    CoreHandle, DisplayDescriptor, Lifecycle, NativeDisplayState,
    NativeSessionBinding as SessionIdentity, NativeVideoBinding, NativeVideoError,
};
use nestlink_media_codec::{VideoCodec, VideoConfig, VideoEncoder, VideoQuality};
use nestlink_remote::input::InputDevice;
use nestlink_remote::video::{
    CaptureDevice, Display, HostEncodeStep, HostFrame, HostVideoConfig, RawFrame, VideoController,
};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::{
    io,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinHandle};
use zeroize::{Zeroize, Zeroizing};

const LAYOUT_EPOCH: u64 = 1;
const FPS: u32 = 30;
const BITRATE_KBPS: u32 = 4_000;
const CAPTURE_TICK: Duration = Duration::from_millis(10);
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

fn authorized_session(core: &CoreHandle) -> Option<SessionIdentity> {
    core.native_host_session_binding()
}

fn is_current_session(core: &CoreHandle, expected: &SessionIdentity) -> bool {
    authorized_session(core).is_some_and(|actual| {
        actual.request_id == expected.request_id
            && actual.connection_generation == expected.connection_generation
    })
}

/// Owns the daemon-lifetime capture actor and provides a non-detaching stop.
pub struct NativeVideoCaptureTask {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl NativeVideoCaptureTask {
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    /// Observe an early actor exit without relinquishing the JoinHandle if this
    /// future is cancelled by `select!` before the task completes.
    pub async fn wait(&mut self) -> Result<(), io::Error> {
        let result = match self.task.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => Err(io::Error::other(error)),
            },
            None => return Ok(()),
        };
        self.task.take();
        result
    }

    pub async fn join(mut self) -> Result<(), io::Error> {
        self.wait().await
    }
}

pub fn spawn_native_video_capture(
    core: CoreHandle,
    clipboard_factory: InstalledClipboardFactory,
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
) -> NativeVideoCaptureTask {
    let (stop, receiver) = watch::channel(false);
    NativeVideoCaptureTask {
        stop,
        task: Some(tokio::spawn(run_native_video_capture(
            core,
            clipboard_factory,
            privileged,
            receiver,
        ))),
    }
}

async fn run_native_video_capture(
    core: CoreHandle,
    clipboard_factory: InstalledClipboardFactory,
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut observed = core.observe();
    loop {
        if *stop.borrow() || core.snapshot().lifecycle != Lifecycle::Running {
            core.clear_native_video_stream();
            return Ok(());
        }
        let Some(identity) = authorized_session(&core) else {
            tokio::select! {
                changed = observed.changed() => if changed.is_err() { return Ok(()); },
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { return Ok(()); },
            }
            continue;
        };

        let prepared = match prepare_until_session_changes(
            &core,
            &identity,
            &clipboard_factory,
            &privileged,
            &mut observed,
            &mut stop,
        )
        .await
        {
            PrepareOutcome::Ready(prepared) => *prepared,
            PrepareOutcome::SessionChanged => {
                core.clear_native_video_stream_for(&identity);
                continue;
            }
            PrepareOutcome::Failed => {
                fail_if_current(&core, &identity, &mut observed).await;
                continue;
            }
            PrepareOutcome::CoreStopped => {
                core.clear_native_video_stream_for(&identity);
                return Ok(());
            }
            PrepareOutcome::CleanupFailed(error) => {
                let _ = core.fail_native_video_capture(&identity);
                core.clear_native_video_stream_for(&identity);
                return Err(error);
            }
        };
        if *stop.borrow() {
            reset_prepared(prepared).await?;
            core.clear_native_video_stream_for(&identity);
            return Ok(());
        }

        let mut input = prepared.input;
        let display = match prepared
            .displays
            .iter()
            .find(|display| display.source == prepared.initial_source)
            .copied()
        {
            Some(display) => display,
            None => {
                reset_unattached_input(input.take()).await?;
                let mut device = prepared.device;
                tokio::task::spawn_blocking(move || device.reset())
                    .await
                    .map_err(io::Error::other)??;
                fail_if_current(&core, &identity, &mut observed).await;
                continue;
            }
        };
        let capture = StableDisplayCapture {
            inner: prepared.device,
            approved: prepared.displays.iter().map(|d| d.source).collect(),
        };
        let controller =
            match core.attach_native_video_capture_set(&identity, capture, prepared.displays) {
                Ok(controller) => controller,
                Err(NativeVideoError::Cleanup(error)) => {
                    let _ = reset_unattached_input(input.take()).await;
                    let _ = core.fail_native_video_capture(&identity);
                    return Err(error);
                }
                Err(_) => {
                    reset_unattached_input(input.take()).await?;
                    fail_if_current(&core, &identity, &mut observed).await;
                    continue;
                }
            };
        if core
            .configure_native_video_stream(
                &identity,
                display.source,
                display.logical.width,
                display.logical.height,
                LAYOUT_EPOCH,
            )
            .await
            .is_err()
        {
            reset_unattached_input(input.take()).await?;
            fail_if_current(&core, &identity, &mut observed).await;
            drop(controller);
            continue;
        }
        if let Some(input) = input.take() {
            let runtime = tokio::runtime::Handle::current();
            let input_core = core.clone();
            let input_identity = identity.clone();
            let attached = tokio::task::spawn_blocking(move || {
                let _enter = runtime.enter();
                runtime.block_on(input_core.attach_native_input_device(
                    &input_identity,
                    display.source,
                    LAYOUT_EPOCH,
                    input,
                    display.logical,
                ))
            })
            .await;
            if !matches!(attached, Ok(Ok(()))) {
                fail_if_current(&core, &identity, &mut observed).await;
                drop(controller);
                continue;
            }
        }
        if core.advertise_native_displays(&identity).await.is_err() {
            fail_if_current(&core, &identity, &mut observed).await;
            drop(controller);
            continue;
        }
        let runtime = tokio::runtime::Handle::current();
        let worker = tokio::task::spawn_blocking({
            let core = core.clone();
            let identity = identity.clone();
            let stop = stop.clone();
            move || stream_capture(&core, &identity, controller, runtime, &stop)
        })
        .await;
        let (controller, exit) = match worker {
            Ok(result) => result,
            Err(_) => {
                fail_if_current(&core, &identity, &mut observed).await;
                core.clear_native_video_stream_for(&identity);
                continue;
            }
        };
        core.clear_native_video_stream_for(&identity);
        if !*stop.borrow()
            && matches!(
                exit,
                StreamExit::CaptureFailed | StreamExit::TransportFailed
            )
        {
            fail_if_current(&core, &identity, &mut observed).await;
        }
        drop(controller);
        if *stop.borrow() {
            return Ok(());
        }
    }
}

// A preparation future can spend time in the Wayland consent dialog. Keep it
// alive across unrelated snapshot updates, but cancel it as soon as this exact
// connected session is no longer authorized.
enum PrepareOutcome {
    Ready(Box<PreparedCapture>),
    SessionChanged,
    Failed,
    CoreStopped,
    CleanupFailed(io::Error),
}

enum PrepareError {
    Capture(io::Error),
    Cleanup(io::Error),
}

impl From<io::Error> for PrepareError {
    fn from(error: io::Error) -> Self {
        Self::Capture(error)
    }
}

async fn prepare_until_session_changes(
    core: &CoreHandle,
    identity: &SessionIdentity,
    clipboard_factory: &InstalledClipboardFactory,
    privileged: &Arc<crate::privileged_input::PrivilegedInput>,
    observed: &mut watch::Receiver<Arc<nestlink_app_core::Snapshot>>,
    stop: &mut watch::Receiver<bool>,
) -> PrepareOutcome {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let prepare = prepare_capture(
        cancel_rx,
        core.native_host_input_authorized(identity),
        core,
        identity,
        clipboard_factory,
        privileged,
    );
    tokio::pin!(prepare);
    let mut interrupted = None;
    loop {
        if let Some(outcome) = interrupted {
            // The platform open may be running in spawn_blocking and cannot be
            // aborted safely. Keep it supervised until it returns, then reset
            // any late-created device before allowing the actor to exit.
            return match prepare.await {
                Ok(prepared) => match reset_prepared(prepared).await {
                    Ok(()) => outcome,
                    Err(error) => PrepareOutcome::CleanupFailed(error),
                },
                Err(PrepareError::Cleanup(error)) => PrepareOutcome::CleanupFailed(error),
                Err(PrepareError::Capture(_)) => outcome,
            };
        }
        tokio::select! {
            biased;
            result = &mut prepare => {
                return match result {
                    Ok(prepared) if !*stop.borrow() && is_current_session(core, identity) => PrepareOutcome::Ready(Box::new(prepared)),
                    Ok(prepared) => {
                        match reset_prepared(prepared).await {
                            Ok(()) => PrepareOutcome::SessionChanged,
                            Err(error) => PrepareOutcome::CleanupFailed(error),
                        }
                    }
                    Err(PrepareError::Cleanup(error)) => PrepareOutcome::CleanupFailed(error),
                    Err(PrepareError::Capture(_))
                        if *stop.borrow()
                            || core.snapshot().lifecycle != Lifecycle::Running =>
                    {
                        PrepareOutcome::CoreStopped
                    }
                    Err(PrepareError::Capture(error)) if is_current_session(core, identity) => {
                        eprintln!("native screen source unavailable: {:?}", error.kind());
                        PrepareOutcome::Failed
                    },
                    Err(PrepareError::Capture(_)) => PrepareOutcome::SessionChanged,
                };
            }
            changed = observed.changed(), if interrupted.is_none() => {
                if changed.is_err() || core.snapshot().lifecycle != Lifecycle::Running {
                    cancel_tx.send_replace(true);
                    interrupted = Some(PrepareOutcome::CoreStopped);
                } else if !is_current_session(core, identity) {
                    cancel_tx.send_replace(true);
                    interrupted = Some(PrepareOutcome::SessionChanged);
                }
            }
            changed = stop.changed(), if interrupted.is_none() => {
                if changed.is_err() || *stop.borrow() {
                    cancel_tx.send_replace(true);
                    interrupted = Some(PrepareOutcome::CoreStopped);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn reset_capture(mut device: ErasedCapture) -> io::Result<()> {
    tokio::task::spawn_blocking(move || device.reset())
        .await
        .map_err(io::Error::other)?
}

struct PreparedCapture {
    device: ErasedCapture,
    displays: Vec<Display>,
    initial_source: u32,
    input: Option<SystemInput>,
}

async fn reset_prepared(mut prepared: PreparedCapture) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let capture = prepared.device.reset();
        let input = if let Some(input) = &mut prepared.input {
            let begun = InputDevice::begin_reset(input);
            let reset = InputDevice::reset(input);
            begun.and(reset)
        } else {
            Ok(())
        };
        capture.and(input)
    })
    .await
    .map_err(io::Error::other)?
}

async fn reset_unattached_input(input: Option<SystemInput>) -> io::Result<()> {
    if let Some(mut input) = input {
        tokio::task::spawn_blocking(move || {
            let begun = InputDevice::begin_reset(&mut input);
            let reset = InputDevice::reset(&mut input);
            begun.and(reset)
        })
        .await
        .map_err(io::Error::other)?
    } else {
        Ok(())
    }
}

async fn prepare_capture(
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
    core: &CoreHandle,
    identity: &SessionIdentity,
    clipboard_factory: &InstalledClipboardFactory,
    privileged: &Arc<crate::privileged_input::PrivilegedInput>,
) -> Result<PreparedCapture, PrepareError> {
    #[cfg(windows)]
    let _ = clipboard_factory;
    #[cfg(windows)]
    {
        use nestlink_platform_capture::WindowsCapture;
        let sources = tokio::task::spawn_blocking(WindowsCapture::enumerate)
            .await
            .map_err(io::Error::other)??;
        if *cancel.borrow() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
        }
        let candidates = sources
            .iter()
            .map(|source| source.display())
            .collect::<Vec<_>>();
        let approval = approve_candidates(core, identity, &candidates, false, &cancel).await?;
        let initial_source = approval
            .initial_source
            .ok_or_else(|| io::Error::other("no approved initial screen"))?;
        let selected = sources
            .into_iter()
            .filter(|source| approval.approved_sources.contains(&source.display().source))
            .collect::<Vec<_>>();
        let displays = selected
            .iter()
            .map(|source| source.display())
            .collect::<Vec<_>>();
        let input_lease = if input_enabled {
            Some(
                core.native_host_input_lease(identity)
                    .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        let input_layout = displays
            .iter()
            .find(|display| display.source == initial_source)
            .map(|display| display.logical)
            .ok_or_else(|| io::Error::other("no initial input layout"))?;
        let privileged = privileged.clone();
        let connection_generation = identity.connection_generation;
        let diagnostics = crate::native_gpu_diagnostics::observer(connection_generation);
        let (device, input) = tokio::task::spawn_blocking(move || {
            let mut device = nestlink_platform_capture::WindowsHostCapture::open_with_observer(
                selected,
                Some(diagnostics),
            )?;
            let input = if input_enabled {
                let opened = privileged
                    .open(
                        input_lease
                            .as_ref()
                            .ok_or_else(|| io::Error::other("no proved input lease"))?,
                        nestlink_remote::input::InputEpoch {
                            input: 1,
                            layout: LAYOUT_EPOCH,
                            connection: connection_generation,
                        },
                        input_layout,
                    )
                    .and_then(|input| match input {
                        Some(input) => Ok(SystemInput::Privileged(input)),
                        None => {
                            nestlink_platform_input::WindowsInput::open().map(SystemInput::Windows)
                        }
                    });
                match opened {
                    Ok(input) => Some(input),
                    Err(error) => {
                        device.reset().map_err(PrepareError::Cleanup)?;
                        return Err(PrepareError::Capture(error));
                    }
                }
            } else {
                None
            };
            Ok::<_, PrepareError>((device, input))
        })
        .await
        .map_err(io::Error::other)??;
        if *cancel.borrow() {
            reset_prepared(PreparedCapture {
                device: ErasedCapture(Box::new(device)),
                displays,
                initial_source,
                input,
            })
            .await
            .map_err(PrepareError::Cleanup)?;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
        }
        Ok(PreparedCapture {
            device: ErasedCapture(Box::new(device)),
            displays,
            initial_source,
            input,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let _ = privileged;
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return prepare_wayland(cancel, input_enabled, core, identity, clipboard_factory).await;
        }
        let display = std::env::var("DISPLAY")
            .ok()
            .filter(|display| !display.is_empty())
            .ok_or_else(|| io::Error::other("no supported desktop display is available"))?;
        prepare_x11(display, cancel, input_enabled, core, identity).await
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (
            cancel,
            input_enabled,
            core,
            identity,
            clipboard_factory,
            privileged,
        );
        Err(io::Error::other("native desktop capture is unsupported on this platform").into())
    }
}

#[cfg(target_os = "linux")]
async fn prepare_x11(
    display_name: String,
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
    core: &CoreHandle,
    identity: &SessionIdentity,
) -> Result<PreparedCapture, PrepareError> {
    use nestlink_platform_capture::X11Capture;
    use nestlink_platform_input::X11CaptureSource;

    let process_id = std::process::id();
    let input_display = display_name.clone();
    let source = tokio::task::spawn_blocking(move || {
        X11CaptureSource::open_for_desktop(&display_name, process_id)
    })
    .await
    .map_err(io::Error::other)??;
    if *cancel.borrow() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
    }
    let candidates = source.displays().to_vec();
    let approval = approve_candidates(core, identity, &candidates, false, &cancel).await?;
    let displays = candidates
        .into_iter()
        .filter(|display| approval.approved_sources.contains(&display.source))
        .collect::<Vec<_>>();
    let selected = displays
        .iter()
        .map(|display| display.source)
        .collect::<Vec<_>>();
    let initial_source = approval
        .initial_source
        .ok_or_else(|| io::Error::other("no approved initial screen"))?;
    let (device, input) = tokio::task::spawn_blocking(move || {
        let mut device = X11Capture::open(source, selected)?;
        let input = if input_enabled {
            match nestlink_platform_input::X11Input::open_for_desktop(&input_display, process_id) {
                Ok(input) => Some(SystemInput::X11(Box::new(input))),
                Err(error) => {
                    device.reset().map_err(PrepareError::Cleanup)?;
                    return Err(PrepareError::Capture(error));
                }
            }
        } else {
            None
        };
        Ok::<_, PrepareError>((device, input))
    })
    .await
    .map_err(io::Error::other)??;
    if *cancel.borrow() {
        reset_prepared(PreparedCapture {
            device: ErasedCapture(Box::new(device)),
            displays,
            initial_source,
            input,
        })
        .await
        .map_err(PrepareError::Cleanup)?;
        return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
    }
    Ok(PreparedCapture {
        device: ErasedCapture(Box::new(device)),
        displays,
        initial_source,
        input,
    })
}

#[cfg(target_os = "linux")]
async fn prepare_wayland(
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
    core: &CoreHandle,
    identity: &SessionIdentity,
    clipboard_factory: &InstalledClipboardFactory,
) -> Result<PreparedCapture, PrepareError> {
    use nestlink_platform_capture::PortalCapture;
    use nestlink_platform_input::portal::{PortalInput, PortalOptions, PortalView};

    let clipboard_binding = core.native_clipboard_status().and_then(|status| {
        let binding = status.binding;
        (binding.request_id == identity.request_id
            && binding.connection_generation == identity.connection_generation
            && (status.permitted_read || status.permitted_write))
            .then_some(binding)
    });

    if input_enabled {
        let options = PortalOptions::current_process(String::new());
        let grant = if clipboard_binding.is_some() {
            PortalInput::request_with_clipboard(options, cancel.clone()).await?
        } else {
            PortalInput::request(options, cancel.clone()).await?
        };
        return prepare_wayland_remote(
            grant,
            true,
            clipboard_binding,
            clipboard_factory,
            cancel,
            core,
            identity,
        )
        .await;
    }

    if let Some(binding) = clipboard_binding {
        let grant = PortalInput::request_clipboard_capture(
            PortalOptions::current_process(String::new()),
            cancel.clone(),
        )
        .await?;
        return prepare_wayland_remote(
            grant,
            false,
            Some(binding),
            clipboard_factory,
            cancel,
            core,
            identity,
        )
        .await;
    }

    let mut grant = PortalView::request_multiple(
        PortalOptions::current_process(String::new()),
        cancel.clone(),
    )
    .await?;
    let granted = grant
        .info()
        .streams
        .iter()
        .map(|stream| Display {
            source: stream.node_id,
            logical: stream.layout,
        })
        .collect::<Vec<_>>();
    if let Err(error) = approve_candidates(core, identity, &granted, true, &cancel).await {
        grant.close().map_err(PrepareError::Cleanup)?;
        return Err(error);
    }
    let device = match PortalCapture::open_view(&mut grant) {
        Ok(device) => device,
        Err(error) => {
            grant.close().map_err(PrepareError::Cleanup)?;
            return Err(error.into());
        }
    };
    let owned = OwnedPortalCapture { device, grant };
    if *cancel.borrow() {
        reset_capture(ErasedCapture(Box::new(owned)))
            .await
            .map_err(PrepareError::Cleanup)?;
        return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
    }
    let displays = owned.device.displays().to_vec();
    let Some(initial_source) = displays.first().map(|d| d.source) else {
        reset_capture(ErasedCapture(Box::new(owned)))
            .await
            .map_err(PrepareError::Cleanup)?;
        return Err(io::Error::other("portal returned no granted screen").into());
    };
    Ok(PreparedCapture {
        device: ErasedCapture(Box::new(owned)),
        displays,
        initial_source,
        input: None,
    })
}

#[cfg(target_os = "linux")]
async fn prepare_wayland_remote(
    mut grant: nestlink_platform_input::portal::PortalInput,
    input_enabled: bool,
    clipboard_binding: Option<NativeClipboardBinding>,
    clipboard_factory: &InstalledClipboardFactory,
    cancel: watch::Receiver<bool>,
    core: &CoreHandle,
    identity: &SessionIdentity,
) -> Result<PreparedCapture, PrepareError> {
    use nestlink_platform_capture::PortalCapture;

    let granted = grant
        .info()
        .streams
        .iter()
        .map(|stream| Display {
            source: stream.node_id,
            logical: stream.layout,
        })
        .collect::<Vec<_>>();
    if let Err(error) = approve_candidates(core, identity, &granted, true, &cancel).await {
        InputDevice::reset(&mut grant).map_err(PrepareError::Cleanup)?;
        return Err(error);
    }
    let mut device = match PortalCapture::open(&mut grant) {
        Ok(device) => device,
        Err(error) => {
            InputDevice::reset(&mut grant).map_err(PrepareError::Cleanup)?;
            return Err(error.into());
        }
    };
    let displays = device.displays().to_vec();
    let Some(initial_source) = displays.first().map(|display| display.source) else {
        let capture = device.reset();
        let input = InputDevice::reset(&mut grant);
        capture.and(input).map_err(PrepareError::Cleanup)?;
        return Err(io::Error::other("Wayland portal returned no granted screen").into());
    };
    if let Some(binding) = clipboard_binding {
        let control = grant.control();
        let clipboard_grant = match grant.take_clipboard_grant() {
            Ok(grant) => grant,
            Err(error) => {
                let capture = device.reset();
                let input = InputDevice::reset(&mut grant);
                capture.and(input).map_err(PrepareError::Cleanup)?;
                return Err(error.into());
            }
        };
        let factory = clipboard_factory.clone();
        let provided = tokio::task::spawn_blocking(move || {
            factory.provide_portal_grant(binding, clipboard_grant, control)
        })
        .await;
        let result = match provided {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error)),
        };
        if let Err(error) = result {
            let capture = device.reset();
            let input = InputDevice::reset(&mut grant);
            capture.and(input).map_err(PrepareError::Cleanup)?;
            return Err(error.into());
        }
    }
    let grant = Arc::new(Mutex::new(grant));
    let input = input_enabled.then(|| SystemInput::Portal(grant.clone()));
    let prepared = PreparedCapture {
        displays,
        initial_source,
        device: ErasedCapture(Box::new(OwnedPortalInputCapture {
            device,
            grant: grant.clone(),
            close_grant_on_reset: !input_enabled,
        })),
        input,
    };
    if *cancel.borrow() {
        reset_prepared(prepared)
            .await
            .map_err(PrepareError::Cleanup)?;
        return Err(io::Error::new(io::ErrorKind::Interrupted, "capture cancelled").into());
    }
    Ok(prepared)
}

struct ErasedCapture(Box<dyn CaptureDevice>);
impl CaptureDevice for ErasedCapture {
    fn reset_before(&mut self, deadline: Instant) -> io::Result<()> {
        self.0.reset_before(deadline)
    }

    fn cancellation(&self) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        self.0.cancellation()
    }
    fn discard_pending_frames(&mut self) -> io::Result<()> {
        self.0.discard_pending_frames()
    }
    fn host_configure(&mut self, c: HostVideoConfig) -> io::Result<bool> {
        self.0.host_configure(c)
    }
    fn host_capture(&mut self, source: u32, repeated: bool) -> io::Result<Option<HostFrame>> {
        self.0.host_capture(source, repeated)
    }
    fn host_encode(&mut self, ticket: u64, pts: u64, keyframe: bool) -> io::Result<HostEncodeStep> {
        self.0.host_encode(ticket, pts, keyframe)
    }
    fn host_drain(&mut self) -> io::Result<HostEncodeStep> {
        self.0.host_drain()
    }
    fn host_set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        self.0.host_set_bitrate(kbps)
    }
    fn poll_frame_for(&mut self, source: u32) -> io::Result<Option<RawFrame>> {
        self.0.poll_frame_for(source)
    }

    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.0.poll_frame()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}

#[cfg(target_os = "linux")]
struct OwnedPortalCapture {
    device: nestlink_platform_capture::PortalCapture,
    grant: nestlink_platform_input::portal::PortalView,
}
#[cfg(target_os = "linux")]
impl CaptureDevice for OwnedPortalCapture {
    fn check(&mut self) -> io::Result<()> {
        self.grant.check()?;
        self.device.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.grant.check()?;
        self.device.poll_frame()
    }
    fn reset(&mut self) -> io::Result<()> {
        let capture = self.device.reset();
        let grant = self.grant.close();
        capture.and(grant)
    }
}

#[cfg(target_os = "linux")]
struct OwnedPortalInputCapture {
    device: nestlink_platform_capture::PortalCapture,
    grant: Arc<Mutex<nestlink_platform_input::portal::PortalInput>>,
    close_grant_on_reset: bool,
}
#[cfg(target_os = "linux")]
impl CaptureDevice for OwnedPortalInputCapture {
    fn check(&mut self) -> io::Result<()> {
        InputDevice::check(
            &mut *self
                .grant
                .lock()
                .map_err(|_| io::Error::other("input portal poisoned"))?,
        )?;
        self.device.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.check()?;
        self.device.poll_frame()
    }
    fn reset(&mut self) -> io::Result<()> {
        let capture = self.device.reset();
        if self.close_grant_on_reset {
            let mut input = self
                .grant
                .lock()
                .map_err(|_| io::Error::other("input portal poisoned"))?;
            let begun = InputDevice::begin_reset(&mut *input);
            let reset = InputDevice::reset(&mut *input);
            capture.and(begun).and(reset)
        } else {
            capture
        }
    }
}

struct StableDisplayCapture {
    inner: ErasedCapture,
    approved: Vec<u32>,
}
impl CaptureDevice for StableDisplayCapture {
    fn reset_before(&mut self, deadline: Instant) -> io::Result<()> {
        self.inner.reset_before(deadline)
    }

    fn cancellation(&self) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        self.inner.cancellation()
    }
    fn discard_pending_frames(&mut self) -> io::Result<()> {
        self.inner.discard_pending_frames()
    }
    fn host_configure(&mut self, c: HostVideoConfig) -> io::Result<bool> {
        if !self.approved.contains(&c.source) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unapproved host source",
            ));
        }
        self.inner.host_configure(c)
    }
    fn host_capture(&mut self, source: u32, repeated: bool) -> io::Result<Option<HostFrame>> {
        self.inner.host_capture(source, repeated)
    }
    fn host_encode(&mut self, ticket: u64, pts: u64, keyframe: bool) -> io::Result<HostEncodeStep> {
        self.inner.host_encode(ticket, pts, keyframe)
    }
    fn host_drain(&mut self) -> io::Result<HostEncodeStep> {
        self.inner.host_drain()
    }
    fn host_set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        self.inner.host_set_bitrate(kbps)
    }

    fn check(&mut self) -> io::Result<()> {
        self.inner.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        let frame = self.inner.poll_frame()?;
        if frame
            .as_ref()
            .is_some_and(|frame| !self.approved.contains(&frame.source))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture produced a source outside local approval",
            ));
        }
        Ok(frame)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.inner.reset()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamExit {
    SessionEnded,
    CaptureFailed,
    TransportFailed,
}

fn observe_quality(
    core: &CoreHandle,
    identity: &SessionIdentity,
    binding: NativeVideoBinding,
    quality: &mut VideoQuality,
    encoding: Duration,
    enqueue: Duration,
) -> io::Result<Option<u32>> {
    let now = Instant::now();
    Ok(
        match core.native_video_receiver_condition(identity, binding, quality.fps())? {
            Some(receiver) => quality.observe_with_receiver(now, encoding, enqueue, receiver),
            None => quality.observe(now, encoding, enqueue),
        },
    )
}
fn stream_capture<D: CaptureDevice>(
    core: &CoreHandle,
    identity: &SessionIdentity,
    controller: VideoController<D>,
    runtime: tokio::runtime::Handle,
    stop: &watch::Receiver<bool>,
) -> (VideoController<D>, StreamExit) {
    let mut active: Option<NativeVideoBinding> = None;
    let mut encoder: Option<VideoEncoder> = None;
    let mut legacy_prepare: Option<(nestlink_media_session::LegacyPrepare, VideoConfig)> = None;
    let mut negotiated_target = false;
    let mut owner_encoding = false;
    let mut owner_output_seen = false;
    let mut pending_sources = std::collections::BTreeMap::new();
    let mut pixels = Zeroizing::new(Vec::new());
    let origin = Instant::now();
    let mut source_pts = std::collections::BTreeMap::<u32, u64>::new();
    let mut selected_since = origin;
    let mut first_deadline = origin + FIRST_FRAME_TIMEOUT;
    let mut next_frame = origin;
    let mut quality = VideoQuality::new(FPS, BITRATE_KBPS, origin);
    let outcome = (|| {
        loop {
            if *stop.borrow() || !is_current_session(core, identity) {
                return (controller, StreamExit::SessionEnded);
            }
            if let Ok(Some(request)) = core.native_display_switch_request(identity)
                && runtime
                    .block_on(core.commit_native_display_switch(identity, &request))
                    .is_err()
            {
                return (controller, StreamExit::CaptureFailed);
            }
            let state = match core.native_displays(identity) {
                Ok(state) => state,
                Err(_) => return (controller, StreamExit::SessionEnded),
            };
            // Drain the bounded capture pipeline during negotiation, retaining no
            // pixels from an old selection and leaving its original grant alive.
            let captured = match if owner_encoding {
                Ok(None)
            } else {
                controller.poll()
            } {
                Ok(frame) => frame,
                Err(_) => return (controller, StreamExit::CaptureFailed),
            };
            if state.pending.is_some() || state.selected.is_none() {
                pixels.clear();
                thread::sleep(CAPTURE_TICK);
                continue;
            }
            let Some(selection) = state.selected.as_ref() else {
                return (controller, StreamExit::CaptureFailed);
            };
            let Some(display) = state
                .displays
                .iter()
                .find(|display| display.source == selection.source)
            else {
                return (controller, StreamExit::CaptureFailed);
            };
            let binding = NativeVideoBinding {
                source: selection.source,
                width: display.width,
                height: display.height,
                layout_epoch: selection.layout_epoch,
            };
            if active != Some(binding) {
                pixels.clear();
                pending_sources.clear();
                let codec_kind = match core.native_video_codec(identity) {
                    Ok(codec) => codec,
                    Err(_) => return (controller, StreamExit::SessionEnded),
                };
                let target_fps = if codec_kind == VideoCodec::H264Baseline {
                    60
                } else {
                    FPS
                };
                let formats = match core.native_video_formats(identity) {
                    Ok(value) => value,
                    Err(_) => return (controller, StreamExit::SessionEnded),
                };
                negotiated_target = formats.is_some();
                if negotiated_target
                    && core
                        .native_video_encoder_backend(identity)
                        .ok()
                        .flatten()
                        .as_deref()
                        != Some("cpu-software")
                {
                    return (controller, StreamExit::CaptureFailed);
                }
                let mut execution_format = None;
                let config = if let Some(formats) = formats {
                    let codec = if codec_kind == VideoCodec::H264Baseline {
                        nestlink_protocol::media_format::Codec::H264
                    } else {
                        nestlink_protocol::media_format::Codec::Vp8
                    };
                    let width = binding.width
                        + (u32::from(codec_kind == VideoCodec::H264Baseline) * (binding.width & 1));
                    let height = binding.height
                        + (u32::from(codec_kind == VideoCodec::H264Baseline)
                            * (binding.height & 1));
                    let target = formats
                        .formats()
                        .iter()
                        .filter(|format| {
                            format.codec == codec
                                && format.width == width
                                && format.height == height
                                && format.frame_rate.denominator == 1
                                && (1..=120).contains(&format.frame_rate.numerator)
                                && (64..=100_000).contains(&format.max_kbps)
                        })
                        .max_by_key(|format| (format.frame_rate.numerator, format.max_kbps));
                    let Some(target) = target else {
                        return (controller, StreamExit::CaptureFailed);
                    };
                    execution_format = Some(*target);
                    VideoConfig {
                        width: binding.width,
                        height: binding.height,
                        fps: target.frame_rate.numerator,
                        bitrate_kbps: target.max_kbps,
                    }
                } else {
                    VideoConfig {
                        width: binding.width,
                        height: binding.height,
                        fps: target_fps,
                        bitrate_kbps: BITRATE_KBPS,
                    }
                };
                quality = VideoQuality::new(config.fps, config.bitrate_kbps, Instant::now());
                legacy_prepare = match nestlink_media_session::LegacyPrepare::new_cpu_visible(
                    codec_kind,
                    config.width,
                    config.height,
                ) {
                    Ok(prepare) => Some((prepare, config)),
                    Err(_) => return (controller, StreamExit::CaptureFailed),
                };
                owner_encoding = if codec_kind == VideoCodec::H264Baseline && !negotiated_target {
                    match controller.host_configure(HostVideoConfig {
                        source: binding.source,
                        width: config.width,
                        height: config.height,
                        fps: config.fps,
                        bitrate_kbps: config.bitrate_kbps,
                        max_level_idc: 42,
                        require_constrained_baseline: false,
                    }) {
                        Ok(enabled) => enabled,
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    }
                } else {
                    false
                };
                if let Some(retired) = encoder.take()
                    && matches!(&retired, VideoEncoder::Execution { .. })
                    && retired.close().is_err()
                {
                    return (controller, StreamExit::CaptureFailed);
                }
                encoder = if owner_encoding {
                    None
                } else {
                    match if negotiated_target && codec_kind == VideoCodec::H264Baseline {
                        match execution_format {
                            Some(format) => {
                                nestlink_media_session::h264_execution_target(format, config)
                                    .and_then(VideoEncoder::with_execution_target)
                            }
                            None => Err(io::Error::other("missing signed execution target")),
                        }
                    } else {
                        VideoEncoder::new(codec_kind, config)
                    } {
                        Ok(e) => Some(e),
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    }
                };
                owner_output_seen = false;
                active = Some(binding);
                selected_since = Instant::now();
                first_deadline = selected_since + FIRST_FRAME_TIMEOUT;
            }
            let keyframe =
                match runtime.block_on(core.native_video_keyframe_needed(identity, binding)) {
                    Ok(needed) => needed,
                    Err(_)
                        if core
                            .native_displays(identity)
                            .is_ok_and(|state| state.pending.is_some()) =>
                    {
                        continue;
                    }
                    Err(_) => return (controller, StreamExit::TransportFailed),
                };
            if owner_encoding {
                let started = Instant::now();
                let frame = match controller.host_capture(keyframe) {
                    Ok(f) => f,
                    Err(_) => return (controller, StreamExit::CaptureFailed),
                };
                let step = if let Some(frame) = frame {
                    let previous = source_pts.entry(binding.source).or_default();
                    let clock = match core.native_video_capture_pts(identity, frame.frame.encode_at)
                    {
                        Ok(p) => p,
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    };
                    let pts = clock.max(previous.saturating_add(1));
                    *previous = pts;
                    controller.host_encode(frame, pts, keyframe)
                } else {
                    controller.host_drain()
                };
                let step = match step {
                    Ok(s) => s,
                    Err(_) => return (controller, StreamExit::CaptureFailed),
                };
                let encoding_time = started.elapsed();
                let enqueue = Instant::now();
                if let Some(mut output) = step.output {
                    if output.source != binding.source
                        || output.epoch.layout != binding.layout_epoch
                        || output.epoch.connection != identity.connection_generation
                    {
                        return (controller, StreamExit::CaptureFailed);
                    }
                    owner_output_seen = true;
                    let packet = &mut output.packet;
                    let Some((prepare, config)) = legacy_prepare.as_mut() else {
                        return (controller, StreamExit::CaptureFailed);
                    };
                    let admitted = prepare
                        .validate(&packet.data, packet.keyframe)
                        .and_then(|sps| prepare.configured(*config, sps));
                    let actual = match admitted {
                        Ok(actual) => actual,
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    };
                    match runtime.block_on(core.propose_native_video_format(identity, actual)) {
                        Ok(true) => {}
                        Ok(false) => {
                            packet.data.zeroize();
                            thread::sleep(Duration::from_nanos(
                                1_000_000_000 / u64::from(config.fps),
                            ));
                            continue;
                        }
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    }
                    let sent = if output.repeated {
                        runtime.block_on(core.send_native_video_recovery_frame(
                            identity,
                            binding,
                            packet.pts_90khz,
                            std::mem::take(&mut packet.data),
                        ))
                    } else {
                        runtime.block_on(core.send_native_video_frame(
                            identity,
                            binding,
                            packet.pts_90khz,
                            packet.keyframe,
                            std::mem::take(&mut packet.data),
                        ))
                    };
                    if sent.is_err()
                        && !core
                            .native_displays(identity)
                            .is_ok_and(|s| s.pending.is_some())
                    {
                        return (controller, StreamExit::TransportFailed);
                    }
                } else if !owner_output_seen && Instant::now() >= first_deadline {
                    return (controller, StreamExit::CaptureFailed);
                }
                if !negotiated_target {
                    let changed = match observe_quality(
                        core,
                        identity,
                        binding,
                        &mut quality,
                        encoding_time,
                        enqueue.elapsed(),
                    ) {
                        Ok(changed) => changed,
                        Err(_) => return (controller, StreamExit::SessionEnded),
                    };
                    if let Some(kbps) = changed
                        && controller.host_set_bitrate(kbps).is_err()
                    {
                        return (controller, StreamExit::CaptureFailed);
                    }
                }
                let fps = if negotiated_target {
                    legacy_prepare.as_ref().map_or(1, |(_, config)| config.fps)
                } else if step.hardware {
                    quality.fps()
                } else {
                    quality.fps().min(FPS)
                };
                next_frame += Duration::from_nanos(1_000_000_000 / u64::from(fps));
                let delay = next_frame.saturating_duration_since(Instant::now());
                if !delay.is_zero() {
                    thread::sleep(delay);
                } else {
                    next_frame = Instant::now();
                }
                continue;
            }
            let fresh = captured.filter(|frame| {
                frame.frame.source == binding.source && frame.frame.captured_at >= selected_since
            });
            let (captured_at, repeated) = if let Some(mut fresh) = fresh {
                if fresh.frame.width != binding.width || fresh.frame.height != binding.height {
                    return (controller, StreamExit::CaptureFailed);
                }
                pixels = Zeroizing::new(std::mem::take(&mut fresh.frame.pixels));
                (fresh.frame.captured_at, false)
            } else if keyframe && !pixels.is_empty() {
                (Instant::now(), true)
            } else {
                if pixels.is_empty() && Instant::now() >= first_deadline {
                    return (controller, StreamExit::CaptureFailed);
                }
                thread::sleep(CAPTURE_TICK);
                continue;
            };
            let previous = source_pts.entry(binding.source).or_default();
            let clock_pts = match core.native_video_capture_pts(identity, captured_at) {
                Ok(pts) => pts,
                Err(_) => return (controller, StreamExit::CaptureFailed),
            };
            let pts = clock_pts.max(previous.saturating_add(1)).max(1);
            *previous = pts;
            let Some(current_encoder) = encoder.as_mut() else {
                return (controller, StreamExit::CaptureFailed);
            };
            if pending_sources.len() >= 16 {
                return (controller, StreamExit::CaptureFailed);
            }
            let encoding_started = Instant::now();
            let step = match current_encoder.encode_step(&pixels, pts, keyframe || repeated) {
                Ok(step) => step,
                Err(_) => return (controller, StreamExit::CaptureFailed),
            };
            if step.accepted {
                pending_sources.insert(pts, repeated);
            }
            let mut encoded = match step.output {
                Some(encoded) => encoded,
                None => {
                    thread::sleep(CAPTURE_TICK);
                    continue;
                }
            };
            let Some((prepare, config)) = legacy_prepare.as_mut() else {
                return (controller, StreamExit::CaptureFailed);
            };
            let admitted = prepare
                .validate(&encoded.data, encoded.keyframe)
                .and_then(|sps| prepare.configured(*config, sps));
            let actual = match admitted {
                Ok(actual) => actual,
                Err(_) => return (controller, StreamExit::CaptureFailed),
            };
            let Some(repeated) = pending_sources.remove(&encoded.pts_90khz) else {
                return (controller, StreamExit::CaptureFailed);
            };
            let execution = current_encoder.execution_receipt();
            if negotiated_target {
                let Some(receipt) = execution.as_ref() else {
                    return (controller, StreamExit::CaptureFailed);
                };
                if runtime
                    .block_on(core.register_native_video_execution(identity, receipt.clone()))
                    .is_err()
                {
                    return (controller, StreamExit::CaptureFailed);
                }
            }
            match runtime.block_on(core.propose_native_video_format(identity, actual)) {
                Ok(true) => {}
                Ok(false) => {
                    encoded.data.zeroize();
                    thread::sleep(Duration::from_nanos(1_000_000_000 / u64::from(config.fps)));
                    continue;
                }
                Err(_) => return (controller, StreamExit::CaptureFailed),
            }
            let encoding_time = encoding_started.elapsed();
            let enqueue_started = Instant::now();
            let sent = if let Some(execution) = execution {
                runtime.block_on(core.send_native_video_execution_frame(
                    identity,
                    binding,
                    encoded.pts_90khz,
                    encoded.keyframe,
                    repeated,
                    encoded.data,
                    execution,
                ))
            } else if repeated {
                runtime.block_on(core.send_native_video_recovery_frame(
                    identity,
                    binding,
                    encoded.pts_90khz,
                    encoded.data,
                ))
            } else {
                runtime.block_on(core.send_native_video_frame(
                    identity,
                    binding,
                    encoded.pts_90khz,
                    encoded.keyframe,
                    encoded.data,
                ))
            };
            if sent.is_err()
                && !core
                    .native_displays(identity)
                    .is_ok_and(|state| state.pending.is_some())
            {
                return (controller, StreamExit::TransportFailed);
            }
            let hardware = current_encoder.hardware();
            let changed = match observe_quality(
                core,
                identity,
                binding,
                &mut quality,
                encoding_time,
                enqueue_started.elapsed(),
            ) {
                Ok(changed) => changed,
                Err(_) => return (controller, StreamExit::SessionEnded),
            };
            if negotiated_target {
                let approved = match core.native_video_formats(identity) {
                    Ok(Some(formats)) => formats,
                    _ => return (controller, StreamExit::SessionEnded),
                };
                let next = match nestlink_media_session::select_h264_budget(
                    &approved,
                    actual,
                    quality.fps(),
                    quality.bitrate_kbps(),
                ) {
                    Ok(next) => next,
                    Err(_) => return (controller, StreamExit::CaptureFailed),
                };
                if next != actual {
                    let next_config = VideoConfig {
                        fps: next.frame_rate.numerator,
                        bitrate_kbps: next.max_kbps,
                        ..*config
                    };
                    // Retire and join the original sealed owner before a new
                    // one can register. The first actual replacement AU goes
                    // through the same proposal and exact format ACK above.
                    let Some(retired) = encoder.take() else {
                        return (controller, StreamExit::CaptureFailed);
                    };
                    if retired.close().is_err() {
                        return (controller, StreamExit::CaptureFailed);
                    }
                    pending_sources.clear();
                    let next_encoder =
                        nestlink_media_session::h264_execution_target(next, next_config)
                            .and_then(VideoEncoder::with_execution_target);
                    encoder = match next_encoder {
                        Ok(next) => Some(next),
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    };
                    legacy_prepare = match nestlink_media_session::LegacyPrepare::new_cpu_visible(
                        VideoCodec::H264Baseline,
                        next_config.width,
                        next_config.height,
                    ) {
                        Ok(next) => Some((next, next_config)),
                        Err(_) => return (controller, StreamExit::CaptureFailed),
                    };
                    next_frame = Instant::now();
                    continue;
                }
            } else if let Some(kbps) = changed
                && current_encoder.set_bitrate(kbps).is_err()
            {
                return (controller, StreamExit::CaptureFailed);
            }
            let fps = if negotiated_target {
                config.fps
            } else if hardware {
                quality.fps()
            } else {
                quality.fps().min(FPS)
            };
            next_frame += Duration::from_nanos(1_000_000_000 / u64::from(fps));
            let delay = next_frame.saturating_duration_since(Instant::now());
            if !delay.is_zero() {
                thread::sleep(delay);
            } else {
                next_frame = Instant::now();
            }
        }
    })();
    if let Some(retired) = encoder.take()
        && matches!(&retired, VideoEncoder::Execution { .. })
        && retired.close().is_err()
    {
        return (outcome.0, StreamExit::CaptureFailed);
    }
    outcome
}

async fn approve_candidates(
    core: &CoreHandle,
    identity: &SessionIdentity,
    displays: &[Display],
    system_approved: bool,
    cancel: &watch::Receiver<bool>,
) -> Result<NativeDisplayState, PrepareError> {
    let mut descriptors = displays
        .iter()
        .map(|display| DisplayDescriptor {
            source: display.source,
            left: display.logical.left,
            top: display.logical.top,
            width: display.logical.width,
            height: display.logical.height,
            label: format!("Display {}", display.source),
        })
        .collect::<Vec<_>>();
    descriptors.sort_by_key(|display| display.source);
    core.publish_native_display_candidates(identity, descriptors, system_approved)?;
    loop {
        if *cancel.borrow() || !is_current_session(core, identity) {
            return Err(
                io::Error::new(io::ErrorKind::Interrupted, "display selection cancelled").into(),
            );
        }
        let state = core.native_displays(identity)?;
        if !state.local_approval_required && !state.approved_sources.is_empty() {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn fail_if_current(
    core: &CoreHandle,
    identity: &SessionIdentity,
    observed: &mut watch::Receiver<Arc<nestlink_app_core::Snapshot>>,
) {
    if is_current_session(core, identity) {
        let _ = core.fail_native_video_capture(identity);
    }
    core.clear_native_video_stream_for(identity);
    while is_current_session(core, identity) && core.snapshot().lifecycle == Lifecycle::Running {
        if observed.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct FakeCapture {
        frame: Option<RawFrame>,
        reset_error: bool,
    }

    impl CaptureDevice for FakeCapture {
        fn check(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
            Ok(self.frame.take())
        }
        fn reset(&mut self) -> io::Result<()> {
            if self.reset_error {
                Err(io::Error::other("cleanup failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn preserves_the_locally_approved_physical_source() {
        let device = ErasedCapture(Box::new(FakeCapture {
            frame: Some(RawFrame {
                source: 17,
                width: 1,
                height: 1,
                captured_at: Instant::now(),
                pixels: vec![0; 4],
            }),
            reset_error: false,
        }));
        let mut capture = StableDisplayCapture {
            inner: device,
            approved: vec![17],
        };
        assert!(matches!(capture.poll_frame(), Ok(Some(frame)) if frame.source == 17));
        assert!(matches!(capture.poll_frame(), Ok(None)));
    }

    #[test]
    fn rejects_a_frame_from_a_different_desktop_source() {
        let device = ErasedCapture(Box::new(FakeCapture {
            frame: Some(RawFrame {
                source: 18,
                width: 1,
                height: 1,
                captured_at: Instant::now(),
                pixels: vec![0; 4],
            }),
            reset_error: false,
        }));
        let mut capture = StableDisplayCapture {
            inner: device,
            approved: vec![17],
        };
        assert!(capture.poll_frame().is_err());
    }

    #[test]
    fn propagates_capture_cleanup_result() {
        let device = ErasedCapture(Box::new(FakeCapture {
            frame: None,
            reset_error: true,
        }));
        let mut capture = StableDisplayCapture {
            inner: device,
            approved: vec![17],
        };
        assert!(capture.reset().is_err());
    }

    #[tokio::test]
    async fn runner_wait_retains_owner_when_select_cancels_and_propagates_failure_once() {
        let (stop, _stop_rx) = watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = started_tx.send(());
            let _ = finish_rx.await;
            Err(io::Error::other("simulated capture cleanup failure"))
        });
        let mut owner = NativeVideoCaptureTask {
            stop,
            task: Some(task),
        };
        assert!(started_rx.await.is_ok());

        {
            let waiting = owner.wait();
            tokio::pin!(waiting);
            tokio::select! {
                biased;
                result = &mut waiting => panic!("pending task completed early: {result:?}"),
                _ = tokio::task::yield_now() => {},
            }
        }
        assert!(finish_tx.send(()).is_ok());

        let Err(error) = owner.wait().await else {
            panic!("capture cleanup failure was not retained");
        };
        assert_eq!(error.to_string(), "simulated capture cleanup failure");
        assert!(owner.task.is_none());
        assert!(owner.wait().await.is_ok());
        assert!(owner.join().await.is_ok());
    }
}
