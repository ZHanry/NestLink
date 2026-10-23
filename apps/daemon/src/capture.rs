use crate::browser_data::{self, BrowserHostDataRegistry};
use nestlink_app_core::{
    BrowserHostCaptureProvider, BrowserHostConfig, BrowserHostDisplayApproval, BrowserHostError,
    PreparedBrowserCapture,
};
use nestlink_identity::VerifiedPermit;
use nestlink_media_codec::VideoConfig;
use nestlink_protocol::{
    Permission,
    native_displays::{DisplayDescriptor, catalog_key},
};
use nestlink_remote::{
    LeaseControl,
    audio::{AudioBinding, AudioCaptureController},
    input::{InputController, InputDevice, InputEpoch, PlatformInput},
    video::{CaptureDevice, Display, VideoController, VideoEpoch},
};
use nestlink_sdk::webrtc_host::{
    HostAudioSource, HostInputSource, HostMediaSources, HostVideoSource, WebRtcHostError,
};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio::sync::watch;

pub fn browser_host_config(
    data: Arc<BrowserHostDataRegistry>,
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
) -> BrowserHostConfig {
    BrowserHostConfig::new(Arc::new(SystemCaptureProvider::new(data, privileged)))
}

struct SystemCaptureProvider {
    data: Arc<BrowserHostDataRegistry>,
    #[cfg(windows)]
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
    #[cfg(target_os = "linux")]
    mode: LinuxCaptureMode,
}

impl SystemCaptureProvider {
    fn new(
        data: Arc<BrowserHostDataRegistry>,
        privileged: Arc<crate::privileged_input::PrivilegedInput>,
    ) -> Self {
        #[cfg(not(windows))]
        let _ = privileged;
        Self {
            data,
            #[cfg(windows)]
            privileged,
            #[cfg(target_os = "linux")]
            mode: LinuxCaptureMode::from_environment(),
        }
    }
}

pub(crate) enum SystemInput {
    #[cfg(windows)]
    Windows(nestlink_platform_input::WindowsInput),
    #[cfg(windows)]
    Privileged(crate::privileged_input::RenewingBrokerInput),
    #[cfg(target_os = "linux")]
    X11(Box<nestlink_platform_input::X11Input>),
    #[cfg(target_os = "linux")]
    Portal(Arc<Mutex<nestlink_platform_input::portal::PortalInput>>),
    #[cfg(not(any(windows, target_os = "linux")))]
    Unsupported,
}

impl InputDevice for SystemInput {
    fn check(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => InputDevice::check(device),
            #[cfg(windows)]
            Self::Privileged(device) => InputDevice::check(device),
            #[cfg(target_os = "linux")]
            Self::X11(device) => InputDevice::check(&mut **device),
            #[cfg(target_os = "linux")]
            Self::Portal(device) => InputDevice::check(
                &mut *device
                    .lock()
                    .map_err(|_| io::Error::other("portal input grant poisoned"))?,
            ),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native input is unavailable on this target",
            )),
        }
    }

    fn begin_reset(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => InputDevice::begin_reset(device),
            #[cfg(windows)]
            Self::Privileged(device) => InputDevice::begin_reset(device),
            #[cfg(target_os = "linux")]
            Self::X11(device) => InputDevice::begin_reset(&mut **device),
            #[cfg(target_os = "linux")]
            Self::Portal(device) => InputDevice::begin_reset(
                &mut *device
                    .lock()
                    .map_err(|_| io::Error::other("portal input grant poisoned"))?,
            ),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Ok(()),
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => InputDevice::reset(device),
            #[cfg(windows)]
            Self::Privileged(device) => InputDevice::reset(device),
            #[cfg(target_os = "linux")]
            Self::X11(device) => InputDevice::reset(&mut **device),
            #[cfg(target_os = "linux")]
            Self::Portal(device) => InputDevice::reset(
                &mut *device
                    .lock()
                    .map_err(|_| io::Error::other("portal input grant poisoned"))?,
            ),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Ok(()),
        }
    }

    fn select_source(
        &mut self,
        source: u32,
        layout: nestlink_remote::input::InputLayout,
    ) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => device.select_source(source, layout),
            #[cfg(windows)]
            Self::Privileged(device) => device.select_source(source, layout),
            #[cfg(target_os = "linux")]
            Self::X11(device) => device.select_source(source, layout),
            #[cfg(target_os = "linux")]
            Self::Portal(device) => device
                .lock()
                .map_err(|_| io::Error::other("portal input poisoned"))?
                .select_source(source, layout),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native input is unavailable on this target",
            )),
        }
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => InputDevice::inject(device, input),
            #[cfg(windows)]
            Self::Privileged(device) => InputDevice::inject(device, input),
            #[cfg(target_os = "linux")]
            Self::X11(device) => InputDevice::inject(&mut **device, input),
            #[cfg(target_os = "linux")]
            Self::Portal(device) => InputDevice::inject(
                &mut *device
                    .lock()
                    .map_err(|_| io::Error::other("portal input grant poisoned"))?,
                input,
            ),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native input is unavailable on this target",
            )),
        }
    }
}

impl BrowserHostCaptureProvider for SystemCaptureProvider {
    fn supports_audio(&self) -> bool {
        cfg!(any(windows, target_os = "linux"))
    }

    fn supports_input(&self) -> bool {
        cfg!(any(windows, target_os = "linux"))
    }

    fn supports_files(&self) -> bool {
        cfg!(any(windows, target_os = "linux"))
    }

    fn supports_clipboard(&self) -> bool {
        #[cfg(windows)]
        {
            true
        }
        #[cfg(target_os = "linux")]
        {
            matches!(&self.mode, LinuxCaptureMode::X11(_))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            false
        }
    }

    fn prepare_data<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<nestlink_sdk::webrtc_host::HostDataFactory>,
                        BrowserHostError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if *cancel.borrow() {
                return Err(BrowserHostError::Cancelled);
            }
            let factory =
                browser_data::prepare_data_factory(self.data.clone(), request_id, permit)?;
            if *cancel.borrow() {
                return Err(BrowserHostError::Cancelled);
            }
            Ok(Some(factory))
        })
    }

    fn prepare<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        Box::pin(async move {
            let binding = nestlink_app_core::browser_host_binding(request_id, permit)?;
            self.prepare_request(&binding, &permit.claims().permissions, cancel)
                .await
        })
    }

    fn prepare_request<'a>(
        &'a self,
        _binding: &'a nestlink_app_core::BrowserHostBinding,
        permissions: &'a [i32],
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        Box::pin(async move {
            if *cancel.borrow() {
                return Err(BrowserHostError::Cancelled);
            }
            #[cfg(windows)]
            {
                prepare_windows(
                    cancel,
                    permissions.contains(&(Permission::Input as i32)),
                    self.privileged.clone(),
                )
                .await
            }
            #[cfg(target_os = "linux")]
            {
                let input_enabled = permissions.contains(&(Permission::Input as i32));
                match &self.mode {
                    LinuxCaptureMode::Wayland => prepare_wayland(cancel, input_enabled).await,
                    LinuxCaptureMode::X11(display) => {
                        prepare_x11(display.clone(), cancel, input_enabled).await
                    }
                    LinuxCaptureMode::Unavailable => Err(BrowserHostError::Capture),
                }
            }
            #[cfg(not(any(windows, target_os = "linux")))]
            {
                let _ = cancel;
                Err(BrowserHostError::Capture)
            }
        })
    }
}

fn host_media<D: CaptureDevice>(
    device: D,
    displays: Vec<Display>,
    approval: BrowserHostDisplayApproval,
    candidates: Vec<DisplayDescriptor>,
    lease: LeaseControl,
    permit: VerifiedPermit,
    input: Option<SystemInput>,
) -> Result<HostMediaSources, WebRtcHostError> {
    let claims = permit.claims();
    if !claims.permissions.contains(&(Permission::View as i32)) {
        return Err(WebRtcHostError::Permit);
    }
    let approved_displays = candidates
        .into_iter()
        .filter(|display| approval.sources.contains(&display.source))
        .collect::<Vec<_>>();
    if approved_displays.len() != approval.sources.len()
        || approved_displays
            .iter()
            .map(|display| display.source)
            .collect::<Vec<_>>()
            != approval.sources
    {
        return Err(WebRtcHostError::Permit);
    }
    let remote_catalog = catalog_key(
        &approval.catalog.request_id,
        approval.catalog.connection_generation,
        approval.catalog.revision,
        &approved_displays,
    )?;
    let display = displays
        .iter()
        .find(|display| display.source == approval.initial_source)
        .copied()
        .ok_or(WebRtcHostError::Permit)?;
    if displays.len() != approved_displays.len()
        || displays.iter().any(|display| {
            !approved_displays.iter().any(|candidate| {
                candidate.source == display.source
                    && candidate.left == display.logical.left
                    && candidate.top == display.logical.top
                    && candidate.width == display.logical.width
                    && candidate.height == display.logical.height
            })
        })
    {
        return Err(WebRtcHostError::Permit);
    }
    let epoch = VideoEpoch {
        layout: 1,
        connection: claims.connection_generation,
    };
    let codec = VideoConfig {
        width: display.logical.width,
        height: display.logical.height,
        fps: 30,
        bitrate_kbps: 4_000,
    };
    let controller = VideoController::attach_selected(
        lease.clone(),
        device,
        epoch,
        displays.clone(),
        approval.initial_source,
    )?;
    let audio = if claims.permissions.contains(&(Permission::Audio as i32)) {
        let binding = AudioBinding {
            connection: claims.connection_generation,
            source: 0,
            channels: 2,
        };
        // The factory runs only after mutual endpoint proof. Check the same
        // lease before opening this machine's selected system loopback device.
        lease.check_media_binding(
            nestlink_transport_stream::Channel::Audio,
            binding.connection,
        )?;
        let audio_device = crate::native_audio::open_system_capture(binding)?;
        let audio_controller =
            AudioCaptureController::attach(lease.clone(), audio_device, binding)?;
        Some(HostAudioSource::new(audio_controller, binding, 64_000))
    } else {
        None
    };
    let media = HostMediaSources::new(
        HostVideoSource::with_display_catalog(
            controller,
            epoch,
            display,
            codec,
            remote_catalog,
            approved_displays,
        )?,
        audio,
    );
    if let Some(mut input) = input {
        let input_epoch = InputEpoch {
            input: 1,
            layout: 1,
            connection: claims.connection_generation,
        };
        input.select_source(approval.initial_source, display.logical)?;
        let controller = InputController::attach(lease, input, input_epoch, display.logical)?;
        Ok(media.with_input(HostInputSource::new(
            controller,
            input_epoch,
            display.logical,
        )))
    } else {
        Ok(media)
    }
}

#[cfg(windows)]
async fn prepare_windows(
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
) -> Result<PreparedBrowserCapture, BrowserHostError> {
    use nestlink_platform_capture::WindowsCapture;
    let sources = tokio::task::spawn_blocking(WindowsCapture::enumerate)
        .await
        .map_err(|_| BrowserHostError::Capture)?
        .map_err(|_| BrowserHostError::Capture)?;
    if *cancel.borrow() {
        return Err(BrowserHostError::Cancelled);
    }
    if sources.is_empty() {
        return Err(BrowserHostError::Capture);
    }
    let offered = sources
        .into_iter()
        .map(|source| {
            let display = source.display();
            (
                source,
                display_descriptor(display, format!("Display {}", display.source)),
            )
        })
        .collect::<Vec<_>>();
    let mut offered = offered;
    offered.sort_by_key(|(_, display)| display.source);
    let descriptors = offered
        .iter()
        .map(|(_, display)| display.clone())
        .collect::<Vec<_>>();
    let candidates = descriptors.clone();
    Ok(
        PreparedBrowserCapture::new(descriptors, move |approval, lease, permit| {
            // This starts pixel capture only after WebRTC mutual proof.
            let selected = offered
                .iter()
                .filter(|(_, display)| approval.sources.contains(&display.source))
                .map(|(source, _)| source.clone())
                .collect::<Vec<_>>();
            let mut capture = WindowsCapture::open(selected)?;
            let displays = capture.displays().to_vec();
            let display = displays
                .iter()
                .find(|display| display.source == approval.initial_source)
                .copied()
                .ok_or(WebRtcHostError::Permit)?;
            let input = if input_enabled {
                let opened = privileged
                    .open(
                        &lease,
                        InputEpoch {
                            input: 1,
                            layout: 1,
                            connection: permit.claims().connection_generation,
                        },
                        display.logical,
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
                        capture.reset()?;
                        return Err(error.into());
                    }
                }
            } else {
                None
            };
            host_media(
                capture, displays, approval, candidates, lease, permit, input,
            )
        })
        .with_video_parameters(30, 4_000),
    )
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
enum LinuxCaptureMode {
    Wayland,
    X11(String),
    Unavailable,
}

#[cfg(target_os = "linux")]
impl LinuxCaptureMode {
    fn from_environment() -> Self {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return Self::Wayland;
        }
        match std::env::var("DISPLAY") {
            Ok(display) if !display.is_empty() => Self::X11(display),
            _ => Self::Unavailable,
        }
    }
}

#[cfg(target_os = "linux")]
async fn prepare_wayland(
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
) -> Result<PreparedBrowserCapture, BrowserHostError> {
    use nestlink_platform_capture::PortalCapture;
    use nestlink_platform_input::portal::{PortalInput, PortalOptions, PortalView};

    if input_enabled {
        let grant = PortalInput::request(PortalOptions::current_process(String::new()), cancel)
            .await
            .map_err(|_| BrowserHostError::Capture)?;
        if grant.info().streams.is_empty() || grant.info().streams.len() > 64 {
            return Err(BrowserHostError::Capture);
        }
        let mut descriptors = portal_descriptors(&grant.info().streams);
        descriptors.sort_by_key(|display| display.source);
        let candidates = descriptors.clone();
        let grant = Arc::new(Mutex::new(grant));
        return Ok(PreparedBrowserCapture::new(
            descriptors,
            move |approval, lease, permit| {
                let capture = {
                    let mut grant = grant.lock().map_err(|_| {
                        WebRtcHostError::Io(io::Error::other("portal input grant poisoned"))
                    })?;
                    PortalCapture::open_selected(&mut grant, &approval.sources)?
                };
                let displays = capture.displays().to_vec();
                if !displays
                    .iter()
                    .any(|display| display.source == approval.initial_source)
                {
                    return Err(WebRtcHostError::Permit);
                }
                let input = SystemInput::Portal(grant.clone());
                host_media(
                    OwnedPortalInputCapture {
                        capture,
                        grant: grant.clone(),
                    },
                    displays,
                    approval,
                    candidates,
                    lease,
                    permit,
                    Some(input),
                )
            },
        ));
    }

    // The user grants ScreenCast consent before proof, but no PipeWire capture
    // starts until the post-proof media factory consumes this closure.
    let grant = PortalView::request_multiple(PortalOptions::current_process(String::new()), cancel)
        .await
        .map_err(|_| BrowserHostError::Capture)?;
    if grant.info().streams.is_empty() || grant.info().streams.len() > 64 {
        return Err(BrowserHostError::Capture);
    }
    let mut descriptors = portal_descriptors(&grant.info().streams);
    descriptors.sort_by_key(|display| display.source);
    let candidates = descriptors.clone();
    Ok(PreparedBrowserCapture::new(
        descriptors,
        move |approval, lease, permit| {
            let mut grant = grant;
            let capture = PortalCapture::open_view_selected(&mut grant, &approval.sources)?;
            let displays = capture.displays().to_vec();
            if !displays
                .iter()
                .any(|display| display.source == approval.initial_source)
            {
                return Err(WebRtcHostError::Permit);
            }
            host_media(
                OwnedPortalCapture { capture, grant },
                displays,
                approval,
                candidates,
                lease,
                permit,
                None,
            )
        },
    ))
}

#[cfg(target_os = "linux")]
async fn prepare_x11(
    display: String,
    cancel: watch::Receiver<bool>,
    input_enabled: bool,
) -> Result<PreparedBrowserCapture, BrowserHostError> {
    use nestlink_platform_capture::X11Capture;
    use nestlink_platform_input::X11CaptureSource;

    // Connect only to enumerate the local monitor snapshot. X11Capture, which
    // reads pixels, is opened later by the proof-gated factory below.
    let process_id = std::process::id();
    let capture_display = display.clone();
    let source = tokio::task::spawn_blocking(move || {
        X11CaptureSource::open_for_desktop(&capture_display, process_id)
    })
    .await
    .map_err(|_| BrowserHostError::Capture)?
    .map_err(|_| BrowserHostError::Capture)?;
    if *cancel.borrow() {
        return Err(BrowserHostError::Cancelled);
    }
    let mut descriptors = source
        .displays()
        .iter()
        .map(|display| display_descriptor(*display, format!("Display {}", display.source)))
        .collect::<Vec<_>>();
    descriptors.sort_by_key(|display| display.source);
    let candidates = descriptors.clone();
    if descriptors.is_empty() {
        return Err(BrowserHostError::Capture);
    }
    let input = if input_enabled {
        let input_display = display.clone();
        let process_id = std::process::id();
        Some(
            tokio::task::spawn_blocking(move || {
                nestlink_platform_input::X11Input::open_for_desktop(&input_display, process_id)
            })
            .await
            .map_err(|_| BrowserHostError::Capture)?
            .map(|input| SystemInput::X11(Box::new(input)))
            .map_err(|_| BrowserHostError::Capture)?,
        )
    } else {
        None
    };
    Ok(PreparedBrowserCapture::new(
        descriptors,
        move |approval, lease, permit| {
            let capture = X11Capture::open(source, approval.sources.clone())?;
            let displays = capture.displays().to_vec();
            host_media(
                capture, displays, approval, candidates, lease, permit, input,
            )
        },
    ))
}

fn display_descriptor(display: Display, label: String) -> DisplayDescriptor {
    DisplayDescriptor {
        source: display.source,
        left: display.logical.left,
        top: display.logical.top,
        width: display.logical.width,
        height: display.logical.height,
        label,
    }
}

#[cfg(target_os = "linux")]
fn portal_descriptors(
    streams: &[nestlink_platform_input::portal::PortalStream],
) -> Vec<DisplayDescriptor> {
    streams
        .iter()
        .map(|stream| {
            display_descriptor(
                Display {
                    source: stream.node_id,
                    logical: stream.layout,
                },
                format!("Display {}", stream.node_id),
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
struct OwnedPortalCapture {
    capture: nestlink_platform_capture::PortalCapture,
    grant: nestlink_platform_input::portal::PortalView,
}

#[cfg(target_os = "linux")]
impl CaptureDevice for OwnedPortalCapture {
    fn check(&mut self) -> std::io::Result<()> {
        self.grant.check()?;
        self.capture.check()
    }

    fn poll_frame(&mut self) -> std::io::Result<Option<nestlink_remote::video::RawFrame>> {
        self.grant.check()?;
        self.capture.poll_frame()
    }

    fn reset(&mut self) -> std::io::Result<()> {
        let capture = self.capture.reset();
        let grant = self.grant.close();
        capture.and(grant)
    }
}

#[cfg(target_os = "linux")]
struct OwnedPortalInputCapture {
    capture: nestlink_platform_capture::PortalCapture,
    grant: Arc<Mutex<nestlink_platform_input::portal::PortalInput>>,
}

#[cfg(target_os = "linux")]
impl CaptureDevice for OwnedPortalInputCapture {
    fn check(&mut self) -> io::Result<()> {
        InputDevice::check(
            &mut *self
                .grant
                .lock()
                .map_err(|_| io::Error::other("portal input grant poisoned"))?,
        )?;
        self.capture.check()
    }

    fn poll_frame(&mut self) -> io::Result<Option<nestlink_remote::video::RawFrame>> {
        InputDevice::check(
            &mut *self
                .grant
                .lock()
                .map_err(|_| io::Error::other("portal input grant poisoned"))?,
        )?;
        self.capture.poll_frame()
    }

    fn reset(&mut self) -> io::Result<()> {
        self.capture.reset()
    }
}
