//! Android provider for the existing Rust WebRTC BrowserHost endpoint.
//!
//! Platform preparation may wait for the one-use Android projection consent,
//! but it must not open a VirtualDisplay, read a frame, or start AudioRecord.
//! `activate_after_proof` is consumed from the BrowserHost media factory, which
//! runs only after the SDK verifies mutual endpoint proof.

use crate::browser_data::AndroidBrowserDataRegistry;
use nestlink_app_core::{
    BrowserHostBinding, BrowserHostCaptureProvider, BrowserHostConfig, BrowserHostError,
    BrowserHostStatus, CoreHandle, PreparedBrowserCapture, browser_host_binding,
};
use nestlink_identity::VerifiedPermit;
use nestlink_media_codec::VideoConfig;
use nestlink_protocol::{
    Permission,
    native_displays::{DisplayDescriptor, catalog_key},
};
use nestlink_remote::{
    LeaseControl,
    audio::{AudioBinding, AudioCaptureController, AudioCaptureDevice, CapturedAudio},
    input::{InputController, InputDevice, InputEpoch, InputLayout, PlatformInput},
    video::{CaptureDevice, Display, RawFrame, VideoController, VideoEpoch},
};
use nestlink_sdk::webrtc_host::{
    HostAudioSource, HostDataFactory, HostInputSource, HostMediaSources, HostVideoSource,
    WebRtcHostError,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
};
use tokio::sync::watch;

pub(crate) type Prepared<T> =
    Pin<Box<dyn Future<Output = Result<T, BrowserHostError>> + Send + 'static>>;

/// Android UI/JNI service boundary. Consent results are keyed by the exact
/// BrowserHost binding and are one-use; implementations retain SAF URIs and
/// system clipboard state locally rather than placing them in a remote message.
pub(crate) trait AndroidBrowserHostPort: Send + Sync + 'static {
    fn supports_audio(&self) -> bool;
    fn supports_input(&self) -> bool;

    fn prepare_capture(
        &self,
        binding: BrowserHostBinding,
        cancel: watch::Receiver<bool>,
    ) -> Prepared<Box<dyn AndroidBrowserCaptureReservation>>;
}

pub(crate) trait AndroidBrowserCaptureReservation: Send {
    /// Immutable geometry of the staged one-use system grant. This must not
    /// activate MediaProjection or read a frame.
    fn prepared_display(&self) -> Result<Display, BrowserHostError>;

    /// Starts the exact projection owner after proof and attaches only the
    /// media devices authorized by this permit. Every returned device is
    /// already tied to this binding and stops through its LeaseControl owner.
    fn activate_after_proof(
        self: Box<Self>,
        lease: LeaseControl,
        binding: &BrowserHostBinding,
        permit: &VerifiedPermit,
    ) -> Result<AndroidBrowserCaptureOwners, WebRtcHostError>;
}

pub(crate) struct AndroidBrowserCaptureOwners {
    pub display: Display,
    pub video: Box<dyn CaptureDevice>,
    pub audio: Option<Box<dyn AudioCaptureDevice>>,
    pub input: Option<Box<dyn InputDevice>>,
}

pub(crate) struct AndroidBrowserHostProvider {
    port: Arc<dyn AndroidBrowserHostPort>,
    data: Arc<AndroidBrowserDataRegistry>,
    core: Arc<OnceLock<CoreHandle>>,
}

impl AndroidBrowserHostProvider {
    pub(crate) fn config(
        port: Arc<dyn AndroidBrowserHostPort>,
        data: Arc<AndroidBrowserDataRegistry>,
        core: Arc<OnceLock<CoreHandle>>,
    ) -> BrowserHostConfig {
        BrowserHostConfig::new(Arc::new(Self { port, data, core }))
    }
}

impl BrowserHostCaptureProvider for AndroidBrowserHostProvider {
    fn supports_audio(&self) -> bool {
        self.port.supports_audio()
    }

    fn supports_input(&self) -> bool {
        self.port.supports_input()
    }

    fn supports_files(&self) -> bool {
        self.data.supports_files()
    }

    fn supports_clipboard(&self) -> bool {
        self.data.supports_clipboard()
    }

    fn prepare_data<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<HostDataFactory>, BrowserHostError>> + Send + 'a>>
    {
        let data = Arc::clone(&self.data);
        let core = self.core.get().cloned();
        let request_id = request_id.to_owned();
        let permit = permit.clone();
        Box::pin(async move {
            if *cancel.borrow() {
                return Err(BrowserHostError::Cancelled);
            }
            let core = core.ok_or(BrowserHostError::Capture)?;
            data.prepare_factory(core, &request_id, &permit).map(Some)
        })
    }

    fn prepare<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        self.prepare_binding(browser_host_binding(request_id, permit), cancel)
    }

    fn prepare_request<'a>(
        &'a self,
        binding: &'a BrowserHostBinding,
        _permissions: &'a [i32],
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        self.prepare_binding(Ok(binding.clone()), cancel)
    }
}

impl AndroidBrowserHostProvider {
    fn prepare_binding<'a>(
        &'a self,
        binding: Result<BrowserHostBinding, BrowserHostError>,
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        let port = Arc::clone(&self.port);
        let core = self.core.get().cloned();
        Box::pin(async move {
            let binding = binding?;
            if binding.request_id.is_empty()
                || binding.connection_generation == 0
                || *cancel.borrow()
            {
                return Err(BrowserHostError::Cancelled);
            }
            let reservation = tokio::select! {
                biased;
                _ = async {
                    let mut cancel = cancel.clone();
                    loop {
                        if *cancel.borrow() || cancel.changed().await.is_err() { break; }
                    }
                } => return Err(BrowserHostError::Cancelled),
                result = port.prepare_capture(binding.clone(), cancel.clone()) => result?,
            };
            let display = reservation.prepared_display()?;
            if display.source != 0 {
                return Err(BrowserHostError::Capture);
            }
            let displays = vec![DisplayDescriptor {
                source: 0,
                left: display.logical.left,
                top: display.logical.top,
                width: display.logical.width,
                height: display.logical.height,
                label: "Android shared screen".into(),
            }];
            let local_catalog = catalog_key(
                &binding.request_id,
                binding.connection_generation,
                1,
                &displays,
            )
            .map_err(|_| BrowserHostError::Capture)?;
            let core = core.ok_or(BrowserHostError::Capture)?;
            // The system picker has already approved this exact one-use source.
            // Carry that local fact into Core's normal catalog-CAS command; View
            // permission alone is never treated as display approval.
            let consent_task =
                DisplayConsentTask::start(core, binding.clone(), local_catalog.clone(), cancel);
            let prepared =
                PreparedBrowserCapture::new(displays, move |approval, lease, proved_permit| {
                    let _consent_task = consent_task;
                    let proved_binding = browser_host_binding(&binding.request_id, &proved_permit)
                        .map_err(|_| WebRtcHostError::Permit)?;
                    if !nestlink_app_core::browser_preparation_matches(&binding, &proved_binding)
                        || approval.binding != proved_binding
                        || approval.catalog != local_catalog
                        || approval.sources.as_slice() != [0]
                        || approval.initial_source != 0
                    {
                        return Err(WebRtcHostError::Permit);
                    }
                    let claims = proved_permit.claims();
                    let has = |permission| claims.permissions.contains(&(permission as i32));
                    if !has(Permission::View) {
                        return Err(WebRtcHostError::Permit);
                    }
                    let owners = reservation.activate_after_proof(
                        lease.clone(),
                        &binding,
                        &proved_permit,
                    )?;
                    let connection = claims.connection_generation;
                    let epoch = VideoEpoch {
                        layout: 1,
                        connection,
                    };
                    if owners.display.source != display.source
                        || owners.display.logical != display.logical
                    {
                        return Err(WebRtcHostError::Permit);
                    }
                    let displays = vec![DisplayDescriptor {
                        source: display.source,
                        left: display.logical.left,
                        top: display.logical.top,
                        width: display.logical.width,
                        height: display.logical.height,
                        label: "Android shared screen".into(),
                    }];
                    let catalog = catalog_key(&claims.session_id, connection, 1, &displays)?;
                    let video_controller = VideoController::attach(
                        lease.clone(),
                        ErasedCapture(owners.video),
                        epoch,
                        vec![display],
                    )?;
                    let codec = VideoConfig {
                        width: display.logical.width,
                        height: display.logical.height,
                        fps: 15,
                        bitrate_kbps: 2_000,
                    };
                    let audio = if has(Permission::Audio) {
                        let binding = AudioBinding {
                            connection,
                            source: 0,
                            channels: 2,
                        };
                        lease.check_media_binding(
                            nestlink_transport_stream::Channel::Audio,
                            connection,
                        )?;
                        let device = owners.audio.ok_or(WebRtcHostError::Permit)?;
                        let controller = AudioCaptureController::attach(
                            lease.clone(),
                            ErasedAudio(device),
                            binding,
                        )?;
                        Some(HostAudioSource::new(controller, binding, 64_000))
                    } else {
                        None
                    };
                    let mut media = HostMediaSources::new(
                        HostVideoSource::with_display_catalog(
                            video_controller,
                            epoch,
                            display,
                            codec,
                            catalog,
                            displays,
                        )?,
                        audio,
                    );
                    if has(Permission::Input) {
                        let device = owners.input.ok_or(WebRtcHostError::Permit)?;
                        let input_epoch = InputEpoch {
                            input: 1,
                            layout: 1,
                            connection,
                        };
                        let controller = InputController::attach(
                            lease,
                            ErasedInput(device),
                            input_epoch,
                            display.logical,
                        )?;
                        media = media.with_input(HostInputSource::new(
                            controller,
                            input_epoch,
                            display.logical,
                        ));
                    }
                    Ok(media)
                });
            Ok(prepared)
        })
    }
}

/// The prepared factory owns this short-lived observer. Dropping preparation
/// cancels it; it retains no JNI handle, media device, or detached cleanup task.
struct DisplayConsentTask(tokio::task::JoinHandle<()>);

impl DisplayConsentTask {
    fn start(
        core: CoreHandle,
        binding: BrowserHostBinding,
        catalog: nestlink_protocol::native_displays::DisplayCatalogKey,
        mut cancel: watch::Receiver<bool>,
    ) -> Self {
        Self(tokio::spawn(async move {
            let mut snapshots = core.observe();
            let generation = snapshots.borrow().generation;
            let approve = async {
                loop {
                    let snapshot = snapshots.borrow_and_update().clone();
                    if *cancel.borrow() || snapshot.generation != generation {
                        return;
                    }
                    let Some(host) = snapshot.browser_host.data.as_ref() else {
                        return;
                    };
                    if host.status != BrowserHostStatus::Establishing
                        || host.request_id != binding.request_id
                    {
                        return;
                    }
                    if let Some(offered) = &host.displays.catalog {
                        if host.binding.as_ref() == Some(&binding)
                            && offered == &catalog
                            && host.displays.approval_required
                        {
                            let _ = core
                                .approve_browser_host_displays(
                                    binding,
                                    generation,
                                    catalog,
                                    vec![0],
                                    0,
                                )
                                .await;
                        }
                        return;
                    }
                    tokio::select! {
                        biased;
                        changed = cancel.changed() => {
                            if changed.is_err() || *cancel.borrow() { return; }
                        }
                        changed = snapshots.changed() => {
                            if changed.is_err() { return; }
                        }
                    }
                }
            };
            let _ = tokio::time::timeout(std::time::Duration::from_secs(120), approve).await;
        }))
    }
}

impl Drop for DisplayConsentTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ErasedCapture(Box<dyn CaptureDevice>);
impl CaptureDevice for ErasedCapture {
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

struct ErasedAudio(Box<dyn AudioCaptureDevice>);
impl nestlink_remote::audio::AudioDevice for ErasedAudio {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}
impl AudioCaptureDevice for ErasedAudio {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        self.0.poll_chunk()
    }
}

struct ErasedInput(Box<dyn InputDevice>);
impl InputDevice for ErasedInput {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.0.begin_reset()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        self.0.select_source(source, layout)
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        self.0.inject(input)
    }
}
