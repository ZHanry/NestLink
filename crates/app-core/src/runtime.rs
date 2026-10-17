use crate::{
    Action, ApprovedServer, Authentication, BrowserHostBinding, BrowserHostDataView,
    BrowserHostStatus, BrowserHostView, Event, Failure, FailureKind, Lifecycle,
    NativeSessionCleanup, NativeSessionConfig, NativeSessionEffects, NativeSessionStatus,
    NativeSessionStopReason, NativeSessionView, OperationId, OperationKind, OperationResult,
    OperationStatus, PublicOutput, RemoteEffect, ServerView, Snapshot, action::SectionKey,
    sdk_call,
};
use crate::{
    BrowserHostDisplayApproval, BrowserHostDisplayOffer, BrowserHostExit, BrowserHostFailure,
    BrowserHostReady, run_browser_host,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[path = "runtime/native_network_control.rs"]
mod native_network_control;
#[path = "runtime/native_recovery.rs"]
mod native_recovery;
#[path = "runtime/service_host.rs"]
mod service_host;
use service_host::{
    PREVIEW_LIFETIME, PREVIEW_LIFETIME_MS, PendingServiceHostPreview, SERVICE_HOST_CLEANUP_POLL,
    ServiceHostBinding, ServiceHostContext, ServiceHostOwner, ServiceHostTarget,
    approved_service_matches, binding_for, https_backend_sha256,
    local_service_host_cleanup_unconfirmed, parse_local_choice, principal_matches_sdk,
    service_is_hostable, snapshot_context_matches_binding, snapshot_matches_binding,
};
#[path = "native_audio.rs"]
mod native_audio;
use native_audio::NativeAudioRoute;
pub use native_audio::{NativeAudioBinding, NativeAudioError, NativeAudioRole};
#[path = "native_clipboard.rs"]
mod native_clipboard;
use native_clipboard::NativeClipboardRoute;
pub use native_clipboard::*;
#[path = "native_files.rs"]
mod native_files;
pub use native_files::*;
use native_files::{NativeFileBudget, NativeFilesRoute};
use nestlink_identity::VerifiedPermit;
use nestlink_media_session::{
    DecodedVideo, SessionMediaTiming, VideoLayout, VideoPresentation, VideoReceiver,
};
use nestlink_protocol::{
    NativeVideo, NativeVideoFeedback, Permission, SCHEMA_VERSION, VIDEO_KEYFRAME_INTERVAL_MS,
};
use nestlink_remote::{
    ChannelReceiver, ChannelRuntime, ChannelSender, DeliveryGuard, LeaseControl,
    video::{CaptureDevice, Display, VideoController, VideoEpoch},
};
pub use nestlink_sdk::download_queue::{NativeDownloadQueueLimits, NativeDownloadQueueStatus};
use nestlink_sdk::services::{
    HttpsBackendTls, LocalServiceRuntime, LocalServiceTargetConsent, ServiceHostWait,
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, PathSet, Sdk, StopReason,
    download_queue::{
        NATIVE_DOWNLOAD_ACTIVE_MAX, NATIVE_DOWNLOAD_RESERVED_MAX, NATIVE_DOWNLOAD_TASKS_MAX,
    },
    native::{
        CleanupStatus, DialError, NativeEndpoint, NativeSession, NativeSessionControl,
        NativeSessionOptions, SessionEstablishError, StopReport,
    },
};
use nestlink_transport_stream::Channel;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::{JoinError, JoinHandle},
};
use zeroize::{Zeroize, Zeroizing};

#[path = "native_input.rs"]
mod native_input;
use native_input::NativeInputRoute;
pub use native_input::{
    NativeInputAction, NativeInputBinding, NativeInputError, NativeInputLayout,
};

#[path = "native_displays.rs"]
mod native_displays;
use native_displays::NativeDisplayRoute;
pub use native_displays::{
    DisplayCatalogKey, DisplayDescriptor, DisplaySelection, NativeDisplayRequest,
    NativeDisplayState,
};

const NATIVE_PERMIT_POLL_INTERVAL: Duration = Duration::from_millis(750);

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Counts queued and running operations together, including abandoned tickets.
    pub operations: usize,
    /// Independent capacity keeps logout and server switching usable under load.
    pub controls: usize,
    pub history: usize,
    pub sensitive_outputs: usize,
    /// Shared per-Core limits for queued/running native downloads and their
    /// temporary destination bytes.
    pub native_downloads: NativeDownloadQueueLimits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 16,
            controls: 4,
            history: 64,
            sensitive_outputs: 4,
            native_downloads: NativeDownloadQueueLimits::default(),
        }
    }
}
impl Limits {
    fn valid(self) -> bool {
        (1..=32).contains(&self.operations)
            && (1..=8).contains(&self.controls)
            && (self.operations + self.controls..=256).contains(&self.history)
            && (1..=8).contains(&self.sensitive_outputs)
            && (1..=NATIVE_DOWNLOAD_ACTIVE_MAX).contains(&self.native_downloads.active)
            && (self.native_downloads.active..=NATIVE_DOWNLOAD_TASKS_MAX)
                .contains(&self.native_downloads.tasks)
            && (1..=NATIVE_DOWNLOAD_RESERVED_MAX).contains(&self.native_downloads.reserved_bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("product core is stopping or stopped")]
    Stopped,
    #[error("product operation capacity reached")]
    Capacity,
    #[error("operation input exceeds its contract")]
    Invalid,
    #[error("the UI generation was replaced before submission")]
    StaleGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BrowserHostDataError {
    #[error("browser host session binding is stale")]
    StaleBinding,
    #[error("browser host data direction is not permitted or unavailable")]
    Unauthorized,
    #[error("Core generation changed before the local data action completed")]
    StaleGeneration,
    #[error("browser host data state is invalid")]
    Invalid,
    #[error("product core is stopping or stopped")]
    Stopped,
    #[error("product control capacity reached")]
    Capacity,
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHostDisplayError {
    #[error("browser host display offer is stale or already approved")]
    StaleOffer,
    #[error("selected displays are outside the offered catalog or exceed its budget")]
    InvalidSelection,
    #[error("Core generation changed before the local display approval completed")]
    StaleGeneration,
    #[error("product core is stopping or stopped")]
    Stopped,
    #[error("product control capacity reached")]
    Capacity,
}
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("invalid product core limits")]
    Limits,
    #[error("a running Tokio runtime is required")]
    Runtime,
    #[error("invalid native session configuration")]
    NativeSessionConfig,
}
#[derive(Debug, thiserror::Error)]
#[error("product core ended before delivering an operation result")]
pub struct CoreClosed;

/// No Clone/Serialize. The binding explicitly consumes this once, then clears
/// its display/cache on generation changes and clears its IPC encoding buffer.
pub enum SensitiveMaterial {}
impl std::fmt::Debug for SensitiveMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveMaterial([redacted])")
    }
}
type SecretSlot = Arc<Mutex<Option<SensitiveMaterial>>>;

pub struct Completion {
    pub result: OperationResult,
    sensitive: Option<SecretSlot>,
    generation: Arc<AtomicU64>,
}
impl Completion {
    pub fn is_current(&self) -> bool {
        self.result.generation == self.generation.load(Ordering::Acquire)
    }
    /// Returns None after consumption or after a logout/switch/expiry fence.
    pub fn take_sensitive(&mut self) -> Option<SensitiveMaterial> {
        let slot = self.sensitive.take()?;
        let mut value = slot.lock().ok()?;
        if !self.is_current() {
            value.take();
            return None;
        }
        value.take()
    }
    fn redact_stale(&mut self) {
        if !self.is_current() {
            self.result.status = OperationStatus::Superseded;
            self.result.output = PublicOutput::None;
            self.result.failure = None;
            if let Some(slot) = self.sensitive.take()
                && let Ok(mut value) = slot.lock()
            {
                value.take();
            }
        }
    }
}

pub struct Ticket {
    id: OperationId,
    reply: oneshot::Receiver<Completion>,
}
impl Ticket {
    pub fn id(&self) -> OperationId {
        self.id
    }
    /// Dropping this wait never aborts an already dispatched HTTP transaction.
    pub async fn wait(self) -> Result<Completion, CoreClosed> {
        let mut completion = self.reply.await.map_err(|_| CoreClosed)?;
        completion.redact_stale();
        Ok(completion)
    }
    pub fn try_complete(&mut self) -> Result<Option<Completion>, CoreClosed> {
        match self.reply.try_recv() {
            Ok(mut completion) => {
                completion.redact_stale();
                Ok(Some(completion))
            }
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            Err(oneshot::error::TryRecvError::Closed) => Err(CoreClosed),
        }
    }
}

pub struct CancelTicket(oneshot::Receiver<Result<bool, SubmitError>>);
impl CancelTicket {
    /// True means a still-owned operation accepted cancellation, not rollback.
    pub async fn wait(self) -> Result<bool, CoreClosed> {
        Ok(self.0.await.map_err(|_| CoreClosed)?.unwrap_or(false))
    }
    /// Also reports when the actor's execution-time generation check rejects a
    /// queued cancellation after the UI has already been replaced.
    pub async fn wait_for_generation(self) -> Result<Result<bool, SubmitError>, CoreClosed> {
        self.0.await.map_err(|_| CoreClosed)
    }
}

struct Shared {
    closing: Arc<AtomicBool>,
    next_id: AtomicU64,
    generation: Arc<AtomicU64>,
    operations: Arc<Semaphore>,
    controls: Arc<Semaphore>,
    native_video: Mutex<Option<Arc<NativeVideoRoute>>>,
    native_displays: Mutex<Option<Arc<NativeDisplayRoute>>>,
    native_video_presentation: Mutex<Option<Arc<NativeVideoPresentationRoute>>>,
    native_input: Mutex<Option<Arc<NativeInputRoute>>>,
    native_audio: Mutex<Option<Arc<NativeAudioRoute>>>,
    native_audio_owners: Mutex<Vec<Arc<NativeAudioRoute>>>,
    native_clipboard: Mutex<Option<Arc<NativeClipboardRoute>>>,
    native_clipboard_owners: Mutex<Vec<Arc<NativeClipboardRoute>>>,
    native_clipboard_factory: Mutex<Option<Arc<dyn NativeClipboardPlatformFactory>>>,
    native_files: Mutex<Option<Arc<NativeFilesRoute>>>,
    native_files_owners: Mutex<Vec<Arc<NativeFilesRoute>>>,
    native_file_budget: Arc<NativeFileBudget>,
}
#[derive(Debug, thiserror::Error)]
pub enum NativeVideoError {
    #[error("no connected host View session is authorized")]
    Unauthorized,
    #[error("host video frame does not match its bound source, layout or sequence")]
    Invalid,
    #[error("authorized host video transport stopped")]
    Transport,
    #[error("platform capture cleanup failed: {0}")]
    Cleanup(#[source] io::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeVideoBinding {
    pub source: u32,
    pub width: u32,
    pub height: u32,
    pub layout_epoch: u64,
}
/// Original proved request and transport generation. Generations are scoped
/// to a request and cannot identify a platform owner on their own.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionBinding {
    pub request_id: String,
    pub connection_generation: u64,
}
#[derive(Default)]
struct NativeVideoCursor {
    binding: Option<NativeVideoBinding>,
    sequence: u64,
    pts_90khz: Option<u64>,
    last_feedback: Option<NativeVideoFeedback>,
    keyframe_pending: bool,
    last_keyframe: Option<Instant>,
    retired_sources: std::collections::BTreeMap<u32, NativeVideoHistory>,
}
#[derive(Clone)]
struct NativeVideoHistory {
    binding: NativeVideoBinding,
    sequence: u64,
    pts_90khz: Option<u64>,
    last_feedback: Option<NativeVideoFeedback>,
    last_keyframe: Option<Instant>,
}
impl NativeVideoCursor {
    fn bind(&mut self, binding: NativeVideoBinding, active: bool) -> Result<(), NativeVideoError> {
        if let Some(existing) = self.binding {
            if active {
                return if existing == binding {
                    Ok(())
                } else {
                    Err(NativeVideoError::Invalid)
                };
            }
            if binding.layout_epoch <= existing.layout_epoch {
                return Err(NativeVideoError::Invalid);
            }
        }
        if let Some(existing) = self.binding.filter(|old| old.source != binding.source) {
            if self.retired_sources.len() >= 64
                && !self.retired_sources.contains_key(&binding.source)
            {
                return Err(NativeVideoError::Invalid);
            }
            self.retired_sources.insert(
                existing.source,
                NativeVideoHistory {
                    binding: existing,
                    sequence: self.sequence,
                    pts_90khz: self.pts_90khz,
                    last_feedback: self.last_feedback.take(),
                    last_keyframe: self.last_keyframe,
                },
            );
            if let Some(history) = self.retired_sources.remove(&binding.source) {
                self.sequence = history.sequence;
                self.pts_90khz = history.pts_90khz;
                self.last_feedback = history.last_feedback;
                self.last_keyframe = history.last_keyframe;
            } else {
                self.sequence = 0;
                self.pts_90khz = None;
                self.last_feedback = None;
                self.last_keyframe = None;
            }
        }
        self.binding = Some(binding);
        self.keyframe_pending = true;
        Ok(())
    }

    fn feedback(&mut self, request: NativeVideoFeedback) -> Result<(), NativeVideoError> {
        let binding = self.binding.ok_or(NativeVideoError::Invalid)?;
        if request.source != binding.source {
            let history = self
                .retired_sources
                .get_mut(&request.source)
                .ok_or(NativeVideoError::Invalid)?;
            let mut retired = NativeVideoCursor {
                binding: Some(history.binding),
                sequence: history.sequence,
                pts_90khz: history.pts_90khz,
                last_feedback: history.last_feedback,
                last_keyframe: history.last_keyframe,
                ..NativeVideoCursor::default()
            };
            retired.feedback(request)?;
            history.last_feedback = retired.last_feedback;
            return Ok(());
        }
        if request.layout_epoch > binding.layout_epoch || request.last_sequence > self.sequence {
            return Err(NativeVideoError::Invalid);
        }
        if self.last_feedback.as_ref() == Some(&request) {
            return Ok(());
        }
        let expected = self
            .last_feedback
            .as_ref()
            .map_or(Some(1), |last| last.request_sequence.checked_add(1));
        if expected != Some(request.request_sequence)
            || self
                .last_feedback
                .as_ref()
                .is_some_and(|last| request.last_sequence < last.last_sequence)
        {
            return Err(NativeVideoError::Invalid);
        }
        // Feedback already in flight for a retired layout consumes its request
        // sequence but cannot force media from that layout to return.
        self.keyframe_pending |= request.layout_epoch == binding.layout_epoch;
        self.last_feedback = Some(request);
        Ok(())
    }

    fn keyframe_needed(&self, now: Instant) -> bool {
        self.keyframe_pending
            && self.last_keyframe.is_none_or(|last| {
                now.saturating_duration_since(last)
                    >= Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS)
            })
    }

    fn keyframe_sent(&mut self, binding: NativeVideoBinding, sequence: u64, now: Instant) {
        self.last_keyframe = Some(now);
        if self.binding == Some(binding)
            && self.last_feedback.as_ref().is_none_or(|feedback| {
                feedback.layout_epoch != binding.layout_epoch || feedback.last_sequence < sequence
            })
        {
            // Feedback can arrive while the encoded frame waits for capacity.
            // A report about this very frame still requires a later keyframe.
            self.keyframe_pending = false;
        }
    }

    /// Reserve before the bounded async send can yield, so cancellation cannot
    /// reuse a frame id that may already have reached the transport writer.
    fn reserve(&mut self, pts_90khz: u64) -> Result<u64, NativeVideoError> {
        if pts_90khz > i64::MAX as u64
            || self.pts_90khz.is_some_and(|previous| pts_90khz <= previous)
        {
            return Err(NativeVideoError::Invalid);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(NativeVideoError::Invalid)?;
        self.sequence = sequence;
        self.pts_90khz = Some(pts_90khz);
        Ok(sequence)
    }
}
struct HostVideoGate {
    state: Mutex<HostVideoGateState>,
}
#[derive(Default)]
struct HostVideoGateState {
    active: bool,
    generation: u64,
    retired: bool,
}
impl HostVideoGate {
    fn is_live(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retired
    }
    fn is_active(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
    fn open(&self) -> Result<(), NativeVideoError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.retired {
            return Err(NativeVideoError::Unauthorized);
        }
        if !state.active {
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(NativeVideoError::Invalid)?;
            state.active = true;
        }
        Ok(())
    }
    fn pause(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active = false;
    }
    fn retire(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = false;
        state.retired = true;
    }
    fn guard(self: &Arc<Self>) -> HostVideoDeliveryGuard {
        let generation = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        HostVideoDeliveryGuard {
            gate: self.clone(),
            generation,
        }
    }
}
struct HostVideoDeliveryGuard {
    gate: Arc<HostVideoGate>,
    generation: u64,
}
impl DeliveryGuard for HostVideoDeliveryGuard {
    fn check(&self) -> io::Result<()> {
        let state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active && !state.retired && state.generation == self.generation {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host video source is no longer active",
            ))
        }
    }
}
struct NativeVideoRoute {
    request_id: String,
    connection_generation: u64,
    sender: ChannelSender,
    lease: LeaseControl,
    gate: Arc<HostVideoGate>,
    send_order: AsyncMutex<()>,
    cursor: Mutex<NativeVideoCursor>,
    timing: SessionMediaTiming,
}
struct GuardedNativeCapture<D: CaptureDevice> {
    device: D,
    guard: HostVideoDeliveryGuard,
}
impl<D: CaptureDevice> CaptureDevice for GuardedNativeCapture<D> {
    fn check(&mut self) -> io::Result<()> {
        self.guard.check()?;
        self.device.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<nestlink_remote::video::RawFrame>> {
        self.guard.check()?;
        let mut frame = self.device.poll_frame()?;
        if let Err(error) = self.guard.check() {
            if let Some(frame) = &mut frame {
                frame.pixels.zeroize();
            }
            return Err(error);
        }
        Ok(frame)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.device.reset()
    }
}
struct LiveNativeCapture<D: CaptureDevice> {
    device: D,
    gate: Arc<HostVideoGate>,
}
impl<D: CaptureDevice> CaptureDevice for LiveNativeCapture<D> {
    fn check(&mut self) -> io::Result<()> {
        if !self.gate.is_live() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture grant retired",
            ));
        }
        self.device.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<nestlink_remote::video::RawFrame>> {
        self.check()?;
        let mut frame = self.device.poll_frame()?;
        if !self.gate.is_live() {
            if let Some(frame) = frame.as_mut() {
                frame.pixels.zeroize();
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture grant retired",
            ));
        }
        Ok(frame)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.device.reset()
    }
}
fn reject_native_capture<D: CaptureDevice>(
    mut device: D,
    error: NativeVideoError,
) -> NativeVideoError {
    let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.reset()))
        .unwrap_or_else(|_| Err(io::Error::other("capture cleanup panicked")));
    reset.err().map_or(error, NativeVideoError::Cleanup)
}
struct NativeVideoPresentationRoute {
    request_id: String,
    connection_generation: u64,
    generation: u64,
    presentation: VideoPresentation,
}
impl NativeVideoRoute {
    fn retire(&self) {
        self.gate.retire();
        let _ = self.sender.discard_video();
    }

    async fn ordered_send(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, NativeVideoError> {
        let mut stopped = self.lease.subscribe_stopped();
        if stopped.borrow().is_some() {
            return Err(NativeVideoError::Unauthorized);
        }
        let guard = tokio::select! { biased;
            _ = stopped.changed() => return Err(NativeVideoError::Unauthorized),
            guard = self.send_order.lock() => guard,
        };
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(|_| NativeVideoError::Unauthorized)?;
        Ok(guard)
    }
}

impl Shared {
    fn set_native_video_route(&self, route: Option<Arc<NativeVideoRoute>>) {
        let mut current = self
            .native_video
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = std::mem::replace(&mut *current, route) {
            previous.retire();
        }
    }
    fn native_video_route(&self) -> Option<Arc<NativeVideoRoute>> {
        self.native_video
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    fn clear_native_video_route(&self) {
        self.set_native_video_route(None);
        self.set_native_video_presentation(None);
        self.set_native_input_route(None);
        self.set_native_display_route(None);
    }
    fn set_native_video_presentation(&self, route: Option<Arc<NativeVideoPresentationRoute>>) {
        let mut current = self
            .native_video_presentation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = std::mem::replace(&mut *current, route) {
            previous.presentation.retire();
        }
    }
}
#[derive(Clone)]
pub struct CoreHandle {
    commands: mpsc::Sender<Envelope>,
    controls: mpsc::Sender<Control>,
    shared: Arc<Shared>,
    view: watch::Receiver<Arc<Snapshot>>,
}
impl CoreHandle {
    fn native_host_video_route(
        &self,
        binding: &NativeSessionBinding,
    ) -> Result<Arc<NativeVideoRoute>, NativeVideoError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeVideoError::Unauthorized);
        }
        let snapshot = self.snapshot();
        let session = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|session| {
                session.status == NativeSessionStatus::Connected
                    && session.host_view_authorized
                    && session.request_id == binding.request_id
                    && session.connection_generation == binding.connection_generation
            })
            .ok_or(NativeVideoError::Unauthorized)?;
        self.shared
            .native_video_route()
            .filter(|route| {
                route.request_id == session.request_id
                    && route.connection_generation == session.connection_generation
            })
            .ok_or(NativeVideoError::Unauthorized)
    }

    pub fn native_host_session_binding(&self) -> Option<NativeSessionBinding> {
        let snapshot = self.snapshot();
        let session = snapshot.native_session.data.as_ref()?;
        let binding = NativeSessionBinding {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        };
        self.native_host_video_route(&binding).ok()?;
        Some(binding)
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.view.borrow().clone()
    }

    /// Return the exact browser proof binding only while this local install
    /// owns a connected browser-host session. Native sessions never satisfy
    /// this lookup.
    pub fn browser_host_data_binding(&self) -> Option<BrowserHostBinding> {
        if self.shared.closing.load(Ordering::Acquire) {
            return None;
        }
        let snapshot = self.snapshot();
        browser_host_data_binding_for(&snapshot, self.shared.generation.load(Ordering::Acquire))
    }

    /// Publish sanitized local approvals and root labels for the exact proved
    /// browser session. `expected_generation` fences a stale UI action but is
    /// not part of the stable browser binding.
    pub async fn update_browser_host_data(
        &self,
        binding: BrowserHostBinding,
        expected_generation: u64,
        data: BrowserHostDataView,
    ) -> Result<(), BrowserHostDataError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(BrowserHostDataError::Stopped);
        }
        if expected_generation != self.shared.generation.load(Ordering::Acquire) {
            return Err(BrowserHostDataError::StaleGeneration);
        }
        let snapshot = self.snapshot();
        if !browser_host_data_binding_matches(
            &snapshot,
            self.shared.generation.load(Ordering::Acquire),
            &binding,
        ) {
            return Err(BrowserHostDataError::StaleBinding);
        }
        let permit = self.capacity(true).map_err(|error| match error {
            SubmitError::Stopped => BrowserHostDataError::Stopped,
            SubmitError::Capacity => BrowserHostDataError::Capacity,
            SubmitError::StaleGeneration => BrowserHostDataError::StaleGeneration,
            SubmitError::Invalid => BrowserHostDataError::Invalid,
        })?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::BrowserHostDataUpdate {
                binding: Box::new(binding),
                expected_generation,
                data,
                reply,
                _permit: permit,
            })
            .map_err(|error| match send_error(error) {
                SubmitError::Stopped => BrowserHostDataError::Stopped,
                SubmitError::Capacity => BrowserHostDataError::Capacity,
                SubmitError::StaleGeneration => BrowserHostDataError::StaleGeneration,
                SubmitError::Invalid => BrowserHostDataError::Invalid,
            })?;
        receive.await.unwrap_or(Err(BrowserHostDataError::Stopped))
    }

    /// Approve an exact subset of the current browser-host display catalog.
    /// This is available while establishing because no capture can start until
    /// the approval reaches the proof-gated media factory.
    pub async fn approve_browser_host_displays(
        &self,
        binding: BrowserHostBinding,
        expected_generation: u64,
        catalog: DisplayCatalogKey,
        sources: Vec<u32>,
        initial_source: u32,
    ) -> Result<(), BrowserHostDisplayError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(BrowserHostDisplayError::Stopped);
        }
        if expected_generation != self.shared.generation.load(Ordering::Acquire) {
            return Err(BrowserHostDisplayError::StaleGeneration);
        }
        let snapshot = self.snapshot();
        if !valid_browser_host_display_selection(
            &snapshot,
            self.shared.generation.load(Ordering::Acquire),
            &binding,
            &catalog,
            &sources,
            initial_source,
        ) {
            return Err(BrowserHostDisplayError::StaleOffer);
        }
        let permit = self.capacity(true).map_err(|error| match error {
            SubmitError::Stopped => BrowserHostDisplayError::Stopped,
            SubmitError::Capacity => BrowserHostDisplayError::Capacity,
            SubmitError::StaleGeneration => BrowserHostDisplayError::StaleGeneration,
            SubmitError::Invalid => BrowserHostDisplayError::InvalidSelection,
        })?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::BrowserHostDisplayApproval {
                approval: BrowserHostDisplayApproval {
                    binding,
                    catalog,
                    sources,
                    initial_source,
                },
                expected_generation,
                reply,
                _permit: permit,
            })
            .map_err(|error| match send_error(error) {
                SubmitError::Stopped => BrowserHostDisplayError::Stopped,
                SubmitError::Capacity => BrowserHostDisplayError::Capacity,
                SubmitError::StaleGeneration => BrowserHostDisplayError::StaleGeneration,
                SubmitError::Invalid => BrowserHostDisplayError::InvalidSelection,
            })?;
        receive
            .await
            .unwrap_or(Err(BrowserHostDisplayError::Stopped))
    }

    pub fn observe(&self) -> watch::Receiver<Arc<Snapshot>> {
        self.view.clone()
    }
    fn native_video_presentation(
        &self,
    ) -> Result<Arc<NativeVideoPresentationRoute>, NativeVideoError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeVideoError::Unauthorized);
        }
        let snapshot = self.snapshot();
        let session = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|session| session.status == NativeSessionStatus::Connected)
            .ok_or(NativeVideoError::Unauthorized)?;
        self.shared
            .native_video_presentation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|route| {
                route.request_id == session.request_id
                    && route.connection_generation == session.connection_generation
                    && route.generation == snapshot.generation
                    && route.generation == self.shared.generation.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or(NativeVideoError::Unauthorized)
    }
    /// Nonblocking controller pixels, decoded on a dedicated worker. Every
    /// dequeue rechecks the View lease and this product session's generation.
    pub fn poll_native_video(&self) -> Result<Option<DecodedVideo>, NativeVideoError> {
        let route = self.native_video_presentation()?;
        let frame = route
            .presentation
            .poll_video()
            .map_err(|_| NativeVideoError::Transport)?;
        if !Arc::ptr_eq(&self.native_video_presentation()?, &route) {
            return Err(NativeVideoError::Unauthorized);
        }
        Ok(frame)
    }
    /// Layout is published before decoding so UI bindings can remove an old
    /// image while a new layout is awaiting its first usable keyframe.
    pub fn native_video_layout(
        &self,
        source: u32,
    ) -> Result<Option<VideoLayout>, NativeVideoError> {
        self.native_video_presentation()?
            .presentation
            .layout(source)
            .map_err(|_| NativeVideoError::Transport)
    }
    /// Common session capture clock, shared with system audio and retained on
    /// every source switch. The caller supplies the real capture Instant.
    pub fn native_video_capture_pts(
        &self,
        binding: &NativeSessionBinding,
        captured_at: Instant,
    ) -> Result<u64, NativeVideoError> {
        let route = self.native_host_video_route(binding)?;
        route
            .timing
            .capture
            .video_pts(captured_at)
            .map_err(|_| NativeVideoError::Invalid)
    }
    /// Bind a single platform capture source to the active host View lease.
    /// Pause and discard the previous stream before binding a strictly newer
    /// layout epoch. Frame sequence and presentation time remain monotonic.
    pub async fn configure_native_video_stream(
        &self,
        session_binding: &NativeSessionBinding,
        source: u32,
        width: u32,
        height: u32,
        layout_epoch: u64,
    ) -> Result<(), NativeVideoError> {
        let pixels = u64::from(width) * u64::from(height);
        if width == 0
            || height == 0
            || width > 8192
            || height > 8192
            || pixels.saturating_mul(4) > 64 * 1024 * 1024
            || layout_epoch == 0
            || layout_epoch > i64::MAX as u64
        {
            return Err(NativeVideoError::Invalid);
        }
        let route = self.native_host_video_route(session_binding)?;
        let binding = NativeVideoBinding {
            source,
            width,
            height,
            layout_epoch,
        };
        let input = self
            .shared
            .native_input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(input) = input.filter(|input| {
            input.matches_session(session_binding) && input.has_attached_host_input()
        }) {
            // An existing Input owner must never target a replacement display.
            // Dynamic input layouts require a new platform/session owner.
            let _ = tokio::task::spawn_blocking(move || input.stop_for_capture_change()).await;
            return Err(NativeVideoError::Unauthorized);
        }
        let _send_order = route.ordered_send().await?;
        let mut cursor = route
            .cursor
            .lock()
            .map_err(|_| NativeVideoError::Transport)?;
        cursor.bind(binding, route.gate.is_active())?;
        // The versioned selection ACK owns activation for negotiated native
        // displays. Configuring the first codec must never precede that ACK.
        if let Ok(state) = self.native_displays(session_binding) {
            if state.pending.is_none()
                && state.selected.as_ref().is_some_and(|selected| {
                    selected.source == source && selected.layout_epoch == layout_epoch
                })
            {
                route.gate.open()?;
            } else {
                route.gate.pause();
            }
        } else {
            route.gate.open()?;
        }
        Ok(())
    }
    /// Disable capture delivery synchronously and remove queued frames before
    /// returning. This does not revoke the remote View lease itself.
    pub fn clear_native_video_stream(&self) {
        if let Some(route) = self.shared.native_video_route() {
            route.gate.pause();
            let _ = route.sender.discard_video();
        }
    }
    /// Fence only the original producer. A late worker cannot pause a newer
    /// request that happens to have the same generation and display layout.
    pub fn clear_native_video_stream_for(&self, binding: &NativeSessionBinding) {
        if let Some(route) = self.shared.native_video_route().filter(|route| {
            route.request_id == binding.request_id
                && route.connection_generation == binding.connection_generation
        }) {
            route.gate.pause();
            let _ = route.sender.discard_video();
        }
    }
    /// Stop this exact host session when platform capture cannot be prepared.
    /// An obsolete worker cannot end a replacement connection.
    pub fn fail_native_video_capture(
        &self,
        binding: &NativeSessionBinding,
    ) -> Result<(), NativeVideoError> {
        let route = self.native_host_video_route(binding)?;
        route.retire();
        route
            .lease
            .stop(StopReason::PlatformChanged)
            .map_err(|_| NativeVideoError::Transport)?;
        Ok(())
    }
    /// Register actual capture cleanup with this proved host session. The
    /// platform supplies its locally approved display, including logical
    /// coordinates; it cannot attach to a controller or a retired route.
    pub fn attach_native_video_capture<D: CaptureDevice>(
        &self,
        binding: &NativeSessionBinding,
        layout_epoch: u64,
        device: D,
        display: Display,
    ) -> Result<VideoController<impl CaptureDevice>, NativeVideoError> {
        let route = (|| {
            if layout_epoch == 0 || layout_epoch > i64::MAX as u64 {
                return Err(NativeVideoError::Invalid);
            }
            let route = self.native_host_video_route(binding)?;
            let cursor = route
                .cursor
                .lock()
                .map_err(|_| NativeVideoError::Transport)?;
            if cursor.binding.is_some_and(|binding| {
                binding.layout_epoch != layout_epoch || binding.source != display.source
            }) {
                return Err(NativeVideoError::Invalid);
            }
            drop(cursor);
            route.gate.open()?;
            Ok(route)
        })();
        let route = match route {
            Ok(route) => route,
            Err(error) => return Err(reject_native_capture(device, error)),
        };
        let device = GuardedNativeCapture {
            device,
            guard: route.gate.guard(),
        };
        VideoController::attach(
            route.lease.clone(),
            device,
            VideoEpoch {
                layout: layout_epoch,
                connection: route.connection_generation,
            },
            vec![display],
        )
        .map_err(|error| match error {
            nestlink_remote::RemoteError::Cleanup(error) => NativeVideoError::Cleanup(error),
            _ => NativeVideoError::Unauthorized,
        })
    }
    /// Attach the whole stable, locally approved source set once. Pausing a
    /// selected delivery stream does not invalidate its capture owner or portal
    /// grant. Terminal route retirement still fences every frame and cleanup.
    pub fn attach_native_video_capture_set<D: CaptureDevice>(
        &self,
        binding: &NativeSessionBinding,
        device: D,
        displays: Vec<Display>,
    ) -> Result<VideoController<impl CaptureDevice>, NativeVideoError> {
        let validated = (|| {
            let route = self.native_host_video_route(binding)?;
            let consent = self
                .native_displays(binding)
                .map_err(|_| NativeVideoError::Unauthorized)?;
            if consent.local_approval_required
                || displays.len() != consent.approved_sources.len()
                || displays.iter().any(|display| {
                    !consent.displays.iter().any(|approved| {
                        approved.source == display.source
                            && approved.left == display.logical.left
                            && approved.top == display.logical.top
                            && approved.width == display.logical.width
                            && approved.height == display.logical.height
                    })
                })
            {
                return Err(NativeVideoError::Unauthorized);
            }
            Ok(route)
        })();
        let route = match validated {
            Ok(route) => route,
            Err(error) => return Err(reject_native_capture(device, error)),
        };
        let device = LiveNativeCapture {
            device,
            gate: route.gate.clone(),
        };
        VideoController::attach(
            route.lease.clone(),
            device,
            VideoEpoch {
                layout: 1,
                connection: route.connection_generation,
            },
            displays,
        )
        .map_err(|error| match error {
            nestlink_remote::RemoteError::Cleanup(error) => NativeVideoError::Cleanup(error),
            _ => NativeVideoError::Unauthorized,
        })
    }
    /// Observe pending authenticated receiver feedback without consuming it.
    /// A successful keyframe send acknowledges it; failed/cancelled sends do
    /// not. Platform encoders must query this before encoding their next frame.
    pub async fn native_video_keyframe_needed(
        &self,
        session_binding: &NativeSessionBinding,
        binding: NativeVideoBinding,
    ) -> Result<bool, NativeVideoError> {
        let route = self.native_host_video_route(session_binding)?;
        let cursor = route
            .cursor
            .lock()
            .map_err(|_| NativeVideoError::Transport)?;
        if cursor.binding != Some(binding) || !route.gate.is_active() {
            return Err(NativeVideoError::Invalid);
        }
        // Cached product state cannot revive a revoked transport lease.
        route
            .lease
            .check_media_binding(Channel::Video, route.connection_generation)
            .map_err(|_| NativeVideoError::Unauthorized)?;
        Ok(cursor.keyframe_needed(Instant::now()))
    }
    /// Sends one already encoded frame through the active session's View queue.
    /// Source, layout, connection, sequence and timestamp are checked or
    /// assigned here; callers cannot select a different lease or channel.
    pub fn send_native_video_frame(
        &self,
        session_binding: &NativeSessionBinding,
        source_binding: NativeVideoBinding,
        pts_90khz: u64,
        keyframe: bool,
        encoded_frame: Vec<u8>,
    ) -> impl Future<Output = Result<(), NativeVideoError>> + '_ {
        self.send_native_video_frame_inner(
            session_binding.clone(),
            source_binding,
            pts_90khz,
            keyframe,
            false,
            Zeroizing::new(encoded_frame),
        )
    }
    /// Re-encode the latest locally approved pixels for authenticated feedback.
    /// The packet is always a keyframe, and its PTS names this new encoding.
    pub fn send_native_video_recovery_frame(
        &self,
        session_binding: &NativeSessionBinding,
        source_binding: NativeVideoBinding,
        pts_90khz: u64,
        encoded_frame: Vec<u8>,
    ) -> impl Future<Output = Result<(), NativeVideoError>> + '_ {
        self.send_native_video_frame_inner(
            session_binding.clone(),
            source_binding,
            pts_90khz,
            true,
            true,
            Zeroizing::new(encoded_frame),
        )
    }
    async fn send_native_video_frame_inner(
        &self,
        session_binding: NativeSessionBinding,
        source_binding: NativeVideoBinding,
        pts_90khz: u64,
        keyframe: bool,
        repeated_source: bool,
        mut encoded_frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), NativeVideoError> {
        // The public entry points create the guard synchronously, so dropping
        // an unpolled or cancelled producer future also clears the frame.
        let route = self.native_host_video_route(&session_binding)?;
        // Keep prepared references in order, while leaving the short cursor
        // lock available to feedback and encoder queries under backpressure.
        let _send_order = route.ordered_send().await?;
        let (binding, sequence, keyframe_deadline) = {
            let mut cursor = route
                .cursor
                .lock()
                .map_err(|_| NativeVideoError::Transport)?;
            let binding = cursor.binding.ok_or(NativeVideoError::Unauthorized)?;
            if source_binding != binding || !route.gate.is_active() {
                return Err(NativeVideoError::Invalid);
            }
            let sequence = cursor.reserve(pts_90khz)?;
            let deadline = if keyframe {
                cursor
                    .last_keyframe
                    .map(|last| last + Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS))
            } else {
                None
            };
            (binding, sequence, deadline)
        };
        let delivery_guard = Arc::new(route.gate.guard());
        let mut frame = NativeVideo {
            schema_version: SCHEMA_VERSION,
            connection_generation: route.connection_generation,
            layout_epoch: binding.layout_epoch,
            source: binding.source,
            sequence,
            pts_90khz,
            width: binding.width,
            height: binding.height,
            keyframe,
            payload: std::mem::take(&mut *encoded_frame),
            repeated_source,
        };
        let encoded = frame.encode_validated();
        frame.payload.zeroize();
        let encoded = Zeroizing::new(encoded.map_err(|_| NativeVideoError::Invalid)?);
        if let Some(deadline) = keyframe_deadline {
            let mut stopped = route.lease.subscribe_stopped();
            if stopped.borrow().is_some() {
                return Err(NativeVideoError::Unauthorized);
            }
            tokio::select! { biased;
                _ = stopped.changed() => return Err(NativeVideoError::Unauthorized),
                _ = tokio::time::sleep_until(deadline.into()) => {},
            }
        }
        if route
            .sender
            .send_video_guarded(&encoded, delivery_guard)
            .await
            .is_err()
        {
            return Err(NativeVideoError::Transport);
        }
        if keyframe {
            route
                .cursor
                .lock()
                .map_err(|_| NativeVideoError::Transport)?
                .keyframe_sent(binding, sequence, Instant::now());
        }
        Ok(())
    }
    pub fn submit(&self, action: Action) -> Result<Ticket, SubmitError> {
        self.submit_inner(None, action)
    }
    pub fn submit_for_generation(
        &self,
        expected: u64,
        action: Action,
    ) -> Result<Ticket, SubmitError> {
        self.submit_inner(Some(expected), action)
    }
    fn submit_inner(&self, expected: Option<u64>, action: Action) -> Result<Ticket, SubmitError> {
        if !action.valid_input() {
            return Err(SubmitError::Invalid);
        }
        let (mut envelope, ticket) = self.envelope(action.kind(), false, expected)?;
        envelope.action = Some(action);
        self.commands.try_send(envelope).map_err(send_error)?;
        Ok(ticket)
    }
    pub fn switch_server(&self, server: ApprovedServer) -> Result<Ticket, SubmitError> {
        self.switch_inner(None, server)
    }
    pub fn switch_server_for_generation(
        &self,
        expected: u64,
        server: ApprovedServer,
    ) -> Result<Ticket, SubmitError> {
        self.switch_inner(Some(expected), server)
    }
    fn switch_inner(
        &self,
        expected: Option<u64>,
        server: ApprovedServer,
    ) -> Result<Ticket, SubmitError> {
        if server.origin.len() > 2048
            || !(nestlink_protocol::valid_id(&server.deployment_id)
                || server.deployment_id.is_empty() && server.permit_issuer == [0; 32])
        {
            return Err(SubmitError::Invalid);
        }
        let (envelope, ticket) = self.envelope(OperationKind::Connect, true, expected)?;
        self.controls
            .try_send(Control::Boundary(Box::new(Boundary::Connect {
                server,
                envelope,
            })))
            .map_err(send_error)?;
        Ok(ticket)
    }
    pub fn logout(&self) -> Result<Ticket, SubmitError> {
        self.logout_inner(None)
    }
    pub fn logout_for_generation(&self, expected: u64) -> Result<Ticket, SubmitError> {
        self.logout_inner(Some(expected))
    }
    /// Produce an authenticated, one-use preview from the exact selected
    /// service view. The literal target comes from native UI input and is
    /// parsed as SocketAddr before it can enter Core state.
    pub async fn preview_local_service_host(
        &self,
        request: crate::LocalServiceHostRequest,
    ) -> Result<crate::LocalServiceHostPreview, SubmitError> {
        if !nestlink_protocol::valid_id(&request.runtime_id)
            || !nestlink_protocol::valid_id(&request.service_id)
            || request.definition_sha256.len() > 64
            || parse_local_choice(&request.protocol, &request.address).is_err()
            || (request.protocol == "https") != request.backend_tls.is_some()
            || request
                .backend_tls
                .as_ref()
                .is_some_and(|config| !service_host::valid_https_backend_config(config))
        {
            return Err(SubmitError::Invalid);
        }
        if request.expected_generation != self.shared.generation.load(Ordering::Acquire) {
            return Err(SubmitError::StaleGeneration);
        }
        let permit = self.capacity(true)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::PreviewLocalServiceHost {
                request: Box::new(request),
                reply,
                _permit: permit,
            })
            .map_err(send_error)?;
        receive.await.unwrap_or(Err(SubmitError::Stopped))
    }
    /// Start consumes the nonce inside the Core actor and returns an ordinary
    /// operation ticket; the IPC stream stays available while remote approval
    /// and publication setup run.
    pub fn start_local_service_host_for_generation(
        &self,
        runtime_id: String,
        expected_generation: u64,
        preview_nonce: String,
    ) -> Result<Ticket, SubmitError> {
        if !nestlink_protocol::valid_id(&runtime_id) || !nestlink_protocol::valid_id(&preview_nonce)
        {
            return Err(SubmitError::Invalid);
        }
        let (envelope, ticket) = self.envelope(
            OperationKind::StartLocalServiceHost,
            false,
            Some(expected_generation),
        )?;
        self.controls
            .try_send(Control::StartLocalServiceHost {
                runtime_id,
                preview_nonce,
                envelope,
            })
            .map_err(send_error)?;
        Ok(ticket)
    }
    /// Stop revokes the target's delivery gate synchronously in the actor,
    /// then returns while Core retains and awaits physical cleanup.
    pub async fn stop_local_service_host(
        &self,
        runtime_id: String,
        expected_generation: u64,
    ) -> Result<bool, SubmitError> {
        if !nestlink_protocol::valid_id(&runtime_id) {
            return Err(SubmitError::Invalid);
        }
        if expected_generation != self.shared.generation.load(Ordering::Acquire) {
            return Err(SubmitError::StaleGeneration);
        }
        let permit = self.capacity(true)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::StopLocalServiceHost {
                runtime_id,
                expected_generation,
                reply,
                _permit: permit,
            })
            .map_err(send_error)?;
        receive.await.unwrap_or(Err(SubmitError::Stopped))
    }
    fn logout_inner(&self, expected: Option<u64>) -> Result<Ticket, SubmitError> {
        let (envelope, ticket) = self.envelope(OperationKind::Logout, true, expected)?;
        self.controls
            .try_send(Control::Boundary(Box::new(Boundary::Logout { envelope })))
            .map_err(send_error)?;
        Ok(ticket)
    }
    pub fn cancel(&self, id: OperationId) -> Result<CancelTicket, SubmitError> {
        self.cancel_inner(None, id)
    }
    pub fn cancel_for_generation(
        &self,
        expected: u64,
        id: OperationId,
    ) -> Result<CancelTicket, SubmitError> {
        self.cancel_inner(Some(expected), id)
    }
    fn cancel_inner(
        &self,
        expected: Option<u64>,
        id: OperationId,
    ) -> Result<CancelTicket, SubmitError> {
        if expected
            .is_some_and(|expected| expected != self.shared.generation.load(Ordering::Acquire))
        {
            return Err(SubmitError::StaleGeneration);
        }
        let permit = self.capacity(true)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::Cancel {
                id,
                expected_generation: expected,
                reply,
                _permit: permit,
            })
            .map_err(send_error)?;
        Ok(CancelTicket(receive))
    }
    fn capacity(&self, control: bool) -> Result<OwnedSemaphorePermit, SubmitError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(SubmitError::Stopped);
        }
        let capacity = if control {
            &self.shared.controls
        } else {
            &self.shared.operations
        };
        capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| SubmitError::Capacity)
    }
    fn envelope(
        &self,
        kind: OperationKind,
        control: bool,
        expected: Option<u64>,
    ) -> Result<(Envelope, Ticket), SubmitError> {
        let current = self.shared.generation.load(Ordering::Acquire);
        if expected.is_some_and(|expected| expected != current) {
            return Err(SubmitError::StaleGeneration);
        }
        let permit = self.capacity(control)?;
        let value = self
            .shared
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| SubmitError::Stopped)?;
        let id = OperationId(value);
        let (reply, receive) = oneshot::channel();
        Ok((
            Envelope {
                id,
                generation: expected.unwrap_or(current),
                generation_guard: expected.is_some(),
                kind,
                action: None,
                reply,
                _permit: permit,
            },
            Ticket { id, reply: receive },
        ))
    }
}
fn send_error<T>(error: mpsc::error::TrySendError<T>) -> SubmitError {
    match error {
        mpsc::error::TrySendError::Full(_) => SubmitError::Capacity,
        mpsc::error::TrySendError::Closed(_) => SubmitError::Stopped,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    Complete,
    /// Cleanup is still owned and running. Capacity and completion aren't faked.
    Pending,
    Failed,
}

/// Own this in the per-user daemon, not in a window or Activity. Handle/view
/// clones don't extend ownership after this owner's Drop.
pub struct AppCore {
    handle: CoreHandle,
    stop: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl AppCore {
    pub fn start(limits: Limits) -> Result<Self, StartError> {
        Self::start_owned(limits, None, None)
    }
    pub fn with_identity(limits: Limits, identity: DeviceIdentity) -> Result<Self, StartError> {
        Self::start_owned(limits, Some(Arc::new(identity)), None)
    }
    pub fn with_identity_and_native_session(
        limits: Limits,
        identity: DeviceIdentity,
        native: NativeSessionConfig,
    ) -> Result<Self, StartError> {
        Self::start_owned(limits, Some(Arc::new(identity)), Some(native))
    }
    fn start_owned(
        limits: Limits,
        identity: Option<Arc<DeviceIdentity>>,
        native: Option<NativeSessionConfig>,
    ) -> Result<Self, StartError> {
        if !limits.valid() {
            return Err(StartError::Limits);
        }
        if native.as_ref().is_some_and(|native| !native.validate()) {
            return Err(StartError::NativeSessionConfig);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| StartError::Runtime)?;
        let shared = Arc::new(Shared {
            closing: Arc::new(AtomicBool::new(false)),
            next_id: AtomicU64::new(1),
            generation: Arc::new(AtomicU64::new(1)),
            operations: Arc::new(Semaphore::new(limits.operations)),
            controls: Arc::new(Semaphore::new(limits.controls)),
            native_video: Mutex::new(None),
            native_displays: Mutex::new(None),
            native_video_presentation: Mutex::new(None),
            native_input: Mutex::new(None),
            native_audio: Mutex::new(None),
            native_audio_owners: Mutex::new(Vec::new()),
            native_clipboard: Mutex::new(None),
            native_clipboard_owners: Mutex::new(Vec::new()),
            native_clipboard_factory: Mutex::new(None),
            native_files: Mutex::new(None),
            native_files_owners: Mutex::new(Vec::new()),
            native_file_budget: NativeFileBudget::new(limits.native_downloads),
        });
        let (commands, incoming) = mpsc::channel(limits.operations);
        let (controls, controlling) = mpsc::channel(limits.controls);
        let view = Snapshot {
            native_network: native.as_ref().map_or_else(
                crate::NativeNetworkSettings::default,
                NativeSessionConfig::network_settings,
            ),
            installation: identity.as_ref().map(|identity| crate::InstallationView {
                device_id: identity.device_id.clone(),
                public_key_sha256: identity.identity.fingerprint(),
            }),
            ..Snapshot::default()
        };
        let (views, watching) = watch::channel(Arc::new(view.clone()));
        let (stop, stopping) = watch::channel(false);
        let (finish, finished) = watch::channel(false);
        let handle = CoreHandle {
            commands,
            controls,
            shared: shared.clone(),
            view: watching,
        };
        let actor = Actor {
            limits,
            shared,
            incoming,
            controlling,
            stopping,
            finish,
            views,
            view,
            identity,
            native,
            sdk: None,
            native_session_key: None,
            native_session_control: None,
            native_session_task: None,
            native_recovery: None,
            browser_host: None,
            service_host_preview: None,
            service_host_start_cancel: None,
            service_host_owner: None,
            native_poll_deadline: None,
            local_stop_reason: None,
            active: None,
            pending: VecDeque::new(),
            boundary: None,
            retire: false,
            secret_slots: Vec::new(),
            access_deadline: None,
        };
        let task = Some(runtime.spawn(actor.run()));
        Ok(Self {
            handle,
            stop,
            finished,
            task,
        })
    }
    pub fn handle(&self) -> CoreHandle {
        self.handle.clone()
    }
    pub fn request_shutdown(&self) {
        self.handle.shared.closing.store(true, Ordering::Release);
        self.stop.send_replace(true);
    }
    pub async fn shutdown(&mut self, timeout: Duration) -> ShutdownState {
        self.request_shutdown();
        let finished = &mut self.finished;
        let shared = self.handle.shared.clone();
        let wait = async {
            while !*finished.borrow_and_update() {
                finished.changed().await.map_err(|_| CoreClosed)?;
            }
            while shared.native_audio_cleanup_pending()
                || shared.native_clipboard_cleanup_pending()
                || shared.native_files_cleanup_pending()
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<(), CoreClosed>(())
        };
        match tokio::time::timeout(timeout, wait).await {
            Err(_) => ShutdownState::Pending,
            Ok(Err(_)) => ShutdownState::Failed,
            Ok(Ok(())) => match self.task.take() {
                Some(task) => {
                    if task.await.is_err() {
                        ShutdownState::Failed
                    } else {
                        ShutdownState::Complete
                    }
                }
                None => ShutdownState::Complete,
            },
        }
    }
    /// Enables a daemon supervisor to observe actual completion after owner Drop.
    pub fn finished(&self) -> watch::Receiver<bool> {
        self.finished.clone()
    }
}
impl Drop for AppCore {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

struct Envelope {
    id: OperationId,
    generation: u64,
    generation_guard: bool,
    kind: OperationKind,
    action: Option<Action>,
    reply: oneshot::Sender<Completion>,
    _permit: OwnedSemaphorePermit,
}
impl Envelope {
    fn result(
        &self,
        status: OperationStatus,
        effect: RemoteEffect,
        failure: Option<Failure>,
        output: PublicOutput,
    ) -> OperationResult {
        OperationResult {
            id: self.id,
            generation: self.generation,
            kind: self.kind,
            status,
            remote_effect: effect,
            failure,
            output,
        }
    }
}
enum Boundary {
    Connect {
        server: ApprovedServer,
        envelope: Envelope,
    },
    Logout {
        envelope: Envelope,
    },
}
impl Boundary {
    fn envelope(&self) -> &Envelope {
        match self {
            Self::Connect { envelope, .. } | Self::Logout { envelope } => envelope,
        }
    }
    fn envelope_mut(&mut self) -> &mut Envelope {
        match self {
            Self::Connect { envelope, .. } | Self::Logout { envelope } => envelope,
        }
    }
    fn into_envelope(self) -> Envelope {
        match self {
            Self::Connect { envelope, .. } | Self::Logout { envelope } => envelope,
        }
    }
}
enum Control {
    Boundary(Box<Boundary>),
    ConfigureNativeNetwork {
        expected_generation: u64,
        expected_revision: u64,
        settings: crate::NativeNetworkSettings,
        reply: oneshot::Sender<Result<crate::NativeNetworkSettings, crate::NativeNetworkError>>,
        _permit: OwnedSemaphorePermit,
    },
    InstallNativeNetworkSettingsStore {
        expected_generation: u64,
        expected_revision: u64,
        store: Arc<dyn crate::NativeNetworkSettingsStore>,
        reply: oneshot::Sender<Result<crate::NativeNetworkSettings, crate::NativeNetworkError>>,
        _permit: OwnedSemaphorePermit,
    },
    Cancel {
        id: OperationId,
        expected_generation: Option<u64>,
        reply: oneshot::Sender<Result<bool, SubmitError>>,
        _permit: OwnedSemaphorePermit,
    },
    BrowserHostDataUpdate {
        binding: Box<BrowserHostBinding>,
        expected_generation: u64,
        data: BrowserHostDataView,
        reply: oneshot::Sender<Result<(), BrowserHostDataError>>,
        _permit: OwnedSemaphorePermit,
    },
    BrowserHostDisplayApproval {
        approval: BrowserHostDisplayApproval,
        expected_generation: u64,
        reply: oneshot::Sender<Result<(), BrowserHostDisplayError>>,
        _permit: OwnedSemaphorePermit,
    },
    PreviewLocalServiceHost {
        request: Box<crate::LocalServiceHostRequest>,
        reply: oneshot::Sender<Result<crate::LocalServiceHostPreview, SubmitError>>,
        _permit: OwnedSemaphorePermit,
    },
    StartLocalServiceHost {
        runtime_id: String,
        preview_nonce: String,
        envelope: Envelope,
    },
    StopLocalServiceHost {
        runtime_id: String,
        expected_generation: u64,
        reply: oneshot::Sender<Result<bool, SubmitError>>,
        _permit: OwnedSemaphorePermit,
    },
}
struct Client {
    sdk: Sdk,
    server: ApprovedServer,
}
enum Job {
    Operation(sdk_call::Response),
    Connected(Result<Sdk, Failure>),
    NativeEstablished {
        client: Box<Client>,
        request_id: String,
        core_generation: u64,
        expected_connection_generation: Option<u64>,
        result: Result<EstablishedNativeSession, Failure>,
    },
    NativePermitPolled {
        client: Client,
        key: NativeSessionKey,
        result: NativePermitState,
    },
    Retired {
        client: Client,
        had_session: bool,
        result: Result<(), Failure>,
    },
    LocalServiceHostStarted {
        client: Box<Client>,
        binding: Box<ServiceHostBinding>,
        approved: Option<nestlink_protocol::api::ServiceView>,
        result: Result<LocalServiceRuntime, Failure>,
    },
}
struct EstablishedNativeSession {
    session: NativeSession,
    key: NativeSessionKey,
    endpoint: Box<NativeEndpoint>,
    recovery: NativeRecoveryContext,
}
/// Trusted local inputs and the original product fence travel with the proved
/// session. Recovery never re-reads mutable UI network or permission choices.
struct NativeRecoveryContext {
    config: NativeSessionConfig,
    peer_key: [u8; 32],
    core_generation: u64,
    server: ApprovedServer,
    deadline: Option<Instant>,
}
struct NativeRecoverySource {
    key: NativeSessionKey,
    failed: NativeSession,
    // Its lifecycle sender must outlive SDK budget extraction from `failed`.
    endpoint: Box<NativeEndpoint>,
    budget: nestlink_remote::ReconnectionBudget,
    context: NativeRecoveryContext,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeSessionKey {
    request_id: String,
    connection_generation: u64,
    lease_sequence: u64,
    is_host: bool,
    host_view_authorized: bool,
    controller_view_authorized: bool,
    input_authorized: bool,
    audio_authorized: bool,
    file_read_authorized: bool,
    file_write_authorized: bool,
    clipboard_read_authorized: bool,
    clipboard_write_authorized: bool,
    path: i32,
}
struct NativeSessionStop {
    key: NativeSessionKey,
    stop_reason: Option<NativeSessionStopReason>,
    stop_effects: Option<NativeSessionEffects>,
    cleanup: Option<NativeSessionCleanup>,
    failure: Option<Failure>,
    recovery: Option<Box<NativeRecoverySource>>,
}
struct BrowserHostRuntime {
    request_id: String,
    connection_generation: u64,
    lease_sequence: u64,
    server: ApprovedServer,
    cancel: watch::Sender<bool>,
    display_approval: watch::Sender<Option<BrowserHostDisplayApproval>>,
    events: mpsc::Receiver<BrowserHostEvent>,
    start_envelope: Option<Envelope>,
}
enum BrowserHostEvent {
    DisplayOffer(Box<BrowserHostDisplayOffer>),
    Ready(Result<Box<BrowserHostReady>, BrowserHostFailure>),
    Finished(Box<BrowserHostExit>),
}
#[derive(Clone, Copy)]
enum NativePermitState {
    Current,
    Revoked,
    Expired,
    Retry,
}
struct Active {
    envelope: Option<Envelope>,
    server: Option<ApprovedServer>,
    section: Option<SectionKey>,
    cancelled: Option<OperationStatus>,
    cancellation: Arc<AtomicBool>,
    secret: Option<SecretSlot>,
    remote_revoke: Option<String>,
    native_request_id: Option<String>,
    native_connection_generation: Option<u64>,
    service_host_runtime_id: Option<String>,
    future: Pin<Box<dyn Future<Output = Job> + Send>>,
}

struct Actor {
    limits: Limits,
    shared: Arc<Shared>,
    incoming: mpsc::Receiver<Envelope>,
    controlling: mpsc::Receiver<Control>,
    stopping: watch::Receiver<bool>,
    finish: watch::Sender<bool>,
    views: watch::Sender<Arc<Snapshot>>,
    view: Snapshot,
    identity: Option<Arc<DeviceIdentity>>,
    native: Option<NativeSessionConfig>,
    sdk: Option<Client>,
    native_session_key: Option<NativeSessionKey>,
    native_session_control: Option<NativeSessionControl>,
    native_session_task: Option<JoinHandle<NativeSessionStop>>,
    native_recovery: Option<Box<NativeRecoverySource>>,
    browser_host: Option<BrowserHostRuntime>,
    service_host_preview: Option<PendingServiceHostPreview>,
    /// Kept by the actor until the SDK's owned startup/cleanup future returns.
    service_host_start_cancel: Option<watch::Sender<bool>>,
    service_host_owner: Option<ServiceHostOwner>,
    native_poll_deadline: Option<tokio::time::Instant>,
    local_stop_reason: Option<NativeSessionStopReason>,
    active: Option<Active>,
    pending: VecDeque<Envelope>,
    boundary: Option<Boundary>,
    retire: bool,
    secret_slots: Vec<Weak<Mutex<Option<SensitiveMaterial>>>>,
    access_deadline: Option<tokio::time::Instant>,
}

impl Actor {
    async fn run(mut self) {
        let mut timer = tokio::time::interval(Duration::from_millis(100));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if !matches!(self.view.lifecycle, Lifecycle::Running) {
                if self.active.is_none()
                    && self.sdk.is_none()
                    && self.native_session_task.is_none()
                    && self.browser_host.is_none()
                    && self.service_host_owner.is_none()
                {
                    self.view.lifecycle = Lifecycle::Stopped;
                    self.publish();
                    self.finish.send_replace(true);
                    return;
                }
            } else if self.expired() {
                self.expire();
            }
            self.start_next();
            enum Step {
                Stop,
                Control(Option<Box<Control>>),
                Incoming(Option<Box<Envelope>>),
                Complete(Box<Job>),
                NativeStopped(Result<Box<NativeSessionStop>, JoinError>),
                BrowserHost(Option<Box<BrowserHostEvent>>),
                ServiceHostCleanup(ServiceHostWait),
                Tick,
            }
            let running = self.view.lifecycle == Lifecycle::Running;
            let step = tokio::select! {
                biased;
                _ = self.stopping.changed(), if running => Step::Stop,
                job = next_job(&mut self.active) => Step::Complete(Box::new(job)),
                stopped = next_native_session(&mut self.native_session_task) => {
                    Step::NativeStopped(stopped.map(Box::new))
                },
                browser = next_browser_host_event(&mut self.browser_host) => {
                    Step::BrowserHost(browser.map(Box::new))
                },
                host_cleanup = next_service_host_cleanup(&mut self.service_host_owner) => {
                    Step::ServiceHostCleanup(host_cleanup)
                },
                control = self.controlling.recv(), if running => {
                    Step::Control(control.map(Box::new))
                },
                _ = timer.tick() => Step::Tick,
                envelope = self.incoming.recv(), if running => {
                    Step::Incoming(envelope.map(Box::new))
                },
            };
            match step {
                Step::Stop => self.stop(),
                Step::Control(Some(control)) => self.control(*control),
                Step::Incoming(Some(envelope)) => self.admit(*envelope),
                Step::Control(None) | Step::Incoming(None) => self.stop(),
                Step::Complete(job) => self.completed(*job),
                Step::NativeStopped(stopped) => {
                    self.native_session_task = None;
                    self.native_stopped(stopped.map(|stopped| *stopped));
                }
                Step::BrowserHost(Some(event)) => match *event {
                    BrowserHostEvent::DisplayOffer(offer) => {
                        self.browser_host_display_offer(*offer);
                    }
                    BrowserHostEvent::Ready(result) => {
                        self.browser_host_ready(result.map(|ready| *ready));
                    }
                    BrowserHostEvent::Finished(exit) => self.browser_host_finished(*exit),
                },
                Step::BrowserHost(None) => self.browser_host_event_lost(),
                Step::ServiceHostCleanup(result) => self.service_host_cleanup_result(result),
                Step::Tick => self.poll_native_session(),
            }
        }
    }
    fn publish(&mut self) {
        self.view.revision = self.view.revision.saturating_add(1);
        self.views.send_replace(Arc::new(self.view.clone()));
    }
    fn record(&mut self, result: OperationResult) {
        if let Some(old) = self
            .view
            .operations
            .iter_mut()
            .find(|old| old.id == result.id)
        {
            *old = result.clone();
        } else {
            if self.view.operations.len() >= self.limits.history
                && let Some(index) = self
                    .view
                    .operations
                    .iter()
                    .position(|entry| entry.status.terminal())
            {
                self.view.operations.remove(index);
            }
            self.view.operations.push(result.clone());
        }
        if result.status.terminal() {
            self.view.event_sequence = self.view.event_sequence.saturating_add(1);
            if self.view.events.len() == self.limits.history {
                self.view.events.remove(0);
            }
            self.view.events.push(Event {
                sequence: self.view.event_sequence,
                result,
            });
        }
    }
    fn deliver(
        &mut self,
        envelope: Envelope,
        status: OperationStatus,
        effect: RemoteEffect,
        failure: Option<Failure>,
        output: PublicOutput,
        sensitive: Option<SecretSlot>,
    ) {
        let result = envelope.result(status, effect, failure, output);
        self.record(result.clone());
        // IPC and other runtime threads can wake immediately on this reply.
        // Publish first so their snapshot observes the completed state.
        self.publish();
        let _ = envelope.reply.send(Completion {
            result,
            sensitive,
            generation: self.shared.generation.clone(),
        });
    }
    fn admit(&mut self, envelope: Envelope) {
        if envelope.generation != self.view.generation || self.view.lifecycle != Lifecycle::Running
        {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
        } else {
            if let Some(Action::StopNativeSession {
                request_id,
                connection_generation,
            }) = envelope.action.as_ref()
            {
                let accepted = self.request_native_stop(
                    StopReason::ExplicitExit,
                    Some((request_id, *connection_generation)),
                );
                self.deliver(
                    envelope,
                    if accepted {
                        OperationStatus::Succeeded
                    } else {
                        OperationStatus::Failed
                    },
                    RemoteEffect::None,
                    (!accepted).then(|| Failure::local(FailureKind::Invalid)),
                    PublicOutput::None,
                    None,
                );
                self.publish();
                return;
            }
            if let Some(Action::StopBrowserHost {
                request_id,
                connection_generation,
            }) = envelope.action.as_ref()
            {
                let accepted = self.request_browser_stop(request_id, *connection_generation);
                self.deliver(
                    envelope,
                    if accepted {
                        OperationStatus::Succeeded
                    } else {
                        OperationStatus::Failed
                    },
                    RemoteEffect::None,
                    (!accepted).then(|| Failure::local(FailureKind::Invalid)),
                    PublicOutput::None,
                    None,
                );
                self.publish();
                return;
            }
            self.record(envelope.result(
                OperationStatus::Queued,
                RemoteEffect::None,
                None,
                PublicOutput::None,
            ));
            self.pending.push_back(envelope);
        }
        self.publish();
    }
    fn preview_local_service_host(
        &mut self,
        request: crate::LocalServiceHostRequest,
    ) -> Result<crate::LocalServiceHostPreview, SubmitError> {
        let crate::LocalServiceHostRequest {
            runtime_id,
            expected_generation,
            expected_snapshot_revision,
            service_id,
            service_revision,
            definition_sha256,
            protocol,
            address,
            backend_tls,
        } = request;
        if self.active.is_some()
            || self.service_host_owner.is_some()
            || local_service_host_cleanup_unconfirmed(&self.view)
        {
            return Err(SubmitError::Capacity);
        }
        if self
            .service_host_preview
            .as_ref()
            .is_some_and(|preview| preview.binding.runtime_id != runtime_id)
        {
            return Err(SubmitError::Invalid);
        }
        // A replacement request from its owner invalidates the previous
        // consent even when the replacement later fails validation.
        self.service_host_preview = None;
        if expected_generation != self.view.generation
            || expected_snapshot_revision != self.view.revision
            || self.view.authentication != Authentication::SignedIn
            || self.view.lifecycle != Lifecycle::Running
        {
            return Err(SubmitError::StaleGeneration);
        }
        let client = self.sdk.as_ref().ok_or(SubmitError::Invalid)?;
        let principal = client.sdk.principal().ok_or(SubmitError::Invalid)?;
        if !principal_matches_sdk(&self.view, principal) {
            return Err(SubmitError::StaleGeneration);
        }
        let identity = self.identity.as_ref().ok_or(SubmitError::Invalid)?;
        let service = self
            .view
            .selected_service
            .data
            .as_ref()
            .ok_or(SubmitError::Invalid)?
            .as_ref()
            .clone();
        let (protocol, address) =
            parse_local_choice(&protocol, &address).map_err(|_| SubmitError::Invalid)?;
        let server = self
            .view
            .server
            .as_ref()
            .filter(|server| server.verified_health.is_some())
            .ok_or(SubmitError::Invalid)?;
        if service.id != service_id
            || service.revision != service_revision
            || service.definition_sha256 != definition_sha256
            || service.account_id != principal.account_id
            || service.management_session_id != principal.session_id
            || !service_is_hostable(&service, &identity.device_id)
        {
            return Err(SubmitError::StaleGeneration);
        }
        let mut consent =
            LocalServiceTargetConsent::from_local_choice(&service, &protocol, address)
                .map_err(|_| SubmitError::Invalid)?;
        let (backend_tls_server_name, backend_tls_digest) = if let Some(config) = backend_tls {
            let tls = HttpsBackendTls::new(
                config.server_name.clone(),
                config.ca_certificates_der.clone(),
            )
            .map_err(|_| SubmitError::Invalid)?;
            consent = consent
                .with_https_backend_tls(tls)
                .map_err(|_| SubmitError::Invalid)?;
            let digest = https_backend_sha256(&config);
            (Some(config.server_name), Some(digest))
        } else {
            (None, None)
        };
        let binding = binding_for(
            ServiceHostContext {
                runtime_id,
                server_origin: server.origin.clone(),
                deployment_id: server.deployment_id.clone(),
                generation: self.view.generation,
            },
            principal,
            &service,
            ServiceHostTarget {
                target_id: consent.target_id().to_owned(),
                target_sha256: consent.target_digest().to_owned(),
                protocol: protocol.clone(),
                address,
                backend_tls_server_name: backend_tls_server_name.clone(),
                backend_tls_sha256: backend_tls_digest.clone(),
            },
        );
        let preview = crate::LocalServiceHostPreview {
            nonce: nestlink_auth::random_id(),
            service,
            protocol,
            address: address.to_string(),
            backend_tls_server_name,
            backend_tls_sha256: backend_tls_digest,
            lifetime_ms: PREVIEW_LIFETIME_MS,
        };
        self.service_host_preview = Some(PendingServiceHostPreview {
            public: preview.clone(),
            binding,
            expires_at: tokio::time::Instant::now() + PREVIEW_LIFETIME,
            consent,
        });
        Ok(preview)
    }

    fn start_local_service_host(
        &mut self,
        runtime_id: String,
        preview_nonce: String,
        envelope: Envelope,
    ) {
        if envelope.generation != self.view.generation || self.view.lifecycle != Lifecycle::Running
        {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::StaleGeneration)),
                PublicOutput::None,
                None,
            );
            return;
        }
        if self.active.is_some() || self.service_host_owner.is_some() {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Capacity)),
                PublicOutput::None,
                None,
            );
            return;
        }
        if self
            .service_host_preview
            .as_ref()
            .is_none_or(|preview| preview.public.nonce != preview_nonce)
        {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Invalid)),
                PublicOutput::None,
                None,
            );
            return;
        }
        let Some(preview) = self.service_host_preview.take() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Invalid)),
                PublicOutput::None,
                None,
            );
            return;
        };
        let client_matches = self.sdk.as_ref().is_some_and(|client| {
            client
                .sdk
                .principal()
                .is_some_and(|principal| principal_matches_sdk(&self.view, principal))
        });
        let context_matches = preview.expires_at > tokio::time::Instant::now()
            && preview.binding.runtime_id == runtime_id
            && preview.binding.generation == envelope.generation
            && snapshot_matches_binding(&self.view, &preview.binding, &runtime_id)
            && self.identity.as_ref().is_some_and(|identity| {
                service_is_hostable(&preview.public.service, &identity.device_id)
            })
            && client_matches;
        if !context_matches {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::StaleGeneration)),
                PublicOutput::None,
                None,
            );
            return;
        }
        let Some(identity) = self.identity.clone() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::LocalIdentityRequired)),
                PublicOutput::None,
                None,
            );
            return;
        };
        let Some(client) = self.sdk.take() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::SignInRequired)),
                PublicOutput::None,
                None,
            );
            return;
        };
        let binding = preview.binding;
        let service_name = preview.public.service.definition.name.clone();
        self.view.local_service_host = Some(crate::LocalServiceHostView {
            service_id: binding.service_id.clone(),
            service_name,
            approved_from_revision: binding.service_revision,
            approved_revision: None,
            protocol: binding.protocol.clone(),
            address: binding.address.to_string(),
            status: crate::LocalServiceHostStatus::Starting,
            cleanup_failed: false,
            failure: None,
        });
        self.record(envelope.result(
            OperationStatus::Running,
            RemoteEffect::None,
            None,
            PublicOutput::None,
        ));
        let cancellation = Arc::new(AtomicBool::new(false));
        let (service_host_start_cancel, service_host_start_cancelled) = watch::channel(false);
        self.service_host_start_cancel = Some(service_host_start_cancel);
        let fence = sdk_call::DispatchFence {
            generation: self.shared.generation.clone(),
            expected: envelope.generation,
            closing: self.shared.closing.clone(),
            cancelled: cancellation.clone(),
        };
        let consent = preview.consent;
        let Client { sdk, server } = client;
        let operation_binding = binding.clone();
        self.active = Some(Active {
            envelope: Some(envelope),
            server: None,
            section: None,
            cancelled: None,
            cancellation,
            secret: None,
            remote_revoke: None,
            native_request_id: None,
            native_connection_generation: None,
            service_host_runtime_id: Some(binding.runtime_id.clone()),
            future: Box::pin(async move {
                let (approved, result) = match fence.check() {
                    Err(failure) => (None, Err(failure)),
                    Ok(()) => match sdk
                        .approve_service_target(&identity, &consent, PREVIEW_LIFETIME_MS)
                        .await
                    {
                        Ok(approved) if approved_service_matches(&operation_binding, &approved) => {
                            let approved_for_job = approved.clone();
                            if let Err(failure) = fence.check() {
                                (Some(approved_for_job), Err(failure))
                            } else {
                                let result = sdk
                                    .start_service_host_cancellable(
                                        identity,
                                        consent,
                                        service_host_start_cancelled,
                                    )
                                    .await
                                    .map_err(Failure::from);
                                (Some(approved_for_job), result)
                            }
                        }
                        Ok(_) => (None, Err(Failure::local(FailureKind::Trust))),
                        Err(error) => (None, Err(Failure::from(error))),
                    },
                };
                Job::LocalServiceHostStarted {
                    client: Box::new(Client { sdk, server }),
                    binding: Box::new(operation_binding),
                    approved,
                    result,
                }
            }),
        });
        self.publish();
    }

    fn stop_local_service_host_owner(&mut self) -> bool {
        self.service_host_preview = None;
        let mut accepted = false;
        if let Some(cancel) = &self.service_host_start_cancel {
            cancel.send_replace(true);
        }
        if let Some(owner) = &mut self.service_host_owner {
            owner.cleanup_requested = true;
            owner.runtime.stop();
            accepted = true;
        }
        if let Some(active) = &mut self.active
            && active
                .envelope
                .as_ref()
                .is_some_and(|envelope| envelope.kind == OperationKind::StartLocalServiceHost)
        {
            active.cancellation.store(true, Ordering::Release);
            if active.cancelled.is_none() {
                active.cancelled = Some(OperationStatus::Cancelled);
            }
            accepted = true;
        }
        if accepted && let Some(host) = &mut self.view.local_service_host {
            host.status = crate::LocalServiceHostStatus::Stopping;
        }
        accepted
    }

    fn fence(&mut self) {
        self.service_host_preview = None;
        self.stop_local_service_host_owner();
        self.request_native_stop(StopReason::ExplicitExit, None);
        let browser_start = self.browser_host.as_mut().and_then(|host| {
            host.cancel.send_replace(true);
            host.start_envelope.take()
        });
        if let Some(host) = self.view.browser_host.data.as_ref()
            && matches!(
                host.status,
                BrowserHostStatus::Establishing | BrowserHostStatus::Connected
            )
        {
            let mut host = host.as_ref().clone();
            host.status = BrowserHostStatus::Stopping;
            host.host_view_authorized = false;
            self.view.browser_host.data = Some(Arc::new(host));
        }
        if let Some(next) = self.view.generation.checked_add(1) {
            self.view.generation = next;
            self.shared.generation.store(next, Ordering::Release);
        } else {
            self.shared.closing.store(true, Ordering::Release);
            self.view.lifecycle = Lifecycle::Stopping;
        }
        for slot in self
            .secret_slots
            .drain(..)
            .filter_map(|slot| slot.upgrade())
        {
            if let Ok(mut value) = slot.lock() {
                value.take();
            }
        }
        self.view.clear_account();
        self.access_deadline = None;
        self.view.authentication = if self.verified() {
            Authentication::SignedOut
        } else {
            Authentication::Disconnected
        };
        self.view.operations.clear();
        self.view.events.clear();
        while let Some(envelope) = self.pending.pop_front() {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
        }
        while let Ok(envelope) = self.incoming.try_recv() {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
        }
        if let Some(active) = &mut self.active {
            active.cancellation.store(true, Ordering::Release);
            active.cancelled = Some(OperationStatus::Superseded);
        }
        if let Some(envelope) = browser_start {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
        }
    }
    fn control(&mut self, control: Control) {
        match control {
            Control::ConfigureNativeNetwork {
                expected_generation,
                expected_revision,
                settings,
                reply,
                ..
            } => {
                let result =
                    self.configure_native_network(expected_generation, expected_revision, settings);
                let _ = reply.send(result);
            }
            Control::InstallNativeNetworkSettingsStore {
                expected_generation,
                expected_revision,
                store,
                reply,
                ..
            } => {
                let result = self.install_native_network_settings_store(
                    expected_generation,
                    expected_revision,
                    store,
                );
                let _ = reply.send(result);
            }
            Control::Boundary(boundary) => {
                let mut boundary = *boundary;
                if boundary.envelope().generation_guard
                    && boundary.envelope().generation != self.view.generation
                {
                    self.deliver(
                        boundary.into_envelope(),
                        OperationStatus::Superseded,
                        RemoteEffect::None,
                        Some(Failure::local(FailureKind::StaleGeneration)),
                        PublicOutput::None,
                        None,
                    );
                    self.publish();
                    return;
                }
                self.fence();
                self.retire = true;
                if let Some(previous) = self.boundary.take() {
                    self.deliver(
                        previous.into_envelope(),
                        OperationStatus::Superseded,
                        RemoteEffect::None,
                        None,
                        PublicOutput::None,
                        None,
                    );
                }
                boundary.envelope_mut().generation = self.view.generation;
                match &boundary {
                    Boundary::Connect { server, .. } => {
                        self.view.server = Some(ServerView {
                            origin: server.origin.clone(),
                            deployment_id: server.deployment_id.clone(),
                            approved_issuer: server.permit_issuer,
                            verified_health: None,
                            error: None,
                        });
                        self.view.authentication = Authentication::VerifyingServer;
                    }
                    Boundary::Logout { .. } => {
                        self.view.authentication = if self.verified() {
                            Authentication::SignedOut
                        } else {
                            Authentication::Disconnected
                        }
                    }
                }
                self.record(boundary.envelope().result(
                    OperationStatus::Queued,
                    RemoteEffect::None,
                    None,
                    PublicOutput::None,
                ));
                self.boundary = Some(boundary);
            }
            Control::Cancel {
                id,
                expected_generation,
                reply,
                ..
            } => {
                if expected_generation.is_some_and(|expected| expected != self.view.generation) {
                    let _ = reply.send(Err(SubmitError::StaleGeneration));
                    self.publish();
                    return;
                }
                // The inbox counts toward the same semaphore, so draining it
                // here stays bounded and permits cancellation before dispatch.
                while let Ok(envelope) = self.incoming.try_recv() {
                    self.admit(envelope);
                }
                let accepted = self.cancel(id);
                self.publish();
                let _ = reply.send(Ok(accepted));
            }
            Control::BrowserHostDataUpdate {
                binding,
                expected_generation,
                data,
                reply,
                ..
            } => {
                let result = if expected_generation != self.view.generation {
                    Err(BrowserHostDataError::StaleGeneration)
                } else {
                    let Some(current) = self.view.browser_host.data.as_ref() else {
                        let _ = reply.send(Err(BrowserHostDataError::StaleBinding));
                        return;
                    };
                    if current.status != BrowserHostStatus::Connected
                        || !current.host_view_authorized
                        || current.binding.as_ref() != Some(binding.as_ref())
                    {
                        Err(BrowserHostDataError::StaleBinding)
                    } else if !valid_browser_host_data_update(&current.data, &data) {
                        Err(BrowserHostDataError::Invalid)
                    } else {
                        let mut current = current.as_ref().clone();
                        current.data = data;
                        self.view.browser_host.data = Some(Arc::new(current));
                        self.publish();
                        Ok(())
                    }
                };
                let _ = reply.send(result);
            }
            Control::BrowserHostDisplayApproval {
                approval,
                expected_generation,
                reply,
                ..
            } => {
                let result = if expected_generation != self.view.generation {
                    Err(BrowserHostDisplayError::StaleGeneration)
                } else if !valid_browser_host_display_selection(
                    &self.view,
                    self.view.generation,
                    &approval.binding,
                    &approval.catalog,
                    &approval.sources,
                    approval.initial_source,
                ) {
                    Err(BrowserHostDisplayError::StaleOffer)
                } else if let Some(runtime) = self.browser_host.as_ref().filter(|runtime| {
                    runtime.request_id == approval.binding.request_id
                        && runtime.connection_generation == approval.binding.connection_generation
                        && runtime.display_approval.receiver_count() > 0
                }) {
                    runtime
                        .display_approval
                        .send_replace(Some(approval.clone()));
                    if let Some(current) = self.view.browser_host.data.as_ref() {
                        let mut current = current.as_ref().clone();
                        current.displays.approval_required = false;
                        current.displays.approved_sources = approval.sources.clone();
                        current.displays.initial_source = Some(approval.initial_source);
                        self.view.browser_host.data = Some(Arc::new(current));
                        self.publish();
                        Ok(())
                    } else {
                        Err(BrowserHostDisplayError::StaleOffer)
                    }
                } else {
                    Err(BrowserHostDisplayError::StaleOffer)
                };
                let _ = reply.send(result);
            }
            Control::PreviewLocalServiceHost { request, reply, .. } => {
                let result = self.preview_local_service_host(*request);
                let _ = reply.send(result);
            }
            Control::StartLocalServiceHost {
                runtime_id,
                preview_nonce,
                envelope,
            } => self.start_local_service_host(runtime_id, preview_nonce, envelope),
            Control::StopLocalServiceHost {
                runtime_id,
                expected_generation,
                reply,
                ..
            } => {
                let result = if expected_generation != self.view.generation {
                    Err(SubmitError::StaleGeneration)
                } else if self
                    .service_host_owner
                    .as_ref()
                    .is_some_and(|owner| owner.binding.runtime_id != runtime_id)
                    || self
                        .service_host_preview
                        .as_ref()
                        .is_some_and(|preview| preview.binding.runtime_id != runtime_id)
                    || self.active.as_ref().is_some_and(|active| {
                        active.envelope.as_ref().is_some_and(|envelope| {
                            envelope.kind == OperationKind::StartLocalServiceHost
                                && active.service_host_runtime_id.as_deref()
                                    != Some(runtime_id.as_str())
                        })
                    })
                {
                    Err(SubmitError::Invalid)
                } else {
                    let accepted = self.stop_local_service_host_owner();
                    self.publish();
                    Ok(accepted)
                };
                let _ = reply.send(result);
            }
        }
        self.publish();
    }
    fn service_host_cleanup_result(&mut self, result: ServiceHostWait) {
        match result {
            ServiceHostWait::CleanupPending { failed } => {
                if let Some(owner) = &mut self.service_host_owner {
                    owner.cleanup_requested = true;
                    owner.runtime.stop();
                }
                if let Some(host) = &mut self.view.local_service_host {
                    let unexpected = host.status == crate::LocalServiceHostStatus::Running;
                    host.status = crate::LocalServiceHostStatus::Stopping;
                    host.cleanup_failed |= failed;
                    if unexpected && host.failure.is_none() {
                        host.failure = Some(Failure::local(FailureKind::Transport));
                    }
                }
            }
            ServiceHostWait::Stopped(report) => {
                self.service_host_owner = None;
                if let Some(host) = &mut self.view.local_service_host {
                    host.cleanup_failed |= report.failed;
                    host.status = if host.cleanup_failed {
                        crate::LocalServiceHostStatus::Failed
                    } else {
                        crate::LocalServiceHostStatus::Stopped
                    };
                    if host.cleanup_failed && host.failure.is_none() {
                        host.failure = Some(Failure::local(FailureKind::Transport));
                    }
                }
            }
        }
        self.publish();
    }

    fn reconcile_local_service_host(&mut self) {
        let Some(owner) = self.service_host_owner.as_ref() else {
            return;
        };
        let context_valid =
            snapshot_context_matches_binding(&self.view, &owner.binding, &owner.binding.runtime_id)
                && owner
                    .approved_view
                    .as_ref()
                    .is_some_and(|view| approved_service_matches(&owner.binding, view));
        let selected_changed = self
            .view
            .selected_service
            .data
            .as_ref()
            .filter(|service| service.id == owner.binding.service_id)
            .is_some_and(|service| !approved_service_matches(&owner.binding, service));
        let page_changed = self
            .view
            .services
            .data
            .as_ref()
            .and_then(|page| {
                page.services
                    .iter()
                    .find(|service| service.id == owner.binding.service_id)
            })
            .is_some_and(|service| !approved_service_matches(&owner.binding, service));
        if !context_valid || selected_changed || page_changed {
            self.stop_local_service_host_owner();
        }
    }

    fn cancel(&mut self, id: OperationId) -> bool {
        if let Some(index) = self.pending.iter().position(|entry| entry.id == id) {
            if let Some(envelope) = self.pending.remove(index) {
                self.deliver(
                    envelope,
                    OperationStatus::Cancelled,
                    RemoteEffect::None,
                    None,
                    PublicOutput::None,
                    None,
                );
            }
            return true;
        }
        if self
            .boundary
            .as_ref()
            .is_some_and(|boundary| boundary.envelope().id == id)
        {
            if let Some(boundary) = self.boundary.take() {
                self.deliver(
                    boundary.into_envelope(),
                    OperationStatus::Cancelled,
                    RemoteEffect::None,
                    None,
                    PublicOutput::None,
                    None,
                );
                self.view.authentication = if self.verified() {
                    Authentication::SignedOut
                } else {
                    Authentication::Disconnected
                };
            }
            return true;
        }
        let browser_start = self
            .browser_host
            .as_ref()
            .and_then(|host| host.start_envelope.as_ref())
            .is_some_and(|envelope| envelope.id == id);
        if browser_start {
            let cancelling = if let Some(host) = self.browser_host.as_mut() {
                host.cancel.send_replace(true);
                host.start_envelope.as_ref().map(|envelope| {
                    envelope.result(
                        OperationStatus::Cancelling,
                        RemoteEffect::Unknown,
                        None,
                        PublicOutput::None,
                    )
                })
            } else {
                None
            };
            if let Some(cancelling) = cancelling {
                self.record(cancelling);
            }
            self.set_browser_host_stopping(NativeSessionStopReason::UserCancelled);
            return true;
        }
        let Some(active) = &mut self.active else {
            return false;
        };
        let Some(envelope) = &active.envelope else {
            return false;
        };
        if envelope.id != id || active.cancelled.is_some() {
            return false;
        }
        let credential_transition = matches!(
            envelope.kind,
            OperationKind::Connect | OperationKind::SignIn | OperationKind::Refresh
        );
        let native_start = envelope.kind == OperationKind::StartNativeSession;
        let local_service_host_start = envelope.kind == OperationKind::StartLocalServiceHost;
        active.cancelled = Some(OperationStatus::Cancelled);
        active.cancellation.store(true, Ordering::Release);
        let cancelling = envelope.result(
            OperationStatus::Cancelling,
            RemoteEffect::Unknown,
            None,
            PublicOutput::None,
        );
        if credential_transition {
            self.fence();
            // Keep the requested status even though its credentials are fenced.
            if let Some(active) = &mut self.active {
                active.cancelled = Some(OperationStatus::Cancelled);
            }
            self.retire = true;
            self.view.authentication = if self.verified() {
                Authentication::SignedOut
            } else {
                Authentication::Disconnected
            };
        }
        if native_start {
            self.set_native_stopping(NativeSessionStopReason::UserCancelled);
        }
        if local_service_host_start {
            self.stop_local_service_host_owner();
        }
        self.record(cancelling);
        true
    }
    fn verified(&self) -> bool {
        self.view
            .server
            .as_ref()
            .is_some_and(|server| server.verified_health.is_some())
    }
    fn expired(&self) -> bool {
        self.browser_host.is_none()
            && (self
                .access_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
                || self.view.principal.as_ref().is_some_and(|principal| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(true, |time| time.as_secs() >= principal.access_expires)
                }))
    }
    fn install_deadline(&mut self) {
        self.access_deadline = self.view.principal.as_ref().map(|principal| {
            let remaining = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |time| {
                    principal.access_expires.saturating_sub(time.as_secs())
                });
            // The v15 management access lifetime is at most five minutes. An
            // OS wall-clock rollback can't extend credentials beyond this
            // monotonic deadline; only a real refresh installs a new one.
            tokio::time::Instant::now() + Duration::from_secs(remaining.min(300))
        });
    }
    fn expire(&mut self) {
        self.fence();
        self.retire = true;
        self.view.authentication = Authentication::Expired;
        self.view.authentication_error = Some(Failure::local(FailureKind::SignInRequired));
        self.publish();
    }
    fn stop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        self.incoming.close();
        self.controlling.close();
        self.fence();
        self.view.lifecycle = Lifecycle::Stopping;
        self.view.authentication = Authentication::Disconnected;
        self.retire = true;
        if let Some(boundary) = self.boundary.take() {
            self.deliver(
                boundary.into_envelope(),
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
        }
        while let Ok(control) = self.controlling.try_recv() {
            match control {
                Control::ConfigureNativeNetwork { reply, .. }
                | Control::InstallNativeNetworkSettingsStore { reply, .. } => {
                    let _ = reply.send(Err(crate::NativeNetworkError::Stopped));
                }
                Control::Boundary(boundary) => self.deliver(
                    (*boundary).into_envelope(),
                    OperationStatus::Superseded,
                    RemoteEffect::None,
                    None,
                    PublicOutput::None,
                    None,
                ),
                Control::Cancel { reply, .. } => {
                    let _ = reply.send(Err(SubmitError::Stopped));
                }
                Control::BrowserHostDataUpdate { reply, .. } => {
                    let _ = reply.send(Err(BrowserHostDataError::Stopped));
                }
                Control::BrowserHostDisplayApproval { reply, .. } => {
                    let _ = reply.send(Err(BrowserHostDisplayError::Stopped));
                }
                Control::PreviewLocalServiceHost { reply, .. } => {
                    let _ = reply.send(Err(SubmitError::Stopped));
                }
                Control::StartLocalServiceHost { envelope, .. } => self.deliver(
                    envelope,
                    OperationStatus::Superseded,
                    RemoteEffect::None,
                    Some(Failure::local(FailureKind::CoreStopped)),
                    PublicOutput::None,
                    None,
                ),
                Control::StopLocalServiceHost { reply, .. } => {
                    let _ = reply.send(Err(SubmitError::Stopped));
                }
            }
        }
        self.publish();
    }
    fn start_next(&mut self) {
        if self.active.is_some() {
            return;
        }
        if self.retire {
            if let Some(host) = &self.browser_host {
                host.cancel.send_replace(true);
                return;
            }
            if let Some(mut client) = self.sdk.take() {
                let had_session = client.sdk.principal().is_some();
                self.active = Some(Active {
                    envelope: None,
                    server: None,
                    section: None,
                    cancelled: None,
                    cancellation: Arc::new(AtomicBool::new(false)),
                    secret: None,
                    remote_revoke: None,
                    native_request_id: None,
                    native_connection_generation: None,
                    service_host_runtime_id: None,
                    future: Box::pin(async move {
                        let result = client.sdk.logout().await.map_err(Failure::from);
                        Job::Retired {
                            client,
                            had_session,
                            result,
                        }
                    }),
                });
                return;
            }
            self.retire = false;
        }
        if self.view.lifecycle != Lifecycle::Running {
            return;
        }
        if self.native_poll_due() {
            self.start_native_permit_poll();
            if self.active.is_some() {
                return;
            }
        }
        if let Some(boundary) = self.boundary.take() {
            match boundary {
                Boundary::Connect { server, envelope } => {
                    self.sdk = None;
                    self.record(envelope.result(
                        OperationStatus::Running,
                        RemoteEffect::None,
                        None,
                        PublicOutput::None,
                    ));
                    let config = server.clone();
                    self.active = Some(Active {
                        envelope: Some(envelope),
                        server: Some(server),
                        section: None,
                        cancelled: None,
                        cancellation: Arc::new(AtomicBool::new(false)),
                        secret: None,
                        remote_revoke: None,
                        native_request_id: None,
                        native_connection_generation: None,
                        service_host_runtime_id: None,
                        future: Box::pin(async move {
                            Job::Connected(
                                if config.deployment_id.is_empty() {
                                    Sdk::connect_origin(&config.origin, config.allow_loopback_http)
                                        .await
                                } else {
                                    Sdk::connect(
                                        &config.origin,
                                        DeploymentTrust {
                                            deployment_id: config.deployment_id,
                                            permit_issuer: config.permit_issuer,
                                        },
                                        config.allow_loopback_http,
                                    )
                                    .await
                                }
                                .map_err(Failure::from),
                            )
                        }),
                    });
                }
                Boundary::Logout { envelope } => {
                    self.deliver(
                        envelope,
                        OperationStatus::Succeeded,
                        RemoteEffect::None,
                        None,
                        PublicOutput::None,
                        None,
                    );
                }
            }
            self.publish();
            return;
        }
        if self.browser_host.is_some() {
            return;
        }
        if self.pending.is_empty() && self.start_native_recovery() {
            return;
        }
        let Some(mut envelope) = self.pending.pop_front() else {
            return;
        };
        if envelope.generation != self.view.generation {
            self.deliver(
                envelope,
                OperationStatus::Superseded,
                RemoteEffect::None,
                None,
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        let Some(action) = envelope.action.take() else {
            return;
        };
        let failure = if self.sdk.is_none() {
            Some(Failure::local(FailureKind::SignInRequired))
        } else if action.local_identity() && self.identity.is_none() {
            Some(Failure::local(FailureKind::LocalIdentityRequired))
        } else if !matches!(action, Action::SignIn { .. })
            && self
                .sdk
                .as_ref()
                .is_some_and(|client| client.sdk.principal().is_none())
        {
            Some(Failure::local(FailureKind::SignInRequired))
        } else {
            None
        };
        if let Some(failure) = failure {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(failure),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        if let Action::StartNativeSession { request_id } = &action {
            self.start_native_establishment(envelope, request_id.clone());
            return;
        }
        if let Action::StartBrowserHost { request_id } = &action {
            self.start_browser_host(envelope, request_id.clone());
            return;
        }
        if let Action::StopNativeSession {
            request_id,
            connection_generation,
        } = &action
        {
            let accepted = self.request_native_stop(
                StopReason::ExplicitExit,
                Some((request_id, *connection_generation)),
            );
            self.deliver(
                envelope,
                if accepted {
                    OperationStatus::Succeeded
                } else {
                    OperationStatus::Failed
                },
                RemoteEffect::None,
                (!accepted).then(|| Failure::local(FailureKind::Invalid)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        let secret = if action.sensitive() {
            self.secret_slots.retain(|slot| {
                slot.upgrade().is_some_and(|slot| {
                    slot.lock().map_or(true, |value| value.is_some())
                        || Arc::strong_count(&slot) > 1
                })
            });
            if self.secret_slots.len() >= self.limits.sensitive_outputs {
                self.deliver(
                    envelope,
                    OperationStatus::Failed,
                    RemoteEffect::None,
                    Some(Failure::local(FailureKind::Capacity)),
                    PublicOutput::None,
                    None,
                );
                self.publish();
                return;
            }
            let slot = Arc::new(Mutex::new(None));
            self.secret_slots.push(Arc::downgrade(&slot));
            Some(slot)
        } else {
            None
        };
        let Some(client) = self.sdk.take() else {
            return;
        };
        if matches!(action, Action::SignIn { .. }) {
            self.fence();
            envelope.generation = self.view.generation;
            self.view.authentication = Authentication::SigningIn;
        }
        let section = action.section();
        section.status(&mut self.view, Some(envelope.id), None);
        self.record(envelope.result(
            OperationStatus::Running,
            RemoteEffect::None,
            None,
            PublicOutput::None,
        ));
        let identity = self.identity.clone();
        let cancellation = Arc::new(AtomicBool::new(false));
        let fence = sdk_call::DispatchFence {
            generation: self.shared.generation.clone(),
            expected: envelope.generation,
            closing: self.shared.closing.clone(),
            cancelled: cancellation.clone(),
        };
        self.active = Some(Active {
            envelope: Some(envelope),
            server: Some(client.server),
            section: Some(section),
            cancelled: None,
            cancellation,
            secret,
            remote_revoke: match &action {
                Action::RevokeRemote { request_id } => Some(request_id.clone()),
                _ => None,
            },
            native_request_id: None,
            native_connection_generation: None,
            service_host_runtime_id: None,
            future: Box::pin(async move {
                Job::Operation(sdk_call::run(client.sdk, identity, action, fence).await)
            }),
        });
        self.publish();
    }
    fn start_native_establishment(&mut self, envelope: Envelope, request_id: String) {
        let Some(config) = self.native.clone() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        if self
            .view
            .native_session
            .data
            .as_ref()
            .is_some_and(|session| {
                matches!(
                    session.status,
                    NativeSessionStatus::Establishing
                        | NativeSessionStatus::Connected
                        | NativeSessionStatus::Stopping
                )
            })
        {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Capacity)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        if !config.network().subscribe().borrow().available {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::NetworkChanged)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        let selected = self
            .view
            .selected_request
            .data
            .as_ref()
            .filter(|request| request.id == request_id);
        let expected_connection_generation = selected.map(|request| request.connection_generation);
        let initial_generation = expected_connection_generation.unwrap_or(0);
        let initial_sequence = selected.map_or(0, |request| request.lease_sequence);
        let Some(identity) = self.identity.clone() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::LocalIdentityRequired)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        let Some(client) = self.sdk.take() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::SignInRequired)),
                PublicOutput::None,
                None,
            );
            return;
        };
        let operation_id = envelope.id;
        let generation = envelope.generation;
        let cancellation = Arc::new(AtomicBool::new(false));
        let fence = sdk_call::DispatchFence {
            generation: self.shared.generation.clone(),
            expected: generation,
            closing: self.shared.closing.clone(),
            cancelled: cancellation.clone(),
        };
        self.view.native_session = crate::Section {
            data: Some(Arc::new(NativeSessionView {
                request_id: request_id.clone(),
                connection_generation: initial_generation,
                lease_sequence: initial_sequence,
                status: NativeSessionStatus::Establishing,
                host_view_authorized: false,
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            })),
            loading: Some(operation_id),
            error: None,
        };
        self.record(envelope.result(
            OperationStatus::Running,
            RemoteEffect::None,
            None,
            PublicOutput::None,
        ));
        let native_request_id = request_id.clone();
        self.active = Some(Active {
            envelope: Some(envelope),
            server: Some(client.server.clone()),
            section: None,
            cancelled: None,
            cancellation,
            secret: None,
            remote_revoke: None,
            native_request_id: Some(native_request_id),
            native_connection_generation: expected_connection_generation,
            service_host_runtime_id: None,
            future: Box::pin(async move {
                let result = establish_native_session(
                    &client,
                    &identity,
                    &config,
                    &request_id,
                    expected_connection_generation,
                    fence,
                )
                .await;
                Job::NativeEstablished {
                    client: Box::new(client),
                    request_id,
                    core_generation: generation,
                    expected_connection_generation,
                    result,
                }
            }),
        });
        self.publish();
    }

    fn start_browser_host(&mut self, envelope: Envelope, request_id: String) {
        let Some(config) = self
            .native
            .as_ref()
            .and_then(|config| config.browser_host.clone())
        else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        if self.browser_host.is_some()
            || self
                .view
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    matches!(
                        session.status,
                        NativeSessionStatus::Establishing
                            | NativeSessionStatus::Connected
                            | NativeSessionStatus::Stopping
                    )
                })
        {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Capacity)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        let Some(identity) = self.identity.clone() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::LocalIdentityRequired)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        let selected = self
            .view
            .selected_request
            .data
            .as_ref()
            .filter(|request| request.id == request_id);
        let Some(selected) = selected else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        if selected.status != "approved"
            || selected.host_device_id != identity.device_id
            || selected.connection_generation == 0
            || selected.lease_sequence == 0
            || selected.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
        {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::Invalid)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        }
        let connection_generation = selected.connection_generation;
        let lease_sequence = selected.lease_sequence;
        let operation_id = envelope.id;
        let Some(client) = self.sdk.take() else {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::SignInRequired)),
                PublicOutput::None,
                None,
            );
            self.publish();
            return;
        };
        let server = client.server.clone();
        let (cancel, cancel_rx) = watch::channel(false);
        let (display_approval, display_approval_rx) = watch::channel(None);
        let (event_tx, events) = mpsc::channel(2);
        let (display_offer_tx, display_offer_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let runtime_request_id = request_id.clone();
        let host_sdk = client.sdk;
        let running = envelope.result(
            OperationStatus::Running,
            RemoteEffect::None,
            None,
            PublicOutput::None,
        );
        tokio::spawn(async move {
            let runner = run_browser_host(
                host_sdk,
                identity,
                runtime_request_id,
                config,
                crate::BrowserHostChannels {
                    cancel: cancel_rx,
                    display_offer: display_offer_tx,
                    display_approval: display_approval_rx,
                    ready: ready_tx,
                },
            );
            tokio::pin!(runner);
            let mut display_offer_rx = Some(display_offer_rx);
            let mut ready_rx = Some(ready_rx);
            let mut ready_sent = false;
            loop {
                tokio::select! {
                    biased;
                    exit = &mut runner => {
                        if let Some(mut receiver) = display_offer_rx.take()
                            && let Ok(offer) = receiver.try_recv()
                        {
                            let _ = event_tx
                                .send(BrowserHostEvent::DisplayOffer(Box::new(offer)))
                                .await;
                        }
                        if !ready_sent {
                            let ready = if let Some(mut receiver) = ready_rx.take() {
                                match receiver.try_recv() {
                                    Ok(ready) => ready,
                                    Err(_) if exit.connected => exit
                                        .binding.clone().zip(exit.data.clone())
                                        .map(|(binding, data)| BrowserHostReady {
                                            binding,
                                            lease_sequence: exit.lease_sequence,
                                            data,
                                            displays: crate::BrowserHostDisplayView::default(),
                                            path: exit.path.unwrap_or_default(),
                                        })
                                        .ok_or(BrowserHostFailure::Unavailable),
                                    Err(_) => Err(exit.failure.unwrap_or(BrowserHostFailure::Unavailable)),
                                }
                            } else {
                                Err(BrowserHostFailure::Unavailable)
                            };
                            let _ = event_tx.send(BrowserHostEvent::Ready(ready.map(Box::new))).await;
                        }
                        let _ = event_tx.send(BrowserHostEvent::Finished(Box::new(exit))).await;
                        break;
                    }
                    offer = async {
                        match display_offer_rx.as_mut() {
                            Some(receiver) => receiver.await,
                            None => std::future::pending().await,
                        }
                    }, if display_offer_rx.is_some() => {
                        display_offer_rx = None;
                        if let Ok(offer) = offer {
                            let _ = event_tx
                                .send(BrowserHostEvent::DisplayOffer(Box::new(offer)))
                                .await;
                        }
                    }
                    ready = async {
                        match ready_rx.as_mut() {
                            Some(receiver) => receiver.await,
                            None => std::future::pending().await,
                        }
                    }, if ready_rx.is_some() => {
                        ready_rx = None;
                        ready_sent = true;
                        let ready = ready.unwrap_or(Err(BrowserHostFailure::Unavailable));
                        let _ = event_tx.send(BrowserHostEvent::Ready(ready.map(Box::new))).await;
                    }
                }
            }
        });
        self.access_deadline = None;
        self.view.browser_host = crate::Section {
            data: Some(Arc::new(BrowserHostView {
                request_id: request_id.clone(),
                connection_generation,
                lease_sequence,
                status: BrowserHostStatus::Establishing,
                host_view_authorized: false,
                binding: None,
                displays: crate::BrowserHostDisplayView::default(),
                data: BrowserHostDataView::default(),
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            })),
            loading: Some(operation_id),
            error: None,
        };
        self.browser_host = Some(BrowserHostRuntime {
            request_id,
            connection_generation,
            lease_sequence,
            server,
            cancel,
            display_approval,
            events,
            start_envelope: Some(envelope),
        });
        self.record(running);
        self.publish();
    }

    fn request_browser_stop(&mut self, request_id: &str, generation: u64) -> bool {
        let Some(host) = self.browser_host.as_ref() else {
            return false;
        };
        if host.request_id != request_id || host.connection_generation != generation {
            return false;
        }
        let active = self.view.browser_host.data.as_ref().is_some_and(|session| {
            session.request_id == request_id
                && session.connection_generation == generation
                && matches!(
                    session.status,
                    BrowserHostStatus::Establishing
                        | BrowserHostStatus::Connected
                        | BrowserHostStatus::Stopping
                )
        });
        if !active {
            return false;
        }
        if let Some(host) = &self.browser_host {
            host.cancel.send_replace(true);
        }
        self.set_browser_host_stopping(NativeSessionStopReason::UserCancelled);
        true
    }

    fn set_browser_host_stopping(&mut self, reason: NativeSessionStopReason) {
        if let Some(session) = self.view.browser_host.data.as_ref()
            && matches!(
                session.status,
                BrowserHostStatus::Establishing
                    | BrowserHostStatus::Connected
                    | BrowserHostStatus::Stopping
            )
        {
            let mut session = session.as_ref().clone();
            session.status = BrowserHostStatus::Stopping;
            session.host_view_authorized = false;
            session.binding = None;
            session.displays = crate::BrowserHostDisplayView::default();
            session.data = BrowserHostDataView::default();
            session.stop_reason = Some(reason);
            self.view.browser_host.data = Some(Arc::new(session));
        }
    }

    fn browser_host_display_offer(&mut self, offer: BrowserHostDisplayOffer) {
        let Some(host) = self.browser_host.as_ref().filter(|host| {
            host.request_id == offer.binding.request_id
                && host.connection_generation == offer.binding.connection_generation
        }) else {
            return;
        };
        let key_valid = offer.catalog.request_id == host.request_id
            && offer.catalog.connection_generation == host.connection_generation
            && offer.catalog.revision == 1
            && nestlink_protocol::native_displays::catalog_key(
                &offer.catalog.request_id,
                offer.catalog.connection_generation,
                offer.catalog.revision,
                &offer.displays,
            )
            .is_ok_and(|expected| expected == offer.catalog);
        if !key_valid {
            if let Some(host) = &self.browser_host {
                host.cancel.send_replace(true);
            }
            return;
        }
        let Some(current) = self.view.browser_host.data.as_ref() else {
            return;
        };
        if current.status != BrowserHostStatus::Establishing
            || current.request_id != offer.binding.request_id
            || current.connection_generation != offer.binding.connection_generation
            || current.displays.catalog.is_some()
        {
            if let Some(host) = &self.browser_host {
                host.cancel.send_replace(true);
            }
            return;
        }
        let mut current = current.as_ref().clone();
        current.binding = Some(offer.binding);
        current.displays = crate::BrowserHostDisplayView {
            catalog: Some(offer.catalog),
            displays: offer.displays,
            approval_required: true,
            approved_sources: Vec::new(),
            initial_source: None,
        };
        self.view.browser_host.data = Some(Arc::new(current));
        self.publish();
    }

    fn browser_host_ready(&mut self, result: Result<BrowserHostReady, BrowserHostFailure>) {
        let Some(host) = self.browser_host.as_mut() else {
            return;
        };
        let envelope = host.start_envelope.take();
        match result {
            Ok(ready) => {
                host.connection_generation = ready.binding.connection_generation;
                host.lease_sequence = ready.lease_sequence;
                self.view.browser_host = crate::Section {
                    data: Some(Arc::new(BrowserHostView {
                        request_id: host.request_id.clone(),
                        connection_generation: ready.binding.connection_generation,
                        lease_sequence: ready.lease_sequence,
                        status: BrowserHostStatus::Connected,
                        host_view_authorized: true,
                        binding: Some(ready.binding),
                        displays: ready.displays,
                        data: ready.data,
                        path: Some(ready.path),
                        stop_reason: None,
                        stop_effects: None,
                        cleanup: None,
                        failure: None,
                    })),
                    loading: None,
                    error: None,
                };
                if let Some(envelope) = envelope {
                    self.deliver(
                        envelope,
                        OperationStatus::Succeeded,
                        RemoteEffect::None,
                        None,
                        PublicOutput::None,
                        None,
                    );
                }
            }
            Err(kind) => {
                let failure = browser_host_failure(kind);
                let status = if kind == BrowserHostFailure::Cancelled {
                    BrowserHostStatus::Stopped
                } else {
                    BrowserHostStatus::Failed
                };
                let request_id = host.request_id.clone();
                let connection_generation = host.connection_generation;
                let lease_sequence = host.lease_sequence;
                self.view.browser_host = crate::Section {
                    data: Some(Arc::new(BrowserHostView {
                        request_id,
                        connection_generation,
                        lease_sequence,
                        status,
                        host_view_authorized: false,
                        binding: None,
                        displays: crate::BrowserHostDisplayView::default(),
                        data: BrowserHostDataView::default(),
                        path: None,
                        stop_reason: (kind == BrowserHostFailure::Cancelled)
                            .then_some(NativeSessionStopReason::UserCancelled),
                        stop_effects: None,
                        cleanup: None,
                        failure: (status == BrowserHostStatus::Failed).then(|| failure.clone()),
                    })),
                    loading: None,
                    error: (status == BrowserHostStatus::Failed).then_some(failure.clone()),
                };
                if let Some(envelope) = envelope {
                    self.deliver(
                        envelope,
                        if kind == BrowserHostFailure::Cancelled {
                            OperationStatus::Cancelled
                        } else {
                            OperationStatus::Failed
                        },
                        RemoteEffect::None,
                        (kind != BrowserHostFailure::Cancelled).then_some(failure),
                        PublicOutput::None,
                        None,
                    );
                }
            }
        }
        self.publish();
    }

    fn browser_host_finished(&mut self, exit: BrowserHostExit) {
        let ready_result = if exit.connected {
            exit.binding
                .clone()
                .zip(exit.data.clone())
                .map(|(binding, data)| BrowserHostReady {
                    binding,
                    lease_sequence: exit.lease_sequence,
                    data,
                    displays: self
                        .view
                        .browser_host
                        .data
                        .as_ref()
                        .map_or_else(crate::BrowserHostDisplayView::default, |view| {
                            view.displays.clone()
                        }),
                    path: exit.path.unwrap_or_default(),
                })
                .ok_or(BrowserHostFailure::Unavailable)
        } else {
            Err(exit.failure.unwrap_or(BrowserHostFailure::Unavailable))
        };
        if self
            .browser_host
            .as_ref()
            .is_some_and(|host| host.start_envelope.is_some())
        {
            self.browser_host_ready(ready_result);
        }
        let Some(host) = self.browser_host.take() else {
            return;
        };
        self.sdk = Some(Client {
            sdk: exit.sdk,
            server: host.server,
        });
        if !self.retire && self.view.lifecycle == Lifecycle::Running {
            self.view.principal = self
                .sdk
                .as_ref()
                .and_then(|client| client.sdk.principal().cloned());
            self.install_deadline();
        }

        let report = exit.stop;
        let stop_reason = report
            .map(|report| map_stop_reason(report.reason))
            .or_else(|| exit.failure.map(browser_host_stop_reason));
        let stop_effects = report.map(|report| {
            map_report_effects(
                report.effects.cancel_channels,
                report.effects.release_inputs,
                report.effects.discard_queues,
                report.effects.close_allocations,
            )
        });
        let cleanup = browser_host_cleanup(report, exit.cleanup_failed);
        let cleanup_failed = exit.cleanup_failed || cleanup == Some(NativeSessionCleanup::Failed);
        let failure = exit
            .failure
            .filter(|failure| *failure != BrowserHostFailure::Cancelled)
            .map(browser_host_failure)
            .or_else(|| {
                cleanup_failed.then(|| Failure::local(FailureKind::NativeSessionUnavailable))
            });
        let status = if failure.is_some() {
            BrowserHostStatus::Failed
        } else {
            BrowserHostStatus::Stopped
        };
        self.view.browser_host = crate::Section {
            data: Some(Arc::new(BrowserHostView {
                request_id: exit.request_id,
                connection_generation: exit.connection_generation,
                lease_sequence: exit.lease_sequence,
                status,
                host_view_authorized: false,
                binding: None,
                displays: crate::BrowserHostDisplayView::default(),
                data: BrowserHostDataView::default(),
                path: exit.path,
                stop_reason,
                stop_effects,
                cleanup,
                failure: failure.clone(),
            })),
            loading: None,
            error: failure,
        };
        self.publish();
    }

    fn browser_host_event_lost(&mut self) {
        let Some(host) = self.browser_host.take() else {
            return;
        };
        host.cancel.send_replace(true);
        let failure = Failure::local(FailureKind::NativeSessionUnavailable);
        self.view.browser_host = crate::Section {
            data: Some(Arc::new(BrowserHostView {
                request_id: host.request_id,
                connection_generation: host.connection_generation,
                lease_sequence: host.lease_sequence,
                status: BrowserHostStatus::Failed,
                host_view_authorized: false,
                binding: None,
                displays: crate::BrowserHostDisplayView::default(),
                data: BrowserHostDataView::default(),
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: Some(NativeSessionCleanup::Failed),
                failure: Some(failure.clone()),
            })),
            loading: None,
            error: Some(failure),
        };
        if let Some(envelope) = host.start_envelope {
            self.deliver(
                envelope,
                OperationStatus::Failed,
                RemoteEffect::None,
                Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                PublicOutput::None,
                None,
            );
        }
        self.publish();
    }

    fn native_poll_due(&self) -> bool {
        self.active.is_none()
            && !self.retire
            && self.boundary.is_none()
            && self.view.lifecycle == Lifecycle::Running
            && self.sdk.is_some()
            && self.native_session_key.is_some()
            && self
                .view
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| session.status == NativeSessionStatus::Connected)
            && self
                .native_poll_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    }
    fn start_native_permit_poll(&mut self) {
        let (Some(key), Some(client), Some(identity)) = (
            self.native_session_key.clone(),
            self.sdk.take(),
            self.identity.clone(),
        ) else {
            return;
        };
        self.native_poll_deadline = None;
        let cancellation = Arc::new(AtomicBool::new(false));
        let fence = sdk_call::DispatchFence {
            generation: self.shared.generation.clone(),
            expected: self.view.generation,
            closing: self.shared.closing.clone(),
            cancelled: cancellation.clone(),
        };
        self.active = Some(Active {
            envelope: None,
            server: None,
            section: None,
            cancelled: None,
            cancellation,
            secret: None,
            remote_revoke: None,
            native_request_id: None,
            native_connection_generation: None,
            service_host_runtime_id: None,
            future: Box::pin(async move {
                let result = poll_native_permit(&client, &identity, &key, &fence).await;
                Job::NativePermitPolled {
                    client,
                    key,
                    result,
                }
            }),
        });
    }
    fn poll_native_session(&mut self) {
        self.shared.reap_native_audio_owners();
        self.shared.reap_native_clipboard_owners();
        self.shared.reap_native_files_owners();
        if self.native_poll_due() {
            self.start_native_permit_poll();
        }
    }
    fn request_native_stop(&mut self, reason: StopReason, target: Option<(&str, u64)>) -> bool {
        let matches_target = |request_id: &str, connection_generation: u64| {
            target.is_none_or(|(id, generation)| {
                request_id == id && connection_generation == generation
            })
        };
        let key_matches = self
            .native_session_key
            .as_ref()
            .is_some_and(|key| matches_target(&key.request_id, key.connection_generation));
        let session_matches = self
            .view
            .native_session
            .data
            .as_ref()
            .filter(|session| {
                matches!(
                    session.status,
                    NativeSessionStatus::Establishing
                        | NativeSessionStatus::Connected
                        | NativeSessionStatus::Stopping
                )
            })
            .is_some_and(|session| {
                matches_target(&session.request_id, session.connection_generation)
            });
        let active_matches = self.active.as_ref().is_some_and(|active| {
            active
                .native_request_id
                .as_deref()
                .is_some_and(|request_id| {
                    target.is_none_or(|(id, generation)| {
                        request_id == id && active.native_connection_generation == Some(generation)
                    })
                })
        });
        let recovery_matches = self.native_recovery.as_ref().is_some_and(|source| {
            matches_target(&source.key.request_id, source.key.connection_generation)
        });
        if !key_matches && !session_matches && !active_matches && !recovery_matches {
            return false;
        }
        self.shared.clear_native_video_route();
        self.shared.set_native_audio_route(None);
        self.shared.set_native_clipboard_route(None);
        self.shared.set_native_files_route(None);
        self.local_stop_reason = Some(map_stop_reason(reason));
        self.native_poll_deadline = None;
        if let Some(control) = self.native_session_control.as_ref() {
            let _ = control.stop(reason);
        }
        if recovery_matches && let Some(source) = self.native_recovery.take() {
            let _ = source.failed.control.stop(reason);
        }
        if active_matches && let Some(active) = &mut self.active {
            active.cancelled = Some(OperationStatus::Cancelled);
            active.cancellation.store(true, Ordering::Release);
        }
        self.set_native_stopping(map_stop_reason(reason));
        if recovery_matches && self.native_session_task.is_none() && !active_matches {
            self.set_native_recovery_terminal(None);
        }
        true
    }
    fn set_native_stopping(&mut self, reason: NativeSessionStopReason) {
        if let Some(session) = self.view.native_session.data.as_ref() {
            if !matches!(
                session.status,
                NativeSessionStatus::Establishing
                    | NativeSessionStatus::Connected
                    | NativeSessionStatus::Stopping
            ) {
                return;
            }
            let mut session = session.as_ref().clone();
            session.status = NativeSessionStatus::Stopping;
            session.host_view_authorized = false;
            session.stop_reason = Some(reason);
            self.view.native_session.data = Some(Arc::new(session));
        }
    }
    fn native_stopped(&mut self, stopped: Result<NativeSessionStop, JoinError>) {
        self.shared.clear_native_video_route();
        self.shared.set_native_audio_route(None);
        self.shared.set_native_clipboard_route(None);
        self.shared.set_native_files_route(None);
        self.native_session_control = None;
        self.native_session_key = None;
        self.native_poll_deadline = None;
        self.native_recovery = None;
        let (request_id, generation, sequence, path, reason, effects, cleanup, failure) =
            match stopped {
                Ok(stopped) => {
                    if self.local_stop_reason.is_none()
                        && let Some(source) = stopped.recovery
                        && self.native_recovery_context_current(&source.context)
                    {
                        self.native_recovery = Some(source);
                    }
                    let effects = stopped.stop_effects;
                    let cleanup = stopped.cleanup;
                    let failure = stopped.failure;
                    (
                        stopped.key.request_id,
                        stopped.key.connection_generation,
                        stopped.key.lease_sequence,
                        Some(stopped.key.path),
                        stopped.stop_reason.or(self.local_stop_reason),
                        effects,
                        cleanup,
                        failure,
                    )
                }
                Err(_) => {
                    let previous = self.view.native_session.data.as_ref();
                    (
                        previous.map_or_else(String::new, |session| session.request_id.clone()),
                        previous.map_or(0, |session| session.connection_generation),
                        previous.map_or(0, |session| session.lease_sequence),
                        previous.and_then(|session| session.path),
                        self.local_stop_reason,
                        None,
                        Some(NativeSessionCleanup::Failed),
                        Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                    )
                }
            };
        let status = if self.native_recovery.is_some() {
            NativeSessionStatus::Establishing
        } else if failure.is_some() {
            NativeSessionStatus::Failed
        } else {
            NativeSessionStatus::Stopped
        };
        self.view.native_session = crate::Section {
            data: Some(Arc::new(NativeSessionView {
                request_id,
                connection_generation: generation,
                lease_sequence: sequence,
                status,
                host_view_authorized: false,
                path,
                stop_reason: reason,
                stop_effects: effects,
                cleanup,
                failure: failure.clone(),
            })),
            loading: None,
            error: failure,
        };
        self.local_stop_reason = None;
        self.publish();
    }
    fn completed(&mut self, job: Job) {
        let Some(mut active) = self.active.take() else {
            return;
        };
        let job = match job {
            Job::NativeEstablished {
                client,
                request_id,
                core_generation,
                expected_connection_generation,
                result,
            } => {
                self.complete_native_establishment(
                    active,
                    *client,
                    request_id,
                    core_generation,
                    expected_connection_generation,
                    result,
                );
                return;
            }
            Job::NativePermitPolled {
                client,
                key,
                result,
            } => {
                self.complete_native_poll(active, client, key, result);
                return;
            }
            Job::LocalServiceHostStarted {
                client,
                binding,
                approved,
                result,
            } => {
                self.complete_local_service_host_start(active, *client, *binding, approved, result);
                return;
            }
            job => job,
        };
        if let Job::Retired {
            client,
            had_session,
            result,
        } = job
        {
            self.retire = false;
            if had_session {
                self.view.logout_confirmed = Some(result.is_ok());
            }
            let same_server = self.view.server.as_ref().is_some_and(|server| {
                server.origin == client.server.origin
                    && server.deployment_id == client.server.deployment_id
                    && server.approved_issuer == client.server.permit_issuer
                    && server.verified_health.is_some()
            });
            if self.view.lifecycle == Lifecycle::Running && same_server {
                self.sdk = Some(client);
            }
            if let Some(Boundary::Logout { .. }) = self.boundary.as_ref()
                && let Some(boundary) = self.boundary.take()
            {
                self.view.logout_confirmed = had_session.then_some(result.is_ok());
                let failure = result.err();
                let status = if failure.is_some() {
                    OperationStatus::Failed
                } else {
                    OperationStatus::Succeeded
                };
                self.deliver(
                    boundary.into_envelope(),
                    status,
                    if had_session {
                        if failure.is_none() {
                            RemoteEffect::Committed
                        } else {
                            RemoteEffect::Unknown
                        }
                    } else {
                        RemoteEffect::None
                    },
                    failure,
                    PublicOutput::None,
                    None,
                );
            }
            self.publish();
            return;
        }
        let Some(mut envelope) = active.envelope.take() else {
            return;
        };
        let current = envelope.generation == self.view.generation
            && self.view.lifecycle == Lifecycle::Running;
        match job {
            Job::Connected(result) => {
                let failure = match result {
                    Ok(sdk) => {
                        if current && active.cancelled.is_none() {
                            if let Some(server) = &mut self.view.server {
                                server.verified_health = Some(sdk.health().clone());
                                server.error = None;
                            }
                            self.view.authentication = Authentication::SignedOut;
                        }
                        if let Some(mut server) = active.server.take() {
                            server.deployment_id = sdk.health().deployment_id.clone();
                            if let Ok(bytes) = URL_SAFE_NO_PAD.decode(&sdk.health().permit_issuer)
                                && let Ok(issuer) = <[u8; 32]>::try_from(bytes)
                            {
                                server.permit_issuer = issuer;
                            }
                            if current
                                && active.cancelled.is_none()
                                && let Some(view) = &mut self.view.server
                            {
                                view.deployment_id = server.deployment_id.clone();
                                view.approved_issuer = server.permit_issuer;
                            }
                            self.sdk = Some(Client { sdk, server });
                        }
                        if !current || active.cancelled.is_some() {
                            self.retire = true;
                        }
                        None
                    }
                    Err(failure) => {
                        if current && active.cancelled.is_none() {
                            if let Some(server) = &mut self.view.server {
                                server.error = Some(failure.clone());
                            }
                            self.view.authentication = Authentication::Disconnected;
                        }
                        Some(failure)
                    }
                };
                let status = active.cancelled.unwrap_or(if !current {
                    OperationStatus::Superseded
                } else if failure.is_some() {
                    OperationStatus::Failed
                } else {
                    OperationStatus::Succeeded
                });
                self.deliver(
                    envelope,
                    status,
                    RemoteEffect::None,
                    if current { failure } else { None },
                    PublicOutput::None,
                    None,
                );
            }
            Job::Operation(mut response) => {
                let sign_in = envelope.kind == OperationKind::SignIn;
                if let Some(server) = active.server.take() {
                    self.sdk = Some(Client {
                        sdk: response.sdk,
                        server,
                    });
                }
                if let Some(request_id) = active.remote_revoke.take()
                    && response.effect != RemoteEffect::None
                {
                    let connection_generation = self
                        .native_session_key
                        .as_ref()
                        .filter(|key| key.request_id == request_id)
                        .map(|key| key.connection_generation)
                        .or_else(|| {
                            self.view
                                .native_session
                                .data
                                .as_ref()
                                .filter(|session| session.request_id == request_id)
                                .map(|session| session.connection_generation)
                        });
                    if let Some(connection_generation) = connection_generation {
                        let _ = self.request_native_stop(
                            StopReason::Revoked,
                            Some((&request_id, connection_generation)),
                        );
                    }
                }
                let visible = current && active.cancelled.is_none();
                if visible {
                    for patch in response.patches.drain(..) {
                        patch.apply(&mut self.view);
                    }
                    if self.access_deadline.is_none() || envelope.kind == OperationKind::Refresh {
                        self.install_deadline();
                    }
                    if let Some(section) = active.section {
                        section.status(&mut self.view, None, response.failure.clone());
                    }
                    if sign_in {
                        self.view.authentication = if response.failure.is_none() {
                            Authentication::SignedIn
                        } else {
                            Authentication::SignedOut
                        };
                        self.view.authentication_error = response.failure.clone();
                    }
                } else if current && let Some(section) = active.section {
                    section.status(&mut self.view, None, None);
                }
                let mut sensitive = None;
                if visible
                    && let (Some(slot), Some(value)) =
                        (active.secret.take(), response.sensitive.take())
                {
                    if let Ok(mut pending) = slot.lock() {
                        *pending = Some(value);
                    }
                    sensitive = Some(slot);
                }
                let status = active.cancelled.unwrap_or(if !current {
                    OperationStatus::Superseded
                } else if response.failure.is_some() {
                    OperationStatus::Failed
                } else {
                    OperationStatus::Succeeded
                });
                let must_retire = !current
                    || (sign_in && (response.failure.is_some() || active.cancelled.is_some()))
                    || (envelope.kind == OperationKind::Refresh && active.cancelled.is_some());
                let lost = visible && response.session_lost;
                // Credential invalidation must happen before delivering success
                // for a password change, or an auth-loss response.
                if lost {
                    self.expire();
                    envelope.generation = self.view.generation;
                } else if must_retire {
                    self.retire = true;
                }
                self.reconcile_local_service_host();
                self.deliver(
                    envelope,
                    status,
                    response.effect,
                    if current { response.failure } else { None },
                    if visible {
                        response.output
                    } else {
                        PublicOutput::None
                    },
                    sensitive,
                );
            }
            Job::Retired { .. } => {}
            Job::NativeEstablished { .. }
            | Job::NativePermitPolled { .. }
            | Job::LocalServiceHostStarted { .. } => {}
        }
        self.publish();
    }
    fn install_approved_service_view(&mut self, approved: &nestlink_protocol::api::ServiceView) {
        self.view.selected_service.replace(approved.clone());
        if let Some(page) = self.view.services.data.as_ref() {
            let mut page = page.as_ref().clone();
            if let Some(current) = page
                .services
                .iter_mut()
                .find(|service| service.id == approved.id)
            {
                *current = approved.clone();
                self.view.services.data = Some(Arc::new(page));
            }
        }
    }

    fn complete_local_service_host_start(
        &mut self,
        mut active: Active,
        client: Client,
        binding: ServiceHostBinding,
        approved: Option<nestlink_protocol::api::ServiceView>,
        result: Result<LocalServiceRuntime, Failure>,
    ) {
        self.service_host_start_cancel = None;
        let Some(envelope) = active.envelope.take() else {
            self.sdk = Some(client);
            return;
        };
        let context_current = envelope.generation == self.view.generation
            && snapshot_matches_binding(&self.view, &binding, &binding.runtime_id);
        let same_server = self.view.server.as_ref().is_some_and(|server| {
            server.origin == client.server.origin
                && server.deployment_id == client.server.deployment_id
                && server.approved_issuer == client.server.permit_issuer
                && server.verified_health.is_some()
        });
        if !same_server {
            self.retire = true;
        }
        self.sdk = Some(client);

        let approved = approved.filter(|view| approved_service_matches(&binding, view));
        if context_current && let Some(approved) = approved.as_ref() {
            self.install_approved_service_view(approved);
        }
        let approved_revision = approved.as_ref().map(|view| view.revision);
        let mut failure = None;
        let mut effect = if approved.is_some() {
            RemoteEffect::Committed
        } else if active.cancelled.is_some() {
            RemoteEffect::None
        } else {
            RemoteEffect::Unknown
        };
        let result = match result {
            Ok(runtime)
                if context_current
                    && same_server
                    && !self.retire
                    && active.cancelled.is_none()
                    && approved.is_some() =>
            {
                let approved_view = approved.clone();
                self.service_host_owner = Some(ServiceHostOwner {
                    binding: binding.clone(),
                    approved_view,
                    runtime,
                    cleanup_requested: false,
                });
                if let Some(host) = &mut self.view.local_service_host {
                    host.approved_revision = approved_revision;
                    host.status = crate::LocalServiceHostStatus::Running;
                    host.cleanup_failed = false;
                    host.failure = None;
                }
                Ok(())
            }
            Ok(runtime) => {
                runtime.stop();
                self.service_host_owner = Some(ServiceHostOwner {
                    binding: binding.clone(),
                    approved_view: approved.clone(),
                    runtime,
                    cleanup_requested: true,
                });
                if let Some(host) = &mut self.view.local_service_host {
                    host.approved_revision = approved_revision;
                    host.status = crate::LocalServiceHostStatus::Stopping;
                }
                if !context_current && active.cancelled.is_none() {
                    failure = Some(Failure::local(FailureKind::StaleGeneration));
                } else if approved.is_none() {
                    failure = Some(Failure::local(FailureKind::Trust));
                }
                Err(())
            }
            Err(error) => {
                if let Some(host) = &mut self.view.local_service_host {
                    host.approved_revision = approved_revision;
                    if active.cancelled.is_some() || !context_current {
                        host.status = crate::LocalServiceHostStatus::Stopped;
                        host.failure = None;
                    } else {
                        host.status = crate::LocalServiceHostStatus::Failed;
                        host.failure = Some(error.clone());
                    }
                }
                failure = (active.cancelled.is_none() && context_current).then_some(error);
                Err(())
            }
        };
        let status = active.cancelled.unwrap_or(if !context_current {
            OperationStatus::Superseded
        } else if result.is_err() {
            OperationStatus::Failed
        } else {
            OperationStatus::Succeeded
        });
        if status == OperationStatus::Cancelled && approved.is_some() {
            effect = RemoteEffect::Committed;
        }
        self.deliver(
            envelope,
            status,
            effect,
            failure,
            approved_revision.map_or(PublicOutput::None, |revision| PublicOutput::Revision {
                revision,
            }),
            None,
        );
    }

    fn complete_native_establishment(
        &mut self,
        mut active: Active,
        client: Client,
        request_id: String,
        core_generation: u64,
        expected_connection_generation: Option<u64>,
        result: Result<EstablishedNativeSession, Failure>,
    ) {
        let envelope = active.envelope.take();
        let current = core_generation == self.view.generation
            && core_generation == self.shared.generation.load(Ordering::Acquire)
            && self.view.lifecycle == Lifecycle::Running
            && !self.shared.closing.load(Ordering::Acquire);
        let cancelled = active.cancelled;
        if current {
            self.sdk = Some(client);
        } else {
            self.sdk = Some(client);
            self.retire = true;
        }
        match result {
            Ok(mut established) => {
                let key = established.key.clone();
                let control = established.session.control.clone();
                let deadline_expired = established
                    .recovery
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline);
                let accepted = current
                    && cancelled.is_none()
                    && !deadline_expired
                    && self.native_recovery_context_current(&established.recovery);
                if deadline_expired {
                    self.local_stop_reason = Some(NativeSessionStopReason::Expired);
                }
                let media_timing = SessionMediaTiming::default();
                let video_receiver = if accepted && key.controller_view_authorized {
                    match VideoReceiver::attach_advertised_channel_timed(
                        &mut established.session.channels,
                        key.connection_generation,
                        media_timing.playout.clone(),
                    ) {
                        Ok(receiver) => Some(receiver),
                        Err(_) => {
                            let _ = control.stop(StopReason::PlatformChanged);
                            None
                        }
                    }
                } else {
                    None
                };
                self.shared
                    .set_native_video_presentation(video_receiver.as_ref().map(|receiver| {
                        Arc::new(NativeVideoPresentationRoute {
                            request_id: key.request_id.clone(),
                            connection_generation: key.connection_generation,
                            generation: self.view.generation,
                            presentation: receiver.presentation(),
                        })
                    }));
                let video_route = if accepted && key.host_view_authorized {
                    Some(Arc::new(NativeVideoRoute {
                        request_id: key.request_id.clone(),
                        connection_generation: key.connection_generation,
                        sender: established.session.channels.sender(),
                        lease: established.session.channels.lease_control(),
                        gate: Arc::new(HostVideoGate {
                            state: Mutex::new(HostVideoGateState::default()),
                        }),
                        send_order: AsyncMutex::new(()),
                        cursor: Mutex::new(NativeVideoCursor::default()),
                        timing: media_timing.clone(),
                    }))
                } else {
                    None
                };
                self.shared.set_native_video_route(video_route);
                let audio_route = if accepted && key.audio_authorized {
                    match NativeAudioRoute::attach(
                        &self.shared,
                        &mut established.session.channels,
                        &key,
                        self.view.generation,
                        media_timing,
                    ) {
                        Ok(route) => Some(route),
                        Err(_) => {
                            let _ = control.stop(StopReason::PlatformChanged);
                            None
                        }
                    }
                } else {
                    None
                };
                self.shared.set_native_audio_route(audio_route.clone());
                let clipboard_route = if accepted
                    && (key.clipboard_read_authorized || key.clipboard_write_authorized)
                {
                    match NativeClipboardRoute::attach(
                        &self.shared,
                        &mut established.session.channels,
                        &key,
                        self.view.generation,
                    ) {
                        Ok(route) => Some(route),
                        Err(_) => {
                            let _ = control.stop(StopReason::PlatformChanged);
                            None
                        }
                    }
                } else {
                    None
                };
                self.shared
                    .set_native_clipboard_route(clipboard_route.clone());
                let files_route =
                    if accepted && (key.file_read_authorized || key.file_write_authorized) {
                        match NativeFilesRoute::attach(
                            &self.shared,
                            &mut established.session.channels,
                            &key,
                            self.view.generation,
                        ) {
                            Ok(route) => Some(route),
                            Err(_) => {
                                let _ = control.stop(StopReason::PlatformChanged);
                                None
                            }
                        }
                    } else {
                        None
                    };
                self.shared.set_native_files_route(files_route.clone());
                let input_route = if accepted && key.input_authorized {
                    match NativeInputRoute::attach(
                        &mut established.session.channels,
                        &key,
                        self.view.generation,
                    ) {
                        Ok(route) => Some(route),
                        Err(_) => {
                            let _ = control.stop(StopReason::PlatformChanged);
                            None
                        }
                    }
                } else {
                    None
                };
                self.shared.set_native_input_route(input_route.clone());
                let (display_route, video_feedback) =
                    if accepted && (key.host_view_authorized || key.controller_view_authorized) {
                        match NativeDisplayRoute::attach(
                            &self.shared,
                            &mut established.session.channels,
                            &key,
                            self.view.generation,
                        ) {
                            Ok((route, worker)) => (Some(route), Some(worker)),
                            Err(_) => {
                                let _ = control.stop(StopReason::PlatformChanged);
                                (None, None)
                            }
                        }
                    } else {
                        (None, None)
                    };
                self.shared.set_native_display_route(display_route);
                self.native_session_key = Some(key.clone());
                self.native_session_control = Some(control);
                self.native_recovery = None;
                let stop_key = key.clone();
                let audio_owner_store = self.shared.clone();
                self.native_session_task = Some(tokio::spawn(async move {
                    let endpoint = established.endpoint;
                    let recovery_context = established.recovery;
                    let mut session = established.session;
                    let (endpoint, stopped) =
                        retain_owner_until_stopped(endpoint, session.channels.wait_stopped()).await;
                    // Keep the decoder owner alive until the transport's
                    // actual stop receipt; its presentation handle is inert
                    // after lease stop. Thread cleanup runs off the actor.
                    let video_attached = video_receiver.is_some() || video_feedback.is_some();
                    let stop_reason = stopped
                        .as_ref()
                        .map_or(StopReason::ExplicitExit, |report| report.reason);
                    let audio_attached = audio_route.is_some();
                    let audio_shutdown = if let Some(route) = audio_route.as_ref() {
                        let outcome = route.shutdown(stop_reason).await;
                        if outcome.owner_pending {
                            audio_owner_store.retain_native_audio_owner(route.clone());
                        }
                        outcome
                    } else {
                        Default::default()
                    };
                    let clipboard_attached = clipboard_route.is_some();
                    let clipboard_shutdown = if let Some(route) = clipboard_route.as_ref() {
                        let outcome = route.shutdown(stop_reason).await;
                        if outcome.owner_pending {
                            audio_owner_store.retain_native_clipboard_owner(route.clone());
                        }
                        outcome
                    } else {
                        Default::default()
                    };
                    let files_attached = files_route.is_some();
                    let files_shutdown = if let Some(route) = files_route.as_ref() {
                        let outcome = route.shutdown(stop_reason).await;
                        if outcome.owner_pending {
                            audio_owner_store.retain_native_files_owner(route.clone());
                        }
                        outcome
                    } else {
                        Default::default()
                    };
                    let input_cleanup_failed = if let Some(route) = input_route {
                        route.shutdown().await.is_err()
                    } else {
                        false
                    };
                    let (mut video_cleanup_failed, mut video_worker_failed) =
                        if let Some(mut receiver) = video_receiver {
                            tokio::task::spawn_blocking(move || {
                                let outcome = receiver.shutdown(stop_reason);
                                let status = receiver.monitor().status();
                                let cleanup_failed = !matches!(
                                    outcome,
                                    Ok(nestlink_media_session::ShutdownReport::Joined)
                                ) || status.cleanup_timed_out
                                    || !status.finished;
                                (cleanup_failed, status.error.is_some())
                            })
                            .await
                            .unwrap_or((true, true))
                        } else {
                            (false, false)
                        };
                    if let Some(mut feedback) = video_feedback {
                        match tokio::time::timeout(Duration::from_millis(250), &mut feedback).await
                        {
                            Ok(Ok(Ok(()))) => {}
                            Ok(_) => video_worker_failed = true,
                            Err(_) => {
                                video_cleanup_failed = true;
                                feedback.abort();
                                let _ = feedback.await;
                            }
                        }
                    }
                    match stopped {
                        Ok(report) => {
                            let transport_cleanup = map_report_cleanup(report.cleanup);
                            let cleanup = if video_cleanup_failed
                                || input_cleanup_failed
                                || audio_shutdown.cleanup_failed
                                || clipboard_shutdown.cleanup_failed
                                || files_shutdown.cleanup_failed
                            {
                                NativeSessionCleanup::Failed
                            } else if (video_attached
                                || audio_attached
                                || clipboard_attached
                                || files_attached)
                                && transport_cleanup == NativeSessionCleanup::NotAttached
                            {
                                NativeSessionCleanup::Succeeded
                            } else {
                                transport_cleanup
                            };
                            let effects = report.effects;
                            let failure = (cleanup == NativeSessionCleanup::Failed
                                || video_worker_failed
                                || audio_shutdown.worker_failed
                                || clipboard_shutdown.worker_failed
                                || files_shutdown.worker_failed)
                                .then(|| Failure::local(FailureKind::NativeSessionUnavailable));
                            let mut stopped = NativeSessionStop {
                                key: stop_key,
                                stop_reason: Some(map_stop_reason(report.reason)),
                                stop_effects: Some(map_report_effects(
                                    effects.cancel_channels,
                                    effects.release_inputs,
                                    effects.discard_queues,
                                    effects.close_allocations,
                                )),
                                cleanup: Some(cleanup),
                                failure,
                                recovery: None,
                            };
                            stopped.recovery = native_recovery::retain_source(
                                session,
                                endpoint,
                                recovery_context,
                                &stopped,
                                audio_shutdown.owner_pending
                                    || clipboard_shutdown.owner_pending
                                    || files_shutdown.owner_pending,
                            );
                            stopped
                        }
                        Err(_) => NativeSessionStop {
                            key: stop_key,
                            stop_reason: None,
                            stop_effects: None,
                            cleanup: Some(NativeSessionCleanup::Failed),
                            failure: Some(Failure::local(FailureKind::NativeSessionUnavailable)),
                            recovery: None,
                        },
                    }
                }));
                self.view.native_session = crate::Section {
                    data: Some(Arc::new(NativeSessionView {
                        request_id: key.request_id.clone(),
                        connection_generation: key.connection_generation,
                        lease_sequence: key.lease_sequence,
                        status: if accepted {
                            NativeSessionStatus::Connected
                        } else {
                            NativeSessionStatus::Stopping
                        },
                        host_view_authorized: accepted && key.host_view_authorized,
                        path: Some(key.path),
                        stop_reason: None,
                        stop_effects: None,
                        cleanup: None,
                        failure: None,
                    })),
                    loading: None,
                    error: None,
                };
                if accepted {
                    self.local_stop_reason = None;
                    self.native_poll_deadline =
                        Some(tokio::time::Instant::now() + NATIVE_PERMIT_POLL_INTERVAL);
                } else {
                    let reason = if cancelled.is_some() {
                        StopReason::ExplicitExit
                    } else {
                        self.local_stop_reason
                            .map(to_stop_reason)
                            .unwrap_or(StopReason::ExplicitExit)
                    };
                    self.local_stop_reason = Some(if cancelled.is_some() {
                        NativeSessionStopReason::UserCancelled
                    } else {
                        map_stop_reason(reason)
                    });
                    let _ = self.request_native_stop(reason, None);
                }
                let failure = if deadline_expired && current {
                    Some(Failure::local(FailureKind::PermitExpired))
                } else if cancelled.is_some() && current {
                    Some(Failure::local(FailureKind::NativeSessionCancelled))
                } else {
                    None
                };
                let status = cancelled.unwrap_or(if !current {
                    OperationStatus::Superseded
                } else if deadline_expired {
                    OperationStatus::Failed
                } else if failure.is_some() {
                    OperationStatus::Cancelled
                } else {
                    OperationStatus::Succeeded
                });
                if let Some(envelope) = envelope {
                    self.deliver(
                        envelope,
                        status,
                        RemoteEffect::None,
                        if current { failure } else { None },
                        PublicOutput::None,
                        None,
                    );
                }
            }
            Err(mut failure) => {
                self.shared.clear_native_video_route();
                self.shared.set_native_audio_route(None);
                self.shared.set_native_clipboard_route(None);
                self.shared.set_native_files_route(None);
                let cancelled_by_fence = cancelled.is_some() || !current;
                if cancelled_by_fence {
                    failure = Failure::local(FailureKind::NativeSessionCancelled);
                }
                let status = cancelled.unwrap_or(if !current {
                    OperationStatus::Superseded
                } else {
                    OperationStatus::Failed
                });
                let stop_reason = if cancelled.is_some() {
                    Some(NativeSessionStopReason::UserCancelled)
                } else {
                    failure_stop_reason(&failure)
                };
                let generation = expected_connection_generation.unwrap_or(0);
                let previous = self.view.native_session.data.as_ref();
                self.view.native_session = crate::Section {
                    data: Some(Arc::new(NativeSessionView {
                        request_id: request_id.clone(),
                        connection_generation: generation,
                        lease_sequence: previous.map_or(0, |session| session.lease_sequence),
                        status: if cancelled.is_some() {
                            NativeSessionStatus::Stopped
                        } else {
                            NativeSessionStatus::Failed
                        },
                        host_view_authorized: false,
                        path: None,
                        stop_reason,
                        stop_effects: None,
                        cleanup: None,
                        failure: Some(failure.clone()),
                    })),
                    loading: None,
                    error: Some(failure.clone()),
                };
                self.native_session_key = None;
                self.native_session_control = None;
                self.native_poll_deadline = None;
                if current && cancelled.is_none() {
                    self.local_stop_reason = None;
                }
                if let Some(envelope) = envelope {
                    self.deliver(
                        envelope,
                        status,
                        RemoteEffect::None,
                        if current { Some(failure) } else { None },
                        PublicOutput::None,
                        None,
                    );
                }
            }
        }
        self.publish();
    }
    fn complete_native_poll(
        &mut self,
        active: Active,
        client: Client,
        key: NativeSessionKey,
        result: NativePermitState,
    ) {
        let current = self.view.lifecycle == Lifecycle::Running
            && self.view.generation == self.shared.generation.load(Ordering::Acquire);
        let same_session = self.native_session_key.as_ref() == Some(&key)
            || self
                .native_recovery
                .as_ref()
                .is_some_and(|source| source.key == key);
        self.sdk = Some(client);
        if !current {
            self.retire = true;
        } else if same_session && active.cancelled.is_none() {
            match result {
                NativePermitState::Current => {
                    self.native_poll_deadline =
                        Some(tokio::time::Instant::now() + NATIVE_PERMIT_POLL_INTERVAL);
                }
                NativePermitState::Retry => {
                    self.native_poll_deadline =
                        Some(tokio::time::Instant::now() + NATIVE_PERMIT_POLL_INTERVAL);
                }
                NativePermitState::Revoked => {
                    let _ = self.request_native_stop(
                        StopReason::Revoked,
                        Some((&key.request_id, key.connection_generation)),
                    );
                }
                NativePermitState::Expired => {
                    let _ = self.request_native_stop(
                        StopReason::Expired,
                        Some((&key.request_id, key.connection_generation)),
                    );
                }
            }
        }
        self.publish();
    }
}
async fn establish_native_session(
    client: &Client,
    identity: &DeviceIdentity,
    config: &NativeSessionConfig,
    request_id: &str,
    expected_connection_generation: Option<u64>,
    fence: sdk_call::DispatchFence,
) -> Result<EstablishedNativeSession, Failure> {
    fence.check()?;
    let remote = client.sdk.remote(request_id).await.map_err(Failure::from)?;
    fence.check()?;
    if remote.id != request_id
        || remote.status != "approved"
        || remote.connection_generation == 0
        || remote.lease_sequence == 0
        || expected_connection_generation
            .is_some_and(|expected| expected != remote.connection_generation)
        || remote.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
    {
        return Err(Failure::local(FailureKind::NativeSessionUnavailable));
    }
    let is_controller = remote.controller_device_id == identity.device_id;
    let is_host = remote.host_device_id == identity.device_id;
    if is_controller == is_host {
        return Err(Failure::local(FailureKind::Trust));
    }
    let permit = if is_controller {
        client.sdk.permit(request_id).await
    } else {
        client.sdk.host_permit(identity, request_id).await
    }
    .map_err(Failure::from)?;
    fence.check()?;
    let (mut key, options) =
        native_recovery::authorize_native_session(client, identity, config, &remote, &permit)?;
    let peer_key = client
        .sdk
        .remote_peer_key(&permit, identity)
        .await
        .map_err(Failure::from)?;
    fence.check()?;
    let config = if options
        .local_paths
        .contains(nestlink_protocol::Path::Direct)
    {
        config
            .clone()
            .resolve_deployment_stun(&client.sdk)
            .await
            .map_err(Failure::from)?
    } else {
        config.clone()
    };
    fence.check()?;
    let address_policy = config
        .address_policy()
        .map_err(|_| Failure::local(FailureKind::NativeSessionUnavailable))?;
    let endpoint = if config.bind_address == std::net::SocketAddr::from(([0, 0, 0, 0], 0)) {
        NativeEndpoint::new_dual_stack_monitored(
            identity,
            &peer_key,
            permit,
            config.stun_servers.clone(),
            address_policy,
            config.network(),
        )
    } else {
        NativeEndpoint::new_monitored(
            config.bind_address,
            identity,
            &peer_key,
            permit,
            config.stun_servers.clone(),
            address_policy,
            config.network(),
        )
    }
    .map_err(map_dial_failure)?;
    let core_generation = fence.expected;
    let result =
        native_recovery::prove_endpoint(client, identity, &config, &endpoint, options, fence, None)
            .await?;
    key.path = result.candidate.path() as i32;
    Ok(EstablishedNativeSession {
        session: result,
        key,
        endpoint: Box::new(endpoint),
        recovery: NativeRecoveryContext {
            config,
            peer_key,
            core_generation,
            server: client.server.clone(),
            deadline: None,
        },
    })
}
async fn wait_for_fence_invalidation(fence: sdk_call::DispatchFence) {
    loop {
        if fence.check().is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn poll_native_permit(
    client: &Client,
    identity: &DeviceIdentity,
    key: &NativeSessionKey,
    fence: &sdk_call::DispatchFence,
) -> NativePermitState {
    if fence.check().is_err() {
        return NativePermitState::Revoked;
    }
    let remote = match client.sdk.remote(&key.request_id).await {
        Ok(remote) => remote,
        Err(error) => return classify_permit_poll_error(Failure::from(error)),
    };
    if fence.check().is_err() {
        return NativePermitState::Revoked;
    }
    if remote.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX) || remote.status == "expired"
    {
        return NativePermitState::Expired;
    }
    if remote.status != "approved"
        || remote.connection_generation != key.connection_generation
        || remote.lease_sequence != key.lease_sequence
    {
        return NativePermitState::Revoked;
    }
    let permit = if identity.device_id == remote.controller_device_id {
        client.sdk.permit(&key.request_id).await
    } else if identity.device_id == remote.host_device_id {
        client.sdk.host_permit(identity, &key.request_id).await
    } else {
        return NativePermitState::Revoked;
    };
    let permit = match permit {
        Ok(permit) => permit,
        Err(error) => return classify_permit_poll_error(Failure::from(error)),
    };
    if fence.check().is_err() {
        return NativePermitState::Revoked;
    }
    let claims = permit.claims();
    if claims.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX) {
        NativePermitState::Expired
    } else if claims.session_id == key.request_id
        && claims.connection_generation == key.connection_generation
        && claims.lease_sequence == key.lease_sequence
        && remote.connection_generation == key.connection_generation
        && remote.lease_sequence == key.lease_sequence
        && claims.permissions == remote.permissions
        && claims.paths == remote.paths
    {
        NativePermitState::Current
    } else {
        NativePermitState::Revoked
    }
}
fn classify_permit_poll_error(failure: Failure) -> NativePermitState {
    if matches!(failure.kind, FailureKind::Transport | FailureKind::Timeout) {
        NativePermitState::Retry
    } else {
        NativePermitState::Revoked
    }
}
fn unix_millis() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}
fn map_dial_failure(error: DialError) -> Failure {
    match error {
        DialError::NetworkChanged => Failure::local(FailureKind::NetworkChanged),
        DialError::Expired => Failure::local(FailureKind::PermitExpired),
        DialError::Cancelled => Failure::local(FailureKind::NativeSessionCancelled),
        DialError::Failed { .. } => Failure::local(FailureKind::Transport),
        DialError::Binding | DialError::Setup | DialError::Contract(_) => {
            Failure::local(FailureKind::NativeSessionUnavailable)
        }
    }
}
fn map_establish_failure(error: SessionEstablishError) -> Failure {
    match error {
        SessionEstablishError::Sdk(error) => Failure::from(error),
        SessionEstablishError::Dial(error) => map_dial_failure(error),
        SessionEstablishError::PermitChanged => Failure::local(FailureKind::Trust),
        SessionEstablishError::Cancelled => Failure::local(FailureKind::NativeSessionCancelled),
        SessionEstablishError::Binding | SessionEstablishError::NoCandidates => {
            Failure::local(FailureKind::NativeSessionUnavailable)
        }
        SessionEstablishError::RelayOnlyUnsupported => {
            Failure::local(FailureKind::NativeSessionUnavailable)
        }
        SessionEstablishError::SignalTimeout => Failure::local(FailureKind::Timeout),
        SessionEstablishError::Remote(_) | SessionEstablishError::Contract(_) => {
            Failure::local(FailureKind::NativeSessionUnavailable)
        }
    }
}
fn map_stop_reason(reason: StopReason) -> NativeSessionStopReason {
    match reason {
        StopReason::Revoked => NativeSessionStopReason::Revoked,
        StopReason::Expired => NativeSessionStopReason::Expired,
        StopReason::TransportLost => NativeSessionStopReason::TransportLost,
        StopReason::ProtocolViolation => NativeSessionStopReason::ProtocolViolation,
        StopReason::NetworkChanged => NativeSessionStopReason::NetworkChanged,
        StopReason::PlatformChanged => NativeSessionStopReason::PlatformChanged,
        StopReason::Suspended => NativeSessionStopReason::Suspended,
        StopReason::ClockInvalid => NativeSessionStopReason::ClockInvalid,
        StopReason::ExplicitExit => NativeSessionStopReason::ExplicitExit,
    }
}
fn to_stop_reason(reason: NativeSessionStopReason) -> StopReason {
    match reason {
        NativeSessionStopReason::Revoked => StopReason::Revoked,
        NativeSessionStopReason::Expired => StopReason::Expired,
        NativeSessionStopReason::TransportLost => StopReason::TransportLost,
        NativeSessionStopReason::ProtocolViolation => StopReason::ProtocolViolation,
        NativeSessionStopReason::NetworkChanged => StopReason::NetworkChanged,
        NativeSessionStopReason::PlatformChanged => StopReason::PlatformChanged,
        NativeSessionStopReason::Suspended => StopReason::Suspended,
        NativeSessionStopReason::ClockInvalid => StopReason::ClockInvalid,
        NativeSessionStopReason::UserCancelled | NativeSessionStopReason::ExplicitExit => {
            StopReason::ExplicitExit
        }
    }
}
fn failure_stop_reason(failure: &Failure) -> Option<NativeSessionStopReason> {
    match failure.kind {
        FailureKind::NetworkChanged => Some(NativeSessionStopReason::NetworkChanged),
        FailureKind::PermitExpired => Some(NativeSessionStopReason::Expired),
        FailureKind::NativeSessionCancelled => Some(NativeSessionStopReason::UserCancelled),
        _ => None,
    }
}
fn map_report_cleanup(cleanup: CleanupStatus) -> NativeSessionCleanup {
    match cleanup {
        CleanupStatus::NotAttached => NativeSessionCleanup::NotAttached,
        CleanupStatus::Succeeded => NativeSessionCleanup::Succeeded,
        CleanupStatus::Failed(_) => NativeSessionCleanup::Failed,
    }
}

fn browser_host_cleanup(
    report: Option<StopReport>,
    cleanup_failed: bool,
) -> Option<NativeSessionCleanup> {
    if cleanup_failed {
        Some(NativeSessionCleanup::Failed)
    } else {
        report.map(|report| map_report_cleanup(report.cleanup))
    }
}
fn map_report_effects(
    cancel_channels: bool,
    release_inputs: bool,
    discard_queues: bool,
    close_allocations: bool,
) -> NativeSessionEffects {
    NativeSessionEffects {
        cancel_channels,
        release_inputs,
        discard_queues,
        close_allocations,
    }
}

fn browser_host_data_binding_for(
    snapshot: &Snapshot,
    generation: u64,
) -> Option<BrowserHostBinding> {
    if snapshot.generation != generation {
        return None;
    }
    let host = snapshot.browser_host.data.as_ref()?;
    if host.status != BrowserHostStatus::Connected || !host.host_view_authorized {
        return None;
    }
    let binding = host.binding.as_ref()?;
    if binding.request_id != host.request_id
        || binding.connection_generation != host.connection_generation
    {
        return None;
    }
    Some(binding.clone())
}

fn browser_host_data_binding_matches(
    snapshot: &Snapshot,
    generation: u64,
    binding: &BrowserHostBinding,
) -> bool {
    browser_host_data_binding_for(snapshot, generation).as_ref() == Some(binding)
}

fn valid_browser_host_display_selection(
    snapshot: &Snapshot,
    generation: u64,
    binding: &BrowserHostBinding,
    catalog: &DisplayCatalogKey,
    sources: &[u32],
    initial_source: u32,
) -> bool {
    if snapshot.generation != generation || sources.is_empty() {
        return false;
    }
    let Some(host) = snapshot.browser_host.data.as_ref() else {
        return false;
    };
    let display = &host.displays;
    if host.status != BrowserHostStatus::Establishing
        || host.binding.as_ref() != Some(binding)
        || !display.approval_required
        || display.catalog.as_ref() != Some(catalog)
        || catalog.request_id != binding.request_id
        || catalog.connection_generation != binding.connection_generation
        || sources.windows(2).any(|pair| pair[0] >= pair[1])
        || sources.len() > display.displays.len()
        || !sources.contains(&initial_source)
    {
        return false;
    }
    let Ok(expected) = nestlink_protocol::native_displays::catalog_key(
        &catalog.request_id,
        catalog.connection_generation,
        catalog.revision,
        &display.displays,
    ) else {
        return false;
    };
    if expected != *catalog {
        return false;
    }
    if sources.iter().any(|source| {
        !display
            .displays
            .iter()
            .any(|candidate| candidate.source == *source)
    }) {
        return false;
    }
    let selected: Vec<_> = display
        .displays
        .iter()
        .filter(|candidate| sources.contains(&candidate.source))
        .cloned()
        .collect();
    nestlink_protocol::native_displays::validate_displays(&selected).is_ok()
}

fn valid_browser_host_data_update(
    current: &BrowserHostDataView,
    next: &BrowserHostDataView,
) -> bool {
    let valid_roots = |roots: &[crate::BrowserHostFileRootView], maximum: u64| {
        roots.len() as u64 <= maximum
            && roots.iter().all(|root| {
                nestlink_protocol::valid_id(&root.root_id)
                    && !root.display_name.is_empty()
                    && root.display_name.trim() == root.display_name
                    && root.display_name.len() as u64
                        <= nestlink_protocol::FILE_ROOT_DISPLAY_NAME_BYTES
                    && !root.display_name.chars().any(|character| {
                        character.is_control() || matches!(character, '/' | '\\' | ':')
                    })
            })
            && roots
                .iter()
                .map(|root| root.root_id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len()
                == roots.len()
    };
    let removed_clipboard_direction = (current.local_clipboard_read && !next.local_clipboard_read)
        || (current.local_clipboard_write && !next.local_clipboard_write);
    let clipboard_restart_valid = if current.clipboard_restart_required {
        next.clipboard_restart_required
            && (!next.local_clipboard_read || current.local_clipboard_read)
            && (!next.local_clipboard_write || current.local_clipboard_write)
    } else {
        next.clipboard_restart_required == removed_clipboard_direction
    };
    next.files_available == current.files_available
        && next.clipboard_available == current.clipboard_available
        && next.permitted_file_read == current.permitted_file_read
        && next.permitted_file_write == current.permitted_file_write
        && next.permitted_clipboard_read == current.permitted_clipboard_read
        && next.permitted_clipboard_write == current.permitted_clipboard_write
        && (!next.local_file_read || (next.files_available && next.permitted_file_read))
        && (!next.local_file_write || (next.files_available && next.permitted_file_write))
        && next.local_file_read != next.read_roots.is_empty()
        && next.local_file_write != next.write_roots.is_empty()
        && (!next.local_clipboard_read
            || (next.clipboard_available && next.permitted_clipboard_read))
        && (!next.local_clipboard_write
            || (next.clipboard_available && next.permitted_clipboard_write))
        && valid_roots(&next.read_roots, nestlink_protocol::FILE_READ_ROOTS)
        && valid_roots(&next.write_roots, nestlink_protocol::FILE_WRITE_ROOTS)
        && next.read_roots.iter().all(|root| {
            !next
                .write_roots
                .iter()
                .any(|other| other.root_id == root.root_id)
        })
        && clipboard_restart_valid
}

#[cfg(test)]
mod browser_host_data_contract_tests {
    use super::*;
    use std::sync::Arc;

    fn browser_binding() -> BrowserHostBinding {
        BrowserHostBinding {
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            session_id: "00000000-0000-4000-8000-000000000002".into(),
            controller_device_id: "controller".into(),
            host_device_id: "host".into(),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [3; 32],
            connection_generation: 7,
        }
    }

    fn connected_browser_snapshot(binding: BrowserHostBinding) -> Snapshot {
        let mut snapshot = Snapshot::default();
        snapshot.browser_host.data = Some(Arc::new(BrowserHostView {
            request_id: binding.request_id.clone(),
            connection_generation: binding.connection_generation,
            lease_sequence: 4,
            status: BrowserHostStatus::Connected,
            host_view_authorized: true,
            binding: Some(binding),
            displays: crate::BrowserHostDisplayView::default(),
            data: BrowserHostDataView::default(),
            path: Some(1),
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }));
        snapshot
    }

    fn initial() -> BrowserHostDataView {
        BrowserHostDataView {
            files_available: true,
            clipboard_available: true,
            permitted_file_read: true,
            permitted_file_write: true,
            permitted_clipboard_read: true,
            permitted_clipboard_write: true,
            ..BrowserHostDataView::default()
        }
    }

    #[test]
    fn browser_data_updates_keep_remote_permit_fixed_and_roots_name_only() {
        let current = initial();
        let mut selected = current.clone();
        selected.local_file_read = true;
        selected.read_roots.push(crate::BrowserHostFileRootView {
            root_id: "e7e58d38-16bf-4b95-9b9e-04360c4d5a41".into(),
            display_name: "Documents".into(),
        });
        assert!(valid_browser_host_data_update(&current, &selected));

        let mut widened = selected.clone();
        widened.permitted_clipboard_write = false;
        assert!(!valid_browser_host_data_update(&current, &widened));

        let mut unsafe_label = selected;
        unsafe_label.read_roots[0].display_name = "C:\\Users\\me".into();
        assert!(!valid_browser_host_data_update(&current, &unsafe_label));
    }

    #[test]
    fn browser_clipboard_direction_cannot_be_reenabled_after_local_revocation() {
        let mut current = initial();
        current.local_clipboard_read = true;
        let mut revoked = current.clone();
        revoked.local_clipboard_read = false;
        revoked.clipboard_restart_required = true;
        assert!(valid_browser_host_data_update(&current, &revoked));

        revoked.local_clipboard_read = true;
        assert!(!valid_browser_host_data_update(
            &BrowserHostDataView {
                local_clipboard_read: false,
                clipboard_restart_required: true,
                ..current
            },
            &revoked
        ));
    }

    #[test]
    fn browser_data_binding_is_exact_and_fenced_by_core_generation() {
        let binding = browser_binding();
        let snapshot = connected_browser_snapshot(binding.clone());

        assert_eq!(
            browser_host_data_binding_for(&snapshot, 1),
            Some(binding.clone())
        );
        assert!(browser_host_data_binding_matches(&snapshot, 1, &binding));
        assert_eq!(browser_host_data_binding_for(&snapshot, 2), None);

        let mut stale_binding = binding.clone();
        stale_binding.permit_sha256[0] ^= 1;
        assert!(!browser_host_data_binding_matches(
            &snapshot,
            1,
            &stale_binding
        ));
        let mut stale_session = binding.clone();
        stale_session.session_id.push_str("-other");
        assert!(!browser_host_data_binding_matches(
            &snapshot,
            1,
            &stale_session
        ));
    }

    #[test]
    fn native_session_binding_never_satisfies_browser_data_lookup() {
        let mut snapshot = Snapshot::default();
        snapshot.native_session.data = Some(Arc::new(NativeSessionView {
            request_id: "00000000-0000-4000-8000-000000000003".into(),
            connection_generation: 7,
            lease_sequence: 4,
            status: NativeSessionStatus::Connected,
            host_view_authorized: true,
            path: Some(1),
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }));

        assert_eq!(browser_host_data_binding_for(&snapshot, 1), None);
        assert!(!browser_host_data_binding_matches(
            &snapshot,
            1,
            &browser_binding()
        ));
    }
}

fn browser_host_failure(failure: BrowserHostFailure) -> Failure {
    let kind = match failure {
        BrowserHostFailure::Cancelled => FailureKind::NativeSessionCancelled,
        BrowserHostFailure::UnsupportedPermission => FailureKind::Invalid,
        BrowserHostFailure::Rejected => FailureKind::Trust,
        BrowserHostFailure::Transport => FailureKind::Transport,
        BrowserHostFailure::Capture | BrowserHostFailure::Unavailable => {
            FailureKind::NativeSessionUnavailable
        }
    };
    Failure::local(kind)
}
fn browser_host_stop_reason(failure: BrowserHostFailure) -> NativeSessionStopReason {
    match failure {
        BrowserHostFailure::Cancelled => NativeSessionStopReason::UserCancelled,
        BrowserHostFailure::Capture => NativeSessionStopReason::PlatformChanged,
        BrowserHostFailure::Transport => NativeSessionStopReason::TransportLost,
        BrowserHostFailure::Rejected | BrowserHostFailure::UnsupportedPermission => {
            NativeSessionStopReason::ProtocolViolation
        }
        BrowserHostFailure::Unavailable => NativeSessionStopReason::ExplicitExit,
    }
}
async fn next_browser_host_event(
    host: &mut Option<BrowserHostRuntime>,
) -> Option<BrowserHostEvent> {
    match host {
        Some(host) => host.events.recv().await,
        None => std::future::pending().await,
    }
}
async fn next_service_host_cleanup(owner: &mut Option<ServiceHostOwner>) -> ServiceHostWait {
    match owner {
        Some(owner) if owner.cleanup_requested || owner.runtime.cleanup_pending() => {
            owner.runtime.wait_stopped(SERVICE_HOST_CLEANUP_POLL).await
        }
        Some(_) | None => std::future::pending().await,
    }
}
async fn next_native_session(
    task: &mut Option<JoinHandle<NativeSessionStop>>,
) -> Result<NativeSessionStop, JoinError> {
    match task {
        Some(task) => (&mut *task).await,
        None => std::future::pending().await,
    }
}
async fn retain_owner_until_stopped<Owner, Stopped>(
    owner: Owner,
    stopped: Stopped,
) -> (Owner, Stopped::Output)
where
    Stopped: Future,
{
    let result = stopped.await;
    (owner, result)
}
async fn next_job(active: &mut Option<Active>) -> Job {
    match active {
        Some(active) => active.future.as_mut().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn browser_host_display_approval_fixture() -> (Snapshot, BrowserHostBinding, DisplayCatalogKey)
    {
        let binding = BrowserHostBinding {
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            session_id: "00000000-0000-4000-8000-000000000002".into(),
            controller_device_id: "controller-device".into(),
            host_device_id: "host-device".into(),
            controller_key_sha256: [0x31; 32],
            host_key_sha256: [0x82; 32],
            permit_sha256: [0xA7; 32],
            connection_generation: 9,
        };
        let displays = vec![
            DisplayDescriptor {
                source: 3,
                left: 0,
                top: 0,
                width: 640,
                height: 360,
                label: "Display 3".into(),
            },
            DisplayDescriptor {
                source: 8,
                left: -640,
                top: 0,
                width: 640,
                height: 360,
                label: "Display 8".into(),
            },
        ];
        let catalog = nestlink_protocol::native_displays::catalog_key(
            &binding.request_id,
            binding.connection_generation,
            4,
            &displays,
        )
        .unwrap();
        let mut snapshot = Snapshot {
            generation: 12,
            ..Snapshot::default()
        };
        snapshot.browser_host.data = Some(Arc::new(BrowserHostView {
            request_id: binding.request_id.clone(),
            connection_generation: binding.connection_generation,
            lease_sequence: 1,
            status: BrowserHostStatus::Establishing,
            // The host has View authority, but the fresh display offer still
            // requires a separate local display approval.
            host_view_authorized: true,
            binding: Some(binding.clone()),
            displays: crate::BrowserHostDisplayView {
                catalog: Some(catalog.clone()),
                displays,
                approval_required: true,
                approved_sources: Vec::new(),
                initial_source: None,
            },
            data: BrowserHostDataView::default(),
            path: None,
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }));
        (snapshot, binding, catalog)
    }

    #[test]
    fn browser_host_display_approval_rejects_stale_generation_catalog_and_binding() {
        let (snapshot, binding, catalog) = browser_host_display_approval_fixture();
        let approved = [8];
        assert!(valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation,
            &binding,
            &catalog,
            &approved,
            8,
        ));

        assert!(!valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation + 1,
            &binding,
            &catalog,
            &approved,
            8,
        ));
        let mut stale_snapshot = snapshot.clone();
        stale_snapshot.generation += 1;
        assert!(!valid_browser_host_display_selection(
            &stale_snapshot,
            snapshot.generation,
            &binding,
            &catalog,
            &approved,
            8,
        ));

        let mut stale_catalog = catalog.clone();
        stale_catalog.revision -= 1;
        assert!(!valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation,
            &binding,
            &stale_catalog,
            &approved,
            8,
        ));
        let mut wrong_catalog_generation = catalog.clone();
        wrong_catalog_generation.connection_generation += 1;
        assert!(!valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation,
            &binding,
            &wrong_catalog_generation,
            &approved,
            8,
        ));

        let mut wrong_binding = binding.clone();
        wrong_binding.permit_sha256[0] ^= 1;
        assert!(!valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation,
            &wrong_binding,
            &catalog,
            &approved,
            8,
        ));
    }

    #[test]
    fn browser_host_display_approval_rejects_unapproved_and_invalid_sources() {
        let (snapshot, binding, catalog) = browser_host_display_approval_fixture();
        let approve = |sources: &[u32], initial| {
            valid_browser_host_display_selection(
                &snapshot,
                snapshot.generation,
                &binding,
                &catalog,
                sources,
                initial,
            )
        };

        assert!(approve(&[3, 8], 8));
        assert!(!approve(&[], 3));
        assert!(!approve(&[3, 99], 3));
        assert!(!approve(&[3], 8));
        assert!(!approve(&[3, 8], 99));
        assert!(!approve(&[3, 3], 3));
        assert!(!approve(&[8, 3], 8));
    }

    #[test]
    fn browser_host_view_authority_does_not_approve_a_screen_by_itself() {
        let (snapshot, binding, catalog) = browser_host_display_approval_fixture();
        let host = snapshot.browser_host.data.as_ref().unwrap();
        assert!(host.host_view_authorized);
        assert!(host.displays.approval_required);
        assert!(host.displays.approved_sources.is_empty());

        assert!(!valid_browser_host_display_selection(
            &snapshot,
            snapshot.generation,
            &binding,
            &catalog,
            &[],
            3,
        ));
    }

    #[test]
    fn browser_data_worker_cleanup_failure_overrides_successful_session_cleanup() {
        let stop = StopReport {
            reason: StopReason::Revoked,
            effects: nestlink_session::StopEffects {
                cancel_channels: true,
                release_inputs: true,
                discard_queues: true,
                close_allocations: true,
            },
            cleanup: CleanupStatus::Succeeded,
        };
        let close = nestlink_sdk::webrtc_host::WebRtcHostCloseReport {
            stop: Some(stop),
            lease_stop_failed: false,
            peer_close_failed: false,
            input_worker_cleanup_failed: false,
            data_worker_cleanup_failed: true,
        };

        assert!(close.cleanup_failed());
        assert_eq!(
            browser_host_cleanup(close.stop, close.cleanup_failed()),
            Some(NativeSessionCleanup::Failed)
        );
        assert_eq!(
            close.stop.map(|report| map_stop_reason(report.reason)),
            Some(NativeSessionStopReason::Revoked)
        );
    }

    #[test]
    fn native_feedback_is_idempotent_bound_and_cannot_reset_on_resize() {
        let now = Instant::now();
        let binding = NativeVideoBinding {
            source: 0,
            width: 64,
            height: 48,
            layout_epoch: 3,
        };
        let mut cursor = NativeVideoCursor::default();
        cursor.bind(binding, false).unwrap();
        cursor.reserve(1).unwrap();
        cursor.keyframe_pending = false;
        cursor.last_keyframe = Some(now);
        let request = NativeVideoFeedback {
            schema_version: SCHEMA_VERSION,
            connection_generation: 7,
            layout_epoch: 3,
            source: 0,
            request_sequence: 1,
            last_sequence: 1,
            reason: nestlink_protocol::VideoRecoveryReason::DecoderFailure as i32,
        };
        cursor.feedback(request).unwrap();
        assert!(!cursor.keyframe_needed(now));
        assert!(cursor.keyframe_needed(now + Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS)));
        cursor.keyframe_pending = false;
        cursor.feedback(request).unwrap();
        assert!(
            !cursor.keyframe_pending,
            "a duplicate cannot force another keyframe"
        );
        for conflicting in [
            NativeVideoFeedback {
                source: 1,
                ..request
            },
            NativeVideoFeedback {
                last_sequence: 2,
                ..request
            },
            NativeVideoFeedback {
                reason: 2,
                ..request
            },
            NativeVideoFeedback {
                request_sequence: 3,
                ..request
            },
        ] {
            assert!(cursor.feedback(conflicting).is_err());
        }
        cursor
            .bind(
                NativeVideoBinding {
                    layout_epoch: 4,
                    ..binding
                },
                false,
            )
            .unwrap();
        assert!(
            !cursor.keyframe_needed(now),
            "resize cannot bypass source throttling"
        );
        assert!(cursor.keyframe_needed(now + Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS)));
        cursor.keyframe_pending = false;
        cursor
            .feedback(NativeVideoFeedback {
                request_sequence: 2,
                ..request
            })
            .unwrap();
        assert!(
            !cursor.keyframe_pending,
            "retired layout feedback cannot revive it"
        );
        assert!(
            cursor
                .feedback(NativeVideoFeedback {
                    layout_epoch: 4,
                    ..request
                })
                .is_err()
        );
        assert_eq!(cursor.sequence, 1);
    }

    #[test]
    fn switching_back_preserves_each_sources_sequence_pts_and_feedback_history() {
        let first = NativeVideoBinding {
            source: 3,
            width: 64,
            height: 48,
            layout_epoch: 1,
        };
        let second = NativeVideoBinding {
            source: 8,
            layout_epoch: 2,
            ..first
        };
        let mut cursor = NativeVideoCursor::default();
        cursor.bind(first, false).unwrap();
        assert_eq!(cursor.reserve(90).unwrap(), 1);
        let request = NativeVideoFeedback {
            schema_version: SCHEMA_VERSION,
            connection_generation: 7,
            layout_epoch: 1,
            source: 3,
            request_sequence: 1,
            last_sequence: 1,
            reason: nestlink_protocol::VideoRecoveryReason::DecoderFailure as i32,
        };
        cursor.feedback(request).unwrap();
        cursor.bind(second, false).unwrap();
        assert_eq!(
            cursor.reserve(45).unwrap(),
            1,
            "PTS/sequence are per source"
        );
        cursor.keyframe_pending = false;
        cursor
            .feedback(NativeVideoFeedback {
                request_sequence: 2,
                ..request
            })
            .unwrap();
        assert!(
            !cursor.keyframe_pending,
            "inactive feedback cannot revive old pixels"
        );
        cursor
            .bind(
                NativeVideoBinding {
                    layout_epoch: 3,
                    ..first
                },
                false,
            )
            .unwrap();
        assert!(cursor.reserve(90).is_err());
        assert_eq!(cursor.reserve(91).unwrap(), 2);
        assert_eq!(cursor.last_feedback.as_ref().unwrap().request_sequence, 2);
        assert!(
            cursor.feedback(request).is_err(),
            "source feedback history cannot reset"
        );
        cursor.keyframe_pending = false;
        cursor
            .feedback(NativeVideoFeedback {
                request_sequence: 3,
                ..request
            })
            .unwrap();
        assert!(!cursor.keyframe_pending);
        cursor
            .bind(
                NativeVideoBinding {
                    layout_epoch: 4,
                    ..second
                },
                false,
            )
            .unwrap();
        assert_eq!(cursor.reserve(46).unwrap(), 2);
    }

    #[test]
    fn feedback_about_a_queued_keyframe_survives_its_send_completion() {
        let binding = NativeVideoBinding {
            source: 0,
            width: 64,
            height: 48,
            layout_epoch: 1,
        };
        let now = Instant::now();
        let mut cursor = NativeVideoCursor::default();
        cursor.bind(binding, false).unwrap();
        cursor.reserve(1).unwrap();
        cursor.keyframe_sent(binding, 1, now);
        assert!(!cursor.keyframe_pending);
        cursor.reserve(2).unwrap();
        cursor
            .feedback(NativeVideoFeedback {
                schema_version: SCHEMA_VERSION,
                connection_generation: 7,
                layout_epoch: 1,
                source: 0,
                request_sequence: 1,
                last_sequence: 2,
                reason: nestlink_protocol::VideoRecoveryReason::DecoderFailure as i32,
            })
            .unwrap();
        cursor.keyframe_sent(binding, 2, now);
        assert!(
            cursor.keyframe_pending,
            "completion must not erase feedback about that frame"
        );
        assert!(!cursor.keyframe_needed(now));
        let later = now + Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS);
        assert!(cursor.keyframe_needed(later));
        cursor.reserve(3).unwrap();
        cursor.keyframe_sent(binding, 3, later);
        assert!(!cursor.keyframe_pending);
    }

    #[test]
    fn native_video_reservations_are_monotonic_and_not_reused_after_cancellation() {
        let mut cursor = NativeVideoCursor::default();

        // A producer can be cancelled after reserving while waiting for the
        // one-frame queue. The next frame must leave that id as a harmless gap.
        assert_eq!(cursor.reserve(90).unwrap(), 1);
        assert!(matches!(cursor.reserve(90), Err(NativeVideoError::Invalid)));
        assert!(matches!(cursor.reserve(89), Err(NativeVideoError::Invalid)));
        assert_eq!(cursor.sequence, 1);
        assert_eq!(cursor.pts_90khz, Some(90));
        assert_eq!(cursor.reserve(91).unwrap(), 2);
        assert_eq!(cursor.sequence, 2);
    }

    #[test]
    fn capture_rebinding_requires_a_paused_source_and_a_new_epoch_without_resetting_ids() {
        let first = NativeVideoBinding {
            source: 1,
            width: 640,
            height: 480,
            layout_epoch: 1,
        };
        let next = NativeVideoBinding {
            width: 480,
            height: 640,
            layout_epoch: 2,
            ..first
        };
        let mut cursor = NativeVideoCursor::default();
        cursor.bind(first, false).unwrap();
        assert_eq!(cursor.reserve(90).unwrap(), 1);
        assert!(cursor.bind(next, true).is_err());
        assert_eq!(cursor.binding, Some(first));
        assert!(cursor.bind(first, false).is_err());
        assert!(
            cursor
                .bind(
                    NativeVideoBinding {
                        width: 480,
                        height: 640,
                        ..first
                    },
                    false
                )
                .is_err()
        );
        cursor.bind(next, false).unwrap();
        assert_eq!(cursor.binding, Some(next));
        assert_eq!(cursor.sequence, 1);
        assert!(cursor.reserve(90).is_err());
        assert_eq!(cursor.reserve(91).unwrap(), 2);
        assert!(cursor.bind(first, false).is_err());
    }

    #[test]
    fn in_flight_video_from_a_paused_source_does_not_revive_when_capture_resumes() {
        let gate = Arc::new(HostVideoGate {
            state: Mutex::new(HostVideoGateState::default()),
        });
        gate.open().unwrap();
        let old = gate.guard();
        assert!(old.check().is_ok());
        gate.pause();
        assert!(old.check().is_err());
        gate.open().unwrap();
        assert!(old.check().is_err());
        let current = gate.guard();
        assert!(current.check().is_ok());
        gate.retire();
        assert!(current.check().is_err());
        assert!(gate.open().is_err());
    }

    struct EndpointOwnerProbe(Option<oneshot::Sender<()>>);

    impl Drop for EndpointOwnerProbe {
        fn drop(&mut self) {
            if let Some(dropped) = self.0.take() {
                let _ = dropped.send(());
            }
        }
    }

    #[tokio::test]
    async fn endpoint_owner_survives_stop_until_recovery_budget_has_been_consumed()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (dropped_sender, mut dropped_receiver) = oneshot::channel();
        let (stop_sender, stop_receiver) = oneshot::channel();
        let stop_task = tokio::spawn(retain_owner_until_stopped(
            EndpointOwnerProbe(Some(dropped_sender)),
            stop_receiver,
        ));

        tokio::task::yield_now().await;
        assert!(matches!(
            dropped_receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        assert!(
            stop_sender.send(()).is_ok(),
            "stop task should still be waiting"
        );
        let (owner, stopped) = stop_task.await?;
        stopped?;
        assert!(matches!(
            dropped_receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        drop(owner);
        dropped_receiver.await?;
        Ok(())
    }
}
