//! Native WebRTC answerer for signed browser offers.
//!
//! The host accepts capability-negotiated cumulative ICE snapshots. It verifies the
//! controller's signed offer through `Sdk::peer_signals`, negotiates only the
//! VP8/Opus profile, and signs the answer and negotiated ICE snapshots through
//! `Sdk::publish_signal`. Media capture must already have been attached to the
//! authorized session's capture controllers before it is passed here.

mod data;
mod input;
mod rate;
mod turn_policy;
pub use data::{HostDataClaims, HostDataFactory, HostDataOwner};
use data::{HostDataRuntime, PendingDataChannel};
use input::{InputPermitResolver, InputPermitWindows};
use rate::RateController;
use turn_policy::{bounded_turn_operation, optional_turn_result};

use super::{DeviceIdentity, Sdk, SdkError, SignalCursor, TurnCredentials};
use bytes::Bytes;
use nestlink_identity::{VerifiedPermit, verify_endpoint_proof};
use nestlink_media_codec::{OpusConfig, OpusEncoder, VideoConfig, Vp8Encoder};
use nestlink_protocol::{
    ContractError, EndpointProofClaims, NativeProof, Path, Permission, SCHEMA_VERSION,
    TurnPeerBindingClaims, TurnPurpose,
    api::{RemoteView, SignalPayload, WebRtcDescription},
    native_displays::{
        DisplayCatalogKey, DisplayDescriptor, DisplayEnvelope, DisplaySelection, catalog_key,
        validate_displays,
    },
    turn::optional_ice_candidate_addresses,
    webrtc::WebRtcInputAction,
    webrtc::{
        MAX_WEBRTC_CONTROL_BYTES, WEBRTC_CONTROL_LABEL, WebRtcControl, WebRtcDisplayControl,
        validate_media_sdp,
    },
    webrtc_data::WebRtcDataChannel,
};
use nestlink_remote::{
    CleanupStatus, LeaseControl, RemoteError, RuntimeClock, SessionSetup, StopReport,
    audio::{AudioBinding, AudioCaptureController, AudioCaptureDevice, CapturedAudio},
    input::{InputAction, InputController, InputDevice, InputEpoch, InputEvent, InputLayout},
    video::{CaptureDevice, CapturedVideo, Display, VideoController, VideoEpoch},
};
use nestlink_session::{EndpointRole, SessionState, StopReason};
use prost::Message;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    runtime::Handle,
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};
use webrtc::{
    Error as WebRtcError,
    api::{
        APIBuilder,
        interceptor_registry::register_default_interceptors,
        media_engine::{MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine},
        setting_engine::SettingEngine,
    },
    data_channel::{
        RTCDataChannel, data_channel_message::DataChannelMessage,
        data_channel_state::RTCDataChannelState,
    },
    ice::{
        candidate::{CandidatePairState, CandidateType},
        mdns::MulticastDnsMode,
    },
    ice_transport::{
        ice_candidate::RTCIceCandidateInit, ice_gathering_state::RTCIceGatheringState,
        ice_server::RTCIceServer,
    },
    interceptor::registry::Registry,
    media::Sample,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        policy::ice_transport_policy::RTCIceTransportPolicy,
        sdp::session_description::RTCSessionDescription,
    },
    rtcp::{
        payload_feedbacks::{
            full_intra_request::FullIntraRequest, picture_loss_indication::PictureLossIndication,
            receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate,
        },
        receiver_report::ReceiverReport,
    },
    rtp_transceiver::{
        RTCPFeedback,
        rtp_codec::{RTCRtpCodecCapability, RTCRtpCodecParameters, RTPCodecType},
    },
    stats::StatsReportType,
    track::track_local::track_local_static_sample::TrackLocalStaticSample,
};

const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SIGNAL_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const ENDPOINT_PROOF_TIMEOUT: Duration = Duration::from_secs(3);
const TURN_RENEWAL_WINDOW: Duration = Duration::from_secs(3);
const TURN_BINDING_MAINTAIN_INTERVAL: Duration = Duration::from_millis(250);
const MAX_PENDING_CONTROL_MESSAGES: usize = 4;
const MAX_PENDING_INPUT_MESSAGES: usize = 64;
const MAX_PENDING_DISPLAY_MESSAGES: usize = 8;
const DISPLAY_SELECTION_ACK_TIMEOUT: Duration = Duration::from_secs(6);
const INPUT_WORKER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(4);
const PATH_AUTHORITY_POLL: Duration = Duration::from_millis(50);
const MAX_VIDEO_FRAME_AGE: Duration = Duration::from_millis(250);
const AUDIO_FRAME_DURATION: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum WebRtcHostError {
    #[error("SDK operation failed: {0}")]
    Sdk(#[from] SdkError),
    #[error("WebRTC negotiation failed: {0}")]
    WebRtc(#[from] WebRtcError),
    #[error("protocol contract failed: {0}")]
    Contract(#[from] ContractError),
    #[error("media or capture failed: {0}")]
    Io(#[from] io::Error),
    #[error("remote session authorization failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("host permit is expired or does not authorize this media session")]
    Permit,
    #[error("browser signal is not a complete VP8/Opus offer for this permit")]
    InvalidOffer,
    #[error("the host can only use a permitted direct ICE path until trusted TURN is configured")]
    DirectPathRequired,
    #[error("host TURN support requires a permit authorizing the relay path")]
    RelayPathRequired,
    #[error("the WebRTC peer is closed or its session has stopped")]
    Closed,
    #[error("the WebRTC peer did not reach an authorized path in time")]
    ConnectTimeout,
    #[error("the peer did not publish a complete ICE answer in time")]
    GatherTimeout,
    #[error("the reliable control DataChannel is not open")]
    ControlChannelUnavailable,
    #[error("the remote endpoint selected a relay ICE candidate pair")]
    RelayPathSelected,
    #[error("the selected ICE path is not authorized by the current signed TURN binding")]
    TurnBinding,
    #[error("the TURN allocation or peer binding is unavailable")]
    RelayUnavailable,
    #[error("the WebRTC peer did not reach an authorized ICE path in time")]
    PathConnectTimeout,
    #[error("the WebRTC endpoint proof did not complete within its budget")]
    EndpointProof,
    #[error("the browser did not acknowledge the display selection within its budget")]
    DisplaySelectionAckTimeout,
    #[error("a required reliable business DataChannel is missing or invalid")]
    BusinessDataChannel,
    #[error("the peers' SCTP maxMessageSize is too small for the business protocol")]
    DataMessageSize,
}

/// Safe, fixed-label diagnostics for the first owned peer shutdown cause.
/// This intentionally carries no error strings, addresses, SDP or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcHostDiagnosticReason {
    PeerGuardCancelRequested,
    PeerGuardCancelChannelClosed,
    PeerGuardPermitNotLive,
    PeerGuardPeerFailed,
    PeerGuardPeerClosed,
    PeerGuardSelectedPathChanged,
    PeerGuardSessionStopped,
    PeerGuardPermitChannelClosed,
    PeerGuardStateChannelClosed,
    PeerGuardPathChannelClosed,
    PeerGuardStopChannelClosed,
    VideoWorkerFailed,
    AudioWorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebRtcHostDiagnostic {
    pub reason: WebRtcHostDiagnosticReason,
    pub io_error_kind: Option<io::ErrorKind>,
    pub elapsed_ms: u64,
}

/// Local monotonic timings from peer creation. Missing values mean the stage
/// was not observed. These are not cross-machine one-way latency estimates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebRtcConnectionTimeline {
    pub offer_received_ms: Option<u64>,
    pub answer_published_ms: Option<u64>,
    pub first_local_candidate_ms: Option<u64>,
    pub first_remote_candidate_ms: Option<u64>,
    pub gather_complete_ms: Option<u64>,
    pub selected_pair_ms: Option<u64>,
    pub endpoint_proved_ms: Option<u64>,
    pub running_authorized_ms: Option<u64>,
    pub first_encoded_ms: Option<u64>,
    pub first_rtp_write_ms: Option<u64>,
    pub local_candidate_count: usize,
    pub remote_candidate_count: usize,
    pub selected_path: Option<i32>,
    pub ice_restarts: u64,
}

#[derive(Clone)]
struct PeerDiagnosticRecorder {
    started: Instant,
    first: Arc<StdMutex<Option<WebRtcHostDiagnostic>>>,
    timeline: Arc<StdMutex<WebRtcConnectionTimeline>>,
}

impl Default for PeerDiagnosticRecorder {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            first: Arc::new(StdMutex::new(None)),
            timeline: Arc::new(StdMutex::new(WebRtcConnectionTimeline::default())),
        }
    }
}

impl PeerDiagnosticRecorder {
    fn mark(&self, field: fn(&mut WebRtcConnectionTimeline) -> &mut Option<u64>) {
        let mut timeline = self
            .timeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        field(&mut timeline).get_or_insert(
            self.started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
    }
    fn timeline(&self) -> WebRtcConnectionTimeline {
        *self
            .timeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn candidates(&self, local: bool, count: usize, complete: bool) {
        if local {
            self.timeline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .local_candidate_count = count;
            if count > 0 {
                self.mark(|value| &mut value.first_local_candidate_ms);
            }
            if complete {
                self.mark(|value| &mut value.gather_complete_ms);
            }
        } else {
            self.timeline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remote_candidate_count = count;
            if count > 0 {
                self.mark(|value| &mut value.first_remote_candidate_ms);
            }
        }
    }
    fn record(&self, reason: WebRtcHostDiagnosticReason, io_error_kind: Option<io::ErrorKind>) {
        let diagnostic = WebRtcHostDiagnostic {
            reason,
            io_error_kind,
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        let mut first = self
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if first.is_none() {
            *first = Some(diagnostic);
        }
    }

    fn get(&self) -> Option<WebRtcHostDiagnostic> {
        *self
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub type HostMediaFactory =
    Box<dyn FnOnce(LeaseControl) -> Result<HostMediaSources, WebRtcHostError> + Send + 'static>;

#[derive(Clone)]
struct TurnBindingContext {
    controller_network_generation: u64,
    host_network_generation: u64,
    controller_candidates: Vec<String>,
    host_candidates: Vec<String>,
}

/// One video source already attached to the live session's lease controller.
/// `VideoController::poll` keeps every captured frame bound to View permission,
/// the selected display and the original connection generation.
#[derive(Clone)]
pub struct HostVideoSource {
    source: Arc<dyn VideoPoll>,
    selection: watch::Sender<HostVideoSelection>,
    pub catalog: Option<DisplayCatalogKey>,
    pub displays: Vec<DisplayDescriptor>,
    pub epoch: VideoEpoch,
    pub display: Display,
    pub codec: VideoConfig,
}

#[derive(Clone, Copy)]
struct HostVideoSelection {
    epoch: VideoEpoch,
    display: Display,
    codec: VideoConfig,
}

trait VideoPoll: Send + Sync {
    fn poll(&self) -> Result<Option<CapturedVideo>, RemoteError>;
    fn select_source(&self, source: u32, epoch: VideoEpoch) -> Result<Display, RemoteError>;
}
impl<D: CaptureDevice> VideoPoll for VideoController<D> {
    fn poll(&self) -> Result<Option<CapturedVideo>, RemoteError> {
        VideoController::poll(self)
    }

    fn select_source(&self, source: u32, epoch: VideoEpoch) -> Result<Display, RemoteError> {
        VideoController::select_source(self, source, epoch)
    }
}

impl HostVideoSource {
    pub fn new<D: CaptureDevice>(
        controller: VideoController<D>,
        epoch: VideoEpoch,
        display: Display,
        codec: VideoConfig,
    ) -> Self {
        Self::build(controller, epoch, display, codec, None, Vec::new())
    }

    /// Attach the exact locally approved display subset that may be exposed to
    /// the proved browser controller. The catalog hash is recomputed here so a
    /// local approval over a larger candidate set never reveals denied screens.
    pub fn with_display_catalog<D: CaptureDevice>(
        controller: VideoController<D>,
        epoch: VideoEpoch,
        display: Display,
        codec: VideoConfig,
        catalog: DisplayCatalogKey,
        displays: Vec<DisplayDescriptor>,
    ) -> Result<Self, WebRtcHostError> {
        validate_displays(&displays)?;
        if catalog.connection_generation != epoch.connection
            || catalog_key(
                &catalog.request_id,
                catalog.connection_generation,
                catalog.revision,
                &displays,
            )? != catalog
            || !displays.iter().any(|item| {
                item.source == display.source
                    && item.left == display.logical.left
                    && item.top == display.logical.top
                    && item.width == display.logical.width
                    && item.height == display.logical.height
            })
        {
            return Err(WebRtcHostError::Permit);
        }
        Ok(Self::build(
            controller,
            epoch,
            display,
            codec,
            Some(catalog),
            displays,
        ))
    }

    fn build<D: CaptureDevice>(
        controller: VideoController<D>,
        epoch: VideoEpoch,
        display: Display,
        codec: VideoConfig,
        catalog: Option<DisplayCatalogKey>,
        displays: Vec<DisplayDescriptor>,
    ) -> Self {
        let selection = HostVideoSelection {
            epoch,
            display,
            codec,
        };
        let (selection, _) = watch::channel(selection);
        Self {
            source: Arc::new(controller),
            selection,
            catalog,
            displays,
            epoch,
            display,
            codec,
        }
    }

    fn poll(&self) -> Result<Option<CapturedVideo>, RemoteError> {
        self.source.poll()
    }

    fn selection(&self) -> HostVideoSelection {
        *self.selection.borrow()
    }

    fn select_source(&self, source: u32) -> Result<HostVideoSelection, WebRtcHostError> {
        let descriptor = self
            .displays
            .iter()
            .find(|display| display.source == source)
            .ok_or(WebRtcHostError::Permit)?;
        let current = self.selection();
        let layout = current
            .epoch
            .layout
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(WebRtcHostError::Permit)?;
        let epoch = VideoEpoch {
            layout,
            connection: current.epoch.connection,
        };
        let display = self.source.select_source(source, epoch)?;
        if display.logical.left != descriptor.left
            || display.logical.top != descriptor.top
            || display.logical.width != descriptor.width
            || display.logical.height != descriptor.height
        {
            return Err(WebRtcHostError::Permit);
        }
        let selection = HostVideoSelection {
            epoch,
            display,
            codec: VideoConfig {
                width: descriptor.width,
                height: descriptor.height,
                ..current.codec
            },
        };
        self.selection.send_replace(selection);
        Ok(selection)
    }

    fn descriptor(&self, source: u32) -> Option<&DisplayDescriptor> {
        self.displays
            .iter()
            .find(|display| display.source == source)
    }
}

/// One microphone/loopback source already attached to the live session's
/// Audio permission controller. Audio capture is never opened implicitly.
pub struct HostAudioSource {
    source: Box<dyn AudioPoll>,
    pub binding: AudioBinding,
    pub bitrate: u32,
}

/// Input is attached to the proved lease and is only present when the signed
/// permit grants Input. The source keeps the controller and the exact layout
/// advertised to the browser together.
#[derive(Clone)]
pub struct HostInputSource {
    controller: Arc<dyn HostInputControl>,
    selection: Arc<std::sync::Mutex<HostInputSelection>>,
}

#[derive(Clone, Copy)]
struct HostInputSelection {
    epoch: InputEpoch,
    layout: InputLayout,
}

trait HostInputControl: Send + Sync {
    fn apply_with_deadline(
        &self,
        event: InputEvent,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<bool, RemoteError>;
    fn release_all_with_deadline(
        &self,
        epoch: InputEpoch,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<(), RemoteError>;
    fn select_source(&self, source: u32, layout: InputLayout) -> Result<InputEpoch, RemoteError>;
}

impl<D: InputDevice> HostInputControl for InputController<D> {
    fn apply_with_deadline(
        &self,
        event: InputEvent,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<bool, RemoteError> {
        InputController::apply_with_deadline(self, &event, deadline, expires_at_unix_ms)
    }

    fn release_all_with_deadline(
        &self,
        epoch: InputEpoch,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<(), RemoteError> {
        InputController::release_all_with_deadline(self, epoch, deadline, expires_at_unix_ms)
    }

    fn select_source(&self, source: u32, layout: InputLayout) -> Result<InputEpoch, RemoteError> {
        InputController::select_source(self, source, layout)
    }
}

impl HostInputSource {
    pub fn new<D: InputDevice>(
        controller: InputController<D>,
        epoch: InputEpoch,
        layout: InputLayout,
    ) -> Self {
        Self {
            controller: Arc::new(controller),
            selection: Arc::new(std::sync::Mutex::new(HostInputSelection { epoch, layout })),
        }
    }

    fn selection(&self) -> Result<HostInputSelection, WebRtcHostError> {
        self.selection
            .lock()
            .map(|state| *state)
            .map_err(|_| WebRtcHostError::Io(io::Error::other("input selection poisoned")))
    }

    fn select_source(
        &self,
        source: u32,
        layout: InputLayout,
    ) -> Result<InputEpoch, WebRtcHostError> {
        let epoch = self.controller.select_source(source, layout)?;
        *self
            .selection
            .lock()
            .map_err(|_| io::Error::other("input selection poisoned"))? =
            HostInputSelection { epoch, layout };
        Ok(epoch)
    }
}

trait AudioPoll: Send {
    fn poll(&mut self) -> Result<Option<CapturedAudio>, RemoteError>;
}
impl<D: AudioCaptureDevice> AudioPoll for AudioCaptureController<D> {
    fn poll(&mut self) -> Result<Option<CapturedAudio>, RemoteError> {
        AudioCaptureController::poll(self)
    }
}

impl HostAudioSource {
    pub fn new<D: AudioCaptureDevice>(
        controller: AudioCaptureController<D>,
        binding: AudioBinding,
        bitrate: u32,
    ) -> Self {
        Self {
            source: Box::new(controller),
            binding,
            bitrate,
        }
    }
}

/// Media sources are mandatory for the permissions in the current permit.
/// This prevents an apparently successful session that negotiates media but
/// has no authorized capture pipeline behind it.
pub struct HostMediaSources {
    video: HostVideoSource,
    audio: Option<HostAudioSource>,
    input: Option<HostInputSource>,
    data_factory: Option<HostDataFactory>,
}

impl HostMediaSources {
    pub fn new(video: HostVideoSource, audio: Option<HostAudioSource>) -> Self {
        Self {
            video,
            audio,
            input: None,
            data_factory: None,
        }
    }

    pub fn with_input(mut self, input: HostInputSource) -> Self {
        self.input = Some(input);
        self
    }

    /// Attach file and clipboard services. The factory is invoked only after
    /// mutual endpoint proof and receives one-shot claims for the signed data
    /// permissions. Its returned owner remains held until cleanup completes.
    pub fn with_data_factory(mut self, factory: HostDataFactory) -> Self {
        self.data_factory = Some(factory);
        self
    }
}

/// The native host-side WebRTC session. It answers subsequent signed browser
/// offers on the same peer connection, including browser-requested ICE restarts.
pub struct WebRtcHostPeer {
    peer: Arc<RTCPeerConnection>,
    permit_tx: watch::Sender<VerifiedPermit>,
    permit_rx: watch::Receiver<VerifiedPermit>,
    input_permits_tx: watch::Sender<Option<InputPermitWindows>>,
    // Serializes permit commits/renewals with display-control transactions.
    display_transaction_gate: Arc<Mutex<()>>,
    state_rx: watch::Receiver<RTCPeerConnectionState>,
    cancel_tx: watch::Sender<bool>,
    control: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    pending_data_channels: Arc<Mutex<HashMap<WebRtcDataChannel, PendingDataChannel>>>,
    proof_messages: mpsc::Receiver<Bytes>,
    input_messages: Option<mpsc::Receiver<Bytes>>,
    display_messages: Option<mpsc::Receiver<Bytes>>,
    proof_complete: Arc<AtomicBool>,
    business_data_proof_complete: Arc<AtomicBool>,
    display_authorized: Arc<AtomicBool>,
    display_selection_sequence: Option<u64>,
    setup: Option<SessionSetup>,
    media_factory: Option<HostMediaFactory>,
    lease: Option<LeaseControl>,
    clock: RuntimeClock,
    cursor: SignalCursor,
    signal_sequence: u64,
    local_ice_signal: Option<SignalPayload>,
    remote_offer_sequence: u64,
    remote_ice: nestlink_protocol::ice::IceSnapshotCursor,
    network_generation: u64,
    stun_urls: Vec<String>,
    turn_credentials: Option<TurnCredentials>,
    turn_binding_claims: Option<TurnPeerBindingClaims>,
    turn_binding_context: Option<TurnBindingContext>,
    last_turn_binding_check: Instant,
    selected_path: Path,
    selected_path_tx: watch::Sender<Option<Path>>,
    path_authority_tx: watch::Sender<bool>,
    last_refresh: Instant,
    last_renewal_sequence: u64,
    controller_key: [u8; 32],
    media: Option<HostMediaSources>,
    video_track: Arc<TrackLocalStaticSample>,
    audio_track: Option<Arc<TrackLocalStaticSample>>,
    video_sender: Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    media_started: bool,
    stop_monitor: JoinHandle<()>,
    lease_stop_worker: Option<JoinHandle<Result<(), RemoteError>>>,
    lease_stop_failed: Option<bool>,
    input_worker: Option<JoinHandle<()>>,
    display_worker: Option<JoinHandle<()>>,
    data_runtime: Option<HostDataRuntime>,
    diagnostics: PeerDiagnosticRecorder,
    cleanup_complete: bool,
}

/// StopReport is retained even when closing the independent WebRTC peer fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebRtcHostCloseReport {
    pub stop: Option<StopReport>,
    pub lease_stop_failed: bool,
    pub peer_close_failed: bool,
    pub input_worker_cleanup_failed: bool,
    pub data_worker_cleanup_failed: bool,
}
impl WebRtcHostCloseReport {
    pub fn cleanup_failed(self) -> bool {
        self.lease_stop_failed
            || self.input_worker_cleanup_failed
            || self.data_worker_cleanup_failed
            || self
                .stop
                .is_some_and(|report| matches!(report.cleanup, CleanupStatus::Failed(_)))
    }
}

impl WebRtcHostPeer {
    /// Return the first fixed-label peer guard or media worker termination
    /// diagnostic, if one was recorded.
    pub fn diagnostic(&self) -> Option<WebRtcHostDiagnostic> {
        self.diagnostics.get()
    }

    pub fn connection_timeline(&self) -> WebRtcConnectionTimeline {
        self.diagnostics.timeline()
    }

    /// Creates a VP8/Opus-only peer for the verified host endpoint. The peer
    /// uses direct ICE only; it never consumes TURN credentials from a signal.
    pub async fn new<F>(
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: VerifiedPermit,
        setup: SessionSetup,
        media_factory: F,
    ) -> Result<Self, WebRtcHostError>
    where
        F: FnOnce(LeaseControl) -> Result<HostMediaSources, WebRtcHostError> + Send + 'static,
    {
        Self::new_inner(sdk, installation, permit, setup, false, media_factory).await
    }

    /// Creates a host peer with TURN credentials obtained from the trusted
    /// management plane. Credentials from browser signaling are never used.
    /// Both direct and relay paths may be selected when the permit allows them.
    pub async fn new_with_turn<F>(
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: VerifiedPermit,
        setup: SessionSetup,
        media_factory: F,
    ) -> Result<Self, WebRtcHostError>
    where
        F: FnOnce(LeaseControl) -> Result<HostMediaSources, WebRtcHostError> + Send + 'static,
    {
        Self::new_inner(sdk, installation, permit, setup, true, media_factory).await
    }

    async fn new_inner<F>(
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: VerifiedPermit,
        setup: SessionSetup,
        with_turn: bool,
        media_factory: F,
    ) -> Result<Self, WebRtcHostError>
    where
        F: FnOnce(LeaseControl) -> Result<HostMediaSources, WebRtcHostError> + Send + 'static,
    {
        // Fetch only through the pinned management channel, before the fresh
        // host permit. Never accept ICE endpoints from a peer's SDP.
        let stun_urls = if permit.claims().paths.contains(&(Path::Direct as i32)) {
            match sdk.native_discovery_config().await {
                Ok(config) => config.webrtc_stun_urls()?,
                Err(error) if error.discovery_temporarily_unavailable() => Vec::new(),
                Err(error) => return Err(error.into()),
            }
        } else {
            Vec::new()
        };
        let fresh = sdk
            .host_permit(installation, &permit.claims().session_id)
            .await?;
        ensure_permit_binding(&permit, &fresh, installation)?;
        ensure_live(&fresh)?;
        if with_turn && !fresh.claims().paths.contains(&(Path::Relay as i32)) {
            return Err(WebRtcHostError::RelayPathRequired);
        }
        if !with_turn && !fresh.claims().paths.contains(&(Path::Direct as i32)) {
            return Err(WebRtcHostError::DirectPathRequired);
        }
        let expected_path = setup.path;
        let local_transcript = setup.session.proof_transcript();
        if setup.role != EndpointRole::Host
            || !fresh.claims().paths.contains(&(expected_path as i32))
            || (!with_turn && expected_path != Path::Direct)
            || setup.session.state() != SessionState::AwaitingProof
            || local_transcript.path != expected_path as i32
            || local_transcript.connection_generation != fresh.claims().connection_generation
            || local_transcript.permit_sha256.as_slice() != fresh.digest()
        {
            return Err(WebRtcHostError::Permit);
        }
        let view = sdk.remote(&fresh.claims().session_id).await?;
        ensure_remote_view(&view, &fresh)?;
        let controller_key = sdk.remote_peer_key(&fresh, installation).await?;

        let cursor = SignalCursor::new(&fresh, installation)?;
        let network_generation = 1;
        let turn_credentials = if with_turn {
            let optional = fresh.claims().paths.contains(&(Path::Direct as i32));
            let reserved = bounded_turn_operation(&fresh, optional, async {
                Ok(sdk
                    .reserve_turn_credentials(
                        installation,
                        &fresh,
                        &nestlink_auth::random_id(),
                        network_generation,
                        unix_ms()?,
                    )
                    .await?)
            })
            .await;
            optional_turn_result(&fresh, optional, reserved)?
        } else {
            None
        };
        let (peer, video_track, audio_track, video_sender) = make_peer(
            &fresh,
            fresh
                .claims()
                .permissions
                .contains(&(Permission::Audio as i32)),
            turn_credentials.as_ref(),
            &stun_urls,
        )
        .await?;
        let (permit_tx, permit_rx) = watch::channel(fresh.clone());
        let display_transaction_gate = Arc::new(Mutex::new(()));
        let (state_tx, state_rx) = watch::channel(peer.connection_state());
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let diagnostics = PeerDiagnosticRecorder::default();
        let (selected_path_tx, selected_path_rx) = watch::channel(None);
        let (path_authority_tx, _) = watch::channel(true);
        let control = Arc::new(Mutex::new(None));
        let pending_data_channels = Arc::new(Mutex::new(HashMap::new()));
        let (proof_tx, proof_messages) = mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        let (input_tx, input_messages) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let (display_tx, display_messages) = mpsc::channel(MAX_PENDING_DISPLAY_MESSAGES);
        let proof_complete = Arc::new(AtomicBool::new(false));
        let business_data_proof_complete = Arc::new(AtomicBool::new(false));
        let display_authorized = Arc::new(AtomicBool::new(false));

        install_peer_handlers(
            &peer,
            &control,
            &pending_data_channels,
            &cancel_tx,
            &state_tx,
            &permit_rx,
            PeerHandlerMessages {
                proof_messages: proof_tx,
                input_messages: input_tx,
                display_messages: display_tx,
                proof_complete: proof_complete.clone(),
                business_data_proof_complete: business_data_proof_complete.clone(),
                display_authorized: display_authorized.clone(),
                input_authorized: fresh
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32)),
            },
        );
        let lifecycle_stop = setup.lifecycle.stop.clone();
        let stop_monitor = spawn_peer_guard(PeerGuardWorker {
            peer: peer.clone(),
            permit: permit_rx.clone(),
            cancel: cancel_rx,
            cancel_tx: cancel_tx.clone(),
            state: state_rx.clone(),
            selected_path: selected_path_rx,
            stop: Some(lifecycle_stop),
            diagnostics: diagnostics.clone(),
        });
        let clock = setup.clock.clone();

        Ok(Self {
            peer,
            permit_tx,
            permit_rx,
            input_permits_tx: watch::channel(None).0,
            display_transaction_gate,
            state_rx,
            cancel_tx,
            control,
            pending_data_channels,
            proof_messages,
            input_messages: Some(input_messages),
            display_messages: Some(display_messages),
            proof_complete: proof_complete.clone(),
            business_data_proof_complete,
            display_authorized,
            display_selection_sequence: None,
            setup: Some(setup),
            media_factory: Some(Box::new(media_factory)),
            lease: None,
            clock,
            cursor,
            signal_sequence: 0,
            local_ice_signal: None,
            remote_offer_sequence: 0,
            remote_ice: Default::default(),
            network_generation,
            stun_urls,
            turn_credentials,
            turn_binding_claims: None,
            turn_binding_context: None,
            last_turn_binding_check: Instant::now(),
            selected_path: expected_path,
            selected_path_tx,
            path_authority_tx,
            last_refresh: Instant::now(),
            last_renewal_sequence: fresh.claims().lease_sequence,
            controller_key,
            media: None,
            video_track,
            audio_track,
            video_sender,
            media_started: false,
            stop_monitor,
            lease_stop_worker: None,
            lease_stop_failed: None,
            input_worker: None,
            display_worker: None,
            data_runtime: None,
            diagnostics,
            cleanup_complete: false,
        })
    }

    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer.connection_state()
    }

    /// Return the exact lease and selected path after mutual proof is complete.
    pub fn proved_session_info(&self) -> Option<(u64, u64, Path)> {
        if !self.proof_complete.load(Ordering::Acquire) {
            return None;
        }
        let permit = self.current_permit();
        Some((
            permit.claims().connection_generation,
            permit.claims().lease_sequence,
            self.selected_path,
        ))
    }

    /// Maintains the proved lease, reads the current signed controller signal
    /// and publishes its answer. Call regularly even while signaling is idle.
    /// Returns `false` when no new offer is waiting.
    pub async fn answer_next_offer(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<bool, WebRtcHostError> {
        self.ensure_open()?;
        if self.lease.is_some() && self.last_refresh.elapsed() >= SIGNAL_REFRESH_INTERVAL {
            self.refresh_authority(sdk, installation).await?;
        }
        if self.lease.is_some()
            && self.turn_credentials.is_some()
            && self.last_turn_binding_check.elapsed() >= TURN_BINDING_MAINTAIN_INTERVAL
        {
            self.maintain_turn_binding(sdk, installation).await?;
        }
        if self.lease.is_some() && self.renewal_due()? {
            self.send_renewal_signature(sdk, installation).await?;
        }
        let permit = self.current_permit();
        ensure_live(&permit)?;
        let signals = sdk
            .peer_signals(installation, &permit, &mut self.cursor)
            .await?;
        self.ensure_open()?;
        let Some(offer) = signals.into_iter().last() else {
            self.publish_local_ice(sdk, installation).await?;
            return Ok(false);
        };
        let claims = self.current_permit();
        validate_offer(&offer, &claims)?;
        if offer.ice.is_some() && offer.description_sequence() == self.remote_offer_sequence {
            self.apply_remote_ice(&offer).await?;
            self.publish_local_ice(sdk, installation).await?;
            return Ok(false);
        }
        self.diagnostics.mark(|value| &mut value.offer_received_ms);
        if self.remote_offer_sequence != 0 {
            self.diagnostics
                .timeline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ice_restarts += 1;
        }
        self.publish_answer(sdk, installation, &claims, offer)
            .await?;
        if !self.media_started {
            self.select_path_before_endpoint_proof(sdk, installation)
                .await?;
            self.complete_endpoint_proof(Some(sdk), installation)
                .await?;
            self.start_media()?;
            self.media_started = true;
        }
        Ok(true)
    }

    /// Refreshes the host's permit after the controller completes a renewal.
    /// A DataChannel signature alone never extends the host's authority.
    pub async fn refresh_authority(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        self.refresh_authority_inner(sdk, installation, false).await
    }

    async fn refresh_authority_inner(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        display_transaction_held: bool,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        let previous = self.current_permit();
        let request_started_ms = self.clock.monotonic_ms();
        let fresh = sdk
            .host_permit(installation, &previous.claims().session_id)
            .await?;
        ensure_permit_binding(&previous, &fresh, installation)?;
        ensure_live(&fresh)?;
        let view = sdk.remote(&fresh.claims().session_id).await?;
        ensure_remote_view(&view, &fresh)?;
        if fresh.claims().lease_sequence < previous.claims().lease_sequence
            || fresh.claims().lease_sequence > previous.claims().lease_sequence.saturating_add(1)
        {
            return Err(WebRtcHostError::Permit);
        }
        let lease_renewed = fresh.claims().lease_sequence > previous.claims().lease_sequence;
        if display_transaction_held {
            self.install_refreshed_permit(fresh, request_started_ms)?;
        } else {
            let _display_transaction = self.lock_display_transaction().await?;
            self.install_refreshed_permit(fresh, request_started_ms)?;
        }
        let current = self.current_permit();
        self.refresh_turn_allocation(sdk, installation, &current, lease_renewed)
            .await?;
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn install_refreshed_permit(
        &mut self,
        fresh: VerifiedPermit,
        request_started_ms: u64,
    ) -> Result<(), WebRtcHostError> {
        if fresh.claims().lease_sequence > self.last_renewal_sequence {
            self.last_renewal_sequence = fresh.claims().lease_sequence;
        }
        let previous = self.current_permit();
        if fresh.claims().lease_sequence > previous.claims().lease_sequence {
            self.lease
                .as_ref()
                .ok_or(WebRtcHostError::EndpointProof)?
                .renew(fresh.clone(), request_started_ms)?;
            self.publish_input_permit(&fresh)?;
        }
        self.permit_tx.send_replace(fresh);
        Ok(())
    }

    /// Input windows are a decoding history, never an authority source. The
    /// actual proved lease must already hold this exact verified permit.
    fn publish_input_permit(&self, permit: &VerifiedPermit) -> Result<(), WebRtcHostError> {
        if !permit
            .claims()
            .permissions
            .contains(&(Permission::Input as i32))
        {
            return Ok(());
        }
        let lease = self.lease.as_ref().ok_or(WebRtcHostError::EndpointProof)?;
        let deadline = lease.input_permit_deadline(permit)?;
        let previous = self.input_permits_tx.borrow().clone();
        let windows = match previous {
            Some(windows) => windows.advance(permit.clone(), deadline)?,
            None => InputPermitWindows::new(permit.clone(), deadline)?,
        };
        self.input_permits_tx.send_replace(Some(windows));
        Ok(())
    }

    async fn refresh_turn_allocation(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        force: bool,
    ) -> Result<(), WebRtcHostError> {
        if self.turn_credentials.is_none() {
            return Ok(());
        }
        let optional = self.optional_turn_allowed();
        let result = bounded_turn_operation(
            permit,
            optional,
            self.refresh_turn_allocation_inner(sdk, installation, permit, force),
        )
        .await;
        match optional_turn_result(permit, optional, result)? {
            Some(()) => Ok(()),
            None => self.disable_optional_turn().await,
        }
    }

    async fn refresh_turn_allocation_inner(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        force: bool,
    ) -> Result<(), WebRtcHostError> {
        let Some(current) = self.turn_credentials.as_ref() else {
            return Ok(());
        };
        let now = unix_ms()?;
        let allocation_id = current.claims().allocation_id.clone();
        let previous_grant_sequence = current.claims().grant_sequence;
        let previous_expiry = current.claims().expires_at_unix_ms;
        if !force && previous_expiry > now.saturating_add(TURN_RENEWAL_WINDOW.as_millis() as u64) {
            return Ok(());
        }
        let renewed = sdk
            .reserve_turn_credentials(
                installation,
                permit,
                &allocation_id,
                self.network_generation,
                now,
            )
            .await?;
        renewed.authorize(permit, unix_ms()?)?;
        if renewed.claims().grant_sequence != previous_grant_sequence
            || renewed.claims().expires_at_unix_ms != previous_expiry
        {
            self.peer
                .set_configuration(peer_configuration_with_stun(
                    permit,
                    Some(&renewed),
                    &self.stun_urls,
                ))
                .await?;
        }
        self.turn_credentials = Some(renewed);
        if force {
            self.turn_binding_claims = None;
            if self.selected_path == Path::Relay {
                self.path_authority_tx.send_replace(false);
            }
        }
        Ok(())
    }

    /// Indicates that this lease is due and its next signature is not sent yet.
    pub fn renewal_due(&self) -> Result<bool, WebRtcHostError> {
        let claims = self.current_permit();
        ensure_live(&claims)?;
        if self.last_renewal_sequence > claims.claims().lease_sequence {
            return Ok(false);
        }
        if claims.claims().is_setup() {
            return Ok(true);
        }
        let lifetime = claims
            .claims()
            .expires_at_unix_ms
            .checked_sub(claims.claims().issued_at_unix_ms)
            .ok_or(WebRtcHostError::Permit)?;
        // Deliver the host signature early enough for the browser to complete
        // its authenticated renewal while a bounded ICE restart is in flight.
        let due_at = claims
            .claims()
            .issued_at_unix_ms
            .checked_add(lifetime / 3)
            .ok_or(WebRtcHostError::Permit)?;
        Ok(unix_ms()? >= due_at)
    }

    /// Signs and sends the next lease sequence over the reliable, ordered
    /// control DataChannel. The controller must still call the management API.
    pub async fn send_renewal_signature(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<bool, WebRtcHostError> {
        let _display_transaction = self.lock_display_transaction().await?;
        self.ensure_open()?;
        if self.lease.is_none() {
            return Err(WebRtcHostError::EndpointProof);
        }
        self.refresh_authority_inner(sdk, installation, true)
            .await?;
        // A concurrent controller renewal may have replaced the lease during
        // the refresh. Wait for that new lease's own renewal window.
        if !self.renewal_due()? {
            return Ok(false);
        }
        let permit = self.current_permit();
        ensure_live(&permit)?;
        let claims = permit.claims();
        let next_sequence = claims
            .lease_sequence
            .checked_add(1)
            .ok_or(WebRtcHostError::Permit)?;
        if next_sequence <= self.last_renewal_sequence {
            return Ok(false);
        }
        let Some(channel) = self.control.lock().await.clone() else {
            return Ok(false);
        };
        if channel.ready_state() != RTCDataChannelState::Open {
            return Ok(false);
        }
        if channel.label() != WEBRTC_CONTROL_LABEL
            || !channel.ordered()
            || channel.max_retransmits().is_some()
            || channel.max_packet_lifetime().is_some()
        {
            return Err(WebRtcHostError::ControlChannelUnavailable);
        }
        let view = sdk.remote(&claims.session_id).await?;
        self.ensure_open()?;
        ensure_remote_view(&view, &permit)?;
        let signature = sdk.renewal_signature(installation, &view, &permit)?;
        let control = WebRtcControl::HostRenewalSignature {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: next_sequence,
            signature,
        };
        let bytes = control.encode_validated(claims)?;
        if bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(WebRtcHostError::ControlChannelUnavailable);
        }
        channel.send(&Bytes::from(bytes)).await?;
        ensure_live(&permit)?;
        self.last_renewal_sequence = next_sequence;
        Ok(true)
    }

    async fn lock_display_transaction(
        &mut self,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, WebRtcHostError> {
        self.ensure_open()?;
        let mut cancel = self.cancel_tx.subscribe();
        tokio::select! {
            biased;
            _ = cancel.changed() => Err(WebRtcHostError::Closed),
            guard = self.display_transaction_gate.clone().lock_owned() => Ok(guard),
        }
    }

    /// Waits until WebRTC is connected and confirms the selected candidate
    /// pair still uses the path authorized by endpoint proof.
    pub async fn wait_connected(&mut self, timeout: Duration) -> Result<(), WebRtcHostError> {
        let deadline = Instant::now()
            .checked_add(timeout.min(CONNECT_TIMEOUT))
            .ok_or(WebRtcHostError::ConnectTimeout)?;
        let mut states = self.state_rx.clone();
        let mut permit = self.permit_rx.clone();
        let mut cancelled = self.cancel_tx.subscribe();
        loop {
            if *cancelled.borrow() {
                return Err(WebRtcHostError::Closed);
            }
            ensure_live(&permit.borrow().clone())?;
            match self.peer.connection_state() {
                RTCPeerConnectionState::Connected => {
                    let (path, local, remote) = selected_ice_pair(&self.peer).await?;
                    self.validate_selected_pair(path, &local, &remote)?;
                    ensure_live(&permit.borrow().clone())?;
                    return Ok(());
                }
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    return Err(WebRtcHostError::Closed);
                }
                _ => {}
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(WebRtcHostError::ConnectTimeout)?;
            tokio::select! {
                _ = tokio::time::sleep(remaining.min(Duration::from_millis(100))) => {},
                changed = states.changed() => { changed.map_err(|_| WebRtcHostError::Closed)?; },
                changed = permit.changed() => { changed.map_err(|_| WebRtcHostError::Closed)?; },
                changed = cancelled.changed() => {
                    if changed.is_err() || *cancelled.borrow() { return Err(WebRtcHostError::Closed); }
                }
            }
        }
    }

    async fn select_path_before_endpoint_proof(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        let (path, local, remote) = self
            .wait_for_selected_pair(CONNECT_TIMEOUT, sdk, installation)
            .await?;
        let permit = self.current_permit();
        if path == Path::Relay {
            let claims = self
                .turn_binding_claims
                .as_ref()
                .ok_or(WebRtcHostError::TurnBinding)?
                .clone();
            self.wait_for_signed_turn_binding(sdk, installation, &permit, &claims)
                .await?;
            self.validate_selected_pair(path, &local, &remote)?;
        } else {
            self.validate_selected_pair(path, &local, &remote)?;
            // Endpoint proof fixes this connection to its actual direct path.
            // Optional TURN grants can no longer help it recover, and must not
            // make its independent direct lease depend on a relay renewal.
            if self.turn_credentials.is_some() {
                self.disable_optional_turn().await?;
            }
        }
        let setup = self.setup.as_mut().ok_or(WebRtcHostError::EndpointProof)?;
        setup
            .session
            .select_path_before_proof(path, setup.clock.sample()?)?;
        setup.path = path;
        self.selected_path = path;
        self.diagnostics.mark(|value| &mut value.selected_pair_ms);
        self.diagnostics
            .timeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .selected_path = Some(path as i32);
        self.selected_path_tx.send_replace(Some(path));
        self.path_authority_tx.send_replace(true);
        Ok(())
    }

    async fn wait_for_selected_pair(
        &mut self,
        timeout: Duration,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(Path, String, String), WebRtcHostError> {
        let deadline = Instant::now()
            .checked_add(timeout.min(CONNECT_TIMEOUT))
            .ok_or(WebRtcHostError::PathConnectTimeout)?;
        let mut state = self.state_rx.clone();
        let mut permit = self.permit_rx.clone();
        let mut cancelled = self.cancel_tx.subscribe();
        loop {
            if self.local_ice_signal.is_some() {
                self.exchange_ice(sdk, installation).await?;
            }
            // During initial ICE negotiation, expiry means no reachable path
            // was established within the signed startup lease.
            if ensure_live(&permit.borrow().clone()).is_err() {
                return Err(WebRtcHostError::PathConnectTimeout);
            }
            if *cancelled.borrow() {
                return Err(WebRtcHostError::Closed);
            }
            ensure_live(&permit.borrow().clone())?;
            match self.peer.connection_state() {
                RTCPeerConnectionState::Connected => {
                    let pair = selected_ice_pair(&self.peer).await?;
                    ensure_live(&permit.borrow().clone())?;
                    return Ok(pair);
                }
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    return Err(WebRtcHostError::Closed);
                }
                _ => {}
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(WebRtcHostError::PathConnectTimeout)?;
            tokio::select! {
                _ = tokio::time::sleep(remaining.min(Duration::from_millis(100))) => {},
                changed = state.changed() => { changed.map_err(|_| WebRtcHostError::Closed)?; },
                changed = permit.changed() => { changed.map_err(|_| WebRtcHostError::Closed)?; },
                changed = cancelled.changed() => {
                    if changed.is_err() || *cancelled.borrow() { return Err(WebRtcHostError::Closed); }
                }
            }
        }
    }

    async fn wait_for_signed_turn_binding(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        expected: &TurnPeerBindingClaims,
    ) -> Result<(), WebRtcHostError> {
        let deadline = Instant::now()
            .checked_add(CONNECT_TIMEOUT)
            .ok_or(WebRtcHostError::TurnBinding)?;
        loop {
            ensure_live(permit)?;
            let state = sdk.turn_binding_state(installation, permit).await?;
            if let Some(binding) = state.binding {
                let claims: TurnPeerBindingClaims = nestlink_protocol::decode_bounded(
                    &binding.claims,
                    nestlink_protocol::turn::TURN_BINDING_BYTES,
                )?;
                if binding.claims == expected.encode_to_vec()
                    && claims == *expected
                    && binding.controller_signature.len() == 64
                    && binding.host_signature.len() == 64
                {
                    return Ok(());
                }
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(WebRtcHostError::TurnBinding)?;
            tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
        }
    }

    fn validate_selected_pair(
        &self,
        path: Path,
        local: &str,
        remote: &str,
    ) -> Result<(), WebRtcHostError> {
        let permit = self.current_permit();
        match path {
            Path::Direct => {
                if !permit.claims().paths.contains(&(Path::Direct as i32)) {
                    return Err(WebRtcHostError::DirectPathRequired);
                }
            }
            Path::Relay => {
                if self.turn_credentials.is_none()
                    || !permit.claims().paths.contains(&(Path::Relay as i32))
                {
                    return Err(WebRtcHostError::RelayPathSelected);
                }
                let claims = self
                    .turn_binding_claims
                    .as_ref()
                    .ok_or(WebRtcHostError::TurnBinding)?;
                if claims.host_network_generation != self.network_generation
                    || !claims
                        .host_candidates
                        .iter()
                        .any(|candidate| candidate == local)
                    || !claims
                        .controller_candidates
                        .iter()
                        .any(|candidate| candidate == remote)
                {
                    return Err(WebRtcHostError::TurnBinding);
                }
            }
            _ => return Err(WebRtcHostError::TurnBinding),
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), WebRtcHostError> {
        self.close_with_reason(StopReason::ExplicitExit).await?;
        Ok(())
    }

    /// Stop the authorized lease before closing the peer and return the lease's
    /// actual synchronous platform cleanup report when proof attached capture.
    pub async fn close_with_reason(
        &mut self,
        reason: StopReason,
    ) -> Result<Option<StopReport>, WebRtcHostError> {
        let report = self.close_with_reason_report(reason).await;
        if report.lease_stop_failed || report.peer_close_failed || report.cleanup_failed() {
            return Err(WebRtcHostError::Closed);
        }
        Ok(report.stop)
    }

    /// Stop the lease and close the peer while preserving both outcomes.
    /// Product lifecycle code should use this report API so capture cleanup
    /// remains visible even if peer.close itself fails.
    pub async fn close_with_reason_report(&mut self, reason: StopReason) -> WebRtcHostCloseReport {
        self.cancel_tx.send_replace(true);
        let lease_stop_failed = self.stop_lease_for_close(reason).await;
        let stop = self.lease.as_ref().and_then(|lease| {
            let stopped = lease.subscribe_stopped();
            *stopped.borrow()
        });
        let peer_close_failed = self.peer.close().await.is_err();
        self.stop_monitor.abort();
        let input_worker_cleanup_failed =
            drain_input_worker(&mut self.input_worker, INPUT_WORKER_DRAIN_TIMEOUT).await;
        let data_worker_cleanup_failed = drain_data_runtime(&mut self.data_runtime, reason).await;
        self.cleanup_complete = !lease_stop_failed
            && !peer_close_failed
            && self.input_worker.is_none()
            && self.data_runtime.is_none();
        WebRtcHostCloseReport {
            stop,
            lease_stop_failed,
            peer_close_failed,
            input_worker_cleanup_failed,
            data_worker_cleanup_failed,
        }
    }

    async fn stop_lease_for_close(&mut self, reason: StopReason) -> bool {
        if self.lease_stop_failed == Some(false) {
            return false;
        }
        let Some(lease) = self.lease.clone() else {
            self.lease_stop_failed = Some(false);
            return false;
        };
        if self.lease_stop_worker.is_none() {
            self.lease_stop_worker = Some(tokio::task::spawn_blocking(move || {
                lease.stop(reason).map(|_| ())
            }));
        }
        let result = match self.lease_stop_worker.as_mut() {
            Some(worker) => worker.await,
            None => unreachable!("lease stop worker was just installed"),
        };
        let _ = self.lease_stop_worker.take();
        let failed = !matches!(result, Ok(Ok(())));
        self.lease_stop_failed = Some(failed);
        failed
    }

    fn current_permit(&self) -> VerifiedPermit {
        self.permit_rx.borrow().clone()
    }

    fn ensure_open(&self) -> Result<(), WebRtcHostError> {
        if *self.cancel_tx.borrow()
            || self.peer.connection_state() == RTCPeerConnectionState::Closed
        {
            return Err(WebRtcHostError::Closed);
        }
        ensure_live(&self.current_permit())
    }

    async fn publish_answer(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        offer: SignalPayload,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        if self.peer.signaling_state()
            != webrtc::peer_connection::signaling_state::RTCSignalingState::Stable
        {
            return Err(WebRtcHostError::InvalidOffer);
        }
        let remote = offer
            .description
            .as_ref()
            .ok_or(WebRtcHostError::InvalidOffer)?;
        self.peer
            .set_remote_description(RTCSessionDescription::offer(remote.sdp.clone())?)
            .await?;
        self.remote_offer_sequence = offer.description_sequence();
        self.remote_ice.reset();
        self.apply_remote_ice(&offer).await?;
        self.ensure_open()?;
        let answer = self.peer.create_answer(None).await?;
        // Register gathering completion before setting local SDP; gathering can
        // finish immediately on a host with only one active interface.
        let mut gathered = self.peer.gathering_complete_promise().await;
        self.peer.set_local_description(answer).await?;
        // The upstream promise signals completion by closing its channel,
        // rather than sending an item. A closed channel is the normal result.
        if offer.ice.is_none() {
            let _ = tokio::time::timeout(ICE_GATHER_TIMEOUT, gathered.recv())
                .await
                .map_err(|_| WebRtcHostError::GatherTimeout)?;
        }
        self.ensure_open()?;
        if offer.ice.is_none() && self.peer.ice_gathering_state() != RTCIceGatheringState::Complete
        {
            return Err(WebRtcHostError::GatherTimeout);
        }
        let local = self
            .peer
            .local_description()
            .await
            .ok_or(WebRtcHostError::InvalidOffer)?;
        validate_media_sdp(&local.sdp, &permit.claims().permissions)?;
        data::validate_sctp_message_size(&local.sdp)?;
        let fingerprint = dtls_fingerprint(&local.sdp)?;
        let description = WebRtcDescription {
            kind: "answer".into(),
            sdp: if cfg!(target_os = "android") {
                if offer.ice.is_some() {
                    nestlink_protocol::ice::without_candidates(&local.sdp)
                } else {
                    local.sdp.clone()
                }
            } else {
                format!(
                    "{}a=nestlink-scroll:120\r\n",
                    if offer.ice.is_some() {
                        nestlink_protocol::ice::without_candidates(&local.sdp)
                    } else {
                        local.sdp.clone()
                    }
                )
            },
            dtls_sha256: fingerprint,
            in_reply_to_sequence: Some(offer.description_sequence()),
        };
        let sequence = self
            .signal_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(WebRtcHostError::InvalidOffer)?;
        let answer_payload = SignalPayload {
            ice: if offer.ice.is_some() {
                Some(nestlink_protocol::ice::snapshot(
                    &local.sdp,
                    sequence,
                    self.peer.ice_gathering_state() == RTCIceGatheringState::Complete,
                )?)
            } else {
                None
            },
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            network_generation: self.network_generation,
            sequence,
            candidates: Vec::new(),
            description: Some(description),
        };
        answer_payload.validate(permit.claims())?;
        // A failed/ambiguous publish must never cause sequence reuse.
        self.signal_sequence = sequence;
        self.local_ice_signal = answer_payload.ice.as_ref().map(|_| answer_payload.clone());
        sdk.publish_signal(installation, permit, answer_payload)
            .await?;
        self.diagnostics
            .mark(|value| &mut value.answer_published_ms);
        self.diagnostics.candidates(
            true,
            local
                .sdp
                .lines()
                .filter(|line| line.starts_with("a=candidate:"))
                .count(),
            self.peer.ice_gathering_state() == RTCIceGatheringState::Complete,
        );
        if self.turn_credentials.is_some() {
            self.prepare_turn_binding(sdk, installation, permit, &offer, &remote.sdp, &local.sdp)
                .await?;
        }
        Ok(())
    }

    async fn apply_remote_ice(&mut self, signal: &SignalPayload) -> Result<(), WebRtcHostError> {
        let Some(ice) = &signal.ice else {
            return Ok(());
        };
        if ice.description_sequence != self.remote_offer_sequence {
            return Err(WebRtcHostError::InvalidOffer);
        }
        signal.validate(self.current_permit().claims())?;
        self.diagnostics
            .candidates(false, ice.candidates.len(), ice.end_of_candidates);
        for candidate in self.remote_ice.apply(ice)? {
            self.ensure_open()?;
            self.peer
                .add_ice_candidate(RTCIceCandidateInit {
                    candidate: candidate.candidate,
                    sdp_mid: candidate.sdp_mid,
                    sdp_mline_index: Some(candidate.sdp_m_line_index),
                    username_fragment: Some(candidate.username_fragment),
                })
                .await?;
        }
        if ice.end_of_candidates {
            self.peer
                .add_ice_candidate(RTCIceCandidateInit::default())
                .await?;
        }
        Ok(())
    }

    async fn publish_local_ice(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        let Some(mut signal) = self.local_ice_signal.clone() else {
            return Ok(());
        };
        self.ensure_open()?;
        let local = self
            .peer
            .local_description()
            .await
            .ok_or(WebRtcHostError::InvalidOffer)?;
        let snapshot = nestlink_protocol::ice::snapshot(
            &local.sdp,
            signal.description_sequence(),
            self.peer.ice_gathering_state() == RTCIceGatheringState::Complete,
        )?;
        if signal.ice.as_ref() == Some(&snapshot) {
            return Ok(());
        }
        let permit = self.current_permit();
        self.signal_sequence = self
            .signal_sequence
            .checked_add(1)
            .ok_or(WebRtcHostError::InvalidOffer)?;
        signal.sequence = self.signal_sequence;
        signal.lease_sequence = permit.claims().lease_sequence;
        signal.ice = Some(snapshot);
        signal.validate(permit.claims())?;
        if let Some(ice) = &signal.ice {
            self.diagnostics
                .candidates(true, ice.candidates.len(), ice.end_of_candidates);
        }
        sdk.publish_signal(installation, &permit, signal.clone())
            .await?;
        self.local_ice_signal = Some(signal);
        Ok(())
    }

    async fn exchange_ice(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        self.publish_local_ice(sdk, installation).await?;
        let permit = self.current_permit();
        for signal in sdk
            .peer_signals(installation, &permit, &mut self.cursor)
            .await?
        {
            validate_offer(&signal, &permit)?;
            self.apply_remote_ice(&signal).await?;
        }
        Ok(())
    }

    async fn prepare_turn_binding(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        offer: &SignalPayload,
        controller_sdp: &str,
        host_sdp: &str,
    ) -> Result<(), WebRtcHostError> {
        let controller_candidates = optional_ice_candidate_addresses(controller_sdp)?;
        let host_candidates = optional_ice_candidate_addresses(host_sdp)?;
        let (Some(controller_candidates), Some(host_candidates)) =
            (controller_candidates, host_candidates)
        else {
            if self.optional_turn_allowed() {
                return self.disable_optional_turn().await;
            }
            return Err(WebRtcHostError::RelayUnavailable);
        };
        let context = TurnBindingContext {
            controller_network_generation: offer.network_generation,
            host_network_generation: self.network_generation,
            controller_candidates,
            host_candidates,
        };
        self.turn_binding_context = Some(context.clone());
        let optional = self.optional_turn_allowed();
        let result = bounded_turn_operation(
            permit,
            optional,
            self.propose_turn_binding(sdk, installation, permit, &context, true),
        )
        .await;
        let Some(ready) = optional_turn_result(permit, optional, result)? else {
            return self.disable_optional_turn().await;
        };
        if self.media_started && self.selected_path == Path::Relay {
            self.path_authority_tx.send_replace(ready);
        }
        self.last_turn_binding_check = Instant::now();
        Ok(())
    }

    async fn maintain_turn_binding(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        self.last_turn_binding_check = Instant::now();
        let Some(context) = self.turn_binding_context.clone() else {
            return Ok(());
        };
        let permit = self.current_permit();
        let optional = self.optional_turn_allowed();
        let result = bounded_turn_operation(
            &permit,
            optional,
            self.propose_turn_binding(sdk, installation, &permit, &context, false),
        )
        .await;
        let Some(ready) = optional_turn_result(&permit, optional, result)? else {
            return self.disable_optional_turn().await;
        };
        if self.selected_path == Path::Relay {
            self.path_authority_tx.send_replace(ready);
        }
        Ok(())
    }

    fn optional_turn_allowed(&self) -> bool {
        self.current_permit()
            .claims()
            .paths
            .contains(&(Path::Direct as i32))
            && self
                .selected_path_tx
                .borrow()
                .is_none_or(|path| path == Path::Direct)
    }

    async fn disable_optional_turn(&mut self) -> Result<(), WebRtcHostError> {
        if !self.optional_turn_allowed() {
            return Err(WebRtcHostError::RelayPathRequired);
        }
        self.ensure_open()?;
        // Withdraw relay authority before awaiting the ICE configuration
        // update. Already gathered or late relay pairs still fail validation.
        self.turn_credentials = None;
        self.turn_binding_claims = None;
        self.turn_binding_context = None;
        let mut configuration =
            peer_configuration_with_stun(&self.current_permit(), None, &self.stun_urls);
        // webrtc 0.14 treats an empty ice_servers vector as "leave unchanged".
        // A valid server with no URLs replaces the public configuration with
        // no endpoints or credentials. Previously gathered allocations may
        // remain until peer close/their original expiry; they confer no path
        // authority and the selected-pair guard still rejects every relay.
        if configuration.ice_servers.is_empty() {
            configuration.ice_servers.push(RTCIceServer::default());
        }
        self.peer.set_configuration(configuration).await?;
        Ok(())
    }

    async fn propose_turn_binding(
        &mut self,
        sdk: &Sdk,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        context: &TurnBindingContext,
        required: bool,
    ) -> Result<bool, WebRtcHostError> {
        let credentials = self
            .turn_credentials
            .as_ref()
            .ok_or(WebRtcHostError::TurnBinding)?;
        let now = unix_ms()?;
        credentials.authorize(permit, now)?;
        let host_credentials = credentials.claims();
        if host_credentials.network_generation != context.host_network_generation
            || context.host_network_generation != self.network_generation
        {
            return Err(WebRtcHostError::TurnBinding);
        }
        let state = sdk.turn_binding_state(installation, permit).await?;
        let Some(controller_allocation_id) = state.controller_allocation_id.clone() else {
            if required {
                return Err(WebRtcHostError::RelayUnavailable);
            }
            return Ok(false);
        };
        let Some(host_allocation_id) = state.host_allocation_id.clone() else {
            if required {
                return Err(WebRtcHostError::RelayUnavailable);
            }
            return Ok(false);
        };
        let Some(controller_expires_at_unix_ms) = state.controller_expires_at_unix_ms else {
            if required {
                return Err(WebRtcHostError::RelayUnavailable);
            }
            return Ok(false);
        };
        let Some(host_expires_at_unix_ms) = state.host_expires_at_unix_ms else {
            if required {
                return Err(WebRtcHostError::RelayUnavailable);
            }
            return Ok(false);
        };
        if host_allocation_id != host_credentials.allocation_id
            || host_expires_at_unix_ms != host_credentials.expires_at_unix_ms
            || controller_allocation_id == host_allocation_id
        {
            return Err(WebRtcHostError::TurnBinding);
        }
        if controller_expires_at_unix_ms <= now || host_expires_at_unix_ms <= now {
            if required {
                return Err(WebRtcHostError::RelayUnavailable);
            }
            return Ok(false);
        }
        let fresh_claims = TurnPeerBindingClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: permit.claims().deployment_id.clone(),
            security_epoch: permit.claims().security_epoch,
            session_id: permit.claims().session_id.clone(),
            temporary_identity: permit.claims().controller_device_id.clone(),
            purpose: TurnPurpose::BrowserWebRtc as i32,
            controller_allocation_id,
            host_allocation_id,
            controller_device_id: permit.claims().controller_device_id.clone(),
            host_device_id: permit.claims().host_device_id.clone(),
            controller_key_sha256: permit.claims().controller_key_sha256.clone(),
            host_key_sha256: permit.claims().host_key_sha256.clone(),
            controller_network_generation: context.controller_network_generation,
            host_network_generation: context.host_network_generation,
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            permit_sha256: permit.digest().to_vec(),
            controller_candidates: context.controller_candidates.clone(),
            host_candidates: context.host_candidates.clone(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: permit
                .claims()
                .expires_at_unix_ms
                .min(controller_expires_at_unix_ms)
                .min(host_expires_at_unix_ms)
                .min(host_credentials.expires_at_unix_ms),
        };
        fresh_claims.validate()?;
        if fresh_claims.expires_at_unix_ms <= now {
            return Err(WebRtcHostError::TurnBinding);
        }

        let mut full_signature = false;
        let mut host_signature_present = false;
        let claims = if let Some(binding) = state.binding.as_ref() {
            let previous: TurnPeerBindingClaims = nestlink_protocol::decode_bounded(
                &binding.claims,
                nestlink_protocol::turn::TURN_BINDING_BYTES,
            )?;
            let matches_context = previous.controller_allocation_id
                == fresh_claims.controller_allocation_id
                && previous.host_allocation_id == fresh_claims.host_allocation_id
                && previous.controller_network_generation
                    == fresh_claims.controller_network_generation
                && previous.host_network_generation == fresh_claims.host_network_generation
                && previous.controller_candidates == fresh_claims.controller_candidates
                && previous.host_candidates == fresh_claims.host_candidates
                && previous.expires_at_unix_ms > now
                && previous.expires_at_unix_ms <= fresh_claims.expires_at_unix_ms;
            if !matches_context {
                if required {
                    return Err(WebRtcHostError::TurnBinding);
                }
                return Ok(false);
            }
            full_signature =
                binding.controller_signature.len() == 64 && binding.host_signature.len() == 64;
            host_signature_present = binding.host_signature.len() == 64;
            previous
        } else {
            fresh_claims
        };

        if full_signature {
            self.turn_binding_claims = Some(claims);
            return Ok(true);
        }
        if host_signature_present {
            self.turn_binding_claims = Some(claims);
            return Ok(false);
        }
        let proved = sdk.prove_turn_peers(installation, permit, &claims).await?;
        let signed = proved.binding.ok_or(WebRtcHostError::TurnBinding)?;
        if signed.claims != claims.encode_to_vec()
            || signed.host_signature.len() != 64
            || (!signed.controller_signature.is_empty() && signed.controller_signature.len() != 64)
        {
            return Err(WebRtcHostError::TurnBinding);
        }
        let full_signature = signed.controller_signature.len() == 64;
        self.turn_binding_claims = Some(claims);
        Ok(full_signature)
    }

    async fn complete_endpoint_proof(
        &mut self,
        sdk: Option<&Sdk>,
        installation: &DeviceIdentity,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        if self.lease.is_some() || self.proof_complete.load(Ordering::Acquire) {
            return Err(WebRtcHostError::EndpointProof);
        }
        let mut setup = self.setup.take().ok_or(WebRtcHostError::EndpointProof)?;
        let mut permit = self.current_permit();
        let proof = tokio::time::timeout(
            ENDPOINT_PROOF_TIMEOUT,
            self.complete_native_proof(&mut setup, installation, &permit),
        )
        .await;
        if !matches!(&proof, Ok(Ok(()))) {
            setup.session.stop(StopReason::Revoked);
            self.cancel_tx.send_replace(true);
            let _ = self.peer.close().await;
            return Err(match proof {
                Err(_) => WebRtcHostError::EndpointProof,
                Ok(Err(error)) => error,
                Ok(Ok(())) => unreachable!(),
            });
        }
        // Business DataChannels may be registered before proof, but their
        // bounded queues become eligible to buffer only after both endpoints
        // have completed the signed proof exchange.
        self.business_data_proof_complete
            .store(true, Ordering::Release);
        self.diagnostics.mark(|value| &mut value.endpoint_proved_ms);

        let SessionSetup {
            session,
            path,
            clock,
            lifecycle,
            ..
        } = setup;
        let lease = match LeaseControl::from_proved_session(session, path, clock.clone(), lifecycle)
        {
            Ok(lease) => lease,
            Err(error) => {
                self.cancel_tx.send_replace(true);
                let _ = self.peer.close().await;
                return Err(error.into());
            }
        };
        let accepted = WebRtcControl::EndpointProofAccepted {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
        };
        if let Err(error) = self.send_control(accepted, &permit).await {
            let _ = lease.stop(StopReason::Revoked);
            self.cancel_tx.send_replace(true);
            let _ = self.peer.close().await;
            return Err(error);
        }
        self.clock = clock.clone();
        self.lease = Some(lease.clone());
        if permit.claims().is_setup() {
            let sdk = sdk.ok_or(WebRtcHostError::Permit)?;
            self.send_renewal_signature(sdk, installation).await?;
            while self.current_permit().claims().is_setup() {
                self.ensure_open()?;
                self.refresh_authority(sdk, installation).await?;
                if self.current_permit().claims().is_setup() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            permit = self.current_permit();
        }
        self.diagnostics
            .mark(|value| &mut value.running_authorized_ms);
        let Some(factory) = self.media_factory.take() else {
            let _ = lease.stop(StopReason::Revoked);
            self.cancel_tx.send_replace(true);
            let _ = self.peer.close().await;
            return Err(WebRtcHostError::EndpointProof);
        };
        let mut media = match factory(lease.clone()) {
            Ok(media) => media,
            Err(error) => {
                let _ = lease.stop(StopReason::PlatformChanged);
                self.cancel_tx.send_replace(true);
                let _ = self.peer.close().await;
                return Err(error);
            }
        };
        if let Err(error) = ensure_media_sources(&media, &permit) {
            let _ = lease.stop(StopReason::PlatformChanged);
            self.cancel_tx.send_replace(true);
            let _ = self.peer.close().await;
            return Err(error);
        }
        let data_runtime = match HostDataRuntime::start(
            self.peer.clone(),
            lease.clone(),
            permit.clone(),
            self.permit_rx.clone(),
            self.pending_data_channels.clone(),
            self.cancel_tx.clone(),
            media.data_factory.take(),
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = lease.stop(StopReason::PlatformChanged);
                self.cancel_tx.send_replace(true);
                let _ = self.peer.close().await;
                return Err(error);
            }
        };
        self.data_runtime = data_runtime;
        self.display_authorized
            .store(media.video.catalog.is_some(), Ordering::Release);
        self.media = Some(media);
        self.publish_input_permit(&permit)?;
        self.proof_complete.store(true, Ordering::Release);
        if self.display_authorized.load(Ordering::Acquire) {
            if let Err(error) = self.complete_initial_display_selection(&permit).await {
                let _ = lease.stop(StopReason::Revoked);
                self.cancel_tx.send_replace(true);
                let _ = self.peer.close().await;
                return Err(error);
            }
        } else if let Some(input) = self.media.as_ref().and_then(|media| media.input.as_ref()) {
            let selected = input.selection()?;
            let layout = input_layout_message(permit.claims(), selected);
            if let Err(error) = self.send_control(layout, &permit).await {
                let _ = lease.stop(StopReason::Revoked);
                self.cancel_tx.send_replace(true);
                let _ = self.peer.close().await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn complete_native_proof(
        &mut self,
        setup: &mut SessionSetup,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
    ) -> Result<(), WebRtcHostError> {
        let local = setup.session.proof_transcript();
        let opening = self.receive_control(permit).await?;
        let peer = match opening {
            WebRtcControl::EndpointProof { proof, .. } => proof,
            _ => return Err(WebRtcHostError::EndpointProof),
        };
        if !peer.peer_transcript_signature.is_empty() {
            return Err(WebRtcHostError::EndpointProof);
        }
        let peer_transcript = peer
            .transcript
            .as_ref()
            .ok_or(WebRtcHostError::EndpointProof)?;
        matches_endpoint_transcript(&local, peer_transcript)?;
        verify_endpoint_proof(peer_transcript, &self.controller_key, &peer.signature)?;

        let host_signature = installation.identity.prove(&local)?;
        setup.session.confirm_endpoint(
            EndpointRole::Host,
            &installation.identity.public_key(),
            &host_signature,
            setup.clock.monotonic_ms(),
        )?;
        let response = WebRtcControl::EndpointProof {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            proof: NativeProof {
                transcript: Some(local.clone()),
                signature: host_signature,
                peer_transcript_signature: installation.identity.prove(peer_transcript)?,
            },
        };
        self.send_control(response, permit).await?;

        let response = self.receive_control(permit).await?;
        let controller = match response {
            WebRtcControl::EndpointProof { proof, .. } => proof,
            _ => return Err(WebRtcHostError::EndpointProof),
        };
        if controller.transcript.as_ref() != Some(&local)
            || !controller.peer_transcript_signature.is_empty()
        {
            return Err(WebRtcHostError::EndpointProof);
        }
        setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &self.controller_key,
            &controller.signature,
            setup.clock.monotonic_ms(),
        )?;
        if setup.session.state() != SessionState::Active || !self.proof_messages.is_empty() {
            return Err(WebRtcHostError::EndpointProof);
        }
        Ok(())
    }

    async fn receive_control(
        &mut self,
        permit: &VerifiedPermit,
    ) -> Result<WebRtcControl, WebRtcHostError> {
        self.ensure_open()?;
        let mut cancel = self.cancel_tx.subscribe();
        let message = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() { return Err(WebRtcHostError::Closed); }
                return Err(WebRtcHostError::Closed);
            }
            message = self.proof_messages.recv() => message.ok_or(WebRtcHostError::EndpointProof)?,
        };
        Ok(WebRtcControl::decode_validated(&message, permit.claims())?)
    }

    async fn send_control(
        &mut self,
        message: WebRtcControl,
        permit: &VerifiedPermit,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        let bytes = message.encode_validated(permit.claims())?;
        let channel = self
            .control
            .lock()
            .await
            .clone()
            .ok_or(WebRtcHostError::ControlChannelUnavailable)?;
        if channel.ready_state() != RTCDataChannelState::Open {
            return Err(WebRtcHostError::ControlChannelUnavailable);
        }
        channel.send(&Bytes::from(bytes)).await?;
        self.ensure_open()
    }

    async fn send_display_envelope(
        &mut self,
        message: DisplayEnvelope,
        permit: &VerifiedPermit,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        let envelope = WebRtcDisplayControl {
            schema_version: permit.claims().schema_version,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            message,
        };
        let bytes = envelope.encode_validated(permit.claims())?;
        let channel = self
            .control
            .lock()
            .await
            .clone()
            .ok_or(WebRtcHostError::ControlChannelUnavailable)?;
        if channel.ready_state() != RTCDataChannelState::Open {
            return Err(WebRtcHostError::ControlChannelUnavailable);
        }
        channel.send(&Bytes::from(bytes)).await?;
        self.ensure_open()
    }

    async fn receive_display_envelope(&mut self) -> Result<WebRtcDisplayControl, WebRtcHostError> {
        self.ensure_open()?;
        let mut cancel = self.cancel_tx.subscribe();
        let messages = self
            .display_messages
            .as_mut()
            .ok_or(WebRtcHostError::Closed)?;
        let bytes = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() { return Err(WebRtcHostError::Closed); }
                return Err(WebRtcHostError::Closed);
            }
            message = messages.recv() => message.ok_or(WebRtcHostError::Closed)?,
        };
        let permit = self.current_permit();
        Ok(WebRtcDisplayControl::decode_validated(
            &bytes,
            permit.claims(),
        )?)
    }

    async fn complete_initial_display_selection(
        &mut self,
        permit: &VerifiedPermit,
    ) -> Result<(), WebRtcHostError> {
        let (catalog, displays) = {
            let video = &self.media.as_ref().ok_or(WebRtcHostError::Closed)?.video;
            (
                video.catalog.clone().ok_or(WebRtcHostError::Permit)?,
                video.displays.clone(),
            )
        };
        self.send_display_envelope(
            DisplayEnvelope::CatalogBegin {
                catalog: catalog.clone(),
                count: u8::try_from(displays.len()).map_err(|_| WebRtcHostError::Permit)?,
            },
            permit,
        )
        .await?;
        for (index, display) in displays.iter().enumerate() {
            self.send_display_envelope(
                DisplayEnvelope::CatalogEntry {
                    catalog: catalog.clone(),
                    index: u8::try_from(index).map_err(|_| WebRtcHostError::Permit)?,
                    display: display.clone(),
                },
                permit,
            )
            .await?;
        }
        self.send_display_envelope(DisplayEnvelope::CatalogCommit(catalog.clone()), permit)
            .await?;
        let acknowledged = self.receive_display_envelope().await?;
        if acknowledged.message != DisplayEnvelope::CatalogAck(catalog.clone()) {
            return Err(WebRtcHostError::EndpointProof);
        }
        let request = self.receive_display_envelope().await?;
        let (sequence, source) = match request.message {
            DisplayEnvelope::Select {
                catalog: requested_catalog,
                sequence,
                source,
            } if requested_catalog == catalog && sequence == 1 => (sequence, source),
            _ => return Err(WebRtcHostError::EndpointProof),
        };
        if !displays.iter().any(|display| display.source == source) {
            return Err(WebRtcHostError::Permit);
        }
        let video = self
            .media
            .as_ref()
            .ok_or(WebRtcHostError::Closed)?
            .video
            .clone();
        let input = self
            .media
            .as_ref()
            .and_then(|media| media.input.as_ref())
            .cloned();
        let selection = tokio::task::spawn_blocking(move || {
            let video_selection = video.select_source(source)?;
            let input_epoch = match input {
                Some(input) => {
                    let epoch = input.select_source(
                        source,
                        nestlink_remote::input::InputLayout {
                            left: video_selection.display.logical.left,
                            top: video_selection.display.logical.top,
                            width: video_selection.display.logical.width,
                            height: video_selection.display.logical.height,
                        },
                    )?;
                    if epoch.layout != video_selection.epoch.layout
                        || epoch.connection != video_selection.epoch.connection
                    {
                        return Err(WebRtcHostError::Permit);
                    }
                    epoch.input
                }
                None => 0,
            };
            Ok::<_, WebRtcHostError>(DisplaySelection {
                catalog,
                sequence,
                source,
                layout_epoch: video_selection.epoch.layout,
                input_epoch,
            })
        })
        .await
        .map_err(io::Error::other)??;
        if let Some(input) = self.media.as_ref().and_then(|media| media.input.as_ref()) {
            let selected = input.selection()?;
            self.send_control(input_layout_message(permit.claims(), selected), permit)
                .await?;
        }
        self.send_display_envelope(DisplayEnvelope::Selected(selection.clone()), permit)
            .await?;
        let acknowledged = self.receive_display_envelope().await?;
        if acknowledged.message != DisplayEnvelope::SelectionAck(selection.clone()) {
            return Err(WebRtcHostError::EndpointProof);
        }
        self.display_selection_sequence = Some(selection.sequence);
        Ok(())
    }

    fn start_media(&mut self) -> Result<(), WebRtcHostError> {
        let sources = self.media.take().ok_or(WebRtcHostError::Closed)?;
        let display_video = sources.video.clone();
        let display_input = sources.input.clone();
        if let Some(input) = sources.input {
            let messages = self.input_messages.take().ok_or(WebRtcHostError::Closed)?;
            self.input_worker = Some(spawn_input_control(
                self.peer.clone(),
                self.cancel_tx.clone(),
                self.lease.clone().ok_or(WebRtcHostError::Closed)?,
                input,
                messages,
                self.input_permits_tx.subscribe(),
                self.clock.clone(),
            ));
        }
        let handle = Handle::current();
        let mut cancellation = self.cancel_tx.subscribe();
        let state = self.state_rx.clone();
        let permit = self.permit_rx.clone();
        let path_authority = self.path_authority_tx.subscribe();
        let peer = self.peer.clone();
        let selected_path = self.selected_path;
        let track = self.video_track.clone();
        let keyframe = Arc::new(AtomicBool::new(true));
        let target_kbps = Arc::new(AtomicU32::new(sources.video.codec.bitrate_kbps));
        let video_gate = Arc::new(tokio::sync::Mutex::new(()));
        let video_selection = sources.video.selection.subscribe();
        let sender_gate = video_gate.clone();
        let sender_keyframe = keyframe.clone();
        let video_diagnostics = self.diagnostics.clone();
        let _feedback = spawn_video_feedback(
            self.video_sender.clone(),
            self.cancel_tx.subscribe(),
            keyframe.clone(),
            target_kbps.clone(),
        );
        spawn_media_worker(
            WebRtcHostDiagnosticReason::VideoWorkerFailed,
            self.diagnostics.clone(),
            peer.clone(),
            self.cancel_tx.clone(),
            async move {
                wait_connected_gate(
                    peer.clone(),
                    permit.clone(),
                    state,
                    selected_path,
                    &mut cancellation,
                )
                .await?;
                let source = sources.video;
                let track = track;
                let peer = peer.clone();
                let permit = permit;
                let path_authority = path_authority;
                let selected_path = selected_path;
                let cancel = cancellation;
                tokio::task::spawn_blocking(move || {
                    run_video_source(
                        source,
                        track,
                        VideoSourceContext {
                            peer,
                            permit,
                            path_authority,
                            selected_path,
                            cancel,
                            force_keyframe: sender_keyframe,
                            target_kbps,
                            selection: video_selection,
                            gate: sender_gate,
                            runtime: handle,
                            diagnostics: video_diagnostics,
                        },
                    )
                })
                .await
                .map_err(io::Error::other)??;
                Ok::<(), io::Error>(())
            },
        );

        if let Some(catalog) = display_video.catalog.clone() {
            let messages = self
                .display_messages
                .take()
                .ok_or(WebRtcHostError::EndpointProof)?;
            self.display_worker = Some(spawn_display_selection(DisplaySelectionWorker {
                peer: self.peer.clone(),
                cancel_tx: self.cancel_tx.clone(),
                lease: self.lease.clone().ok_or(WebRtcHostError::Closed)?,
                channel: self.control.clone(),
                permits: self.permit_rx.clone(),
                messages,
                catalog,
                video: display_video,
                input: display_input,
                video_gate,
                authority_gate: self.display_transaction_gate.clone(),
                force_keyframe: keyframe,
                last_sequence: self
                    .display_selection_sequence
                    .ok_or(WebRtcHostError::EndpointProof)?,
            }));
        }

        if let (Some(audio), Some(track)) = (sources.audio, self.audio_track.clone()) {
            let mut cancellation = self.cancel_tx.subscribe();
            let state = self.state_rx.clone();
            let permit = self.permit_rx.clone();
            let path_authority = self.path_authority_tx.subscribe();
            let peer = self.peer.clone();
            let selected_path = self.selected_path;
            let handle = Handle::current();
            spawn_media_worker(
                WebRtcHostDiagnosticReason::AudioWorkerFailed,
                self.diagnostics.clone(),
                peer.clone(),
                self.cancel_tx.clone(),
                async move {
                    wait_connected_gate(
                        peer.clone(),
                        permit.clone(),
                        state,
                        selected_path,
                        &mut cancellation,
                    )
                    .await?;
                    let path_authority = path_authority;
                    let selected_path = selected_path;
                    let cancel = cancellation;
                    let peer = peer.clone();
                    tokio::task::spawn_blocking(move || {
                        run_audio_source(
                            audio,
                            AudioSourceContext {
                                track,
                                peer,
                                permit,
                                path_authority,
                                selected_path,
                                cancel,
                                runtime: handle,
                            },
                        )
                    })
                    .await
                    .map_err(io::Error::other)??;
                    Ok::<(), io::Error>(())
                },
            );
        }
        Ok(())
    }
}

impl Drop for WebRtcHostPeer {
    fn drop(&mut self) {
        self.cancel_tx.send_replace(true);
        self.stop_monitor.abort();
        if self.cleanup_complete {
            return;
        }
        let mut owner = InputCleanupOwner {
            peer: self.peer.clone(),
            cancel_tx: self.cancel_tx.clone(),
            lease: self.lease.clone(),
            lease_stop_worker: self.lease_stop_worker.take(),
            input_worker: self.input_worker.take(),
            data_runtime: self.data_runtime.take(),
            complete: false,
        };
        if owner.lease.is_none()
            && owner.lease_stop_worker.is_none()
            && owner.input_worker.is_none()
            && owner.data_runtime.is_none()
        {
            owner.complete = true;
            return;
        }
        handoff_dropped_input_cleanup(owner);
    }
}

async fn drain_input_worker(worker: &mut Option<JoinHandle<()>>, timeout: Duration) -> bool {
    let first_wait = {
        let Some(worker) = worker.as_mut() else {
            return false;
        };
        tokio::time::timeout(timeout, &mut *worker).await
    };
    match first_wait {
        Ok(result) => {
            let _ = worker.take();
            result.is_err()
        }
        Err(_) => {
            // Keep the JoinHandle in its owner across both awaits. If this
            // future is cancelled, close can be retried or Drop can hand it to
            // the cleanup actor without detaching an in-flight injection.
            let result = match worker.as_mut() {
                Some(worker) => worker.await,
                None => return true,
            };
            let _ = worker.take();
            let _ = result;
            true
        }
    }
}

async fn drain_data_runtime(runtime: &mut Option<HostDataRuntime>, reason: StopReason) -> bool {
    let Some(owner) = runtime.as_mut() else {
        return false;
    };
    match owner.shutdown(reason).await {
        Ok(()) => {
            *runtime = None;
            false
        }
        Err(_) => true,
    }
}

struct InputCleanupOwner {
    peer: Arc<RTCPeerConnection>,
    cancel_tx: watch::Sender<bool>,
    lease: Option<LeaseControl>,
    lease_stop_worker: Option<JoinHandle<Result<(), RemoteError>>>,
    input_worker: Option<JoinHandle<()>>,
    data_runtime: Option<HostDataRuntime>,
    complete: bool,
}

impl InputCleanupOwner {
    async fn run(mut self) {
        self.cancel_tx.send_replace(true);
        let lease_stop_failed = self.stop_lease().await;
        let peer_close_failed = self.peer.close().await.is_err();
        let input_worker_cleanup_failed =
            drain_input_worker(&mut self.input_worker, INPUT_WORKER_DRAIN_TIMEOUT).await;
        let data_worker_cleanup_failed =
            drain_data_runtime(&mut self.data_runtime, StopReason::ExplicitExit).await;
        if lease_stop_failed || input_worker_cleanup_failed || data_worker_cleanup_failed {
            eprintln!("NestLink WebRTC cleanup did not finish; cleanup ownership is retained");
            self.complete = true;
            std::mem::forget(self);
            return;
        }
        if peer_close_failed {
            eprintln!("NestLink WebRTC cleanup finished with peer-close diagnostics");
        }
        self.complete = true;
    }

    async fn stop_lease(&mut self) -> bool {
        let Some(lease) = self.lease.clone() else {
            return false;
        };
        if self.lease_stop_worker.is_none() {
            self.lease_stop_worker = Some(tokio::task::spawn_blocking(move || {
                lease.stop(StopReason::ExplicitExit).map(|_| ())
            }));
        }
        let result = match self.lease_stop_worker.as_mut() {
            Some(worker) => worker.await,
            None => unreachable!("lease stop worker was just installed"),
        };
        let _ = self.lease_stop_worker.take();
        if matches!(result, Ok(Ok(()))) {
            return false;
        }

        let Some(lease) = self.lease.clone() else {
            return true;
        };
        match tokio::task::spawn_blocking(move || lease.stop(StopReason::ExplicitExit).map(|_| ()))
            .await
        {
            Ok(Ok(())) => false,
            _ => self.stop_lease_synchronously(),
        }
    }

    /// Last-resort resource-exhaustion path only. `InputDevice` is a bounded,
    /// synchronous adapter contract; the shipped Windows, Portal, and X11
    /// cleanup paths use 150 ms OS/IPC budgets. This can wait for one in-flight
    /// native injection to return, then stops the lease and releases held input.
    fn stop_lease_synchronously(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.stop(StopReason::ExplicitExit).is_err())
    }
}

impl Drop for InputCleanupOwner {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        self.cancel_tx.send_replace(true);
        let owner = InputCleanupOwner {
            peer: self.peer.clone(),
            cancel_tx: self.cancel_tx.clone(),
            lease: self.lease.take(),
            lease_stop_worker: self.lease_stop_worker.take(),
            input_worker: self.input_worker.take(),
            data_runtime: self.data_runtime.take(),
            complete: false,
        };
        self.complete = true;
        match try_spawn_cleanup_thread(owner) {
            Ok(()) => {
                eprintln!(
                    "NestLink WebRTC cleanup task stopped early; a dedicated thread retained input cleanup ownership"
                );
            }
            Err((error, owner)) => {
                let owner = *owner;
                let lease_stop_failed = owner.stop_lease_synchronously();
                eprintln!(
                    "NestLink WebRTC cleanup thread fallback failed ({error}); synchronous lease stop failed={lease_stop_failed}; input cleanup owner retained"
                );
                std::mem::forget(owner);
            }
        }
    }
}

fn handoff_dropped_input_cleanup(owner: InputCleanupOwner) {
    match try_spawn_cleanup_thread(owner) {
        Ok(()) => {}
        Err((thread_error, owner)) => {
            let owner = *owner;
            if let Ok(handle) = Handle::try_current() {
                eprintln!(
                    "NestLink WebRTC cleanup thread unavailable ({thread_error}); using the current Tokio runtime with a cancellation fallback"
                );
                drop(handle.spawn(owner.run()));
                return;
            }

            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(owner.run()),
                Err(runtime_error) => {
                    let lease_stop_failed = owner.stop_lease_synchronously();
                    eprintln!(
                        "NestLink WebRTC cleanup thread and fallback runtime creation failed ({thread_error}; {runtime_error}); synchronous lease stop failed={lease_stop_failed}; input cleanup owner retained"
                    );
                    std::mem::forget(owner);
                }
            }
        }
    }
}

fn try_spawn_cleanup_thread(
    owner: InputCleanupOwner,
) -> Result<(), (io::Error, Box<InputCleanupOwner>)> {
    let pending = Arc::new(std::sync::Mutex::new(Some(owner)));
    let thread_pending = pending.clone();
    match std::thread::Builder::new()
        .name("nestlink-webrtc-input-cleanup".into())
        .spawn(move || {
            let owner = match thread_pending.lock() {
                Ok(mut owner) => owner.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            let Some(owner) = owner else {
                return;
            };
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(owner.run()),
                Err(error) => {
                    let lease_stop_failed = owner.stop_lease_synchronously();
                    eprintln!(
                        "NestLink WebRTC cleanup runtime creation failed ({error}); synchronous lease stop failed={lease_stop_failed}; input cleanup owner retained"
                    );
                    std::mem::forget(owner);
                }
            }
        })
    {
        Ok(thread) => {
            drop(thread);
            Ok(())
        }
        Err(error) => {
            let owner = match pending.lock() {
                Ok(mut owner) => owner.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            let Some(owner) = owner else {
                eprintln!(
                    "NestLink WebRTC cleanup thread handoff had already transferred ownership"
                );
                return Ok(());
            };
            Err((error, Box::new(owner)))
        }
    }
}

async fn make_peer(
    permit: &VerifiedPermit,
    with_audio: bool,
    turn_credentials: Option<&TurnCredentials>,
    stun_urls: &[String],
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<TrackLocalStaticSample>,
        Option<Arc<TrackLocalStaticSample>>,
        Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    ),
    WebRtcHostError,
> {
    make_peer_with_configuration(
        permit,
        with_audio,
        // Native endpoints publish their actual interface candidates through
        // the authorized signed signal. A single mDNS name cannot represent
        // the distinct IP/port pairs of multiple native interfaces. Keep
        // resolving the browser's own privacy-preserving mDNS candidates.
        MulticastDnsMode::QueryOnly,
        turn_credentials,
        stun_urls,
    )
    .await
}

#[cfg(test)]
async fn make_peer_with_mdns(
    permit: &VerifiedPermit,
    with_audio: bool,
    mdns_mode: MulticastDnsMode,
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<TrackLocalStaticSample>,
        Option<Arc<TrackLocalStaticSample>>,
        Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    ),
    WebRtcHostError,
> {
    make_peer_with_configuration(permit, with_audio, mdns_mode, None, &[]).await
}

async fn make_peer_with_configuration(
    permit: &VerifiedPermit,
    with_audio: bool,
    mdns_mode: MulticastDnsMode,
    turn_credentials: Option<&TurnCredentials>,
    stun_urls: &[String],
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<TrackLocalStaticSample>,
        Option<Arc<TrackLocalStaticSample>>,
        Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    ),
    WebRtcHostError,
> {
    let mut media = MediaEngine::default();
    let video_feedback = vec![
        RTCPFeedback {
            typ: "nack".into(),
            parameter: String::new(),
        },
        RTCPFeedback {
            typ: "nack".into(),
            parameter: "pli".into(),
        },
        RTCPFeedback {
            typ: "ccm".into(),
            parameter: "fir".into(),
        },
        RTCPFeedback {
            typ: "goog-remb".into(),
            parameter: String::new(),
        },
    ];
    media.register_codec(
        RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: MIME_TYPE_VP8.into(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: video_feedback,
            },
            payload_type: 96,
            ..Default::default()
        },
        RTPCodecType::Video,
    )?;
    if with_audio {
        media.register_codec(
            RTCRtpCodecParameters {
                capability: RTCRtpCodecCapability {
                    mime_type: MIME_TYPE_OPUS.into(),
                    clock_rate: 48_000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".into(),
                    rtcp_feedback: Vec::new(),
                },
                payload_type: 111,
                ..Default::default()
            },
            RTPCodecType::Audio,
        )?;
    }
    let registry: Registry = register_default_interceptors(Registry::new(), &mut media)?;
    let mut settings = SettingEngine::default();
    settings.set_ice_multicast_dns_mode(mdns_mode);
    let paths = Arc::new(nestlink_platform_network::path::NetworkPathManager::from_default()?);
    if paths.selected.is_some() {
        let filter = paths.clone();
        settings.set_ip_filter(Box::new(move |address| filter.allows_ip(address)));
        let mut ephemeral = webrtc::ice::udp_network::EphemeralUDP::default();
        ephemeral.set_socket_factory(Arc::new(move |address| paths.bind_udp(address)));
        settings.set_udp_network(webrtc::ice::udp_network::UDPNetwork::Ephemeral(ephemeral));
    }

    let api = APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_setting_engine(settings)
        .build();
    // webrtc 0.14 copies ICE URLs into its gatherer at construction. Its
    // set_configuration updates public metadata only, so STUN must be present
    // before creating the peer, not applied to the peer afterwards.
    let configuration = peer_configuration_with_stun(permit, turn_credentials, stun_urls);
    let peer = Arc::new(api.new_peer_connection(configuration).await?);
    let video_track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_VP8.into(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![
                RTCPFeedback {
                    typ: "nack".into(),
                    parameter: String::new(),
                },
                RTCPFeedback {
                    typ: "nack".into(),
                    parameter: "pli".into(),
                },
                RTCPFeedback {
                    typ: "ccm".into(),
                    parameter: "fir".into(),
                },
                RTCPFeedback {
                    typ: "goog-remb".into(),
                    parameter: String::new(),
                },
            ],
        },
        "nestlink-video".into(),
        permit.claims().session_id.clone(),
    ));
    let video_sender = peer.add_track(video_track.clone()).await?;
    let audio_track = if with_audio {
        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_OPUS.into(),
                clock_rate: 48_000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".into(),
                rtcp_feedback: Vec::new(),
            },
            "nestlink-audio".into(),
            permit.claims().session_id.clone(),
        ));
        peer.add_track(track.clone()).await?;
        Some(track)
    } else {
        None
    };
    Ok((peer, video_track, audio_track, video_sender))
}

fn peer_configuration(
    permit: &VerifiedPermit,
    turn_credentials: Option<&TurnCredentials>,
) -> RTCConfiguration {
    let mut configuration = RTCConfiguration::default();
    if let Some(credentials) = turn_credentials {
        configuration.ice_servers.push(RTCIceServer {
            urls: credentials.claims().endpoints.clone(),
            username: credentials.claims().username.clone(),
            credential: credentials.claims().password.clone(),
        });
        configuration.ice_transport_policy =
            if permit.claims().paths.contains(&(Path::Direct as i32)) {
                RTCIceTransportPolicy::All
            } else {
                RTCIceTransportPolicy::Relay
            };
    }
    configuration
}

fn peer_configuration_with_stun(
    permit: &VerifiedPermit,
    turn_credentials: Option<&TurnCredentials>,
    stun_urls: &[String],
) -> RTCConfiguration {
    let mut configuration = peer_configuration(permit, turn_credentials);
    if permit.claims().paths.contains(&(Path::Direct as i32)) && !stun_urls.is_empty() {
        configuration.ice_servers.push(RTCIceServer {
            urls: stun_urls.to_vec(),
            ..Default::default()
        });
    }
    configuration
}

fn spawn_input_control(
    peer: Arc<RTCPeerConnection>,
    cancel_tx: watch::Sender<bool>,
    lease: LeaseControl,
    input: HostInputSource,
    mut messages: mpsc::Receiver<Bytes>,
    permits: watch::Receiver<Option<InputPermitWindows>>,
    clock: RuntimeClock,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let cancel = cancel_tx.subscribe();
        let mut authority =
            InputPermitResolver::new(permits, cancel.clone(), lease.subscribe_stopped(), clock);
        loop {
            let message = tokio::select! {
                biased;
                changed = authority.changed() => match changed {
                    Ok(()) => continue,
                    Err(error) => Err(error),
                },
                message = messages.recv() => match message {
                    Some(message) => Ok(message),
                    None => break,
                },
            };
            let result = async {
                let message = message?;
                let resolved = authority.resolve(&message).await?;
                let guard = resolved.guard;
                let (deadline, expires_at_unix_ms) = guard.original_deadlines();
                match resolved.control {
                    WebRtcControl::InputEvent {
                        input_epoch,
                        layout_epoch,
                        connection_generation,
                        lease_sequence,
                        sequence,
                        action,
                        ..
                    } => {
                        let action = match action {
                            WebRtcInputAction::Key { usage, down } => {
                                InputAction::Key { code: usage, down }
                            }
                            WebRtcInputAction::Pointer { button, down, x, y } => {
                                InputAction::Pointer { button, down, x, y }
                            }
                            WebRtcInputAction::Scroll { x, y } => InputAction::Scroll { x, y },
                            WebRtcInputAction::Text { text } => InputAction::Text(text),
                        };
                        let event = InputEvent {
                            epoch: InputEpoch {
                                input: input_epoch,
                                layout: layout_epoch,
                                connection: connection_generation,
                            },
                            sequence,
                            action,
                        };
                        let controller = input.controller.clone();
                        tokio::task::spawn_blocking(move || {
                            guard.check()?;
                            // The same controller serializes current authority,
                            // epochs and its global sequence across renewals.
                            controller
                                .apply_with_deadline(event, deadline, expires_at_unix_ms)
                                .map_err(WebRtcHostError::from)
                        })
                        .await
                        .map_err(io::Error::other)??;
                        authority.input_event_applied(lease_sequence);
                    }
                    WebRtcControl::InputReleaseAll {
                        input_epoch,
                        layout_epoch,
                        connection_generation,
                        ..
                    } => {
                        let epoch = InputEpoch {
                            input: input_epoch,
                            layout: layout_epoch,
                            connection: connection_generation,
                        };
                        let controller = input.controller.clone();
                        tokio::task::spawn_blocking(move || {
                            guard.check()?;
                            controller
                                .release_all_with_deadline(epoch, deadline, expires_at_unix_ms)
                                .map_err(WebRtcHostError::from)
                        })
                        .await
                        .map_err(io::Error::other)??;
                    }
                    _ => return Err(WebRtcHostError::EndpointProof),
                }
                Ok::<(), WebRtcHostError>(())
            }
            .await;
            if result.is_err() {
                if *cancel.borrow() {
                    return;
                }
                trace_webrtc_host("input_control_worker_rejected_message");
                // Invalid input still stops the current lease. A next-sequence
                // packet never installs a permit or extends any deadline.
                let stop_lease = lease.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    stop_lease.stop(StopReason::ProtocolViolation)
                })
                .await;
                cancel_tx.send_replace(true);
                let _ = peer.close().await;
                return;
            }
        }
        let stop_lease = lease.clone();
        let _ = tokio::task::spawn_blocking(move || stop_lease.stop(StopReason::Revoked)).await;
    })
}

fn input_layout_message(
    claims: &nestlink_protocol::PermitClaims,
    selected: HostInputSelection,
) -> WebRtcControl {
    WebRtcControl::HostInputLayout {
        schema_version: claims.schema_version,
        session_id: claims.session_id.clone(),
        connection_generation: claims.connection_generation,
        lease_sequence: claims.lease_sequence,
        input_epoch: selected.epoch.input,
        layout_epoch: selected.epoch.layout,
        left: selected.layout.left,
        top: selected.layout.top,
        width: selected.layout.width,
        height: selected.layout.height,
    }
}

async fn send_host_control(
    channel: &Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    permit: &VerifiedPermit,
    message: WebRtcControl,
) -> Result<(), WebRtcHostError> {
    let bytes = message.encode_validated(permit.claims())?;
    let channel = channel
        .lock()
        .await
        .clone()
        .ok_or(WebRtcHostError::ControlChannelUnavailable)?;
    if channel.ready_state() != RTCDataChannelState::Open {
        return Err(WebRtcHostError::ControlChannelUnavailable);
    }
    channel.send(&Bytes::from(bytes)).await?;
    Ok(())
}

async fn send_host_display(
    channel: &Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    permit: &VerifiedPermit,
    message: DisplayEnvelope,
) -> Result<(), WebRtcHostError> {
    let claims = permit.claims();
    let bytes = WebRtcDisplayControl {
        schema_version: claims.schema_version,
        session_id: claims.session_id.clone(),
        connection_generation: claims.connection_generation,
        lease_sequence: claims.lease_sequence,
        message,
    }
    .encode_validated(claims)?;
    let channel = channel
        .lock()
        .await
        .clone()
        .ok_or(WebRtcHostError::ControlChannelUnavailable)?;
    if channel.ready_state() != RTCDataChannelState::Open {
        return Err(WebRtcHostError::ControlChannelUnavailable);
    }
    channel.send(&Bytes::from(bytes)).await?;
    Ok(())
}

struct DisplaySelectionWorker {
    peer: Arc<RTCPeerConnection>,
    cancel_tx: watch::Sender<bool>,
    lease: LeaseControl,
    channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    permits: watch::Receiver<VerifiedPermit>,
    messages: mpsc::Receiver<Bytes>,
    catalog: DisplayCatalogKey,
    video: HostVideoSource,
    input: Option<HostInputSource>,
    video_gate: Arc<tokio::sync::Mutex<()>>,
    authority_gate: Arc<tokio::sync::Mutex<()>>,
    force_keyframe: Arc<AtomicBool>,
    last_sequence: u64,
}

fn spawn_display_selection(worker: DisplaySelectionWorker) -> JoinHandle<()> {
    let DisplaySelectionWorker {
        peer,
        cancel_tx,
        lease,
        channel,
        permits,
        mut messages,
        catalog,
        video,
        input,
        video_gate,
        authority_gate,
        force_keyframe,
        mut last_sequence,
    } = worker;
    tokio::spawn(async move {
        let mut cancelled = cancel_tx.subscribe();
        loop {
            let bytes = tokio::select! {
                biased;
                changed = cancelled.changed() => {
                    if changed.is_err() || *cancelled.borrow() { return; }
                    continue;
                }
                message = messages.recv() => match message {
                    Some(message) => message,
                    None => break,
                },
            };
            let operation = async {
                let (permit, sequence, source) = {
                    let authority_lock = authority_gate.clone();
                    let _authority_guard = tokio::select! {
                        biased;
                        _ = cancelled.changed() => return Err(WebRtcHostError::Closed),
                        guard = authority_lock.lock_owned() => guard,
                    };
                    let permit = permits.borrow().clone();
                    ensure_live(&permit)?;
                    let request = WebRtcDisplayControl::decode_validated(&bytes, permit.claims())?;
                    let expected_sequence = last_sequence
                        .checked_add(1)
                        .ok_or(WebRtcHostError::Permit)?;
                    let (sequence, source) = match request.message {
                        DisplayEnvelope::Select {
                            catalog: requested_catalog,
                            sequence,
                            source,
                        } if requested_catalog == catalog && sequence == expected_sequence => {
                            (sequence, source)
                        }
                        _ => return Err(WebRtcHostError::EndpointProof),
                    };
                    if video.descriptor(source).is_none() {
                        return Err(WebRtcHostError::Permit);
                    }
                    (permit, sequence, source)
                };
                let selection_gate = video_gate.clone();
                trace_webrtc_host("display_selection_waiting_for_video_gate");
                let _selection_guard = tokio::select! {
                    biased;
                    _ = cancelled.changed() => return Err(WebRtcHostError::Closed),
                    guard = selection_gate.lock() => guard,
                };
                trace_webrtc_host("display_selection_video_gate_acquired");
                let video_for_switch = video.clone();
                let input_for_switch = input.clone();
                let (selected, input_selected) = tokio::task::spawn_blocking(move || {
                    let video_selected = video_for_switch.select_source(source)?;
                    let input_selected = match input_for_switch {
                        Some(input) => {
                            let epoch = input.select_source(
                                source,
                                nestlink_remote::input::InputLayout {
                                    left: video_selected.display.logical.left,
                                    top: video_selected.display.logical.top,
                                    width: video_selected.display.logical.width,
                                    height: video_selected.display.logical.height,
                                },
                            )?;
                            if epoch.layout != video_selected.epoch.layout
                                || epoch.connection != video_selected.epoch.connection
                            {
                                return Err(WebRtcHostError::Permit);
                            }
                            Some(input.selection()?)
                        }
                        None => None,
                    };
                    Ok::<_, WebRtcHostError>((video_selected, input_selected))
                })
                .await
                .map_err(io::Error::other)??;
                force_keyframe.store(true, Ordering::Release);
                let input_epoch = input_selected.map_or(0, |selected| selected.epoch.input);
                let selected = DisplaySelection {
                    catalog: catalog.clone(),
                    sequence,
                    source,
                    layout_epoch: selected.epoch.layout,
                    input_epoch,
                };
                if let Some(input_selected) = input_selected {
                    ensure_live(&permit)?;
                    send_host_control(
                        &channel,
                        &permit,
                        input_layout_message(permit.claims(), input_selected),
                    )
                    .await?;
                }
                ensure_live(&permit)?;
                send_host_display(
                    &channel,
                    &permit,
                    DisplayEnvelope::Selected(selected.clone()),
                )
                .await?;
                let response = tokio::select! {
                    biased;
                    _ = cancelled.changed() => return Err(WebRtcHostError::Closed),
                    response = tokio::time::timeout(
                        DISPLAY_SELECTION_ACK_TIMEOUT,
                        messages.recv(),
                    ) => response
                        .map_err(|_| WebRtcHostError::DisplaySelectionAckTimeout)?
                        .ok_or(WebRtcHostError::Closed)?,
                };
                validate_display_selection_ack(&response, &permit, &selected)?;
                lease.check_media_binding(
                    nestlink_transport_stream::Channel::Video,
                    permit.claims().connection_generation,
                )?;
                trace_webrtc_host("display_selection_ack_accepted");
                last_sequence = sequence;
                Ok::<(), WebRtcHostError>(())
            }
            .await;
            if operation.is_err() {
                if *cancelled.borrow() {
                    return;
                }
                trace_webrtc_host("display_selection_worker_rejected_request");
                let stop_lease = lease.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    stop_lease.stop(StopReason::ProtocolViolation)
                })
                .await;
                cancel_tx.send_replace(true);
                let _ = peer.close().await;
                return;
            }
        }
        let stop_lease = lease.clone();
        let _ = tokio::task::spawn_blocking(move || stop_lease.stop(StopReason::Revoked)).await;
    })
}

fn validate_display_selection_ack(
    bytes: &[u8],
    permit: &VerifiedPermit,
    selected: &DisplaySelection,
) -> Result<(), WebRtcHostError> {
    ensure_live(permit)?;
    let response = WebRtcDisplayControl::decode_validated(bytes, permit.claims())?;
    if response.message != DisplayEnvelope::SelectionAck(selected.clone()) {
        return Err(WebRtcHostError::EndpointProof);
    }
    Ok(())
}

struct PeerHandlerMessages {
    proof_messages: mpsc::Sender<Bytes>,
    input_messages: mpsc::Sender<Bytes>,
    display_messages: mpsc::Sender<Bytes>,
    proof_complete: Arc<AtomicBool>,
    business_data_proof_complete: Arc<AtomicBool>,
    display_authorized: Arc<AtomicBool>,
    input_authorized: bool,
}

fn install_peer_handlers(
    peer: &Arc<RTCPeerConnection>,
    control: &Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    pending_data_channels: &Arc<Mutex<HashMap<WebRtcDataChannel, PendingDataChannel>>>,
    cancel: &watch::Sender<bool>,
    state: &watch::Sender<RTCPeerConnectionState>,
    permits: &watch::Receiver<VerifiedPermit>,
    messages: PeerHandlerMessages,
) {
    let PeerHandlerMessages {
        proof_messages,
        input_messages,
        display_messages,
        proof_complete,
        business_data_proof_complete,
        display_authorized,
        input_authorized,
    } = messages;
    let state = state.clone();
    peer.on_peer_connection_state_change(Box::new(move |new_state| {
        let state = state.clone();
        Box::pin(async move {
            state.send_replace(new_state);
        })
    }));

    let weak_track_peer = Arc::downgrade(peer);
    let cancel_track = cancel.clone();
    peer.on_track(Box::new(move |_track, _receiver, _transceiver| {
        let weak_peer = weak_track_peer.clone();
        let cancel = cancel_track.clone();
        Box::pin(async move {
            // This product session only sends host capture. Receiving an RTP
            // track from the browser is outside the approved media contract.
            trace_webrtc_host("unexpected_remote_media_track");
            cancel.send_replace(true);
            if let Some(peer) = weak_peer.upgrade() {
                let _ = peer.close().await;
            }
        })
    }));

    let control = control.clone();
    let cancel = cancel.clone();
    let weak_peer = Arc::downgrade(peer);
    let proof_messages = proof_messages.clone();
    let input_messages = input_messages.clone();
    let display_messages = display_messages.clone();
    let pending_data_channels = pending_data_channels.clone();
    let permits = permits.clone();
    let proof_complete = proof_complete.clone();
    let business_data_proof_complete = business_data_proof_complete.clone();
    let display_authorized = display_authorized.clone();
    peer.on_data_channel(Box::new(move |channel| {
        let control = control.clone();
        let cancel = cancel.clone();
        let weak_peer = weak_peer.clone();
        let proof_messages = proof_messages.clone();
        let input_messages = input_messages.clone();
        let display_messages = display_messages.clone();
        let pending_data_channels = pending_data_channels.clone();
        let permits = permits.clone();
        let proof_complete = proof_complete.clone();
        let business_data_proof_complete = business_data_proof_complete.clone();
        let display_authorized = display_authorized.clone();
        let input_authorized = input_authorized;
        Box::pin(async move {
            if channel.label() != WEBRTC_CONTROL_LABEL {
                let kind = WebRtcDataChannel::from_label(channel.label()).ok();
                let permitted = kind.is_some_and(|kind| {
                    permits
                        .borrow()
                        .claims()
                        .permissions
                        .contains(&(kind.permission() as i32))
                });
                let result = match (kind, permitted, weak_peer.upgrade()) {
                    (Some(kind), true, Some(peer)) => {
                        data::register_channel(
                            kind,
                            channel.clone(),
                            pending_data_channels,
                            cancel.clone(),
                            business_data_proof_complete,
                            Arc::downgrade(&peer),
                        )
                        .await
                    }
                    _ => Err(WebRtcHostError::BusinessDataChannel),
                };
                if result.is_err() {
                    trace_webrtc_host("business_data_channel_rejected");
                    cancel.send_replace(true);
                    let _ = channel.close().await;
                    if let Some(peer) = weak_peer.upgrade() {
                        let _ = peer.close().await;
                    }
                }
                return;
            }
            if !channel.ordered()
                || channel.max_retransmits().is_some()
                || channel.max_packet_lifetime().is_some()
                || channel.negotiated()
                || !channel.protocol().is_empty()
            {
                trace_webrtc_host("control_data_channel_rejected");
                cancel.send_replace(true);
                let _ = channel.close().await;
                if let Some(peer) = weak_peer.upgrade() {
                    let _ = peer.close().await;
                }
                return;
            }
            let mut slot = control.lock().await;
            if slot.is_some() {
                trace_webrtc_host("duplicate_control_data_channel");
                cancel.send_replace(true);
                let _ = channel.close().await;
                if let Some(peer) = weak_peer.upgrade() {
                    let _ = peer.close().await;
                }
                return;
            }
            *slot = Some(channel.clone());
            drop(slot);

            let cancel_message = cancel.clone();
            let weak_message_peer = weak_peer.clone();
            let proof_message_sender = proof_messages.clone();
            let input_message_sender = input_messages.clone();
            let display_message_sender = display_messages.clone();
            let proof_is_complete = proof_complete.clone();
            let display_is_authorized = display_authorized.clone();
            let input_is_authorized = input_authorized;
            channel.on_message(Box::new(move |message: DataChannelMessage| {
                let cancel = cancel_message.clone();
                let weak_peer = weak_message_peer.clone();
                let proof_message_sender = proof_message_sender.clone();
                let input_message_sender = input_message_sender.clone();
                let display_message_sender = display_message_sender.clone();
                let proof_is_complete = proof_is_complete.clone();
                let display_is_authorized = display_is_authorized.clone();
                let input_is_authorized = input_is_authorized;
                Box::pin(async move {
                    let invalid =
                        if message.is_string || message.data.len() > MAX_WEBRTC_CONTROL_BYTES {
                            true
                        } else if proof_is_complete.load(Ordering::Acquire) {
                            if message.data.starts_with(b"NLDB") {
                                !display_is_authorized.load(Ordering::Acquire)
                                    || display_message_sender.try_send(message.data).is_err()
                            } else if input_is_authorized {
                                input_message_sender.try_send(message.data).is_err()
                            } else {
                                true
                            }
                        } else {
                            proof_message_sender.try_send(message.data).is_err()
                        };
                    if invalid {
                        trace_webrtc_host("control_message_rejected");
                        cancel.send_replace(true);
                        if let Some(peer) = weak_peer.upgrade() {
                            let _ = peer.close().await;
                        }
                    }
                })
            }));
            let cancel_close = cancel.clone();
            channel.on_close(Box::new(move || {
                let cancel = cancel_close.clone();
                Box::pin(async move {
                    trace_webrtc_host("control_data_channel_closed");
                    cancel.send_replace(true);
                })
            }));
        })
    }));
}

struct PeerGuardWorker {
    peer: Arc<RTCPeerConnection>,
    permit: watch::Receiver<VerifiedPermit>,
    cancel: watch::Receiver<bool>,
    cancel_tx: watch::Sender<bool>,
    state: watch::Receiver<RTCPeerConnectionState>,
    selected_path: watch::Receiver<Option<Path>>,
    stop: Option<watch::Receiver<Option<StopReason>>>,
    diagnostics: PeerDiagnosticRecorder,
}

fn spawn_peer_guard(worker: PeerGuardWorker) -> JoinHandle<()> {
    let PeerGuardWorker {
        peer,
        mut permit,
        mut cancel,
        cancel_tx,
        mut state,
        mut selected_path,
        stop,
        diagnostics,
    } = worker;
    tokio::spawn(async move {
        let mut stop = stop;
        let reason = loop {
            if *cancel.borrow() {
                break WebRtcHostDiagnosticReason::PeerGuardCancelRequested;
            }
            if ensure_live(&permit.borrow().clone()).is_err() {
                break WebRtcHostDiagnosticReason::PeerGuardPermitNotLive;
            }
            match peer.connection_state() {
                RTCPeerConnectionState::Failed => {
                    break WebRtcHostDiagnosticReason::PeerGuardPeerFailed;
                }
                RTCPeerConnectionState::Closed => {
                    break WebRtcHostDiagnosticReason::PeerGuardPeerClosed;
                }
                _ => {}
            }
            let expected_path = *selected_path.borrow();
            if let Some(expected) = expected_path
                && peer.connection_state() == RTCPeerConnectionState::Connected
                && selected_ice_pair(&peer)
                    .await
                    .is_ok_and(|(actual, _, _)| actual != expected)
            {
                break WebRtcHostDiagnosticReason::PeerGuardSelectedPathChanged;
            }
            if stop
                .as_ref()
                .is_some_and(|receiver| receiver.borrow().is_some())
            {
                break WebRtcHostDiagnosticReason::PeerGuardSessionStopped;
            }
            let remaining = match remaining(&permit.borrow().clone()) {
                Ok(remaining) => remaining,
                Err(_) => break WebRtcHostDiagnosticReason::PeerGuardPermitNotLive,
            };
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() { break WebRtcHostDiagnosticReason::PeerGuardCancelChannelClosed; }
                    if *cancel.borrow() { break WebRtcHostDiagnosticReason::PeerGuardCancelRequested; }
                },
                changed = permit.changed() => if changed.is_err() { break WebRtcHostDiagnosticReason::PeerGuardPermitChannelClosed; },
                changed = state.changed() => if changed.is_err() { break WebRtcHostDiagnosticReason::PeerGuardStateChannelClosed; },
                changed = selected_path.changed() => if changed.is_err() { break WebRtcHostDiagnosticReason::PeerGuardPathChannelClosed; },
                changed = async {
                    match stop.as_mut() { Some(receiver) => receiver.changed().await, None => std::future::pending().await }
                } => {
                    if changed.is_err() { break WebRtcHostDiagnosticReason::PeerGuardStopChannelClosed; }
                    if stop.as_ref().is_some_and(|receiver| receiver.borrow().is_some()) {
                        break WebRtcHostDiagnosticReason::PeerGuardSessionStopped;
                    }
                },
                _ = tokio::time::sleep(remaining.min(Duration::from_millis(250))) => {},
            }
        };
        diagnostics.record(reason, None);
        cancel_tx.send_replace(true);
        let _ = peer.close().await;
    })
}

fn spawn_video_feedback(
    sender: Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    mut cancel: watch::Receiver<bool>,
    force_keyframe: Arc<AtomicBool>,
    target_kbps: Arc<AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let parameters = sender.get_parameters().await;
        let ssrc = parameters
            .encodings
            .first()
            .map_or(0, |encoding| encoding.ssrc);
        let mut rate = RateController::new(target_kbps.load(Ordering::Acquire), Instant::now());
        let mut last_keyframe: Option<Instant> = None;
        loop {
            if *cancel.borrow() {
                break;
            }
            tokio::select! {
                changed = cancel.changed() => if changed.is_err() || *cancel.borrow() { break; },
                result = sender.read_rtcp() => match result {
                    Ok((packets, _)) => {
                        let now = Instant::now();
                        for packet in packets {
                            if ssrc == 0 { continue; }
                            let keyframe = packet.as_any().downcast_ref::<PictureLossIndication>()
                                .is_some_and(|pli| pli.media_ssrc == ssrc)
                                || packet.as_any().downcast_ref::<FullIntraRequest>()
                                    .is_some_and(|fir| fir.fir.iter().any(|entry| entry.ssrc == ssrc));
                            if keyframe && last_keyframe.is_none_or(|previous|
                                now.saturating_duration_since(previous) >= Duration::from_millis(250))
                            {
                                force_keyframe.store(true, Ordering::Release);
                                last_keyframe = Some(now);
                            }
                            if let Some(estimate) = packet.as_any().downcast_ref::<ReceiverEstimatedMaximumBitrate>()
                                && estimate.ssrcs.contains(&ssrc)
                            {
                                rate.receiver_estimate(estimate.bitrate, now);
                            }
                            if let Some(report) = packet.as_any().downcast_ref::<ReceiverReport>() {
                                for reception in &report.reports {
                                    if reception.ssrc == ssrc {
                                        rate.receiver_report(reception.last_sequence_number, reception.fraction_lost, now);
                                    }
                                }
                            }
                        }
                        target_kbps.store(rate.target_kbps(), Ordering::Release);
                    }
                    Err(_) => break,
                }
            }
        }
    })
}

fn spawn_media_worker<F>(
    reason: WebRtcHostDiagnosticReason,
    diagnostics: PeerDiagnosticRecorder,
    peer: Arc<RTCPeerConnection>,
    cancel: watch::Sender<bool>,
    worker: F,
) where
    F: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = worker.await {
            trace_webrtc_host(match reason {
                WebRtcHostDiagnosticReason::VideoWorkerFailed => "video_media_worker_failed",
                WebRtcHostDiagnosticReason::AudioWorkerFailed => "audio_media_worker_failed",
                _ => "media_worker_failed",
            });
            diagnostics.record(reason, Some(error.kind()));
            cancel.send_replace(true);
            let _ = peer.close().await;
        }
    });
}

async fn wait_connected_gate(
    peer: Arc<RTCPeerConnection>,
    permit: watch::Receiver<VerifiedPermit>,
    mut state: watch::Receiver<RTCPeerConnectionState>,
    expected_path: Path,
    cancel: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let mut permit = permit;
    let deadline = Instant::now()
        .checked_add(CONNECT_TIMEOUT)
        .ok_or_else(|| io::Error::other("connection deadline overflow"))?;
    loop {
        if *cancel.borrow() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "peer stopped"));
        }
        ensure_live(&permit.borrow().clone()).map_err(io::Error::other)?;
        match peer.connection_state() {
            RTCPeerConnectionState::Connected => {
                let (path, _, _) = selected_ice_pair(&peer).await.map_err(io::Error::other)?;
                if path != expected_path {
                    return Err(io::Error::other(
                        "selected ICE path changed after endpoint proof",
                    ));
                }
                ensure_live(&permit.borrow().clone()).map_err(io::Error::other)?;
                return Ok(());
            }
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "WebRTC peer closed",
                ));
            }
            _ => {}
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "WebRTC connection timed out")
            })?;
        tokio::select! {
            _ = tokio::time::sleep(remaining.min(Duration::from_millis(100))) => {},
            changed = state.changed() => changed.map_err(io::Error::other)?,
            changed = permit.changed() => changed.map_err(io::Error::other)?,
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() { return Err(io::Error::new(io::ErrorKind::Interrupted, "peer stopped")); }
            }
        }
    }
}

struct VideoSourceContext {
    peer: Arc<RTCPeerConnection>,
    permit: watch::Receiver<VerifiedPermit>,
    path_authority: watch::Receiver<bool>,
    selected_path: Path,
    cancel: watch::Receiver<bool>,
    force_keyframe: Arc<AtomicBool>,
    target_kbps: Arc<AtomicU32>,
    selection: watch::Receiver<HostVideoSelection>,
    gate: Arc<tokio::sync::Mutex<()>>,
    runtime: Handle,
    diagnostics: PeerDiagnosticRecorder,
}

fn run_video_source(
    source: HostVideoSource,
    track: Arc<TrackLocalStaticSample>,
    context: VideoSourceContext,
) -> io::Result<()> {
    let VideoSourceContext {
        peer,
        permit,
        path_authority,
        selected_path,
        cancel,
        force_keyframe,
        target_kbps,
        mut selection,
        gate,
        runtime,
        diagnostics,
    } = context;
    let mut current_selection = *selection.borrow_and_update();
    let mut encoder = Vp8Encoder::new(current_selection.codec)?;
    let mut current_kbps = current_selection.codec.bitrate_kbps;
    let started = Instant::now();
    let mut last_poll_trace = started;
    let mut last_traced_source = current_selection.display.source;
    let mut frame_period =
        Duration::from_nanos(1_000_000_000 / u64::from(current_selection.codec.fps));
    let mut next_frame = started;
    let mut last_pts = None;
    loop {
        if *cancel.borrow() {
            trace_video_worker("cancel_observed", started, current_selection);
            return Ok(());
        }
        if selected_path == Path::Relay && !*path_authority.borrow() {
            runtime.block_on(tokio::time::sleep(PATH_AUTHORITY_POLL));
            continue;
        }
        ensure_media_permit(&permit, Permission::View)?;
        let now = Instant::now();
        if now < next_frame {
            runtime.block_on(tokio::time::sleep((next_frame - now).min(POLL_INTERVAL)));
            continue;
        }
        // The same gate surrounds a frame's capture/encode/write and each
        // display-selection transaction. Once selection holds it, no frame
        // from the old epoch can appear after the acknowledgement boundary.
        let frame_gate = gate.clone();
        let _frame_guard = runtime.block_on(frame_gate.lock());
        if *cancel.borrow() {
            return Ok(());
        }
        let updated = *selection.borrow_and_update();
        if updated.epoch != current_selection.epoch
            || updated.display.source != current_selection.display.source
            || updated.codec.width != current_selection.codec.width
            || updated.codec.height != current_selection.codec.height
        {
            current_selection = updated;
            trace_video_worker("selection_observed", started, current_selection);
            trace_video_worker("encoder_recreate_started", started, current_selection);
            encoder = Vp8Encoder::new(current_selection.codec)?;
            trace_video_worker("encoder_recreate_completed", started, current_selection);
            current_kbps = current_selection.codec.bitrate_kbps;
            frame_period =
                Duration::from_nanos(1_000_000_000 / u64::from(current_selection.codec.fps));
            force_keyframe.store(true, Ordering::Release);
            next_frame = Instant::now();
        }
        if current_selection.display.source != last_traced_source
            || last_poll_trace.elapsed() >= Duration::from_secs(1)
        {
            trace_video_worker("capture_poll", started, current_selection);
            last_traced_source = current_selection.display.source;
            last_poll_trace = Instant::now();
        }
        let captured = source.poll().map_err(io::Error::other)?;
        let Some(captured) = captured else {
            drop(_frame_guard);
            runtime.block_on(tokio::time::sleep(POLL_INTERVAL));
            continue;
        };
        let now = Instant::now();
        if captured.epoch != current_selection.epoch
            || captured.display.source != current_selection.display.source
            || captured.frame.source != current_selection.display.source
            || captured.frame.width != current_selection.codec.width
            || captured.frame.height != current_selection.codec.height
            || captured.frame.validate().is_err()
            || captured.frame.captured_at > now
            || now.duration_since(captured.frame.captured_at) > MAX_VIDEO_FRAME_AGE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured video does not match its approved source/epoch/geometry",
            ));
        }
        ensure_media_permit(&permit, Permission::View)?;
        let elapsed = captured
            .frame
            .captured_at
            .checked_duration_since(started)
            .unwrap_or_default();
        let pts = u64::try_from(elapsed.as_nanos().saturating_mul(90_000) / 1_000_000_000)
            .map_err(io::Error::other)?;
        let pts = pts.max(last_pts.map_or(0, |previous: u64| previous.saturating_add(1)));
        let force = force_keyframe.swap(false, Ordering::AcqRel) || last_pts.is_none();
        let requested_kbps = target_kbps.load(Ordering::Acquire);
        if requested_kbps != current_kbps {
            encoder.set_bitrate(requested_kbps)?;
            current_kbps = requested_kbps;
        }
        let packet = encoder.encode(&captured.frame.pixels, pts, force)?;
        diagnostics.mark(|value| &mut value.first_encoded_ms);
        ensure_media_permit(&permit, Permission::View)?;
        let sample = Sample {
            data: Bytes::from(packet.data),
            timestamp: SystemTime::now(),
            duration: frame_period,
            packet_timestamp: packet.pts_90khz as u32,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        if !write_media_sample(&peer, &track, &sample, &runtime).map_err(io::Error::other)? {
            force_keyframe.store(true, Ordering::Release);
        } else {
            diagnostics.mark(|value| &mut value.first_rtp_write_ms);
        }
        last_pts = Some(pts);
        // Encoding and RTP writes consume this frame's period. Adding a full
        // period after that work steadily lowers the configured frame rate.
        // Keep the cadence when on time; an overrun starts a fresh slot so we
        // never burst a backlog of obsolete capture opportunities.
        next_frame = (next_frame + frame_period).max(Instant::now());
    }
}

fn trace_video_worker(stage: &str, started: Instant, selection: HostVideoSelection) {
    if std::env::var_os("NESTLINK_VIDEO_WORKER_TRACE").is_some() {
        eprintln!(
            "nestlink_video_worker stage={stage} elapsed_ms={} source={} layout={}",
            started.elapsed().as_millis(),
            selection.display.source,
            selection.epoch.layout
        );
    }
}

fn trace_webrtc_host(stage: &str) {
    if std::env::var_os("NESTLINK_VIDEO_WORKER_TRACE").is_some() {
        eprintln!("nestlink_webrtc_host stage={stage}");
    }
}

struct AudioSourceContext {
    track: Arc<TrackLocalStaticSample>,
    peer: Arc<RTCPeerConnection>,
    permit: watch::Receiver<VerifiedPermit>,
    path_authority: watch::Receiver<bool>,
    selected_path: Path,
    cancel: watch::Receiver<bool>,
    runtime: Handle,
}

fn run_audio_source(mut source: HostAudioSource, context: AudioSourceContext) -> io::Result<()> {
    let AudioSourceContext {
        track,
        peer,
        permit,
        path_authority,
        selected_path,
        cancel,
        runtime,
    } = context;
    let mut encoder = OpusEncoder::new(OpusConfig {
        channels: source.binding.channels,
        bitrate: source.bitrate,
    })?;
    loop {
        if *cancel.borrow() {
            return Ok(());
        }
        if selected_path == Path::Relay && !*path_authority.borrow() {
            runtime.block_on(tokio::time::sleep(PATH_AUTHORITY_POLL));
            continue;
        }
        ensure_media_permit(&permit, Permission::Audio)?;
        let captured = source.source.poll().map_err(io::Error::other)?;
        let Some(captured) = captured else {
            runtime.block_on(tokio::time::sleep(POLL_INTERVAL));
            continue;
        };
        ensure_media_permit(&permit, Permission::Audio)?;
        if captured.captured_at > Instant::now()
            || captured.captured_at.elapsed() > Duration::from_millis(100)
            || captured.chunk.source != source.binding.source
            || captured.chunk.channels != source.binding.channels
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured audio does not match its approved source or freshness budget",
            ));
        }
        let payload = encoder.encode(&captured.chunk.samples)?;
        ensure_media_permit(&permit, Permission::Audio)?;
        let sample = Sample {
            data: Bytes::from(payload),
            timestamp: SystemTime::now(),
            duration: AUDIO_FRAME_DURATION,
            packet_timestamp: captured.chunk.pts_48khz as u32,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        write_media_sample(&peer, &track, &sample, &runtime).map_err(io::Error::other)?;
    }
}

fn write_media_sample(
    peer: &RTCPeerConnection,
    track: &TrackLocalStaticSample,
    sample: &Sample,
    runtime: &Handle,
) -> Result<bool, WebRtcError> {
    match runtime.block_on(track.write_sample(sample)) {
        Ok(()) => Ok(true),
        Err(_error) if is_transient_media_write_state(peer.connection_state()) => {
            // An ICE restart briefly interrupts RTP writes while signaling
            // and ICE return to Connected. Drop this stale frame and keep the
            // source alive; a persistent failure after reconnection remains
            // terminal, and PeerGuard still closes failed/expired sessions.
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn is_transient_media_write_state(state: RTCPeerConnectionState) -> bool {
    matches!(
        state,
        RTCPeerConnectionState::Connecting | RTCPeerConnectionState::Disconnected
    )
}

fn ensure_media_permit(
    permit: &watch::Receiver<VerifiedPermit>,
    permission: Permission,
) -> io::Result<()> {
    let permit = permit.borrow().clone();
    ensure_live(&permit).map_err(io::Error::other)?;
    if !permit.claims().permissions.contains(&(permission as i32)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "media permission revoked",
        ));
    }
    Ok(())
}

async fn selected_ice_pair(
    peer: &RTCPeerConnection,
) -> Result<(Path, String, String), WebRtcHostError> {
    let report = peer.get_stats().await;
    let mut candidates = HashMap::new();
    for value in report.reports.values() {
        match value {
            StatsReportType::LocalCandidate(candidate)
            | StatsReportType::RemoteCandidate(candidate) => {
                let address = candidate
                    .ip
                    .parse::<std::net::IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, candidate.port).to_string())
                    .unwrap_or_else(|_| format!("{}:{}", candidate.ip, candidate.port));
                candidates.insert(candidate.id.as_str(), (candidate.candidate_type, address));
            }
            _ => {}
        }
    }
    let selected = report
        .reports
        .values()
        .find_map(|value| {
            if let StatsReportType::CandidatePair(pair) = value
                && pair.nominated
                && pair.state == CandidatePairState::Succeeded
            {
                Some((
                    pair.local_candidate_id.as_str(),
                    pair.remote_candidate_id.as_str(),
                ))
            } else {
                None
            }
        })
        .ok_or(WebRtcHostError::ConnectTimeout)?;
    let local = candidates
        .get(selected.0)
        .ok_or(WebRtcHostError::ConnectTimeout)?;
    let remote = candidates
        .get(selected.1)
        .ok_or(WebRtcHostError::ConnectTimeout)?;
    let path = if local.0 == CandidateType::Relay || remote.0 == CandidateType::Relay {
        Path::Relay
    } else {
        Path::Direct
    };
    Ok((path, local.1.clone(), remote.1.clone()))
}

fn validate_offer(offer: &SignalPayload, permit: &VerifiedPermit) -> Result<(), WebRtcHostError> {
    let claims = permit.claims();
    ensure_live(permit)?;
    offer.validate(claims)?;
    require_no_trickle(offer)?;
    let description = offer
        .description
        .as_ref()
        .ok_or(WebRtcHostError::InvalidOffer)?;
    if description.kind != "offer" || description.in_reply_to_sequence.is_some() {
        return Err(WebRtcHostError::InvalidOffer);
    }
    validate_media_sdp(&description.sdp, &claims.permissions)?;
    data::validate_sctp_message_size(&description.sdp)?;
    validate_offer_directions(&description.sdp)?;
    let mut video = 0;
    let mut audio = 0;
    let mut application = 0;
    for line in description
        .sdp
        .lines()
        .filter(|line| line.starts_with("m="))
    {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 4 || fields[1] == "0" {
            return Err(WebRtcHostError::InvalidOffer);
        }
        match fields[0] {
            "m=video" => video += 1,
            "m=audio" => audio += 1,
            "m=application" => application += 1,
            _ => return Err(WebRtcHostError::InvalidOffer),
        }
    }
    let needs_audio = claims.permissions.contains(&(Permission::Audio as i32));
    if video != 1 || audio != usize::from(needs_audio) || application != 1 {
        return Err(WebRtcHostError::InvalidOffer);
    }
    Ok(())
}

fn require_no_trickle(offer: &SignalPayload) -> Result<(), WebRtcHostError> {
    if offer.candidates.is_empty() {
        Ok(())
    } else {
        Err(WebRtcHostError::InvalidOffer)
    }
}

fn validate_offer_directions(sdp: &str) -> Result<(), WebRtcHostError> {
    let mut kind = None;
    let mut direction = None;
    let mut video = 0;
    let mut audio = 0;
    let mut application = 0;
    for line in sdp.lines().chain(std::iter::once("m=end")) {
        if line.starts_with("m=") {
            if matches!(kind, Some("video" | "audio")) && direction != Some("a=recvonly") {
                return Err(WebRtcHostError::InvalidOffer);
            }
            if line == "m=end" {
                break;
            }
            kind = line
                .split_ascii_whitespace()
                .next()
                .and_then(|field| field.strip_prefix("m="));
            direction = None;
            match kind {
                Some("video") => video += 1,
                Some("audio") => audio += 1,
                Some("application") => application += 1,
                _ => return Err(WebRtcHostError::InvalidOffer),
            }
        } else if matches!(
            line,
            "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive"
        ) && direction.replace(line).is_some()
        {
            return Err(WebRtcHostError::InvalidOffer);
        }
    }
    if video != 1 || application != 1 || audio > 1 {
        return Err(WebRtcHostError::InvalidOffer);
    }
    Ok(())
}

fn ensure_media_sources(
    media: &HostMediaSources,
    permit: &VerifiedPermit,
) -> Result<(), WebRtcHostError> {
    let claims = permit.claims();
    let video = &media.video;
    let selected_video = video.selection();
    let raw_bytes = u64::from(video.codec.width)
        .checked_mul(u64::from(video.codec.height))
        .and_then(|pixels| pixels.checked_mul(4));
    if !claims.permissions.contains(&(Permission::View as i32))
        || video.epoch.connection != claims.connection_generation
        || video.epoch.layout == 0
        || video.codec.width == 0
        || video.codec.height == 0
        || video.codec.width > 8192
        || video.codec.height > 8192
        || raw_bytes.is_none_or(|bytes| bytes > 64 * 1024 * 1024)
        || !(1..=120).contains(&video.codec.fps)
        || !(64..=100_000).contains(&video.codec.bitrate_kbps)
    {
        return Err(WebRtcHostError::Permit);
    }
    match &video.catalog {
        Some(catalog)
            if catalog.connection_generation == claims.connection_generation
                && catalog.request_id == claims.session_id
                && validate_displays(&video.displays).is_ok()
                && catalog_key(
                    &catalog.request_id,
                    catalog.connection_generation,
                    catalog.revision,
                    &video.displays,
                )
                .is_ok_and(|expected| expected == *catalog)
                && video.descriptor(video.display.source).is_some() => {}
        None if video.displays.is_empty() => {}
        _ => return Err(WebRtcHostError::Permit),
    }
    if selected_video.display.source != video.display.source
        || selected_video.epoch != video.epoch
        || selected_video.codec.width != video.codec.width
        || selected_video.codec.height != video.codec.height
    {
        return Err(WebRtcHostError::Permit);
    }
    let needs_audio = claims.permissions.contains(&(Permission::Audio as i32));
    match (&media.audio, needs_audio) {
        (Some(audio), true)
            if audio.binding.connection == claims.connection_generation
                && audio.binding.validate().is_ok()
                && (6_000..=256_000).contains(&audio.bitrate) => {}
        (None, false) => {}
        _ => return Err(WebRtcHostError::Permit),
    }
    let needs_input = claims.permissions.contains(&(Permission::Input as i32));
    match (&media.input, needs_input) {
        (Some(input), true) => {
            let selected = input.selection()?;
            if selected.epoch.connection != claims.connection_generation
                || selected.epoch.input == 0
                || selected.epoch.layout == 0
                || selected.layout.width == 0
                || selected.layout.height == 0
                || selected.layout.width > 32768
                || selected.layout.height > 32768
                || selected
                    .layout
                    .left
                    .checked_add_unsigned(selected.layout.width)
                    .is_none()
                || selected
                    .layout
                    .top
                    .checked_add_unsigned(selected.layout.height)
                    .is_none()
            {
                return Err(WebRtcHostError::Permit);
            }
        }
        (None, false) => {}
        _ => return Err(WebRtcHostError::Permit),
    }
    if !claims.paths.contains(&(Path::Direct as i32))
        && !claims.paths.contains(&(Path::Relay as i32))
        || !claims
            .required_capabilities
            .iter()
            .any(|name| name == "vp8")
        || (needs_audio
            && !claims
                .required_capabilities
                .iter()
                .any(|name| name == "opus"))
    {
        return Err(WebRtcHostError::Permit);
    }
    Ok(())
}

fn matches_endpoint_transcript(
    local: &EndpointProofClaims,
    peer: &EndpointProofClaims,
) -> Result<(), WebRtcHostError> {
    let mut expected = local.clone();
    expected.challenge = peer.challenge.clone();
    if peer.challenge.len() != 32 || expected != *peer {
        return Err(WebRtcHostError::EndpointProof);
    }
    Ok(())
}

fn ensure_permit_binding(
    previous: &VerifiedPermit,
    fresh: &VerifiedPermit,
    installation: &DeviceIdentity,
) -> Result<(), WebRtcHostError> {
    ensure_live(fresh)?;
    let claims = fresh.claims();
    if claims.host_device_id != installation.device_id
        || claims.host_key_sha256.as_slice() != installation.identity.fingerprint()
        || previous.claims().deployment_id != claims.deployment_id
        || previous.claims().session_id != claims.session_id
        || previous.claims().account_id != claims.account_id
        || previous.claims().controller_device_id != claims.controller_device_id
        || previous.claims().host_device_id != claims.host_device_id
        || previous.claims().resource_id != claims.resource_id
        || previous.claims().controller_key_sha256 != claims.controller_key_sha256
        || previous.claims().host_key_sha256 != claims.host_key_sha256
        || previous.claims().capability_sha256 != claims.capability_sha256
        || previous.claims().permissions != claims.permissions
        || previous.claims().paths != claims.paths
        || previous.claims().security_epoch != claims.security_epoch
        || previous.claims().policy_revision != claims.policy_revision
        || previous.claims().connection_generation != claims.connection_generation
        || previous.issuer() != fresh.issuer()
    {
        return Err(WebRtcHostError::Permit);
    }
    Ok(())
}

fn ensure_remote_view(view: &RemoteView, permit: &VerifiedPermit) -> Result<(), WebRtcHostError> {
    let claims = permit.claims();
    if view.id != claims.session_id
        || view.controller_device_id != claims.controller_device_id
        || view.host_device_id != claims.host_device_id
        || view.status != "approved"
        || view.connection_generation != claims.connection_generation
        || view.lease_sequence != claims.lease_sequence
        || view.policy_revision != claims.policy_revision
        || view.permissions != claims.permissions
        || view.paths != claims.paths
    {
        return Err(WebRtcHostError::Permit);
    }
    // RemoteView.expires_at_unix_ms bounds the pending approval request.
    // Only the verified permit bounds the active, independently renewed lease.
    Ok(())
}

fn ensure_live(permit: &VerifiedPermit) -> Result<(), WebRtcHostError> {
    permit.claims().validate()?;
    if permit.claims().expires_at_unix_ms <= unix_ms()? {
        return Err(WebRtcHostError::Permit);
    }
    Ok(())
}

fn remaining(permit: &VerifiedPermit) -> Result<Duration, WebRtcHostError> {
    ensure_live(permit)?;
    let milliseconds = permit
        .claims()
        .expires_at_unix_ms
        .saturating_sub(unix_ms()?);
    Ok(Duration::from_millis(milliseconds))
}

fn unix_ms() -> Result<u64, WebRtcHostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WebRtcHostError::Permit)?
        .as_millis()
        .try_into()
        .map_err(|_| WebRtcHostError::Permit)
}

fn dtls_fingerprint(sdp: &str) -> Result<Vec<u8>, WebRtcHostError> {
    let mut fingerprint = None;
    for line in sdp
        .lines()
        .filter_map(|line| line.strip_prefix("a=fingerprint:"))
    {
        let digest = line
            .strip_prefix("sha-256 ")
            .ok_or(WebRtcHostError::InvalidOffer)?;
        let bytes: Vec<u8> = digest
            .split(':')
            .map(|part| {
                if part.len() != 2 {
                    return Err(WebRtcHostError::InvalidOffer);
                }
                u8::from_str_radix(part, 16).map_err(|_| WebRtcHostError::InvalidOffer)
            })
            .collect::<Result<_, _>>()?;
        if bytes.len() != 32 || fingerprint.as_ref().is_some_and(|prior| prior != &bytes) {
            return Err(WebRtcHostError::InvalidOffer);
        }
        fingerprint = Some(bytes);
    }
    fingerprint.ok_or(WebRtcHostError::InvalidOffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_identity::{PermitSigner, digest, verify_permit};
    use nestlink_policy::PathSet;
    use nestlink_protocol::PermitClaims;
    use nestlink_remote::SessionLifecycle;
    use nestlink_session::{Session, SessionBinding};
    use std::error::Error;
    use webrtc::rtp_transceiver::{
        RTCRtpTransceiverInit, rtp_transceiver_direction::RTCRtpTransceiverDirection,
    };

    #[path = "data_loopback_tests.rs"]
    mod data_loopback_tests;
    #[path = "feedback_tests.rs"]
    mod feedback_tests;
    #[path = "input_renewal_tests.rs"]
    mod input_renewal_tests;
    #[path = "turn_fallback_tests.rs"]
    mod turn_fallback_tests;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[test]
    fn media_sample_write_failures_are_transient_only_during_peer_recovery() {
        assert!(is_transient_media_write_state(
            RTCPeerConnectionState::Connecting
        ));
        assert!(is_transient_media_write_state(
            RTCPeerConnectionState::Disconnected
        ));
        assert!(!is_transient_media_write_state(RTCPeerConnectionState::New));
        assert!(!is_transient_media_write_state(
            RTCPeerConnectionState::Connected
        ));
        assert!(!is_transient_media_write_state(
            RTCPeerConnectionState::Failed
        ));
        assert!(!is_transient_media_write_state(
            RTCPeerConnectionState::Closed
        ));
    }

    fn id(n: u8) -> String {
        format!("{n:08x}-1111-4111-8111-111111111111")
    }

    fn test_permit(
        controller: &DeviceIdentity,
        host: &DeviceIdentity,
    ) -> TestResult<VerifiedPermit> {
        test_permit_with_permissions(controller, host, vec![Permission::View])
    }

    fn test_permit_with_permissions(
        controller: &DeviceIdentity,
        host: &DeviceIdentity,
        permissions: Vec<Permission>,
    ) -> TestResult<VerifiedPermit> {
        let now = unix_ms()?;
        let claims = PermitClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            session_id: id(2),
            account_id: id(3),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            controller_key_sha256: digest(&controller.identity.public_key()).to_vec(),
            host_key_sha256: digest(&host.identity.public_key()).to_vec(),
            resource_id: host.device_id.clone(),
            permissions: permissions
                .into_iter()
                .map(|permission| permission as i32)
                .collect(),
            paths: vec![Path::Direct as i32],
            policy_revision: 1,
            connection_generation: 1,
            lease_sequence: 1,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + nestlink_protocol::SESSION_LEASE_MS,
            capability_sha256: digest(b"test-webrtc-vp8").to_vec(),
            required_capabilities: vec!["vp8".into()],
        };
        let signer = PermitSigner::generate();
        Ok(verify_permit(
            &signer.sign(&claims)?.encode_to_vec(),
            &signer.public_key(),
        )?)
    }

    fn test_permit_at_sequence(
        permit: &VerifiedPermit,
        sequence: u64,
        expired: bool,
    ) -> TestResult<VerifiedPermit> {
        let now = unix_ms()?;
        let mut claims = permit.claims().clone();
        claims.lease_sequence = sequence;
        if expired {
            claims.expires_at_unix_ms = now.saturating_sub(1);
            claims.issued_at_unix_ms = claims
                .expires_at_unix_ms
                .saturating_sub(nestlink_protocol::SESSION_LEASE_MS);
        } else {
            claims.issued_at_unix_ms = now;
            claims.expires_at_unix_ms = now + nestlink_protocol::SESSION_LEASE_MS;
        }
        let signer = PermitSigner::generate();
        Ok(verify_permit(
            &signer.sign(&claims)?.encode_to_vec(),
            &signer.public_key(),
        )?)
    }

    fn test_display_selection(permit: &VerifiedPermit, source: u32) -> DisplaySelection {
        DisplaySelection {
            catalog: DisplayCatalogKey {
                request_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                revision: 1,
                sha256: [1; 32],
            },
            sequence: 1,
            source,
            layout_epoch: 2,
            input_epoch: 0,
        }
    }

    fn encode_test_selection_ack(
        permit: &VerifiedPermit,
        selection: DisplaySelection,
    ) -> TestResult<Vec<u8>> {
        let claims = permit.claims();
        Ok(WebRtcDisplayControl {
            schema_version: claims.schema_version,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            message: DisplayEnvelope::SelectionAck(selection),
        }
        .encode_validated(claims)?)
    }

    #[test]
    fn in_flight_display_ack_uses_pinned_permit_after_renewal() -> TestResult {
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let permit_n = test_permit(&controller, &host)?;
        let selection = test_display_selection(&permit_n, 8);
        let ack = encode_test_selection_ack(&permit_n, selection.clone())?;
        let (permit_tx, permits) = watch::channel(permit_n);
        let pinned_permit = permits.borrow().clone();
        permit_tx.send_replace(test_permit_at_sequence(&pinned_permit, 2, false)?);
        assert_eq!(permits.borrow().claims().lease_sequence, 2);

        validate_display_selection_ack(&ack, &pinned_permit, &selection)?;
        let renewed_permit = permits.borrow().clone();
        assert!(validate_display_selection_ack(&ack, &renewed_permit, &selection).is_err());
        Ok(())
    }

    #[test]
    fn expired_and_mismatched_display_acks_are_rejected() -> TestResult {
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let permit = test_permit(&controller, &host)?;
        let selection = test_display_selection(&permit, 3);
        let expired = test_permit_at_sequence(&permit, 1, true)?;
        let expired_ack = encode_test_selection_ack(&expired, selection.clone())?;
        assert!(matches!(
            validate_display_selection_ack(&expired_ack, &expired, &selection),
            Err(WebRtcHostError::Permit)
        ));

        let wrong_selection = test_display_selection(&permit, 8);
        let wrong_ack = encode_test_selection_ack(&permit, wrong_selection)?;
        assert!(matches!(
            validate_display_selection_ack(&wrong_ack, &permit, &selection),
            Err(WebRtcHostError::EndpointProof)
        ));
        Ok(())
    }

    fn test_binding(permit: &VerifiedPermit) -> TestResult<SessionBinding> {
        let claims = permit.claims();
        Ok(SessionBinding {
            deployment_id: claims.deployment_id.clone(),
            security_epoch: claims.security_epoch,
            session_id: claims.session_id.clone(),
            account_id: claims.account_id.clone(),
            controller_device_id: claims.controller_device_id.clone(),
            host_device_id: claims.host_device_id.clone(),
            controller_key_sha256: claims.controller_key_sha256.as_slice().try_into()?,
            host_key_sha256: claims.host_key_sha256.as_slice().try_into()?,
            resource_id: claims.resource_id.clone(),
            policy_revision: claims.policy_revision,
            connection_generation: claims.connection_generation,
            capability_sha256: claims.capability_sha256.as_slice().try_into()?,
            granted_permissions: claims
                .permissions
                .iter()
                .map(|permission| {
                    Permission::try_from(*permission)
                        .map_err(|_| io::Error::other("invalid test permission"))
                })
                .collect::<Result<_, _>>()?,
            supported_capabilities: claims.required_capabilities.clone(),
            local_paths: PathSet::DIRECT,
        })
    }

    fn test_setup(
        permit: &VerifiedPermit,
        role: EndpointRole,
    ) -> TestResult<(SessionSetup, watch::Sender<Option<StopReason>>)> {
        let clock = RuntimeClock::default();
        let started = clock.monotonic_ms();
        let session = Session::activate(
            permit.clone(),
            test_binding(permit)?,
            Path::Direct,
            started,
            clock.sample()?,
        )?;
        let (stop_owner, stop) = watch::channel(None);
        Ok((
            SessionSetup {
                session,
                path: Path::Direct,
                role,
                clock,
                lifecycle: SessionLifecycle::new(stop),
            },
            stop_owner,
        ))
    }

    async fn make_browser_peer() -> Result<Arc<RTCPeerConnection>, WebRtcHostError> {
        let mut media = MediaEngine::default();
        media.register_codec(
            RTCRtpCodecParameters {
                capability: RTCRtpCodecCapability {
                    mime_type: MIME_TYPE_VP8.into(),
                    clock_rate: 90_000,
                    ..Default::default()
                },
                payload_type: 96,
                ..Default::default()
            },
            RTPCodecType::Video,
        )?;
        let registry = register_default_interceptors(Registry::new(), &mut media)?;
        let mut settings = SettingEngine::default();
        settings.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
        let api = APIBuilder::new()
            .with_media_engine(media)
            .with_interceptor_registry(registry)
            .with_setting_engine(settings)
            .build();
        let peer = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
        peer.add_transceiver_from_kind(
            RTPCodecType::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                send_encodings: Vec::new(),
            }),
        )
        .await?;
        Ok(peer)
    }

    async fn test_host_peer_state(
        permit: &VerifiedPermit,
        host_identity: &DeviceIdentity,
        controller_key: [u8; 32],
    ) -> TestResult<WebRtcHostPeer> {
        let (peer, video_track, audio_track, video_sender) =
            make_peer_with_mdns(permit, false, MulticastDnsMode::Disabled).await?;
        let (permit_tx, permit_rx) = watch::channel(permit.clone());
        let (_state_tx, state_rx) = watch::channel(peer.connection_state());
        let (cancel_tx, _) = watch::channel(false);
        let (selected_path_tx, _) = watch::channel(None);
        let (path_authority_tx, _) = watch::channel(true);
        let (proof_tx, proof_messages) = mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        let (input_tx, input_messages) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        drop(proof_tx);
        drop(input_tx);
        Ok(WebRtcHostPeer {
            peer,
            permit_tx,
            permit_rx,
            input_permits_tx: watch::channel(None).0,
            display_transaction_gate: Arc::new(Mutex::new(())),
            state_rx,
            cancel_tx,
            control: Arc::new(Mutex::new(None)),
            pending_data_channels: Arc::new(Mutex::new(HashMap::new())),
            proof_messages,
            input_messages: Some(input_messages),
            display_messages: None,
            proof_complete: Arc::new(AtomicBool::new(false)),
            business_data_proof_complete: Arc::new(AtomicBool::new(false)),
            display_authorized: Arc::new(AtomicBool::new(false)),
            display_selection_sequence: None,
            setup: None,
            media_factory: None,
            lease: None,
            clock: RuntimeClock::default(),
            cursor: SignalCursor::new(permit, host_identity)?,
            signal_sequence: 0,
            local_ice_signal: None,
            remote_offer_sequence: 0,
            remote_ice: nestlink_protocol::ice::IceSnapshotCursor::default(),
            network_generation: 1,
            stun_urls: Vec::new(),
            turn_credentials: None,
            turn_binding_claims: None,
            turn_binding_context: None,
            last_turn_binding_check: Instant::now(),
            selected_path: Path::Direct,
            selected_path_tx,
            path_authority_tx,
            last_refresh: Instant::now(),
            last_renewal_sequence: permit.claims().lease_sequence,
            controller_key,
            media: None,
            video_track,
            audio_track,
            video_sender,
            media_started: false,
            stop_monitor: tokio::spawn(std::future::pending()),
            lease_stop_worker: None,
            lease_stop_failed: None,
            input_worker: None,
            display_worker: None,
            data_runtime: None,
            diagnostics: PeerDiagnosticRecorder::default(),
            cleanup_complete: false,
        })
    }

    fn test_proved_lease(
        permit: &VerifiedPermit,
        controller: &DeviceIdentity,
        host_identity: &DeviceIdentity,
    ) -> TestResult<(LeaseControl, watch::Sender<Option<StopReason>>)> {
        let (mut setup, stop_owner) = test_setup(permit, EndpointRole::Host)?;
        let transcript = setup.session.proof_transcript();
        let controller_public = controller.identity.public_key();
        let controller_signature = controller.identity.prove(&transcript)?;
        let host_public = host_identity.identity.public_key();
        let host_signature = host_identity.identity.prove(&transcript)?;
        let now = setup.clock.monotonic_ms();
        setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &controller_public,
            &controller_signature,
            now,
        )?;
        setup
            .session
            .confirm_endpoint(EndpointRole::Host, &host_public, &host_signature, now)?;
        let SessionSetup {
            session,
            path,
            clock,
            lifecycle,
            ..
        } = setup;
        let lease = LeaseControl::from_proved_session(session, path, clock, lifecycle)?;
        Ok((lease, stop_owner))
    }

    #[tokio::test]
    async fn close_wait_can_be_cancelled_and_retried_without_losing_input_join_owner() -> TestResult
    {
        let controller = DeviceIdentity::generate();
        let host_identity = DeviceIdentity::generate();
        let permit = test_permit(&controller, &host_identity)?;
        let mut host =
            test_host_peer_state(&permit, &host_identity, controller.identity.public_key()).await?;
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        host.input_worker = Some(tokio::spawn(async move {
            let _ = release_rx.await;
        }));

        let mut first_close = Box::pin(host.close_with_reason_report(StopReason::ExplicitExit));
        tokio::select! {
            _ = &mut first_close => return Err(io::Error::other("close unexpectedly passed the held input worker").into()),
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
        drop(first_close);
        assert!(host.input_worker.is_some());

        let mut retry = Box::pin(host.close_with_reason_report(StopReason::ExplicitExit));
        tokio::select! {
            _ = &mut retry => return Err(io::Error::other("retry unexpectedly passed the held input worker").into()),
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
        release_tx
            .send(())
            .map_err(|_| io::Error::other("held input worker exited before retry"))?;
        let report = retry.await;
        assert!(!report.input_worker_cleanup_failed);
        assert!(!report.peer_close_failed);
        assert!(host.input_worker.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn dropping_host_peer_releases_held_input_and_drains_worker() -> TestResult {
        let controller = DeviceIdentity::generate();
        let host_identity = DeviceIdentity::generate();
        let permit = test_permit_with_permissions(
            &controller,
            &host_identity,
            vec![Permission::View, Permission::Input],
        )?;
        let (lease, _stop_owner) = test_proved_lease(&permit, &controller, &host_identity)?;
        let epoch = InputEpoch {
            input: 1,
            layout: 1,
            connection: permit.claims().connection_generation,
        };
        let layout = InputLayout {
            left: 0,
            top: 0,
            width: 1280,
            height: 720,
        };
        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let controller_input = InputController::attach(
            lease.clone(),
            RecordingInputDevice(records.clone()),
            epoch,
            layout,
        )?;
        let mut host =
            test_host_peer_state(&permit, &host_identity, controller.identity.public_key()).await?;
        host.lease = Some(lease.clone());
        host.publish_input_permit(&permit)?;
        host.input_messages = None;
        let (input_tx, input_rx) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let worker = spawn_input_control(
            host.peer.clone(),
            host.cancel_tx.clone(),
            lease.clone(),
            HostInputSource::new(controller_input, epoch, layout),
            input_rx,
            host.input_permits_tx.subscribe(),
            host.clock.clone(),
        );
        let (worker_done_tx, worker_done_rx) = tokio::sync::oneshot::channel();
        host.input_worker = Some(tokio::spawn(async move {
            let result = worker.await;
            let _ = worker_done_tx.send(result.is_ok());
        }));

        let action = WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: epoch.input,
            layout_epoch: epoch.layout,
            sequence: 1,
            action: WebRtcInputAction::Key {
                usage: 4,
                down: true,
            },
        };
        input_tx
            .send(Bytes::from(action.encode_validated(permit.claims())?))
            .await
            .map_err(|_| io::Error::other("input cleanup test worker closed"))?;
        wait_for_input_records(&records, |items| {
            items.contains(&RecordedInput::Action(InputAction::Key {
                code: 4,
                down: true,
            }))
        })
        .await?;

        let peer = host.peer.clone();
        let mut cancel = host.cancel_tx.subscribe();
        drop(host);
        tokio::time::timeout(Duration::from_secs(3), async {
            while !*cancel.borrow() {
                if cancel.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
        wait_for_input_records(&records, |items| {
            items.contains(&RecordedInput::Release(
                nestlink_remote::input::Button::Key(4),
            )) && items.last() == Some(&RecordedInput::Reset)
        })
        .await?;
        assert!(lease.subscribe_stopped().borrow().is_some());
        assert!(tokio::time::timeout(Duration::from_secs(3), worker_done_rx).await??);
        tokio::time::timeout(Duration::from_secs(3), async {
            while peer.connection_state() != RTCPeerConnectionState::Closed {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }

    #[test]
    fn fingerprint_parser_requires_sha256_and_consistent_media_fingerprints() {
        let fingerprint = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
        let sdp = format!(
            "v=0\r\na=fingerprint:sha-256 {fingerprint}\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 {fingerprint}\r\n"
        );
        assert_eq!(dtls_fingerprint(&sdp).ok(), Some(vec![0xab; 32]));
        assert!(dtls_fingerprint("v=0\r\na=fingerprint:sha-1 00:11\r\n").is_err());
        let other = format!(
            "v=0\r\na=fingerprint:sha-256 {fingerprint}\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 {}\r\n",
            "CD:".repeat(31) + "CD"
        );
        assert!(dtls_fingerprint(&other).is_err());
    }

    #[test]
    fn host_requires_receive_only_media_offers() {
        let offer_sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=recvonly\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        assert!(validate_offer_directions(offer_sdp).is_ok());
        let sendrecv = offer_sdp.replace("a=recvonly", "a=sendrecv");
        assert!(validate_offer_directions(&sendrecv).is_err());
        let duplicate_direction = offer_sdp.replace("a=recvonly", "a=recvonly\r\na=inactive");
        assert!(validate_offer_directions(&duplicate_direction).is_err());
    }

    #[test]
    fn host_rejects_trickle_candidate_payloads() {
        let mut offer = SignalPayload {
            ice: None,
            connection_generation: 1,
            lease_sequence: 1,
            network_generation: 1,
            sequence: 1,
            candidates: Vec::new(),
            description: None,
        };
        assert!(require_no_trickle(&offer).is_ok());
        offer.candidates.push(nestlink_protocol::api::Candidate {
            address: std::net::SocketAddr::from(([8, 8, 8, 8], 3478)),
            transport: nestlink_protocol::api::Transport::WebRtc,
            kind: nestlink_protocol::api::CandidateKind::Lan,
            generation: 1,
        });
        assert!(require_no_trickle(&offer).is_err());
    }

    #[tokio::test]
    async fn native_mutual_proof_completes_over_a_real_webrtc_data_channel() -> TestResult {
        let controller = DeviceIdentity::generate();
        let host_identity = DeviceIdentity::generate();
        let permit = test_permit(&controller, &host_identity)?;
        let (mut host_setup, _host_stop_owner) = test_setup(&permit, EndpointRole::Host)?;
        let (mut controller_setup, _controller_stop_owner) =
            test_setup(&permit, EndpointRole::Controller)?;

        let (host_peer, video_track, audio_track, video_sender) =
            make_peer_with_mdns(&permit, false, MulticastDnsMode::Disabled).await?;
        let controller_peer = make_browser_peer().await?;
        let controller_channel = controller_peer
            .create_data_channel(WEBRTC_CONTROL_LABEL, None)
            .await?;

        let (controller_messages_tx, mut controller_messages_rx) =
            mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        controller_channel.on_message(Box::new(move |message| {
            let sender = controller_messages_tx.clone();
            Box::pin(async move {
                let _ = sender.try_send(message.data);
            })
        }));

        let (permit_tx, permit_rx) = watch::channel(permit.clone());
        let (state_tx, state_rx) = watch::channel(host_peer.connection_state());
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (selected_path_tx, _selected_path_rx) = watch::channel(None);
        let (path_authority_tx, _) = watch::channel(true);
        let control = Arc::new(Mutex::new(None));
        let pending_data_channels = Arc::new(Mutex::new(HashMap::new()));
        let (proof_tx, proof_messages) = mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        let (input_tx, input_messages) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let (display_tx, _display_messages) = mpsc::channel(MAX_PENDING_DISPLAY_MESSAGES);
        let proof_complete = Arc::new(AtomicBool::new(false));
        let business_data_proof_complete = Arc::new(AtomicBool::new(false));
        let display_authorized = Arc::new(AtomicBool::new(false));
        install_peer_handlers(
            &host_peer,
            &control,
            &pending_data_channels,
            &cancel_tx,
            &state_tx,
            &permit_rx,
            PeerHandlerMessages {
                proof_messages: proof_tx,
                input_messages: input_tx,
                display_messages: display_tx,
                proof_complete: proof_complete.clone(),
                business_data_proof_complete: business_data_proof_complete.clone(),
                display_authorized,
                input_authorized: permit
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32)),
            },
        );

        let offer = controller_peer.create_offer(None).await?;
        let mut browser_gathered = controller_peer.gathering_complete_promise().await;
        controller_peer.set_local_description(offer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), browser_gathered.recv()).await?;
        assert_eq!(
            controller_peer.ice_gathering_state(),
            RTCIceGatheringState::Complete
        );
        let offer = controller_peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("browser local offer missing"))?;
        host_peer.set_remote_description(offer).await?;

        let answer = host_peer.create_answer(None).await?;
        let mut host_gathered = host_peer.gathering_complete_promise().await;
        host_peer.set_local_description(answer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), host_gathered.recv()).await?;
        assert_eq!(
            host_peer.ice_gathering_state(),
            RTCIceGatheringState::Complete
        );
        let answer = host_peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("host local answer missing"))?;
        controller_peer.set_remote_description(answer).await?;

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let host_channel_open = control
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|channel| channel.ready_state() == RTCDataChannelState::Open);
                if host_channel_open
                    && controller_channel.ready_state() == RTCDataChannelState::Open
                {
                    break;
                }
                if matches!(
                    host_peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) || matches!(
                    controller_peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) {
                    return Err(io::Error::other("loopback WebRTC connection failed"));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), io::Error>(())
        })
        .await??;

        let mut host_peer_state = WebRtcHostPeer {
            peer: host_peer.clone(),
            permit_tx,
            permit_rx,
            input_permits_tx: watch::channel(None).0,
            display_transaction_gate: Arc::new(Mutex::new(())),
            state_rx,
            cancel_tx: cancel_tx.clone(),
            control,
            pending_data_channels,
            proof_messages,
            input_messages: Some(input_messages),
            display_messages: None,
            proof_complete: proof_complete.clone(),
            business_data_proof_complete,
            display_authorized: Arc::new(AtomicBool::new(false)),
            display_selection_sequence: None,
            setup: None,
            media_factory: None,
            lease: None,
            clock: host_setup.clock.clone(),
            cursor: SignalCursor::new(&permit, &host_identity)?,
            signal_sequence: 0,
            local_ice_signal: None,
            remote_offer_sequence: 0,
            remote_ice: nestlink_protocol::ice::IceSnapshotCursor::default(),
            network_generation: 1,
            stun_urls: Vec::new(),
            turn_credentials: None,
            turn_binding_claims: None,
            turn_binding_context: None,
            last_turn_binding_check: Instant::now(),
            selected_path: Path::Direct,
            selected_path_tx,
            path_authority_tx,
            last_refresh: Instant::now(),
            last_renewal_sequence: permit.claims().lease_sequence,
            controller_key: controller.identity.public_key(),
            media: None,
            video_track,
            audio_track,
            video_sender,
            media_started: false,
            stop_monitor: tokio::spawn(std::future::pending()),
            lease_stop_worker: None,
            lease_stop_failed: None,
            input_worker: None,
            display_worker: None,
            data_runtime: None,
            diagnostics: PeerDiagnosticRecorder::default(),
            cleanup_complete: false,
        };

        let controller_transcript = controller_setup.session.proof_transcript();
        let controller_signature = controller.identity.prove(&controller_transcript)?;
        controller_setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &controller.identity.public_key(),
            &controller_signature,
            controller_setup.clock.monotonic_ms(),
        )?;
        let opening = WebRtcControl::EndpointProof {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            proof: NativeProof {
                transcript: Some(controller_transcript.clone()),
                signature: controller_signature,
                peer_transcript_signature: Vec::new(),
            },
        };
        controller_channel
            .send(&Bytes::from(opening.encode_validated(permit.claims())?))
            .await?;

        {
            let proof = tokio::time::timeout(
                ENDPOINT_PROOF_TIMEOUT,
                host_peer_state.complete_native_proof(&mut host_setup, &host_identity, &permit),
            );
            tokio::pin!(proof);
            let middle = tokio::select! {
                result = &mut proof => {
                    result??;
                    return Err(io::Error::other("host proof completed before its challenge was answered").into());
                }
                message = tokio::time::timeout(Duration::from_secs(3), controller_messages_rx.recv()) => {
                    message?.ok_or_else(|| io::Error::other("host proof response channel closed"))?
                }
            };
            let middle = WebRtcControl::decode_validated(&middle, permit.claims())?;
            let (host_transcript, host_signature, peer_signature) = match middle {
                WebRtcControl::EndpointProof { proof, .. } => (
                    proof
                        .transcript
                        .ok_or_else(|| io::Error::other("host transcript missing"))?,
                    proof.signature,
                    proof.peer_transcript_signature,
                ),
                _ => return Err(io::Error::other("host sent an unexpected proof message").into()),
            };
            matches_endpoint_transcript(&controller_transcript, &host_transcript)?;
            verify_endpoint_proof(
                &host_transcript,
                &host_identity.identity.public_key(),
                &host_signature,
            )?;
            verify_endpoint_proof(
                &controller_transcript,
                &host_identity.identity.public_key(),
                &peer_signature,
            )?;
            controller_setup.session.confirm_endpoint(
                EndpointRole::Host,
                &host_identity.identity.public_key(),
                &peer_signature,
                controller_setup.clock.monotonic_ms(),
            )?;

            let final_message = WebRtcControl::EndpointProof {
                schema_version: SCHEMA_VERSION,
                session_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                lease_sequence: permit.claims().lease_sequence,
                proof: NativeProof {
                    transcript: Some(host_transcript.clone()),
                    signature: controller.identity.prove(&host_transcript)?,
                    peer_transcript_signature: Vec::new(),
                },
            };
            controller_channel
                .send(&Bytes::from(
                    final_message.encode_validated(permit.claims())?,
                ))
                .await?;
            proof.await??;
        }

        assert_eq!(host_setup.session.state(), SessionState::Active);
        assert_eq!(controller_setup.session.state(), SessionState::Active);
        proof_complete.store(true, Ordering::Release);
        let unauthorized_input = WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            sequence: 1,
            action: WebRtcInputAction::Key {
                usage: 4,
                down: true,
            },
        };
        // A View-only controller cannot encode this through the contract; send
        // its JSON envelope as a hostile peer to verify the host rejects it.
        controller_channel
            .send(&Bytes::from(serde_json::to_vec(&unauthorized_input)?))
            .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !*cancel_rx.borrow() {
                if cancel_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
        assert!(*cancel_rx.borrow());
        let _ = host_peer_state
            .close_with_reason_report(StopReason::ProtocolViolation)
            .await;
        controller_peer.close().await?;
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordedInput {
        Action(InputAction),
        Release(nestlink_remote::input::Button),
        Reset,
    }

    struct RecordingInputDevice(Arc<std::sync::Mutex<Vec<RecordedInput>>>);

    impl InputDevice for RecordingInputDevice {
        fn reset(&mut self) -> io::Result<()> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("input test records poisoned"))?
                .push(RecordedInput::Reset);
            Ok(())
        }

        fn inject(&mut self, input: nestlink_remote::input::PlatformInput<'_>) -> io::Result<()> {
            let record = match input {
                nestlink_remote::input::PlatformInput::Action(action) => {
                    RecordedInput::Action(action.clone())
                }
                nestlink_remote::input::PlatformInput::Release(button) => {
                    RecordedInput::Release(button)
                }
            };
            self.0
                .lock()
                .map_err(|_| io::Error::other("input test records poisoned"))?
                .push(record);
            Ok(())
        }
    }

    struct EmptyCapture;

    impl CaptureDevice for EmptyCapture {
        fn check(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn poll_frame(&mut self) -> io::Result<Option<nestlink_remote::video::RawFrame>> {
            Ok(None)
        }

        fn reset(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    async fn wait_for_input_records(
        records: &Arc<std::sync::Mutex<Vec<RecordedInput>>>,
        expected: impl Fn(&[RecordedInput]) -> bool,
    ) -> TestResult {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let snapshot = records
                    .lock()
                    .map_err(|_| io::Error::other("input test records poisoned"))?
                    .clone();
                if expected(&snapshot) {
                    return Ok::<(), io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        Ok(())
    }

    async fn send_browser_control(
        channel: &Arc<RTCDataChannel>,
        permit: &VerifiedPermit,
        control: WebRtcControl,
    ) -> TestResult {
        channel
            .send(&Bytes::from(control.encode_validated(permit.claims())?))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn input_uses_the_proved_data_channel_and_drains_before_close() -> TestResult {
        let controller = DeviceIdentity::generate();
        let host_identity = DeviceIdentity::generate();
        let permit = test_permit_with_permissions(
            &controller,
            &host_identity,
            vec![Permission::View, Permission::Input],
        )?;
        let (host_setup, _host_stop_owner) = test_setup(&permit, EndpointRole::Host)?;
        let (mut controller_setup, _controller_stop_owner) =
            test_setup(&permit, EndpointRole::Controller)?;

        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let media_records = records.clone();
        let connection_generation = permit.claims().connection_generation;
        let media_factory: HostMediaFactory = Box::new(move |lease| {
            let layout = InputLayout {
                left: -1920,
                top: 0,
                width: 1920,
                height: 1080,
            };
            let input_epoch = InputEpoch {
                input: 1,
                layout: 1,
                connection: connection_generation,
            };
            let input_controller = InputController::attach(
                lease.clone(),
                RecordingInputDevice(media_records),
                input_epoch,
                layout,
            )?;
            let display = Display {
                source: 1,
                logical: layout,
            };
            let video_epoch = VideoEpoch {
                layout: 1,
                connection: connection_generation,
            };
            let video_controller =
                VideoController::attach(lease, EmptyCapture, video_epoch, vec![display])?;
            let video = HostVideoSource::new(
                video_controller,
                video_epoch,
                display,
                VideoConfig {
                    width: layout.width,
                    height: layout.height,
                    fps: 30,
                    bitrate_kbps: 4_000,
                },
            );
            Ok(
                HostMediaSources::new(video, None).with_input(HostInputSource::new(
                    input_controller,
                    input_epoch,
                    layout,
                )),
            )
        });

        let (host_peer, video_track, audio_track, video_sender) =
            make_peer_with_mdns(&permit, false, MulticastDnsMode::Disabled).await?;
        let controller_peer = make_browser_peer().await?;
        let controller_channel = controller_peer
            .create_data_channel(WEBRTC_CONTROL_LABEL, None)
            .await?;
        let (controller_messages_tx, mut controller_messages_rx) =
            mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        controller_channel.on_message(Box::new(move |message| {
            let sender = controller_messages_tx.clone();
            Box::pin(async move {
                let _ = sender.try_send(message.data);
            })
        }));

        let (permit_tx, permit_rx) = watch::channel(permit.clone());
        let (state_tx, state_rx) = watch::channel(host_peer.connection_state());
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (selected_path_tx, _selected_path_rx) = watch::channel(None);
        let (path_authority_tx, _) = watch::channel(true);
        let control = Arc::new(Mutex::new(None));
        let pending_data_channels = Arc::new(Mutex::new(HashMap::new()));
        let (proof_tx, proof_messages) = mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        let (input_tx, input_messages) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let (display_tx, _display_messages) = mpsc::channel(MAX_PENDING_DISPLAY_MESSAGES);
        let proof_complete = Arc::new(AtomicBool::new(false));
        let business_data_proof_complete = Arc::new(AtomicBool::new(false));
        let display_authorized = Arc::new(AtomicBool::new(false));
        install_peer_handlers(
            &host_peer,
            &control,
            &pending_data_channels,
            &cancel_tx,
            &state_tx,
            &permit_rx,
            PeerHandlerMessages {
                proof_messages: proof_tx,
                input_messages: input_tx,
                display_messages: display_tx,
                proof_complete: proof_complete.clone(),
                business_data_proof_complete: business_data_proof_complete.clone(),
                display_authorized,
                input_authorized: true,
            },
        );

        let offer = controller_peer.create_offer(None).await?;
        let mut browser_gathered = controller_peer.gathering_complete_promise().await;
        controller_peer.set_local_description(offer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), browser_gathered.recv()).await?;
        assert_eq!(
            controller_peer.ice_gathering_state(),
            RTCIceGatheringState::Complete
        );
        let offer = controller_peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("browser local offer missing"))?;
        host_peer.set_remote_description(offer).await?;

        let answer = host_peer.create_answer(None).await?;
        let mut host_gathered = host_peer.gathering_complete_promise().await;
        host_peer.set_local_description(answer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), host_gathered.recv()).await?;
        assert_eq!(
            host_peer.ice_gathering_state(),
            RTCIceGatheringState::Complete
        );
        let answer = host_peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("host local answer missing"))?;
        controller_peer.set_remote_description(answer).await?;

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let host_channel_open = control
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|channel| channel.ready_state() == RTCDataChannelState::Open);
                if host_channel_open
                    && controller_channel.ready_state() == RTCDataChannelState::Open
                {
                    break;
                }
                if matches!(
                    host_peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) || matches!(
                    controller_peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) {
                    return Err(io::Error::other("loopback WebRTC connection failed"));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), io::Error>(())
        })
        .await??;

        let clock = host_setup.clock.clone();
        let mut host_peer_state = WebRtcHostPeer {
            peer: host_peer.clone(),
            permit_tx,
            permit_rx,
            input_permits_tx: watch::channel(None).0,
            display_transaction_gate: Arc::new(Mutex::new(())),
            state_rx,
            cancel_tx: cancel_tx.clone(),
            control,
            pending_data_channels,
            proof_messages,
            input_messages: Some(input_messages),
            display_messages: None,
            proof_complete,
            business_data_proof_complete,
            display_authorized: Arc::new(AtomicBool::new(false)),
            display_selection_sequence: None,
            setup: Some(host_setup),
            media_factory: Some(media_factory),
            lease: None,
            clock,
            cursor: SignalCursor::new(&permit, &host_identity)?,
            signal_sequence: 0,
            local_ice_signal: None,
            remote_offer_sequence: 0,
            remote_ice: nestlink_protocol::ice::IceSnapshotCursor::default(),
            network_generation: 1,
            stun_urls: Vec::new(),
            turn_credentials: None,
            turn_binding_claims: None,
            turn_binding_context: None,
            last_turn_binding_check: Instant::now(),
            selected_path: Path::Direct,
            selected_path_tx,
            path_authority_tx,
            last_refresh: Instant::now(),
            last_renewal_sequence: permit.claims().lease_sequence,
            controller_key: controller.identity.public_key(),
            media: None,
            video_track,
            audio_track,
            video_sender,
            media_started: false,
            stop_monitor: tokio::spawn(std::future::pending()),
            lease_stop_worker: None,
            lease_stop_failed: None,
            input_worker: None,
            display_worker: None,
            data_runtime: None,
            diagnostics: PeerDiagnosticRecorder::default(),
            cleanup_complete: false,
        };

        let controller_transcript = controller_setup.session.proof_transcript();
        let controller_signature = controller.identity.prove(&controller_transcript)?;
        controller_setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &controller.identity.public_key(),
            &controller_signature,
            controller_setup.clock.monotonic_ms(),
        )?;
        let opening = WebRtcControl::EndpointProof {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            proof: NativeProof {
                transcript: Some(controller_transcript.clone()),
                signature: controller_signature,
                peer_transcript_signature: Vec::new(),
            },
        };
        controller_channel
            .send(&Bytes::from(opening.encode_validated(permit.claims())?))
            .await?;

        {
            let proof = tokio::time::timeout(
                ENDPOINT_PROOF_TIMEOUT,
                host_peer_state.complete_endpoint_proof(None, &host_identity),
            );
            tokio::pin!(proof);
            let middle = tokio::select! {
                result = &mut proof => {
                    result??;
                    return Err(io::Error::other("host proof completed before its challenge was answered").into());
                }
                message = tokio::time::timeout(Duration::from_secs(3), controller_messages_rx.recv()) => {
                    message?.ok_or_else(|| io::Error::other("host proof response channel closed"))?
                }
            };
            let middle = WebRtcControl::decode_validated(&middle, permit.claims())?;
            let (host_transcript, host_signature, peer_signature) = match middle {
                WebRtcControl::EndpointProof { proof, .. } => (
                    proof
                        .transcript
                        .ok_or_else(|| io::Error::other("host transcript missing"))?,
                    proof.signature,
                    proof.peer_transcript_signature,
                ),
                _ => return Err(io::Error::other("host sent an unexpected proof message").into()),
            };
            matches_endpoint_transcript(&controller_transcript, &host_transcript)?;
            verify_endpoint_proof(
                &host_transcript,
                &host_identity.identity.public_key(),
                &host_signature,
            )?;
            verify_endpoint_proof(
                &controller_transcript,
                &host_identity.identity.public_key(),
                &peer_signature,
            )?;
            controller_setup.session.confirm_endpoint(
                EndpointRole::Host,
                &host_identity.identity.public_key(),
                &peer_signature,
                controller_setup.clock.monotonic_ms(),
            )?;

            let final_message = WebRtcControl::EndpointProof {
                schema_version: SCHEMA_VERSION,
                session_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                lease_sequence: permit.claims().lease_sequence,
                proof: NativeProof {
                    transcript: Some(host_transcript.clone()),
                    signature: controller.identity.prove(&host_transcript)?,
                    peer_transcript_signature: Vec::new(),
                },
            };
            controller_channel
                .send(&Bytes::from(
                    final_message.encode_validated(permit.claims())?,
                ))
                .await?;
            proof.await??;
        }

        let accepted = tokio::time::timeout(Duration::from_secs(3), controller_messages_rx.recv())
            .await?
            .ok_or_else(|| io::Error::other("host did not accept input proof"))?;
        assert!(matches!(
            WebRtcControl::decode_validated(&accepted, permit.claims())?,
            WebRtcControl::EndpointProofAccepted { .. }
        ));
        let advertised_layout =
            tokio::time::timeout(Duration::from_secs(3), controller_messages_rx.recv())
                .await?
                .ok_or_else(|| io::Error::other("host input layout was not sent"))?;
        assert_eq!(
            WebRtcControl::decode_validated(&advertised_layout, permit.claims())?,
            WebRtcControl::HostInputLayout {
                schema_version: SCHEMA_VERSION,
                session_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                lease_sequence: permit.claims().lease_sequence,
                input_epoch: 1,
                layout_epoch: 1,
                left: -1920,
                top: 0,
                width: 1920,
                height: 1080,
            }
        );

        let lease = host_peer_state
            .lease
            .clone()
            .ok_or_else(|| io::Error::other("proved lease missing"))?;
        let input = host_peer_state
            .media
            .as_mut()
            .and_then(|media| media.input.take())
            .ok_or_else(|| io::Error::other("host input controller missing"))?;
        let input_messages = host_peer_state
            .input_messages
            .take()
            .ok_or_else(|| io::Error::other("host input queue missing"))?;
        host_peer_state.input_worker = Some(spawn_input_control(
            host_peer.clone(),
            cancel_tx.clone(),
            lease,
            input,
            input_messages,
            host_peer_state.input_permits_tx.subscribe(),
            host_peer_state.clock.clone(),
        ));

        let input_binding = |sequence, action| WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            sequence,
            action,
        };
        let key_down = input_binding(
            1,
            WebRtcInputAction::Key {
                usage: 4,
                down: true,
            },
        );
        send_browser_control(&controller_channel, &permit, key_down.clone()).await?;
        // The reliable channel may retransmit an identical final command; the
        // consumer accepts it idempotently without injecting the key twice.
        send_browser_control(&controller_channel, &permit, key_down).await?;
        send_browser_control(
            &controller_channel,
            &permit,
            input_binding(
                2,
                WebRtcInputAction::Pointer {
                    button: Some(1),
                    down: true,
                    x: -1,
                    y: 10,
                },
            ),
        )
        .await?;
        wait_for_input_records(&records, |items| items.len() >= 2).await?;
        assert_eq!(
            records
                .lock()
                .map_err(|_| io::Error::other("input test records poisoned"))?
                .as_slice(),
            &[
                RecordedInput::Action(InputAction::Key {
                    code: 4,
                    down: true
                }),
                RecordedInput::Action(InputAction::Pointer {
                    button: Some(1),
                    down: true,
                    x: -1,
                    y: 10,
                }),
            ]
        );

        let release = WebRtcControl::InputReleaseAll {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
        };
        send_browser_control(&controller_channel, &permit, release).await?;
        wait_for_input_records(&records, |items| {
            items.contains(&RecordedInput::Release(
                nestlink_remote::input::Button::Key(4),
            )) && items.contains(&RecordedInput::Release(
                nestlink_remote::input::Button::Pointer(1),
            ))
        })
        .await?;

        send_browser_control(
            &controller_channel,
            &permit,
            input_binding(
                3,
                WebRtcInputAction::Key {
                    usage: 4,
                    down: true,
                },
            ),
        )
        .await?;
        wait_for_input_records(&records, |items| {
            items
                .iter()
                .filter(|item| {
                    **item
                        == RecordedInput::Action(InputAction::Key {
                            code: 4,
                            down: true,
                        })
                })
                .count()
                == 2
        })
        .await?;
        // The envelope is valid, but the input epoch is stale. The live
        // controller rejects it, ends the lease and releases the held key.
        let stale_layout = WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: 2,
            layout_epoch: 1,
            sequence: 4,
            action: WebRtcInputAction::Key {
                usage: 5,
                down: true,
            },
        };
        send_browser_control(&controller_channel, &permit, stale_layout).await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !*cancel_rx.borrow() {
                if cancel_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
        assert!(*cancel_rx.borrow());
        wait_for_input_records(&records, |items| {
            items
                .iter()
                .filter(|item| {
                    **item == RecordedInput::Release(nestlink_remote::input::Button::Key(4))
                })
                .count()
                == 2
                && items.last() == Some(&RecordedInput::Reset)
        })
        .await?;

        let report = host_peer_state
            .close_with_reason_report(StopReason::ProtocolViolation)
            .await;
        assert!(!report.input_worker_cleanup_failed);
        controller_peer.close().await?;
        Ok(())
    }
}
