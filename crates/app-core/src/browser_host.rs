//! Browser-facing host lifecycle. Capture providers may prepare local consent
//! or enumerate devices before negotiation, but activate the platform source
//! only from the SDK's post-mutual-proof media factory.

use crate::{BrowserHostBinding, BrowserHostDataView};
use nestlink_identity::VerifiedPermit;
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path, Permission,
    native_displays::{
        DisplayCatalogKey, DisplayDescriptor, catalog_key, validate_candidates, validate_displays,
    },
};
use nestlink_remote::{LeaseControl, RuntimeClock, SessionLifecycle, SessionSetup, StopReport};
use nestlink_sdk::{
    DeviceIdentity, Sdk, SdkError,
    webrtc_host::{HostDataFactory, HostMediaSources, WebRtcHostError, WebRtcHostPeer},
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};

const OFFER_POLL_INTERVAL: Duration = Duration::from_millis(200);
const ACCESS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const DISPLAY_APPROVAL_BUDGET: Duration = Duration::from_secs(120);

pub struct BrowserHostDisplayOffer {
    pub binding: BrowserHostBinding,
    pub catalog: DisplayCatalogKey,
    pub displays: Vec<DisplayDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserHostDisplayApproval {
    pub binding: BrowserHostBinding,
    pub catalog: DisplayCatalogKey,
    pub sources: Vec<u32>,
    pub initial_source: u32,
}

pub struct PreparedBrowserCapture {
    pub displays: Vec<DisplayDescriptor>,
    factory: Box<
        dyn FnOnce(
                BrowserHostDisplayApproval,
                LeaseControl,
                VerifiedPermit,
            ) -> Result<HostMediaSources, WebRtcHostError>
            + Send
            + 'static,
    >,
}
impl PreparedBrowserCapture {
    pub fn new(
        displays: Vec<DisplayDescriptor>,
        factory: impl FnOnce(
            BrowserHostDisplayApproval,
            LeaseControl,
            VerifiedPermit,
        ) -> Result<HostMediaSources, WebRtcHostError>
        + Send
        + 'static,
    ) -> Self {
        Self {
            displays,
            factory: Box::new(factory),
        }
    }
}

/// Prepare consent/device selection only. `PreparedBrowserCapture` is consumed
/// later by `WebRtcHostPeer` after both endpoint proofs succeed.
pub trait BrowserHostCaptureProvider: Send + Sync + 'static {
    /// Prepare local consent without a lease. Capture/input activation must
    /// remain deferred to the factory called after mutual endpoint proof.
    fn prepare_request<'a>(
        &'a self,
        _binding: &'a BrowserHostBinding,
        _permissions: &'a [i32],
        _cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>
    {
        Box::pin(async { Err(BrowserHostError::UnsupportedPermission) })
    }
    fn supports_audio(&self) -> bool {
        false
    }

    fn supports_input(&self) -> bool {
        false
    }

    fn supports_files(&self) -> bool {
        false
    }

    fn supports_clipboard(&self) -> bool {
        false
    }

    /// Prepare local file/clipboard consent and device handles without
    /// opening a remote worker. The returned factory is invoked only after
    /// mutual endpoint proof with the exact one-shot permission claims.
    fn prepare_data<'a>(
        &'a self,
        _request_id: &'a str,
        _permit: &'a VerifiedPermit,
        _cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<HostDataFactory>, BrowserHostError>> + Send + 'a>>
    {
        Box::pin(async { Ok(None) })
    }

    /// The outer request ID is part of the local capture binding; it is not
    /// interchangeable with the signed permit's session ID.
    fn prepare<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<Box<dyn Future<Output = Result<PreparedBrowserCapture, BrowserHostError>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct BrowserHostConfig {
    provider: Arc<dyn BrowserHostCaptureProvider>,
    diagnostics: Option<Arc<dyn Fn(BrowserHostDiagnostic) + Send + Sync>>,
}
impl BrowserHostConfig {
    pub fn new(provider: Arc<dyn BrowserHostCaptureProvider>) -> Self {
        Self {
            provider,
            diagnostics: None,
        }
    }
    pub fn with_diagnostics(
        mut self,
        sink: Arc<dyn Fn(BrowserHostDiagnostic) + Send + Sync>,
    ) -> Self {
        self.diagnostics = Some(sink);
        self
    }
    fn report(&self, event: BrowserHostDiagnostic) {
        if let Some(sink) = &self.diagnostics {
            sink(event);
        }
    }

    pub fn supports_audio(&self) -> bool {
        self.provider.supports_audio()
    }

    pub fn supports_input(&self) -> bool {
        self.provider.supports_input()
    }

    pub fn supports_files(&self) -> bool {
        self.provider.supports_files()
    }

    pub fn supports_clipboard(&self) -> bool {
        self.provider.supports_clipboard()
    }
}

/// One-shot startup and lifecycle channels owned by the browser host task.
pub struct BrowserHostChannels {
    pub cancel: watch::Receiver<bool>,
    pub display_offer: oneshot::Sender<BrowserHostDisplayOffer>,
    pub display_approval: watch::Receiver<Option<BrowserHostDisplayApproval>>,
    pub ready: oneshot::Sender<Result<BrowserHostReady, BrowserHostFailure>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserHostFailure {
    Cancelled,
    Unavailable,
    UnsupportedPermission,
    Capture,
    Transport,
    Connectivity,
    PermitExpired,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserHostDiagnosticStage {
    FetchHostPermit,
    PrepareCapture,
    AwaitDisplayApproval,
    PrepareData,
    ActivateSession,
    CreatePeer,
    HostLoop,
    RefreshSdk,
    AnswerNextOffer,
    Shutdown,
}

/// Fixed error-source labels safe for local fixture diagnostics. Never include
/// the source error's Display/Debug text in this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserHostDiagnosticSource {
    Progress,
    Cancelled,
    Capture,
    UnsupportedPermission,
    HostIdentity,
    SessionBinding,
    ViewRequired,
    SdkTimeout,
    SdkOther,
    WebRtcSdkTimeout,
    WebRtcSdkOther,
    WebRtcEngine,
    WebRtcContract,
    WebRtcIo,
    WebRtcRemote,
    WebRtcPermit,
    WebRtcInvalidOffer,
    WebRtcDirectPathRequired,
    WebRtcRelayPathRequired,
    WebRtcClosed,
    WebRtcConnectTimeout,
    WebRtcGatherTimeout,
    WebRtcControlChannelUnavailable,
    WebRtcRelayPathSelected,
    WebRtcTurnBinding,
    WebRtcRelayUnavailable,
    WebRtcPathConnectTimeout,
    WebRtcEndpointProof,
    WebRtcDisplaySelectionAckTimeout,
    WebRtcBusinessDataChannel,
    WebRtcDataMessageSize,
    ShutdownCleanupFailed,
    ShutdownPeerCloseFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserHostDiagnostic {
    pub request_sha256: [u8; 32],
    pub connection_generation: u64,
    pub timeline: Option<nestlink_sdk::webrtc_host::WebRtcConnectionTimeline>,
    pub stage: BrowserHostDiagnosticStage,
    pub source: BrowserHostDiagnosticSource,
    pub elapsed_ms: u64,
    pub peer: Option<nestlink_sdk::webrtc_host::WebRtcHostDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserHostReady {
    pub binding: BrowserHostBinding,
    pub lease_sequence: u64,
    pub data: BrowserHostDataView,
    pub displays: crate::BrowserHostDisplayView,
    pub path: i32,
}

pub struct BrowserHostExit {
    pub sdk: Sdk,
    pub request_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub binding: Option<BrowserHostBinding>,
    pub data: Option<BrowserHostDataView>,
    pub connected: bool,
    pub path: Option<i32>,
    pub stop: Option<StopReport>,
    pub cleanup_failed: bool,
    pub failure: Option<BrowserHostFailure>,
    pub diagnostic: Option<BrowserHostDiagnostic>,
}

#[derive(Debug, thiserror::Error)]
pub enum BrowserHostError {
    #[error("SDK operation failed: {0}")]
    Sdk(#[from] SdkError),
    #[error("WebRTC host negotiation failed: {0}")]
    WebRtc(#[from] WebRtcHostError),
    #[error("local screen capture preparation failed")]
    Capture,
    #[error("browser host requires View permission")]
    ViewRequired,
    #[error("this browser endpoint does not implement one or more approved permissions")]
    UnsupportedPermission,
    #[error("verified host permit does not belong to this installation")]
    HostIdentity,
    #[error("verified host permit cannot form a host session")]
    SessionBinding,
    #[error("browser host was cancelled")]
    Cancelled,
}

/// Own the SDK and browser peer until remote revocation, expiry, transport
/// failure, or an explicit local stop. `ready` is sent only after the SDK host
/// completed mutual proof and attached real capture sources to that lease.
pub async fn run_browser_host(
    mut sdk: Sdk,
    installation: Arc<DeviceIdentity>,
    request_id: String,
    config: BrowserHostConfig,
    channels: BrowserHostChannels,
) -> BrowserHostExit {
    let BrowserHostChannels {
        mut cancel,
        display_offer,
        mut display_approval,
        ready: ready_sender,
    } = channels;
    let started = Instant::now();
    let request_sha256 = nestlink_identity::digest(request_id.as_bytes());
    let mut ready = Some(ready_sender);
    let mut peer: Option<WebRtcHostPeer> = None;
    let mut stop_owner = None;
    let mut connected = false;
    let mut ready_info: Option<BrowserHostReady> = None;
    let mut failure = None;
    let mut diagnostic_stage = BrowserHostDiagnosticStage::FetchHostPermit;
    let mut diagnostic = None;
    let mut preparation_generation = 0;
    let mut startup_cancel = cancel.clone();

    let startup = async {
        ensure_not_cancelled(&cancel)?;
        diagnostic_stage = BrowserHostDiagnosticStage::FetchHostPermit;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let request = sdk.remote(&request_id).await?;
        preparation_generation = request.connection_generation;
        if request.status != "approved"
            || request.host_device_id != installation.device_id
            || request.connection_generation == 0
        {
            return Err(BrowserHostError::HostIdentity);
        }
        // Existing native test/explicit sessions can already have a permit.
        // Browser inbox sessions prepare local consent before any lease exists.
        let existing_permit = if request.lease_sequence > 0 {
            Some(sdk.host_permit(&installation, &request_id).await?)
        } else {
            None
        };
        let preparation_binding = if let Some(permit) = &existing_permit {
            validate_host_permit(
                permit,
                &installation,
                config.supports_audio(),
                config.supports_input(),
                config.supports_files(),
                config.supports_clipboard(),
            )?;
            browser_host_binding(&request_id, permit)?
        } else {
            // This binding identifies LOCAL consent only. Zero digests cannot
            // activate a session, data worker, capture source or peer proof.
            BrowserHostBinding {
                request_id: request_id.clone(),
                session_id: request_id.clone(),
                controller_device_id: request.controller_device_id.clone(),
                host_device_id: request.host_device_id.clone(),
                controller_key_sha256: [0; 32],
                host_key_sha256: installation.identity.fingerprint(),
                permit_sha256: [0; 32],
                connection_generation: request.connection_generation,
            }
        };
        diagnostic_stage = BrowserHostDiagnosticStage::PrepareCapture;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let preparation_cancel = cancel.clone();
        let preparation = async {
            if let Some(permit) = &existing_permit {
                config
                    .provider
                    .prepare(&request_id, permit, preparation_cancel)
                    .await
            } else {
                config
                    .provider
                    .prepare_request(
                        &preparation_binding,
                        &request.permissions,
                        preparation_cancel,
                    )
                    .await
            }
        };
        let prepared = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
            result = preparation => result?,
        };
        ensure_not_cancelled(&cancel)?;
        validate_candidates(&prepared.displays).map_err(|_| BrowserHostError::Capture)?;
        let catalog = catalog_key(
            &request_id,
            request.connection_generation,
            1,
            &prepared.displays,
        )
        .map_err(|_| BrowserHostError::Capture)?;
        if display_offer
            .send(BrowserHostDisplayOffer {
                binding: preparation_binding.clone(),
                catalog: catalog.clone(),
                displays: prepared.displays.clone(),
            })
            .is_err()
        {
            return Err(BrowserHostError::Cancelled);
        }
        diagnostic_stage = BrowserHostDiagnosticStage::AwaitDisplayApproval;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let mut approval = tokio::time::timeout(DISPLAY_APPROVAL_BUDGET, async {
            loop {
                if let Some(approval) = display_approval.borrow_and_update().clone() {
                    return Ok(approval);
                }
                tokio::select! {
                    biased;
                    _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
                    changed = display_approval.changed() => {
                        if changed.is_err() { return Err(BrowserHostError::Cancelled); }
                    }
                }
            }
        })
        .await
        .map_err(|_| BrowserHostError::Capture)??;
        if approval.binding != preparation_binding
            || approval.catalog != catalog
            || approval.sources.is_empty()
            || approval.sources.len() > prepared.displays.len()
            || approval.sources.windows(2).any(|pair| pair[0] >= pair[1])
            || approval.sources.iter().any(|source| {
                !prepared
                    .displays
                    .iter()
                    .any(|display| display.source == *source)
            })
            || !approval.sources.contains(&approval.initial_source)
        {
            return Err(BrowserHostError::UnsupportedPermission);
        }
        let approved_displays: Vec<_> = prepared
            .displays
            .iter()
            .filter(|display| approval.sources.contains(&display.source))
            .cloned()
            .collect();
        validate_displays(&approved_displays).map_err(|_| BrowserHostError::Capture)?;
        let permit = if let Some(permit) = existing_permit {
            permit
        } else {
            ensure_not_cancelled(&cancel)?;
            sdk.mark_browser_host_ready(&installation, &request).await?;
            diagnostic_stage = BrowserHostDiagnosticStage::FetchHostPermit;
            config.report(BrowserHostDiagnostic {
                request_sha256,
                connection_generation: preparation_generation,
                timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
                stage: diagnostic_stage,
                source: BrowserHostDiagnosticSource::Progress,
                elapsed_ms: elapsed_ms(started),
                peer: None,
            });
            // Keep the wait finite, cancelable, and subject to server-side
            // revocation/policy/login/deadline checks on every observation.
            tokio::time::timeout(DISPLAY_APPROVAL_BUDGET, async {
                loop {
                    ensure_not_cancelled(&cancel)?;
                    let current = sdk.remote(&request_id).await?;
                    if current.status != "approved"
                        || current.connection_generation != request.connection_generation
                        || !sdk.browser_host_readiness(&request_id).await?.ready
                    {
                        return Err(BrowserHostError::SessionBinding);
                    }
                    if current.lease_sequence > 0 {
                        return sdk
                            .host_permit(&installation, &request_id)
                            .await
                            .map_err(BrowserHostError::from);
                    }
                    tokio::select! {
                        biased;
                        _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
                        _ = tokio::time::sleep(OFFER_POLL_INTERVAL) => {}
                    }
                }
            })
            .await
            .map_err(|_| BrowserHostError::SessionBinding)??
        };
        validate_host_permit(
            &permit,
            &installation,
            config.supports_audio(),
            config.supports_input(),
            config.supports_files(),
            config.supports_clipboard(),
        )?;
        let claims = permit.claims();
        if claims.connection_generation != request.connection_generation
            || claims.controller_device_id != request.controller_device_id
            || claims.permissions != request.permissions
            || claims.paths != request.paths
            || claims.policy_revision != request.policy_revision
        {
            return Err(BrowserHostError::SessionBinding);
        }
        let binding = browser_host_binding(&request_id, &permit)?;
        // Rebind only the already-approved local source set after validating
        // the signed permit against the exact preparation request/generation.
        approval.binding = binding.clone();
        let has = |permission: Permission| claims.permissions.contains(&(permission as i32));
        ready_info = Some(BrowserHostReady {
            binding,
            lease_sequence: claims.lease_sequence,
            data: BrowserHostDataView {
                files_available: config.supports_files(),
                clipboard_available: config.supports_clipboard(),
                permitted_file_read: has(Permission::FileRead),
                permitted_file_write: has(Permission::FileWrite),
                permitted_clipboard_read: has(Permission::ClipboardRead),
                permitted_clipboard_write: has(Permission::ClipboardWrite),
                ..BrowserHostDataView::default()
            },
            displays: crate::BrowserHostDisplayView {
                catalog: Some(catalog.clone()),
                displays: approved_displays,
                approval_required: false,
                approved_sources: approval.sources.clone(),
                initial_source: Some(approval.initial_source),
            },
            path: preferred_path(&claims.paths)? as i32,
        });

        let data_requested = claims.permissions.iter().any(|permission| {
            matches!(
                Permission::try_from(*permission),
                Ok(Permission::FileRead
                    | Permission::FileWrite
                    | Permission::ClipboardRead
                    | Permission::ClipboardWrite)
            )
        });
        diagnostic_stage = BrowserHostDiagnosticStage::PrepareData;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let prepared_data = if data_requested {
            let data_cancel = cancel.clone();
            tokio::select! {
                biased;
                _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
                result = config.provider.prepare_data(&request_id, &permit, data_cancel) => result?,
            }
        } else {
            None
        };
        if data_requested && prepared_data.is_none() {
            return Err(BrowserHostError::UnsupportedPermission);
        }
        ensure_not_cancelled(&cancel)?;

        let clock = RuntimeClock::default();
        let request_started_ms = clock.monotonic_ms();
        let now = clock
            .sample()
            .map_err(|_| BrowserHostError::SessionBinding)?;
        let path = Path::try_from(
            ready_info
                .as_ref()
                .ok_or(BrowserHostError::SessionBinding)?
                .path,
        )
        .map_err(|_| BrowserHostError::SessionBinding)?;
        let binding = session_binding(&permit)?;
        diagnostic_stage = BrowserHostDiagnosticStage::ActivateSession;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let session = Session::activate(permit.clone(), binding, path, request_started_ms, now)
            .map_err(|_| BrowserHostError::SessionBinding)?;
        let (stop_tx, stop_rx) = watch::channel(None);
        stop_owner = Some(stop_tx);
        let setup = SessionSetup {
            session,
            path,
            role: EndpointRole::Host,
            clock,
            lifecycle: SessionLifecycle::new(stop_rx),
        };
        let media_permit = permit.clone();
        let mut prepared = Some(prepared.factory);
        let approval_for_media = approval.clone();
        let factory = move |lease| {
            let prepared = prepared.take().ok_or(WebRtcHostError::Closed)?;
            let mut media = prepared(approval_for_media, lease, media_permit)?;
            if let Some(data_factory) = prepared_data {
                media = media.with_data_factory(data_factory);
            }
            Ok(media)
        };
        diagnostic_stage = BrowserHostDiagnosticStage::CreatePeer;
        config.report(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: BrowserHostDiagnosticSource::Progress,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
        let host = if claims.paths.contains(&(Path::Relay as i32)) {
            WebRtcHostPeer::new_with_turn(&sdk, &installation, permit, setup, factory).await?
        } else {
            WebRtcHostPeer::new(&sdk, &installation, permit, setup, factory).await?
        };
        peer = Some(host);
        let mut last_timeline = None;
        let mut last_access_refresh = Instant::now();
        loop {
            diagnostic_stage = BrowserHostDiagnosticStage::HostLoop;
            ensure_not_cancelled(&cancel)?;
            if last_access_refresh.elapsed() >= ACCESS_REFRESH_INTERVAL {
                // Keep the background host authenticated independently while it
                // owns the SDK. The rotated SDK is returned to AppCore on exit.
                diagnostic_stage = BrowserHostDiagnosticStage::RefreshSdk;
                sdk.refresh().await?;
                ensure_not_cancelled(&cancel)?;
                last_access_refresh = Instant::now();
            }
            diagnostic_stage = BrowserHostDiagnosticStage::AnswerNextOffer;
            let answered = tokio::select! {
                biased;
                _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
                result = async {
                    let host = peer.as_mut().ok_or(BrowserHostError::SessionBinding)?;
                    host.answer_next_offer(&sdk, &installation).await.map_err(BrowserHostError::from)
                } => result?,
            };
            let timeline = peer.as_ref().map(WebRtcHostPeer::connection_timeline);
            if timeline != last_timeline {
                config.report(BrowserHostDiagnostic {
                    request_sha256,
                    connection_generation: preparation_generation,
                    timeline,
                    stage: BrowserHostDiagnosticStage::HostLoop,
                    source: BrowserHostDiagnosticSource::Progress,
                    elapsed_ms: elapsed_ms(started),
                    peer: None,
                });
                last_timeline = timeline;
            }
            if answered && !connected {
                connected = true;
                if let Some((_connection_generation, lease_sequence, path)) =
                    peer.as_ref().and_then(WebRtcHostPeer::proved_session_info)
                    && let Some(ready_info) = ready_info.as_mut()
                {
                    ready_info.lease_sequence = lease_sequence;
                    ready_info.path = path as i32;
                }
                if let Some(ready) = ready.take() {
                    if let Some(ready_info) = ready_info.clone() {
                        let _ = ready.send(Ok(ready_info));
                    } else {
                        let _ = ready.send(Err(BrowserHostFailure::Rejected));
                    }
                }
            }
            if !answered {
                tokio::select! {
                    biased;
                    _ = cancelled(&mut cancel) => return Err(BrowserHostError::Cancelled),
                    _ = tokio::time::sleep(OFFER_POLL_INTERVAL) => {}
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), BrowserHostError>(())
    };
    // Include in-flight HTTP reads/writes in the cancellation budget as well
    // as local consent, polling sleeps and peer negotiation.
    let startup = tokio::select! {
        biased;
        _ = cancelled(&mut startup_cancel) => Err(BrowserHostError::Cancelled),
        result = startup => result,
    };

    if let Err(error) = startup {
        failure = Some(classify_failure(&error));
        diagnostic = Some(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: diagnostic_stage,
            source: classify_diagnostic_source(&error),
            elapsed_ms: elapsed_ms(started),
            peer: peer.as_ref().and_then(WebRtcHostPeer::diagnostic),
        });
        if let Some(ready) = ready.take() {
            let _ = ready.send(Err(classify_failure(&error)));
        }
    }

    let reason = if *cancel.borrow() || cancel.has_changed().is_err() {
        StopReason::ExplicitExit
    } else if failure == Some(BrowserHostFailure::Capture) {
        StopReason::PlatformChanged
    } else if matches!(
        failure,
        Some(BrowserHostFailure::Transport | BrowserHostFailure::Connectivity)
    ) {
        StopReason::TransportLost
    } else if failure == Some(BrowserHostFailure::PermitExpired) {
        StopReason::Expired
    } else if failure.is_some() {
        StopReason::ProtocolViolation
    } else {
        StopReason::ExplicitExit
    };
    if let Some(owner) = stop_owner.take() {
        owner.send_replace(Some(reason));
    }
    let close = if let Some(peer) = &mut peer {
        Some(peer.close_with_reason_report(reason).await)
    } else {
        None
    };
    let stop = close.and_then(|report| report.stop);
    let cleanup_failed = close.is_some_and(|report| report.cleanup_failed());
    if cleanup_failed {
        failure.get_or_insert(BrowserHostFailure::Capture);
        diagnostic.get_or_insert(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: BrowserHostDiagnosticStage::Shutdown,
            source: BrowserHostDiagnosticSource::ShutdownCleanupFailed,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
    } else if close.is_some_and(|report| report.peer_close_failed) {
        failure.get_or_insert(BrowserHostFailure::Transport);
        diagnostic.get_or_insert(BrowserHostDiagnostic {
            request_sha256,
            connection_generation: preparation_generation,
            timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
            stage: BrowserHostDiagnosticStage::Shutdown,
            source: BrowserHostDiagnosticSource::ShutdownPeerCloseFailed,
            elapsed_ms: elapsed_ms(started),
            peer: None,
        });
    }

    config.report(diagnostic.unwrap_or(BrowserHostDiagnostic {
        request_sha256,
        connection_generation: preparation_generation,
        timeline: peer.as_ref().map(WebRtcHostPeer::connection_timeline),
        stage: BrowserHostDiagnosticStage::Shutdown,
        source: BrowserHostDiagnosticSource::Progress,
        elapsed_ms: elapsed_ms(started),
        peer: None,
    }));
    BrowserHostExit {
        sdk,
        request_id,
        connection_generation: ready_info.as_ref().map_or(preparation_generation, |ready| {
            ready.binding.connection_generation
        }),
        lease_sequence: ready_info.as_ref().map_or(0, |ready| ready.lease_sequence),
        binding: connected
            .then(|| ready_info.as_ref().map(|ready| ready.binding.clone()))
            .flatten(),
        data: connected
            .then(|| ready_info.as_ref().map(|ready| ready.data.clone()))
            .flatten(),
        connected,
        path: connected
            .then(|| ready_info.as_ref().map(|ready| ready.path))
            .flatten(),
        stop,
        cleanup_failed,
        failure,
        diagnostic,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub fn browser_host_binding(
    request_id: &str,
    permit: &VerifiedPermit,
) -> Result<BrowserHostBinding, BrowserHostError> {
    let claims = permit.claims();
    if !nestlink_protocol::valid_id(request_id) || claims.connection_generation == 0 {
        return Err(BrowserHostError::SessionBinding);
    }
    Ok(BrowserHostBinding {
        request_id: request_id.to_owned(),
        session_id: claims.session_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: fixed_digest(&claims.controller_key_sha256)?,
        host_key_sha256: fixed_digest(&claims.host_key_sha256)?,
        permit_sha256: permit.digest(),
        connection_generation: claims.connection_generation,
    })
}

/// Compare a local pre-lease consent binding with the verified session binding.
/// This only preserves a prepared source selection; it cannot authorize media.
pub fn browser_preparation_matches(
    prepared: &BrowserHostBinding,
    proved: &BrowserHostBinding,
) -> bool {
    if prepared.permit_sha256 != [0; 32] {
        return prepared == proved;
    }
    prepared.controller_key_sha256 == [0; 32]
        && proved.permit_sha256 != [0; 32]
        && proved.controller_key_sha256 != [0; 32]
        && prepared.request_id == proved.request_id
        && prepared.session_id == proved.session_id
        && prepared.controller_device_id == proved.controller_device_id
        && prepared.host_device_id == proved.host_device_id
        && prepared.host_key_sha256 == proved.host_key_sha256
        && prepared.connection_generation != 0
        && prepared.connection_generation == proved.connection_generation
}

fn ensure_not_cancelled(cancel: &watch::Receiver<bool>) -> Result<(), BrowserHostError> {
    if *cancel.borrow() || cancel.has_changed().is_err() {
        Err(BrowserHostError::Cancelled)
    } else {
        Ok(())
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() || cancel.changed().await.is_err() {
            return;
        }
    }
}

fn validate_host_permit(
    permit: &VerifiedPermit,
    installation: &DeviceIdentity,
    supports_audio: bool,
    supports_input: bool,
    supports_files: bool,
    supports_clipboard: bool,
) -> Result<(), BrowserHostError> {
    validate_host_claims(
        permit.claims(),
        installation,
        supports_audio,
        supports_input,
        supports_files,
        supports_clipboard,
    )
}

fn validate_host_claims(
    claims: &nestlink_protocol::PermitClaims,
    installation: &DeviceIdentity,
    supports_audio: bool,
    supports_input: bool,
    supports_files: bool,
    supports_clipboard: bool,
) -> Result<(), BrowserHostError> {
    if claims.host_device_id != installation.device_id
        || claims.host_key_sha256.as_slice() != installation.identity.fingerprint()
    {
        return Err(BrowserHostError::HostIdentity);
    }
    if !claims.permissions.contains(&(Permission::View as i32)) {
        return Err(BrowserHostError::ViewRequired);
    }
    let supported_audio =
        supports_audio && claims.required_capabilities.iter().any(|v| v == "opus");
    for permission in &claims.permissions {
        let supported = *permission == Permission::View as i32
            || (*permission == Permission::Audio as i32 && supported_audio)
            || (*permission == Permission::Input as i32 && supports_input)
            || matches!(
                Permission::try_from(*permission),
                Ok(Permission::FileRead | Permission::FileWrite) if supports_files
            )
            || matches!(
                Permission::try_from(*permission),
                Ok(Permission::ClipboardRead | Permission::ClipboardWrite) if supports_clipboard
            );
        if !supported {
            return Err(BrowserHostError::UnsupportedPermission);
        }
    }
    if claims.required_capabilities.iter().any(|capability| {
        !(matches!(
            capability.as_str(),
            "vp8" | "webrtc-trickle-v1" | "setup-budget-v1"
        ) || (supported_audio && capability == "opus"))
    }) {
        return Err(BrowserHostError::UnsupportedPermission);
    }
    Ok(())
}

fn preferred_path(paths: &[i32]) -> Result<Path, BrowserHostError> {
    if paths.contains(&(Path::Direct as i32)) {
        Ok(Path::Direct)
    } else if paths.contains(&(Path::Relay as i32)) {
        Ok(Path::Relay)
    } else {
        Err(BrowserHostError::SessionBinding)
    }
}

fn session_binding(permit: &VerifiedPermit) -> Result<SessionBinding, BrowserHostError> {
    let claims = permit.claims();
    Ok(SessionBinding {
        deployment_id: claims.deployment_id.clone(),
        security_epoch: claims.security_epoch,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: fixed_digest(&claims.controller_key_sha256)?,
        host_key_sha256: fixed_digest(&claims.host_key_sha256)?,
        resource_id: claims.resource_id.clone(),
        policy_revision: claims.policy_revision,
        connection_generation: claims.connection_generation,
        capability_sha256: fixed_digest(&claims.capability_sha256)?,
        granted_permissions: claims
            .permissions
            .iter()
            .map(|permission| {
                Permission::try_from(*permission).map_err(|_| BrowserHostError::SessionBinding)
            })
            .collect::<Result<_, _>>()?,
        supported_capabilities: claims
            .required_capabilities
            .iter()
            .filter(|capability| {
                matches!(
                    capability.as_str(),
                    "vp8" | "opus" | "webrtc-trickle-v1" | "setup-budget-v1"
                )
            })
            .cloned()
            .collect(),
        local_paths: PathSet::from_wire(&claims.paths)
            .map_err(|_| BrowserHostError::SessionBinding)?,
    })
}

fn fixed_digest(value: &[u8]) -> Result<[u8; 32], BrowserHostError> {
    value
        .try_into()
        .map_err(|_| BrowserHostError::SessionBinding)
}

fn classify_failure(error: &BrowserHostError) -> BrowserHostFailure {
    match error {
        BrowserHostError::Cancelled => BrowserHostFailure::Cancelled,
        BrowserHostError::Capture => BrowserHostFailure::Capture,
        BrowserHostError::UnsupportedPermission => BrowserHostFailure::UnsupportedPermission,
        BrowserHostError::HostIdentity
        | BrowserHostError::SessionBinding
        | BrowserHostError::ViewRequired => BrowserHostFailure::Rejected,
        BrowserHostError::WebRtc(WebRtcHostError::Permit) => BrowserHostFailure::PermitExpired,
        BrowserHostError::WebRtc(WebRtcHostError::GatherTimeout)
        | BrowserHostError::WebRtc(WebRtcHostError::ConnectTimeout)
        | BrowserHostError::WebRtc(WebRtcHostError::PathConnectTimeout) => {
            BrowserHostFailure::Connectivity
        }
        BrowserHostError::WebRtc(WebRtcHostError::Io(_)) => BrowserHostFailure::Capture,
        BrowserHostError::Sdk(_) | BrowserHostError::WebRtc(_) => BrowserHostFailure::Transport,
    }
}

fn classify_diagnostic_source(error: &BrowserHostError) -> BrowserHostDiagnosticSource {
    use BrowserHostDiagnosticSource as Source;
    use WebRtcHostError as WebRtc;

    match error {
        BrowserHostError::Cancelled => Source::Cancelled,
        BrowserHostError::Capture => Source::Capture,
        BrowserHostError::UnsupportedPermission => Source::UnsupportedPermission,
        BrowserHostError::HostIdentity => Source::HostIdentity,
        BrowserHostError::SessionBinding => Source::SessionBinding,
        BrowserHostError::ViewRequired => Source::ViewRequired,
        BrowserHostError::Sdk(SdkError::Timeout) => Source::SdkTimeout,
        BrowserHostError::Sdk(_) => Source::SdkOther,
        BrowserHostError::WebRtc(WebRtc::Sdk(SdkError::Timeout)) => Source::WebRtcSdkTimeout,
        BrowserHostError::WebRtc(WebRtc::Sdk(_)) => Source::WebRtcSdkOther,
        BrowserHostError::WebRtc(WebRtc::WebRtc(_)) => Source::WebRtcEngine,
        BrowserHostError::WebRtc(WebRtc::Contract(_)) => Source::WebRtcContract,
        BrowserHostError::WebRtc(WebRtc::Io(_)) => Source::WebRtcIo,
        BrowserHostError::WebRtc(WebRtc::Remote(_)) => Source::WebRtcRemote,
        BrowserHostError::WebRtc(WebRtc::Permit) => Source::WebRtcPermit,
        BrowserHostError::WebRtc(WebRtc::InvalidOffer) => Source::WebRtcInvalidOffer,
        BrowserHostError::WebRtc(WebRtc::DirectPathRequired) => Source::WebRtcDirectPathRequired,
        BrowserHostError::WebRtc(WebRtc::RelayPathRequired) => Source::WebRtcRelayPathRequired,
        BrowserHostError::WebRtc(WebRtc::Closed) => Source::WebRtcClosed,
        BrowserHostError::WebRtc(WebRtc::ConnectTimeout) => Source::WebRtcConnectTimeout,
        BrowserHostError::WebRtc(WebRtc::GatherTimeout) => Source::WebRtcGatherTimeout,
        BrowserHostError::WebRtc(WebRtc::ControlChannelUnavailable) => {
            Source::WebRtcControlChannelUnavailable
        }
        BrowserHostError::WebRtc(WebRtc::RelayPathSelected) => Source::WebRtcRelayPathSelected,
        BrowserHostError::WebRtc(WebRtc::TurnBinding) => Source::WebRtcTurnBinding,
        BrowserHostError::WebRtc(WebRtc::RelayUnavailable) => Source::WebRtcRelayUnavailable,
        BrowserHostError::WebRtc(WebRtc::PathConnectTimeout) => Source::WebRtcPathConnectTimeout,
        BrowserHostError::WebRtc(WebRtc::EndpointProof) => Source::WebRtcEndpointProof,
        BrowserHostError::WebRtc(WebRtc::DisplaySelectionAckTimeout) => {
            Source::WebRtcDisplaySelectionAckTimeout
        }
        BrowserHostError::WebRtc(WebRtc::BusinessDataChannel) => Source::WebRtcBusinessDataChannel,
        BrowserHostError::WebRtc(WebRtc::DataMessageSize) => Source::WebRtcDataMessageSize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_rebinding_preserves_both_devices_generation_and_local_host_key() {
        let prepared = BrowserHostBinding {
            request_id: "request".into(),
            session_id: "request".into(),
            controller_device_id: "controller".into(),
            host_device_id: "host".into(),
            controller_key_sha256: [0; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [0; 32],
            connection_generation: 1,
        };
        assert!(!browser_preparation_matches(&prepared, &prepared));
        let proved = BrowserHostBinding {
            controller_key_sha256: [1; 32],
            permit_sha256: [3; 32],
            ..prepared.clone()
        };
        assert!(browser_preparation_matches(&prepared, &proved));
        for changed in [
            BrowserHostBinding {
                request_id: "other".into(),
                ..proved.clone()
            },
            BrowserHostBinding {
                session_id: "other".into(),
                ..proved.clone()
            },
            BrowserHostBinding {
                controller_device_id: "other".into(),
                ..proved.clone()
            },
            BrowserHostBinding {
                host_device_id: "other".into(),
                ..proved.clone()
            },
            BrowserHostBinding {
                host_key_sha256: [4; 32],
                ..proved.clone()
            },
            BrowserHostBinding {
                connection_generation: 2,
                ..proved.clone()
            },
        ] {
            assert!(!browser_preparation_matches(&prepared, &changed));
        }
        assert!(browser_preparation_matches(&proved, &proved));
        let renewed = BrowserHostBinding {
            permit_sha256: [4; 32],
            ..proved.clone()
        };
        assert!(!browser_preparation_matches(&proved, &renewed));
    }

    fn claims_for(installation: &DeviceIdentity) -> nestlink_protocol::PermitClaims {
        nestlink_protocol::PermitClaims {
            host_device_id: installation.device_id.clone(),
            host_key_sha256: installation.identity.fingerprint().to_vec(),
            permissions: vec![Permission::View as i32],
            required_capabilities: vec!["vp8".into()],
            ..Default::default()
        }
    }

    #[test]
    fn browser_host_accepts_only_a_matching_view_only_vp8_permit() {
        let installation = DeviceIdentity::generate();
        let claims = claims_for(&installation);

        assert!(validate_host_claims(&claims, &installation, false, false, false, false).is_ok());
    }

    #[test]
    fn browser_host_rejects_missing_view_extra_permissions_and_unsupported_codecs() {
        let installation = DeviceIdentity::generate();
        let mut claims = claims_for(&installation);

        claims.permissions.clear();
        assert!(matches!(
            validate_host_claims(&claims, &installation, false, false, false, false),
            Err(BrowserHostError::ViewRequired)
        ));

        claims.permissions = vec![Permission::View as i32, Permission::Input as i32];
        assert!(matches!(
            validate_host_claims(&claims, &installation, false, false, false, false),
            Err(BrowserHostError::UnsupportedPermission)
        ));
        assert!(validate_host_claims(&claims, &installation, false, true, false, false).is_ok());

        claims.permissions = vec![Permission::View as i32];
        claims.required_capabilities = vec!["h264".into()];
        assert!(matches!(
            validate_host_claims(&claims, &installation, false, false, false, false),
            Err(BrowserHostError::UnsupportedPermission)
        ));
    }

    #[test]
    fn browser_host_rejects_permits_bound_to_another_installation() {
        let installation = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let claims = claims_for(&other);

        assert!(matches!(
            validate_host_claims(&claims, &installation, false, false, false, false),
            Err(BrowserHostError::HostIdentity)
        ));
    }

    #[test]
    fn direct_path_is_preferred_and_an_empty_path_set_is_rejected() {
        assert!(matches!(
            preferred_path(&[Path::Relay as i32, Path::Direct as i32]),
            Ok(Path::Direct)
        ));
        assert!(matches!(
            preferred_path(&[]),
            Err(BrowserHostError::SessionBinding)
        ));
    }
}
