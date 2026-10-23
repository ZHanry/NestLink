use nestlink_protocol::service_plane::publication::ServiceEdgeNamespaceView;
use nestlink_protocol::{
    ErrorCode,
    api::*,
    native_displays::{DisplayCatalogKey, DisplayDescriptor},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub(crate) u64);
impl OperationId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authentication {
    Disconnected,
    VerifyingServer,
    SignedOut,
    SigningIn,
    SignedIn,
    Expired,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerView {
    pub origin: String,
    pub deployment_id: String,
    pub approved_issuer: [u8; 32],
    pub verified_health: Option<HealthResponse>,
    pub error: Option<Failure>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationView {
    pub device_id: String,
    pub public_key_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Transport,
    IceConnection,
    Timeout,
    Rejected,
    SignInRequired,
    Trust,
    Invalid,
    Capacity,
    NativeSessionUnavailable,
    NativeSessionCancelled,
    NetworkChanged,
    PermitExpired,
    LocalIdentityRequired,
    CoreStopped,
    StaleGeneration,
    Superseded,
}

/// A stable, non-sensitive error. HTTP URLs, bodies and credential values are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub status: Option<u16>,
    pub code: Option<ErrorCode>,
}
impl Failure {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn local(kind: FailureKind) -> Self {
        Self {
            kind,
            status: None,
            code: None,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn authentication_rejected(&self) -> bool {
        self.kind == FailureKind::SignInRequired
            || self.status == Some(401)
            || self.code == Some(ErrorCode::AuthRequired)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Section<T> {
    pub data: Option<Arc<T>>,
    pub loading: Option<OperationId>,
    pub error: Option<Failure>,
}
impl<T> Default for Section<T> {
    fn default() -> Self {
        Self {
            data: None,
            loading: None,
            error: None,
        }
    }
}
impl<T> Clone for Section<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            loading: self.loading,
            error: self.error.clone(),
        }
    }
}
impl<T> Section<T> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn replace(&mut self, data: T) {
        self.data = Some(Arc::new(data));
        self.error = None;
    }
}

#[derive(Serialize, Deserialize)]
pub struct TrustedDevices {
    pub host_device_id: String,
    pub devices: Vec<TrustedDeviceView>,
}
#[derive(Serialize, Deserialize)]
pub struct HostRemotePassword {
    pub host_device_id: String,
    pub settings: RemotePasswordView,
}
#[derive(Serialize, Deserialize)]
pub struct RemotePasswordOffer {
    pub request_id: String,
    pub settings: RemotePasswordView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionStatus {
    Establishing,
    Connected,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHostStatus {
    Establishing,
    Connected,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionStopReason {
    Revoked,
    Expired,
    TransportLost,
    ProtocolViolation,
    NetworkChanged,
    PlatformChanged,
    Suspended,
    ClockInvalid,
    UserCancelled,
    ExplicitExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionCleanup {
    NotAttached,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSessionEffects {
    pub cancel_channels: bool,
    pub release_inputs: bool,
    pub discard_queues: bool,
    pub close_allocations: bool,
}

/// Sanitized lifecycle facts from the one session owned by the app core.
/// Peer addresses and permit material are deliberately omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSessionView {
    pub request_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub status: NativeSessionStatus,
    /// True only for a connected, locally hosted session whose validated
    /// permit grants View. UI capture sources use this as their authorization gate.
    pub host_view_authorized: bool,
    pub path: Option<i32>,
    pub stop_reason: Option<NativeSessionStopReason>,
    pub stop_effects: Option<NativeSessionEffects>,
    pub cleanup: Option<NativeSessionCleanup>,
    pub failure: Option<Failure>,
}

/// Sanitized state for the independently owned browser-facing host endpoint.
/// Connected is published only after the WebRTC mutual proof and capture attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserHostView {
    pub request_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub status: BrowserHostStatus,
    pub host_view_authorized: bool,
    /// Exact permit/proof identity for this browser endpoint. The Core
    /// generation used by IPC is deliberately separate from this stable
    /// session binding, so ordinary UI actions do not invalidate it.
    pub binding: Option<BrowserHostBinding>,
    /// Candidate screens are exposed only to the local desktop UI. They do
    /// not become capture authority until the exact catalog is approved.
    pub displays: BrowserHostDisplayView,
    pub data: BrowserHostDataView,
    pub path: Option<i32>,
    pub stop_reason: Option<NativeSessionStopReason>,
    pub stop_effects: Option<NativeSessionEffects>,
    pub cleanup: Option<NativeSessionCleanup>,
    pub failure: Option<Failure>,
}

/// Sanitized local display offer for a browser-host session. The catalog key
/// binds consent to one request and proved connection generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserHostDisplayView {
    pub catalog: Option<DisplayCatalogKey>,
    pub displays: Vec<DisplayDescriptor>,
    pub approval_required: bool,
    pub approved_sources: Vec<u32>,
    pub initial_source: Option<u32>,
}

/// Status of the locally approved TCP/UDP/HTTP/HTTPS target host. This never grants a
/// remote peer permission by itself; it reports the daemon-owned runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceHostStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalServiceHostView {
    pub service_id: String,
    pub service_name: String,
    /// The exact revision shown to the local user before approval.
    pub approved_from_revision: u64,
    /// The server's revision returned by target approval, normally N + 1.
    pub approved_revision: Option<u64>,
    pub protocol: String,
    /// Canonical numeric SocketAddr chosen on this device.
    pub address: String,
    pub status: LocalServiceHostStatus,
    /// True means cleanup failed or could not be certified; it is never
    /// represented as Stopped until the runtime reports physical completion.
    pub cleanup_failed: bool,
    pub failure: Option<Failure>,
}

/// Short-lived, one-use preview sent only over mutually authenticated local
/// IPC. The UI must show `service`, `protocol`, and `address`, plus the local
/// TLS identity when HTTPS is selected, before sending the nonce to start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalServiceHostPreview {
    pub nonce: String,
    pub service: ServiceView,
    pub protocol: String,
    pub address: String,
    /// Local HTTPS backend trust is never sent to the management server. Only
    /// its server name and trust-binding digest are echoed for review.
    pub backend_tls_server_name: Option<String>,
    pub backend_tls_sha256: Option<String>,
    pub lifetime_ms: u64,
}

/// User-selected trust for an HTTPS backend. These DER roots only travel over
/// authenticated desktop-to-daemon IPC and are retained by the local owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalHttpsBackendConfig {
    pub server_name: String,
    pub ca_certificates_der: Vec<Vec<u8>>,
}

/// Exact local selection and the snapshot that the user reviewed. This is an
/// application request, not a transferable service authorization.
pub struct LocalServiceHostRequest {
    pub runtime_id: String,
    pub expected_generation: u64,
    pub expected_snapshot_revision: u64,
    pub service_id: String,
    pub service_revision: u64,
    pub definition_sha256: String,
    pub protocol: String,
    pub address: String,
    pub backend_tls: Option<LocalHttpsBackendConfig>,
}

/// Identifies one browser-host proof session independently of UI/action
/// generations and lease renewals. It is never interchangeable with a native
/// session binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserHostBinding {
    pub request_id: String,
    pub session_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub controller_key_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub permit_sha256: [u8; 32],
    pub connection_generation: u64,
}

/// Sanitized browser data consent and selected roots. OS paths and clipboard
/// contents are never part of a Core snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserHostDataView {
    pub files_available: bool,
    pub clipboard_available: bool,
    pub permitted_file_read: bool,
    pub permitted_file_write: bool,
    pub permitted_clipboard_read: bool,
    pub permitted_clipboard_write: bool,
    pub local_file_read: bool,
    pub local_file_write: bool,
    pub local_clipboard_read: bool,
    pub local_clipboard_write: bool,
    /// Once clipboard directions are removed they cannot be re-enabled on the
    /// same proof session; a new browser session is required.
    pub clipboard_restart_required: bool,
    pub read_roots: Vec<BrowserHostFileRootView>,
    pub write_roots: Vec<BrowserHostFileRootView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserHostFileRootView {
    pub root_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Connect,
    SignIn,
    Refresh,
    Logout,
    Load,
    LoadServiceEdgeNamespace,
    SetServiceEdgeNamespace,
    CreateService,
    UpdateService,
    RevokeService,
    EnrollDevice,
    RevokeDevice,
    RequestRemote,
    ApproveRemote,
    RevokeRemote,
    IssueRemotePermit,
    StartNativeSession,
    StopNativeSession,
    StartBrowserHost,
    StopBrowserHost,
    StartLocalServiceHost,
    ChangePassword,
    CreateAccount,
    DisableAccount,
    SetPolicy,
    SetPathLimit,
    SetRelayQuota,
    RegisterNode,
    RevokeNode,
    SetAuditRetention,
    TrustRemote,
    RevokeDeviceTrust,
    ConfigureRemotePassword,
    RevokeRemotePassword,
    AuthorizeRemotePassword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    Superseded,
}
impl OperationStatus {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running | Self::Cancelling)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteEffect {
    None,
    Committed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublicOutput {
    None,
    Created { id: String },
    Revision { revision: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationResult {
    pub id: OperationId,
    pub generation: u64,
    pub kind: OperationKind,
    pub status: OperationStatus,
    pub remote_effect: RemoteEffect,
    pub failure: Option<Failure>,
    pub output: PublicOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub result: OperationResult,
}

/// Each update is a new immutable snapshot. All lists are actual SDK responses;
/// `None` means not loaded, while an empty loaded list means the server returned none.
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub revision: u64,
    pub generation: u64,
    pub lifecycle: Lifecycle,
    pub authentication: Authentication,
    pub server: Option<ServerView>,
    /// An installation fact, not evidence of account ownership or registration.
    pub installation: Option<InstallationView>,
    pub principal: Option<Principal>,
    pub authentication_error: Option<Failure>,
    pub security: Section<MeResponse>,
    pub devices: Section<Vec<DeviceView>>,
    pub services: Section<ServicePage>,
    pub selected_service: Section<ServiceView>,
    #[serde(default)]
    pub service_edge_namespace: Section<ServiceEdgeNamespaceView>,
    pub requests: Section<Vec<RemoteView>>,
    pub selected_request: Section<RemoteView>,
    pub native_session: Section<NativeSessionView>,
    /// This installation's explicit local dialing consent; never server data.
    pub native_network: crate::NativeNetworkSettings,
    /// Independent CAS fence for this installation's local network approval.
    pub native_network_revision: u64,
    /// Last save in this runtime; false means committed with uncertain durability.
    pub native_network_durable: Option<bool>,
    pub browser_host: Section<BrowserHostView>,
    /// Native desktop only. Android and web never create a local target host.
    pub local_service_host: Option<LocalServiceHostView>,
    pub accounts: Section<Vec<AccountView>>,
    pub policy: Section<PolicyResponse>,
    pub path_limits: Section<Vec<PathLimit>>,
    pub relay_quota: Section<RelayQuota>,
    pub relay_usage: Section<RelayUsage>,
    pub nodes: Section<Vec<NodeView>>,
    pub node_usage: Section<NodeUsagePage>,
    pub audit: Section<AuditPage>,
    pub audit_retention: Section<AuditRetention>,
    pub trusted_devices: Section<TrustedDevices>,
    pub remote_password: Section<HostRemotePassword>,
    pub remote_password_offer: Section<RemotePasswordOffer>,
    pub operations: Vec<OperationResult>,
    pub events: Vec<Event>,
    pub event_sequence: u64,
    /// True only after the SDK's actual logout response confirmed revocation.
    pub logout_confirmed: Option<bool>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            generation: 1,
            lifecycle: Lifecycle::Running,
            authentication: Authentication::Disconnected,
            server: None,
            installation: None,
            principal: None,
            authentication_error: None,
            security: Section::default(),
            devices: Section::default(),
            services: Section::default(),
            selected_service: Section::default(),
            service_edge_namespace: Section::default(),
            requests: Section::default(),
            selected_request: Section::default(),
            native_session: Section::default(),
            native_network: crate::NativeNetworkSettings::default(),
            native_network_revision: 0,
            native_network_durable: None,
            browser_host: Section::default(),
            local_service_host: None,
            accounts: Section::default(),
            policy: Section::default(),
            path_limits: Section::default(),
            relay_quota: Section::default(),
            relay_usage: Section::default(),
            nodes: Section::default(),
            node_usage: Section::default(),
            audit: Section::default(),
            audit_retention: Section::default(),
            trusted_devices: Section::default(),
            remote_password: Section::default(),
            remote_password_offer: Section::default(),
            operations: Vec::new(),
            events: Vec::new(),
            event_sequence: 0,
            logout_confirmed: None,
        }
    }
}
impl Snapshot {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn clear_account(&mut self) {
        self.principal = None;
        self.security = Section::default();
        self.devices = Section::default();
        self.services = Section::default();
        self.selected_service = Section::default();
        self.service_edge_namespace = Section::default();
        self.requests = Section::default();
        self.selected_request = Section::default();
        self.accounts = Section::default();
        self.policy = Section::default();
        self.path_limits = Section::default();
        self.relay_quota = Section::default();
        self.relay_usage = Section::default();
        self.nodes = Section::default();
        self.node_usage = Section::default();
        self.audit = Section::default();
        self.audit_retention = Section::default();
        self.trusted_devices = Section::default();
        self.remote_password = Section::default();
        self.remote_password_offer = Section::default();
        self.authentication_error = None;
        self.logout_confirmed = None;
    }
}
