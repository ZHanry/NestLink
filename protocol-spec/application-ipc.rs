// This is the application IPC's single Rust/JSON source. The local TLS transport
// is separately specified in local-ipc.json; it cannot confer remote authority.
use crate::browser_data::{BrowserHostDataCommand, BrowserHostDataReply};
use crate::files::{NativeFileCommand, NativeFileReply};
use crate::privileged_input::{PrivilegedInputAction, PrivilegedInputResult};
use nestlink_app_core::{
    Action, ApprovedServer, BrowserHostBinding, DisplayCatalogKey, LocalHttpsBackendConfig,
    LocalServiceHostPreview, NativeClipboardAction, NativeClipboardBinding, NativeClipboardEffect,
    NativeClipboardStatus, NativeDisplayRequest, NativeDisplayState, NativeInputAction,
    NativeInputBinding, NativeInputLayout, NativeSessionBinding, OperationId, OperationResult,
    Snapshot,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub runtime_id: String,
    pub sequence: u64,
    pub expected_generation: u64,
    pub command: Command,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    OpenNativeCompressedVideo {
        open: crate::compressed_video::NativeCompressedOpen,
    },
    OpenNativeCompressedData {
        ticket: [u8; 32],
    },
    #[serde(deserialize_with = "empty_command")]
    Snapshot,
    /// Changes only this device's locally persisted dialing consent.
    ConfigureNativeNetwork {
        expected_revision: u64,
        settings: nestlink_app_core::NativeNetworkSettings,
    },
    /// Start is sent only after an explicit local user click.
    PrivilegedInput {
        action: PrivilegedInputAction,
    },
    Connect {
        server: ApprovedServer,
    },
    Submit {
        action: Action,
    },
    GetNativeDisplays {
        binding: NativeSessionBinding,
    },
    /// Local Windows/X11 consent, bound to the read-only enumeration hash.
    ApproveNativeDisplays {
        binding: NativeSessionBinding,
        catalog: DisplayCatalogKey,
        sources: Vec<u32>,
        initial_source: u32,
    },
    /// Controller selection cannot expand the host's locally approved set.
    SelectNativeDisplay {
        binding: NativeSessionBinding,
        request: NativeDisplayRequest,
    },
    /// Opens a dedicated binary-only stream on this authenticated TLS
    /// connection after the daemon confirms the current View session binding.
    OpenNativeVideo {
        request_id: String,
        connection_generation: u64,
        source: u32,
    },
    /// Reads the current AppCore-owned, input-authorized display layout. The
    /// session fields are checked against both the snapshot and native route.
    GetNativeInputLayout {
        request_id: String,
        connection_generation: u64,
        source: u32,
    },
    /// Sends one bounded action on the current, authorized native Input route.
    SendNativeInput {
        binding: NativeInputBinding,
        action: NativeInputAction,
    },
    /// Releases all held remote input on this exact authorized route.
    ReleaseNativeInput {
        binding: NativeInputBinding,
    },
    NativeFiles {
        binding: NativeSessionBinding,
        action: NativeFileCommand,
    },
    /// Local task facts and cleanup remain available without an old session.
    NativeDownloadRecovery {
        action: nestlink_protocol::file_recovery::DownloadRecoveryCommand,
    },
    /// Mutates browser-host local data consent under the exact proof binding.
    /// `expected_generation` on the outer Request remains an independent stale-action fence.
    BrowserHostData {
        binding: BrowserHostBinding,
        action: BrowserHostDataCommand,
    },
    /// Explicitly approve a subset of one exact browser-host local catalog.
    /// This grants capture only within these source IDs and initial source.
    ApproveBrowserHostDisplays {
        binding: BrowserHostBinding,
        catalog: DisplayCatalogKey,
        sources: Vec<u32>,
        initial_source: u32,
    },
    /// Creates a one-use, short-lived preview from the selected Core service
    /// and a literal local SocketAddr. The server never supplies the target.
    PreviewLocalServiceHost {
        service_id: String,
        service_revision: u64,
        definition_sha256: String,
        expected_snapshot_revision: u64,
        protocol: String,
        address: String,
        /// Explicit, local-only HTTPS backend trust. Never sourced from the
        /// server and never echoed back in the preview response.
        backend_tls: Option<LocalHttpsBackendConfig>,
    },
    /// Consumes a preview nonce after the UI has shown the exact service,
    /// revision, protocol, address and (for HTTPS) the local trust identity.
    StartLocalServiceHost {
        preview_nonce: String,
    },
    /// Revokes the daemon-owned local target immediately and retains cleanup.
    StopLocalServiceHost,
    #[serde(deserialize_with = "empty_command")]
    GetNativeClipboardStatus,
    SetNativeClipboardDirections {
        binding: NativeClipboardBinding,
        read: bool,
        write: bool,
    },
    RunNativeClipboardAction {
        binding: NativeClipboardBinding,
        action: NativeClipboardAction,
    },
    #[serde(deserialize_with = "empty_command")]
    Logout,
    Cancel {
        operation: OperationId,
    },
    Completion {
        operation: OperationId,
    },
    #[serde(deserialize_with = "empty_command")]
    Exit,
}
fn empty_command<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}
impl Command {
    pub fn mutates(&self) -> bool {
        !matches!(
            self,
            Self::Snapshot
                | Self::Completion { .. }
                | Self::GetNativeClipboardStatus
                | Self::GetNativeDisplays { .. }
                | Self::PrivilegedInput {
                    action: PrivilegedInputAction::Status
                }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    StaleGeneration,
    Capacity,
    Invalid,
    Stopped,
    UnknownOperation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitResult {
    Complete,
    Pending,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClipboardRejection {
    StaleBinding,
    Unauthorized,
    LocalConsentRequired,
    ReestablishSession,
    PlatformUnavailable,
    Transport,
    Stopped,
    Cleanup,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub runtime_id: String,
    pub sequence: u64,
    pub snapshot: Arc<Snapshot>,
    pub result: Reply,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    CompressedVideoOpened {
        context: crate::compressed_video::CompressedContext,
        ticket: [u8; 32],
    },
    CompressedDataOpened,
    Snapshot,
    NativeNetworkConfigured {
        result:
            Result<nestlink_app_core::NativeNetworkSettings, nestlink_app_core::NativeNetworkError>,
    },
    PrivilegedInput {
        generation: u64,
        result: PrivilegedInputResult,
    },
    Accepted {
        operation: OperationId,
    },
    Pending {
        operation: OperationId,
    },
    Completed {
        operation: OperationResult,
        sensitive: Option<SensitiveReply>,
    },
    /// The JSON control response is followed by bounded binary media frames
    /// on this connection; it is not an operation and carries no authority.
    NativeDisplays {
        binding: NativeSessionBinding,
        state: Option<NativeDisplayState>,
    },
    VideoStreamOpened {
        connection_generation: u64,
        source: u32,
    },
    NativeInputLayout {
        layout: Option<NativeInputLayout>,
    },
    NativeInputAccepted,
    NativeInputReleased,
    NativeFiles {
        binding: NativeSessionBinding,
        generation: u64,
        result: NativeFileReply,
    },
    NativeDownloadRecovery {
        generation: u64,
        result: nestlink_protocol::file_recovery::DownloadRecoveryReply,
    },
    BrowserHostData {
        binding: BrowserHostBinding,
        generation: u64,
        result: BrowserHostDataReply,
    },
    BrowserHostDisplaysApproved {
        result: Result<(), nestlink_app_core::BrowserHostDisplayError>,
    },
    LocalServiceHostPreview {
        preview: LocalServiceHostPreview,
    },
    LocalServiceHostStopped {
        accepted: bool,
    },
    NativeClipboardStatus {
        status: Option<NativeClipboardStatus>,
    },
    NativeClipboardDirectionsSet {
        status: NativeClipboardStatus,
    },
    NativeClipboardActionResult {
        effect: NativeClipboardEffect,
    },
    NativeClipboardRejected {
        reason: NativeClipboardRejection,
    },
    Cancelled {
        accepted: bool,
    },
    Rejected {
        reason: Rejection,
    },
    Exited {
        result: ExitResult,
    },
}
/// A consumed sensitive delivery, excluded from snapshots and reusable history.
/// Serializing it is permitted only into the authenticated transient IPC frame.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SensitiveReply {}
