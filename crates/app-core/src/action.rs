use crate::OperationKind;
#[cfg(not(target_arch = "wasm32"))]
use crate::Snapshot;
use nestlink_auth::Secret;
use nestlink_protocol::api::*;
use serde::{Deserialize, Serialize};

/// Configuration must come from an explicitly approved trust anchor. This type
/// never learns an issuer from the endpoint being connected to.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedServer {
    pub origin: String,
    pub deployment_id: String,
    pub permit_issuer: [u8; 32],
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Page {
    AccountSecurity,
    Devices,
    Services,
    Requests,
    Accounts,
    Policy,
    PathLimits,
    RelayQuota,
    RelayUsage,
    Nodes,
    AuditRetention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAccess {
    LocalApproval,
    TrustedDevice,
}

/// No `Debug` or `Clone`: secret-bearing inputs are moved into the owner.
/// Serialization is exclusively for authenticated, bounded local IPC. Bindings
/// must not log, persist, or include these inputs in an operation history.
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    SignIn {
        username: String,
        #[serde(with = "secret")]
        password: Secret,
        #[serde(default, with = "optional_secret")]
        factor: Option<Secret>,
    },
    #[serde(deserialize_with = "empty_action")]
    RefreshSession,
    Load {
        page: Page,
    },
    LoadServicesPage {
        after_id: Option<String>,
        limit: u16,
    },
    InspectService {
        service_id: String,
    },
    CreateService {
        create: ServiceCreate,
    },
    UpdateService {
        service_id: String,
        update: ServiceUpdate,
    },
    RevokeService {
        service_id: String,
        expected_revision: u64,
    },
    LoadAudit {
        after_sequence: u64,
        limit: u16,
    },
    LoadNodeUsage {
        node_id: String,
        after_generation: u64,
        limit: u16,
    },
    InspectRemote {
        request_id: String,
    },
    IssueRemotePermit {
        request_id: String,
    },
    /// Start the app-core-owned native session after fresh permit validation
    /// and mutual endpoint proof. This is not satisfied by approval alone.
    StartNativeSession {
        request_id: String,
    },
    /// Stop only the currently displayed request/generation pair.
    StopNativeSession {
        request_id: String,
        connection_generation: u64,
    },
    /// Start a host-side browser session for the currently approved request.
    /// Browser capture is opened only after the signed mutual endpoint proof.
    StartBrowserHost {
        request_id: String,
    },
    /// Stop the matching app-core-owned browser host session.
    StopBrowserHost {
        request_id: String,
        connection_generation: u64,
    },
    EnrollLocalDevice {
        name: String,
        platform: String,
        capabilities: Vec<String>,
        path_mode: String,
    },
    RevokeDevice {
        device_id: String,
    },
    RequestRemote {
        host_device_id: String,
        permissions: Vec<i32>,
        path_mode: String,
        access: RemoteAccess,
    },
    ApproveRemote {
        request_id: String,
        expected_nonce: String,
        expected_policy_revision: u64,
        choice: ApprovalChoice,
    },
    RevokeRemote {
        request_id: String,
    },
    BeginTotp {
        #[serde(with = "secret")]
        password: Secret,
        #[serde(default, with = "optional_secret")]
        factor: Option<Secret>,
    },
    ConfirmTotp {
        #[serde(with = "secret")]
        code: Secret,
    },
    ResetRecovery {
        #[serde(with = "secret")]
        password: Secret,
        #[serde(with = "secret")]
        factor: Secret,
    },
    ChangePassword {
        #[serde(with = "secret")]
        current_password: Secret,
        #[serde(with = "secret")]
        new_password: Secret,
        #[serde(default, with = "optional_secret")]
        factor: Option<Secret>,
    },
    CreateAccount {
        username: String,
        #[serde(with = "secret")]
        password: Secret,
    },
    DisableAccount {
        account_id: String,
    },
    SetPolicy {
        update: PolicyUpdate,
    },
    SetPathLimit {
        scope: String,
        resource_id: String,
        update: PathLimitUpdate,
    },
    SetRelayQuota {
        update: RelayQuotaUpdate,
    },
    RegisterNode {
        node: NodeRegistration,
    },
    RevokeNode {
        node_id: String,
    },
    SetAuditRetention {
        update: AuditRetentionUpdate,
    },
    LoadTrustedDevices {
        host_device_id: String,
    },
    TrustRemote {
        request_id: String,
        choice: TrustChoice,
    },
    RevokeDeviceTrust {
        host_device_id: String,
        controller_device_id: String,
        expected_revision: u64,
    },
    LoadRemotePassword {
        host_device_id: String,
    },
    LoadRemotePasswordOffer {
        request_id: String,
    },
    ConfigureRemotePassword {
        settings: RemotePasswordSettings,
        #[serde(with = "secret")]
        password: Secret,
    },
    RevokeRemotePassword {
        expected_revision: u64,
    },
    AuthorizeRemotePassword {
        request_id: String,
        expected_revision: u64,
        #[serde(with = "secret")]
        password: Secret,
    },
}
impl Action {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::SignIn { .. } => OperationKind::SignIn,
            Self::RefreshSession => OperationKind::Refresh,
            Self::Load { .. }
            | Self::LoadServicesPage { .. }
            | Self::InspectService { .. }
            | Self::LoadAudit { .. }
            | Self::LoadNodeUsage { .. }
            | Self::InspectRemote { .. }
            | Self::LoadTrustedDevices { .. }
            | Self::LoadRemotePassword { .. }
            | Self::LoadRemotePasswordOffer { .. } => OperationKind::Load,
            Self::CreateService { .. } => OperationKind::CreateService,
            Self::UpdateService { .. } => OperationKind::UpdateService,
            Self::RevokeService { .. } => OperationKind::RevokeService,
            Self::EnrollLocalDevice { .. } => OperationKind::EnrollDevice,
            Self::RevokeDevice { .. } => OperationKind::RevokeDevice,
            Self::RequestRemote { .. } => OperationKind::RequestRemote,
            Self::ApproveRemote { .. } => OperationKind::ApproveRemote,
            Self::RevokeRemote { .. } => OperationKind::RevokeRemote,
            Self::IssueRemotePermit { .. } => OperationKind::IssueRemotePermit,
            Self::StartNativeSession { .. } => OperationKind::StartNativeSession,
            Self::StopNativeSession { .. } => OperationKind::StopNativeSession,
            Self::StartBrowserHost { .. } => OperationKind::StartBrowserHost,
            Self::StopBrowserHost { .. } => OperationKind::StopBrowserHost,
            Self::BeginTotp { .. } => OperationKind::BeginTotp,
            Self::ConfirmTotp { .. } => OperationKind::ConfirmTotp,
            Self::ResetRecovery { .. } => OperationKind::ResetRecovery,
            Self::ChangePassword { .. } => OperationKind::ChangePassword,
            Self::CreateAccount { .. } => OperationKind::CreateAccount,
            Self::DisableAccount { .. } => OperationKind::DisableAccount,
            Self::SetPolicy { .. } => OperationKind::SetPolicy,
            Self::SetPathLimit { .. } => OperationKind::SetPathLimit,
            Self::SetRelayQuota { .. } => OperationKind::SetRelayQuota,
            Self::RegisterNode { .. } => OperationKind::RegisterNode,
            Self::RevokeNode { .. } => OperationKind::RevokeNode,
            Self::SetAuditRetention { .. } => OperationKind::SetAuditRetention,
            Self::TrustRemote { .. } => OperationKind::TrustRemote,
            Self::RevokeDeviceTrust { .. } => OperationKind::RevokeDeviceTrust,
            Self::ConfigureRemotePassword { .. } => OperationKind::ConfigureRemotePassword,
            Self::RevokeRemotePassword { .. } => OperationKind::RevokeRemotePassword,
            Self::AuthorizeRemotePassword { .. } => OperationKind::AuthorizeRemotePassword,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn sensitive(&self) -> bool {
        matches!(
            self,
            Self::BeginTotp { .. } | Self::ConfirmTotp { .. } | Self::ResetRecovery { .. }
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn reauthentication(&self) -> bool {
        matches!(
            self,
            Self::BeginTotp { .. }
                | Self::ConfirmTotp { .. }
                | Self::ResetRecovery { .. }
                | Self::ChangePassword { .. }
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn local_identity(&self) -> bool {
        matches!(
            self,
            Self::EnrollLocalDevice { .. }
                | Self::RequestRemote { .. }
                | Self::ApproveRemote { .. }
                | Self::StartNativeSession { .. }
                | Self::StopNativeSession { .. }
                | Self::StartBrowserHost { .. }
                | Self::StopBrowserHost { .. }
                | Self::TrustRemote { .. }
                | Self::ConfigureRemotePassword { .. }
                | Self::RevokeRemotePassword { .. }
                | Self::AuthorizeRemotePassword { .. }
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn valid_input(&self) -> bool {
        use nestlink_protocol::valid_id;
        let short = |s: &str| s.len() <= 128;
        let password = |s: &Secret| s.expose().len() <= 1024;
        let factor = |s: &Option<Secret>| s.as_ref().is_none_or(|s| s.expose().len() <= 128);
        match self {
            Self::SignIn {
                username,
                password: value,
                factor: value_factor,
            } => short(username) && password(value) && factor(value_factor),
            Self::BeginTotp {
                password: value,
                factor: value_factor,
            } => password(value) && factor(value_factor),
            Self::ConfirmTotp { code } => code.expose().len() <= 128,
            Self::ResetRecovery {
                password: value,
                factor,
            } => password(value) && factor.expose().len() <= 128,
            Self::ChangePassword {
                current_password,
                new_password,
                factor: value_factor,
            } => password(current_password) && password(new_password) && factor(value_factor),
            Self::CreateAccount {
                username,
                password: value,
            } => short(username) && password(value),
            Self::LoadServicesPage { after_id, limit } => {
                (1..=100).contains(limit) && after_id.as_ref().is_none_or(|id| valid_id(id))
            }
            Self::InspectService { service_id } => valid_id(service_id),
            Self::CreateService { create } => {
                valid_id(&create.id) && create.definition.validate().is_ok()
            }
            Self::UpdateService { service_id, update } => {
                valid_id(service_id)
                    && nestlink_protocol::services::revision_valid(update.expected_revision)
                    && update.definition.validate().is_ok()
            }
            Self::RevokeService {
                service_id,
                expected_revision,
            } => {
                valid_id(service_id)
                    && nestlink_protocol::services::revision_valid(*expected_revision)
            }
            Self::LoadAudit {
                after_sequence,
                limit,
            } => *after_sequence <= i64::MAX as u64 && (1..=100).contains(limit),
            Self::LoadNodeUsage {
                node_id,
                after_generation,
                limit,
            } => {
                valid_id(node_id)
                    && *after_generation <= i64::MAX as u64
                    && (1..=100).contains(limit)
            }
            Self::EnrollLocalDevice {
                name,
                platform,
                capabilities,
                path_mode,
            } => {
                short(name)
                    && short(platform)
                    && short(path_mode)
                    && capabilities.len() <= 32
                    && capabilities.iter().all(|s| short(s))
            }
            Self::RequestRemote {
                host_device_id,
                permissions,
                path_mode,
                ..
            } => valid_id(host_device_id) && permissions.len() <= 7 && short(path_mode),
            Self::ApproveRemote {
                request_id,
                expected_nonce,
                choice,
                ..
            } => {
                valid_id(request_id)
                    && short(expected_nonce)
                    && choice.permissions.len() <= 7
                    && choice.paths.len() <= 2
            }
            Self::RevokeDevice { device_id } => valid_id(device_id),
            Self::DisableAccount { account_id } => valid_id(account_id),
            Self::RevokeNode { node_id } => valid_id(node_id),
            Self::InspectRemote { request_id }
            | Self::IssueRemotePermit { request_id }
            | Self::StartNativeSession { request_id }
            | Self::StartBrowserHost { request_id }
            | Self::RevokeRemote { request_id }
            | Self::TrustRemote { request_id, .. } => valid_id(request_id),
            Self::StopNativeSession {
                request_id,
                connection_generation,
            }
            | Self::StopBrowserHost {
                request_id,
                connection_generation,
            } => valid_id(request_id) && *connection_generation <= i64::MAX as u64,
            Self::SetPolicy { update } => {
                short(&update.policy.server_forwarding)
                    && short(&update.policy.peer_path_mode)
                    && short(&update.policy.public_ingress)
            }
            Self::SetPathLimit {
                scope,
                resource_id,
                update,
            } => {
                valid_id(resource_id)
                    && ["account", "device", "resource", "login_session"].contains(&scope.as_str())
                    && short(&update.path_mode)
            }
            Self::SetRelayQuota { update } => update.limits.valid(),
            Self::RegisterNode { node } => {
                valid_id(&node.id)
                    && short(&node.name)
                    && short(&node.public_key)
                    && node.roles.len() <= 8
            }
            Self::LoadTrustedDevices { host_device_id }
            | Self::LoadRemotePassword { host_device_id } => valid_id(host_device_id),
            Self::LoadRemotePasswordOffer { request_id } => valid_id(request_id),
            Self::RevokeDeviceTrust {
                host_device_id,
                controller_device_id,
                ..
            } => valid_id(host_device_id) && valid_id(controller_device_id),
            Self::ConfigureRemotePassword {
                settings,
                password: value,
            } => settings.permissions.len() <= 7 && settings.paths.len() <= 2 && password(value),
            Self::AuthorizeRemotePassword {
                request_id,
                password: value,
                ..
            } => valid_id(request_id) && password(value),
            _ => true,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn section(&self) -> SectionKey {
        match self {
            Self::Load { page } => (*page).into(),
            Self::SignIn { .. }
            | Self::RefreshSession
            | Self::BeginTotp { .. }
            | Self::ConfirmTotp { .. }
            | Self::ResetRecovery { .. }
            | Self::ChangePassword { .. } => SectionKey::Security,
            Self::LoadServicesPage { .. } => SectionKey::Services,
            Self::InspectService { .. }
            | Self::CreateService { .. }
            | Self::UpdateService { .. }
            | Self::RevokeService { .. } => SectionKey::SelectedService,
            Self::LoadAudit { .. } => SectionKey::Audit,
            Self::LoadNodeUsage { .. } => SectionKey::NodeUsage,
            Self::EnrollLocalDevice { .. } | Self::RevokeDevice { .. } => SectionKey::Devices,
            Self::ApproveRemote { .. } | Self::RevokeRemote { .. } => SectionKey::Requests,
            Self::StartNativeSession { .. } | Self::StopNativeSession { .. } => {
                SectionKey::NativeSession
            }
            Self::StartBrowserHost { .. } | Self::StopBrowserHost { .. } => SectionKey::BrowserHost,
            Self::InspectRemote { .. }
            | Self::IssueRemotePermit { .. }
            | Self::RequestRemote { .. }
            | Self::AuthorizeRemotePassword { .. } => SectionKey::SelectedRequest,
            Self::CreateAccount { .. } | Self::DisableAccount { .. } => SectionKey::Accounts,
            Self::SetPolicy { .. } => SectionKey::Policy,
            Self::SetPathLimit { .. } => SectionKey::PathLimits,
            Self::SetRelayQuota { .. } => SectionKey::RelayQuota,
            Self::RegisterNode { .. } | Self::RevokeNode { .. } => SectionKey::Nodes,
            Self::SetAuditRetention { .. } => SectionKey::AuditRetention,
            Self::LoadTrustedDevices { .. }
            | Self::TrustRemote { .. }
            | Self::RevokeDeviceTrust { .. } => SectionKey::TrustedDevices,
            Self::LoadRemotePassword { .. }
            | Self::ConfigureRemotePassword { .. }
            | Self::RevokeRemotePassword { .. } => SectionKey::RemotePassword,
            Self::LoadRemotePasswordOffer { .. } => SectionKey::RemotePasswordOffer,
        }
    }
}

#[derive(Clone, Copy)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum SectionKey {
    Security,
    Devices,
    Services,
    SelectedService,
    Requests,
    SelectedRequest,
    Accounts,
    Policy,
    PathLimits,
    RelayQuota,
    RelayUsage,
    Nodes,
    NodeUsage,
    Audit,
    AuditRetention,
    TrustedDevices,
    RemotePassword,
    RemotePasswordOffer,
    NativeSession,
    BrowserHost,
}
#[cfg(not(target_arch = "wasm32"))]
impl From<Page> for SectionKey {
    fn from(page: Page) -> Self {
        match page {
            Page::AccountSecurity => Self::Security,
            Page::Devices => Self::Devices,
            Page::Services => Self::Services,
            Page::Requests => Self::Requests,
            Page::Accounts => Self::Accounts,
            Page::Policy => Self::Policy,
            Page::PathLimits => Self::PathLimits,
            Page::RelayQuota => Self::RelayQuota,
            Page::RelayUsage => Self::RelayUsage,
            Page::Nodes => Self::Nodes,
            Page::AuditRetention => Self::AuditRetention,
        }
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl SectionKey {
    pub(crate) fn status(
        self,
        view: &mut Snapshot,
        loading: Option<crate::OperationId>,
        error: Option<crate::Failure>,
    ) {
        macro_rules! set {
            ($field:ident) => {{
                view.$field.loading = loading;
                view.$field.error = error;
            }};
        }
        match self {
            Self::Security => set!(security),
            Self::Devices => set!(devices),
            Self::Services => set!(services),
            Self::SelectedService => set!(selected_service),
            Self::Requests => set!(requests),
            Self::SelectedRequest => set!(selected_request),
            Self::Accounts => set!(accounts),
            Self::Policy => set!(policy),
            Self::PathLimits => set!(path_limits),
            Self::RelayQuota => set!(relay_quota),
            Self::RelayUsage => set!(relay_usage),
            Self::Nodes => set!(nodes),
            Self::NodeUsage => set!(node_usage),
            Self::Audit => set!(audit),
            Self::AuditRetention => set!(audit_retention),
            Self::TrustedDevices => set!(trusted_devices),
            Self::RemotePassword => set!(remote_password),
            Self::RemotePasswordOffer => set!(remote_password_offer),
            Self::NativeSession => set!(native_session),
            Self::BrowserHost => set!(browser_host),
        }
    }
}

mod secret {
    use nestlink_auth::Secret;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.expose())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        String::deserialize(deserializer).map(Secret::from_text)
    }
}

fn empty_action<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}
mod optional_secret {
    use nestlink_auth::Secret;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &Option<Secret>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(value.expose()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Secret>, D::Error> {
        Option::<String>::deserialize(deserializer).map(|value| value.map(Secret::from_text))
    }
}
