use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Discovery inputs supplied by the authenticated, pinned deployment. Local
/// private-network consent is deliberately absent from this response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeDiscoveryConfig {
    pub deployment_id: String,
    pub stun_servers: Vec<std::net::SocketAddr>,
}
impl NativeDiscoveryConfig {
    pub fn validate(&self) -> Result<(), crate::ContractError> {
        let invalid = || {
            crate::ContractError::new(
                crate::ErrorCode::InvalidMessage,
                "invalid deployment discovery configuration",
            )
        };
        if !crate::valid_id(&self.deployment_id) || self.stun_servers.len() > 4 {
            return Err(invalid());
        }
        let mut seen = std::collections::HashSet::new();
        for address in &self.stun_servers {
            if address.port() == 0
                || !crate::turn::safe_turn_peer_address(address.ip())
                || matches!(address, std::net::SocketAddr::V6(v6)
                    if v6.scope_id() != 0 || v6.flowinfo() != 0)
                || !seen.insert(*address)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceDescriptor {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub capabilities: Vec<String>,
    pub path_mode: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistration {
    pub challenge_id: String,
    pub device: DeviceDescriptor,
    pub signature: String,
}
/// A browser endpoint identity is tied to a management-authenticated registration
/// challenge and receives a fixed, server-enforced ten-minute lifetime.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserEndpointRegistration {
    pub challenge_id: String,
    pub device: DeviceDescriptor,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserEndpointLease {
    pub device_id: String,
    pub expires_at_unix_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteRequest {
    pub id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub permissions: Vec<i32>,
    pub path_mode: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChoice {
    pub approved: bool,
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubmission {
    pub choice: ApprovalChoice,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustChoice {
    pub expected_revision: u64,
    pub expires_at_unix_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustSubmission {
    pub choice: TrustChoice,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustRevocation {
    pub expected_revision: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TrustedDeviceView {
    pub host_device_id: String,
    pub controller_device_id: String,
    pub host_key_sha256: String,
    pub controller_key_sha256: String,
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
    pub revision: u64,
    pub expires_at_unix_ms: u64,
    pub active: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TrustedDevicesResponse {
    pub devices: Vec<TrustedDeviceView>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordSettings {
    pub expected_revision: u64,
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
    pub expires_at_unix_ms: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordChoice {
    pub settings: RemotePasswordSettings,
    pub password: String,
}
impl Drop for RemotePasswordChoice {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordSetup {
    pub challenge_id: String,
    pub choice: RemotePasswordChoice,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordAttempt {
    pub expected_revision: u64,
    pub password: String,
}
impl Drop for RemotePasswordAttempt {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordSubmission {
    pub attempt: RemotePasswordAttempt,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePasswordRevocation {
    pub expected_revision: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RemotePasswordView {
    pub revision: u64,
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
    pub expires_at_unix_ms: u64,
    pub active: bool,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenewalSubmission {
    pub lease_sequence: u64,
    pub controller_signature: String,
    pub host_signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionChoice {
    pub previous_permit_sha256: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub nonce: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionSubmission {
    pub choice: ReconnectionChoice,
    pub controller_signature: String,
    pub host_signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionOffer {
    pub choice: ReconnectionChoice,
    pub controller_signature: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionApproval {
    pub choice: ReconnectionChoice,
    pub host_signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionResponse {
    pub grant: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectionState {
    pub offer: Option<ReconnectionOffer>,
    pub host_signature: Option<String>,
    pub grant: Option<String>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub username: String,
    pub password: String,
    pub factor: Option<String>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    pub refresh_token: Option<String>,
    pub generation: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
    pub factor: Option<String>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAccount {
    pub username: String,
    pub password: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub server_forwarding: String,
    pub peer_path_mode: String,
    pub public_ingress: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub expected_revision: u64,
    pub policy: NetworkPolicy,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathLimitUpdate {
    pub expected_revision: u64,
    pub path_mode: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeDevice {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Principal {
    pub account_id: String,
    pub session_id: String,
    pub name: String,
    pub is_admin: bool,
    pub access_expires: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LoginResponse {
    pub principal: Principal,
    pub access_token: String,
    pub refresh_token: String,
    pub generation: u64,
    pub refresh_expires: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct MeResponse {
    pub principal: Principal,
}
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AccountView {
    pub id: String,
    pub name: String,
    pub is_admin: bool,
    pub disabled: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountsResponse {
    pub accounts: Vec<AccountView>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct EnrollmentChallenge {
    pub id: String,
    pub nonce: String,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub expires_at_unix_ms: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DeviceView {
    pub device: DeviceDescriptor,
    pub revoked: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceView>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RemoteView {
    pub id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
    pub nonce: String,
    pub policy_revision: u64,
    pub expires_at_unix_ms: u64,
    pub status: String,
    pub lease_sequence: u64,
    pub connection_generation: u64,
    pub trust_revision: Option<u64>,
    pub password_revision: Option<u64>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RemoteRequestsResponse {
    pub requests: Vec<RemoteView>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePeerKeys {
    pub session_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub controller_public_key: String,
    pub host_public_key: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PermitResponse {
    pub permit: String,
    pub claims: crate::PermitClaims,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PolicyResponse {
    pub revision: u64,
    pub policy: NetworkPolicy,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RevisionResponse {
    pub revision: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub security_epoch: u64,
    #[serde(default)]
    #[schemars(range(max = 9223372036854775807u64))]
    pub after_sequence: u64,
    #[serde(default = "audit_page_size")]
    #[schemars(range(min = 1, max = 100))]
    pub limit: u16,
}
fn audit_page_size() -> u16 {
    100
}
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditActor {
    Legacy,
    LocalOperator,
    Unauthenticated,
    Management {
        account_id: String,
        session_id: String,
    },
    Device {
        account_id: String,
        session_id: String,
        device_id: String,
    },
    DeviceCredential {
        account_id: String,
        device_id: String,
    },
    Node {
        node_id: String,
        runtime_id: String,
        runtime_generation: u64,
    },
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AuditEntry {
    pub sequence: u64,
    pub event: String,
    pub resource_id: String,
    pub security_epoch: u64,
    pub created_at_unix_ms: u64,
    pub actor: AuditActor,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    pub security_epoch: u64,
    pub next_sequence: u64,
    pub high_watermark: u64,
    pub pruned_through: u64,
    pub history_pruned: bool,
    pub more: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionUpdate {
    pub expected_revision: u64,
    #[schemars(range(min = 3600, max = 31536000))]
    pub retention_seconds: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AuditRetention {
    pub revision: u64,
    pub retention_seconds: u64,
    pub high_watermark: u64,
    pub pruned_through: u64,
    pub last_cleanup_at_unix_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayQuotaLimits {
    #[schemars(range(max = 128))]
    pub max_allocations: u16,
    #[schemars(range(max = 256))]
    pub max_account_endpoints: u16,
    #[schemars(range(min = 1, max = 1073741824))]
    pub bytes_per_second: u64,
    #[schemars(range(min = 1, max = 1099511627776u64))]
    pub bytes_per_allocation: u64,
}
impl RelayQuotaLimits {
    pub fn valid(self) -> bool {
        self.max_allocations <= 128
            && self.max_account_endpoints <= 256
            && (1..=1073741824).contains(&self.bytes_per_second)
            && (1..=1099511627776).contains(&self.bytes_per_allocation)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RelayQuota {
    pub revision: u64,
    pub limits: RelayQuotaLimits,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayQuotaUpdate {
    pub expected_revision: u64,
    pub limits: RelayQuotaLimits,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RelayUsage {
    pub runtime_id: String,
    pub report_sequence: u64,
    pub quota_revision: u64,
    pub allocations: u16,
    pub endpoints: u16,
    pub admitted_bytes: u64,
    pub closed_allocations: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct IdResponse {
    pub id: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PathLimit {
    pub scope: String,
    pub resource_id: String,
    pub path_mode: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PathLimitsResponse {
    pub limits: Vec<PathLimit>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct HealthResponse {
    pub product: String,
    pub version: String,
    pub api_base: String,
    pub alpn: String,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub permit_issuer: String,
    pub node_policy_issuer: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerIdentityChallenge {
    pub nonce: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerIdentityClaims {
    pub nonce: String,
    pub management_origin: String,
    pub product: String,
    pub version: String,
    pub api_base: String,
    pub alpn: String,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub permit_issuer: String,
    pub node_policy_issuer: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerIdentityProof {
    pub claims: ServerIdentityClaims,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ErrorResponse {
    pub code: crate::ErrorCode,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Quic,
    Tls,
    Wss,
    WebRtc,
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Lan,
    Ipv6,
    Reflexive,
    Relay,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub address: std::net::SocketAddr,
    pub transport: Transport,
    pub kind: CandidateKind,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebRtcDescription {
    pub kind: String,
    pub sdp: String,
    pub dtls_sha256: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to_sequence: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalPayload {
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub network_generation: u64,
    pub sequence: u64,
    pub candidates: Vec<Candidate>,
    pub description: Option<WebRtcDescription>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalSubmission {
    pub device_id: String,
    pub payload: SignalPayload,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalView {
    pub account_id: String,
    pub public_key: String,
    pub submission: SignalSubmission,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SignalsResponse {
    pub signals: Vec<SignalView>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayChallenge {
    pub nonce: String,
    pub lease_sequence: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayHello {
    pub device_id: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeRelayChallenge {
    pub nonce: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeRelayHello {
    pub device_id: String,
    pub public_key: String,
    pub allocation: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayReady {
    pub ready: bool,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeRegistration {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub roles: Vec<i32>,
    pub max_connections: u32,
    pub bytes_per_second: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct NodeView {
    pub node: NodeRegistration,
    pub revoked: bool,
    pub last_issued_at_unix_ms: u64,
    pub runtime_id: Option<String>,
    pub runtime_generation: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct NodesResponse {
    pub nodes: Vec<NodeView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeEndpoints {
    pub quic_uri: Option<String>,
    pub wss_origin: Option<String>,
    #[serde(default)]
    pub allow_loopback: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeEndpointsUpdate {
    pub expected_revision: u64,
    pub endpoints: NodeEndpoints,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct NodeEndpointsView {
    pub node_id: String,
    pub revision: u64,
    pub endpoints: NodeEndpoints,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeDiscoveryRequest {
    pub device_id: String,
    pub nonce: String,
    pub permit_sha256: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeDiscoveryResponse {
    pub discovery: String,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayAllocationRequest {
    pub allocation_id: String,
    pub node_id: String,
    pub device_id: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RelayAllocationResponse {
    pub allocation: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnCredentialRequest {
    pub allocation_id: String,
    pub device_id: String,
    pub network_generation: u64,
    pub signature: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnEndpointConfig {
    pub realm: String,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub allow_loopback: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnEndpointsUpdate {
    pub expected_revision: u64,
    pub config: TurnEndpointConfig,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnEndpointsView {
    pub node_id: String,
    pub revision: u64,
    pub config: TurnEndpointConfig,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnPeerSubmission {
    pub device_id: String,
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnBindingState {
    pub controller_allocation_id: Option<String>,
    pub host_allocation_id: Option<String>,
    pub controller_expires_at_unix_ms: Option<u64>,
    pub host_expires_at_unix_ms: Option<u64>,
    pub binding: Option<crate::SignedTurnPeerBinding>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RelayReservationUsage {
    pub security_epoch: u64,
    pub held_allocations: u32,
    pub held_endpoint_slots: u32,
    pub independent_allocations: u32,
    pub combined_allocations: u32,
    #[serde(default)]
    pub turn_allocations: u32,
    pub restore_fenced: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeUsageQuery {
    pub security_epoch: u64,
    #[serde(default)]
    pub after_generation: u64,
    #[serde(default = "audit_page_size")]
    pub limit: u16,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct NodeUsageView {
    pub runtime_id: String,
    pub runtime_generation: u64,
    pub security_epoch: u64,
    pub started_at_unix_ms: u64,
    pub report_sequence: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub admitted_bytes: u64,
    pub sampled_at_unix_ms: u64,
    pub accepted_at_unix_ms: u64,
    pub current: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct NodeUsagePage {
    pub node_id: String,
    pub security_epoch: u64,
    pub entries: Vec<NodeUsageView>,
    pub next_generation: u64,
    pub more: bool,
}

/// Requested ingress only. Creating or approving a record opens no listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceIngress {
    Http { hostname: String },
    Https { hostname: String },
    Tcp { port: u16 },
    Udp { port: u16 },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceSourceNetwork {
    pub address: String,
    pub prefix: u8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceLimits {
    pub maximum_connections: u16,
    pub bytes_per_second: u64,
    pub maximum_bytes: u64,
    pub idle_timeout_seconds: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceDefinition {
    pub name: String,
    pub host_device_id: String,
    pub edge_node_id: String,
    pub requested_ingress: ServiceIngress,
    /// An empty list denies all visitors; /0 is an explicit public choice.
    pub allowed_sources: Vec<ServiceSourceNetwork>,
    pub limits: ServiceLimits,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceCreate {
    pub id: String,
    pub definition: ServiceDefinition,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceUpdate {
    pub expected_revision: u64,
    pub definition: ServiceDefinition,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRevocation {
    pub expected_revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuery {
    pub security_epoch: u64,
    #[serde(default)]
    pub after_id: Option<String>,
    #[serde(default = "audit_page_size")]
    pub limit: u16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceApprovalState {
    Pending,
    ApprovedTarget,
    Invalidated,
    Revoked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServicePublicationStatus {
    NotPublished,
    Published,
    Stopping,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceView {
    pub id: String,
    pub account_id: String,
    pub management_session_id: String,
    pub revision: u64,
    pub definition: ServiceDefinition,
    pub definition_sha256: String,
    pub approval: ServiceApprovalState,
    pub target_id: Option<String>,
    pub target_sha256: Option<String>,
    pub approval_expires_at_unix_ms: Option<u64>,
    pub publication: ServicePublicationStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServicePage {
    pub security_epoch: u64,
    pub services: Vec<ServiceView>,
    pub next_id: Option<String>,
    pub more: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceApprovalChallengeRequest {
    pub expected_revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceApprovalChallenge {
    pub id: String,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub account_id: String,
    pub management_session_id: String,
    pub host_device_id: String,
    pub service_id: String,
    pub service_revision: u64,
    pub definition_sha256: String,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceTargetChoice {
    pub expected_revision: u64,
    pub target_id: String,
    /// Commits to the actual locally selected, fixed address and target protocol.
    pub target_sha256: String,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceTargetApproval {
    pub challenge_id: String,
    pub choice: ServiceTargetChoice,
    pub signature: String,
}
