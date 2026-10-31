use crate::{ContractError, ErrorCode, SCHEMA_VERSION, valid_id};
use crate::api::ServiceView;
use crate::service_plane::{SignedServiceLease, SERVICE_LEASE_MS, SERVICE_MESSAGE_BYTES};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccessMode { Private, Public, Both }
impl ServiceAccessMode {
    pub fn private_enabled(self) -> bool { matches!(self, Self::Private | Self::Both) }
    pub fn public_enabled(self) -> bool { matches!(self, Self::Public | Self::Both) }
}

/// Missing policies preserve legacy public-only behavior. A policy is a fence:
/// stale/revoked target revisions never fall back to that legacy behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceExposureUpdate {
    pub expected_revision: u64,
    pub expected_service_revision: u64,
    pub space_id: String,
    pub mode: ServiceAccessMode,
    pub private_maximum_bytes: u64,
    pub public_maximum_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceExposureView {
    pub service_id: String,
    pub revision: u64,
    pub service_revision: u64,
    pub target_sha256: [u8; 32],
    pub space_id: String,
    pub mode: ServiceAccessMode,
    pub private_maximum_bytes: u64,
    pub public_maximum_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateServiceSubject {
    Account { account_id: String },
    Installation { installation_id: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceAclUpdate {
    pub expected_exposure_revision: u64,
    pub subject: PrivateServiceSubject,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceAclRevocation {
    pub expected_exposure_revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceAclView {
    pub rule_id: String,
    pub subject: PrivateServiceSubject,
    pub subject_epoch: u64,
    pub host_membership_epoch: u64,
    pub expires_at_unix_ms: u64,
    pub revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServicePolicyView {
    pub exposure: ServiceExposureView,
    pub rules: Vec<PrivateServiceAclView>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceHostClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub service_id: String,
    pub service_revision: u64,
    pub exposure_revision: u64,
    pub target_sha256: [u8; 32],
    pub host_device_id: String,
    pub runtime_id: String,
    pub request_sequence: u64,
    /// Endpoint-pinned inner QUIC address; never a backend destination.
    pub address: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateServiceHost { pub claims: Vec<u8>, pub signature: Vec<u8> }
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateServiceHostWithdrawal { pub claims: Vec<u8>, pub signature: Vec<u8> }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceAccessRequest {
    /// Retried requests retain this ID and every original request field.
    pub request_id: String,
    pub consumer_device_id: String,
    pub expected_service_revision: u64,
    pub expected_exposure_revision: u64,
    /// A bounded sub-reservation, never a second service allowance.
    pub maximum_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceClaims {
    pub schema_version: u32,
    pub service_lease_sha256: [u8; 32],
    pub usage_grant_sha256: [u8; 32],
    pub space_id: String,
    pub space_policy_epoch: u64,
    pub exposure_revision: u64,
    pub acl_rule_id: String,
    pub subject_epoch: u64,
    pub host_membership_epoch: u64,
    pub consumer_membership_epoch: u64,
    pub consumer_account_id: String,
    pub consumer_device_id: String,
    pub consumer_public_key: [u8; 32],
    pub host_public_key: [u8; 32],
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateServiceLease {
    pub service_lease: SignedServiceLease,
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceGrant {
    pub lease: SignedPrivateServiceLease,
    pub issuer: crate::service_plane::publication::SignedServiceIssuerDelegation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrivateServiceAvailability { Offline, Ready, QuotaExceeded }
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceEntry {
    pub service: ServiceView,
    pub exposure: ServiceExposureView,
    pub availability: PrivateServiceAvailability,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServicePage {
    pub security_epoch: u64,
    pub entries: Vec<PrivateServiceEntry>,
    pub next_id: Option<String>,
    pub more: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceUsageClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub grant_id: String,
    pub grant_sha256: [u8; 32],
    pub host_device_id: String,
    pub runtime_id: String,
    pub report_sequence: u64,
    pub admitted_bytes: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub terminal: bool,
    pub sampled_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateServiceUsage { pub claims: Vec<u8>, pub signature: Vec<u8> }
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceUsageAck {
    pub grant_id: String,
    pub report_sequence: u64,
    pub report_sha256: [u8; 32],
    pub terminal: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceOpen {
    pub lease: SignedPrivateServiceLease,
    pub nonce: [u8; 32],
    pub consumer_signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceReady {
    pub lease_sha256: [u8; 32],
    pub nonce: [u8; 32],
    pub host_signature: Vec<u8>,
}

fn invalid() -> ContractError { ContractError::new(ErrorCode::InvalidMessage, "invalid private service authority") }
fn revision(n: u64) -> bool { n > 0 && n <= i64::MAX as u64 }
impl PrivateServiceHostClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        crate::service_plane::publication::service_socket(&self.address)?;
        if self.schema_version != SCHEMA_VERSION
            || [&self.deployment_id, &self.service_id, &self.host_device_id, &self.runtime_id].iter().any(|id| !valid_id(id))
            || [self.security_epoch,self.policy_revision,self.service_revision,self.exposure_revision,self.request_sequence,self.issued_at_unix_ms].iter().any(|n| !revision(*n))
            || self.target_sha256 == [0;32]
            || self.expires_at_unix_ms.checked_sub(self.issued_at_unix_ms).is_none_or(|n| n == 0 || n > SERVICE_LEASE_MS)
        { return Err(invalid()); }
        Ok(())
    }
}
impl PrivateServiceClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [&self.space_id,&self.acl_rule_id,&self.consumer_account_id,&self.consumer_device_id].iter().any(|id| !valid_id(id))
            || [self.space_policy_epoch,self.exposure_revision,self.subject_epoch,self.host_membership_epoch,self.consumer_membership_epoch].iter().any(|n| !revision(*n))
            || [self.service_lease_sha256,self.usage_grant_sha256,self.consumer_public_key,self.host_public_key].contains(&[0;32])
        { return Err(invalid()); }
        Ok(())
    }
}
impl PrivateServiceUsageClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [&self.deployment_id,&self.grant_id,&self.host_device_id,&self.runtime_id].iter().any(|id| !valid_id(id))
            || [self.security_epoch,self.report_sequence,self.sampled_at_unix_ms].iter().any(|n| !revision(*n))
            || [self.admitted_bytes,self.opened_connections,self.closed_connections].iter().any(|n| *n > i64::MAX as u64)
            || self.closed_connections > self.opened_connections
            || self.terminal && self.closed_connections != self.opened_connections
            || self.grant_sha256 == [0;32]
        { return Err(invalid()); }
        Ok(())
    }
}
pub const PRIVATE_SERVICE_MESSAGE_BYTES: usize = SERVICE_MESSAGE_BYTES * 6;
