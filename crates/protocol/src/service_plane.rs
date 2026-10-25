//! Separate service-publication authority; remote desktop permits confer none.
use crate::{
    ContractError, ErrorCode, NodeResourceQueryClaims, SCHEMA_VERSION,
    api::{ServiceDefinition, ServiceIngress, ServiceSourceNetwork},
    services::revision_valid,
    valid_id,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::net::{IpAddr, SocketAddr};
pub mod observation;
pub mod publication;

pub const SERVICE_LEASE_MS: u64 = 10_000;
pub const SERVICE_RESOURCE_MS: u64 = 2_000;
pub const SERVICE_MESSAGE_BYTES: usize = 32 * 1024;
pub const SERVICE_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
pub const SERVICE_PUBLICATIONS_PER_NODE: usize = 32;
pub const SERVICE_DATAGRAM_BYTES: usize = 1200;
pub const SERVICE_USAGE_BYTES: usize = 32 * 1024;

/// Aggregate service quota dimensions. Keys are immutable UUID strings and
/// are bound into every grant and report so callers cannot change scope on a
/// retry or terminal seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceQuotaScope {
    Account,
    Device,
    Node,
    Resource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaUsageQuery {
    pub scope: ServiceQuotaScope,
    pub scope_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaUsageView {
    pub scope: ServiceQuotaScope,
    pub scope_key: String,
    pub spent_bytes: u64,
    pub outstanding_bytes: u64,
    pub limit_bytes: u64,
    pub limit_revision: u64,
    pub active_grants: u64,
    /// Restored snapshots cannot establish complete lifetime usage on their own.
    pub reconciliation_required: bool,
    pub latest_runtime_id: Option<String>,
    pub latest_runtime_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaLimitUpdate {
    pub scope: ServiceQuotaScope,
    pub scope_key: String,
    pub expected_revision: u64,
    pub limit_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceUsageBudgetGrantClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub quota_revision: u64,
    pub account_id: String,
    pub host_device_id: String,
    pub service_id: String,
    pub edge_node_id: String,
    pub publication_id: String,
    pub publication_generation: u64,
    pub service_revision: u64,
    pub definition_sha256: [u8; 32],
    pub target_sha256: [u8; 32],
    pub ingress_claim_id: String,
    pub ingress_claim_revision: u64,
    pub edge_runtime_id: String,
    pub edge_runtime_generation: u64,
    pub grant_id: String,
    pub grant_sequence: u64,
    pub byte_ceiling: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceUsageBudgetGrant {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceUsageReportClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub node_id: String,
    pub node_runtime_id: String,
    pub node_runtime_generation: u64,
    pub grant_id: String,
    pub grant_sha256: [u8; 32],
    pub publication_id: String,
    pub publication_generation: u64,
    pub account_id: String,
    pub host_device_id: String,
    pub service_id: String,
    pub report_sequence: u64,
    pub admitted_bytes: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub sampled_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceUsageReport {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceUsageReportAckClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub node_id: String,
    pub node_runtime_id: String,
    pub node_runtime_generation: u64,
    pub grant_id: String,
    pub report_sequence: u64,
    pub report_sha256: [u8; 32],
    pub accepted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceUsageReportAck {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceUsageRuntimeStopClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub node_id: String,
    pub node_runtime_id: String,
    pub node_runtime_generation: u64,
    pub grant_id: String,
    pub grant_sha256: [u8; 32],
    pub publication_id: String,
    pub publication_generation: u64,
    pub final_report_sequence: u64,
    pub final_report_sha256: [u8; 32],
    pub admitted_bytes: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub stop_nonce: [u8; 32],
    pub stopped_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceUsageRuntimeStop {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceLeaseClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub publication_id: String,
    pub publication_generation: u64,
    pub service_id: String,
    /// Current registry revision, after independent target approval.
    pub service_revision: u64,
    /// Original local choice revision; its digest must not be recomputed at N+1.
    pub choice_revision: u64,
    pub account_id: String,
    pub creator_login_id: String,
    pub approving_login_id: String,
    pub definition: ServiceDefinition,
    pub definition_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub target_id: String,
    pub target_sha256: [u8; 32],
    pub edge_key_sha256: [u8; 32],
    /// Canonical operator-approved service QUIC endpoint, signed with the lease.
    pub edge_service_address: String,
    pub edge_runtime_id: String,
    pub edge_runtime_generation: u64,
    pub ingress_claim_id: String,
    pub ingress_claim_revision: u64,
    /// Immutable per-publication byte authority; renewed leases carry the
    /// same signed grant byte-for-byte.
    pub usage_grant: SignedServiceUsageBudgetGrant,
    pub lease_sequence: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceLease {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Uses the existing bounded node query fields with an independent signature purpose.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceResourceQuery {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceResourceSnapshot {
    pub query: NodeResourceQueryClaims,
    pub query_sha256: [u8; 32],
    /// Delegated by the already trusted independent node-policy issuer.
    pub service_lease_issuer: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub leases: Vec<SignedServiceLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceResourceSnapshot {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTunnelTransport {
    Stream,
    NativeDatagram,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceTunnelChallenge {
    pub lease_sha256: [u8; 32],
    pub stream_id: String,
    pub nonce: [u8; 32],
    /// Taken from the accepted visitor socket, never a forwarded HTTP header.
    pub peer_address: String,
    pub transport: ServiceTunnelTransport,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceTunnelChallenge {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceTunnelProof {
    pub lease_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub host_runtime_id: String,
    pub signature: Vec<u8>,
}

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid service publication metadata",
    )
}

fn usage_invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid service usage transcript",
    )
}

impl ServiceQuotaScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Device => "device",
            Self::Node => "node",
            Self::Resource => "resource",
        }
    }
}

impl ServiceQuotaUsageQuery {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_id(&self.scope_key) {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

impl ServiceQuotaLimitUpdate {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_id(&self.scope_key)
            || self.expected_revision > i64::MAX as u64
            || self.limit_bytes > i64::MAX as u64
        {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

impl ServiceUsageBudgetGrantClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.account_id,
                &self.host_device_id,
                &self.service_id,
                &self.edge_node_id,
                &self.publication_id,
                &self.ingress_claim_id,
                &self.edge_runtime_id,
                &self.grant_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.policy_revision,
                self.quota_revision,
                self.publication_generation,
                self.service_revision,
                self.ingress_claim_revision,
                self.edge_runtime_generation,
                self.grant_sequence,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|value| !revision_valid(*value))
            || self.byte_ceiling == 0
            || self.byte_ceiling > i64::MAX as u64
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || serde_json::to_vec(self).map_err(|_| usage_invalid())?.len() > SERVICE_USAGE_BYTES
        {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

impl ServiceUsageReportClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.node_runtime_id,
                &self.grant_id,
                &self.publication_id,
                &self.account_id,
                &self.host_device_id,
                &self.service_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.policy_revision,
                self.node_runtime_generation,
                self.report_sequence,
                self.sampled_at_unix_ms,
            ]
            .iter()
            .any(|value| !revision_valid(*value))
            || [
                self.admitted_bytes,
                self.opened_connections,
                self.closed_connections,
            ]
            .iter()
            .any(|value| *value > i64::MAX as u64)
            || self.closed_connections > self.opened_connections
            || serde_json::to_vec(self).map_err(|_| usage_invalid())?.len() > SERVICE_USAGE_BYTES
        {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

impl ServiceUsageReportAckClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.node_runtime_id,
                &self.grant_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.node_runtime_generation,
                self.report_sequence,
                self.accepted_at_unix_ms,
            ]
            .iter()
            .any(|value| !revision_valid(*value))
        {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

impl ServiceUsageRuntimeStopClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        let empty_report = self.final_report_sequence == 0 && self.final_report_sha256 == [0; 32];
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.node_runtime_id,
                &self.grant_id,
                &self.publication_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.policy_revision,
                self.node_runtime_generation,
                self.publication_generation,
                self.stopped_at_unix_ms,
            ]
            .iter()
            .any(|value| !revision_valid(*value))
            || self.final_report_sequence > i64::MAX as u64
            || (!empty_report && !revision_valid(self.final_report_sequence))
            || [
                self.admitted_bytes,
                self.opened_connections,
                self.closed_connections,
            ]
            .iter()
            .any(|value| *value > i64::MAX as u64)
            || self.closed_connections > self.opened_connections
            || self.stop_nonce == [0; 32]
            || serde_json::to_vec(self).map_err(|_| usage_invalid())?.len() > SERVICE_USAGE_BYTES
        {
            return Err(usage_invalid());
        }
        Ok(())
    }
}

/// Bounded service wire encoding shared with identity without adding serde as
/// a new direct dependency to that crate.
pub fn encode_service_message<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ContractError> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > maximum {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "service metadata budget exceeded",
        ));
    }
    Ok(bytes)
}
pub fn decode_service_message<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ContractError> {
    if bytes.len() > maximum {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "service metadata budget exceeded",
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

impl ServiceLeaseClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.definition.validate()?;
        publication::service_socket(&self.edge_service_address)?;
        if self.usage_grant.signature.len() != 64 {
            return Err(invalid());
        }
        let grant: ServiceUsageBudgetGrantClaims =
            decode_service_message(&self.usage_grant.claims, SERVICE_USAGE_BYTES)?;
        grant.validate()?;
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.publication_id,
                &self.service_id,
                &self.account_id,
                &self.creator_login_id,
                &self.approving_login_id,
                &self.target_id,
                &self.edge_runtime_id,
                &self.ingress_claim_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.policy_revision,
                self.publication_generation,
                self.service_revision,
                self.choice_revision,
                self.edge_runtime_generation,
                self.ingress_claim_revision,
                self.lease_sequence,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|n| !revision_valid(*n))
            || self.choice_revision.checked_add(1) != Some(self.service_revision)
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > SERVICE_LEASE_MS)
            || grant.deployment_id != self.deployment_id
            || grant.security_epoch != self.security_epoch
            || grant.policy_revision != self.policy_revision
            || grant.account_id != self.account_id
            || grant.host_device_id != self.definition.host_device_id
            || grant.service_id != self.service_id
            || grant.edge_node_id != self.definition.edge_node_id
            || grant.publication_id != self.publication_id
            || grant.publication_generation != self.publication_generation
            || grant.service_revision != self.service_revision
            || grant.definition_sha256 != self.definition_sha256
            || grant.target_sha256 != self.target_sha256
            || grant.ingress_claim_id != self.ingress_claim_id
            || grant.ingress_claim_revision != self.ingress_claim_revision
            || grant.edge_runtime_id != self.edge_runtime_id
            || grant.edge_runtime_generation != self.edge_runtime_generation
            || grant.byte_ceiling > self.definition.limits.maximum_bytes
            || grant.issued_at_unix_ms > self.issued_at_unix_ms
            || grant.expires_at_unix_ms < self.expires_at_unix_ms
        {
            return Err(invalid());
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > SERVICE_MESSAGE_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn permits_source(&self, source: IpAddr) -> bool {
        self.definition
            .allowed_sources
            .iter()
            .any(|network| source_in_network(network, source))
    }
    pub fn permits_transport(&self, transport: ServiceTunnelTransport) -> bool {
        matches!(
            (&self.definition.requested_ingress, transport),
            (
                ServiceIngress::Udp { .. },
                ServiceTunnelTransport::NativeDatagram
            ) | (
                ServiceIngress::Tcp { .. }
                    | ServiceIngress::Http { .. }
                    | ServiceIngress::Https { .. },
                ServiceTunnelTransport::Stream
            )
        )
    }
}

impl ServiceResourceSnapshot {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.query.validate()?;
        if !revision_valid(self.issued_at_unix_ms)
            || !revision_valid(self.expires_at_unix_ms)
            || self.issued_at_unix_ms < self.query.issued_at_unix_ms
            || self.expires_at_unix_ms > self.query.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > SERVICE_RESOURCE_MS)
            || self.leases.len() > SERVICE_PUBLICATIONS_PER_NODE
            || self.leases.iter().any(|lease| {
                lease.claims.len() > SERVICE_MESSAGE_BYTES || lease.signature.len() != 64
            })
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > SERVICE_SNAPSHOT_BYTES
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl ServiceTunnelChallenge {
    pub fn validate(&self, lease: &ServiceLeaseClaims) -> Result<SocketAddr, ContractError> {
        lease.validate()?;
        let peer: SocketAddr = self.peer_address.parse().map_err(|_| invalid())?;
        if !valid_id(&self.stream_id)
            || peer.to_string() != self.peer_address
            || peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || !lease.permits_source(peer.ip())
            || !lease.permits_transport(self.transport)
            || self.issued_at_unix_ms < lease.issued_at_unix_ms
            || self.expires_at_unix_ms > lease.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > SERVICE_RESOURCE_MS)
        {
            return Err(invalid());
        }
        Ok(peer)
    }
}

pub fn source_in_network(network: &ServiceSourceNetwork, source: IpAddr) -> bool {
    if network.validate().is_err() {
        return false;
    }
    let prefix = u32::from(network.prefix);
    match (network.address.parse::<IpAddr>(), source) {
        (Ok(IpAddr::V4(network)), IpAddr::V4(source)) => {
            prefix == 0 || u32::from(source) >> (32 - prefix) == u32::from(network) >> (32 - prefix)
        }
        (Ok(IpAddr::V6(network)), IpAddr::V6(source)) => {
            prefix == 0
                || u128::from(source) >> (128 - prefix) == u128::from(network) >> (128 - prefix)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServiceLimits;
    fn id(n: u8) -> String {
        format!("{n:08x}-1111-4111-8111-111111111111")
    }
    fn lease() -> Result<ServiceLeaseClaims, ContractError> {
        Ok(ServiceLeaseClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            publication_id: id(2),
            publication_generation: 1,
            service_id: id(3),
            service_revision: 4,
            choice_revision: 3,
            account_id: id(4),
            creator_login_id: id(5),
            approving_login_id: id(6),
            definition: ServiceDefinition {
                name: "loopback service".into(),
                host_device_id: id(7),
                edge_node_id: id(8),
                requested_ingress: ServiceIngress::Tcp { port: 29100 },
                allowed_sources: vec![ServiceSourceNetwork {
                    address: "127.0.0.0".into(),
                    prefix: 8,
                }],
                limits: ServiceLimits {
                    maximum_connections: 2,
                    bytes_per_second: 4096,
                    maximum_bytes: 65536,
                    idle_timeout_seconds: 3,
                },
            },
            definition_sha256: [1; 32],
            host_key_sha256: [2; 32],
            target_id: id(9),
            target_sha256: [3; 32],
            edge_key_sha256: [4; 32],
            edge_service_address: "127.0.0.1:29199".into(),
            edge_runtime_id: id(10),
            edge_runtime_generation: 1,
            ingress_claim_id: id(11),
            ingress_claim_revision: 1,
            usage_grant: SignedServiceUsageBudgetGrant {
                claims: encode_service_message(
                    &ServiceUsageBudgetGrantClaims {
                        schema_version: SCHEMA_VERSION,
                        deployment_id: id(1),
                        security_epoch: 1,
                        policy_revision: 2,
                        quota_revision: 1,
                        account_id: id(4),
                        host_device_id: id(7),
                        service_id: id(3),
                        edge_node_id: id(8),
                        publication_id: id(2),
                        publication_generation: 1,
                        service_revision: 4,
                        definition_sha256: [1; 32],
                        target_sha256: [3; 32],
                        ingress_claim_id: id(11),
                        ingress_claim_revision: 1,
                        edge_runtime_id: id(10),
                        edge_runtime_generation: 1,
                        grant_id: id(13),
                        grant_sequence: 1,
                        byte_ceiling: 65536,
                        issued_at_unix_ms: 10000,
                        expires_at_unix_ms: 30000,
                    },
                    SERVICE_USAGE_BYTES,
                )?,
                signature: vec![0; 64],
            },
            lease_sequence: 1,
            issued_at_unix_ms: 10000,
            expires_at_unix_ms: 20000,
        })
    }
    #[test]
    fn sources_match_canonical_cidr_without_cross_family_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        for (network, prefix, yes, no) in [
            ("192.0.2.0", 24, "192.0.2.255", "192.0.3.1"),
            ("192.0.2.7", 32, "192.0.2.7", "192.0.2.8"),
            ("2001:db8::", 32, "2001:db8:ffff::1", "2001:db9::1"),
            ("::1", 128, "::1", "::2"),
        ] {
            let network = ServiceSourceNetwork {
                address: network.into(),
                prefix,
            };
            assert!(source_in_network(&network, yes.parse()?));
            assert!(!source_in_network(&network, no.parse()?));
        }
        let all_v4 = ServiceSourceNetwork {
            address: "0.0.0.0".into(),
            prefix: 0,
        };
        assert!(source_in_network(&all_v4, "203.0.113.9".parse()?));
        assert!(!source_in_network(&all_v4, "::ffff:203.0.113.9".parse()?));
        let malformed = ServiceSourceNetwork {
            address: "192.0.2.1".into(),
            prefix: 24,
        };
        assert!(!source_in_network(&malformed, "192.0.2.1".parse()?));
        let mut c = lease()?;
        c.definition.allowed_sources.clear();
        assert!(!c.permits_source("127.0.0.1".parse()?));
        Ok(())
    }
    #[test]
    fn publication_revision_and_short_lifetimes_are_bounded() -> Result<(), ContractError> {
        let c = lease()?;
        c.validate()?;
        let mut changed = c.clone();
        changed.choice_revision = changed.service_revision;
        assert!(changed.validate().is_err());
        let mut changed = c.clone();
        changed.expires_at_unix_ms += 1;
        assert!(changed.validate().is_err());
        let mut changed = c.clone();
        changed.ingress_claim_revision = 0;
        assert!(changed.validate().is_err());
        let mut changed = c.clone();
        changed.definition.limits.maximum_connections = 129;
        assert!(changed.validate().is_err());
        Ok(())
    }
    #[test]
    fn udp_challenges_require_native_transport_and_actual_canonical_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut c = lease()?;
        c.definition.requested_ingress = ServiceIngress::Udp { port: 29100 };
        let mut challenge = ServiceTunnelChallenge {
            lease_sha256: [7; 32],
            stream_id: id(12),
            nonce: [8; 32],
            peer_address: "127.0.0.1:12345".into(),
            transport: ServiceTunnelTransport::NativeDatagram,
            issued_at_unix_ms: 10001,
            expires_at_unix_ms: 12001,
        };
        challenge.validate(&c)?;
        challenge.transport = ServiceTunnelTransport::Stream;
        assert!(challenge.validate(&c).is_err());
        challenge.transport = ServiceTunnelTransport::NativeDatagram;
        for address in [
            "127.0.0.1:0",
            "192.0.2.1:12345",
            "[::ffff:127.0.0.1]:12345",
            "127.0.0.1:012345",
        ] {
            challenge.peer_address = address.into();
            assert!(challenge.validate(&c).is_err());
        }
        challenge.peer_address = "127.0.0.1:12345".into();
        challenge.expires_at_unix_ms += 1;
        assert!(challenge.validate(&c).is_err());
        Ok(())
    }
}
