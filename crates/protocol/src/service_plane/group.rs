//! Explicit multi-edge publication. Legacy single-edge lease JSON and signing
//! purpose are unchanged; grouped leases require the independent group purpose.
use super::*;
use crate::api::ServiceLimits;

pub const SERVICE_EDGE_GROUP_VERSION: u32 = 1;
pub const SERVICE_EDGE_GROUP_MAX_MEMBERS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeGroupMember {
    pub node_id: String,
    pub namespace_revision: u64,
    /// Operator-approved fixed-entry backend, distinct from the signed QUIC
    /// attachment endpoint. No DNS-derived or visitor-selected destination.
    pub ingress_ip: IpAddr,
    pub limits: ServiceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeGroupUpdate {
    pub group_version: u32,
    pub expected_revision: u64,
    pub expected_service_revision: u64,
    pub public_ips: Vec<IpAddr>,
    /// Strict node-ID order is canonical and prevents duplicate allocation.
    pub members: Vec<ServiceEdgeGroupMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeGroupView {
    pub group_version: u32,
    pub group_id: String,
    pub revision: u64,
    pub service_id: String,
    pub service_revision: u64,
    pub definition_sha256: [u8; 32],
    pub target_sha256: [u8; 32],
    pub public_ips: Vec<IpAddr>,
    pub members: Vec<ServiceEdgeGroupMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeGroupBinding {
    pub group: ServiceEdgeGroupView,
    pub member_node_id: String,
    /// Repeated here so admission never falls back to the whole definition's
    /// limits when a malformed binding names a missing member.
    pub allocation: ServiceLimits,
    pub aggregate_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceGroupPublicationRequest {
    pub group_version: u32,
    pub group_id: String,
    pub expected_group_revision: u64,
    pub expected_service_revision: u64,
    /// The native owner explicitly selected this complete allocation. A
    /// management download alone does not select additional host recipients.
    pub aggregate_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceGroupPublicationGrant {
    pub group: ServiceEdgeGroupView,
    /// In exactly the same canonical order as group.members.
    pub members: Vec<publication::ServicePublicationGrant>,
}

fn unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
}
fn valid_members(public_ips: &[IpAddr], members: &[ServiceEdgeGroupMember]) -> bool {
    !public_ips.is_empty() && public_ips.len() <= 8
        && public_ips.iter().all(|ip| unicast(*ip))
        && public_ips.windows(2).all(|pair| pair[0] < pair[1])
        && (2..=SERVICE_EDGE_GROUP_MAX_MEMBERS).contains(&members.len())
        && members.windows(2).all(|pair| pair[0].node_id < pair[1].node_id)
        && members.iter().all(|member| valid_id(&member.node_id)
            && revision_valid(member.namespace_revision) && unicast(member.ingress_ip))
        && members.iter().enumerate().all(|(index,member)|
            !members[..index].iter().any(|prior| prior.ingress_ip == member.ingress_ip))
}
impl ServiceEdgeGroupUpdate {
    pub fn validate(&self, definition: &ServiceDefinition) -> Result<(), ContractError> {
        if self.group_version != SERVICE_EDGE_GROUP_VERSION
            || self.expected_revision > i64::MAX as u64
            || !revision_valid(self.expected_service_revision)
            || !valid_members(&self.public_ips, &self.members)
        { return Err(invalid()); }
        validate_allocation(&self.members, definition)
    }
}
impl ServiceEdgeGroupView {
    pub fn validate(&self, definition: &ServiceDefinition) -> Result<(), ContractError> {
        if self.group_version != SERVICE_EDGE_GROUP_VERSION
            || !valid_id(&self.group_id) || !valid_id(&self.service_id)
            || !revision_valid(self.revision) || !revision_valid(self.service_revision)
            || !valid_members(&self.public_ips, &self.members)
        { return Err(invalid()); }
        validate_allocation(&self.members, definition)
    }
    pub fn member(&self, node_id: &str) -> Result<&ServiceEdgeGroupMember, ContractError> {
        self.members.iter().find(|member| member.node_id == node_id).ok_or_else(invalid)
    }
}
fn validate_allocation(members: &[ServiceEdgeGroupMember], definition: &ServiceDefinition) -> Result<(), ContractError> {
    definition.validate()?;
    if !members.iter().any(|member| member.node_id == definition.edge_node_id) { return Err(invalid()); }
    let mut connections = 0u64; let mut rate = 0u64; let mut bytes = 0u64;
    for member in members {
        let limits = member.limits;
        if limits.maximum_connections == 0 || limits.bytes_per_second == 0 || limits.maximum_bytes == 0
            || limits.idle_timeout_seconds != definition.limits.idle_timeout_seconds { return Err(invalid()); }
        connections = connections.checked_add(u64::from(limits.maximum_connections)).ok_or_else(invalid)?;
        rate = rate.checked_add(limits.bytes_per_second).ok_or_else(invalid)?;
        bytes = bytes.checked_add(limits.maximum_bytes).ok_or_else(invalid)?;
    }
    if connections > u64::from(definition.limits.maximum_connections)
        || rate > definition.limits.bytes_per_second || bytes > definition.limits.maximum_bytes { return Err(invalid()); }
    Ok(())
}
impl ServiceEdgeGroupBinding {
    pub fn validate(&self, lease: &ServiceLeaseClaims) -> Result<(), ContractError> {
        self.group.validate(&lease.definition)?;
        let member = self.group.member(&self.member_node_id)?;
        if self.group.service_id != lease.service_id || self.group.service_revision != lease.service_revision
            || self.group.definition_sha256 != lease.definition_sha256 || self.group.target_sha256 != lease.target_sha256
            || member.namespace_revision != lease.ingress_claim_revision || member.limits != self.allocation
            || self.aggregate_sha256 == [0;32] { return Err(invalid()); }
        Ok(())
    }
}
impl ServiceGroupPublicationRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.group_version != SERVICE_EDGE_GROUP_VERSION || !valid_id(&self.group_id)
            || !revision_valid(self.expected_group_revision) || !revision_valid(self.expected_service_revision)
            || self.aggregate_sha256 == [0;32] { return Err(invalid()); }
        Ok(())
    }
}
