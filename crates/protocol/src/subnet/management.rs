//! Online management envelopes. Every returned credential still needs pinned
//! signature and current-node verification before local approval or use.
use crate::{api::{NetworkGrantView, NetworkPolicyView}, network::IpPrefix, network_topology::BootIncarnation};
use super::SignedSubnetMapping;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubnetMappingRequest {
    pub mapping_version: u32,
    pub grant_id: String,
    pub gateway_node_id: String,
    pub route_export_grant_id: String,
    pub expected_revision: u64,
    pub expected_policy_epoch: u64,
    pub expected_gateway_incarnation: BootIncarnation,
    pub original: IpPrefix,
    pub alias: IpPrefix,
    /// Effective expiry is intersected with the original export and currently
    /// accepted node lease. A read never renews the resulting signed interval.
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubnetGatewayView {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub incarnation: BootIncarnation,
    pub mapping_revision: u64,
    pub lease_expires_at_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubnetMappingView {
    pub mapping: SignedSubnetMapping,
    pub route_export: NetworkGrantView,
    pub gateway: SubnetGatewayView,
    pub policy: NetworkPolicyView,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubnetMappingRevoke {
    pub expected_revision: u64,
    pub expected_mapping_revision: u64,
}
