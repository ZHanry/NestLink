//! Explicit raw IP admission. These management envelopes never enable a TUN
//! or replace the local operating-system owner's approval of a grant digest.
use crate::{
    api::NetworkGrantView,
    network::{IpPrefix, NetworkRule},
    spaces::addressing::SpaceAddressDirectory,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessRequest {
    pub access_grant_id: String,
    pub connectivity_grant_id: String,
    pub path_grant_id: String,
    pub source_installation_id: String,
    pub destination_installation_id: String,
    pub source_membership_grant_id: String,
    pub destination_membership_grant_id: String,
    pub expected_revision: u64,
    pub expected_policy_epoch: u64,
    pub expected_directory_revision: u64,
    pub expected_source_address_epoch: u64,
    pub expected_destination_address_epoch: u64,
    /// The initial host-only API accepts only the exact current /32 or /128.
    pub source_prefixes: Vec<IpPrefix>,
    pub destination_prefixes: Vec<IpPrefix>,
    /// Inbound means source -> destination; Outbound means destination ->
    /// source at both endpoints, regardless of which peer dials the carrier.
    pub rules: Vec<NetworkRule>,
    pub byte_limit: u64,
    /// At most 60 seconds; issuance also intersects both original memberships.
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessView {
    pub source_membership: NetworkGrantView,
    pub destination_membership: NetworkGrantView,
    pub access: NetworkGrantView,
    pub connectivity: NetworkGrantView,
    pub path: NetworkGrantView,
    /// Fresh grant-scoped disclosure of exactly the two authorized endpoints.
    /// This does not widen the ordinary directory API's visibility. Its rows
    /// still confer no packet authority without independently verified grants.
    pub address_directory: SpaceAddressDirectory,
    /// Fresh online association to the exact original mapping credentials.
    /// Empty for the original host-only API; never populated from peer input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnet_mappings: Vec<crate::subnet::management::SubnetMappingView>,
}

/// A fresh online start attempt by the account that owns this exact endpoint.
/// The public owner ID correlates one ordinary runtime; it is not a capability.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessStart {
    pub installation_id: String,
    pub owner_id: String,
}
