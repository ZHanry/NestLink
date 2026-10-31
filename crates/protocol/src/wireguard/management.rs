//! Explicit account management. Returned JSON is never a live packet owner.
use super::SignedWireGuardClientBinding;
use crate::{api::NetworkPolicyView, network_access::NetworkAccessView, network_topology::BootIncarnation};
use serde::{Deserialize,Serialize};
use schemars::JsonSchema;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientBindingRequest {
    pub binding_version:u32,
    pub grant_id:String,
    pub client_id:String,
    pub expected_client_revision:u64,
    pub expected_revision:u64,
    pub expected_policy_epoch:u64,
    pub installation_id:String,
    pub portal_node_id:String,
    pub expected_portal_incarnation:BootIncarnation,
    pub access_grant_id:String,
    pub client_public_key:[u8;32],
    pub client_address:Ipv4Addr,
    /// Immutable across this client's rotations. Increasing a limit requires a
    /// separately reviewed quota operation, not reissuing this credential.
    pub total_byte_ceiling:u64,
    pub expires_at_ms:u64,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientBindingView {
    pub binding:SignedWireGuardClientBinding,
    pub packet_access:NetworkAccessView,
    pub policy:NetworkPolicyView,
    pub total_byte_ceiling:u64,
    pub committed_bytes:u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientRevoke {
    pub expected_revision:u64,
    pub expected_client_revision:u64,
}
