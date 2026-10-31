//! Exact subnet translation authority. Parsing never publishes a route or
//! authorizes packet forwarding; NetworkAccess remains independently required.
pub mod management;
use crate::{
    ContractError, ErrorCode,
    network::{GrantScope, IpPrefix, PeerId},
    network_topology::BootIncarnation,
    valid_id,
};
use serde::{Deserialize, Serialize};

pub const SUBNET_MAPPING_VERSION: u32 = 1;
pub const SUBNET_MAPPING_BYTES: usize = 4096;
pub const MAX_SUBNET_MAPPING_MS: u64 = 15 * 60 * 1000;
pub const MAX_SUBNET_MAPPINGS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetMappingClaims {
    pub mapping_version: u32,
    pub scope: GrantScope,
    /// Current registered data-node identity, independently checked against
    /// management's accepted node lease; a claimed PeerId is insufficient.
    pub gateway_node_id: String,
    pub gateway_public_key: [u8; 32],
    pub gateway: PeerId,
    pub gateway_incarnation: BootIncarnation,
    pub original: IpPrefix,
    /// NetworkAccess uses this exact wire prefix. The mapping authenticates
    /// which original LAN it denotes; it grants no L3/L4 business access.
    pub alias: IpPrefix,
    pub route_export_digest: [u8; 32],
    pub mapping_revision: u64,
}
impl SubnetMappingClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.scope.validate()?;
        self.gateway.validate()?;
        self.gateway_incarnation.validate()?;
        self.original.validate()?;
        self.alias.validate()?;
        if self.mapping_version != SUBNET_MAPPING_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported subnet mapping version",
            ));
        }
        if !valid_id(&self.gateway_node_id)
            || self.gateway_public_key == [0; 32]
            || self.gateway != PeerId::from_public_key(&self.gateway_public_key)
            || self.route_export_digest == [0; 32]
            || self.mapping_revision == 0
            || self.mapping_revision > i64::MAX as u64
            || self.scope.policy_epoch > i64::MAX as u64
            || self.scope.expires_at_ms > i64::MAX as u64
            || self.scope.expires_at_ms - self.scope.not_before_ms > MAX_SUBNET_MAPPING_MS
            || self.original.network.is_ipv4() != self.alias.network.is_ipv4()
            || self.original.prefix_len != self.alias.prefix_len
        {
            return Err(invalid(
                "invalid exact subnet mapping identity, prefix or lifetime",
            ));
        }
        // IPv6 routing is supported by this contract. IPv6 translation needs a
        // separate reviewed provider and qualification, never an IPv4 fallback.
        if self.original.network.is_ipv6() && self.original != self.alias {
            return Err(invalid(
                "IPv6 subnet translation is not supported by mapping version one",
            ));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("subnet mapping serialization failed"))?;
        if bytes.len() > SUBNET_MAPPING_BYTES {
            return Err(invalid("subnet mapping byte budget exceeded"));
        }
        Ok(bytes)
    }
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > SUBNET_MAPPING_BYTES {
            return Err(invalid("subnet mapping byte budget exceeded"));
        }
        let claims: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("malformed subnet mapping claims"))?;
        if claims.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical subnet mapping claims"));
        }
        Ok(claims)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedSubnetMapping {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedSubnetMapping {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.signature.len() != 64 {
            return Err(invalid("invalid subnet mapping signature length"));
        }
        SubnetMappingClaims::decode_canonical(&self.claims)?;
        Ok(())
    }
}
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

#[cfg(test)]
mod tests;
