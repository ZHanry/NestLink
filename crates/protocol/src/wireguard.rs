//! A standard WireGuard client's independent key binding to one original raw
//! packet business grant. This purpose cannot replace NetworkAccess or a
//! private-service grant and never grants a whole portal's permissions.
pub mod management;
use crate::{ContractError, ErrorCode, network::GrantScope, network_topology::BootIncarnation, valid_id};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const WIREGUARD_BINDING_VERSION: u32 = 1;
pub const WIREGUARD_BINDING_BYTES: usize = 4096;
pub const MAX_WIREGUARD_CLIENTS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientBindingClaims {
    pub binding_version: u32,
    pub scope: GrantScope,
    pub client_id: String,
    pub client_revision: u64,
    pub account_id: String,
    pub installation_id: String,
    /// A WireGuard X25519 public key, never an Ed25519 installation identity.
    pub client_public_key: [u8; 32],
    pub client_address: Ipv4Addr,
    pub portal_node_id: String,
    pub portal_public_key: [u8; 32],
    pub portal_incarnation: BootIncarnation,
    pub access_grant_id: String,
    pub access_digest: [u8; 32],
    /// Equal to the original NetworkAccess byte ceiling. Issuance reserves
    /// that entire original promise against this stable client's finite cap.
    pub committed_bytes: u64,
}
impl WireGuardClientBindingClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.scope.validate()?;
        self.portal_incarnation.validate()?;
        if self.binding_version != WIREGUARD_BINDING_VERSION {
            return Err(ContractError::new(ErrorCode::ProtocolMismatch, "unsupported WireGuard client binding"));
        }
        if [&self.client_id,&self.account_id,&self.installation_id,&self.portal_node_id,&self.access_grant_id].iter().any(|id| !valid_id(id))
            || self.scope.grant_id == self.access_grant_id
            || self.client_revision == 0 || self.client_revision > i64::MAX as u64
            || self.client_public_key == [0;32] || self.portal_public_key == [0;32]
            || self.access_digest == [0;32] || self.committed_bytes == 0 || self.committed_bytes > i64::MAX as u64
            || !self.client_address.is_private() || self.client_address.octets()[3] == 0 || self.client_address.octets()[3] == 255
            || self.scope.policy_epoch > i64::MAX as u64 || self.scope.expires_at_ms > i64::MAX as u64
        { return Err(invalid("invalid WireGuard client identity, exact address or budget")); }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let bytes=serde_json::to_vec(self).map_err(|_|invalid("WireGuard client serialization failed"))?;
        if bytes.len()>WIREGUARD_BINDING_BYTES {return Err(invalid("WireGuard client binding byte budget exceeded"));}
        Ok(bytes)
    }
    pub fn decode_canonical(bytes:&[u8])->Result<Self,ContractError> {
        if bytes.len()>WIREGUARD_BINDING_BYTES {return Err(invalid("WireGuard client binding byte budget exceeded"));}
        let value:Self=serde_json::from_slice(bytes).map_err(|_|invalid("malformed WireGuard client binding"))?;
        if value.canonical_bytes()?!=bytes {return Err(invalid("noncanonical WireGuard client binding"));}
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedWireGuardClientBinding {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedWireGuardClientBinding {
    pub fn validate(&self)->Result<(),ContractError> {
        if self.claims.is_empty() || self.claims.len()>WIREGUARD_BINDING_BYTES || self.signature.len()!=64 {
            return Err(invalid("invalid signed WireGuard client binding size"));
        }
        Ok(())
    }
}
fn invalid(reason:&'static str)->ContractError {ContractError::new(ErrorCode::InvalidMessage,reason)}
