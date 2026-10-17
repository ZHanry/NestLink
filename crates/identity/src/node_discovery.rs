//! Discovery has its own signing purpose under the already pinned permit issuer.
use super::{PermitSigner, Signer, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, NODE_DISCOVERY_BYTES,
    NodeDiscoveryClaims, PermitClaims, SignedNodeDiscovery, decode_bounded,
};
use prost::Message;
const DISCOVERY: &[u8] = b"NestLink/v15/node-discovery/v1\0";
pub fn discovery_transcript(
    permit: &PermitClaims,
    account: &str,
    device: &str,
    nonce: &[u8; 32],
) -> Result<DeviceActionClaims, ContractError> {
    let mut c = super::relay_transcript(permit, account, device, nonce)?;
    c.action = DeviceAction::RelayDiscover as i32;
    Ok(c)
}
impl PermitSigner {
    pub fn sign_node_discovery(
        &self,
        c: &NodeDiscoveryClaims,
    ) -> Result<SignedNodeDiscovery, ContractError> {
        c.validate()?;
        let bytes = c.encode_to_vec();
        if bytes.len() as u64 > NODE_DISCOVERY_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "discovery budget exceeded",
            ));
        }
        Ok(SignedNodeDiscovery {
            signature: self
                .key
                .sign(&domain_message(DISCOVERY, &bytes))
                .to_bytes()
                .to_vec(),
            claims: bytes,
        })
    }
}
#[derive(Debug)]
pub struct VerifiedNodeDiscovery {
    claims: NodeDiscoveryClaims,
}
impl VerifiedNodeDiscovery {
    pub fn claims(&self) -> &NodeDiscoveryClaims {
        &self.claims
    }
    pub fn matches(
        &self,
        permit: &PermitClaims,
        account: &str,
        device: &str,
        nonce: &[u8; 32],
    ) -> Result<bool, ContractError> {
        let t = discovery_transcript(permit, account, device, nonce)?;
        let c = &self.claims;
        let key = if device == permit.controller_device_id {
            &permit.controller_key_sha256
        } else {
            &permit.host_key_sha256
        };
        Ok(c.deployment_id == permit.deployment_id
            && c.security_epoch == permit.security_epoch
            && c.session_id == permit.session_id
            && c.account_id == account
            && c.device_id == device
            && c.device_key_sha256 == *key
            && c.permit_sha256 == digest(&permit.encode_to_vec())
            && c.request_sha256 == digest(&t.encode_to_vec())
            && c.nonce == nonce
            && c.issued_at_unix_ms >= permit.issued_at_unix_ms
            && c.expires_at_unix_ms <= permit.expires_at_unix_ms)
    }
}
pub fn verify_node_discovery(
    bytes: &[u8],
    issuer: &[u8; 32],
) -> Result<VerifiedNodeDiscovery, ContractError> {
    let s: SignedNodeDiscovery = decode_bounded(bytes, NODE_DISCOVERY_BYTES + 128)?;
    if s.claims.len() as u64 > NODE_DISCOVERY_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "discovery budget exceeded",
        ));
    }
    verify_signature(issuer, DISCOVERY, &s.claims, &s.signature)?;
    let claims: NodeDiscoveryClaims = decode_bounded(&s.claims, NODE_DISCOVERY_BYTES)?;
    claims.validate()?;
    Ok(VerifiedNodeDiscovery { claims })
}
#[cfg(test)]
mod tests;
