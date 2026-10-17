//! Independent node-close and control acknowledgement signing purposes.
use super::{NodeIdentity, NodePolicySigner};
use crate::{Signer, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, ErrorCode, RELAY_CLOSE_MESSAGE_BYTES, RelayCloseAckClaims, RelayCloseClaims,
    SignedRelayClose, SignedRelayCloseAck, decode_bounded,
};
use prost::Message;
const CLOSE: &[u8] = b"NestLink/v15/node-relay-close/v1\0";
const ACK: &[u8] = b"NestLink/v15/node-relay-close-ack/v1\0";
#[cfg(test)]
mod tests;
fn bounded(bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.len() as u64 > RELAY_CLOSE_MESSAGE_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "relay close message budget exceeded",
        ));
    }
    Ok(())
}
impl NodeIdentity {
    pub fn sign_relay_close(
        &self,
        c: &RelayCloseClaims,
    ) -> Result<SignedRelayClose, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims)?;
        Ok(SignedRelayClose {
            signature: self
                .key
                .sign(&domain_message(CLOSE, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl NodePolicySigner {
    pub fn sign_relay_close_ack(
        &self,
        c: &RelayCloseAckClaims,
    ) -> Result<SignedRelayCloseAck, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims)?;
        Ok(SignedRelayCloseAck {
            signature: self
                .key
                .sign(&domain_message(ACK, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_relay_close(
    s: &SignedRelayClose,
    node_key: &[u8; 32],
) -> Result<RelayCloseClaims, ContractError> {
    bounded(&s.claims)?;
    verify_signature(node_key, CLOSE, &s.claims, &s.signature)?;
    let c: RelayCloseClaims = decode_bounded(&s.claims, RELAY_CLOSE_MESSAGE_BYTES)?;
    c.validate()?;
    Ok(c)
}
pub fn verify_relay_close_ack(
    s: &SignedRelayCloseAck,
    policy_key: &[u8; 32],
    request: &SignedRelayClose,
) -> Result<RelayCloseAckClaims, ContractError> {
    bounded(&s.claims)?;
    bounded(&request.claims)?;
    verify_signature(policy_key, ACK, &s.claims, &s.signature)?;
    let c: RelayCloseAckClaims = decode_bounded(&s.claims, RELAY_CLOSE_MESSAGE_BYTES)?;
    c.validate()?;
    let q: RelayCloseClaims = decode_bounded(&request.claims, RELAY_CLOSE_MESSAGE_BYTES)?;
    q.validate()?;
    if c.deployment_id != q.deployment_id
        || c.security_epoch != q.security_epoch
        || c.node_id != q.node_id
        || c.runtime_id != q.runtime_id
        || c.runtime_generation != q.runtime_generation
        || c.allocation_id != q.allocation_id
        || c.close_sha256 != digest(&request.claims)
        || c.accepted_at_unix_ms.saturating_add(1000) < q.closed_at_unix_ms
    {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "relay close acknowledgement does not match request",
        ));
    }
    Ok(c)
}
