//! Node policy-key trust binds a fresh snapshot and delegates the allocation issuer.
use super::{NodeIdentity, NodePolicySigner};
use crate::{Signer, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, ErrorCode, NODE_MESSAGE_BYTES, NODE_RESOURCE_MESSAGE_BYTES,
    NodeResourceQueryClaims, NodeResourceSnapshotClaims, SignedNodeResourceQuery,
    SignedNodeResourceSnapshot, decode_bounded,
};
use prost::Message;
const QUERY: &[u8] = b"NestLink/v15/node-resource-query/v1\0";
const SNAPSHOT: &[u8] = b"NestLink/v15/node-resource-snapshot/v1\0";
fn bounded(bytes: &[u8], maximum: u64) -> Result<(), ContractError> {
    if bytes.len() as u64 > maximum {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "node resource message budget exceeded",
        ));
    }
    Ok(())
}
impl NodeIdentity {
    pub fn sign_resource_query(
        &self,
        c: &NodeResourceQueryClaims,
    ) -> Result<SignedNodeResourceQuery, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims, NODE_MESSAGE_BYTES)?;
        Ok(SignedNodeResourceQuery {
            signature: self
                .key
                .sign(&domain_message(QUERY, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl NodePolicySigner {
    pub fn sign_resource_snapshot(
        &self,
        c: &NodeResourceSnapshotClaims,
    ) -> Result<SignedNodeResourceSnapshot, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims, NODE_RESOURCE_MESSAGE_BYTES)?;
        Ok(SignedNodeResourceSnapshot {
            signature: self
                .key
                .sign(&domain_message(SNAPSHOT, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_resource_query(
    s: &SignedNodeResourceQuery,
    key: &[u8; 32],
) -> Result<NodeResourceQueryClaims, ContractError> {
    bounded(&s.claims, NODE_MESSAGE_BYTES)?;
    verify_signature(key, QUERY, &s.claims, &s.signature)?;
    let c: NodeResourceQueryClaims = decode_bounded(&s.claims, NODE_MESSAGE_BYTES)?;
    c.validate()?;
    Ok(c)
}
pub fn verify_resource_snapshot(
    s: &SignedNodeResourceSnapshot,
    issuer: &[u8; 32],
    request: &SignedNodeResourceQuery,
) -> Result<NodeResourceSnapshotClaims, ContractError> {
    bounded(&s.claims, NODE_RESOURCE_MESSAGE_BYTES)?;
    bounded(&request.claims, NODE_MESSAGE_BYTES)?;
    verify_signature(issuer, SNAPSHOT, &s.claims, &s.signature)?;
    let c: NodeResourceSnapshotClaims = decode_bounded(&s.claims, NODE_RESOURCE_MESSAGE_BYTES)?;
    c.validate()?;
    let q: NodeResourceQueryClaims = decode_bounded(&request.claims, NODE_MESSAGE_BYTES)?;
    q.validate()?;
    if c.query.as_ref() != Some(&q) || c.query_sha256 != digest(&request.claims) {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "node resource response does not match request",
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests;
