//! Separate TURN control purposes; native relay signatures cannot be reused.
use super::{NodeIdentity, NodePolicySigner};
use crate::{InstallationIdentity, PermitSigner, Signer, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, NODE_MESSAGE_BYTES,
    NODE_RESOURCE_MESSAGE_BYTES, PermitClaims, SignedTurnCredentials, SignedTurnPeerBinding,
    SignedTurnResourceQuery, SignedTurnResourceSnapshot, TurnCredentialsClaims,
    TurnPeerBindingClaims, TurnResourceQueryClaims, TurnResourceSnapshotClaims,
    api::TurnCredentialRequest, decode_bounded, turn::TURN_BINDING_BYTES,
};
use prost::Message;
const QUERY: &[u8] = b"NestLink/v15/turn-resource-query/v1\0";
const SNAPSHOT: &[u8] = b"NestLink/v15/turn-resource-snapshot/v1\0";
const PEERS: &[u8] = b"NestLink/v15/turn-peer-binding/v1\0";
const CREDENTIALS: &[u8] = b"NestLink/v15/turn-credentials/v1\0";
const REQUEST: &[u8] = b"NestLink/v15/turn-credential-request/v1\0";
pub fn credential_request_transcript(
    permit: &PermitClaims,
    account: &str,
    request: &TurnCredentialRequest,
) -> Result<DeviceActionClaims, ContractError> {
    if !nestlink_protocol::valid_id(&request.allocation_id)
        || request.network_generation == 0
        || request.network_generation > i64::MAX as u64
    {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid TURN credential request",
        ));
    }
    let mut transcript = crate::relay_transcript(
        permit,
        account,
        &request.device_id,
        &digest(&permit.encode_to_vec()),
    )?;
    transcript.action = DeviceAction::TurnAllocate as i32;
    let mut payload = request.allocation_id.as_bytes().to_vec();
    payload.extend_from_slice(&request.network_generation.to_be_bytes());
    transcript.payload_sha256 = digest(&domain_message(REQUEST, &payload)).to_vec();
    Ok(transcript)
}
impl PermitSigner {
    pub fn sign_turn_credentials(
        &self,
        c: &TurnCredentialsClaims,
    ) -> Result<SignedTurnCredentials, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims, TURN_BINDING_BYTES)?;
        Ok(SignedTurnCredentials {
            signature: self
                .key
                .sign(&domain_message(CREDENTIALS, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_turn_credentials(
    s: &SignedTurnCredentials,
    issuer: &[u8; 32],
) -> Result<TurnCredentialsClaims, ContractError> {
    bounded(&s.claims, TURN_BINDING_BYTES)?;
    verify_signature(issuer, CREDENTIALS, &s.claims, &s.signature)?;
    let c: TurnCredentialsClaims = decode_canonical(&s.claims, TURN_BINDING_BYTES)?;
    c.validate()?;
    Ok(c)
}
fn bounded(bytes: &[u8], maximum: u64) -> Result<(), ContractError> {
    if bytes.len() as u64 > maximum {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "TURN message budget exceeded",
        ));
    }
    Ok(())
}
impl NodeIdentity {
    pub fn sign_turn_resource_query(
        &self,
        c: &TurnResourceQueryClaims,
    ) -> Result<SignedTurnResourceQuery, ContractError> {
        c.validate()?;
        let claims = c.encode_to_vec();
        bounded(&claims, NODE_MESSAGE_BYTES)?;
        Ok(SignedTurnResourceQuery {
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
    pub fn sign_turn_resource_snapshot(
        &self,
        c: &TurnResourceSnapshotClaims,
    ) -> Result<SignedTurnResourceSnapshot, ContractError> {
        c.validate()?;
        validate_canonical_peer_bindings(c)?;
        let claims = c.encode_to_vec();
        bounded(&claims, NODE_RESOURCE_MESSAGE_BYTES)?;
        Ok(SignedTurnResourceSnapshot {
            signature: self
                .key
                .sign(&domain_message(SNAPSHOT, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_turn_resource_query(
    s: &SignedTurnResourceQuery,
    key: &[u8; 32],
) -> Result<TurnResourceQueryClaims, ContractError> {
    bounded(&s.claims, NODE_MESSAGE_BYTES)?;
    verify_signature(key, QUERY, &s.claims, &s.signature)?;
    let c: TurnResourceQueryClaims = decode_canonical(&s.claims, NODE_MESSAGE_BYTES)?;
    c.validate()?;
    Ok(c)
}
pub fn verify_turn_resource_snapshot(
    s: &SignedTurnResourceSnapshot,
    issuer: &[u8; 32],
    request: &SignedTurnResourceQuery,
) -> Result<TurnResourceSnapshotClaims, ContractError> {
    bounded(&s.claims, NODE_RESOURCE_MESSAGE_BYTES)?;
    bounded(&request.claims, NODE_MESSAGE_BYTES)?;
    verify_signature(issuer, SNAPSHOT, &s.claims, &s.signature)?;
    let c: TurnResourceSnapshotClaims = decode_canonical(&s.claims, NODE_RESOURCE_MESSAGE_BYTES)?;
    c.validate()?;
    validate_canonical_peer_bindings(&c)?;
    let q: TurnResourceQueryClaims = decode_canonical(&request.claims, NODE_MESSAGE_BYTES)?;
    q.validate()?;
    if c.query.as_ref() != Some(&q) || c.query_sha256 != digest(&request.claims) {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "TURN snapshot does not match query",
        ));
    }
    Ok(c)
}
impl InstallationIdentity {
    pub fn sign_turn_peer_binding(
        &self,
        c: &TurnPeerBindingClaims,
    ) -> Result<Vec<u8>, ContractError> {
        c.validate()?;
        let fingerprint = digest(&self.public_key());
        if c.controller_key_sha256 != fingerprint && c.host_key_sha256 != fingerprint {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "TURN peer signer is not an endpoint",
            ));
        }
        let claims = c.encode_to_vec();
        bounded(&claims, TURN_BINDING_BYTES)?;
        Ok(self
            .key
            .sign(&domain_message(PEERS, &claims))
            .to_bytes()
            .to_vec())
    }
}
pub fn verify_turn_peer_signature(
    claims: &[u8],
    key: &[u8; 32],
    signature: &[u8],
) -> Result<TurnPeerBindingClaims, ContractError> {
    bounded(claims, TURN_BINDING_BYTES)?;
    verify_signature(key, PEERS, claims, signature)?;
    let c: TurnPeerBindingClaims = decode_canonical(claims, TURN_BINDING_BYTES)?;
    c.validate()?;
    let fingerprint = digest(key);
    if c.controller_key_sha256 != fingerprint && c.host_key_sha256 != fingerprint {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "TURN peer key does not match binding",
        ));
    }
    Ok(c)
}
pub fn verify_turn_peer_binding(
    s: &SignedTurnPeerBinding,
    controller: &[u8; 32],
    host: &[u8; 32],
) -> Result<TurnPeerBindingClaims, ContractError> {
    let c = verify_turn_peer_signature(&s.claims, controller, &s.controller_signature)?;
    verify_turn_peer_signature(&s.claims, host, &s.host_signature)?;
    if c.controller_key_sha256 != digest(controller) || c.host_key_sha256 != digest(host) {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "TURN peer roles do not match keys",
        ));
    }
    Ok(c)
}

fn decode_canonical<M: Message + Default>(bytes: &[u8], maximum: u64) -> Result<M, ContractError> {
    let claims: M = decode_bounded(bytes, maximum)?;
    if claims.encode_to_vec().as_slice() != bytes {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "noncanonical TURN protobuf claims",
        ));
    }
    Ok(claims)
}

fn validate_canonical_peer_bindings(
    snapshot: &TurnResourceSnapshotClaims,
) -> Result<(), ContractError> {
    for signed in &snapshot.peer_bindings {
        let claims: TurnPeerBindingClaims = decode_canonical(&signed.claims, TURN_BINDING_BYTES)?;
        claims.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
