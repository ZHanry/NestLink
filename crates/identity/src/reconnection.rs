//! A reconnect preserves consent and the old lease deadline; it only advances generations.
use super::{PermitSigner, Signer, VerifiedPermit, digest, domain_message, verify_signature};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, PermitClaims, RECONNECTION_BYTES,
    ReconnectionGrantClaims, SCHEMA_VERSION, SignedReconnectionGrant,
    api::{ReconnectionChoice, ReconnectionSubmission},
    decode_bounded,
};
use prost::Message;
const GRANT_DOMAIN: &[u8] = b"NestLink/v15/reconnection-grant/v1\0";
pub const NETWORK_RECOVERY_CAPABILITY: &str = "network-route-recovery-v1";
/// Hash only the immutable original signed claims in allocation order. Node
/// availability is an observation and cannot change the agreed original group.
pub fn route_set_fingerprint(path: &[u8], transits: [&[u8]; 2]) -> [u8; 32] {
    let mut bytes = b"NestLink/network/route-set-recovery/v1\0".to_vec();
    for claims in [path, transits[0], transits[1]] { bytes.extend_from_slice(&digest(claims)); }
    digest(&bytes)
}
/// Stable independent request IDs. HTTP retries cannot allocate another slot,
/// restore a consumed allocation, or restart a grant's lifetime.
pub fn network_recovery_id(previous: &PermitClaims, choice: &ReconnectionChoice, purpose: &str) -> Result<String, ContractError> {
    validate_choice(previous, choice)?;
    if choice.network_recovery.is_none() || !["allocation", "connectivity", "path", "transit"].contains(&purpose) {
        return Err(invalid());
    }
    let mut bytes = b"NestLink/network/recovery-request/v1\0".to_vec();
    bytes.extend_from_slice(purpose.as_bytes());
    bytes.extend_from_slice(&serde_json::to_vec(choice).map_err(|_| invalid())?);
    let hash = digest(&bytes);
    let mut id: [u8;16] = hash[..16].try_into().map_err(|_| invalid())?;
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(id).hyphenated().to_string())
}
pub fn validate_network_recovery(previous: &PermitClaims, choice: &nestlink_protocol::api::NetworkRouteRecoveryChoice) -> Result<(), ContractError> {
    if choice.version != 1 || choice.capability != NETWORK_RECOVERY_CAPABILITY
        || choice.previous_path_epoch != 1
        || !previous.paths.contains(&(nestlink_protocol::Path::Relay as i32))
        || [&choice.space_id, &choice.route_set_id, &choice.path_grant_id, &choice.target_node_id]
            .into_iter().any(|id| !nestlink_protocol::valid_id(id))
        || choice.expires_at_unix_ms <= previous.issued_at_unix_ms
        || choice.expires_at_unix_ms > previous.expires_at_unix_ms
    { return Err(invalid()); }
    for encoded in [&choice.original_fingerprint, &choice.transport_group, &choice.target_route_binding] {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != *encoded { return Err(invalid()); }
    }
    Ok(())
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::ReplayRejected, "invalid reconnection binding")
}
pub fn nonce(choice: &ReconnectionChoice) -> Result<[u8; 32], ContractError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&choice.nonce)
        .map_err(|_| invalid())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != choice.nonce {
        return Err(invalid());
    }
    bytes.try_into().map_err(|_| invalid())
}
pub fn validate_choice(
    previous: &PermitClaims,
    choice: &ReconnectionChoice,
) -> Result<(), ContractError> {
    previous.validate()?;
    nonce(choice)?;
    if let Some(recovery) = &choice.network_recovery { validate_network_recovery(previous, recovery)?; }
    if choice.previous_permit_sha256 != URL_SAFE_NO_PAD.encode(digest(&previous.encode_to_vec()))
        || previous.connection_generation.checked_add(1) != Some(choice.connection_generation)
        || previous.lease_sequence.checked_add(1) != Some(choice.lease_sequence)
        || choice.connection_generation > i64::MAX as u64
        || choice.lease_sequence > i64::MAX as u64
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn transcript(
    previous: &PermitClaims,
    device: &str,
    choice: &ReconnectionChoice,
) -> Result<DeviceActionClaims, ContractError> {
    validate_choice(previous, choice)?;
    if device != previous.controller_device_id && device != previous.host_device_id {
        return Err(invalid());
    }
    let choice_bytes = serde_json::to_vec(choice).map_err(|_| invalid())?;
    Ok(DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::Reconnect as i32,
        deployment_id: previous.deployment_id.clone(),
        security_epoch: previous.security_epoch,
        // This account identifies the existing consent, not the endpoint's HTTP login.
        account_id: previous.account_id.clone(),
        device_id: device.into(),
        resource_id: previous.session_id.clone(),
        challenge: digest(&previous.encode_to_vec()).to_vec(),
        payload_sha256: digest(&choice_bytes).to_vec(),
        expires_at_unix_ms: previous.expires_at_unix_ms,
    })
}
pub fn request_digest(request: &ReconnectionSubmission) -> Result<[u8; 32], ContractError> {
    Ok(digest(&serde_json::to_vec(request).map_err(|_| invalid())?))
}
pub fn validate_successor(
    previous: &PermitClaims,
    next: &PermitClaims,
    choice: &ReconnectionChoice,
) -> Result<(), ContractError> {
    validate_choice(previous, choice)?;
    next.validate()?;
    let mut expected = previous.clone();
    expected.connection_generation = choice.connection_generation;
    expected.lease_sequence = choice.lease_sequence;
    expected.issued_at_unix_ms = next.issued_at_unix_ms;
    if next != &expected || next.issued_at_unix_ms < previous.issued_at_unix_ms {
        return Err(invalid());
    }
    Ok(())
}
impl PermitSigner {
    pub fn sign_reconnection(
        &self,
        previous: &PermitClaims,
        request: &ReconnectionSubmission,
        next: &PermitClaims,
    ) -> Result<SignedReconnectionGrant, ContractError> {
        validate_successor(previous, next, &request.choice)?;
        let claims = ReconnectionGrantClaims {
            schema_version: SCHEMA_VERSION,
            previous_permit_sha256: digest(&previous.encode_to_vec()).to_vec(),
            request_sha256: request_digest(request)?.to_vec(),
            nonce: nonce(&request.choice)?.to_vec(),
            permit: self.sign(next)?.encode_to_vec(),
        }
        .encode_to_vec();
        if claims.len() as u64 > RECONNECTION_BYTES {
            return Err(invalid());
        }
        Ok(SignedReconnectionGrant {
            signature: self
                .key
                .sign(&domain_message(GRANT_DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_reconnection(
    bytes: &[u8],
    issuer: &[u8; 32],
    previous: &PermitClaims,
    request: &ReconnectionSubmission,
) -> Result<VerifiedPermit, ContractError> {
    let signed: SignedReconnectionGrant = decode_bounded(bytes, RECONNECTION_BYTES + 128)?;
    if signed.claims.len() as u64 > RECONNECTION_BYTES {
        return Err(invalid());
    }
    verify_signature(issuer, GRANT_DOMAIN, &signed.claims, &signed.signature)?;
    let claims: ReconnectionGrantClaims = decode_bounded(&signed.claims, RECONNECTION_BYTES)?;
    if claims.schema_version != SCHEMA_VERSION
        || claims.previous_permit_sha256 != digest(&previous.encode_to_vec())
        || claims.request_sha256 != request_digest(request)?
        || claims.nonce != nonce(&request.choice)?
    {
        return Err(invalid());
    }
    let permit = super::verify_permit(&claims.permit, issuer)?;
    validate_successor(previous, permit.claims(), &request.choice)?;
    Ok(permit)
}
#[cfg(test)]
mod tests;
