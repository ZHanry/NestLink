//! Domain-separated relay reservations and endpoint request transcripts.
use super::{PermitSigner, Signer, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, Path, PermitClaims,
    RelayAllocationClaims, SignedRelayAllocation, decode_bounded, nodes::NODE_MESSAGE_BYTES,
};
use prost::Message;
const ALLOCATION_DOMAIN: &[u8] = b"NestLink/v15/relay-allocation/v1\0";
const BINDING_DOMAIN: &[u8] = b"NestLink/v15/relay-session-binding/v1\0";
const GRANT_BINDING: &[u8] = b"NestLink/v15/relay-allocation-binding/v1\0";
const ENDPOINT: &[u8] = b"NestLink/v15/node-relay-endpoint/v1\0";
pub fn allocation_binding(c: &RelayAllocationClaims) -> Result<[u8; 32], ContractError> {
    c.validate()?;
    let mut copy = c.clone();
    copy.grant_sequence = 0;
    copy.issued_at_unix_ms = 0;
    copy.expires_at_unix_ms = 0;
    Ok(digest(&domain_message(
        GRANT_BINDING,
        &copy.encode_to_vec(),
    )))
}
pub fn node_relay_transcript(
    c: &RelayAllocationClaims,
    device: &str,
    transport: nestlink_protocol::RelayTransport,
    challenge: &[u8; 32],
) -> Result<DeviceActionClaims, ContractError> {
    c.validate()?;
    let account = if device == c.controller_device_id {
        &c.controller_account_id
    } else if device == c.host_device_id {
        &c.host_account_id
    } else {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "not a relay endpoint",
        ));
    };
    if !c.transports.contains(&(transport as i32)) {
        return Err(ContractError::new(
            ErrorCode::RelayDisabled,
            "relay transport not allocated",
        ));
    }
    let mut payload = c.encode_to_vec();
    payload.extend_from_slice(&(transport as i32).to_be_bytes());
    Ok(DeviceActionClaims {
        schema_version: c.schema_version,
        action: DeviceAction::NodeRelayConnect as i32,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        account_id: account.clone(),
        device_id: device.into(),
        resource_id: c.allocation_id.clone(),
        challenge: challenge.to_vec(),
        payload_sha256: digest(&domain_message(ENDPOINT, &payload)).to_vec(),
        expires_at_unix_ms: c.expires_at_unix_ms,
    })
}
/// Immutable approved session identity/permissions/path/capability binding.
/// Renewal times and lease sequence are excluded; all other permit fields remain.
pub fn session_binding(permit: &PermitClaims) -> Result<[u8; 32], ContractError> {
    permit.validate()?;
    let mut c = permit.clone();
    c.lease_sequence = 0;
    c.issued_at_unix_ms = 0;
    c.expires_at_unix_ms = 0;
    Ok(digest(&domain_message(BINDING_DOMAIN, &c.encode_to_vec())))
}
pub fn allocation_transcript(
    permit: &PermitClaims,
    account: &str,
    device: &str,
    allocation: &str,
    node: &str,
) -> Result<DeviceActionClaims, ContractError> {
    let mut c = super::relay_transcript(permit, account, device, &digest(&permit.encode_to_vec()))?;
    if !nestlink_protocol::valid_id(allocation) || !nestlink_protocol::valid_id(node) {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid relay allocation request",
        ));
    }
    c.action = DeviceAction::RelayAllocate as i32;
    // A fixed protobuf-free tuple of canonical UUID bytes has unambiguous framing.
    let payload = format!("{allocation}\0{node}");
    c.payload_sha256 = digest(payload.as_bytes()).to_vec();
    Ok(c)
}
impl PermitSigner {
    pub fn sign_relay_allocation(
        &self,
        claims: &RelayAllocationClaims,
    ) -> Result<SignedRelayAllocation, ContractError> {
        claims.validate()?;
        let bytes = claims.encode_to_vec();
        if bytes.len() as u64 > NODE_MESSAGE_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "allocation message budget exceeded",
            ));
        }
        Ok(SignedRelayAllocation {
            signature: self
                .key
                .sign(&domain_message(ALLOCATION_DOMAIN, &bytes))
                .to_bytes()
                .to_vec(),
            claims: bytes,
        })
    }
}
#[derive(Clone, Debug)]
pub struct VerifiedRelayAllocation {
    claims: RelayAllocationClaims,
    signed: Vec<u8>,
}
impl VerifiedRelayAllocation {
    pub fn claims(&self) -> &RelayAllocationClaims {
        &self.claims
    }
    /// The original bounded signed ticket, for presentation to the allocated node.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }
    pub fn matches(&self, permit: &PermitClaims) -> Result<bool, ContractError> {
        let c = &self.claims;
        Ok(permit.paths.contains(&(Path::Relay as i32))
            && c.deployment_id == permit.deployment_id
            && c.security_epoch == permit.security_epoch
            && c.session_id == permit.session_id
            && c.controller_account_id == permit.account_id
            && c.controller_device_id == permit.controller_device_id
            && c.host_device_id == permit.host_device_id
            && c.controller_key_sha256 == permit.controller_key_sha256
            && c.host_key_sha256 == permit.host_key_sha256
            && c.connection_generation == permit.connection_generation
            && c.policy_revision == permit.policy_revision
            && c.session_binding_sha256 == session_binding(permit)?)
    }
}
pub fn verify_relay_allocation(
    bytes: &[u8],
    issuer: &[u8; 32],
) -> Result<VerifiedRelayAllocation, ContractError> {
    let signed: SignedRelayAllocation = decode_bounded(bytes, NODE_MESSAGE_BYTES + 128)?;
    if signed.claims.len() as u64 > NODE_MESSAGE_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "allocation message budget exceeded",
        ));
    }
    verify_signature(issuer, ALLOCATION_DOMAIN, &signed.claims, &signed.signature)?;
    let claims: RelayAllocationClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(VerifiedRelayAllocation {
        claims,
        signed: bytes.to_vec(),
    })
}
#[cfg(test)]
mod tests;
