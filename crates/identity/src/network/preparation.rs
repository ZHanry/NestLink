//! Deterministic request identity, independent of either authorization layer.
use crate::digest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{ContractError, ErrorCode, api::NetworkRemotePreparationRequest, valid_id};

pub fn remote_preparation_grant_ids(
    space: &str,
    request: &str,
    binding: &NetworkRemotePreparationRequest,
) -> Result<[String; 2], ContractError> {
    let invalid = || ContractError::new(ErrorCode::InvalidMessage, "invalid preparation binding");
    let permit = URL_SAFE_NO_PAD
        .decode(&binding.permit_sha256)
        .map_err(|_| invalid())?;
    if !valid_id(space)
        || !valid_id(request)
        || permit.len() != 32
        || URL_SAFE_NO_PAD.encode(&permit) != binding.permit_sha256
        || [
            binding.expected_space_revision,
            binding.expected_policy_epoch,
            binding.connection_generation,
        ]
        .into_iter()
        .any(|value| value == 0 || value > i64::MAX as u64)
    {
        return Err(invalid());
    }
    let mut bytes = b"NestLink/network/approved-pair-preparation/v1\0".to_vec();
    for value in [space, request] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    // Revisions are exact preconditions, never allocation entropy. Changing a
    // policy or revoking either original grant cannot allocate a replacement
    // pair for the same approved business digest.
    bytes.extend_from_slice(&binding.connection_generation.to_be_bytes());
    bytes.extend_from_slice(&permit);
    Ok(std::array::from_fn(|role| {
        let mut role_bytes = bytes.clone();
        role_bytes.push(role as u8);
        let hash = digest(&role_bytes);
        let mut id = [0; 16];
        id.copy_from_slice(&hash[..16]);
        id[6] = (id[6] & 0x0f) | 0x80;
        id[8] = (id[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(id).hyphenated().to_string()
    }))
}
