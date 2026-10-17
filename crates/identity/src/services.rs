//! Explicit local target consent, separate from remote desktop approval.
use crate::{digest, verify_device_action};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, SCHEMA_VERSION,
    api::{ServiceApprovalChallenge, ServiceDefinition, ServiceTargetChoice, ServiceView},
    services::{
        SERVICE_APPROVAL_LIFETIME_MS, SERVICE_CHALLENGE_MS, revision_valid, validate_local_target,
    },
    valid_id,
};
use std::net::SocketAddr;

fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid service target approval")
}
pub fn definition_digest(definition: &ServiceDefinition) -> Result<[u8; 32], ContractError> {
    definition.validate()?;
    Ok(digest(
        &serde_json::to_vec(definition).map_err(|_| invalid())?,
    ))
}
pub fn decode_digest(value: &str) -> Result<[u8; 32], ContractError> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn validate_challenge(challenge: &ServiceApprovalChallenge) -> Result<(), ContractError> {
    if [
        &challenge.id,
        &challenge.deployment_id,
        &challenge.account_id,
        &challenge.management_session_id,
        &challenge.host_device_id,
        &challenge.service_id,
    ]
    .iter()
    .any(|s| !valid_id(s))
        || !revision_valid(challenge.security_epoch)
        || !revision_valid(challenge.policy_revision)
        || !revision_valid(challenge.service_revision)
        || !revision_valid(challenge.issued_at_unix_ms)
        || !revision_valid(challenge.expires_at_unix_ms)
        || challenge
            .expires_at_unix_ms
            .checked_sub(challenge.issued_at_unix_ms)
            .is_none_or(|n| n == 0 || n > SERVICE_CHALLENGE_MS)
    {
        return Err(invalid());
    }
    decode_digest(&challenge.nonce)?;
    decode_digest(&challenge.definition_sha256)?;
    Ok(())
}
pub fn approval_transcript(
    challenge: &ServiceApprovalChallenge,
    choice: &ServiceTargetChoice,
) -> Result<DeviceActionClaims, ContractError> {
    validate_challenge(challenge)?;
    if choice.expected_revision != challenge.service_revision
        || !valid_id(&choice.target_id)
        || !revision_valid(choice.expires_at_unix_ms)
        || choice
            .expires_at_unix_ms
            .checked_sub(challenge.issued_at_unix_ms)
            .is_none_or(|n| n == 0 || n > SERVICE_APPROVAL_LIFETIME_MS)
    {
        return Err(invalid());
    }
    decode_digest(&choice.target_sha256)?;
    let payload = serde_json::to_vec(&(challenge, choice)).map_err(|_| invalid())?;
    Ok(DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::ApproveServiceTarget as i32,
        deployment_id: challenge.deployment_id.clone(),
        security_epoch: challenge.security_epoch,
        account_id: challenge.account_id.clone(),
        device_id: challenge.host_device_id.clone(),
        resource_id: challenge.service_id.clone(),
        challenge: decode_digest(&challenge.nonce)?.to_vec(),
        payload_sha256: digest(&payload).to_vec(),
        expires_at_unix_ms: challenge.expires_at_unix_ms,
    })
}
pub fn verify_approval(
    challenge: &ServiceApprovalChallenge,
    choice: &ServiceTargetChoice,
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    verify_device_action(
        &approval_transcript(challenge, choice)?,
        public_key,
        signature,
    )
}
/// Commits to the actual local selection. The registry receives the digest only;
/// this function neither resolves a name nor creates a socket.
pub fn local_target_digest(
    view: &ServiceView,
    target_id: &str,
    protocol: &str,
    address: SocketAddr,
) -> Result<[u8; 32], ContractError> {
    view.definition.validate()?;
    if !valid_id(&view.id)
        || !valid_id(&view.account_id)
        || !valid_id(&view.management_session_id)
        || !valid_id(target_id)
        || !revision_valid(view.revision)
        || definition_digest(&view.definition)? != decode_digest(&view.definition_sha256)?
    {
        return Err(invalid());
    }
    validate_local_target(&view.definition.requested_ingress, protocol, address)?;
    let payload = serde_json::to_vec(&(
        "NestLink/v15/local-service-target/v1",
        &view.id,
        view.revision,
        &view.definition_sha256,
        target_id,
        protocol,
        address.to_string(),
    ))
    .map_err(|_| invalid())?;
    Ok(digest(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstallationIdentity;
    fn id(n: u8) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }
    fn challenge() -> ServiceApprovalChallenge {
        ServiceApprovalChallenge {
            id: id(1),
            deployment_id: id(2),
            security_epoch: 3,
            policy_revision: 4,
            account_id: id(5),
            management_session_id: id(6),
            host_device_id: id(7),
            service_id: id(8),
            service_revision: 9,
            definition_sha256: URL_SAFE_NO_PAD.encode([10; 32]),
            nonce: URL_SAFE_NO_PAD.encode([11; 32]),
            issued_at_unix_ms: 1000,
            expires_at_unix_ms: 61000,
        }
    }
    #[test]
    fn target_proof_binds_purpose_definition_target_login_policy_and_nonce()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = InstallationIdentity::generate();
        let original = challenge();
        let choice = ServiceTargetChoice {
            expected_revision: 9,
            target_id: id(12),
            target_sha256: URL_SAFE_NO_PAD.encode([13; 32]),
            expires_at_unix_ms: 120000,
        };
        let proof = approval_transcript(&original, &choice)?;
        let signature = identity.sign_action(&proof)?;
        verify_approval(&original, &choice, &identity.public_key(), &signature)?;
        let mut other_purpose = proof.clone();
        other_purpose.action = DeviceAction::Approve as i32;
        assert!(verify_device_action(&other_purpose, &identity.public_key(), &signature).is_err());
        let mut alternatives = Vec::new();
        let mut c = original.clone();
        c.management_session_id = id(99);
        alternatives.push(c);
        let mut c = original.clone();
        c.definition_sha256 = URL_SAFE_NO_PAD.encode([99; 32]);
        alternatives.push(c);
        let mut c = original.clone();
        c.policy_revision += 1;
        alternatives.push(c);
        let mut c = original.clone();
        c.nonce = URL_SAFE_NO_PAD.encode([99; 32]);
        alternatives.push(c);
        let mut c = original.clone();
        c.security_epoch += 1;
        alternatives.push(c);
        for changed in alternatives {
            assert!(
                verify_approval(&changed, &choice, &identity.public_key(), &signature).is_err()
            );
        }
        let mut changed = choice.clone();
        changed.target_sha256 = URL_SAFE_NO_PAD.encode([99; 32]);
        assert!(verify_approval(&original, &changed, &identity.public_key(), &signature).is_err());
        Ok(())
    }
}
