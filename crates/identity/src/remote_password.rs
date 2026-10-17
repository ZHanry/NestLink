//! Canonical, purpose-separated fixed-password configuration and use proofs.
use crate::{digest, validate_action};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    ContractError, DeviceAction, DeviceActionClaims, ErrorCode, SCHEMA_VERSION,
    api::{EnrollmentChallenge, RemotePasswordAttempt, RemotePasswordChoice, RemoteView},
};
use zeroize::Zeroizing;

pub fn configure_transcript(
    challenge: &EnrollmentChallenge,
    account: &str,
    host: &str,
    choice: &RemotePasswordChoice,
) -> Result<DeviceActionClaims, ContractError> {
    let payload = Zeroizing::new(serde_json::to_vec(choice).map_err(|_| invalid())?);
    let claims = DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::ConfigureRemotePassword as i32,
        deployment_id: challenge.deployment_id.clone(),
        security_epoch: challenge.security_epoch,
        account_id: account.into(),
        device_id: host.into(),
        resource_id: challenge.id.clone(),
        challenge: URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .map_err(|_| invalid())?,
        payload_sha256: digest(&payload).to_vec(),
        expires_at_unix_ms: challenge.expires_at_unix_ms,
    };
    validate_action(&claims)?;
    Ok(claims)
}

pub fn use_transcript(
    deployment: &str,
    epoch: u64,
    account: &str,
    view: &RemoteView,
    attempt: &RemotePasswordAttempt,
) -> Result<DeviceActionClaims, ContractError> {
    // Include the entire request view, binding host, permissions, paths and nonce
    // as well as the exact configuration revision and submitted password.
    let payload = Zeroizing::new(serde_json::to_vec(&(view, attempt)).map_err(|_| invalid())?);
    let claims = DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::UseRemotePassword as i32,
        deployment_id: deployment.into(),
        security_epoch: epoch,
        account_id: account.into(),
        device_id: view.controller_device_id.clone(),
        resource_id: view.id.clone(),
        challenge: URL_SAFE_NO_PAD.decode(&view.nonce).map_err(|_| invalid())?,
        payload_sha256: digest(&payload).to_vec(),
        expires_at_unix_ms: view.expires_at_unix_ms,
    };
    validate_action(&claims)?;
    Ok(claims)
}

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid remote password transcript",
    )
}
