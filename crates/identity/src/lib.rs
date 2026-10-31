//! Separate signing purposes and explicit deployment trust anchors.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nestlink_protocol::{
    ContractError, EndpointProofClaims, ErrorCode, PERMIT_BYTES, PermitClaims, SignedPermit,
    decode_bounded,
};
use prost::Message;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
pub mod network;
pub mod network_topology;
pub mod node_discovery;
pub mod nodes;
pub mod offline;
pub mod reconnection;
pub mod relay;
pub mod remote_budget;
pub use nodes::closes as node_closes;
pub use nodes::resources as node_resources;
pub use nodes::turn;
pub mod remote_password;
mod server_identity;
pub mod service_plane;
pub mod service_quota_recovery;
pub mod services;
pub mod subnet;
pub mod wireguard;
pub use server_identity::verify_server_identity;

const PERMIT_DOMAIN: &[u8] = b"NestLink/v15/session-permit/v1\0";
const PROOF_DOMAIN: &[u8] = b"NestLink/v15/endpoint-proof/v1\0";
const ACTION_DOMAIN: &[u8] = b"NestLink/v15/device-action/v1\0";

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub struct PermitSigner {
    key: SigningKey,
}
pub struct InstallationIdentity {
    key: SigningKey,
}

impl PermitSigner {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    /// Independent Ed25519 policy key, derived with a purpose-specific HKDF.
    pub fn node_policy_signer(&self) -> Result<nodes::NodePolicySigner, ContractError> {
        let seed = zeroize::Zeroizing::new(self.key.to_bytes());
        nodes::NodePolicySigner::from_master_seed(&seed)
    }
    /// Independent network authority, derived without exposing the master seed.
    pub fn network_authority_signer(
        &self,
    ) -> Result<network::NetworkAuthoritySigner, ContractError> {
        let seed = zeroize::Zeroizing::new(self.key.to_bytes());
        network::NetworkAuthoritySigner::from_master_seed(&seed)
    }
    pub fn sign(&self, claims: &PermitClaims) -> Result<SignedPermit, ContractError> {
        claims.validate()?;
        let bytes = claims.encode_to_vec();
        if bytes.len() as u64 > PERMIT_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "permit budget exceeded",
            ));
        }
        let signature = self
            .key
            .sign(&domain_message(PERMIT_DOMAIN, &bytes))
            .to_bytes()
            .to_vec();
        Ok(SignedPermit {
            claims: bytes,
            signature,
        })
    }
}

#[cfg(test)]
mod installation_identity_tests {
    use super::InstallationIdentity;
    use ed25519_dalek::SigningKey;

    #[test]
    fn zeroizing_seed_constructor_clears_the_callers_buffer() {
        let mut seed = [0x5a; 32];
        let expected_public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let identity = InstallationIdentity::from_seed_zeroizing(&mut seed);

        assert_eq!(identity.public_key(), expected_public_key);
        assert!(seed.iter().all(|byte| *byte == 0));
    }
}

#[derive(Clone)]
pub struct VerifiedPermit {
    remote_budget: Option<remote_budget::VerifiedRemoteUsageBudget>,
    claims: PermitClaims,
    digest: [u8; 32],
    issuer: [u8; 32],
    signed_envelope: std::sync::Arc<[u8]>,
}

impl std::fmt::Debug for VerifiedPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedPermit")
            .field("claims", &self.claims)
            .field("digest", &self.digest)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl VerifiedPermit {
    pub fn remote_budget(&self) -> Option<&remote_budget::VerifiedRemoteUsageBudget> {
        self.remote_budget.as_ref()
    }
    pub fn with_remote_budget(
        mut self,
        signed: &nestlink_protocol::remote_budget::SignedRemoteUsageBudget,
    ) -> Result<Self, ContractError> {
        self.remote_budget = Some(remote_budget::verify_remote_usage_budget(signed, &self)?);
        Ok(self)
    }
    /// Carry the same original meter through a separately verified renewal or
    /// reconnection. A successor cannot obtain an empty counter or expand it.
    pub fn retain_remote_budget(mut self, previous: &Self) -> Result<Self, ContractError> {
        if let Some(budget) = previous.remote_budget() {
            if self.issuer != previous.issuer {
                return Err(ContractError::new(
                    ErrorCode::IdentityMismatch,
                    "remote budget issuer changed",
                ));
            }
            budget.claims().check_permit(&self.claims)?;
            budget.check()?;
            self.remote_budget = Some(budget.clone());
        } else if self
            .claims
            .required_capabilities
            .iter()
            .any(|v| v == nestlink_protocol::remote_budget::CAPABILITY)
        {
            return Err(ContractError::new(
                ErrorCode::AuthRequired,
                "original remote budget owner missing",
            ));
        }
        Ok(self)
    }
    pub fn claims(&self) -> &PermitClaims {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn issuer(&self) -> [u8; 32] {
        self.issuer
    }
    /// The exact bounded SignedPermit bytes whose signature was verified.
    /// A local privilege broker re-verifies this envelope against its own pins;
    /// callers must never reconstruct a signature from claims alone.
    pub fn signed_envelope(&self) -> &[u8] {
        &self.signed_envelope
    }
}

pub fn verify_permit(
    bytes: &[u8],
    trusted_issuer: &[u8; 32],
) -> Result<VerifiedPermit, ContractError> {
    let signed: SignedPermit = decode_bounded(bytes, PERMIT_BYTES + 128)?;
    if signed.claims.len() as u64 > PERMIT_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "permit budget exceeded",
        ));
    }
    verify_signature(
        trusted_issuer,
        PERMIT_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: PermitClaims = decode_bounded(&signed.claims, PERMIT_BYTES)?;
    claims.validate()?;
    Ok(VerifiedPermit {
        remote_budget: None,
        issuer: *trusted_issuer,
        digest: digest(&signed.claims),
        claims,
        signed_envelope: bytes.into(),
    })
}

#[cfg(test)]
mod signed_envelope_tests {
    use super::*;

    #[test]
    fn verified_and_renewed_permits_retain_their_own_exact_signed_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/session-permit-v1.json"
        ))?;
        let hex = vector["envelope_hex"]
            .as_str()
            .ok_or("missing test vector")?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16))
            .collect::<Result<_, _>>()?;
        let signer = PermitSigner::from_seed([1; 32]);
        let first = verify_permit(&bytes, &signer.public_key())?;
        assert_eq!(first.signed_envelope(), bytes);
        let mut claims = first.claims().clone();
        claims.lease_sequence += 1;
        claims.issued_at_unix_ms += 1000;
        claims.expires_at_unix_ms += 1000;
        let renewal_bytes = signer.sign(&claims)?.encode_to_vec();
        let renewal = verify_permit(&renewal_bytes, &signer.public_key())?;
        assert_eq!(renewal.signed_envelope(), renewal_bytes);
        assert_ne!(renewal.signed_envelope(), first.signed_envelope());
        assert_eq!(first.clone().signed_envelope(), bytes);
        let mut invalid = renewal_bytes;
        let last = invalid.last_mut().ok_or("empty test permit")?;
        *last ^= 1;
        assert!(verify_permit(&invalid, &signer.public_key()).is_err());
        Ok(())
    }
}

impl InstallationIdentity {
    /// Short-lived copy for the TLS adapter, zeroized immediately after loading.
    pub fn tls_pkcs8(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, ContractError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        self.key
            .to_pkcs8_der()
            .map(|der| zeroize::Zeroizing::new(der.as_bytes().to_vec()))
            .map_err(|_| {
                ContractError::new(ErrorCode::InternalError, "installation key encoding failed")
            })
    }
    /// Separate domain; cannot be replayed as a management DeviceAction proof.
    pub fn sign_native_renewal(
        &self,
        envelope: &nestlink_protocol::native_renewal::Envelope,
    ) -> Result<[u8; 64], ContractError> {
        Ok(self
            .key
            .sign(&domain_message(
                b"NestLink/v15/native-renewal/v1\0",
                &envelope.signing_bytes()?,
            ))
            .to_bytes())
    }
    pub fn sign_action(
        &self,
        claims: &nestlink_protocol::DeviceActionClaims,
    ) -> Result<Vec<u8>, ContractError> {
        validate_action(claims)?;
        Ok(self
            .key
            .sign(&domain_message(ACTION_DOMAIN, &claims.encode_to_vec()))
            .to_bytes()
            .to_vec())
    }
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        Self::from_seed_zeroizing(&mut seed)
    }
    /// Build an installation identity and erase the caller-owned seed buffer.
    ///
    /// Use this when the seed came from storage or another secret-bearing
    /// buffer. The by-value compatibility constructor can only erase its own
    /// copy; callers remain responsible for copies they retain.
    pub fn from_seed_zeroizing(seed: &mut [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        zeroize::Zeroize::zeroize(seed);
        Self { key }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        digest(&self.public_key())
    }
    pub fn prove(&self, claims: &EndpointProofClaims) -> Result<Vec<u8>, ContractError> {
        validate_proof(claims)?;
        Ok(self
            .key
            .sign(&domain_message(PROOF_DOMAIN, &claims.encode_to_vec()))
            .to_bytes()
            .to_vec())
    }
}

pub fn verify_device_action(
    claims: &nestlink_protocol::DeviceActionClaims,
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    validate_action(claims)?;
    verify_signature(
        public_key,
        ACTION_DOMAIN,
        &claims.encode_to_vec(),
        signature,
    )
}
fn validate_action(claims: &nestlink_protocol::DeviceActionClaims) -> Result<(), ContractError> {
    use nestlink_protocol::{DeviceAction, valid_id};
    if claims.schema_version != nestlink_protocol::SCHEMA_VERSION
        || claims.security_epoch == 0
        || claims.expires_at_unix_ms == 0
        || !matches!(
            DeviceAction::try_from(claims.action),
            Ok(DeviceAction::AnnounceMedia
                | DeviceAction::Register
                | DeviceAction::RegisterBrowserEndpoint
                | DeviceAction::Approve
                | DeviceAction::PrepareBrowserHost
                | DeviceAction::Renew
                | DeviceAction::Signal
                | DeviceAction::RelayConnect
                | DeviceAction::TrustRemote
                | DeviceAction::ConfigureRemotePassword
                | DeviceAction::UseRemotePassword)
                | Ok(DeviceAction::RelayAllocate
                    | DeviceAction::NodeRelayConnect
                    | DeviceAction::RelayDiscover
                    | DeviceAction::TurnAllocate
                    | DeviceAction::ApproveServiceTarget
                    | DeviceAction::Reconnect)
        )
        || [
            &claims.deployment_id,
            &claims.account_id,
            &claims.device_id,
            &claims.resource_id,
        ]
        .iter()
        .any(|v| !valid_id(v))
        || claims.challenge.len() != 32
        || claims.payload_sha256.len() != 32
    {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid device action transcript",
        ));
    }
    Ok(())
}

/// Explicit persistent trust is signed by the host and binds the entire active
/// permit, including both keys, approved permissions and allowed paths.
pub fn trust_transcript(
    permit: &PermitClaims,
    host_account_id: &str,
    choice: &nestlink_protocol::api::TrustChoice,
) -> Result<nestlink_protocol::DeviceActionClaims, ContractError> {
    permit.validate()?;
    if choice.expected_revision >= i64::MAX as u64
        || choice.expires_at_unix_ms <= permit.issued_at_unix_ms
        || choice.expires_at_unix_ms > i64::MAX as u64
    {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid device trust choice",
        ));
    }
    let payload = serde_json::to_vec(choice)
        .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "invalid trust payload"))?;
    let transcript = nestlink_protocol::DeviceActionClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        action: nestlink_protocol::DeviceAction::TrustRemote as i32,
        deployment_id: permit.deployment_id.clone(),
        security_epoch: permit.security_epoch,
        account_id: host_account_id.into(),
        device_id: permit.host_device_id.clone(),
        resource_id: permit.session_id.clone(),
        challenge: digest(&permit.encode_to_vec()).to_vec(),
        payload_sha256: digest(&payload).to_vec(),
        expires_at_unix_ms: permit.expires_at_unix_ms,
    };
    validate_action(&transcript)?;
    Ok(transcript)
}

/// One canonical signaling transcript shared by sender, control service and receiver.
pub fn signal_transcript(
    permit: &PermitClaims,
    account_id: &str,
    device_id: &str,
    payload: &nestlink_protocol::api::SignalPayload,
) -> Result<nestlink_protocol::DeviceActionClaims, ContractError> {
    payload.validate(permit)?;
    if device_id != permit.controller_device_id && device_id != permit.host_device_id {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "signal sender is not an endpoint",
        ));
    }
    let encoded = serde_json::to_vec(payload)
        .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "invalid signal payload"))?;
    let transcript = nestlink_protocol::DeviceActionClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        action: nestlink_protocol::DeviceAction::Signal as i32,
        deployment_id: permit.deployment_id.clone(),
        security_epoch: permit.security_epoch,
        account_id: account_id.into(),
        device_id: device_id.into(),
        resource_id: permit.session_id.clone(),
        challenge: digest(&permit.encode_to_vec()).to_vec(),
        payload_sha256: digest(&encoded).to_vec(),
        expires_at_unix_ms: permit.expires_at_unix_ms,
    };
    validate_action(&transcript)?;
    Ok(transcript)
}

pub fn relay_transcript(
    permit: &PermitClaims,
    account_id: &str,
    device_id: &str,
    nonce: &[u8],
) -> Result<nestlink_protocol::DeviceActionClaims, ContractError> {
    permit.validate()?;
    if !permit
        .paths
        .contains(&(nestlink_protocol::Path::Relay as i32))
        || (device_id != permit.controller_device_id && device_id != permit.host_device_id)
    {
        return Err(ContractError::new(
            ErrorCode::RelayDisabled,
            "relay is not authorized for this endpoint",
        ));
    }
    let transcript = nestlink_protocol::DeviceActionClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        action: nestlink_protocol::DeviceAction::RelayConnect as i32,
        deployment_id: permit.deployment_id.clone(),
        security_epoch: permit.security_epoch,
        account_id: account_id.into(),
        device_id: device_id.into(),
        resource_id: permit.session_id.clone(),
        challenge: nonce.into(),
        payload_sha256: digest(&permit.encode_to_vec()).to_vec(),
        expires_at_unix_ms: permit.expires_at_unix_ms,
    };
    validate_action(&transcript)?;
    Ok(transcript)
}

pub fn verify_endpoint_proof(
    expected: &EndpointProofClaims,
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    validate_proof(expected)?;
    let fingerprint = digest(public_key);
    if expected.controller_key_sha256 != fingerprint && expected.host_key_sha256 != fingerprint {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "proof key is not a permitted endpoint",
        ));
    }
    verify_signature(
        public_key,
        PROOF_DOMAIN,
        &expected.encode_to_vec(),
        signature,
    )
}

fn validate_proof(claims: &EndpointProofClaims) -> Result<(), ContractError> {
    if claims.schema_version != nestlink_protocol::SCHEMA_VERSION
        || claims.connection_generation == 0
        || [
            &claims.permit_sha256,
            &claims.challenge,
            &claims.controller_key_sha256,
            &claims.host_key_sha256,
        ]
        .iter()
        .any(|v| v.len() != 32)
        || !matches!(
            nestlink_protocol::Path::try_from(claims.path),
            Ok(nestlink_protocol::Path::Direct | nestlink_protocol::Path::Relay)
        )
    {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid endpoint proof transcript",
        ));
    }
    Ok(())
}

pub fn verify_native_renewal(
    envelope: &nestlink_protocol::native_renewal::Envelope,
    key: &[u8; 32],
) -> Result<(), ContractError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| {
        ContractError::new(ErrorCode::IdentityMismatch, "invalid renewal endpoint key")
    })?;
    key.verify_strict(
        &domain_message(
            b"NestLink/v15/native-renewal/v1\0",
            &envelope.signing_bytes()?,
        ),
        &Signature::from_bytes(&envelope.signature),
    )
    .map_err(|_| {
        ContractError::new(
            ErrorCode::IdentityMismatch,
            "invalid renewal endpoint signature",
        )
    })
}
fn domain_message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    message
}

fn verify_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    let invalid = || {
        ContractError::new(
            ErrorCode::IdentityMismatch,
            "invalid signature or issuer key",
        )
    };
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
    let signature = Signature::from_slice(signature).map_err(|_| invalid())?;
    key.verify_strict(&domain_message(domain, message), &signature)
        .map_err(|_| invalid())
}

#[cfg(test)]
mod native_renewal_signature_tests {
    use super::*;
    #[test]
    fn renewal_signature_rejects_changed_round_identity_and_payload() -> Result<(), ContractError> {
        use nestlink_protocol::native_renewal::{Envelope, Kind};
        let identity = InstallationIdentity::from_seed([21; 32]);
        let mut envelope = Envelope {
            kind: Kind::Applied,
            session: [1; 16],
            deployment: [2; 32],
            epoch: 1,
            generation: 1,
            old_sequence: 1,
            round: [3; 32],
            old_permit: [4; 32],
            payload: vec![5; 32],
            signature: [0; 64],
        };
        envelope.signature = identity.sign_native_renewal(&envelope)?;
        verify_native_renewal(&envelope, &identity.public_key())?;
        assert!(
            verify_native_renewal(
                &envelope,
                &InstallationIdentity::from_seed([22; 32]).public_key()
            )
            .is_err()
        );
        envelope.round[0] ^= 1;
        assert!(verify_native_renewal(&envelope, &identity.public_key()).is_err());
        envelope.round[0] ^= 1;
        envelope.payload[0] ^= 1;
        assert!(verify_native_renewal(&envelope, &identity.public_key()).is_err());
        Ok(())
    }
}
