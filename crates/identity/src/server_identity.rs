use super::{PermitSigner, domain_message, verify_signature};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use nestlink_protocol::{
    ALPN, API_BASE, ContractError, ErrorCode, api::ServerIdentityClaims, valid_id,
};

const SERVER_IDENTITY_DOMAIN: &[u8] = b"NestLink/v15/server-identity-proof/v1\0";

impl PermitSigner {
    /// Prove possession of the deployment's configured permit key for one
    /// client-generated nonce and the exact public management origin.
    pub fn sign_server_identity(
        &self,
        claims: &ServerIdentityClaims,
    ) -> Result<[u8; 64], ContractError> {
        validate_claims(claims)?;
        if decode_key(&claims.permit_issuer)? != self.public_key() {
            return Err(invalid("identity proof issuer does not match signer"));
        }
        let bytes = serde_json::to_vec(claims).map_err(|_| {
            ContractError::new(ErrorCode::InternalError, "identity proof encode failed")
        })?;
        Ok(self
            .key
            .sign(&domain_message(SERVER_IDENTITY_DOMAIN, &bytes))
            .to_bytes())
    }
}

/// Verify a deployment identity proof using the independently supplied permit
/// issuer trust anchor. The signature has a dedicated domain, separate from
/// permits, device actions, and session endpoint proofs.
pub fn verify_server_identity(
    claims: &ServerIdentityClaims,
    signature: &[u8],
    trusted_issuer: &[u8; 32],
) -> Result<(), ContractError> {
    validate_claims(claims)?;
    if decode_key(&claims.permit_issuer)? != *trusted_issuer {
        return Err(invalid("identity proof issuer does not match trust anchor"));
    }
    let bytes = serde_json::to_vec(claims).map_err(|_| {
        ContractError::new(ErrorCode::InvalidMessage, "identity proof encode failed")
    })?;
    verify_signature(trusted_issuer, SERVER_IDENTITY_DOMAIN, &bytes, signature)
}

fn validate_claims(claims: &ServerIdentityClaims) -> Result<(), ContractError> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&claims.nonce)
        .map_err(|_| invalid("invalid identity proof nonce"))?;
    if nonce.len() != 32
        || URL_SAFE_NO_PAD.encode(&nonce) != claims.nonce
        || !valid_id(&claims.deployment_id)
        || claims.security_epoch == 0
        || claims.management_origin.is_empty()
        || claims.management_origin.len() > 512
        || claims.management_origin.chars().any(char::is_control)
        || claims.product != "NestLink"
        || claims.version.is_empty()
        || claims.version.len() > 64
        || claims.api_base != API_BASE
        || claims.alpn != ALPN
    {
        return Err(invalid("invalid identity proof claims"));
    }
    decode_key(&claims.permit_issuer)?;
    decode_key(&claims.node_policy_issuer)?;
    Ok(())
}

fn decode_key(value: &str) -> Result<[u8; 32], ContractError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("invalid identity proof public key"))?;
    let key = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| invalid("invalid identity proof public key"))?;
    if URL_SAFE_NO_PAD.encode(key) != value {
        return Err(invalid("non-canonical identity proof public key"));
    }
    Ok(key)
}

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::IdentityMismatch, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(issuer: [u8; 32]) -> ServerIdentityClaims {
        ServerIdentityClaims {
            nonce: URL_SAFE_NO_PAD.encode([7; 32]),
            management_origin: "https://manage.example.test".into(),
            product: "NestLink".into(),
            version: "15.0.0-dev.1".into(),
            api_base: API_BASE.into(),
            alpn: ALPN.into(),
            deployment_id: "5f45f908-6d77-4d18-938f-6115e06ae890".into(),
            security_epoch: 3,
            permit_issuer: URL_SAFE_NO_PAD.encode(issuer),
            node_policy_issuer: URL_SAFE_NO_PAD.encode([9; 32]),
        }
    }

    #[test]
    fn server_identity_proof_binds_nonce_origin_and_trust_anchor() -> Result<(), ContractError> {
        let signer = PermitSigner::generate();
        let proof = claims(signer.public_key());
        let signature = signer.sign_server_identity(&proof)?;
        assert!(verify_server_identity(&proof, &signature, &signer.public_key()).is_ok());

        let mut changed_nonce = proof.clone();
        changed_nonce.nonce = URL_SAFE_NO_PAD.encode([8; 32]);
        assert!(verify_server_identity(&changed_nonce, &signature, &signer.public_key()).is_err());

        let mut changed_origin = proof.clone();
        changed_origin.management_origin = "https://attacker.example.test".into();
        assert!(verify_server_identity(&changed_origin, &signature, &signer.public_key()).is_err());

        assert!(
            verify_server_identity(&proof, &signature, &PermitSigner::generate().public_key())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn server_identity_signer_rejects_noncanonical_or_wrong_issuer_claims() {
        let signer = PermitSigner::generate();
        let mut proof = claims(signer.public_key());
        proof.nonce.push('=');
        assert!(signer.sign_server_identity(&proof).is_err());

        let mut proof = claims(signer.public_key());
        proof.permit_issuer = URL_SAFE_NO_PAD.encode([4; 32]);
        assert!(signer.sign_server_identity(&proof).is_err());
    }
}
