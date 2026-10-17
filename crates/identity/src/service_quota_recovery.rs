//! This key belongs to an external cumulative accounting authority. It must
//! never be derived from a restored deployment's permit or node-policy key.
use crate::{Signer, SigningKey, digest, domain_message, verify_signature};
use nestlink_protocol::{
    ContractError, ErrorCode,
    service_plane::{decode_service_message, encode_service_message},
    service_quota_recovery::{
        SERVICE_QUOTA_RECOVERY_BYTES, ServiceQuotaReconciliationClaims,
        ServiceQuotaRecoveryRequest, SignedServiceQuotaReconciliation,
    },
};

pub const SERVICE_QUOTA_RECONCILIATION_DOMAIN: &[u8] =
    b"NestLink/v15/external-service-quota-reconciliation/v1\0";

/// For external accounting integrations. Control startup and restore never
/// generate this key, infer totals, or sign their own reconciliation.
pub struct ExternalServiceQuotaSigner {
    key: SigningKey,
}

impl ExternalServiceQuotaSigner {
    pub fn from_external_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(
        &self,
        claims: &ServiceQuotaReconciliationClaims,
    ) -> Result<SignedServiceQuotaReconciliation, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, SERVICE_QUOTA_RECOVERY_BYTES)?;
        Ok(SignedServiceQuotaReconciliation {
            signature: self
                .key
                .sign(&domain_message(
                    SERVICE_QUOTA_RECONCILIATION_DOMAIN,
                    &claims,
                ))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}

pub struct VerifiedServiceQuotaReconciliation {
    claims: ServiceQuotaReconciliationClaims,
    claims_sha256: [u8; 32],
    issuer: [u8; 32],
}

impl VerifiedServiceQuotaReconciliation {
    pub fn claims(&self) -> &ServiceQuotaReconciliationClaims {
        &self.claims
    }
    pub fn claims_sha256(&self) -> [u8; 32] {
        self.claims_sha256
    }
    pub fn issuer(&self) -> [u8; 32] {
        self.issuer
    }

    pub fn validate_for(
        &self,
        request: &ServiceQuotaRecoveryRequest,
        now_ms: u64,
    ) -> Result<(), ContractError> {
        request.validate()?;
        self.claims.validate()?;
        let c = &self.claims;
        if c.deployment_id != request.deployment_id
            || c.restored_security_epoch != request.restored_security_epoch
            || c.policy_revision != request.policy_revision
            || c.quota_revision != request.quota_revision
            || c.request_sha256 != service_quota_recovery_request_digest(request)?
            || now_ms < c.issued_at_unix_ms
            || now_ms >= c.expires_at_unix_ms
        {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "external quota proof does not match this restored accounting state",
            ));
        }
        Ok(())
    }
}

pub fn service_quota_recovery_request_digest(
    request: &ServiceQuotaRecoveryRequest,
) -> Result<[u8; 32], ContractError> {
    request.validate()?;
    Ok(digest(&encode_service_message(
        request,
        SERVICE_QUOTA_RECOVERY_BYTES,
    )?))
}

pub fn verify_service_quota_reconciliation(
    signed: &SignedServiceQuotaReconciliation,
    trusted_external_key: &[u8; 32],
    request: &ServiceQuotaRecoveryRequest,
    now_ms: u64,
) -> Result<VerifiedServiceQuotaReconciliation, ContractError> {
    if signed.claims.len() > SERVICE_QUOTA_RECOVERY_BYTES || signed.signature.len() != 64 {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "external quota proof exceeds its bound",
        ));
    }
    verify_signature(
        trusted_external_key,
        SERVICE_QUOTA_RECONCILIATION_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let verified = VerifiedServiceQuotaReconciliation {
        claims: decode_service_message(&signed.claims, SERVICE_QUOTA_RECOVERY_BYTES)?,
        claims_sha256: digest(&signed.claims),
        issuer: *trusted_external_key,
    };
    verified.validate_for(request, now_ms)?;
    Ok(verified)
}
