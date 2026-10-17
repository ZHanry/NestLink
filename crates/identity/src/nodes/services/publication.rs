use super::*;
use crate::service_plane::publication::{DELEGATION, EDGE_ATTACH};
use nestlink_protocol::service_plane::publication::*;
impl NodePolicySigner {
    pub fn sign_service_issuer_delegation(
        &self,
        delegation: &ServiceIssuerDelegation,
    ) -> Result<SignedServiceIssuerDelegation, ContractError> {
        delegation.validate()?;
        let claims = encode(delegation, SERVICE_MESSAGE_BYTES)?;
        Ok(SignedServiceIssuerDelegation {
            signature: self
                .key
                .sign(&domain_message(DELEGATION, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl NodeIdentity {
    pub fn challenge_service_attachment(
        &self,
        lease: &VerifiedServiceLease,
        now_ms: u64,
    ) -> Result<SignedServiceAttachmentChallenge, ContractError> {
        if digest(&self.public_key()) != lease.claims().edge_key_sha256 {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "attachment edge key mismatch",
            ));
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let challenge = ServiceAttachmentChallenge {
            lease_sha256: lease.digest(),
            nonce,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms
                .checked_add(SERVICE_RESOURCE_MS)
                .ok_or_else(|| {
                    ContractError::new(ErrorCode::LeaseExpired, "attachment clock overflow")
                })?
                .min(lease.claims().expires_at_unix_ms),
        };
        challenge.validate(lease.claims())?;
        let claims = encode(&challenge, SERVICE_MESSAGE_BYTES)?;
        Ok(SignedServiceAttachmentChallenge {
            signature: self
                .key
                .sign(&domain_message(EDGE_ATTACH, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
