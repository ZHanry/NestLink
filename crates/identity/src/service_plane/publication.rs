//! Delegation and attachment proofs have no remote-desktop signing authority.
use super::*;
use nestlink_protocol::service_plane::publication::*;

pub(crate) const DELEGATION: &[u8] = b"NestLink/v15/service-issuer-delegation/v1\0";
pub(crate) const EDGE_ATTACH: &[u8] = b"NestLink/v15/service-edge-attachment/v1\0";
const HOST_ATTACH: &[u8] = b"NestLink/v15/service-host-attachment/v1\0";

pub struct VerifiedServiceIssuerDelegation {
    claims: ServiceIssuerDelegation,
    policy_issuer: [u8; 32],
}
impl VerifiedServiceIssuerDelegation {
    pub fn claims(&self) -> &ServiceIssuerDelegation {
        &self.claims
    }
    pub fn policy_issuer(&self) -> [u8; 32] {
        self.policy_issuer
    }
    pub fn verify_lease(
        &self,
        signed: &SignedServiceLease,
        now_ms: u64,
    ) -> Result<VerifiedServiceLease, ContractError> {
        let lease = verify_service_lease(signed, &self.claims.service_issuer)?;
        let c = lease.claims();
        if c.deployment_id != self.claims.deployment_id
            || c.security_epoch != self.claims.security_epoch
            || c.policy_revision != self.claims.policy_revision
            || now_ms < self.claims.issued_at_unix_ms
            || now_ms >= self.claims.expires_at_unix_ms
            || c.issued_at_unix_ms < self.claims.issued_at_unix_ms
            || c.expires_at_unix_ms > self.claims.expires_at_unix_ms
            || now_ms < c.issued_at_unix_ms
            || now_ms >= c.expires_at_unix_ms
        {
            return Err(invalid());
        }
        Ok(lease)
    }
}
pub fn verify_service_issuer_delegation(
    signed: &SignedServiceIssuerDelegation,
    trusted_policy_issuer: &[u8; 32],
    deployment_id: &str,
    now_ms: u64,
) -> Result<VerifiedServiceIssuerDelegation, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        trusted_policy_issuer,
        DELEGATION,
        SERVICE_MESSAGE_BYTES,
    )?;
    let claims: ServiceIssuerDelegation = decode(&signed.claims, SERVICE_MESSAGE_BYTES)?;
    claims.validate()?;
    if claims.deployment_id != deployment_id
        || now_ms < claims.issued_at_unix_ms
        || now_ms >= claims.expires_at_unix_ms
    {
        return Err(invalid());
    }
    Ok(VerifiedServiceIssuerDelegation {
        claims,
        policy_issuer: *trusted_policy_issuer,
    })
}
pub fn verify_attachment_challenge(
    signed: &SignedServiceAttachmentChallenge,
    lease: &VerifiedServiceLease,
    edge_key: &[u8; 32],
    now_ms: u64,
) -> Result<ServiceAttachmentChallenge, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        edge_key,
        EDGE_ATTACH,
        SERVICE_MESSAGE_BYTES,
    )?;
    let c: ServiceAttachmentChallenge = decode(&signed.claims, SERVICE_MESSAGE_BYTES)?;
    c.validate(lease.claims())?;
    if c.lease_sha256 != lease.digest()
        || digest(edge_key) != lease.claims().edge_key_sha256
        || now_ms < c.issued_at_unix_ms
        || now_ms >= c.expires_at_unix_ms
    {
        return Err(invalid());
    }
    Ok(c)
}
impl InstallationIdentity {
    pub fn prove_service_attachment(
        &self,
        lease: &VerifiedServiceLease,
        challenge: &SignedServiceAttachmentChallenge,
        edge_key: &[u8; 32],
        host_runtime_id: &str,
        now_ms: u64,
    ) -> Result<ServiceAttachmentProof, ContractError> {
        verify_attachment_challenge(challenge, lease, edge_key, now_ms)?;
        if !valid_id(host_runtime_id) || self.fingerprint() != lease.claims().host_key_sha256 {
            return Err(invalid());
        }
        let mut proof = ServiceAttachmentProof {
            host_runtime_id: host_runtime_id.into(),
            lease_sha256: lease.digest(),
            challenge_sha256: digest(&challenge.claims),
            signature: Vec::new(),
        };
        proof.signature = self
            .key
            .sign(&domain_message(
                HOST_ATTACH,
                &encode(&proof, SERVICE_MESSAGE_BYTES)?,
            ))
            .to_bytes()
            .to_vec();
        Ok(proof)
    }
}
pub fn verify_attachment_proof(
    lease: &VerifiedServiceLease,
    challenge: &SignedServiceAttachmentChallenge,
    proof: &ServiceAttachmentProof,
    host_key: &[u8; 32],
    edge_key: &[u8; 32],
    now_ms: u64,
) -> Result<(), ContractError> {
    verify_attachment_challenge(challenge, lease, edge_key, now_ms)?;
    if proof.lease_sha256 != lease.digest()
        || proof.challenge_sha256 != digest(&challenge.claims)
        || !valid_id(&proof.host_runtime_id)
        || digest(host_key) != lease.claims().host_key_sha256
        || proof.signature.len() != 64
    {
        return Err(invalid());
    }
    let mut copy = proof.clone();
    copy.signature.clear();
    verify_signature(
        host_key,
        HOST_ATTACH,
        &encode(&copy, SERVICE_MESSAGE_BYTES)?,
        &proof.signature,
    )
}
