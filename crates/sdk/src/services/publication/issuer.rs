//! Fresh policy signatures replace an issuer proof; the old proof's deadline
//! is immutable. A refresh cannot rotate realm, epoch, policy or service key.
use super::*;
use nestlink_identity::service_plane::publication::VerifiedServiceIssuerDelegation;
use std::sync::RwLock;

pub(super) struct ServiceIssuerOwner {
    current: RwLock<VerifiedServiceIssuerDelegation>,
}
pub(super) struct Candidate {
    pub(super) lease: VerifiedServiceLease,
    pub(super) issuer: VerifiedServiceIssuerDelegation,
}
fn same_scope(
    old: &VerifiedServiceIssuerDelegation,
    new: &VerifiedServiceIssuerDelegation,
) -> bool {
    let a = old.claims();
    let b = new.claims();
    old.policy_issuer() == new.policy_issuer()
        && a.deployment_id == b.deployment_id
        && a.security_epoch == b.security_epoch
        && a.policy_revision == b.policy_revision
        && a.service_issuer == b.service_issuer
        && b.issued_at_unix_ms >= a.issued_at_unix_ms
        && b.expires_at_unix_ms >= a.expires_at_unix_ms
}
impl ServiceIssuerOwner {
    pub(super) fn new(verified: VerifiedServiceIssuerDelegation) -> Self {
        Self {
            current: RwLock::new(verified),
        }
    }
    pub(super) fn verify_lease(
        &self,
        signed: &SignedServiceLease,
        now: u64,
    ) -> Result<VerifiedServiceLease, SdkError> {
        Ok(self
            .current
            .read()
            .map_err(|_| SdkError::Trust)?
            .verify_lease(signed, now)?)
    }
    /// Copies only the exact original public delegation after checking this lease.
    pub(super) fn observation(
        &self,
        lease: &VerifiedServiceLease,
        now: u64,
    ) -> Result<
        nestlink_protocol::service_plane::observation::ServiceIssuerDelegationEvidence,
        SdkError,
    > {
        use nestlink_protocol::service_plane::observation::{
            ISSUER_DELEGATION_OBSERVATION_BYTES, ServiceIssuerDelegationEvidence,
        };
        let current = self.current.read().map_err(|_| SdkError::Trust)?;
        current.verify_lease(lease.signed(), now)?;
        let signed = current.signed();
        if signed.claims.len() > ISSUER_DELEGATION_OBSERVATION_BYTES || signed.signature.len() != 64
        {
            return Err(SdkError::Trust);
        }
        Ok(ServiceIssuerDelegationEvidence {
            verified_policy_issuer_ed25519: current.policy_issuer(),
            claims: signed.claims.clone(),
            signature: signed.signature.clone(),
        })
    }
    pub(super) fn check_live(&self, now: u64) -> Result<(), SdkError> {
        let current = self.current.read().map_err(|_| SdkError::Trust)?;
        if now < current.claims().issued_at_unix_ms || now >= current.claims().expires_at_unix_ms {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    pub(super) fn prepare(
        &self,
        renewal: &ServiceLeaseRenewal,
        now: u64,
    ) -> Result<Candidate, SdkError> {
        let current = self.current.read().map_err(|_| SdkError::Trust)?;
        let issuer = verify_service_issuer_delegation(
            &renewal.issuer,
            &current.policy_issuer(),
            &current.claims().deployment_id,
            now,
        )?;
        if !same_scope(&current, &issuer) {
            return Err(SdkError::Trust);
        }
        let lease = issuer.verify_lease(&renewal.lease, now)?;
        Ok(Candidate { lease, issuer })
    }
    /// Called only after the lease passed the retained local target and original
    /// publication-binding checks and its one owner accepted the renewal.
    pub(super) fn install(&self, issuer: VerifiedServiceIssuerDelegation) -> Result<(), SdkError> {
        let mut current = self.current.write().map_err(|_| SdkError::Trust)?;
        if !same_scope(&current, &issuer) {
            return Err(SdkError::Trust);
        }
        *current = issuer;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
