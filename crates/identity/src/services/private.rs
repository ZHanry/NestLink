//! Private service signatures have purposes separate from public edge, node
//! accounting, remote control and membership signatures.
use crate::service_plane::{ServiceLeaseSigner, VerifiedServiceLease, verify_service_lease};
use crate::{InstallationIdentity, Signer, digest, domain_message, verify_signature};
use nestlink_protocol::service_plane::{decode_service_message, encode_service_message};
use nestlink_protocol::services::private::*;
use nestlink_protocol::{ContractError, ErrorCode};

const LEASE: &[u8] = b"NestLink/private-service/v1/lease\0";
const HOST: &[u8] = b"NestLink/private-service/v1/host-presence\0";
const USAGE: &[u8] = b"NestLink/private-service/v1/installation-usage\0";
const OPEN: &[u8] = b"NestLink/private-service/v1/consumer-open\0";
const READY: &[u8] = b"NestLink/private-service/v1/host-ready\0";
fn denied() -> ContractError {
    ContractError::new(
        ErrorCode::PermissionRequired,
        "private service authority refused",
    )
}

#[derive(Clone, Debug)]
pub struct VerifiedPrivateServiceLease {
    signed: SignedPrivateServiceLease,
    lease: VerifiedServiceLease,
    claims: PrivateServiceClaims,
    digest: [u8; 32],
}
impl VerifiedPrivateServiceLease {
    pub fn signed(&self) -> &SignedPrivateServiceLease {
        &self.signed
    }
    pub fn lease(&self) -> &VerifiedServiceLease {
        &self.lease
    }
    pub fn claims(&self) -> &PrivateServiceClaims {
        &self.claims
    }
    /// Complete immutable business binding, including target, consumer and the
    /// one shared reservation. Never replace this with the public lease digest.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn check_time(&self, now: u64) -> Result<(), ContractError> {
        let c = self.lease.claims();
        if now < c.issued_at_unix_ms || now >= c.expires_at_unix_ms {
            return Err(denied());
        }
        Ok(())
    }
}
impl ServiceLeaseSigner {
    pub fn sign_private_service(
        &self,
        service_lease: nestlink_protocol::service_plane::SignedServiceLease,
        claims: &PrivateServiceClaims,
    ) -> Result<SignedPrivateServiceLease, ContractError> {
        claims.validate()?;
        let signed = SignedPrivateServiceLease {
            service_lease,
            claims: encode_service_message(claims, PRIVATE_SERVICE_MESSAGE_BYTES)?,
            signature: Vec::new(),
        };
        let mut signed = signed;
        signed.signature = self
            .key
            .sign(&domain_message(LEASE, &signed.claims))
            .to_bytes()
            .to_vec();
        verify_private_service_lease(&signed, &self.public_key())?;
        Ok(signed)
    }
}
pub fn verify_private_service_lease(
    signed: &SignedPrivateServiceLease,
    issuer: &[u8; 32],
) -> Result<VerifiedPrivateServiceLease, ContractError> {
    if signed.claims.len() > PRIVATE_SERVICE_MESSAGE_BYTES {
        return Err(denied());
    }
    verify_signature(issuer, LEASE, &signed.claims, &signed.signature)?;
    let claims: PrivateServiceClaims =
        decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
    claims.validate()?;
    let lease = verify_service_lease(&signed.service_lease, issuer)?;
    let base = lease.claims();
    if claims.service_lease_sha256 != lease.digest()
        || claims.usage_grant_sha256 != digest(&base.usage_grant.claims)
        || digest(&claims.host_public_key) != base.host_key_sha256
        || base.edge_key_sha256 != base.host_key_sha256
        || claims.consumer_device_id == base.definition.host_device_id
        || claims.consumer_public_key == claims.host_public_key
    {
        return Err(denied());
    }
    let digest = digest(&domain_message(LEASE, &signed.claims));
    Ok(VerifiedPrivateServiceLease {
        signed: signed.clone(),
        lease,
        claims,
        digest,
    })
}
impl InstallationIdentity {
    pub fn sign_private_service_host(
        &self,
        claims: &PrivateServiceHostClaims,
    ) -> Result<SignedPrivateServiceHost, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
        Ok(SignedPrivateServiceHost {
            signature: self
                .key
                .sign(&domain_message(HOST, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
    pub fn sign_private_service_usage(
        &self,
        claims: &PrivateServiceUsageClaims,
    ) -> Result<SignedPrivateServiceUsage, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
        Ok(SignedPrivateServiceUsage {
            signature: self
                .key
                .sign(&domain_message(USAGE, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
    pub fn private_service_open(
        &self,
        lease: &VerifiedPrivateServiceLease,
        nonce: [u8; 32],
    ) -> Result<PrivateServiceOpen, ContractError> {
        if self.public_key() != lease.claims.consumer_public_key || nonce == [0; 32] {
            return Err(denied());
        }
        let transcript = encode_service_message(&(lease.digest(), nonce), 512)?;
        Ok(PrivateServiceOpen {
            lease: lease.signed.clone(),
            nonce,
            consumer_signature: self
                .key
                .sign(&domain_message(OPEN, &transcript))
                .to_bytes()
                .to_vec(),
        })
    }
    pub fn private_service_ready(
        &self,
        lease: &VerifiedPrivateServiceLease,
        open: &PrivateServiceOpen,
    ) -> Result<PrivateServiceReady, ContractError> {
        verify_private_service_open(lease, open)?;
        if self.public_key() != lease.claims.host_public_key {
            return Err(denied());
        }
        let transcript = encode_service_message(&(lease.digest(), open.nonce), 512)?;
        Ok(PrivateServiceReady {
            lease_sha256: lease.digest(),
            nonce: open.nonce,
            host_signature: self
                .key
                .sign(&domain_message(READY, &transcript))
                .to_bytes()
                .to_vec(),
        })
    }
}
pub fn verify_private_service_host(
    signed: &SignedPrivateServiceHost,
    key: &[u8; 32],
) -> Result<PrivateServiceHostClaims, ContractError> {
    if signed.claims.len() > PRIVATE_SERVICE_MESSAGE_BYTES {
        return Err(denied());
    }
    verify_signature(key, HOST, &signed.claims, &signed.signature)?;
    let claims: PrivateServiceHostClaims =
        decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_private_service_usage(
    signed: &SignedPrivateServiceUsage,
    key: &[u8; 32],
) -> Result<PrivateServiceUsageClaims, ContractError> {
    if signed.claims.len() > PRIVATE_SERVICE_MESSAGE_BYTES {
        return Err(denied());
    }
    verify_signature(key, USAGE, &signed.claims, &signed.signature)?;
    let claims: PrivateServiceUsageClaims =
        decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_private_service_open(
    lease: &VerifiedPrivateServiceLease,
    open: &PrivateServiceOpen,
) -> Result<(), ContractError> {
    if open.nonce == [0; 32]
        || open.lease.claims != lease.signed.claims
        || open.lease.service_lease.claims != lease.signed.service_lease.claims
    {
        return Err(denied());
    }
    let transcript = encode_service_message(&(lease.digest(), open.nonce), 512)?;
    verify_signature(
        &lease.claims.consumer_public_key,
        OPEN,
        &transcript,
        &open.consumer_signature,
    )
}
pub fn verify_private_service_ready(
    lease: &VerifiedPrivateServiceLease,
    open: &PrivateServiceOpen,
    ready: &PrivateServiceReady,
) -> Result<(), ContractError> {
    if ready.lease_sha256 != lease.digest() || ready.nonce != open.nonce {
        return Err(denied());
    }
    let transcript = encode_service_message(&(lease.digest(), open.nonce), 512)?;
    verify_signature(
        &lease.claims.host_public_key,
        READY,
        &transcript,
        &ready.host_signature,
    )
}
