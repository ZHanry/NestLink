//! Independent publication, node snapshot, and per-tunnel signing purposes.
use crate::{
    InstallationIdentity, PermitSigner, Signer, SigningKey, digest, domain_message,
    services::definition_digest, verify_signature,
};
pub(crate) use nestlink_protocol::service_plane::{
    decode_service_message as decode, encode_service_message as encode,
};
use nestlink_protocol::{
    ContractError, ErrorCode, NodeResourceQueryClaims, service_plane::*, valid_id,
};
use zeroize::Zeroizing;
pub mod publication;

pub(crate) const LEASE: &[u8] = b"NestLink/v15/service-publication-lease/v1\0";
pub(crate) const QUERY: &[u8] = b"NestLink/v15/service-resource-query/v1\0";
pub(crate) const SNAPSHOT: &[u8] = b"NestLink/v15/service-resource-snapshot/v1\0";
pub(crate) const EDGE_OPEN: &[u8] = b"NestLink/v15/service-edge-open/v1\0";
const USAGE_GRANT: &[u8] = b"service-usage-budget/v1\0";
const HOST_PROOF: &[u8] = b"NestLink/v15/service-host-proof/v1\0";
const BINDING: &[u8] = b"NestLink/v15/service-publication-binding/v1\0";

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid signed service authority",
    )
}
fn verify_json(
    bytes: &[u8],
    signature: &[u8],
    key: &[u8; 32],
    domain: &[u8],
    maximum: usize,
) -> Result<(), ContractError> {
    if bytes.len() > maximum || signature.len() != 64 {
        return Err(invalid());
    }
    verify_signature(key, domain, bytes, signature)?;
    Ok(())
}

pub struct ServiceLeaseSigner {
    pub(crate) key: SigningKey,
}
impl ServiceLeaseSigner {
    pub fn from_master_seed(seed: &[u8; 32]) -> Result<Self, ContractError> {
        let mut derived = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"NestLink/v15/deployment-signing-keys/v1"), seed)
            .expand(b"service-publication-ed25519", &mut *derived)
            .map_err(|_| invalid())?;
        Ok(Self {
            key: SigningKey::from_bytes(&derived),
        })
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn sign(&self, claims: &ServiceLeaseClaims) -> Result<SignedServiceLease, ContractError> {
        claims.validate()?;
        if definition_digest(&claims.definition)? != claims.definition_sha256 {
            return Err(invalid());
        }
        verify_service_usage_budget_grant(&claims.usage_grant, &self.public_key())?;
        let claims = encode(claims, SERVICE_MESSAGE_BYTES)?;
        Ok(SignedServiceLease {
            signature: self
                .key
                .sign(&domain_message(LEASE, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }

    pub fn sign_usage_budget_grant(
        &self,
        claims: &ServiceUsageBudgetGrantClaims,
    ) -> Result<SignedServiceUsageBudgetGrant, ContractError> {
        claims.validate()?;
        let claims = encode(claims, SERVICE_USAGE_BYTES)?;
        Ok(SignedServiceUsageBudgetGrant {
            signature: self
                .key
                .sign(&domain_message(USAGE_GRANT, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl PermitSigner {
    pub fn service_lease_signer(&self) -> Result<ServiceLeaseSigner, ContractError> {
        let seed = Zeroizing::new(self.key.to_bytes());
        ServiceLeaseSigner::from_master_seed(&seed)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedServiceLease {
    claims: ServiceLeaseClaims,
    signed: SignedServiceLease,
    digest: [u8; 32],
    binding: [u8; 32],
    issuer: [u8; 32],
}
impl VerifiedServiceLease {
    pub fn claims(&self) -> &ServiceLeaseClaims {
        &self.claims
    }
    pub fn signed(&self) -> &SignedServiceLease {
        &self.signed
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn issuer(&self) -> [u8; 32] {
        self.issuer
    }
}
pub fn verify_service_lease(
    signed: &SignedServiceLease,
    issuer: &[u8; 32],
) -> Result<VerifiedServiceLease, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        issuer,
        LEASE,
        SERVICE_MESSAGE_BYTES,
    )?;
    let claims: ServiceLeaseClaims = decode(&signed.claims, SERVICE_MESSAGE_BYTES)?;
    claims.validate()?;
    verify_service_usage_budget_grant(&claims.usage_grant, issuer)?;
    if definition_digest(&claims.definition)? != claims.definition_sha256 {
        return Err(invalid());
    }
    let binding = publication_binding(&claims)?;
    Ok(VerifiedServiceLease {
        claims,
        signed: signed.clone(),
        digest: digest(&signed.claims),
        binding,
        issuer: *issuer,
    })
}

pub fn verify_service_usage_budget_grant(
    signed: &SignedServiceUsageBudgetGrant,
    issuer: &[u8; 32],
) -> Result<ServiceUsageBudgetGrantClaims, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        issuer,
        USAGE_GRANT,
        SERVICE_USAGE_BYTES,
    )?;
    let claims: ServiceUsageBudgetGrantClaims = decode(&signed.claims, SERVICE_USAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn publication_binding(claims: &ServiceLeaseClaims) -> Result<[u8; 32], ContractError> {
    claims.validate()?;
    let mut copy = claims.clone();
    copy.lease_sequence = 0;
    copy.issued_at_unix_ms = 0;
    copy.expires_at_unix_ms = 0;
    Ok(digest(&domain_message(
        BINDING,
        &encode(&copy, SERVICE_MESSAGE_BYTES)?,
    )))
}
pub fn verify_service_query(
    signed: &SignedServiceResourceQuery,
    key: &[u8; 32],
) -> Result<NodeResourceQueryClaims, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        key,
        QUERY,
        SERVICE_MESSAGE_BYTES,
    )?;
    let query: NodeResourceQueryClaims = decode(&signed.claims, SERVICE_MESSAGE_BYTES)?;
    query.validate()?;
    Ok(query)
}

pub struct VerifiedServiceSnapshot {
    snapshot: ServiceResourceSnapshot,
    leases: Vec<VerifiedServiceLease>,
    policy_issuer: [u8; 32],
    node_key_sha256: [u8; 32],
}
impl VerifiedServiceSnapshot {
    pub fn claims(&self) -> &ServiceResourceSnapshot {
        &self.snapshot
    }
    pub fn leases(&self) -> &[VerifiedServiceLease] {
        &self.leases
    }
    pub fn policy_issuer(&self) -> [u8; 32] {
        self.policy_issuer
    }
    pub fn node_key_sha256(&self) -> [u8; 32] {
        self.node_key_sha256
    }
}
pub fn verify_service_snapshot(
    signed: &SignedServiceResourceSnapshot,
    policy_issuer: &[u8; 32],
    request: &SignedServiceResourceQuery,
    node_public_key: &[u8; 32],
) -> Result<VerifiedServiceSnapshot, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        policy_issuer,
        SNAPSHOT,
        SERVICE_SNAPSHOT_BYTES,
    )?;
    let snapshot: ServiceResourceSnapshot = decode(&signed.claims, SERVICE_SNAPSHOT_BYTES)?;
    snapshot.validate()?;
    let query = verify_service_query(request, node_public_key)?;
    if snapshot.query != query || snapshot.query_sha256 != digest(&request.claims) {
        return Err(invalid());
    }
    let mut leases = Vec::with_capacity(snapshot.leases.len());
    for signed in &snapshot.leases {
        let lease = verify_service_lease(signed, &snapshot.service_lease_issuer)?;
        let c = lease.claims();
        if c.deployment_id != query.deployment_id
            || c.security_epoch != query.security_epoch
            || c.policy_revision != query.policy_revision
            || c.definition.edge_node_id != query.node_id
            || c.edge_runtime_id != query.runtime_id
            || c.edge_runtime_generation != query.runtime_generation
            || c.edge_key_sha256 != digest(node_public_key)
            || c.issued_at_unix_ms > snapshot.issued_at_unix_ms
            || c.expires_at_unix_ms <= snapshot.issued_at_unix_ms
            || leases.last().is_some_and(|last: &VerifiedServiceLease| {
                last.claims().publication_id >= c.publication_id
            })
        {
            return Err(invalid());
        }
        leases.push(lease);
    }
    Ok(VerifiedServiceSnapshot {
        snapshot,
        leases,
        policy_issuer: *policy_issuer,
        node_key_sha256: digest(node_public_key),
    })
}

pub fn verify_tunnel_challenge(
    signed: &SignedServiceTunnelChallenge,
    lease: &VerifiedServiceLease,
    edge_key: &[u8; 32],
) -> Result<ServiceTunnelChallenge, ContractError> {
    verify_json(
        &signed.claims,
        &signed.signature,
        edge_key,
        EDGE_OPEN,
        SERVICE_MESSAGE_BYTES,
    )?;
    let challenge: ServiceTunnelChallenge = decode(&signed.claims, SERVICE_MESSAGE_BYTES)?;
    challenge.validate(lease.claims())?;
    if challenge.lease_sha256 != lease.digest()
        || digest(edge_key) != lease.claims().edge_key_sha256
    {
        return Err(invalid());
    }
    Ok(challenge)
}
impl InstallationIdentity {
    pub fn prove_service_tunnel(
        &self,
        lease: &VerifiedServiceLease,
        challenge: &SignedServiceTunnelChallenge,
        edge_key: &[u8; 32],
        host_runtime_id: &str,
    ) -> Result<ServiceTunnelProof, ContractError> {
        verify_tunnel_challenge(challenge, lease, edge_key)?;
        if !valid_id(host_runtime_id) || self.fingerprint() != lease.claims().host_key_sha256 {
            return Err(invalid());
        }
        let mut proof = ServiceTunnelProof {
            lease_sha256: lease.digest(),
            challenge_sha256: digest(&challenge.claims),
            host_runtime_id: host_runtime_id.into(),
            signature: Vec::new(),
        };
        proof.signature = self
            .key
            .sign(&domain_message(
                HOST_PROOF,
                &encode(&proof, SERVICE_MESSAGE_BYTES)?,
            ))
            .to_bytes()
            .to_vec();
        Ok(proof)
    }
}
pub fn verify_tunnel_proof(
    lease: &VerifiedServiceLease,
    challenge: &SignedServiceTunnelChallenge,
    proof: &ServiceTunnelProof,
    host_key: &[u8; 32],
    edge_key: &[u8; 32],
) -> Result<(), ContractError> {
    let claims = verify_tunnel_challenge(challenge, lease, edge_key)?;
    if proof.lease_sha256 != lease.digest()
        || proof.challenge_sha256 != digest(&challenge.claims)
        || claims.lease_sha256 != lease.digest()
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
        HOST_PROOF,
        &encode(&copy, SERVICE_MESSAGE_BYTES)?,
        &proof.signature,
    )
}

#[cfg(test)]
mod tests;
