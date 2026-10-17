//! Service-only node control and listener proof purposes.
use super::{NodeIdentity, NodePolicySigner};
use crate::{Signer, digest, domain_message, service_plane::*};
use nestlink_protocol::{ContractError, ErrorCode, NodeResourceQueryClaims, service_plane::*};
use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
mod publication;

impl NodeIdentity {
    pub fn sign_service_query(
        &self,
        query: &NodeResourceQueryClaims,
    ) -> Result<SignedServiceResourceQuery, ContractError> {
        query.validate()?;
        let claims = encode(query, SERVICE_MESSAGE_BYTES)?;
        Ok(SignedServiceResourceQuery {
            signature: self
                .key
                .sign(&domain_message(QUERY, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
    pub fn challenge_service_tunnel(
        &self,
        lease: &VerifiedServiceLease,
        stream_id: String,
        peer: SocketAddr,
        transport: ServiceTunnelTransport,
        now_ms: u64,
    ) -> Result<SignedServiceTunnelChallenge, ContractError> {
        if digest(&self.public_key()) != lease.claims().edge_key_sha256 {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "edge key is not leased",
            ));
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let challenge = ServiceTunnelChallenge {
            lease_sha256: lease.digest(),
            stream_id,
            nonce,
            peer_address: peer.to_string(),
            transport,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms
                .checked_add(SERVICE_RESOURCE_MS)
                .ok_or_else(|| {
                    ContractError::new(ErrorCode::LeaseExpired, "service challenge clock overflow")
                })?
                .min(lease.claims().expires_at_unix_ms),
        };
        challenge.validate(lease.claims())?;
        let claims = encode(&challenge, SERVICE_MESSAGE_BYTES)?;
        Ok(SignedServiceTunnelChallenge {
            signature: self
                .key
                .sign(&domain_message(EDGE_OPEN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl NodePolicySigner {
    pub fn sign_service_snapshot(
        &self,
        snapshot: &ServiceResourceSnapshot,
    ) -> Result<SignedServiceResourceSnapshot, ContractError> {
        snapshot.validate()?;
        let claims = encode(snapshot, SERVICE_SNAPSHOT_BYTES)?;
        Ok(SignedServiceResourceSnapshot {
            signature: self
                .key
                .sign(&domain_message(SNAPSHOT, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
