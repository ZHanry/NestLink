//! Bounded read-only diagnostics, never an authority or signed attestation.
use serde::{Deserialize, Serialize};

/// None discovers only the exact service/revision of the current unique owner.
/// Subsequent samples should pin the publication identity returned by discovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLeaseObservationRequest {
    pub service_id: String,
    pub approved_revision: u64,
    pub expected_publication_id: Option<String>,
}
impl ServiceLeaseObservationRequest {
    pub fn valid(&self) -> bool {
        crate::valid_id(&self.service_id)
            && crate::services::revision_valid(self.approved_revision)
            && self
                .expected_publication_id
                .as_ref()
                .is_none_or(|id| crate::valid_id(id))
    }
}
/// Original verified public delegation only; contains no account/token authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIssuerDelegationEvidence {
    pub verified_policy_issuer_ed25519: [u8; 32],
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
/// Only whitelisted public lease identity/signature material is exported. Pair
/// with an independently retained issuer record containing the actual claims.
/// The signature cannot be verified from this summary alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLeaseObservation {
    pub schema_version: u32,
    /// Set by the authenticated Actor IPC path; SDK-only samples have no Actor.
    pub runtime_generation: Option<u64>,
    /// Some on the public LocalServiceRuntime path. Internal base samples omit it.
    pub issuer_delegation: Option<ServiceIssuerDelegationEvidence>,
    pub publication_id: String,
    pub publication_generation: u64,
    pub service_id: String,
    pub service_revision: u64,
    pub choice_revision: u64,
    pub definition_sha256: [u8; 32],
    pub target_sha256: [u8; 32],
    pub lease_sequence: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub verified_issuer_ed25519: [u8; 32],
    /// SHA256 of the original canonical encoded claims, not the signed envelope.
    pub lease_claims_sha256: [u8; 32],
    /// SHA256(domain || u64be(claims.len) || claims || u64be(sig.len) || sig).
    pub signed_lease_envelope_sha256: [u8; 32],
    /// Original issuer signature, base64url without padding, exactly 64 bytes.
    pub issuer_signature_base64url: String,
    pub sample_started_unix_ms: u64,
    pub sample_finished_unix_ms: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub admitted_bytes: u64,
    pub cleanup_pending: bool,
    /// Counters are sampled between two equal live lease reads, not atomically
    /// with each other, wall clock or the lease. This is historical observation.
    pub counters_non_atomic: bool,
}
pub const OBSERVATION_BYTES: usize = 8192;
/// Fixed public delegation claims fit this bound; do not export general signed messages.
pub const ISSUER_DELEGATION_OBSERVATION_BYTES: usize = 1024;
pub const SIGNED_LEASE_OBSERVATION_DOMAIN: &[u8] =
    b"NestLink/v15/service-signed-lease-observation/v1\0";
