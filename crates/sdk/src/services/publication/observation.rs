//! Actual issuer-signed lease sampling. No raw claims/credentials enter IPC.
use super::*;
use nestlink_node::service_plane::ServicePublicationHandle;
use nestlink_protocol::service_plane::observation::{
    OBSERVATION_BYTES, SIGNED_LEASE_OBSERVATION_DOMAIN, ServiceLeaseObservation,
    ServiceLeaseObservationRequest,
};

pub(super) fn envelope_digest(lease: &VerifiedServiceLease) -> [u8; 32] {
    let signed = lease.signed();
    let mut bytes = Vec::with_capacity(
        SIGNED_LEASE_OBSERVATION_DOMAIN.len() + 16 + signed.claims.len() + signed.signature.len(),
    );
    bytes.extend_from_slice(SIGNED_LEASE_OBSERVATION_DOMAIN);
    bytes.extend_from_slice(&(signed.claims.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&signed.claims);
    bytes.extend_from_slice(&(signed.signature.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&signed.signature);
    digest(&bytes)
}
fn matches_request(
    lease: &VerifiedServiceLease,
    request: &ServiceLeaseObservationRequest,
    now: u64,
) -> bool {
    let c = lease.claims();
    request.valid()
        && c.service_id == request.service_id
        && c.service_revision == request.approved_revision
        && request
            .expected_publication_id
            .as_ref()
            .is_none_or(|id| *id == c.publication_id)
        && c.issued_at_unix_ms <= now
        && now < c.expires_at_unix_ms
        && lease.signed().signature.len() == 64
        && lease.signed().claims.len() <= SERVICE_MESSAGE_BYTES
}
pub(super) fn sample(
    publication: &ServicePublicationHandle,
    request: &ServiceLeaseObservationRequest,
    state: impl Fn() -> (bool, bool),
) -> Result<ServiceLeaseObservation, SdkError> {
    if !request.valid() {
        return Err(SdkError::Invalid);
    }
    let started = wall()?;
    let (stopped, cleanup_pending) = state();
    if stopped || cleanup_pending {
        return Err(SdkError::Trust);
    }
    let first = publication.lease()?;
    if !matches_request(&first, request, started) {
        return Err(SdkError::Trust);
    }
    let counters = publication.counters()?;
    let last = publication.lease()?;
    let finished = wall()?;
    let (stopped, cleanup_pending) = state();
    paired(
        &first,
        &last,
        request,
        started,
        finished,
        counters,
        stopped,
        cleanup_pending,
    )
}
#[allow(clippy::too_many_arguments)] // Exact pair of signed observations plus sample metadata.
pub(super) fn paired(
    first: &VerifiedServiceLease,
    last: &VerifiedServiceLease,
    request: &ServiceLeaseObservationRequest,
    started: u64,
    finished: u64,
    counters: nestlink_node::meter::Counters,
    stopped: bool,
    cleanup_pending: bool,
) -> Result<ServiceLeaseObservation, SdkError> {
    if stopped
        || cleanup_pending
        || finished < started
        || !matches_request(first, request, started)
        || first.issuer() != last.issuer()
        || first.signed().claims != last.signed().claims
        || first.signed().signature != last.signed().signature
        || !matches_request(last, request, finished)
    {
        return Err(SdkError::Trust);
    }
    let c = last.claims();
    let observation = ServiceLeaseObservation {
        schema_version: 1,
        runtime_generation: None,
        publication_id: c.publication_id.clone(),
        publication_generation: c.publication_generation,
        service_id: c.service_id.clone(),
        service_revision: c.service_revision,
        choice_revision: c.choice_revision,
        definition_sha256: c.definition_sha256,
        target_sha256: c.target_sha256,
        lease_sequence: c.lease_sequence,
        issued_at_unix_ms: c.issued_at_unix_ms,
        expires_at_unix_ms: c.expires_at_unix_ms,
        verified_issuer_ed25519: last.issuer(),
        lease_claims_sha256: last.digest(),
        signed_lease_envelope_sha256: envelope_digest(last),
        issuer_signature_base64url: URL_SAFE_NO_PAD.encode(&last.signed().signature),
        sample_started_unix_ms: started,
        sample_finished_unix_ms: finished,
        opened_connections: counters.opened_connections,
        closed_connections: counters.closed_connections,
        admitted_bytes: counters.admitted_bytes,
        cleanup_pending,
        counters_non_atomic: true,
    };
    if serde_json::to_vec(&observation)?.len() > OBSERVATION_BYTES {
        return Err(SdkError::Invalid);
    }
    Ok(observation)
}
