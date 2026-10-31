use super::{
    Error, PublicationContext, ServicePublication, ServicePublicationHandle, gate::rejected,
};
use crate::control::NodeControl;
use nestlink_identity::service_plane::{
    VerifiedServiceLease, VerifiedServiceSnapshot,
    publication::{VerifiedServiceIssuerDelegation, verify_service_issuer_delegation},
};
use nestlink_protocol::service_plane::publication::SignedServiceIssuerDelegation;
use nestlink_protocol::{
    ErrorCode,
    service_plane::SERVICE_PUBLICATIONS_PER_NODE,
};
use std::{
    collections::{BTreeMap, HashSet},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_REMEMBERED_PUBLICATIONS: usize = 4096;
/// Bounded timing/count diagnostics. No grant, identity, address, key, response
/// body or publication ID is retained in this observation.
#[derive(Clone, Debug, Default)]
pub struct ServiceResourceObservation {
    pub accepted: u64,
    pub transport_gaps: u64,
    pub superseded: u64,
    pub response_ms: u64,
    pub max_response_ms: u64,
    pub last_ttl_ms: u64,
    pub last_age_ms: Option<u64>,
    pub last_retire: Option<&'static str>,
}
#[derive(Debug, PartialEq, Eq)]
struct Binding {
    deployment_id: String,
    security_epoch: u64,
    policy_revision: u64,
    node_id: String,
    runtime_id: String,
    runtime_generation: u64,
    node_key_sha256: [u8; 32],
    policy_issuer: [u8; 32],
    service_issuer: [u8; 32],
}
/// Owns every service admitted by one node runtime's verified resource poll.
/// Missing, expired or changed publications are terminal for their exact ID;
/// recovery must ask the control plane for a new ID/generation.
pub struct ServiceResourceSet {
    owner_token: [u8; 16],
    binding: Option<Binding>,
    active: BTreeMap<String, ServicePublication>,
    /// Retired owners remain alive until the edge supervisor confirms that the
    /// matching attachment and flow workers have drained.
    draining: BTreeMap<String, ServicePublication>,
    terminal: HashSet<String>,
    sequence: u64,
    usage_store: Option<std::sync::Arc<crate::service_usage::ServiceUsageStore>>,
    last_request_started: Option<Instant>,
    freshness: Option<Instant>,
    stopped: bool,
    observation: ServiceResourceObservation,
    accepted_at: Option<Instant>,
    issuer: Option<(
        SignedServiceIssuerDelegation,
        VerifiedServiceIssuerDelegation,
    )>,
}
impl Default for ServiceResourceSet {
    fn default() -> Self {
        Self {
            owner_token: *uuid::Uuid::new_v4().as_bytes(),
            binding: None,
            active: BTreeMap::new(),
            draining: BTreeMap::new(),
            terminal: HashSet::new(),
            sequence: 0,
            usage_store: None,
            last_request_started: None,
            freshness: None,
            stopped: false,
            observation: ServiceResourceObservation::default(),
            accepted_at: None,
            issuer: None,
        }
    }
}
impl ServiceResourceSet {
    pub(crate) fn observation(&self) -> ServiceResourceObservation {
        let mut value = self.observation.clone();
        value.last_age_ms = self.accepted_at.map(|at| duration_ms(at.elapsed()));
        value
    }
    pub(crate) fn observe_response(&mut self, requested: Instant) {
        let elapsed = duration_ms(requested.elapsed());
        self.observation.response_ms = elapsed;
        self.observation.max_response_ms = self.observation.max_response_ms.max(elapsed);
    }
    pub(crate) fn observe_transport_gap(&mut self) {
        self.observation.transport_gaps = self.observation.transport_gaps.saturating_add(1);
    }
    pub(crate) fn observe_superseded(&mut self) {
        self.observation.superseded = self.observation.superseded.saturating_add(1);
    }
    pub(crate) fn set_usage_store(
        &mut self,
        store: std::sync::Arc<crate::service_usage::ServiceUsageStore>,
    ) {
        self.usage_store = Some(store);
    }
    pub(crate) fn set_issuer_delegation(
        &mut self,
        signed: SignedServiceIssuerDelegation,
    ) -> Result<(), Error> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| rejected(ErrorCode::AuthRequired))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?
            .as_millis()
            .try_into()
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?;
        let verified = verify_service_issuer_delegation(
            &signed,
            &binding.policy_issuer,
            &binding.deployment_id,
            now,
        )?;
        let claims = verified.claims();
        if claims.security_epoch != binding.security_epoch
            || claims.policy_revision != binding.policy_revision
            || claims.service_issuer != binding.service_issuer
            || self.issuer.as_ref().is_some_and(|(_, prior)| {
                prior.claims().issued_at_unix_ms > claims.issued_at_unix_ms
                    || prior.claims().expires_at_unix_ms > claims.expires_at_unix_ms
            })
        {
            return Err(rejected(ErrorCode::IdentityMismatch).into());
        }
        for publication in self.active.values() {
            let lease = publication.handle().lease()?;
            verified.verify_lease(lease.signed(), now)?;
        }
        self.issuer = Some((signed, verified));
        Ok(())
    }
    pub(crate) fn issuer_for(
        &self,
        lease: &VerifiedServiceLease,
    ) -> Result<SignedServiceIssuerDelegation, Error> {
        if self.stopped || self.freshness.is_none_or(|end| Instant::now() >= end) {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        let (signed, verified) = self
            .issuer
            .as_ref()
            .ok_or_else(|| rejected(ErrorCode::AuthRequired))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?
            .as_millis()
            .try_into()
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?;
        verified.verify_lease(lease.signed(), now)?;
        Ok(signed.clone())
    }
    pub(crate) fn owner_token(&self) -> [u8; 16] {
        self.owner_token
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn publication(&self, id: &str) -> Result<ServicePublicationHandle, Error> {
        if self.stopped {
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let publication = self
            .active
            .get(id)
            .ok_or_else(|| rejected(ErrorCode::AuthRequired))?;
        let handle = publication.handle();
        handle.lease()?;
        Ok(handle)
    }
    pub fn active_ids(&self) -> Vec<String> {
        self.active
            .iter()
            .filter_map(|(id, p)| p.handle().lease().ok().map(|_| id.clone()))
            .collect()
    }
    fn retire(&mut self, id: &str) {
        if let Some(publication) = self.active.remove(id) {
            publication.revoke();
            self.draining.insert(id.into(), publication);
            self.terminal.insert(id.into());
        }
    }
    pub(crate) fn expire(&mut self, now: Instant) {
        let stale = self.freshness.is_some_and(|end| now >= end);
        let expired: Vec<_> = self
            .active
            .iter()
            .filter_map(|(id, publication)| {
                let reason = if stale {
                    Some("snapshot-expired")
                } else {
                    match publication.handle().lease() {
                        Ok(_) => None,
                        Err(Error::Authorization(error)) if error.code == ErrorCode::LeaseExpired => Some("publication-expired"),
                        Err(_) => Some("publication-stopped"),
                    }
                };
                reason.map(|reason| (id.clone(), reason))
            })
            .collect();
        for (id, reason) in expired {
            self.observation.last_retire = Some(reason);
            self.retire(&id);
        }
    }
    pub fn stop(&mut self) {
        self.stopped = true;
        self.issuer.take();
        for (id, publication) in std::mem::take(&mut self.active) {
            publication.revoke();
            self.draining.insert(id, publication);
        }
    }
    pub(crate) fn drain_candidates(&self) -> Vec<(String, ServicePublicationHandle)> {
        self.draining
            .iter()
            .map(|(id, publication)| (id.clone(), publication.handle()))
            .collect()
    }
    pub(crate) fn confirm_drained(&mut self, id: &str) -> bool {
        if self.draining.remove(id).is_some() {
            return true;
        }
        if let Some(publication) = self.active.remove(id) {
            publication.revoke();
            self.terminal.insert(id.into());
            self.observation.last_retire = Some("drain-confirmed");
            return true;
        }
        false
    }
    /// `request_started` must be captured before sending this exact signed
    /// query. Anchoring remaining freshness there prevents network delay or a
    /// duplicate response from extending local authority.
    pub fn accept(
        &mut self,
        snapshot: VerifiedServiceSnapshot,
        node: &NodeControl,
        request_started: Instant,
    ) -> Result<(), Error> {
        if self.stopped {
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let (node_deadline, usage_store) =
            match node.claim_service_resource_owner(self.owner_token(), &snapshot) {
                Ok(end) => end,
                Err(error) => {
                    self.stop();
                    return Err(error.into());
                }
            };
        // Bind the public snapshot path to the same real ledger as the
        // pinned control poll, while holding the node owner claim above.
        self.set_usage_store(usage_store);
        self.accept_checked(snapshot, node_deadline, request_started)
    }
    /// Only the control runtime's pinned policy/query check may enter here.
    /// Keeping this crate-private prevents replacing actual gate inspection with
    /// a caller-supplied timestamp, while avoiding a reentrant runtime mutex.
    pub(crate) fn accept_checked(
        &mut self,
        snapshot: VerifiedServiceSnapshot,
        node_deadline: Instant,
        request_started: Instant,
    ) -> Result<(), Error> {
        if self.stopped {
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let now = Instant::now();
        self.expire(now);
        let wall: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?
            .as_millis()
            .try_into()
            .map_err(|_| rejected(ErrorCode::LeaseExpired))?;
        let c = snapshot.claims();
        let q = &c.query;
        if request_started > now
            || self
                .last_request_started
                .is_some_and(|old| request_started <= old)
            || q.request_sequence <= self.sequence
        {
            return Err(nestlink_protocol::ContractError::new(
                ErrorCode::ReplayRejected,
                "service snapshot query replay fence",
            )
            .into());
        }
        // VerifiedServiceSnapshot already enforces its signed <=2s lifetime.
        // Use the same receipt/request intersection as the original node lease;
        // subtracting response latency from an old request anchor counts it twice.
        let deadline = super::gate::signed_deadline(c.issued_at_unix_ms, c.expires_at_unix_ms, request_started, now, wall)?.min(node_deadline);
        if deadline <= now { return Err(rejected(ErrorCode::LeaseExpired).into()); }
        let binding = Binding {
            deployment_id: q.deployment_id.clone(),
            security_epoch: q.security_epoch,
            policy_revision: q.policy_revision,
            node_id: q.node_id.clone(),
            runtime_id: q.runtime_id.clone(),
            runtime_generation: q.runtime_generation,
            node_key_sha256: snapshot.node_key_sha256(),
            policy_issuer: snapshot.policy_issuer(),
            service_issuer: c.service_lease_issuer,
        };
        if self.binding.as_ref().is_some_and(|old| old != &binding) {
            self.stop();
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let incoming: HashSet<_> = snapshot
            .leases()
            .iter()
            .map(|lease| lease.claims().publication_id.clone())
            .collect();
        if incoming.len() != snapshot.leases().len()
            || incoming.len() > SERVICE_PUBLICATIONS_PER_NODE
        {
            return Err(nestlink_protocol::ContractError::new(
                ErrorCode::ReplayRejected,
                "service snapshot duplicate or excess publication fence",
            )
            .into());
        }
        if incoming.iter().any(|id| self.terminal.contains(id)) {
            return Err(nestlink_protocol::ContractError::new(
                ErrorCode::ReplayRejected,
                "service snapshot retired publication fence",
            )
            .into());
        }
        let new_ids = incoming
            .iter()
            .filter(|id| !self.active.contains_key(*id))
            .count();
        if self.terminal.len() + self.active.len() + new_ids > MAX_REMEMBERED_PUBLICATIONS {
            self.stop();
            return Err(rejected(ErrorCode::CapacityExceeded).into());
        }
        let context = PublicationContext {
            deployment_id: q.deployment_id.clone(),
            security_epoch: q.security_epoch,
            policy_revision: q.policy_revision,
            service_lease_issuer: c.service_lease_issuer,
        };
        // A snapshot is authoritative, including an empty list. Removed owners
        // revoke existing I/O before admitting any newly added publication.
        let removed: Vec<_> = self
            .active
            .keys()
            .filter(|id| !incoming.contains(*id))
            .cloned()
            .collect();
        for id in removed {
            self.observation.last_retire = Some("snapshot-absent");
            self.retire(&id);
        }
        for lease in snapshot.leases() {
            let id = &lease.claims().publication_id;
            let updated = if let Some(publication) = self.active.get(id) {
                publication
                    .renew(lease.clone(), request_started)
                    .and_then(|()| publication.cap_by_resource_snapshot(deadline))
            } else {
                let store = self
                    .usage_store
                    .as_ref()
                    .ok_or_else(|| rejected(ErrorCode::PolicyRevoked))?;
                store
                    .activate(lease)
                    .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
                ServicePublication::new_with_usage_store(
                    lease.clone(),
                    &context,
                    request_started,
                    store.clone(),
                )
                .and_then(|publication| {
                    publication.cap_by_resource_snapshot(deadline)?;
                    self.active.insert(id.clone(), publication);
                    Ok(())
                })
            };
            if let Err(error) = updated {
                self.retire(id);
                self.terminal.insert(id.clone());
                self.stop();
                return Err(error);
            }
        }
        self.binding = Some(binding);
        self.sequence = q.request_sequence;
        self.last_request_started = Some(request_started);
        self.freshness = Some(deadline);
        self.observation.accepted = self.observation.accepted.saturating_add(1);
        self.observation.last_ttl_ms = duration_ms(deadline.saturating_duration_since(now));
        self.accepted_at = Some(now);
        Ok(())
    }
}
fn duration_ms(value: std::time::Duration) -> u64 {
    value.as_millis().try_into().unwrap_or(u64::MAX)
}
impl Drop for ServiceResourceSet {
    fn drop(&mut self) {
        self.stop();
    }
}
