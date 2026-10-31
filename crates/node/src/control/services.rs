//! Policy authority and aggregate accounting remain independent of publications.
use super::{Error, NodeCapacityReservation, NodeControl, sample};
use crate::service_plane::gate::rejected;
use nestlink_identity::service_plane::{VerifiedServiceLease, VerifiedServiceSnapshot};
use nestlink_protocol::{
    ContractError, ErrorCode, NodeLeaseClaims, NodeRole, service_plane::ServiceLeaseClaims,
};
use std::time::{Duration, Instant};
use tokio::sync::watch;
mod poll;
pub(super) use poll::poll;

pub struct ServiceNodePermit {
    capacity: NodeCapacityReservation,
    claims: ServiceLeaseClaims,
}
fn matches_node(node: &NodeLeaseClaims, service: &ServiceLeaseClaims) -> bool {
    node.deployment_id == service.deployment_id
        && node.security_epoch == service.security_epoch
        && node.policy_revision == service.policy_revision
        && node.node_id == service.edge_node_id()
        && node.node_key_sha256 == service.edge_key_sha256
        && node.runtime_id == service.edge_runtime_id
        && node.runtime_generation == service.edge_runtime_generation
}
impl NodeControl {
    /// Numeric freshness and poll diagnostics without any signed authority or
    /// endpoint identifiers. Reading this cannot renew or create authority.
    pub fn service_resource_observation(&self) -> Result<crate::service_plane::ServiceResourceObservation, Error> {
        Ok(self.state.lock().map_err(|_| Error::Control)?.resources.services.observation())
    }
    /// A completion observation for maintenance and temporary-directory owners.
    /// It becomes finished only after the control state, reporter and every
    /// outstanding publication have released their real SQLite store owner.
    pub fn service_usage_cleanup(
        &self,
    ) -> Result<crate::service_usage::ServiceUsageCleanup, Error> {
        let state = self.state.lock().map_err(|_| Error::Control)?;
        Ok(crate::service_usage::ServiceUsageStore::cleanup_owner(
            &state.service_usage,
        ))
    }

    /// Revoke all service publications while retaining their exact owners for
    /// the edge supervisor's worker-join and physical-drain phase.
    pub fn stop_service_publications(
        &self,
    ) -> Result<Vec<(String, crate::service_plane::ServicePublicationHandle)>, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        state.service_shutdown = true;
        state.resources.services.stop();
        Ok(state.resources.services.drain_candidates())
    }
    /// Retired owners whose edge attachment has not yet certified worker join.
    pub fn service_drain_candidates(
        &self,
    ) -> Result<Vec<(String, crate::service_plane::ServicePublicationHandle)>, Error> {
        let state = self.state.lock().map_err(|_| Error::Control)?;
        Ok(state.resources.services.drain_candidates())
    }
    /// Accept only the opaque token returned by the stopped publication after
    /// its last flow permit was durably closed. The caller is the edge
    /// supervisor, which separately joins attachment workers and closes the
    /// corresponding QUIC connection before reaching this call.
    pub fn confirm_service_drain(
        &self,
        publication_id: &str,
        token: crate::service_plane::ServiceDrainToken,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        let current = state.gate.current(sample(self.started)?)?;
        if current.runtime_id != token.edge_runtime_id
            || current.runtime_generation != token.edge_runtime_generation
            || token.publication_id != publication_id
        {
            return Err(Error::Control);
        }
        state.service_usage.confirm_drained(&token)?;
        if !state.resources.services.confirm_drained(publication_id) {
            return Err(Error::Control);
        }
        Ok(())
    }
    /// Give the durable reporter a bounded opportunity to deliver the final
    /// report and terminal seal. `false` means the caller must shut down with
    /// the server-side commitment still held.
    pub async fn wait_service_usage_settled(&self, budget: Duration) -> Result<bool, Error> {
        let result = tokio::time::timeout(budget, async {
            loop {
                let store = self
                    .state
                    .lock()
                    .map_err(|_| Error::Control)?
                    .service_usage
                    .clone();
                if store.snapshots(&self.runtime_id)?.is_empty() {
                    return Ok::<bool, Error>(true);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => Ok(false),
        }
    }
    /// Lease and policy delegation come from the same retained resource owner
    /// under one control lock; concurrent polls cannot mix their issuance times.
    pub fn service_publication_renewal(
        &self,
        id: &str,
    ) -> Result<nestlink_protocol::service_plane::publication::ServiceLeaseRenewal, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let handle = state
            .resources
            .services
            .publication(id)
            .map_err(|_| Error::Control)?;
        let lease = handle.lease().map_err(|_| Error::Control)?;
        let node =
            state
                .gate
                .authorize_forwarding(NodeRole::NodeEdge, true, sample(self.started)?)?;
        if !matches_node(node, lease.claims()) {
            return Err(Error::Control);
        }
        let issuer = state
            .resources
            .services
            .issuer_for(&lease)
            .map_err(|_| Error::Control)?;
        Ok(
            nestlink_protocol::service_plane::publication::ServiceLeaseRenewal {
                lease: lease.signed().clone(),
                issuer,
            },
        )
    }
    /// Sticky until the node runtime ends, even after the prior set is dropped.
    pub(crate) fn claim_service_resource_owner(
        &self,
        owner: [u8; 16],
        snapshot: &VerifiedServiceSnapshot,
    ) -> Result<
        (
            Instant,
            std::sync::Arc<crate::service_usage::ServiceUsageStore>,
        ),
        Error,
    > {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let deadline = inspect_snapshot(&mut state.gate, snapshot, self.started)?;
        match state.service_resource_owner {
            Some(existing) if existing != owner => {
                Err(Error::Authorization(rejected(ErrorCode::ReplayRejected)))
            }
            Some(_) => Ok((deadline, state.service_usage.clone())),
            None => {
                state.service_resource_owner = Some(owner);
                Ok((deadline, state.service_usage.clone()))
            }
        }
    }
    /// Inspects the independent edge policy without reserving a visitor slot.
    pub fn inspect_service_lease(&self, lease: &VerifiedServiceLease) -> Result<Instant, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let node =
            state
                .gate
                .authorize_forwarding(NodeRole::NodeEdge, true, sample(self.started)?)?;
        if !matches_node(node, lease.claims()) {
            return Err(Error::Authorization(rejected(ErrorCode::IdentityMismatch)));
        }
        self.started
            .checked_add(Duration::from_millis(state.gate.deadline_ms()))
            .ok_or(Error::Control)
    }
    /// The type's verified marker alone is insufficient: its issuer and query
    /// signer must be the keys pinned by this actual running NodeGate.
    pub fn inspect_service_snapshot(
        &self,
        snapshot: &VerifiedServiceSnapshot,
    ) -> Result<Instant, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        inspect_snapshot(&mut state.gate, snapshot, self.started)
    }
    /// Handles come from the one resource owner retained by this node runtime.
    pub fn service_publication(
        &self,
        id: &str,
    ) -> Result<crate::service_plane::ServicePublicationHandle, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let handle = state
            .resources
            .services
            .publication(id)
            .map_err(|_| Error::Control)?;
        let lease = handle.lease().map_err(|_| Error::Control)?;
        let node =
            state
                .gate
                .authorize_forwarding(NodeRole::NodeEdge, true, sample(self.started)?)?;
        if !matches_node(node, lease.claims()) {
            return Err(Error::Control);
        }
        Ok(handle)
    }
    pub fn service_publication_ids(&self) -> Result<Vec<String>, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        state
            .gate
            .authorize_forwarding(NodeRole::NodeEdge, true, sample(self.started)?)?;
        Ok(state.resources.services.active_ids())
    }
    pub fn reserve_service_capacity(
        &self,
        lease: &VerifiedServiceLease,
    ) -> Result<ServiceNodePermit, Error> {
        let capacity = self.reserve_capacity(NodeRole::NodeEdge, true)?;
        let permit = ServiceNodePermit {
            capacity,
            claims: lease.claims().clone(),
        };
        permit.deadline()?;
        Ok(permit)
    }
}
fn inspect_snapshot(
    gate: &mut crate::gate::NodeGate,
    snapshot: &VerifiedServiceSnapshot,
    started: Instant,
) -> Result<Instant, Error> {
    if snapshot.policy_issuer() != gate.trusted_policy_issuer() {
        return Err(Error::Authorization(rejected(ErrorCode::IdentityMismatch)));
    }
    let node = gate.authorize_forwarding(NodeRole::NodeEdge, true, sample(started)?)?;
    let q = &snapshot.claims().query;
    if q.deployment_id != node.deployment_id
        || q.security_epoch != node.security_epoch
        || q.node_id != node.node_id
        || q.runtime_id != node.runtime_id
        || q.runtime_generation != node.runtime_generation
        || q.policy_revision != node.policy_revision
        || q.lease_sequence != node.lease_sequence
        || snapshot.node_key_sha256().as_slice() != node.node_key_sha256.as_slice()
    {
        return Err(Error::Authorization(rejected(ErrorCode::IdentityMismatch)));
    }
    started
        .checked_add(Duration::from_millis(gate.deadline_ms()))
        .ok_or(Error::Control)
}
impl ServiceNodePermit {
    pub fn stopped(&self) -> watch::Receiver<bool> {
        self.capacity.stopped()
    }
    pub fn deadline(&self) -> Result<Instant, Error> {
        let mut state = self.capacity.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.capacity.stopped.borrow() {
            return Err(Error::Control);
        }
        let node = state.gate.authorize_forwarding(
            NodeRole::NodeEdge,
            true,
            sample(self.capacity.started)?,
        )?;
        if !matches_node(node, &self.claims) {
            return Err(Error::Authorization(rejected(ErrorCode::IdentityMismatch)));
        }
        self.capacity
            .started
            .checked_add(Duration::from_millis(state.gate.deadline_ms()))
            .ok_or(Error::Control)
    }
    pub(crate) fn byte_rate(&self) -> Result<u64, Error> {
        self.deadline()?;
        let mut state = self.capacity.state.lock().map_err(|_| Error::Control)?;
        Ok(state
            .gate
            .authorize_forwarding(NodeRole::NodeEdge, true, sample(self.capacity.started)?)?
            .bytes_per_second)
    }
    /// Synchronous bounded admission; publication quota is checked by the
    /// callback under the node lock, so either both counters commit or neither.
    pub(crate) fn admit<T>(
        &self,
        bytes: u64,
        enqueue: impl FnOnce() -> Result<T, ContractError>,
    ) -> Result<T, ContractError> {
        let mut state = self
            .capacity
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        if !state.ready || *self.capacity.stopped.borrow() {
            return Err(rejected(ErrorCode::PolicyRevoked));
        }
        let now = sample(self.capacity.started).map_err(|_| rejected(ErrorCode::LeaseExpired))?;
        let node = state
            .gate
            .authorize_forwarding(NodeRole::NodeEdge, true, now)?;
        if !matches_node(node, &self.claims) {
            return Err(rejected(ErrorCode::IdentityMismatch));
        }
        let rate = node.bytes_per_second;
        state.meter.admit(bytes, rate, now.monotonic_ms, enqueue)
    }
}

#[cfg(test)]
mod tests;
