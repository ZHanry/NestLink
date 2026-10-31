//! Observation-only delegates share the original exact-query resource owner.
use super::*;
use nestlink_identity::network::{NetworkVerification, SignedNetworkGrant, verify_network_grant};
use nestlink_identity::network_topology::verify_topology_publisher;
use nestlink_protocol::{
    api::NetworkNodeTopologyAuthority,
    network::PeerId,
    network_topology::{
        BootIncarnation, MAX_NEIGHBORS, MAX_NODE_PUBLICATIONS, TopologyPublisherClaims,
    },
};
use std::collections::BTreeSet;

pub(super) fn verify_publications(
    snapshot: &NodeResourceSnapshotClaims,
    lease: &NodeLeaseClaims,
    now: u64,
) -> Result<Vec<NetworkNodeTopologyAuthority>, ContractError> {
    if snapshot.topology_publications_json.is_empty() {
        return Ok(Vec::new());
    }
    let publications: Vec<NetworkNodeTopologyAuthority> =
        serde_json::from_slice(&snapshot.topology_publications_json)
            .map_err(|_| error(ErrorCode::InvalidMessage))?;
    if publications.len() > MAX_NODE_PUBLICATIONS {
        return Err(error(ErrorCode::CapacityExceeded));
    }
    let mut spaces = BTreeSet::new();
    let revoked = BTreeSet::new();
    for publication in &publications {
        let claims = TopologyPublisherClaims::decode_canonical(&publication.publisher.claims)?;
        if !spaces.insert(claims.scope.space_id.clone())
            || publication.authority_key == [0; 32]
            || publication.publisher_digest == [0; 32]
            || claims.node_id != lease.node_id
            || claims.scope.deployment_id != lease.deployment_id
            || claims.incarnation.runtime_id != lease.runtime_id
            || claims.incarnation.runtime_generation != lease.runtime_generation
            || digest(&claims.public_key).as_slice() != lease.node_key_sha256.as_slice()
            || publication.local.node_id != lease.node_id
            || publication.local.revision == 0
            || publication.local.revision > i64::MAX as u64
            || publication.local.endpoints.quic_uri.is_none()
            || publication.neighbors.len() > MAX_NEIGHBORS
            || publication.route_exports.len() > nestlink_protocol::network::MAX_PREFIXES
        {
            return Err(error(ErrorCode::IdentityMismatch));
        }
        publication.local.endpoints.validate()?;
        let context = NetworkVerification {
            authority_key: &publication.authority_key,
            deployment_id: &claims.scope.deployment_id,
            space_id: &claims.scope.space_id,
            policy_epoch: claims.scope.policy_epoch,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let exports = publication
            .route_exports
            .iter()
            .map(|signed| {
                verify_network_grant(
                    &SignedNetworkGrant {
                        claims: signed.claims.clone(),
                        signature: signed.signature.clone(),
                    },
                    &context,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let publisher = verify_topology_publisher(
            &publication.publisher,
            &context,
            &lease.node_id,
            &claims.public_key,
            &BootIncarnation {
                runtime_id: lease.runtime_id.clone(),
                runtime_generation: lease.runtime_generation,
            },
            &exports,
        )?;
        if publisher.digest() != publication.publisher_digest {
            return Err(error(ErrorCode::IdentityMismatch));
        }
        let mut nodes = BTreeSet::new();
        let mut peers = BTreeSet::new();
        for neighbor in &publication.neighbors {
            let peer = PeerId::from_public_key(&neighbor.public_key);
            neighbor.incarnation.validate()?;
            neighbor.node.endpoints.validate()?;
            if neighbor.public_key == [0; 32]
                || neighbor.public_key == claims.public_key
                || neighbor.publisher_digest == [0; 32]
                || neighbor.node.node_id == lease.node_id
                || !nestlink_protocol::valid_id(&neighbor.node.node_id)
                || neighbor.node.revision == 0
                || neighbor.node.revision > i64::MAX as u64
                || neighbor.node.endpoints.quic_uri.is_none()
                || neighbor.expires_at_ms <= now
                || neighbor.expires_at_ms > i64::MAX as u64
                || !nodes.insert(neighbor.node.node_id.clone())
                || !peers.insert(peer)
                || claims.allowed_neighbors.binary_search(&peer).is_err()
            {
                return Err(error(ErrorCode::PermissionRequired));
            }
        }
    }
    Ok(publications)
}

pub(super) fn current(
    state: &mut Runtime,
    now: ClockSample,
) -> Result<Vec<NetworkNodeTopologyAuthority>, Error> {
    let lease = state
        .gate
        .authorize_forwarding(NodeRole::NodeRelay, false, now)?
        .clone();
    state.resources.expire(now);
    let Some(snapshot) = state.resources.snapshot.as_ref().filter(|snapshot| {
        now.monotonic_ms < snapshot.deadline && now.unix_ms < snapshot.claims.expires_at_unix_ms
    }) else {
        return Ok(Vec::new());
    };
    let mut publications = snapshot.topology.clone();
    let mut result = Vec::new();
    for mut publication in publications.drain(..) {
        let claims = TopologyPublisherClaims::decode_canonical(&publication.publisher.claims)?;
        let deadline = *state
            .resources
            .topology_deadlines
            .get(&publication.publisher_digest)
            .ok_or(Error::Control)?;
        if claims.node_id != lease.node_id
            || claims.incarnation.runtime_id != lease.runtime_id
            || claims.incarnation.runtime_generation != lease.runtime_generation
            || claims.scope.expires_at_ms <= now.unix_ms
            || now.monotonic_ms >= deadline
        {
            continue;
        }
        publication
            .neighbors
            .retain(|neighbor| neighbor.expires_at_ms > now.unix_ms);
        result.push(publication);
    }
    Ok(result)
}

impl NodeControl {
    /// Local observation owners retain the same original monotonic boundary;
    /// they cannot derive a fresh one from a detached publisher envelope.
    pub(in crate::control) fn network_topology_observation_deadline(
        &self,
        original: &NetworkNodeTopologyAuthority,
    ) -> Result<u64, Error> {
        self.check_network_topology_authority(original)?;
        let state = self.state.lock().map_err(|_| Error::Control)?;
        state.resources.topology_deadlines.get(&original.publisher_digest)
            .copied().ok_or(Error::Control)
    }

    #[cfg(test)]
    pub(in crate::control) fn install_topology_fixture(
        &self,
        snapshot: NodeResourceSnapshotClaims,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        let now = sample(self.started)?;
        let lease = state.gate.current(now)?.clone();
        state.resources.accept(snapshot, &lease, now.monotonic_ms, now)?;
        Ok(())
    }

    /// Lease observations may advance under the same original publication;
    /// identity, delegation, incarnation and endpoint changes remain terminal.
    pub fn check_network_topology_authority(
        &self,
        original: &NetworkNodeTopologyAuthority,
    ) -> Result<(), Error> {
        let claims = TopologyPublisherClaims::decode_canonical(&original.publisher.claims)?;
        let mut current = self.network_topology_authority(&claims.scope.space_id)?;
        if current.neighbors.len() != original.neighbors.len() {
            return Err(Error::Control);
        }
        for (current, original) in current.neighbors.iter_mut().zip(&original.neighbors) {
            current.expires_at_ms = original.expires_at_ms;
        }
        if &current != original {
            return Err(Error::Control);
        }
        Ok(())
    }
    pub fn network_topology_authorities(&self) -> Result<Vec<NetworkNodeTopologyAuthority>, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        current(&mut state, sample(self.started)?)
    }
    pub fn network_topology_authority(
        &self,
        space: &str,
    ) -> Result<NetworkNodeTopologyAuthority, Error> {
        self.network_topology_authorities()?
            .into_iter()
            .find(|publication| {
                TopologyPublisherClaims::decode_canonical(&publication.publisher.claims)
                    .is_ok_and(|claims| claims.scope.space_id == space)
            })
            .ok_or(Error::Control)
    }
}
