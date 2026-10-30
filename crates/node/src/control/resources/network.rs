//! New ALPN possession uses the same resource candidate, Pair and meters.
use super::*;
use nestlink_identity::network::verify_network_node_admission;
use nestlink_protocol::{
    api::{NetworkGrantView, NetworkRemoteRelayChainView},
    network::{GrantClaims, TransitClaims},
};

pub struct NetworkChainNeighborProof<'a> {
    pub public_key: &'a [u8; 32],
    pub signature: &'a [u8],
}

impl std::fmt::Debug for NodeControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeControl")
    }
}
impl nestlink_transport_stream::tls::CurrentClientPins for NodeControl {
    fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        (|| -> Result<bool, Error> {
            let mut state = self.state.lock().map_err(|_| Error::Control)?;
            if !state.ready || *self.stopped.borrow() {
                return Ok(false);
            }
            let now = sample(self.started)?;
            let topology_pin =
                super::topology::current(&mut state, now)?
                    .iter()
                    .any(|publication| {
                        publication.neighbors.iter().any(|neighbor| {
                            &nestlink_identity::digest(&neighbor.public_key) == fingerprint
                        })
                    });
            state
                .gate
                .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
            state.resources.expire(now);
            Ok(topology_pin
                || state.resources.snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot.entries.values().any(|entry| {
                        now.monotonic_ms < entry.deadline
                            && match entry.network {
                                Some(NetworkBinding::Chain(route)) => {
                                    route.neighbors().iter().any(|peer| &peer.0 == fingerprint)
                                }
                                _ => {
                                    entry.claims.controller_key_sha256.as_slice() == fingerprint
                                        || entry.claims.host_key_sha256.as_slice() == fingerprint
                                }
                            }
                    })
                }))
        })()
        .unwrap_or(false)
    }
}
impl NodeControl {
    /// Enumerate only metadata retained by the current verified resource
    /// snapshot. No endpoint or reverse allocation comes from a peer socket.
    pub fn network_chain_routes(&self) -> Result<Vec<NetworkChainRoute>, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        let lease = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?
            .clone();
        state.resources.expire(now);
        let Some(snapshot) = state.resources.snapshot.as_ref() else {
            return Ok(Vec::new());
        };
        if now.unix_ms >= snapshot.claims.expires_at_unix_ms {
            return Ok(Vec::new());
        }
        let mut routes = Vec::with_capacity(snapshot.claims.network_routes.len());
        for resource in &snapshot.claims.network_routes {
            if resource.network_schema_version != 2 {
                continue;
            }
            let allocation = resource.allocation.as_ref().ok_or(Error::Control)?;
            let entry = snapshot
                .entries
                .get(&allocation.allocation_id)
                .ok_or(Error::Control)?;
            let Some(NetworkBinding::Chain(binding)) = entry.network else {
                return Err(Error::Control);
            };
            if now.monotonic_ms >= entry.deadline
                || now.unix_ms >= entry.claims.expires_at_unix_ms
                || now.unix_ms >= binding.chain.expires_at_ms
            {
                continue;
            }
            let pair = state.resources.pairs.get(&allocation.allocation_id);
            if pair.is_some_and(|pair| pair.closed)
                || (pair.is_none() && state.resources.seen.contains(&allocation.allocation_id))
            {
                continue;
            }
            if entry.claims != *allocation
                || entry.binding != allocation_binding(allocation)?
                || entry.network_credential != Some(digest(&resource.encode_to_vec()))
                || allocation.deployment_id != lease.deployment_id
                || allocation.node_id != lease.node_id
                || allocation.runtime_id != lease.runtime_id
                || allocation.runtime_generation != lease.runtime_generation
                || allocation.security_epoch != lease.security_epoch
                || allocation.policy_revision != lease.policy_revision
                || allocation.node_key_sha256 != lease.node_key_sha256
                || binding.relay.0.as_slice() != lease.node_key_sha256.as_slice()
            {
                return Err(error(ErrorCode::IdentityMismatch).into());
            }
            let view: NetworkRemoteRelayChainView =
                serde_json::from_slice(&resource.chain_bundle_json)
                    .map_err(|_| error(ErrorCode::InvalidMessage))?;
            let local = binding
                .chain
                .relays
                .iter()
                .position(|relay| *relay == binding.relay)
                .ok_or_else(|| error(ErrorCode::IdentityMismatch))?;
            let transits = [
                chain_transit(&view.transits[0])?,
                chain_transit(&view.transits[1])?,
            ];
            let remote = local ^ 1;
            if view.nodes[local].node_id != allocation.node_id
                || view.nodes[local].revision != allocation.node_endpoint_revision
                || view.nodes[remote].node_id == allocation.node_id
                || transits[0].relay != binding.chain.relays[0]
                || transits[1].relay != binding.chain.relays[1]
                || transits[local].scope.grant_id != allocation.allocation_id
                || transits[remote].scope.grant_id == allocation.allocation_id
                || transits[0].route_id != view.route_id
                || transits[1].route_id != view.route_id
                || transits[0]
                    .scope
                    .expires_at_ms
                    .min(transits[1].scope.expires_at_ms)
                    != binding.chain.expires_at_ms
            {
                return Err(error(ErrorCode::IdentityMismatch).into());
            }
            routes.push(NetworkChainRoute {
                binding,
                allocation_id: allocation.allocation_id.clone(),
                neighbor_allocation_id: transits[remote].scope.grant_id.clone(),
                neighbor_node: view.nodes[remote].clone(),
            });
        }
        routes.sort_unstable_by(|left, right| left.allocation_id.cmp(&right.allocation_id));
        Ok(routes)
    }

    /// The inbound handshake compares its peer's reverse allocation with this
    /// current description after preparing its independently verified candidate.
    pub fn network_chain_route(&self, allocation_id: &str) -> Result<NetworkChainRoute, Error> {
        self.network_chain_routes()?
            .into_iter()
            .find(|route| route.allocation_id == allocation_id)
            .ok_or(Error::Control)
    }

    /// Both endpoints and relays prove the exact current neighbor key on this
    /// TLS socket. A business endpoint cannot occupy the other relay's slot.
    pub fn prepare_network_chain_neighbor(
        &self,
        allocation_id: &str,
        binding: &[u8; 32],
        tls_peer: &[u8; 32],
        proof: NetworkChainNeighborProof<'_>,
        challenge: &[u8; 32],
    ) -> Result<RelayEndpointCandidate, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        let lease = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?
            .clone();
        state.resources.expire(now);
        let snapshot = state.resources.snapshot.as_ref().ok_or(Error::Control)?;
        let entry = snapshot.entries.get(allocation_id).ok_or(Error::Control)?;
        let Some(NetworkBinding::Chain(route)) = entry.network else {
            return Err(Error::Control);
        };
        let claims = entry.claims.clone();
        let issuer = snapshot
            .claims
            .allocation_issuer
            .as_slice()
            .try_into()
            .map_err(|_| Error::Control)?;
        let original_deadline = entry.deadline.min(state.gate.deadline());
        let continuity = entry.continuity.clone();
        let role = route
            .neighbors()
            .iter()
            .position(|peer| &peer.0 == tls_peer)
            .ok_or_else(|| error(ErrorCode::IdentityMismatch))?;
        if route.chain.digest != *binding
            || digest(proof.public_key) != *tls_peer
            || claims.node_key_sha256 != lease.node_key_sha256
        {
            return Err(error(ErrorCode::IdentityMismatch).into());
        }
        nestlink_identity::network::verify_network_chain_admission(
            allocation_id,
            binding,
            route.relay,
            proof.public_key,
            challenge,
            proof.signature,
        )?;
        state.resources.inspect(&claims, role, now)?;
        Ok(RelayEndpointCandidate {
            state: self.state.clone(),
            started: self.started,
            claims,
            controller: role == 0,
            transport: RelayTransport::QuicDatagram,
            issuer,
            deadline: original_deadline,
            node_stop: self.stopped.clone(),
            network: Some(NetworkBinding::Chain(route)),
            continuity,
        })
    }

    pub fn prepare_network_relay_endpoint(
        &self,
        allocation_id: &str,
        binding: &[u8; 32],
        tls_peer: &[u8; 32],
        proof: RelayEndpointProof<'_>,
        challenge: &[u8; 32],
    ) -> Result<RelayEndpointCandidate, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        let lease = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?
            .clone();
        state.resources.expire(now);
        let snapshot = state.resources.snapshot.as_ref().ok_or(Error::Control)?;
        let entry = snapshot.entries.get(allocation_id).ok_or(Error::Control)?;
        let Some(NetworkBinding::Single(route)) = entry.network else {
            return Err(Error::Control);
        };
        let claims = entry.claims.clone();
        let issuer = snapshot
            .claims
            .allocation_issuer
            .as_slice()
            .try_into()
            .map_err(|_| Error::Control)?;
        let original_deadline = entry.deadline.min(state.gate.deadline());
        let continuity = entry.continuity.clone();
        let role = if proof.device_id == claims.controller_device_id {
            0
        } else if proof.device_id == claims.host_device_id {
            1
        } else {
            return Err(error(ErrorCode::IdentityMismatch).into());
        };
        let key = if role == 0 {
            &claims.controller_key_sha256
        } else {
            &claims.host_key_sha256
        };
        if route.digest != *binding
            || digest(proof.public_key) != *tls_peer
            || key.as_slice() != tls_peer
            || claims.node_key_sha256 != lease.node_key_sha256
            || proof.transport != RelayTransport::QuicDatagram
        {
            return Err(error(ErrorCode::IdentityMismatch).into());
        }
        verify_network_node_admission(
            allocation_id,
            binding,
            proof.device_id,
            proof.public_key,
            challenge,
            proof.signature,
        )?;
        state.resources.inspect(&claims, role, now)?;
        Ok(RelayEndpointCandidate {
            state: self.state.clone(),
            started: self.started,
            claims,
            controller: role == 0,
            transport: proof.transport,
            issuer,
            deadline: original_deadline,
            node_stop: self.stopped.clone(),
            network: Some(NetworkBinding::Single(route)),
            continuity,
        })
    }
}

fn chain_transit(view: &NetworkGrantView) -> Result<TransitClaims, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&view.claims)
        .map_err(|_| error(ErrorCode::InvalidMessage))?;
    let GrantClaims::Transit(claims) = GrantClaims::decode_canonical(&bytes)? else {
        return Err(error(ErrorCode::IdentityMismatch).into());
    };
    if view.schema_version != 1 || claims.scope.grant_id != view.grant_id {
        return Err(error(ErrorCode::IdentityMismatch).into());
    }
    Ok(claims)
}
