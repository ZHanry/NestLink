//! New ALPN possession uses the same resource candidate, Pair and meters.
use super::*;
use nestlink_identity::network::verify_network_node_admission;

pub struct NetworkChainNeighborProof<'a> {
    pub public_key: &'a [u8;32],
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
            state
                .gate
                .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
            state.resources.expire(now);
            Ok(state.resources.snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.entries.values().any(|entry| {
                    now.monotonic_ms < entry.deadline && match entry.network {
                        Some(NetworkBinding::Chain(route)) => route.neighbors().iter().any(|peer| &peer.0 == fingerprint),
                        _ => entry.claims.controller_key_sha256.as_slice() == fingerprint
                            || entry.claims.host_key_sha256.as_slice() == fingerprint,
                    }
                })
            }))
        })()
        .unwrap_or(false)
    }
}
impl NodeControl {
    /// Both endpoints and relays prove the exact current neighbor key on this
    /// TLS socket. A business endpoint cannot occupy the other relay's slot.
    pub fn prepare_network_chain_neighbor(
        &self, allocation_id: &str, binding: &[u8;32], tls_peer: &[u8;32],
        proof: NetworkChainNeighborProof<'_>, challenge: &[u8;32],
    ) -> Result<RelayEndpointCandidate,Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() { return Err(Error::Control); }
        let now = sample(self.started)?;
        let lease = state.gate.authorize_forwarding(NodeRole::NodeRelay,false,now)?.clone();
        state.resources.expire(now);
        let snapshot = state.resources.snapshot.as_ref().ok_or(Error::Control)?;
        let entry = snapshot.entries.get(allocation_id).ok_or(Error::Control)?;
        let Some(NetworkBinding::Chain(route)) = entry.network else { return Err(Error::Control); };
        let claims = entry.claims.clone();
        let issuer = snapshot.claims.allocation_issuer.as_slice().try_into().map_err(|_| Error::Control)?;
        let original_deadline = entry.deadline.min(state.gate.deadline());
        let continuity = entry.continuity.clone();
        let role = route.neighbors().iter().position(|peer| &peer.0 == tls_peer)
            .ok_or_else(|| error(ErrorCode::IdentityMismatch))?;
        if route.chain.digest != *binding || digest(proof.public_key) != *tls_peer
            || claims.node_key_sha256 != lease.node_key_sha256
        { return Err(error(ErrorCode::IdentityMismatch).into()); }
        nestlink_identity::network::verify_network_chain_admission(
            allocation_id,binding,route.relay,proof.public_key,challenge,proof.signature,
        )?;
        state.resources.inspect(&claims,role,now)?;
        Ok(RelayEndpointCandidate {
            state:self.state.clone(),started:self.started,claims,controller:role==0,
            transport:RelayTransport::QuicDatagram,issuer,deadline:original_deadline,
            node_stop:self.stopped.clone(),network:Some(NetworkBinding::Chain(route)),continuity,
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
        let Some(NetworkBinding::Single(route)) = entry.network else { return Err(Error::Control); };
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
