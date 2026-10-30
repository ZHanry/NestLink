//! Bounded authenticated observations produce route candidates, never grants.
//! Only a current management batch plus exact live advertisement proofs can
//! populate the graph. Historical expired records retain replay fences only.
use nestlink_identity::{
    digest,
    network::{NetworkVerification, VerifiedNetworkPath},
    network_topology::{VerifiedTopologyAdvertisement, VerifiedTopologyUpdate},
};
use nestlink_protocol::{
    ContractError, ErrorCode,
    network::{MAX_HOPS, MAX_RELAYS, PeerId, PeerPair},
    network_topology::{
        BootIncarnation, MAX_ADVERTISEMENTS, MAX_NEIGHBORS, MAX_UPDATE_BYTES,
        SignedTopologyAdvertisement, TopologyAdvertisement, TopologyChange,
        TopologyReport, TopologySync, TopologyWithdrawal,
    },
};
use petgraph::{algo::dijkstra, graph::DiGraph, visit::Reversed};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_GRAPH_NODES: usize = MAX_ADVERTISEMENTS;
pub const MAX_GRAPH_EDGES: usize = MAX_ADVERTISEMENTS * MAX_NEIGHBORS;
pub const MAX_GRAPH_BYTES: usize = MAX_UPDATE_BYTES;

/// The caller supplies only relays from its current authenticated endpoint
/// candidate owner. This value is an input observation, not a network grant.
#[derive(Clone)]
pub struct EndpointAttachments {
    peer: PeerId,
    relays: Vec<PeerId>,
}
impl EndpointAttachments {
    pub fn new(peer: PeerId, mut relays: Vec<PeerId>) -> Result<Self, ContractError> {
        peer.validate()?;
        if relays.len() > MAX_RELAYS {
            return Err(capacity("too many endpoint attachments"));
        }
        relays.sort();
        if relays.contains(&peer) || relays.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid("duplicate or reflexive endpoint attachment"));
        }
        for relay in &relays {
            relay.validate()?;
        }
        Ok(Self { peer, relays })
    }
}

/// A suggested ordered relay chain. Admission still needs a fresh management
/// reservation and each original business/network/neighbor proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteCandidate {
    relays: Vec<PeerId>,
    cursor: u64,
    expires_at_ms: u64,
}
impl RouteCandidate {
    pub fn relays(&self) -> &[PeerId] {
        &self.relays
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Clone)]
struct HighWater {
    peer: PeerId,
    incarnation: BootIncarnation,
    sequence: u64,
    publisher_digest: [u8; 32],
    envelope_digest: Option<[u8; 32]>,
    withdrawn: bool,
}
#[derive(Clone)]
struct Observation {
    report: TopologyReport,
    expires_at_ms: u64,
    publication_grant_ids: Vec<String>,
    statement_bytes: usize,
}

#[derive(Clone)]
pub struct TopologyGraph {
    authority: [u8; 32],
    deployment_id: String,
    space_id: String,
    policy_epoch: u64,
    last_observed_ms: u64,
    cursor: Option<u64>,
    needs_more: bool,
    live: BTreeMap<String, Observation>,
    high_water: BTreeMap<String, HighWater>,
}
impl TopologyGraph {
    pub fn new(context: &NetworkVerification<'_>) -> Result<Self, ContractError> {
        if *context.authority_key == [0; 32]
            || !nestlink_protocol::valid_id(context.deployment_id)
            || !nestlink_protocol::valid_id(context.space_id)
            || context.policy_epoch == 0
            || context.now_ms == 0
        {
            return Err(invalid("invalid trusted topology graph context"));
        }
        Ok(Self {
            authority: *context.authority_key,
            deployment_id: context.deployment_id.into(),
            space_id: context.space_id.into(),
            policy_epoch: context.policy_epoch,
            last_observed_ms: context.now_ms,
            cursor: None,
            needs_more: true,
            live: BTreeMap::new(),
            high_water: BTreeMap::new(),
        })
    }
    pub fn cursor(&self) -> Option<u64> {
        self.cursor
    }
    /// A cursor alone does not establish a current view while the authority
    /// has explicitly reported additional journal pages.
    pub fn needs_more(&self) -> bool {
        self.needs_more
    }
    pub fn active_publishers(&self) -> usize {
        self.live.len()
    }
    pub fn retained_publishers(&self) -> usize {
        self.high_water.len()
    }

    /// `update` must have passed the exact query nonce verifier. Current
    /// upserts require a matching proof of the original signed envelope;
    /// expired historical entries rely only on the enclosing authority batch
    /// for high-water advancement and never enter the live graph.
    /// Batch contents commit together after validation. Trusted time and
    /// current revocation are terminal observations even if the batch fails.
    pub fn apply(
        &mut self,
        context: &NetworkVerification<'_>,
        update: &VerifiedTopologyUpdate,
        advertisements: &[VerifiedTopologyAdvertisement],
    ) -> Result<(), ContractError> {
        self.expire(context)?;
        update.check_current(context)?;
        if advertisements.len() > MAX_ADVERTISEMENTS {
            return Err(capacity("too many topology verification proofs"));
        }
        let mut proofs = BTreeMap::new();
        for advertisement in advertisements {
            if proofs.insert(advertisement.envelope_digest(), advertisement).is_some() {
                return Err(invalid("duplicate topology verification proof"));
            }
        }
        let mut used = BTreeSet::new();
        let mut next = self.clone();
        match &update.claims().sync {
            TopologySync::Full { cursor, advertisements } => {
                if self.cursor.is_some_and(|saved| *cursor < saved) {
                    return Err(replay("topology full snapshot cursor went backward"));
                }
                let advance = self.cursor != Some(*cursor);
                let old_live: Vec<_> = next.live.keys().cloned().collect();
                next.live.clear();
                for signed in advertisements {
                    next.upsert(context, signed, &proofs, &mut used, advance)?;
                }
                for node in old_live {
                    if !next.live.contains_key(&node)
                        && let Some(water) = next.high_water.get_mut(&node)
                    {
                        // A full response replaces the live view. Retain the
                        // fence so its omission cannot resurrect an old ad.
                        water.withdrawn = true;
                    }
                }
                next.cursor = Some(*cursor);
                next.needs_more = false;
            }
            TopologySync::Delta { after_cursor, cursor, changes, has_more } => {
                if self.cursor != Some(*after_cursor) {
                    return Err(replay("topology delta does not match the saved cursor"));
                }
                for entry in changes {
                    match &entry.change {
                        TopologyChange::Upsert(signed) => {
                            next.upsert(context, signed, &proofs, &mut used, true)?;
                        }
                        TopologyChange::Withdraw(withdrawal) => next.withdraw(withdrawal)?,
                    }
                }
                next.cursor = Some(*cursor);
                next.needs_more = *has_more;
            }
        }
        if proofs.keys().any(|key| !used.contains(key)) {
            return Err(invalid("topology proof does not match an update envelope"));
        }
        next.enforce_limits()?;
        next.last_observed_ms = context.now_ms;
        *self = next;
        Ok(())
    }

    /// Expiry and current revocation remove observations while keeping replay
    /// fences. A later clock rollback cannot make those observations live.
    pub fn expire(&mut self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        self.check_context(context)?;
        self.expire_inner(context);
        self.last_observed_ms = context.now_ms;
        Ok(())
    }

    pub fn candidate(
        &mut self,
        context: &NetworkVerification<'_>,
        path: &VerifiedNetworkPath,
        source: &EndpointAttachments,
        destination: &EndpointAttachments,
    ) -> Result<Option<RouteCandidate>, ContractError> {
        self.expire(context)?;
        path.check_current(context)?;
        if PeerPair::new(source.peer, destination.peer)? != path.peers() {
            return Err(invalid("topology endpoint attachments belong to another path"));
        }
        let cursor = self.cursor.ok_or_else(|| replay("topology requires a full snapshot first"))?;
        if self.needs_more {
            return Ok(None);
        }
        let maximum = path.claims().policy.max_hops.min(MAX_HOPS);
        if maximum == 0 {
            return Ok(None);
        }
        let by_peer: BTreeMap<_, _> = self.live.values().map(|ad| (ad.report.peer, ad)).collect();
        let relays: Vec<_> = path.claims().policy.relays.iter().copied()
            .filter(|peer| by_peer.contains_key(peer) && !path.peers().contains(*peer))
            .collect();
        let mut graph = DiGraph::<Vertex, ()>::new();
        let start = graph.add_node(Vertex::Start);
        let end = graph.add_node(Vertex::End);
        let mut vertices = BTreeMap::new();
        for used in 1..=maximum {
            for peer in &relays {
                vertices.insert((*peer, used), graph.add_node(Vertex::Relay(*peer, used)));
            }
        }
        for peer in &relays {
            if source.relays.binary_search(peer).is_ok() {
                let first = *vertices.get(&(*peer, 1)).ok_or_else(|| invalid("missing topology vertex"))?;
                graph.add_edge(start, first, ());
            }
            for used in 1..=maximum {
                let local = *vertices.get(&(*peer, used)).ok_or_else(|| invalid("missing topology vertex"))?;
                if destination.relays.binary_search(peer).is_ok() {
                    graph.add_edge(local, end, ());
                }
                if used < maximum {
                    for remote in &relays {
                        if peer != remote && mutually_observed(&by_peer, *peer, *remote) {
                            let next = *vertices.get(&(*remote, used + 1)).ok_or_else(|| invalid("missing topology vertex"))?;
                            graph.add_edge(local, next, ());
                        }
                    }
                }
            }
        }
        // The mature shortest-path algorithm supplies distances to the goal.
        // Greedy traversal of equal shortest distances then chooses the
        // lexicographically smallest PeerId chain, independent of hash order.
        // Every adjacency costs one; unknown RTT is never represented as zero.
        let distance = dijkstra(Reversed(&graph), end, None, |_| 1u32);
        if !distance.contains_key(&start) {
            return Ok(None);
        }
        let mut current = start;
        let mut selected = Vec::new();
        for _ in 0..=maximum {
            let remaining = *distance.get(&current).ok_or_else(|| invalid("missing topology distance"))?;
            let mut neighbors: Vec<_> = graph.neighbors(current).collect();
            neighbors.sort_by_key(|index| graph[*index]);
            let next = neighbors.into_iter().find(|index| {
                distance.get(index).is_some_and(|value| value.checked_add(1) == Some(remaining))
            }).ok_or_else(|| invalid("broken topology shortest path"))?;
            current = next;
            match graph[current] {
                Vertex::End => break,
                Vertex::Relay(peer, _) => selected.push(peer),
                Vertex::Start => return Err(invalid("topology route loops to its source")),
            }
        }
        if current != end || selected.is_empty() {
            return Err(invalid("topology route exceeded its hop bound"));
        }
        path.check_route(context, &selected)?;
        let mut expires = path.claims().scope.expires_at_ms;
        for peer in &selected {
            let observation = by_peer.get(peer).ok_or_else(|| invalid("topology route lost a relay"))?;
            expires = expires.min(observation.expires_at_ms);
        }
        Ok(Some(RouteCandidate { relays: selected, cursor, expires_at_ms: expires }))
    }

    fn check_context(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        if self.authority != *context.authority_key
            || self.deployment_id != context.deployment_id
            || self.space_id != context.space_id
            || self.policy_epoch != context.policy_epoch
        {
            return Err(ContractError::new(ErrorCode::PolicyRevoked, "topology graph scope or authority changed"));
        }
        if context.now_ms < self.last_observed_ms {
            return Err(replay("topology graph clock went backward"));
        }
        Ok(())
    }
    fn expire_inner(&mut self, context: &NetworkVerification<'_>) {
        let expired: Vec<_> = self.live.iter().filter(|(_, observation)| {
            context.now_ms >= observation.expires_at_ms
                || observation.publication_grant_ids.iter().any(|id| context.revoked_grant_ids.contains(id))
        }).map(|(node, _)| node.clone()).collect();
        for node in expired {
            self.live.remove(&node);
            if let Some(water) = self.high_water.get_mut(&node) {
                water.withdrawn = true;
            }
        }
    }
    fn upsert(
        &mut self,
        context: &NetworkVerification<'_>,
        signed: &SignedTopologyAdvertisement,
        proofs: &BTreeMap<[u8; 32], &VerifiedTopologyAdvertisement>,
        used: &mut BTreeSet<[u8; 32]>,
        allow_advance: bool,
    ) -> Result<(), ContractError> {
        let claims = TopologyAdvertisement::decode_canonical(&signed.claims)?;
        let fingerprint = digest(&signed.canonical_bytes()?);
        let proof = proofs.get(&fingerprint).copied();
        if proof.is_some() {
            used.insert(fingerprint);
        }
        let advanced = self.advance(
            &claims.report.node_id,
            HighWater {
                peer: claims.report.peer,
                incarnation: claims.report.incarnation.clone(),
                sequence: claims.report.sequence,
                publisher_digest: claims.report.publisher_digest,
                envelope_digest: Some(fingerprint),
                withdrawn: false,
            },
            context.now_ms >= claims.expires_at_ms,
        )?;
        if advanced && !allow_advance {
            return Err(replay("unchanged topology cursor introduced new observations"));
        }
        if context.now_ms >= claims.expires_at_ms {
            // The current batch authenticates this historical record, but it
            // provides no live publisher, adjacency or prefix permission.
            self.live.remove(&claims.report.node_id);
            if let Some(water) = self.high_water.get_mut(&claims.report.node_id) {
                water.withdrawn = true;
            }
            return Ok(());
        }
        let proof = proof.ok_or_else(|| invalid("live topology upsert lacks its exact verified envelope"))?;
        proof.check_current(context)?;
        if proof.claims() != &claims {
            return Err(invalid("topology envelope proof claims differ"));
        }
        self.live.insert(claims.report.node_id.clone(), Observation {
            report: claims.report,
            expires_at_ms: claims.expires_at_ms,
            publication_grant_ids: proof.publication_grant_ids(),
            statement_bytes: signed.claims.len().checked_add(signed.signature.len())
                .ok_or_else(|| capacity("topology byte accounting overflow"))?,
        });
        Ok(())
    }
    fn withdraw(&mut self, withdrawal: &TopologyWithdrawal) -> Result<(), ContractError> {
        self.advance(&withdrawal.node_id, HighWater {
            peer: withdrawal.peer,
            incarnation: withdrawal.incarnation.clone(),
            sequence: withdrawal.sequence,
            publisher_digest: withdrawal.publisher_digest,
            envelope_digest: None,
            withdrawn: true,
        }, false)?;
        self.live.remove(&withdrawal.node_id);
        Ok(())
    }
    fn advance(&mut self, node: &str, next: HighWater, historical: bool) -> Result<bool, ContractError> {
        if self.high_water.iter().any(|(id, water)| id != node && water.peer == next.peer) {
            return Err(invalid("topology peer aliases another registered node"));
        }
        if let Some(previous) = self.high_water.get(node) {
            if previous.peer != next.peer {
                return Err(invalid("topology registered node identity changed"));
            }
            if next.incarnation.runtime_generation < previous.incarnation.runtime_generation {
                return Err(replay("old topology boot incarnation"));
            }
            if next.incarnation.runtime_generation == previous.incarnation.runtime_generation {
                if next.incarnation.runtime_id != previous.incarnation.runtime_id {
                    return Err(replay("topology boot UUID changed without a new generation"));
                }
                if next.sequence < previous.sequence {
                    return Err(replay("old topology report sequence"));
                }
                if next.sequence == previous.sequence {
                    if next.publisher_digest != previous.publisher_digest {
                        return Err(replay("same topology sequence has another publisher"));
                    }
                    if next.withdrawn {
                        let changed = !previous.withdrawn;
                        if let Some(previous) = self.high_water.get_mut(node) {
                            previous.withdrawn = true;
                        }
                        return Ok(changed);
                    }
                    if previous.envelope_digest != next.envelope_digest
                        || (previous.withdrawn && !historical)
                    {
                        return Err(replay("topology sequence changed content or was withdrawn"));
                    }
                    // An exact, already expired journal envelope can precede
                    // its withdrawal in the next delta page. It only confirms
                    // the retained fence and cannot restore a live report.
                    return Ok(false);
                }
            }
        }
        self.high_water.insert(node.into(), next);
        Ok(true)
    }
    fn enforce_limits(&self) -> Result<(), ContractError> {
        if self.live.len() > MAX_GRAPH_NODES || self.high_water.len() > MAX_GRAPH_NODES {
            return Err(capacity("topology graph publisher budget exceeded"));
        }
        let mut edges = 0usize;
        let mut bytes = 0usize;
        for observation in self.live.values() {
            edges = edges.checked_add(observation.report.neighbors.len()).ok_or_else(|| capacity("topology edge accounting overflow"))?;
            bytes = bytes.checked_add(observation.statement_bytes).ok_or_else(|| capacity("topology byte accounting overflow"))?;
            for id in &observation.publication_grant_ids {
                bytes = bytes.checked_add(id.len()).ok_or_else(|| capacity("topology byte accounting overflow"))?;
            }
        }
        for (node, water) in &self.high_water {
            let metadata = node.len() + water.incarnation.runtime_id.len() + 32 * 3 + 8 * 2 + 1;
            bytes = bytes.checked_add(metadata).ok_or_else(|| capacity("topology byte accounting overflow"))?;
        }
        if edges > MAX_GRAPH_EDGES || bytes > MAX_GRAPH_BYTES {
            return Err(capacity("topology graph edge or byte budget exceeded"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Vertex {
    Start,
    Relay(PeerId, u8),
    End,
}
fn mutually_observed(observations: &BTreeMap<PeerId, &Observation>, first: PeerId, second: PeerId) -> bool {
    let (Some(a), Some(b)) = (observations.get(&first), observations.get(&second)) else {
        return false;
    };
    let (Some(ab), Some(ba)) = (
        a.report.neighbors.iter().find(|edge| edge.remote == second && edge.up),
        b.report.neighbors.iter().find(|edge| edge.remote == first && edge.up),
    ) else {
        return false;
    };
    ab.local_endpoint_revision == ba.remote_endpoint_revision
        && ab.remote_endpoint_revision == ba.local_endpoint_revision
}
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
fn replay(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::ReplayRejected, reason)
}
fn capacity(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::CapacityExceeded, reason)
}
