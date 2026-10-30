//! Active resource authority, endpoint possession and aggregate queue budgets.
use super::*;
use nestlink_identity::{
    digest,
    node_resources::verify_resource_snapshot,
    relay::{allocation_binding, node_relay_transcript, verify_relay_allocation},
    verify_device_action,
};
use nestlink_protocol::{
    NODE_RELAY_CLOSE_PENDING, NODE_RESOURCE_MESSAGE_BYTES, NODE_RESOURCE_POLL_MS,
    NODE_RESOURCE_TTL_MS, NodeResourceQueryClaims, NodeResourceSnapshotClaims,
    RelayAllocationClaims, RelayCloseClaims, RelayTransport, SignedNodeResourceSnapshot,
};
use std::collections::{HashMap, HashSet, VecDeque};
mod network;
use nestlink_identity::network::RemoteRouteBinding;

pub struct RelayEndpointProof<'a> {
    pub device_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub transport: RelayTransport,
    pub signature: &'a [u8],
}
/// Possession and current facts have been checked, but no role or forwarding
/// capacity has been committed. A data service coordinates a matching carrier
/// first; commit always rechecks current authority and the original deadline.
pub struct RelayEndpointCandidate {
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    claims: RelayAllocationClaims,
    controller: bool,
    transport: RelayTransport,
    issuer: [u8; 32],
    deadline: u64,
    node_stop: watch::Receiver<bool>,
    network: Option<RemoteRouteBinding>,
}
impl RelayEndpointCandidate {
    pub fn network_binding(&self) -> Option<[u8; 32]> {
        self.network.map(|route| route.digest)
    }
    pub fn network_direction(&self) -> Option<nestlink_protocol::network_datagram::Direction> {
        self.network.map(|route| {
            if self.claims.controller_key_sha256 == route.peers.first.0 {
                if self.controller {
                    nestlink_protocol::network_datagram::Direction::FirstToSecond
                } else {
                    nestlink_protocol::network_datagram::Direction::SecondToFirst
                }
            } else if self.controller {
                nestlink_protocol::network_datagram::Direction::SecondToFirst
            } else {
                nestlink_protocol::network_datagram::Direction::FirstToSecond
            }
        })
    }
    pub fn allocation_id(&self) -> &str {
        &self.claims.allocation_id
    }
    pub fn is_controller(&self) -> bool {
        self.controller
    }
    pub fn transport(&self) -> RelayTransport {
        self.transport
    }
    pub fn reserve(self) -> Result<RelayResourceReservation, Error> {
        self.reserve_at(None)
    }
    fn check_at(&self, state: &mut Runtime, now: ClockSample) -> Result<u64, Error> {
        if !state.ready || *self.node_stop.borrow() {
            return Err(Error::Control);
        }
        let lease = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
        if self.claims.node_key_sha256 != lease.node_key_sha256
            || self.claims.issued_at_unix_ms > now.unix_ms.saturating_add(1000)
            || self.claims.expires_at_unix_ms <= now.unix_ms
            || now.monotonic_ms >= self.deadline
        {
            return Err(error(ErrorCode::LeaseExpired).into());
        }
        state
            .resources
            .inspect(&self.claims, usize::from(!self.controller), now)?;
        let snapshot = state.resources.snapshot.as_ref().ok_or(Error::Control)?;
        if snapshot.claims.allocation_issuer != self.issuer {
            return Err(error(ErrorCode::IdentityMismatch).into());
        }
        let entry = snapshot
            .entries
            .get(self.allocation_id())
            .ok_or(Error::Control)?;
        if entry.network != self.network {
            return Err(error(ErrorCode::IdentityMismatch).into());
        }
        Ok(self
            .deadline
            .min(entry.deadline)
            .min(snapshot.deadline)
            .min(state.gate.deadline()))
    }
    /// A detached validity waiter grants no authority. Pending data sockets use
    /// it alongside EOF and a bounded pairing timeout; commit still rechecks.
    pub fn wait_stopped(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut pending = Self {
            state: self.state.clone(),
            started: self.started,
            claims: self.claims.clone(),
            controller: self.controller,
            transport: self.transport,
            issuer: self.issuer,
            deadline: self.deadline,
            node_stop: self.node_stop.clone(),
            network: self.network,
        };
        async move {
            loop {
                let deadline = (|| {
                    let mut state = pending.state.lock().map_err(|_| Error::Control)?;
                    pending.check_at(&mut state, sample(pending.started)?)
                })();
                let Ok(deadline) = deadline else {
                    return;
                };
                let Some(until) = pending.started.checked_add(Duration::from_millis(deadline))
                else {
                    return;
                };
                tokio::select! { biased;
                    changed = pending.node_stop.changed() => { if changed.is_err() { return; } },
                    _ = tokio::time::sleep_until(until.into()) => {},
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {},
                }
            }
        }
    }
    fn reserve_at(self, clock: Option<ClockSample>) -> Result<RelayResourceReservation, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        let now = match clock {
            Some(now) => now,
            None => sample(self.started)?,
        };
        self.check_at(&mut state, now)?;
        let lease = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?
            .clone();
        let c = &self.claims;
        let mut meter = state.meter.clone();
        meter.reserve(lease.max_connections)?;
        let (token, resource_stop) =
            state
                .resources
                .reserve(c, usize::from(!self.controller), now)?;
        state.meter = meter;
        Ok(RelayResourceReservation {
            state: self.state.clone(),
            started: self.started,
            allocation_id: c.allocation_id.clone(),
            token,
            controller: self.controller,
            resource_stop,
            node_stop: self.node_stop.clone(),
            io_stopped: false,
            io_deferred: false,
        })
    }
}
pub struct RelayResourceReservation {
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    allocation_id: String,
    token: String,
    controller: bool,
    resource_stop: watch::Receiver<bool>,
    node_stop: watch::Receiver<bool>,
    io_stopped: bool,
    io_deferred: bool,
}
/// Holds only a cleanup witness. Dropping or cancelling it cannot refund a
/// promise; the resource and aggregate counters have already stopped once.
pub struct RelayIoCleanup {
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    allocation_id: String,
    token: String,
    confirmed: bool,
}
impl RelayIoCleanup {
    pub fn confirm_stopped(mut self) {
        self.confirmed = true;
    }
}
impl Drop for RelayIoCleanup {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            let now = self
                .confirmed
                .then(|| sample(self.started).ok().map(|s| s.unix_ms))
                .flatten();
            state
                .resources
                .complete_io(&self.allocation_id, &self.token, now);
        }
    }
}
impl RelayResourceReservation {
    /// Stop the resource immediately, then wait for a carrier's asynchronous
    /// I/O drain. No receipt can be produced until the returned witness confirms
    /// that drain; cancelling the wait preserves the original capacity promise.
    pub fn defer_io_confirmation(mut self) -> RelayIoCleanup {
        self.io_deferred = true;
        RelayIoCleanup {
            state: self.state.clone(),
            started: self.started,
            allocation_id: self.allocation_id.clone(),
            token: self.token.clone(),
            confirmed: false,
        }
    }
    /// The data service calls this only after dropping every owned reader,
    /// writer and queue and synchronously closing its carrier. Unconfirmed
    /// destruction stops authority but cannot produce a capacity-release fact.
    pub fn confirm_io_stopped(&mut self) {
        self.io_stopped = true;
    }
    pub fn allocation_id(&self) -> &str {
        &self.allocation_id
    }
    pub fn is_controller(&self) -> bool {
        self.controller
    }
    /// I/O must select this future alongside its reader and writer, including idle waits.
    pub async fn wait_stopped(&self) {
        let mut resource = self.resource_stop.clone();
        let mut node = self.node_stop.clone();
        loop {
            if *resource.borrow() || *node.borrow() {
                return;
            }
            let Ok(deadline) = self.live_deadline() else {
                return;
            };
            tokio::select! {biased;
                changed=node.changed()=>{if changed.is_err(){return;}},
                changed=resource.changed()=>{if changed.is_err(){return;}},
                _=tokio::time::sleep_until(deadline.into())=>{},
            }
        }
    }
    /// Recheck before writing an already-admitted frame, without charging twice.
    pub fn check_live(&self) -> Result<(), Error> {
        self.live_deadline().map(|_| ())
    }
    fn live_deadline(&self) -> Result<Instant, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.node_stop.borrow() || *self.resource_stop.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
        let node_deadline = state.gate.deadline();
        let resource_deadline =
            state
                .resources
                .live_deadline(&self.allocation_id, &self.token, now)?;
        self.started
            .checked_add(Duration::from_millis(node_deadline.min(resource_deadline)))
            .ok_or(Error::Control)
    }
    /// The enqueue callback must be synchronous and bounded, and must not reenter
    /// node control. Only successful queue admission is counted, not delivery.
    pub fn admit<T>(
        &self,
        bytes: u64,
        enqueue: impl FnOnce() -> Result<T, ContractError>,
    ) -> Result<T, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.node_stop.borrow() || *self.resource_stop.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        let rate = state
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?
            .bytes_per_second;
        state.resources.expire(now);
        let Runtime {
            meter, resources, ..
        } = &mut *state;
        Ok(meter.admit(bytes, rate, now.monotonic_ms, || {
            resources.admit(&self.allocation_id, &self.token, bytes, now, enqueue)
        })?)
    }
}

#[cfg(test)]
mod tests;
impl Drop for RelayResourceReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && state.resources.close_after_io(
                &self.allocation_id,
                &self.token,
                self.io_stopped
                    .then(|| sample(self.started).ok().map(|s| s.unix_ms))
                    .flatten(),
                self.io_deferred,
            )
        {
            state.meter.close();
        }
    }
}
impl NodeControl {
    pub fn resource_snapshot(&self) -> Result<NodeResourceSnapshotClaims, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        state.gate.check_live(now)?;
        state.resources.expire(now);
        Ok(state
            .resources
            .snapshot
            .as_ref()
            .ok_or(Error::Control)?
            .claims
            .clone())
    }
    /// `challenge` is generated by the data service for this socket and expires
    /// before admission. The original verified ticket and endpoint key are mandatory.
    pub fn reserve_relay_endpoint(
        &self,
        ticket: &[u8],
        proof: RelayEndpointProof<'_>,
        challenge: &[u8; 32],
    ) -> Result<RelayResourceReservation, Error> {
        self.prepare_relay_endpoint(ticket, proof, challenge)?
            .reserve()
    }
    /// Preparation grants no forwarding and consumes no meter slot or bytes.
    pub fn prepare_relay_endpoint(
        &self,
        ticket: &[u8],
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
        let issuer: [u8; 32] = snapshot
            .claims
            .allocation_issuer
            .clone()
            .try_into()
            .map_err(|_| Error::Control)?;
        let ticket = verify_relay_allocation(ticket, &issuer)?;
        let c = ticket.claims();
        if snapshot
            .entries
            .get(&c.allocation_id)
            .is_some_and(|entry| entry.network.is_some())
        {
            return Err(error(ErrorCode::PermissionRequired).into());
        }
        if c.node_key_sha256 != lease.node_key_sha256
            || c.issued_at_unix_ms > now.unix_ms.saturating_add(1000)
            || c.expires_at_unix_ms <= now.unix_ms
        {
            return Err(error(ErrorCode::LeaseExpired).into());
        }
        let role = if proof.device_id == c.controller_device_id {
            0
        } else if proof.device_id == c.host_device_id {
            1
        } else {
            return Err(error(ErrorCode::IdentityMismatch).into());
        };
        let expected_key = if role == 0 {
            &c.controller_key_sha256
        } else {
            &c.host_key_sha256
        };
        if expected_key != &digest(proof.public_key) {
            return Err(error(ErrorCode::IdentityMismatch).into());
        }
        verify_device_action(
            &node_relay_transcript(c, proof.device_id, proof.transport, challenge)?,
            proof.public_key,
            proof.signature,
        )?;
        state.resources.inspect(c, role, now)?;
        let ticket_deadline = deadline(
            now.monotonic_ms,
            c.expires_at_unix_ms,
            c.expires_at_unix_ms - c.issued_at_unix_ms,
            now,
        )?;
        let original_deadline = ticket_deadline.min(
            state
                .resources
                .snapshot
                .as_ref()
                .and_then(|s| s.entries.get(&c.allocation_id))
                .ok_or(Error::Control)?
                .deadline,
        );
        Ok(RelayEndpointCandidate {
            state: self.state.clone(),
            started: self.started,
            claims: c.clone(),
            controller: role == 0,
            transport: proof.transport,
            issuer,
            deadline: original_deadline,
            node_stop: self.stopped.clone(),
            network: None,
        })
    }
}
struct Entry {
    claims: RelayAllocationClaims,
    deadline: u64,
    binding: [u8; 32],
    network: Option<RemoteRouteBinding>,
    network_credential: Option<[u8; 32]>,
}
struct Snapshot {
    claims: NodeResourceSnapshotClaims,
    deadline: u64,
    entries: HashMap<String, Entry>,
}
struct Slot {
    token: String,
    stop: watch::Sender<bool>,
}
struct Pair {
    claims: RelayAllocationClaims,
    deadline: u64,
    binding: [u8; 32],
    network: Option<RemoteRouteBinding>,
    slots: [Option<Slot>; 2],
    meter: Meter,
    closed: bool,
    unconfirmed_io: bool,
    io_drains: HashSet<String>,
}
impl Pair {
    fn stop(&mut self) {
        self.closed = true;
        for slot in self.slots.iter().flatten() {
            slot.stop.send_replace(true);
        }
    }
}
#[derive(Default)]
pub(super) struct Resources {
    pub(super) services: crate::service_plane::ServiceResourceSet,
    snapshot: Option<Snapshot>,
    last_sequence: u64,
    pairs: HashMap<String, Pair>,
    seen: HashSet<String>,
    pub(super) pending_closes: VecDeque<super::closes::PendingClose>,
    pub(super) acknowledged_closes: u64,
    #[cfg(test)]
    network_chain_verifications: u64,
}
fn error(code: ErrorCode) -> ContractError {
    ContractError::new(code, "node resource authority unavailable")
}
fn deadline(
    start: u64,
    expires: u64,
    lifetime: u64,
    now: ClockSample,
) -> Result<u64, ContractError> {
    let remaining = expires
        .checked_sub(now.unix_ms)
        .filter(|n| *n > 0)
        .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
    start
        .checked_add(remaining.min(lifetime))
        .filter(|n| *n > now.monotonic_ms)
        .ok_or_else(|| error(ErrorCode::LeaseExpired))
}
impl Resources {
    pub(super) fn stop(&mut self) {
        self.snapshot = None;
        for pair in self.pairs.values_mut() {
            pair.stop();
        }
    }
    pub(super) fn expire(&mut self, now: ClockSample) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|s| now.monotonic_ms >= s.deadline)
        {
            self.stop();
        }
        for pair in self.pairs.values_mut() {
            if now.monotonic_ms >= pair.deadline {
                pair.stop();
            }
        }
    }
    fn accept(
        &mut self,
        c: NodeResourceSnapshotClaims,
        lease: &NodeLeaseClaims,
        start: u64,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        c.validate()?;
        self.expire(now);
        let q = c
            .query
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidMessage))?;
        if start > now.monotonic_ms
            || q.request_sequence <= self.last_sequence
            || q.deployment_id != lease.deployment_id
            || q.security_epoch != lease.security_epoch
            || q.node_id != lease.node_id
            || q.runtime_id != lease.runtime_id
            || q.runtime_generation != lease.runtime_generation
            || q.policy_revision != lease.policy_revision
            || q.lease_sequence > lease.lease_sequence
            || c.issued_at_unix_ms > now.unix_ms.saturating_add(1000)
        {
            return Err(error(ErrorCode::IdentityMismatch));
        }
        let snapshot_deadline = deadline(start, c.expires_at_unix_ms, NODE_RESOURCE_TTL_MS, now)?;
        if self.snapshot.as_ref().is_some_and(|s| {
            s.claims.allocation_issuer != c.allocation_issuer
                || s.claims.quota_revision != c.quota_revision
        }) {
            self.stop();
        }
        let mut entries = HashMap::new();
        let issuer: [u8; 32] = c
            .allocation_issuer
            .as_slice()
            .try_into()
            .map_err(|_| error(ErrorCode::IdentityMismatch))?;
        let mut routes = HashMap::new();
        for resource in &c.network_routes {
            let grant = resource
                .allocation
                .as_ref()
                .ok_or_else(|| error(ErrorCode::InvalidMessage))?;
            let credential = digest(&resource.encode_to_vec());
            // The fresh, exact-query signed snapshot still authorizes this
            // complete resource. Reuse only an identical chain from the live
            // previous snapshot under the same issuer and quota revision.
            // No detached cache can outlive snapshot expiry, omission, stop or
            // a changed credential; the original allocation deadline below is
            // retained independently of fresh observation time.
            let cached = self.snapshot.as_ref().and_then(|snapshot| {
                if snapshot.claims.allocation_issuer != c.allocation_issuer
                    || snapshot.claims.quota_revision != c.quota_revision
                {
                    return None;
                }
                snapshot.entries.get(&grant.allocation_id).and_then(|entry| {
                    entry.network.filter(|route| {
                        entry.network_credential == Some(credential)
                            && entry.claims == *grant
                            && now.monotonic_ms < entry.deadline
                            && now.unix_ms < route.expires_at_ms
                    })
                })
            });
            let route = match cached {
                Some(route) => route,
                None => {
                    #[cfg(test)]
                    {
                        self.network_chain_verifications += 1;
                    }
                    nestlink_identity::network::verify_node_network_resource(
                        resource,
                        &issuer,
                        now.unix_ms,
                    )?
                }
            };
            routes.insert(
                grant.allocation_id.clone(),
                (route, credential),
            );
        }
        for grant in c.allocations.iter().chain(
            c.network_routes
                .iter()
                .filter_map(|resource| resource.allocation.as_ref()),
        ) {
            if grant.node_key_sha256 != lease.node_key_sha256 {
                return Err(error(ErrorCode::IdentityMismatch));
            }
            let binding = allocation_binding(grant)?;
            let route = routes.get(&grant.allocation_id);
            let network = route.map(|(route, _)| *route);
            let network_credential = route.map(|(_, credential)| *credential);
            let mut expires = deadline(
                start,
                grant.expires_at_unix_ms,
                grant.expires_at_unix_ms - grant.issued_at_unix_ms,
                now,
            )?;
            if let Some(old) = self
                .snapshot
                .as_ref()
                .and_then(|s| s.entries.get(&grant.allocation_id))
            {
                if grant.grant_sequence < old.claims.grant_sequence
                    || (grant.grant_sequence == old.claims.grant_sequence && grant != &old.claims)
                    || old.binding != binding
                    || old.network != network
                    || old.network_credential != network_credential
                {
                    return Err(error(ErrorCode::ReplayRejected));
                }
                if grant.grant_sequence == old.claims.grant_sequence {
                    expires = old.deadline;
                }
            }
            entries.insert(
                grant.allocation_id.clone(),
                Entry {
                    claims: grant.clone(),
                    deadline: expires,
                    binding,
                    network,
                    network_credential,
                },
            );
        }
        for (id, pair) in &mut self.pairs {
            match entries.get(id) {
                Some(entry)
                    if !pair.closed
                        && pair.binding == entry.binding
                        && pair.network == entry.network
                        && entry.claims.grant_sequence >= pair.claims.grant_sequence
                        && now.monotonic_ms < pair.deadline =>
                {
                    if entry.claims.grant_sequence > pair.claims.grant_sequence {
                        pair.deadline = entry.deadline;
                        pair.claims = entry.claims.clone();
                    }
                    // Wake data-service timers when a fresh snapshot or grant
                    // changes the earliest stop boundary. False is a live update.
                    for slot in pair.slots.iter().flatten() {
                        slot.stop.send_replace(false);
                    }
                }
                _ => pair.stop(),
            }
        }
        self.last_sequence = q.request_sequence;
        self.snapshot = Some(Snapshot {
            claims: c,
            deadline: snapshot_deadline,
            entries,
        });
        Ok(())
    }
    fn reserve(
        &mut self,
        ticket: &RelayAllocationClaims,
        role: usize,
        now: ClockSample,
    ) -> Result<(String, watch::Receiver<bool>), ContractError> {
        self.inspect(ticket, role, now)?;
        let entry = self
            .snapshot
            .as_ref()
            .and_then(|s| s.entries.get(&ticket.allocation_id))
            .ok_or_else(|| error(ErrorCode::PermissionRequired))?;
        if !self.pairs.contains_key(&ticket.allocation_id) {
            self.pairs.insert(
                ticket.allocation_id.clone(),
                Pair {
                    claims: entry.claims.clone(),
                    deadline: entry.deadline,
                    binding: entry.binding,
                    network: entry.network,
                    slots: [None, None],
                    meter: Meter::default(),
                    closed: false,
                    unconfirmed_io: false,
                    io_drains: HashSet::new(),
                },
            );
            self.seen.insert(ticket.allocation_id.clone());
        }
        let pair = self
            .pairs
            .get_mut(&ticket.allocation_id)
            .ok_or_else(|| error(ErrorCode::PermissionRequired))?;
        pair.meter.reserve(2)?;
        let token = uuid::Uuid::new_v4().hyphenated().to_string();
        let (stop, stopped) = watch::channel(false);
        pair.slots[role] = Some(Slot {
            token: token.clone(),
            stop,
        });
        Ok((token, stopped))
    }
    fn inspect(
        &mut self,
        ticket: &RelayAllocationClaims,
        role: usize,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        self.expire(now);
        let entry = self
            .snapshot
            .as_ref()
            .and_then(|s| s.entries.get(&ticket.allocation_id))
            .ok_or_else(|| error(ErrorCode::PermissionRequired))?;
        if entry.binding != allocation_binding(ticket)?
            || ticket.grant_sequence > entry.claims.grant_sequence
            || now.monotonic_ms >= entry.deadline
        {
            return Err(error(ErrorCode::LeaseExpired));
        }
        match self.pairs.get(&ticket.allocation_id) {
            Some(pair) if pair.closed || pair.slots[role].is_some() => {
                Err(error(ErrorCode::ReplayRejected))
            }
            None if self.seen.contains(&ticket.allocation_id) || self.seen.len() >= 65536 => {
                Err(error(ErrorCode::ReplayRejected))
            }
            None if self.pairs.len() + self.pending_closes.len()
                >= NODE_RELAY_CLOSE_PENDING as usize =>
            {
                Err(error(ErrorCode::CapacityExceeded))
            }
            _ => Ok(()),
        }
    }
    #[cfg(test)]
    fn close(&mut self, id: &str, token: &str) -> bool {
        self.close_after_io(id, token, None, false)
    }
    fn close_after_io(
        &mut self,
        id: &str,
        token: &str,
        stopped_at: Option<u64>,
        deferred: bool,
    ) -> bool {
        let Some(pair) = self.pairs.get_mut(id) else {
            return false;
        };
        let Some(role) = pair
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.token == token))
        else {
            return false;
        };
        pair.stop();
        if deferred {
            pair.io_drains.insert(token.to_owned());
        } else {
            pair.unconfirmed_io |= stopped_at.is_none();
        }
        pair.slots[role] = None;
        pair.meter.close();
        self.finish_pair(id, stopped_at);
        true
    }
    fn complete_io(&mut self, id: &str, token: &str, stopped_at: Option<u64>) {
        if let Some(pair) = self.pairs.get_mut(id)
            && pair.io_drains.remove(token)
        {
            pair.unconfirmed_io |= stopped_at.is_none();
            self.finish_pair(id, stopped_at);
        }
    }
    fn finish_pair(&mut self, id: &str, stopped_at: Option<u64>) {
        if self
            .pairs
            .get(id)
            .is_some_and(|pair| pair.slots.iter().all(Option::is_none) && pair.io_drains.is_empty())
            && let Some(pair) = self.pairs.remove(id)
            && pair.network.is_none()
            && !pair.unconfirmed_io
            && let Some(closed_at_unix_ms) = stopped_at
        {
            let grant = pair.claims;
            let counters = pair.meter.counters();
            let claims = RelayCloseClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: grant.deployment_id,
                security_epoch: grant.security_epoch,
                node_id: grant.node_id,
                runtime_id: grant.runtime_id,
                runtime_generation: grant.runtime_generation,
                allocation_id: grant.allocation_id,
                allocation_binding_sha256: pair.binding.to_vec(),
                observed_grant_sequence: grant.grant_sequence,
                opened_connections: counters.opened_connections,
                closed_connections: counters.closed_connections,
                admitted_bytes: counters.admitted_bytes,
                closed_at_unix_ms,
            };
            // Admission reserved one slot for this pair. Moving it to
            // pending preserves the combined bound, including failed ACKs.
            self.pending_closes.push_back(super::closes::PendingClose {
                claims,
                signed: None,
            });
        }
    }
    pub(super) fn active_pairs(&self) -> usize {
        self.pairs.len()
    }
    fn admit<T>(
        &mut self,
        id: &str,
        token: &str,
        bytes: u64,
        now: ClockSample,
        enqueue: impl FnOnce() -> Result<T, ContractError>,
    ) -> Result<T, ContractError> {
        self.expire(now);
        if self.snapshot.is_none() {
            return Err(error(ErrorCode::LeaseExpired));
        }
        let pair = self
            .pairs
            .get_mut(id)
            .ok_or_else(|| error(ErrorCode::PermissionRequired))?;
        if pair.closed || !pair.slots.iter().flatten().any(|s| s.token == token) {
            return Err(error(ErrorCode::PolicyRevoked));
        }
        if pair
            .meter
            .counters()
            .admitted_bytes
            .checked_add(bytes)
            .is_none_or(|n| n > pair.claims.bytes_per_allocation)
        {
            return Err(error(ErrorCode::CapacityExceeded));
        }
        pair.meter.admit(
            bytes,
            pair.claims.bytes_per_second,
            now.monotonic_ms,
            enqueue,
        )
    }
    fn live_deadline(
        &mut self,
        id: &str,
        token: &str,
        now: ClockSample,
    ) -> Result<u64, ContractError> {
        self.expire(now);
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
        let pair = self
            .pairs
            .get(id)
            .ok_or_else(|| error(ErrorCode::PermissionRequired))?;
        if pair.closed || !pair.slots.iter().flatten().any(|s| s.token == token) {
            return Err(error(ErrorCode::PolicyRevoked));
        }
        Ok(snapshot.deadline.min(pair.deadline))
    }
}
pub(super) async fn poll(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    state: Arc<Mutex<Runtime>>,
    started: Instant,
) -> Result<(), Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let url = format!(
        "{}/api/v3/nodes/{}/resources",
        config.control_origin, config.node_id
    );
    let issuer = config.issuer()?;
    let mut sequence = 0u64;
    let mut tick = tokio::time::interval(Duration::from_millis(NODE_RESOURCE_POLL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let query = {
            let mut runtime = state.lock().map_err(|_| Error::Control)?;
            if !runtime.ready {
                continue;
            }
            let now = sample(started)?;
            let lease = runtime.gate.current(now)?.clone();
            sequence = sequence
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Error::Control)?;
            NodeResourceQueryClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: lease.deployment_id,
                security_epoch: lease.security_epoch,
                node_id: lease.node_id,
                runtime_id: lease.runtime_id,
                runtime_generation: lease.runtime_generation,
                policy_revision: lease.policy_revision,
                lease_sequence: lease.lease_sequence,
                request_id: uuid::Uuid::new_v4().hyphenated().to_string(),
                request_sequence: sequence,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now
                    .unix_ms
                    .checked_add(NODE_RESOURCE_TTL_MS)
                    .ok_or(Error::Control)?
                    .min(lease.expires_at_unix_ms),
            }
        };
        let signed = identity.sign_resource_query(&query)?;
        let request_start = sample(started)?.monotonic_ms;
        let response = tokio::time::timeout(Duration::from_millis(700), async {
            let response = client
                .post(&url)
                .json(&signed)
                .send()
                .await
                .map_err(|_| Error::Control)?;
            if !response.status().is_success() {
                return Err(Error::Control);
            }
            let mut chunks = response.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|_| Error::Control)?;
                if bytes.len() + chunk.len() > (NODE_RESOURCE_MESSAGE_BYTES * 4 + 512) as usize {
                    return Err(Error::Control);
                }
                bytes.extend_from_slice(&chunk);
            }
            let response: SignedNodeResourceSnapshot =
                serde_json::from_slice(&bytes).map_err(|_| Error::Control)?;
            Ok::<_, Error>(verify_resource_snapshot(&response, &issuer, &signed)?)
        })
        .await;
        let mut runtime = state.lock().map_err(|_| Error::Control)?;
        let now = sample(started)?;
        match response {
            Ok(Ok(c)) => {
                let lease = runtime.gate.current(now)?.clone();
                if runtime
                    .resources
                    .accept(c, &lease, request_start, now)
                    .is_err()
                {
                    runtime.resources.stop();
                }
            }
            _ => runtime.resources.stop(),
        }
    }
}
