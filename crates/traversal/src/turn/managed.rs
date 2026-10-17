//! Runtime TURN grants consumed only after the node has verified a signed
//! TURN resource snapshot.  This registry is deliberately separate from the
//! native relay-pair resource guard.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::Instant,
};
use zeroize::Zeroize;

const MAX_GRANTS: usize = 4096;
const MAX_PEERS: usize = 64;
const MAX_TOKEN_BYTES: usize = 128;
const ALLOCATION_UNUSED: u8 = 0;
const ALLOCATION_PENDING: u8 = 1;
const ALLOCATION_OPEN: u8 = 2;
const ALLOCATION_CLOSED: u8 = 3;
const ALLOCATION_REVOKED: u8 = 4;

/// TURN is currently issued only for a browser WebRTC session. The explicit
/// purpose is part of the verified grant so a native relay ticket cannot be
/// repurposed as TURN authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnPurpose {
    BrowserWebRtc,
}

/// A forwarding operation checked by the managed TURN policy at its final
/// protocol boundary. Peer-bearing operations require an exact paired endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnAction {
    Refresh,
    CreatePermission,
    ChannelBind,
    SendIndication,
    ChannelData,
    RelayToClient,
}

/// A TURN-specific grant prepared from an authenticated control-plane
/// snapshot. The `auth_key` is the RFC 5389 long-term credential key for the
/// deployment realm; clients receive their own username/password and never
/// receive this derived key. `deadline` is the monotonic deadline computed by
/// NodeControl while it verifies the signed lease and resource snapshot.
pub struct TurnAllocationGrant {
    pub deployment_id: String,
    pub node_id: String,
    pub runtime_id: String,
    pub allocation_id: String,
    pub session_id: String,
    pub temporary_identity: String,
    pub purpose: TurnPurpose,
    pub generation: u64,
    pub connection_generation: u64,
    /// Resource revision advances for every change to the signed allocation,
    /// including node lease extensions that leave the session lease unchanged.
    pub grant_sequence: u64,
    /// Monotonic remote-session lease revision. This may remain unchanged
    /// while `grant_sequence` advances to extend node-side authority.
    pub lease_sequence: u64,
    pub node_key_sha256: [u8; 32],
    pub device_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub controller_key_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub permit_sha256: [u8; 32],
    pub session_binding_sha256: [u8; 32],
    pub policy_revision: u64,
    pub quota_revision: u64,
    pub endpoint_revision: u64,
    pub username: String,
    pub realm: String,
    pub auth_key: [u8; 16],
    pub peer_allowlist: Vec<SocketAddr>,
    pub max_peers: usize,
    pub expires_at_unix_ms: u64,
    pub deadline: Instant,
    pub max_total_bytes: u64,
    pub max_bytes_per_second: u64,
}

/// Exact endpoints admitted after NodeControl verifies both peer signatures.
/// Callers must not construct this binding from untrusted TURN packet data.
#[derive(Clone, Copy, Debug)]
pub struct TurnPeerActivation<'a> {
    pub allocation_id: &'a str,
    pub session_id: &'a str,
    pub temporary_identity: &'a str,
    pub generation: u64,
    pub connection_generation: u64,
    pub grant_sequence: u64,
    pub lease_sequence: u64,
    pub peers: &'a [SocketAddr],
}

/// A peer binding whose signatures and claims have been verified by
/// NodeControl. The deadline is monotonic and derived from the signed
/// `issued_at`/`expires_at` interval at the start of the control request.
#[derive(Clone, Copy, Debug)]
pub struct TurnPeerBindingActivation<'a> {
    pub allocation_id: &'a str,
    pub session_id: &'a str,
    pub temporary_identity: &'a str,
    pub generation: u64,
    pub connection_generation: u64,
    pub grant_sequence: u64,
    pub lease_sequence: u64,
    pub binding_sha256: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub deadline: Instant,
    pub peers: &'a [SocketAddr],
}

impl Drop for TurnAllocationGrant {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnGrantError {
    #[error("TURN grant is malformed or outside its limits")]
    InvalidGrant,
    #[error("TURN authorization registry is full")]
    RegistryFull,
    #[error("TURN allocation id or username is already installed")]
    DuplicateGrant,
    #[error("TURN grant was not found")]
    GrantNotFound,
    #[error("TURN authorization state is poisoned")]
    StateUnavailable,
}

struct Budget {
    total_bytes: u64,
    tokens: u64,
    last_refill: Instant,
}

struct Lease {
    grant_sequence: u64,
    lease_sequence: u64,
    permit_sha256: [u8; 32],
    expires_at_unix_ms: u64,
    deadline: Instant,
}

struct GrantState {
    grant: TurnAllocationGrant,
    lease: Mutex<Lease>,
    /// `None` is the deliberately peerless ICE bootstrap phase. It can gather
    /// TURN candidates, but no peer-bearing operation is authorized until the
    /// two endpoint signatures activate one exact allowlist.
    peers: Mutex<PeerAuthorization>,
    live: AtomicBool,
    allocation: AtomicU8,
    client: Mutex<Option<SocketAddr>>,
    slot_accounted: AtomicBool,
    budget: Mutex<Budget>,
}

#[derive(Default)]
struct PeerAuthorization {
    allowed: Option<HashSet<SocketAddr>>,
    /// Present only while a verified binding is active. It is intentionally
    /// independent of the TURN grant's session lease deadline.
    deadline: Option<Instant>,
    /// Retained after a binding is omitted or expires to reject replay and to
    /// keep repeated snapshots from extending the original monotonic deadline.
    last_binding: Option<PeerBindingWatermark>,
    /// Retained until socket close if service cleanup needs another retry.
    expiry_close_pending: bool,
}

struct PeerBindingWatermark {
    digest: [u8; 32],
    issued_at_unix_ms: u64,
}

impl PeerAuthorization {
    fn clear_active(&mut self) {
        self.allowed = None;
        self.deadline = None;
    }
}

impl GrantState {
    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
            && self
                .lease
                .lock()
                .is_ok_and(|lease| Instant::now() < lease.deadline)
    }

    fn lease_expired(&self, now: Instant) -> bool {
        self.lease
            .lock()
            .map_or(true, |lease| now >= lease.deadline)
    }

    fn charge(&self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let Ok(mut budget) = self.budget.lock() else {
            return false;
        };
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(budget.last_refill);
        let replenished = elapsed
            .as_nanos()
            .saturating_mul(self.grant.max_bytes_per_second as u128)
            / 1_000_000_000;
        budget.tokens = budget
            .tokens
            .saturating_add(replenished.min(u64::MAX as u128) as u64)
            .min(self.grant.max_bytes_per_second);
        budget.last_refill = now;
        let Some(total) = budget.total_bytes.checked_add(bytes) else {
            return false;
        };
        if total > self.grant.max_total_bytes || budget.tokens < bytes {
            return false;
        }
        budget.tokens -= bytes;
        budget.total_bytes = total;
        true
    }
}

struct Registry {
    by_allocation: HashMap<String, Arc<GrantState>>,
    by_username: HashMap<String, Arc<GrantState>>,
}

/// Synchronous grant lookup and per-packet authorization shared by the node
/// control verifier and all TURN listeners. Snapshot verification remains the
/// caller's responsibility; only verified grants should be installed here.
pub struct TurnAuthorization {
    registry: RwLock<Registry>,
    active_allocations: AtomicUsize,
    max_allocations: usize,
}

impl TurnAuthorization {
    /// Creates a bounded registry. The limit counts actual allocations across
    /// UDP, TCP and TLS listeners and is not released until their sockets close.
    pub fn new(max_allocations: usize) -> Result<Self, TurnGrantError> {
        if max_allocations == 0 || max_allocations > MAX_GRANTS {
            return Err(TurnGrantError::InvalidGrant);
        }
        Ok(Self {
            registry: RwLock::new(Registry {
                by_allocation: HashMap::new(),
                by_username: HashMap::new(),
            }),
            active_allocations: AtomicUsize::new(0),
            max_allocations,
        })
    }

    /// Installs one already-verified TURN grant. Allocation ids and usernames
    /// remain reserved through the lease expiry, including after close, so a
    /// replay cannot revive a completed allocation.
    pub fn install_grant(&self, grant: TurnAllocationGrant) -> Result<(), TurnGrantError> {
        validate_grant(&grant)?;
        if Instant::now() >= grant.deadline {
            return Err(TurnGrantError::InvalidGrant);
        }
        let mut registry = self
            .registry
            .write()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        let now = Instant::now();
        let expired = registry
            .by_allocation
            .iter()
            .filter(|(_, state)| {
                !state.slot_accounted.load(Ordering::Acquire) && state.lease_expired(now)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(state) = registry.by_allocation.remove(&id) {
                registry.by_username.remove(&state.grant.username);
            }
        }
        if registry.by_allocation.len() >= MAX_GRANTS {
            return Err(TurnGrantError::RegistryFull);
        }
        if registry.by_allocation.contains_key(&grant.allocation_id)
            || registry.by_username.contains_key(&grant.username)
        {
            return Err(TurnGrantError::DuplicateGrant);
        }
        let peers = PeerAuthorization {
            allowed: (!grant.peer_allowlist.is_empty())
                .then(|| grant.peer_allowlist.iter().copied().collect()),
            ..PeerAuthorization::default()
        };
        let now = Instant::now();
        let state = Arc::new(GrantState {
            budget: Mutex::new(Budget {
                total_bytes: 0,
                tokens: grant.max_bytes_per_second,
                last_refill: now,
            }),
            lease: Mutex::new(Lease {
                grant_sequence: grant.grant_sequence,
                lease_sequence: grant.lease_sequence,
                permit_sha256: grant.permit_sha256,
                expires_at_unix_ms: grant.expires_at_unix_ms,
                deadline: grant.deadline,
            }),
            grant,
            peers: Mutex::new(peers),
            live: AtomicBool::new(true),
            allocation: AtomicU8::new(ALLOCATION_UNUSED),
            client: Mutex::new(None),
            slot_accounted: AtomicBool::new(false),
        });
        registry
            .by_username
            .insert(state.grant.username.clone(), state.clone());
        registry
            .by_allocation
            .insert(state.grant.allocation_id.clone(), state);
        Ok(())
    }

    /// Extends an existing allocation lease using a newer, already-verified
    /// control-plane grant. Immutable authority bindings and quotas must be
    /// identical. The open allocation and its traffic budget are preserved;
    /// closed, revoked, or expired grants can never be revived.
    pub fn renew_grant(&self, grant: TurnAllocationGrant) -> Result<(), TurnGrantError> {
        validate_grant(&grant)?;
        let now = Instant::now();
        if now >= grant.deadline {
            return Err(TurnGrantError::InvalidGrant);
        }
        let registry = self
            .registry
            .write()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        let state = registry
            .by_allocation
            .get(&grant.allocation_id)
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;

        let allocation = state.allocation.load(Ordering::Acquire);
        if !state.live.load(Ordering::Acquire)
            || matches!(allocation, ALLOCATION_CLOSED | ALLOCATION_REVOKED)
            || !same_authority(&state.grant, &grant)
        {
            return Err(TurnGrantError::InvalidGrant);
        }

        let mut lease = state
            .lease
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if now >= lease.deadline
            || grant.grant_sequence <= lease.grant_sequence
            || grant.lease_sequence < lease.lease_sequence
            || (grant.lease_sequence == lease.lease_sequence
                && grant.permit_sha256 != lease.permit_sha256)
            || (grant.lease_sequence > lease.lease_sequence
                && grant.permit_sha256 == lease.permit_sha256)
            || grant.expires_at_unix_ms <= lease.expires_at_unix_ms
            || grant.deadline <= lease.deadline
            || !state.live.load(Ordering::Acquire)
            || matches!(
                state.allocation.load(Ordering::Acquire),
                ALLOCATION_CLOSED | ALLOCATION_REVOKED
            )
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        let session_lease_advanced = grant.lease_sequence > lease.lease_sequence;
        lease.grant_sequence = grant.grant_sequence;
        lease.lease_sequence = grant.lease_sequence;
        lease.permit_sha256 = grant.permit_sha256;
        lease.expires_at_unix_ms = grant.expires_at_unix_ms;
        lease.deadline = grant.deadline;
        if session_lease_advanced {
            let mut peers = state
                .peers
                .lock()
                .map_err(|_| TurnGrantError::StateUnavailable)?;
            if peers
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                peers.expiry_close_pending = true;
            }
            peers.clear_active();
        }
        Ok(())
    }

    /// Activates an initial peerless ICE grant exactly once, after NodeControl
    /// has verified both endpoint signatures over the complete candidate
    /// transcript. This method binds that verification result to every grant
    /// generation field so a valid signature set cannot be replayed for a
    /// different session, connection, grant revision, or lease.
    pub fn activate_peers(&self, activation: TurnPeerActivation<'_>) -> Result<(), TurnGrantError> {
        let state = self
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .by_allocation
            .get(activation.allocation_id)
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;
        if !valid_peer_set(activation.peers, state.grant.max_peers)
            || state.grant.session_id != activation.session_id
            || state.grant.temporary_identity != activation.temporary_identity
            || state.grant.generation != activation.generation
            || state.grant.connection_generation != activation.connection_generation
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        let lease = state
            .lease
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if !state.live.load(Ordering::Acquire)
            || Instant::now() >= lease.deadline
            || lease.grant_sequence != activation.grant_sequence
            || lease.lease_sequence != activation.lease_sequence
            || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        let mut current = state
            .peers
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if current.allowed.is_some()
            || !state.live.load(Ordering::Acquire)
            || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        current.allowed = Some(activation.peers.iter().copied().collect());
        Ok(())
    }

    /// Installs or replaces the current signed peer binding. Repeated claims
    /// keep their first monotonic deadline; a different binding must have a
    /// strictly newer signed issue time. Clearing a binding retains this
    /// ordering watermark so an omitted claim cannot later be replayed.
    pub fn activate_peer_binding(
        &self,
        activation: TurnPeerBindingActivation<'_>,
    ) -> Result<(), TurnGrantError> {
        let state = self
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .by_allocation
            .get(activation.allocation_id)
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;
        if !valid_peer_set(activation.peers, state.grant.max_peers)
            || activation.binding_sha256.iter().all(|byte| *byte == 0)
            || activation.issued_at_unix_ms == 0
            || activation.deadline <= Instant::now()
            || state.grant.session_id != activation.session_id
            || state.grant.temporary_identity != activation.temporary_identity
            || state.grant.generation != activation.generation
            || state.grant.connection_generation != activation.connection_generation
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        let lease = state
            .lease
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if !state.live.load(Ordering::Acquire)
            || Instant::now() >= lease.deadline
            || lease.grant_sequence != activation.grant_sequence
            || lease.lease_sequence != activation.lease_sequence
            || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        let mut current = state
            .peers
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        let now = Instant::now();
        if current.expiry_close_pending {
            return Err(TurnGrantError::InvalidGrant);
        }
        if current.deadline.is_some_and(|deadline| now >= deadline) {
            current.expiry_close_pending = true;
            current.clear_active();
            return Err(TurnGrantError::InvalidGrant);
        }
        if let Some(previous) = &current.last_binding {
            if previous.digest == activation.binding_sha256 {
                // Same claims may be retransmitted while continuously active,
                // but an omitted or expired binding cannot be revived.
                if current.allowed.is_some()
                    && current.deadline.is_some_and(|deadline| now < deadline)
                {
                    return Ok(());
                }
                return Err(TurnGrantError::InvalidGrant);
            }
            if activation.issued_at_unix_ms <= previous.issued_at_unix_ms {
                return Err(TurnGrantError::InvalidGrant);
            }
        }
        if !state.live.load(Ordering::Acquire)
            || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
        {
            return Err(TurnGrantError::InvalidGrant);
        }
        current.allowed = Some(activation.peers.iter().copied().collect());
        current.deadline = Some(activation.deadline);
        current.last_binding = Some(PeerBindingWatermark {
            digest: activation.binding_sha256,
            issued_at_unix_ms: activation.issued_at_unix_ms,
        });
        Ok(())
    }

    /// Removes the active peer allowlist when the signed snapshot no longer
    /// contains its binding. The binding watermark remains to prevent replay.
    pub fn clear_peer_binding(
        &self,
        allocation_id: &str,
        lease_sequence: u64,
    ) -> Result<(), TurnGrantError> {
        let state = self
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .by_allocation
            .get(allocation_id)
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;
        let lease = state
            .lease
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if lease.lease_sequence != lease_sequence {
            return Err(TurnGrantError::InvalidGrant);
        }
        let mut peers = state
            .peers
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        if peers
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            peers.expiry_close_pending = true;
        }
        peers.clear_active();
        Ok(())
    }

    /// Returns the verified TURN long-term auth key only while the matching
    /// grant and current monotonic lease deadline remain live.
    pub fn auth_key(&self, username: &str, realm: &str) -> Option<[u8; 16]> {
        let registry = self.registry.read().ok()?;
        let state = registry.by_username.get(username)?;
        if state.grant.realm != realm || !state.is_live() {
            return None;
        }
        Some(state.grant.auth_key)
    }

    /// Atomically reserves the grant's single allocation and a global capacity
    /// slot. Call `allocation_failed` if socket creation fails, and
    /// `allocation_ready` after the TURN allocation is committed.
    pub fn authorize_allocation(&self, username: &str, realm: &str, client: SocketAddr) -> bool {
        let Some(state) = self.by_username(username) else {
            return false;
        };
        if state.grant.realm != realm || !state.is_live() {
            return false;
        }
        if state
            .allocation
            .compare_exchange(
                ALLOCATION_UNUSED,
                ALLOCATION_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if !self.reserve_slot() {
            state.allocation.store(ALLOCATION_UNUSED, Ordering::Release);
            return false;
        }
        state.slot_accounted.store(true, Ordering::Release);
        if let Ok(mut current) = state.client.lock() {
            *current = Some(client);
        } else {
            state.allocation.store(ALLOCATION_UNUSED, Ordering::Release);
            self.release_slot(&state);
            return false;
        }
        if state.is_live() && state.allocation.load(Ordering::Acquire) == ALLOCATION_PENDING {
            true
        } else {
            self.allocation_failed(username, client);
            false
        }
    }

    /// Commits a successfully created allocation. Revocation or lease expiry
    /// between Allocate admission and socket creation fails closed.
    pub fn allocation_ready(&self, username: &str, client: SocketAddr) -> bool {
        let Some(state) = self.by_username(username) else {
            return false;
        };
        if !state.is_live() || !state.matches_client(client) {
            return false;
        }
        state
            .allocation
            .compare_exchange(
                ALLOCATION_PENDING,
                ALLOCATION_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            && state.is_live()
            && state.allocation.load(Ordering::Acquire) == ALLOCATION_OPEN
    }

    /// Rolls back a pending Allocate after the relay socket could not be bound.
    pub fn allocation_failed(&self, username: &str, client: SocketAddr) {
        let Some(state) = self.by_username(username) else {
            return;
        };
        if !state.matches_client(client) {
            return;
        }
        let allocation = state.allocation.load(Ordering::Acquire);
        if allocation == ALLOCATION_PENDING
            && state
                .allocation
                .compare_exchange(
                    ALLOCATION_PENDING,
                    if state.is_live() {
                        ALLOCATION_UNUSED
                    } else {
                        ALLOCATION_REVOKED
                    },
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            if let Ok(mut current) = state.client.lock() {
                *current = None;
            }
            self.release_slot(&state);
        } else if allocation == ALLOCATION_REVOKED {
            self.release_slot(&state);
        }
    }

    /// Marks the allocation closed after both relay and client sockets close.
    /// Its grant remains as a bounded replay tombstone until its current lease
    /// expires, so the same credential cannot allocate a second relay.
    pub fn allocation_closed(&self, username: &str, client: SocketAddr) {
        let Some(state) = self.by_username(username) else {
            return;
        };
        if !state.matches_client(client) {
            return;
        }
        let mut allocation = state.allocation.load(Ordering::Acquire);
        while matches!(allocation, ALLOCATION_PENDING | ALLOCATION_OPEN) {
            match state.allocation.compare_exchange_weak(
                allocation,
                ALLOCATION_CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => allocation = observed,
            }
        }
        if let Ok(mut peers) = state.peers.lock() {
            peers.expiry_close_pending = false;
        }
        self.release_slot(&state);
    }

    /// Checks operation, exact client 5-tuple address, peer allowlist, grant
    /// expiry and byte/rate budget at the TURN protocol's forwarding boundary.
    pub fn authorize_action(
        &self,
        username: &str,
        realm: &str,
        client: SocketAddr,
        action: TurnAction,
        peer: Option<SocketAddr>,
        bytes: u64,
    ) -> bool {
        let Some(state) = self.by_username(username) else {
            return false;
        };
        if state.grant.realm != realm
            || !state.is_live()
            || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
            || !state.matches_client(client)
        {
            return false;
        }
        let peer_required = matches!(
            action,
            TurnAction::CreatePermission
                | TurnAction::ChannelBind
                | TurnAction::SendIndication
                | TurnAction::ChannelData
                | TurnAction::RelayToClient
        );
        let peer_is_authorized = match (peer_required, peer, state.peers.lock()) {
            (false, None, Ok(_)) => true,
            (true, Some(value), Ok(peers)) => {
                peers
                    .deadline
                    .is_none_or(|deadline| Instant::now() < deadline)
                    && peers
                        .allowed
                        .as_ref()
                        .is_some_and(|allowed| allowed.contains(&value))
            }
            _ => false,
        };
        if !peer_is_authorized {
            return false;
        }
        let forwarding = matches!(
            action,
            TurnAction::SendIndication | TurnAction::ChannelData | TurnAction::RelayToClient
        );
        if forwarding != (bytes > 0) {
            return false;
        }
        state.charge(bytes)
    }

    /// Revokes one allocation immediately. Existing socket close is performed
    /// by the service control handle after the live bit has become visible to
    /// every request and relay packet path.
    pub fn revoke(&self, allocation_id: &str) -> Result<String, TurnGrantError> {
        let state = self
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .by_allocation
            .get(allocation_id)
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;
        state.live.store(false, Ordering::Release);
        state
            .allocation
            .store(ALLOCATION_REVOKED, Ordering::Release);
        Ok(state.grant.username.clone())
    }

    /// Revokes every installed temporary TURN identity during node shutdown.
    pub fn revoke_all(&self) {
        if let Ok(registry) = self.registry.read() {
            for state in registry.by_allocation.values() {
                state.live.store(false, Ordering::Release);
                state
                    .allocation
                    .store(ALLOCATION_REVOKED, Ordering::Release);
            }
        }
    }

    /// Finds expired or externally revoked active allocations for the service's
    /// bounded reaper. Snapshot revocation flips the live bit synchronously;
    /// this returns its allocation id so the TURN server can also close relay
    /// sockets and release their capacity.
    pub fn expired_allocations(&self) -> Vec<String> {
        let Ok(mut registry) = self.registry.write() else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut stale = Vec::new();
        for (id, state) in &registry.by_allocation {
            let lease_expired = state.lease_expired(now);
            if lease_expired && state.live.swap(false, Ordering::AcqRel) {
                let previous = state.allocation.swap(ALLOCATION_REVOKED, Ordering::AcqRel);
                debug_assert!(matches!(
                    previous,
                    ALLOCATION_UNUSED
                        | ALLOCATION_PENDING
                        | ALLOCATION_OPEN
                        | ALLOCATION_CLOSED
                        | ALLOCATION_REVOKED
                ));
            }
            if state.allocation.load(Ordering::Acquire) == ALLOCATION_REVOKED
                && state.slot_accounted.load(Ordering::Acquire)
            {
                expired.push(id.clone());
            }
            // Keep every closed/revoked/unused grant as a replay tombstone
            // through the end of its current authorization expiry. Active
            // sockets are retained until the service closes and accounts for
            // their allocation slot.
            if lease_expired && !state.slot_accounted.load(Ordering::Acquire) {
                stale.push(id.clone());
            }
        }
        for id in stale {
            if let Some(state) = registry.by_allocation.remove(&id) {
                registry.by_username.remove(&state.grant.username);
            }
        }
        expired
    }

    /// Returns active allocations whose signed peer binding has expired.
    /// This closes the allocation without changing the grant's own lease
    /// deadline or making its authorization appear lease-expired.
    pub fn expired_peer_allocations(&self) -> Vec<(String, String)> {
        let Ok(registry) = self.registry.read() else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut expired = Vec::new();
        for (id, state) in &registry.by_allocation {
            if !state.is_live()
                || state.allocation.load(Ordering::Acquire) != ALLOCATION_OPEN
                || !state.slot_accounted.load(Ordering::Acquire)
            {
                continue;
            }
            let Ok(mut peers) = state.peers.lock() else {
                continue;
            };
            if peers.deadline.is_some_and(|deadline| now >= deadline) {
                peers.clear_active();
                peers.expiry_close_pending = true;
            }
            if peers.expiry_close_pending {
                expired.push((id.clone(), state.grant.username.clone()));
            }
        }
        expired
    }

    /// Current admitted allocation count, useful for bounded health reporting.
    pub fn active_allocations(&self) -> usize {
        self.active_allocations.load(Ordering::Acquire)
    }

    fn by_username(&self, username: &str) -> Option<Arc<GrantState>> {
        self.registry
            .read()
            .ok()?
            .by_username
            .get(username)
            .cloned()
    }

    fn reserve_slot(&self) -> bool {
        let mut current = self.active_allocations.load(Ordering::Acquire);
        loop {
            if current >= self.max_allocations {
                return false;
            }
            match self.active_allocations.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release_slot(&self, state: &GrantState) {
        if state.slot_accounted.swap(false, Ordering::AcqRel) {
            let _ = self.active_allocations.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| current.checked_sub(1),
            );
        }
    }
}

impl GrantState {
    fn matches_client(&self, client: SocketAddr) -> bool {
        self.client
            .lock()
            .is_ok_and(|current| current.is_some_and(|value| value == client))
    }
}

fn validate_grant(grant: &TurnAllocationGrant) -> Result<(), TurnGrantError> {
    if !valid_token(&grant.deployment_id)
        || !valid_token(&grant.node_id)
        || !valid_token(&grant.runtime_id)
        || !valid_token(&grant.allocation_id)
        || !valid_token(&grant.session_id)
        || !valid_token(&grant.temporary_identity)
        || !valid_username(&grant.username)
        || grant.realm.is_empty()
        || grant.realm.len() > MAX_TOKEN_BYTES
        || !grant.realm.is_ascii()
        || grant.realm.bytes().any(|byte| byte.is_ascii_control())
        || grant.generation == 0
        || grant.connection_generation == 0
        || grant.grant_sequence == 0
        || grant.lease_sequence == 0
        || !valid_token(&grant.device_id)
        || !valid_token(&grant.controller_device_id)
        || !valid_token(&grant.host_device_id)
        || grant.controller_device_id == grant.host_device_id
        || ![&grant.controller_device_id, &grant.host_device_id].contains(&&grant.device_id)
        || grant.policy_revision == 0
        || grant.quota_revision == 0
        || grant.endpoint_revision == 0
        || grant.expires_at_unix_ms == 0
        || grant.max_total_bytes == 0
        || grant.max_bytes_per_second == 0
        || grant.max_peers == 0
        || grant.max_peers > MAX_PEERS
        || grant.peer_allowlist.len() > MAX_PEERS
        || grant.peer_allowlist.len() > grant.max_peers
        || grant.auth_key.iter().all(|byte| *byte == 0)
    {
        return Err(TurnGrantError::InvalidGrant);
    }
    if !grant.peer_allowlist.is_empty() && !valid_peer_set(&grant.peer_allowlist, grant.max_peers) {
        return Err(TurnGrantError::InvalidGrant);
    }
    Ok(())
}

fn valid_peer_set(peers: &[SocketAddr], maximum: usize) -> bool {
    if peers.is_empty() || peers.len() > maximum || peers.len() > MAX_PEERS {
        return false;
    }
    let mut seen = HashSet::with_capacity(peers.len());
    peers.iter().all(|peer| {
        peer.port() != 0
            && !peer.ip().is_unspecified()
            && !peer.ip().is_multicast()
            && !matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
            && seen.insert(*peer)
    })
}

fn same_authority(current: &TurnAllocationGrant, next: &TurnAllocationGrant) -> bool {
    current.deployment_id == next.deployment_id
        && current.node_id == next.node_id
        && current.runtime_id == next.runtime_id
        && current.allocation_id == next.allocation_id
        && current.session_id == next.session_id
        && current.temporary_identity == next.temporary_identity
        && current.purpose == next.purpose
        && current.generation == next.generation
        && current.connection_generation == next.connection_generation
        && current.node_key_sha256 == next.node_key_sha256
        && current.device_id == next.device_id
        && current.controller_device_id == next.controller_device_id
        && current.host_device_id == next.host_device_id
        && current.controller_key_sha256 == next.controller_key_sha256
        && current.host_key_sha256 == next.host_key_sha256
        && current.session_binding_sha256 == next.session_binding_sha256
        && current.policy_revision == next.policy_revision
        && current.quota_revision == next.quota_revision
        && current.endpoint_revision == next.endpoint_revision
        && current.username == next.username
        && current.realm == next.realm
        && current.auth_key == next.auth_key
        && current.peer_allowlist == next.peer_allowlist
        && current.max_peers == next.max_peers
        && current.max_total_bytes == next.max_total_bytes
        && current.max_bytes_per_second == next.max_bytes_per_second
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn grant(id: &str, username: &str, deadline: Instant) -> TurnAllocationGrant {
        TurnAllocationGrant {
            deployment_id: "deployment-1".to_owned(),
            node_id: "node-1".to_owned(),
            runtime_id: "runtime-1".to_owned(),
            allocation_id: id.to_owned(),
            session_id: "session-1".to_owned(),
            temporary_identity: "browser-1".to_owned(),
            purpose: TurnPurpose::BrowserWebRtc,
            generation: 1,
            connection_generation: 1,
            grant_sequence: 1,
            lease_sequence: 1,
            node_key_sha256: [1; 32],
            device_id: "browser-1".to_owned(),
            controller_device_id: "browser-1".to_owned(),
            host_device_id: "host-1".to_owned(),
            controller_key_sha256: [2; 32],
            host_key_sha256: [3; 32],
            permit_sha256: [4; 32],
            session_binding_sha256: [5; 32],
            policy_revision: 1,
            quota_revision: 1,
            endpoint_revision: 1,
            username: username.to_owned(),
            realm: "deployment.example".to_owned(),
            auth_key: [0x5a; 16],
            peer_allowlist: vec![SocketAddr::from(([198, 51, 100, 8], 40000))],
            max_peers: 1,
            expires_at_unix_ms: 1_800_000_000_000,
            deadline,
            max_total_bytes: 1000,
            max_bytes_per_second: 1000,
        }
    }

    #[test]
    fn allocation_is_single_use_and_only_admits_paired_peer_traffic() -> Result<(), TurnGrantError>
    {
        let authorization = TurnAuthorization::new(1)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        let other = SocketAddr::from(([198, 51, 100, 9], 40000));
        authorization.install_grant(grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(30),
        ))?;
        assert!(authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(!authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(authorization.allocation_ready("1700000100:browser-1", client));
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::CreatePermission,
            Some(peer),
            0,
        ));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::ChannelBind,
            Some(other),
            0,
        ));
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            100,
        ));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            901,
        ));
        assert_eq!(authorization.active_allocations(), 1);
        authorization.allocation_closed("1700000100:browser-1", client);
        assert_eq!(authorization.active_allocations(), 0);
        assert!(!authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        Ok(())
    }

    #[test]
    fn allocation_capacity_counts_pending_slots_and_releases_failed_allocations()
    -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let first_username = "1700000100:browser-1";
        let second_username = "1700000100:browser-2";
        let first_client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let second_client = SocketAddr::from(([192, 0, 2, 11], 54000));
        let deadline = Instant::now() + Duration::from_secs(30);
        authorization.install_grant(grant("allocation-1", first_username, deadline))?;
        authorization.install_grant(grant("allocation-2", second_username, deadline))?;

        assert_eq!(authorization.active_allocations(), 0);
        assert!(authorization.authorize_allocation(
            first_username,
            "deployment.example",
            first_client,
        ));
        assert_eq!(authorization.active_allocations(), 1);
        assert!(!authorization.authorize_allocation(
            second_username,
            "deployment.example",
            second_client,
        ));
        assert_eq!(authorization.active_allocations(), 1);

        authorization.allocation_failed(first_username, first_client);
        assert_eq!(authorization.active_allocations(), 0);
        assert!(authorization.authorize_allocation(
            second_username,
            "deployment.example",
            second_client,
        ));
        assert_eq!(authorization.active_allocations(), 1);
        assert!(authorization.allocation_ready(second_username, second_client));
        authorization.allocation_closed(second_username, second_client);
        assert_eq!(authorization.active_allocations(), 0);
        Ok(())
    }

    #[test]
    fn revoke_and_deadline_close_every_authority_path() -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(2)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        authorization.install_grant(grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(30),
        ))?;
        assert!(authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(authorization.allocation_ready("1700000100:browser-1", client));
        assert!(
            authorization
                .auth_key("1700000100:browser-1", "deployment.example")
                .is_some()
        );
        assert_eq!(
            authorization.revoke("allocation-1")?,
            "1700000100:browser-1"
        );
        assert_eq!(
            authorization.expired_allocations(),
            vec!["allocation-1".to_owned()]
        );
        assert!(
            authorization
                .auth_key("1700000100:browser-1", "deployment.example")
                .is_none()
        );
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::RelayToClient,
            Some(peer),
            1,
        ));
        assert_eq!(authorization.active_allocations(), 1);
        authorization.allocation_closed("1700000100:browser-1", client);
        assert_eq!(authorization.active_allocations(), 0);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_peer_credentials_and_expired_install() -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let mut invalid = grant(
            "allocation-1",
            "name",
            Instant::now() + Duration::from_secs(5),
        );
        invalid.peer_allowlist.push(invalid.peer_allowlist[0]);
        assert!(matches!(
            authorization.install_grant(invalid),
            Err(TurnGrantError::InvalidGrant)
        ));
        authorization.install_grant(grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(5),
        ))?;
        assert!(matches!(
            authorization.install_grant(grant(
                "allocation-2",
                "1700000100:browser-1",
                Instant::now() + Duration::from_secs(5),
            )),
            Err(TurnGrantError::DuplicateGrant)
        ));
        assert!(authorization.expired_allocations().is_empty());
        Ok(())
    }

    #[test]
    fn renewal_preserves_open_allocation_and_existing_byte_budget() -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        let deadline = Instant::now() + Duration::from_secs(30);
        authorization.install_grant(grant("allocation-1", "1700000100:browser-1", deadline))?;
        assert!(authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(authorization.allocation_ready("1700000100:browser-1", client));
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            400,
        ));

        let mut renewal = grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(60),
        );
        // A node-grant extension retains the current session permit and peers.
        // Session-lease advancement has a separate reactivation regression.
        renewal.grant_sequence = 2;
        renewal.expires_at_unix_ms += 60_000;
        authorization.renew_grant(renewal)?;

        assert_eq!(authorization.active_allocations(), 1);
        assert!(!authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            601,
        ));
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            600,
        ));
        Ok(())
    }

    #[test]
    fn renewal_rejects_stale_or_changed_authority() -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        authorization.install_grant(grant("allocation-1", "1700000100:browser-1", deadline))?;

        let mut stale = grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(60),
        );
        stale.expires_at_unix_ms += 60_000;
        assert_eq!(
            authorization.renew_grant(stale),
            Err(TurnGrantError::InvalidGrant)
        );

        let mut changed_peer = grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(60),
        );
        changed_peer.grant_sequence = 2;
        changed_peer.lease_sequence = 2;
        changed_peer.permit_sha256 = [6; 32];
        changed_peer.expires_at_unix_ms += 60_000;
        changed_peer.peer_allowlist[0] = SocketAddr::from(([198, 51, 100, 9], 40000));
        assert_eq!(
            authorization.renew_grant(changed_peer),
            Err(TurnGrantError::InvalidGrant)
        );
        assert!(
            authorization
                .auth_key("1700000100:browser-1", "deployment.example")
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn peerless_bootstrap_requires_one_exact_generation_bound_activation()
    -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        let other = SocketAddr::from(([198, 51, 100, 9], 40000));
        let mut initial = grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(30),
        );
        initial.peer_allowlist.clear();
        authorization.install_grant(initial)?;
        assert!(authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(authorization.allocation_ready("1700000100:browser-1", client));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::CreatePermission,
            Some(peer),
            0,
        ));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            1,
        ));

        for (session, temporary_identity, generation, connection_generation, lease_sequence) in [
            ("other-session", "browser-1", 1, 1, 1),
            ("session-1", "other-browser", 1, 1, 1),
            ("session-1", "browser-1", 2, 1, 1),
            ("session-1", "browser-1", 1, 2, 1),
            ("session-1", "browser-1", 1, 1, 2),
        ] {
            assert_eq!(
                authorization.activate_peers(TurnPeerActivation {
                    allocation_id: "allocation-1",
                    session_id: session,
                    temporary_identity,
                    generation,
                    connection_generation,
                    grant_sequence: 1,
                    lease_sequence,
                    peers: &[peer],
                },),
                Err(TurnGrantError::InvalidGrant)
            );
        }
        assert_eq!(
            authorization.activate_peers(TurnPeerActivation {
                allocation_id: "allocation-1",
                session_id: "session-1",
                temporary_identity: "browser-1",
                generation: 1,
                connection_generation: 1,
                grant_sequence: 1,
                lease_sequence: 1,
                peers: &[peer, peer],
            },),
            Err(TurnGrantError::InvalidGrant)
        );

        authorization.activate_peers(TurnPeerActivation {
            allocation_id: "allocation-1",
            session_id: "session-1",
            temporary_identity: "browser-1",
            generation: 1,
            connection_generation: 1,
            grant_sequence: 1,
            lease_sequence: 1,
            peers: &[peer],
        })?;
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(other),
            1,
        ));
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            400,
        ));
        assert_eq!(
            authorization.activate_peers(TurnPeerActivation {
                allocation_id: "allocation-1",
                session_id: "session-1",
                temporary_identity: "browser-1",
                generation: 1,
                connection_generation: 1,
                grant_sequence: 1,
                lease_sequence: 1,
                peers: &[peer],
            },),
            Err(TurnGrantError::InvalidGrant)
        );

        let mut renewal = grant(
            "allocation-1",
            "1700000100:browser-1",
            Instant::now() + Duration::from_secs(60),
        );
        renewal.peer_allowlist.clear();
        renewal.grant_sequence = 2;
        renewal.expires_at_unix_ms += 60_000;
        authorization.renew_grant(renewal)?;
        assert!(authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            600,
        ));
        assert!(!authorization.authorize_action(
            "1700000100:browser-1",
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(other),
            1,
        ));
        Ok(())
    }

    #[test]
    fn signed_peer_binding_deadline_expires_independently_of_the_grant_lease()
    -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let username = "1700000100:browser-1";
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        let mut initial = grant(
            "allocation-1",
            username,
            Instant::now() + Duration::from_secs(30),
        );
        initial.peer_allowlist.clear();
        authorization.install_grant(initial)?;
        assert!(authorization.authorize_allocation(username, "deployment.example", client));
        assert!(authorization.allocation_ready(username, client));
        let original_deadline = Instant::now() + Duration::from_millis(120);
        let activation = TurnPeerBindingActivation {
            allocation_id: "allocation-1",
            session_id: "session-1",
            temporary_identity: "browser-1",
            generation: 1,
            connection_generation: 1,
            grant_sequence: 1,
            lease_sequence: 1,
            binding_sha256: [9; 32],
            issued_at_unix_ms: 1,
            deadline: original_deadline,
            peers: &[peer],
        };
        authorization.activate_peer_binding(activation)?;
        assert!(authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            1,
        ));

        std::thread::sleep(Duration::from_millis(30));
        // A later snapshot carrying identical claims cannot extend the first
        // request's monotonic expiry, even if its derived deadline is later.
        authorization.activate_peer_binding(TurnPeerBindingActivation {
            deadline: Instant::now() + Duration::from_secs(2),
            ..activation
        })?;
        std::thread::sleep(Duration::from_millis(100));
        assert!(!authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(peer),
            1,
        ));
        assert_eq!(
            authorization.expired_peer_allocations(),
            vec![("allocation-1".to_owned(), username.to_owned())]
        );
        assert_eq!(
            authorization.expired_peer_allocations(),
            vec![("allocation-1".to_owned(), username.to_owned())]
        );
        assert!(authorization.expired_allocations().is_empty());
        assert!(
            authorization
                .auth_key(username, "deployment.example")
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn a_new_session_lease_clears_peers_until_its_binding_is_activated()
    -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let old_peer = SocketAddr::from(([198, 51, 100, 8], 40000));
        let new_peer = SocketAddr::from(([198, 51, 100, 9], 40000));
        let username = "1700000100:browser-1";
        let mut initial = grant(
            "allocation-1",
            username,
            Instant::now() + Duration::from_secs(30),
        );
        initial.peer_allowlist.clear();
        authorization.install_grant(initial)?;
        assert!(authorization.authorize_allocation(username, "deployment.example", client,));
        assert!(authorization.allocation_ready(username, client));
        authorization.activate_peers(TurnPeerActivation {
            allocation_id: "allocation-1",
            session_id: "session-1",
            temporary_identity: "browser-1",
            generation: 1,
            connection_generation: 1,
            grant_sequence: 1,
            lease_sequence: 1,
            peers: &[old_peer],
        })?;
        assert!(authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(old_peer),
            1,
        ));

        let mut renewal = grant(
            "allocation-1",
            username,
            Instant::now() + Duration::from_secs(60),
        );
        renewal.peer_allowlist.clear();
        renewal.grant_sequence = 2;
        renewal.lease_sequence = 2;
        renewal.permit_sha256 = [6; 32];
        renewal.expires_at_unix_ms += 60_000;
        authorization.renew_grant(renewal)?;
        assert_eq!(authorization.active_allocations(), 1);
        assert!(!authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(old_peer),
            1,
        ));
        assert_eq!(
            authorization.activate_peers(TurnPeerActivation {
                allocation_id: "allocation-1",
                session_id: "session-1",
                temporary_identity: "browser-1",
                generation: 1,
                connection_generation: 1,
                grant_sequence: 2,
                lease_sequence: 1,
                peers: &[new_peer],
            }),
            Err(TurnGrantError::InvalidGrant),
        );
        authorization.activate_peers(TurnPeerActivation {
            allocation_id: "allocation-1",
            session_id: "session-1",
            temporary_identity: "browser-1",
            generation: 1,
            connection_generation: 1,
            grant_sequence: 2,
            lease_sequence: 2,
            peers: &[new_peer],
        })?;
        assert!(!authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(old_peer),
            1,
        ));
        assert!(authorization.authorize_action(
            username,
            "deployment.example",
            client,
            TurnAction::SendIndication,
            Some(new_peer),
            1,
        ));
        Ok(())
    }

    #[test]
    fn closed_grants_remain_replay_tombstones_until_lease_expiry() -> Result<(), TurnGrantError> {
        let authorization = TurnAuthorization::new(1)?;
        let client = SocketAddr::from(([192, 0, 2, 10], 54000));
        let deadline = Instant::now() + Duration::from_secs(30);
        authorization.install_grant(grant("allocation-1", "1700000100:browser-1", deadline))?;
        assert!(authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert!(authorization.allocation_ready("1700000100:browser-1", client));
        authorization.allocation_closed("1700000100:browser-1", client);
        assert_eq!(authorization.active_allocations(), 0);
        let registry = authorization
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        assert!(registry.by_allocation.contains_key("allocation-1"));
        drop(registry);
        assert!(!authorization.authorize_allocation(
            "1700000100:browser-1",
            "deployment.example",
            client
        ));
        assert_eq!(
            authorization.install_grant(grant(
                "allocation-1",
                "1700000100:browser-1",
                deadline + Duration::from_secs(60),
            )),
            Err(TurnGrantError::DuplicateGrant)
        );
        let mut renewal = grant(
            "allocation-1",
            "1700000100:browser-1",
            deadline + Duration::from_secs(60),
        );
        renewal.lease_sequence = 2;
        renewal.expires_at_unix_ms += 60_000;
        assert_eq!(
            authorization.renew_grant(renewal),
            Err(TurnGrantError::InvalidGrant)
        );

        let state = authorization
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .by_allocation
            .get("allocation-1")
            .cloned()
            .ok_or(TurnGrantError::GrantNotFound)?;
        state
            .lease
            .lock()
            .map_err(|_| TurnGrantError::StateUnavailable)?
            .deadline = Instant::now() - Duration::from_secs(1);
        assert!(authorization.expired_allocations().is_empty());
        let registry = authorization
            .registry
            .read()
            .map_err(|_| TurnGrantError::StateUnavailable)?;
        assert!(!registry.by_allocation.contains_key("allocation-1"));
        Ok(())
    }
}
