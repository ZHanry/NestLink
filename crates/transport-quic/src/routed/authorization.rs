use nestlink_identity::{
    VerifiedPermit,
    network::{
        NetworkVerification, VerifiedNetworkGrant, VerifiedNetworkPath, remote_route_binding,
    },
};
use nestlink_protocol::network::{PeerId, PeerPair};
use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::Instant};

const MAX_LEASE_MS: u64 = 30_000;
struct Binding {
    digest: [u8; 32],
    peers: PeerPair,
    relay: PeerId,
    byte_limit: u64,
    deadline: Instant,
}
/// No unchecked public constructor. All binding fields follow verified signed
/// objects. The initial policy snapshot never becomes indefinite authority.
pub struct RouteAuthorization {
    binding: Arc<Binding>,
    stopped: watch::Receiver<bool>,
}
/// The policy/business owner must retain this handle and revoke it on stop,
/// membership/policy change or business revocation. Dropping its last sender is
/// also fail-closed; leaving a route alive requires explicit owner retention.
pub struct RouteRevocation(watch::Sender<bool>);
impl RouteRevocation {
    pub fn revoke(&self) {
        self.0.send_replace(true);
    }
}
impl RouteAuthorization {
    pub fn remote(
        context: &NetworkVerification<'_>,
        path: &VerifiedNetworkPath,
        connectivity: &VerifiedNetworkGrant,
        transit: &VerifiedNetworkGrant,
        permit: &VerifiedPermit,
    ) -> io::Result<(Self, RouteRevocation)> {
        let started = Instant::now();
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?;
        let current = NetworkVerification {
            authority_key: context.authority_key,
            deployment_id: context.deployment_id,
            space_id: context.space_id,
            policy_epoch: context.policy_epoch,
            revoked_grant_ids: context.revoked_grant_ids,
            now_ms: now.max(context.now_ms),
        };
        // The exact verified references contain the authority, space, both
        // endpoints, purpose, route ID, group, adjacency, hop budget and quota.
        // Generation follows the business permit; path epoch is fixed at one.
        let route = remote_route_binding(&current, path, connectivity, transit, permit)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
        let remaining = route
            .expires_at_ms
            .checked_sub(current.now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(denied)?;
        let (stop, stopped) = watch::channel(false);
        Ok((
            Self {
                binding: Arc::new(Binding {
                    digest: route.digest,
                    peers: route.peers,
                    relay: route.relay,
                    byte_limit: route.byte_limit,
                    deadline: started + Duration::from_millis(remaining.min(MAX_LEASE_MS)),
                }),
                stopped,
            },
            RouteRevocation(stop),
        ))
    }
    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding.digest
    }
    pub fn peers(&self) -> PeerPair {
        self.binding.peers
    }
    pub fn relay(&self) -> PeerId {
        self.binding.relay
    }
    pub fn byte_limit(&self) -> u64 {
        self.binding.byte_limit
    }
    pub fn deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn check_live(&self) -> io::Result<()> {
        self.live()
    }
    pub(crate) fn live(&self) -> io::Result<()> {
        if *self.stopped.borrow() || self.stopped.has_changed().is_err() {
            return Err(denied());
        }
        if Instant::now() >= self.deadline() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
    pub(crate) async fn wait_stopped(&self) {
        if self.live().is_err() {
            return;
        }
        let mut stopped = self.stopped.clone();
        tokio::select! {
            _ = tokio::time::sleep_until(self.deadline()) => {},
            _ = stopped.changed() => {},
        }
    }
    pub(crate) fn retained(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            stopped: self.stopped.clone(),
        }
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "routed transport authority refused or stopped",
    )
}
