use nestlink_identity::{
    VerifiedPermit, digest,
    network::{NetworkVerification, VerifiedNetworkGrant, VerifiedNetworkPath},
};
use nestlink_protocol::{
    Path,
    network::{GrantClaims, PeerId, PeerPair, Purpose},
    network_datagram as wire,
};
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
        path.check_current(&current).map_err(io::Error::other)?;
        connectivity
            .check_current(&current)
            .map_err(io::Error::other)?;
        transit.check_current(&current).map_err(io::Error::other)?;
        let (GrantClaims::Connectivity(connection), GrantClaims::Transit(forward)) =
            (connectivity.claims(), transit.claims())
        else {
            return Err(denied());
        };
        let business = permit.claims();
        let first = PeerId(
            business
                .controller_key_sha256
                .as_slice()
                .try_into()
                .map_err(|_| denied())?,
        );
        let second = PeerId(
            business
                .host_key_sha256
                .as_slice()
                .try_into()
                .map_err(|_| denied())?,
        );
        let peers = PeerPair::new(first, second).map_err(io::Error::other)?;
        path.check_route(&current, &[forward.relay])
            .map_err(io::Error::other)?;
        if path.purpose() != Purpose::RemoteControl
            || connection.purpose != Purpose::RemoteControl
            || connection.peers != peers
            || path.peers() != peers
            || forward.peers != peers
            || connectivity.digest() != path.claims().connectivity_grant_digest
            || connection.business_grant_digest != permit.digest()
            || forward.transport_group != path.transport_group_id()
            || forward.previous != peers.first
            || forward.next != peers.second
            || forward.remaining_hops != 1
            || business.deployment_id != current.deployment_id
            || !business.paths.contains(&(Path::Relay as i32))
            || business.issued_at_unix_ms > current.now_ms
            || business.expires_at_unix_ms <= current.now_ms
            || path.claims().scope.not_before_ms < business.issued_at_unix_ms
            || path.claims().scope.expires_at_ms > business.expires_at_unix_ms
            || forward.scope.not_before_ms < path.claims().scope.not_before_ms
            || forward.scope.expires_at_ms > path.claims().scope.expires_at_ms
        {
            return Err(denied());
        }
        // The exact verified references contain the authority, space, both
        // endpoints, purpose, route ID, group, adjacency, hop budget and quota.
        // Generation follows the business permit; path epoch is fixed at one.
        let mut transcript = b"NestLink/network-datagram/v1/route-binding\0".to_vec();
        transcript.extend_from_slice(&path.transport_group_id());
        transcript.extend_from_slice(&connectivity.digest());
        transcript.extend_from_slice(&transit.digest());
        transcript.extend_from_slice(&permit.digest());
        transcript.extend_from_slice(&business.connection_generation.to_be_bytes());
        transcript.extend_from_slice(&wire::PATH_EPOCH.to_be_bytes());
        let remaining = forward
            .scope
            .expires_at_ms
            .checked_sub(current.now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(denied)?;
        let (stop, stopped) = watch::channel(false);
        Ok((
            Self {
                binding: Arc::new(Binding {
                    digest: digest(&transcript),
                    peers,
                    relay: forward.relay,
                    byte_limit: forward.byte_limit,
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
