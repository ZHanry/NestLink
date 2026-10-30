//! Opt-in network route admission into the existing remote business runtime.
//! This adapter performs no discovery or scheduling. Callers supply the exact
//! authenticated adjacency and live policy snapshot for their selected route.
use crate::DeviceIdentity;
use nestlink_identity::{
    digest,
    network::{NetworkVerification, VerifiedNetworkGrant, VerifiedNetworkPath},
};
use nestlink_protocol::Path;
use nestlink_remote::{ChannelRuntime, RemoteError, SessionSetup, StopHandler, TransportOwner};
use nestlink_session::{EndpointRole, StopEffects, StopReason};
use nestlink_transport_quic::routed::{
    self, Adjacency, RouteAuthorization, RouteRevocation, RoutedTransport,
};
use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio::{sync::watch, time::Instant};
mod control;
pub use control::{PinnedNetworkSpace, VerifiedRemoteRelay, VerifiedRemoteChain};
use nestlink_transport_stream::owner::TaskOwner;

/// Supply a current trusted policy snapshot, not claims read from a peer.
/// These network permissions do not replace the SessionSetup business permit.
pub struct RemoteRouteAuthority<'a> {
    pub context: &'a NetworkVerification<'a>,
    pub path: &'a VerifiedNetworkPath,
    pub connectivity: &'a VerifiedNetworkGrant,
    pub transit: &'a VerifiedNetworkGrant,
}

/// A complete ordered NRD2 path. Both TransitGrants are mandatory and remain
/// separate from the original SessionPermit and its per-business permissions.
pub struct RemoteChainAuthority<'a> {
    pub context: &'a NetworkVerification<'a>,
    pub path: &'a VerifiedNetworkPath,
    pub connectivity: &'a VerifiedNetworkGrant,
    pub transits: &'a [VerifiedNetworkGrant],
}
enum NetworkRouteAuthority<'a> {
    Single(RemoteRouteAuthority<'a>),
    Chain(RemoteChainAuthority<'a>),
}
impl<'a> From<RemoteRouteAuthority<'a>> for NetworkRouteAuthority<'a> {
    fn from(value:RemoteRouteAuthority<'a>) -> Self { Self::Single(value) }
}
impl<'a> From<RemoteChainAuthority<'a>> for NetworkRouteAuthority<'a> {
    fn from(value:RemoteChainAuthority<'a>) -> Self { Self::Chain(value) }
}
impl NetworkRouteAuthority<'_> {
    fn authorize(&self,permit:&nestlink_identity::VerifiedPermit) -> io::Result<(RouteAuthorization,RouteRevocation)> {
        match self {
            Self::Single(authority) => RouteAuthorization::remote(authority.context,authority.path,authority.connectivity,authority.transit,permit),
            Self::Chain(authority) => RouteAuthorization::remote_chain(authority.context,authority.path,authority.connectivity,authority.transits,permit),
        }
    }
}

/// Use the same bounded business runtime, mutual endpoint proof, lifecycle,
/// cancellation and physical cleanup owner as the one-relay path. Callers must
/// keep current policy and business revocations connected to SessionLifecycle.
pub async fn authorize_remote_chain(
    authority:RemoteChainAuthority<'_>,adjacency:Adjacency,setup:SessionSetup,
    local:&DeviceIdentity,peer_key:&[u8;32],deadline:Instant,
) -> Result<ChannelRuntime,RemoteError> {
    authorize_remote_observed(authority,adjacency,setup,local,peer_key,deadline,None,None).await
}

/// Prove the actual SessionSetup permit through a previously selected route.
/// The returned bounded channels are the existing remote runtime; no business
/// stream becomes available before both endpoint proofs. The route's original
/// deadline caps the business lifetime, including any attempted renewal.
///
/// The caller must keep its SessionLifecycle stop source connected to current
/// membership, policy and business revocations. Dropping this future requests
/// teardown. Only a successfully returned runtime has an explicit completion
/// receipt; cancelling establishment requests Drop cleanup without a receipt.
pub async fn authorize_remote(
    authority: RemoteRouteAuthority<'_>,
    adjacency: Adjacency,
    setup: SessionSetup,
    local: &DeviceIdentity,
    peer_key: &[u8; 32],
    deadline: Instant,
) -> Result<ChannelRuntime, RemoteError> {
    authorize_remote_observed(
        authority, adjacency, setup, local, peer_key, deadline, None, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn authorize_remote_observed<'a>(
    authority: impl Into<NetworkRouteAuthority<'a>>,
    mut adjacency: Adjacency,
    mut setup: SessionSetup,
    local: &DeviceIdentity,
    peer_key: &[u8; 32],
    deadline: Instant,
    observer: Option<control::RemoteRouteObserver>,
    mut cancel: Option<watch::Receiver<bool>>,
) -> Result<ChannelRuntime, RemoteError> {
    let authority = authority.into();
    let mut stop = setup.lifecycle.stop.clone();
    if setup_is_stopped(&stop) || cancel.as_ref().is_some_and(control::cancel_is_stopped) {
        adjacency
            .close_and_wait(deadline)
            .await
            .map_err(RemoteError::Cleanup)?;
        return Err(RemoteError::Stopped);
    }
    let validation = (|| {
        if setup.lifecycle.carrier.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "routed carrier lifecycle is already owned",
            ));
        }
        let permit = setup.session.current_verified_permit();
        let business = permit.claims();
        let (device_id, local_key, remote_key) = match setup.role {
            EndpointRole::Controller => (
                &business.controller_device_id,
                &business.controller_key_sha256,
                &business.host_key_sha256,
            ),
            EndpointRole::Host => (
                &business.host_device_id,
                &business.host_key_sha256,
                &business.controller_key_sha256,
            ),
        };
        if device_id != &local.device_id
            || local_key.as_slice() != local.identity.fingerprint()
            || remote_key.as_slice() != digest(peer_key)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "routed remote device binding mismatch",
            ));
        }
        authority.authorize(permit)
    })();
    let (authorization, revocation) = match validation {
        Ok(value) => value,
        Err(error) => {
            adjacency
                .close_and_wait(deadline)
                .await
                .map_err(RemoteError::Cleanup)?;
            return Err(error.into());
        }
    };
    let route_deadline = authorization.deadline();
    let revocation = Arc::new(revocation);
    let setup_deadline = deadline.min(route_deadline);
    let preparation = (|| -> Result<(), RemoteError> {
        let now = setup.clock.sample()?;
        setup.session.select_path_before_proof(Path::Relay, now)?;
        setup
            .session
            .cap_lifetime_deadline_ms(setup.clock.deadline_ms(route_deadline.into_std())?)?;
        setup.path = Path::Relay;
        Ok(())
    })();
    if let Err(error) = preparation {
        revocation.revoke();
        adjacency
            .close_and_wait(deadline)
            .await
            .map_err(RemoteError::Cleanup)?;
        return Err(error);
    }
    setup.lifecycle.resources = Some(Box::new(RemoteRouteStop {
        revocation: revocation.clone(),
        deadline: route_deadline,
        previous: setup.lifecycle.resources.take(),
    }));
    let mut pending = routed::RoutedEstablishment::new(authorization, adjacency);
    let established = tokio::select! { biased;
        _ = wait_setup_stop(&mut stop) => {
            revocation.revoke();
            Err(RemoteError::Stopped)
        },
        _ = wait_setup_cancel(&mut cancel) => {
            revocation.revoke();
            Err(RemoteError::Stopped)
        },
        result = pending.establish(&local.identity, setup_deadline) => {
            result.map_err(io::Error::other).map_err(RemoteError::from)
        },
    };
    if let Err(error) = established {
        revocation.revoke();
        pending
            .close_and_wait(deadline)
            .await
            .map_err(RemoteError::Cleanup)?;
        return Err(error);
    }
    let transport = pending.take_transport()?;
    setup.lifecycle.carrier = Some(transport.subscribe_failure());
    // The owner is retained before business proof awaits. Cancellation closes
    // both inner and outer endpoints and fails the route closed.
    let mut owner = RemoteRouteOwner {
        transport,
        revocation,
        observer: None,
    };
    let connection = owner.transport.connection()?.clone();
    let proved = tokio::select! { biased;
        _ = wait_setup_stop(&mut stop) => Err(RemoteError::Stopped),
        _ = wait_setup_cancel(&mut cancel) => Err(RemoteError::Stopped),
        result = tokio::time::timeout_at(setup_deadline, nestlink_remote::quic::authorize(
            connection, None, setup, &local.identity, peer_key,
        )) => result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut,
            "routed business setup deadline exhausted").into())),
    };
    match proved {
        Ok(mut channels) => {
            // timeout_at polls the inner operation before its timer. Recheck
            // terminal facts at the handoff even if proof became ready late.
            let expired = Instant::now() >= setup_deadline;
            if expired
                || setup_is_stopped(&stop)
                || cancel.as_ref().is_some_and(control::cancel_is_stopped)
            {
                let _ = channels.lease_control().stop(if expired {
                    StopReason::Expired
                } else {
                    StopReason::Revoked
                });
                let business_cleanup =
                    tokio::time::timeout_at(deadline, channels.wait_stopped()).await;
                owner
                    .close_and_wait(deadline)
                    .await
                    .map_err(RemoteError::Cleanup)?;
                business_cleanup
                    .map_err(|_| RemoteError::Cleanup(io::ErrorKind::TimedOut.into()))??;
                return Err(if expired {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "routed business handoff deadline exhausted",
                    )
                    .into()
                } else {
                    RemoteError::Stopped
                });
            }
            owner.observer = observer.map(|observer| observer.spawn(channels.lease_control()));
            Ok(channels.with_transport_owner(owner))
        }
        Err(error) => {
            owner
                .close_and_wait(deadline)
                .await
                .map_err(RemoteError::Cleanup)?;
            Err(error)
        }
    }
}

fn setup_is_stopped(stop: &watch::Receiver<Option<StopReason>>) -> bool {
    stop.borrow().is_some() || stop.has_changed().is_err()
}

async fn wait_setup_stop(stop: &mut watch::Receiver<Option<StopReason>>) {
    loop {
        if setup_is_stopped(stop) {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_setup_cancel(cancel: &mut Option<watch::Receiver<bool>>) {
    match cancel {
        Some(cancel) => control::cancelled(cancel).await,
        None => std::future::pending().await,
    }
}

/// Preserve the caller's synchronous resource handler while revoking forwarding
/// at the business stop linearization point, before any async runtime wait.
struct RemoteRouteStop {
    revocation: Arc<RouteRevocation>,
    deadline: Instant,
    previous: Option<Box<dyn StopHandler>>,
}
impl StopHandler for RemoteRouteStop {
    fn check(&mut self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            self.revocation.revoke();
            return Err(io::ErrorKind::TimedOut.into());
        }
        match &mut self.previous {
            Some(previous) => previous.check(),
            None => Ok(()),
        }
    }
    fn stop(&mut self, reason: StopReason, effects: StopEffects) -> io::Result<()> {
        self.revocation.revoke();
        match &mut self.previous {
            Some(previous) => previous.stop(reason, effects),
            None => Ok(()),
        }
    }
}
impl Drop for RemoteRouteStop {
    fn drop(&mut self) {
        self.revocation.revoke();
    }
}

struct RemoteRouteOwner {
    transport: RoutedTransport,
    revocation: Arc<RouteRevocation>,
    observer: Option<TaskOwner>,
}
impl TransportOwner for RemoteRouteOwner {
    fn request_close(&self) {
        self.revocation.revoke();
        self.transport.request_close();
        if let Some(observer) = &self.observer {
            observer.request_close();
        }
    }
    fn close_and_wait(
        &mut self,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        self.request_close();
        Box::pin(async move {
            if let Some(observer) = &self.observer {
                observer.close_and_wait(deadline).await?;
            }
            self.observer = None;
            self.transport.close_and_wait(deadline).await
        })
    }
}
impl Drop for RemoteRouteOwner {
    fn drop(&mut self) {
        self.request_close();
    }
}

#[cfg(test)]
#[path = "routed_tests.rs"]
mod tests;
