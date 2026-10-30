//! Management readback is the freshness source; the operator-pinned network
//! key verifies every byte. Peer-supplied grants cannot construct this owner.
use super::*;
use crate::{Sdk, SdkError, native::{AddressPolicy, SessionEstablishError}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::Secret;
use nestlink_identity::{VerifiedPermit, network::{VerifiedMembership, verify_network_grant}};
use nestlink_protocol::{api::NetworkRemoteRelayView, network::GrantClaims};
use std::{collections::BTreeSet, net::SocketAddr, time::{Duration, SystemTime, UNIX_EPOCH}};

/// Installed by the local operator for this deployment. A response or a peer
/// cannot replace this key. Loopback nodes require a separate explicit opt-in.
#[derive(Clone)]
pub struct PinnedNetworkSpace {
    space_id: String,
    authority_key: [u8;32],
    allow_loopback_node: bool,
}
impl PinnedNetworkSpace {
    pub fn new(space_id: String, authority_key: [u8;32]) -> Result<Self, SdkError> {
        if !nestlink_protocol::valid_id(&space_id) || authority_key == [0;32] { return Err(SdkError::Invalid); }
        Ok(Self { space_id, authority_key, allow_loopback_node: false })
    }
    pub fn with_loopback_node(mut self, allowed: bool) -> Self { self.allow_loopback_node = allowed; self }
    pub fn space_id(&self) -> &str { &self.space_id }
    pub fn authority_key(&self) -> &[u8;32] { &self.authority_key }
}

/// A short-lived control-plane readback for one exact business permit and login.
/// It retains signed credentials privately and does not implement Debug.
pub struct VerifiedRemoteRelay {
    pin: PinnedNetworkSpace,
    deployment: String,
    security_epoch: u64,
    origin: String,
    login_session: String,
    policy_epoch: u64,
    revoked: BTreeSet<String>,
    permit_digest: [u8;32],
    path: VerifiedNetworkPath,
    connectivity: VerifiedNetworkGrant,
    transit: VerifiedNetworkGrant,
    view: NetworkRemoteRelayView,
    fingerprint: [u8;32],
    fetched: Instant,
    deadline: Instant,
}
impl VerifiedRemoteRelay {
    pub fn allocation_id(&self) -> &str { &self.view.allocation_id }
    pub fn deadline(&self) -> Instant { self.deadline }
    fn context(&self) -> Result<NetworkVerification<'_>, SdkError> {
        Ok(NetworkVerification { authority_key: &self.pin.authority_key,
            deployment_id: &self.deployment, space_id: &self.pin.space_id,
            policy_epoch: self.policy_epoch, now_ms: unix_ms()?, revoked_grant_ids: &self.revoked })
    }
    pub(super) fn bound_to(&self, sdk: &Sdk, permit: &VerifiedPermit) -> bool {
        sdk.trust.deployment_id == self.deployment && sdk.health.security_epoch == self.security_epoch
            && sdk.origin.as_str() == self.origin && permit.digest() == self.permit_digest
            && sdk.login.as_ref().is_some_and(|login| login.principal.session_id == self.login_session)
            && Instant::now() < self.deadline && self.fetched.elapsed() < Duration::from_secs(5)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_handoff(
        &self, sdk: &Sdk, permit: &VerifiedPermit, current: &NetworkRemoteRelayView,
        stop: &watch::Receiver<Option<StopReason>>, cancel: &watch::Receiver<bool>, deadline: Instant,
    ) -> Result<(), SessionEstablishError> {
        // timeout_at polls a ready HTTP response before its timer. The final
        // transfer must independently recheck every terminal setup condition.
        let current_matches = self.bound_to(sdk, permit) && response_digest(current)? == self.fingerprint;
        if super::setup_is_stopped(stop) { return Err(RemoteError::Stopped.into()); }
        if cancel_is_stopped(cancel) { return Err(SessionEstablishError::Cancelled); }
        if Instant::now() >= deadline { return Err(SdkError::Timeout.into()); }
        if !current_matches {
            return Err(SdkError::Trust.into());
        }
        Ok(())
    }
}

fn unix_ms() -> Result<u64, SdkError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| SdkError::Trust)?
        .as_millis().try_into().map_err(|_| SdkError::Invalid)
}
fn response_digest(view: &NetworkRemoteRelayView) -> Result<[u8;32], SdkError> {
    Ok(digest(&serde_json::to_vec(view)?))
}

impl Sdk {
    /// GET performs current membership, business, quota, node-runtime and
    /// revocation checks in one server transaction. Local verification then
    /// binds its exact returned objects to the operator pin and both devices.
    pub async fn verified_network_remote_relay(
        &self, pin: &PinnedNetworkSpace, local: &DeviceIdentity,
        permit: &VerifiedPermit, peer_key: &[u8;32], allocation_id: &str,
    ) -> Result<VerifiedRemoteRelay, SdkError> {
        let started = Instant::now();
        let view = self.network_remote_relay(&pin.space_id, allocation_id).await?;
        self.verify_relay_readback(pin, local, permit, peer_key, allocation_id, view, started)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_relay_readback(
        &self, pin: &PinnedNetworkSpace, local: &DeviceIdentity, permit: &VerifiedPermit,
        peer_key: &[u8;32], allocation_id: &str, view: NetworkRemoteRelayView, started: Instant,
    ) -> Result<VerifiedRemoteRelay, SdkError> {
        let now = unix_ms()?;
        let business = permit.claims();
        let controller = business.controller_device_id == local.device_id;
        let host = business.host_device_id == local.device_id;
        let (controller_key, host_key) = if controller { (local.identity.public_key(), *peer_key) }
            else { (*peer_key, local.identity.public_key()) };
        if controller == host || permit.issuer() != self.trust.permit_issuer
            || business.deployment_id != self.trust.deployment_id || business.security_epoch != self.health.security_epoch
            || business.controller_key_sha256 != digest(&controller_key) || business.host_key_sha256 != digest(&host_key)
            || business.issued_at_unix_ms > now || business.expires_at_unix_ms <= now
            || view.allocation_id != allocation_id || !nestlink_protocol::valid_id(allocation_id)
            || view.path.request_id != business.session_id || started.elapsed() >= Duration::from_secs(5)
            || !nestlink_protocol::valid_id(&view.node.node_id) || view.node.revision == 0
        { return Err(SdkError::Trust); }
        view.node.endpoints.validate()?;
        let signed_path = crate::network_management::decode_network_grant(&view.path.path)?;
        let unverified = GrantClaims::decode_canonical(&signed_path.claims)?;
        let policy_epoch = unverified.scope().policy_epoch;
        let revoked = BTreeSet::new();
        // The epoch is authenticated below. Its currentness comes only from
        // this fresh authenticated readback, never from a peer's certificate.
        let context = NetworkVerification { authority_key: &pin.authority_key, deployment_id: &self.trust.deployment_id,
            space_id: &pin.space_id, policy_epoch, now_ms: now, revoked_grant_ids: &revoked };
        let mut members = Vec::with_capacity(2);
        for (view, installation, key) in [
            (&view.path.controller_membership, &business.controller_device_id, &controller_key),
            (&view.path.host_membership, &business.host_device_id, &host_key),
        ] {
            let grant = verify_network_grant(&crate::network_management::decode_network_grant(view)?, &context)?;
            let GrantClaims::Membership(member) = grant.claims() else { return Err(SdkError::Trust); };
            let epoch = member.membership_epoch;
            members.push(VerifiedMembership::from_grant(grant, &context, installation, key, epoch)?);
        }
        let connectivity = verify_network_grant(&crate::network_management::decode_network_grant(&view.path.connectivity)?, &context)?;
        let path = VerifiedNetworkPath::from_grants(&context, [members.remove(0), members.remove(0)],
            connectivity.clone(), verify_network_grant(&signed_path, &context)?, permit.digest())?;
        let transit = verify_network_grant(&crate::network_management::decode_network_grant(&view.transit)?, &context)?;
        let GrantClaims::Transit(forward) = transit.claims() else { return Err(SdkError::Trust); };
        if forward.route_id != allocation_id || path.claims().policy.allow_direct
            || view.node.endpoints.quic_uri.is_none() { return Err(SdkError::Trust); }
        let (authorization, _owner) = RouteAuthorization::remote(&context, &path, &connectivity, &transit, permit)?;
        let deadline = authorization.deadline();
        let fingerprint = response_digest(&view)?;
        Ok(VerifiedRemoteRelay { pin: pin.clone(), deployment: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch, origin: self.origin.as_str().into(),
            login_session: self.login.as_ref().ok_or(SdkError::SignIn)?.principal.session_id.clone(),
            policy_epoch, revoked, permit_digest: permit.digest(), path, connectivity, transit,
            view, fingerprint, fetched: started, deadline })
    }

    /// Establish only the fixed node returned by current control-plane state,
    /// prove its fresh challenge, and run the existing endpoint business proof.
    /// Private destination prefixes remain a local operator decision.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_network_remote_relay(
        &self, route: VerifiedRemoteRelay, bind: SocketAddr, local: &DeviceIdentity,
        peer_key: &[u8;32], setup: SessionSetup, address_policy: &AddressPolicy,
        mut cancel: watch::Receiver<bool>, deadline: Instant,
    ) -> Result<ChannelRuntime, SessionEstablishError> {
        let permit = setup.session.current_verified_permit().clone();
        if !route.bound_to(self, &permit) { return Err(SdkError::Trust.into()); }
        let deadline = deadline.min(route.deadline);
        let context = route.context()?;
        let (authorization, _keep) = RouteAuthorization::remote(&context, &route.path, &route.connectivity, &route.transit, &permit).map_err(RemoteError::from)?;
        let binding = authorization.binding_digest();
        let relay = authorization.relay();
        let uri = url::Url::parse(route.view.node.endpoints.quic_uri.as_deref().ok_or(SdkError::Trust)?)
            .map_err(|_| SdkError::Invalid)?;
        let host = uri.host().ok_or(SdkError::Invalid)?;
        let port = uri.port().filter(|port| *port != 0).ok_or(SdkError::Invalid)?;
        let mut stop = setup.lifecycle.stop.clone();
        let addresses = tokio::select! { biased;
            _ = super::wait_setup_stop(&mut stop) => return Err(RemoteError::Stopped.into()),
            _ = cancelled(&mut cancel) => return Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout_at(deadline, crate::native::resolve_signed_node_host(host, port)) => result.map_err(|_| SdkError::Timeout)??,
        };
        // Validate the complete DNS set before making any connection. A mixed
        // answer cannot turn a registered node name into a local-network probe.
        if addresses.iter().any(|address| {
            let ip = address.ip().to_canonical();
            if ip.is_loopback() { !(route.pin.allow_loopback_node && route.view.node.endpoints.allow_loopback) }
            else { !address_policy.allows(ip) }
        }) { return Err(SdkError::Trust.into()); }
        let address = addresses.into_iter().find(|address| address.is_ipv4() == bind.is_ipv4()).ok_or(SdkError::Invalid)?;
        let mut pending = nestlink_transport_quic::routed::AdjacencyEndpoint::bind_node(bind, &local.identity, relay)
            .map_err(SdkError::NodeQuic)?;
        let connected = tokio::select! { biased;
            _ = super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = pending.connect_node(address, &local.identity, &local.device_id, &route.view.allocation_id, binding, deadline) => result.map_err(SdkError::NodeQuic).map_err(SessionEstablishError::from),
        };
        let adjacency = match connected {
            Ok(adjacency) => adjacency,
            Err(error) => { pending.close_and_wait(Instant::now() + Duration::from_secs(5)).await.map_err(RemoteError::Cleanup)?; return Err(error); },
        };
        let observer = RemoteRouteObserver { client: self.client.clone(), origin: self.origin.clone(),
            token: Secret::from_text(self.login.as_ref().ok_or(SdkError::SignIn)?.access.expose().into()),
            path: format!("/network/spaces/{}/relays/{}", route.pin.space_id, route.view.allocation_id),
            fingerprint: route.fingerprint, deadline: route.deadline };
        let proved = super::authorize_remote_observed(RemoteRouteAuthority { context: &context,
            path: &route.path, connectivity: &route.connectivity, transit: &route.transit },
            adjacency, setup, local, peer_key, deadline, Some(observer), Some(cancel.clone())).await;
        let mut channels = match proved {
            Ok(channels) => channels,
            Err(error) => {
                // Cleanup errors must remain visible even if cancellation was
                // the original cause; no release receipt may be implied.
                if cancel_is_stopped(&cancel) && !matches!(&error, RemoteError::Cleanup(_)) {
                    return Err(SessionEstablishError::Cancelled);
                }
                return Err(error.into());
            },
        };
        let current = tokio::select! { biased;
            _ = super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.network_remote_relay(&route.pin.space_id, &route.view.allocation_id)) => {
                result.map_err(|_| SdkError::Timeout).and_then(|value| value).map_err(SessionEstablishError::from)
            },
        };
        let handoff = current.and_then(|current| route.validate_handoff(self, &permit, &current, &stop, &cancel, deadline));
        if let Err(error) = handoff {
            let _ = channels.lease_control().stop(StopReason::Revoked);
            tokio::time::timeout(Duration::from_secs(5), channels.wait_stopped()).await
                .map_err(|_| RemoteError::Cleanup(io::ErrorKind::TimedOut.into()))??;
            return Err(error);
        }
        Ok(channels)
    }
}
pub(super) fn cancel_is_stopped(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow() || cancel.has_changed().is_err()
}
pub(super) async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if cancel_is_stopped(cancel) { return; }
        if cancel.changed().await.is_err() { return; }
    }
}

pub(super) struct RemoteRouteObserver {
    client: reqwest::Client,
    origin: url::Url,
    token: Secret,
    path: String,
    fingerprint: [u8;32],
    deadline: Instant,
}
impl RemoteRouteObserver {
    pub(super) fn spawn(self, lease: nestlink_remote::LeaseControl) -> TaskOwner {
        TaskOwner::new(tokio::spawn(async move {
            let _stop_on_drop = ObserverStop(lease.clone());
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { biased;
                    _ = tokio::time::sleep_until(self.deadline) => { let _ = lease.stop(StopReason::Expired); return; },
                    _ = interval.tick() => {},
                }
                let result = tokio::time::timeout_at(self.deadline.min(Instant::now() + Duration::from_secs(2)),
                    crate::request::<NetworkRemoteRelayView>(&self.client, &self.origin, reqwest::Method::GET,
                        &self.path, None, Some(self.token.expose()))).await;
                if !matches!(result, Ok(Ok(Some(view))) if response_digest(&view).ok() == Some(self.fingerprint)) { return; }
                if lease.remaining().is_err() { return; }
            }
        }))
    }
}
struct ObserverStop(nestlink_remote::LeaseControl);
impl Drop for ObserverStop {
    fn drop(&mut self) { let _ = self.0.stop(StopReason::Revoked); }
}
