//! Read-only original-group candidates from an authenticated current readback.
//! No selection, probe, carrier replacement or business channel is created here.
use super::*;
use nestlink_identity::network::{VerifiedRemoteRouteSetGrants, verify_remote_route_set_grants};
use nestlink_protocol::api::{NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetView, NodeEndpointsView};
mod connect;
mod continuation;
mod recovery;
pub use continuation::{ContinuousRouteSetSession, RouteSetRecoveryProposal, RouteSetContinuationStatus};
pub use recovery::{RouteSetRecoverySource, RouteSetRecoveryConfig, RecoveredNetworkSession};

pub(super) fn original_fingerprint(view: &NetworkRemoteRouteSetView) -> Result<[u8;32], SdkError> {
    let mut original = view.clone();
    for member in &mut original.members { member.available = false; }
    response_digest(&original)
}

pub struct VerifiedRemoteRouteSet {
    pin: PinnedNetworkSpace,
    deployment: String,
    security_epoch: u64,
    origin: String,
    login_session: String,
    local_device: String,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    policy_epoch: u64,
    permit_digest: [u8; 32],
    grants: VerifiedRemoteRouteSetGrants,
    view: NetworkRemoteRouteSetView,
    fingerprint: [u8; 32],
    fetched: Instant,
    deadline: Instant,
}
pub struct VerifiedRemoteRouteCandidate<'a> {
    allocation_id: &'a str,
    node: &'a NodeEndpointsView,
    route_binding: [u8; 32],
    byte_limit: u64,
    available: bool,
    relay: nestlink_protocol::network::PeerId,
}
impl VerifiedRemoteRouteCandidate<'_> {
    pub fn allocation_id(&self) -> &str { self.allocation_id }
    pub fn node(&self) -> &NodeEndpointsView { self.node }
    pub fn route_binding(&self) -> [u8; 32] { self.route_binding }
    pub fn byte_limit(&self) -> u64 { self.byte_limit }
    /// Fresh management observation only. The enclosing set's currentness must
    /// still be checked before admission; retaining metadata grants no I/O.
    pub fn available(&self) -> bool { self.available }
    pub fn relay(&self) -> nestlink_protocol::network::PeerId { self.relay }
}
impl VerifiedRemoteRouteSet {
    pub fn set_id(&self) -> &str { &self.view.set_id }
    pub fn path_grant_id(&self) -> &str { &self.grants.path.claims().scope.grant_id }
    pub fn transport_group(&self) -> [u8; 32] { self.grants.path.transport_group_id() }
    pub fn deadline(&self) -> Instant { self.deadline }
    pub fn candidates(&self) -> [VerifiedRemoteRouteCandidate<'_>; 2] {
        [0, 1].map(|index| VerifiedRemoteRouteCandidate {
            allocation_id: &self.view.members[index].allocation_id,
            node: &self.view.members[index].node,
            route_binding: self.grants.bindings[index].digest,
            byte_limit: self.grants.bindings[index].byte_limit,
            available: self.view.members[index].available,
            relay: self.grants.bindings[index].relay,
        })
    }
    /// Return metadata eligible for a new preparation only while this exact
    /// authenticated observation remains current and the member is available.
    pub fn candidate_for_admission(&self, sdk: &Sdk, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8;32], index: usize) -> Option<VerifiedRemoteRouteCandidate<'_>> {
        if index >= 2 || !self.is_current_for(sdk,local,permit,peer_key) || !self.view.members[index].available { return None; }
        self.candidates().into_iter().nth(index)
    }
    /// A retained handle never turns a five-second management observation into
    /// indefinite authority, nor crosses login, business or local identity.
    pub fn is_current_for(&self, sdk: &Sdk, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8; 32]) -> bool {
        if self.deployment != sdk.trust.deployment_id || self.security_epoch != sdk.health.security_epoch
            || self.origin != sdk.origin.as_str() || self.permit_digest != permit.digest()
            || self.local_device != local.device_id || self.local_key != local.identity.public_key()
            || self.peer_key != *peer_key || self.fetched.elapsed() >= Duration::from_secs(5)
            || Instant::now() >= self.deadline
            || sdk.login.as_ref().is_none_or(|login| login.principal.session_id != self.login_session)
        { return false; }
        let Ok(now) = unix_ms() else { return false; };
        let revoked = BTreeSet::new();
        let context = NetworkVerification { authority_key: &self.pin.authority_key,
            deployment_id: &self.deployment, space_id: &self.pin.space_id,
            policy_epoch: self.policy_epoch, now_ms: now, revoked_grant_ids: &revoked };
        self.grants.path.check_current(&context).is_ok()
            && self.grants.transits.iter().all(|transit| nestlink_identity::network::remote_route_binding(&context, &self.grants.path, &self.grants.connectivity, transit, permit).is_ok())
    }
    /// Refresh each candidate's availability without treating one failed node
    /// as revocation of the original group, and without extending its deadline.
    pub async fn refresh_current(&self, sdk: &Sdk, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8; 32]) -> Result<Self, SdkError> {
        if !self.is_current_for(sdk, local, permit, peer_key) { return Err(SdkError::Trust); }
        let mut current = sdk.verified_network_remote_route_set(&self.pin,local,permit,peer_key,&self.view.set_id).await?;
        if !self.is_current_for(sdk,local,permit,peer_key) || current.fingerprint != self.fingerprint { return Err(SdkError::Trust); }
        current.deadline = current.deadline.min(self.deadline);
        Ok(current)
    }
}
impl Sdk {
    pub async fn verified_network_remote_route_set(&self, pin: &PinnedNetworkSpace, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8; 32], set: &str) -> Result<VerifiedRemoteRouteSet, SdkError> {
        let started = Instant::now();
        let view = self.network_remote_route_set(&pin.space_id, set).await?;
        self.verify_route_set_readback(pin, local, permit, peer_key, set, view, started)
    }
    /// POST reserves; the subsequent exact authenticated GET supplies currentness.
    pub async fn reserve_verified_network_remote_route_set(&self, pin: &PinnedNetworkSpace, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8; 32], request: NetworkRemoteRouteSetRequest) -> Result<VerifiedRemoteRouteSet, SdkError> {
        let set = request.set_id.clone();
        let issued = self.reserve_network_remote_route_set(&pin.space_id, local, permit, request).await?;
        let current = self.verified_network_remote_route_set(pin, local, permit, peer_key, &set).await?;
        if original_fingerprint(&issued)? != current.fingerprint { return Err(SdkError::Trust); }
        Ok(current)
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::network::routed) fn verify_route_set_readback(&self, pin: &PinnedNetworkSpace, local: &DeviceIdentity, permit: &VerifiedPermit, peer_key: &[u8; 32], set: &str, view: NetworkRemoteRouteSetView, started: Instant) -> Result<VerifiedRemoteRouteSet, SdkError> {
        let now = unix_ms()?;
        let business = permit.claims();
        let controller = business.controller_device_id == local.device_id;
        let host = business.host_device_id == local.device_id;
        let (controller_key, host_key) = if controller { (local.identity.public_key(), *peer_key) } else { (*peer_key, local.identity.public_key()) };
        if controller == host || permit.issuer() != self.trust.permit_issuer
            || business.deployment_id != self.trust.deployment_id || business.security_epoch != self.health.security_epoch
            || business.controller_key_sha256 != digest(&controller_key) || business.host_key_sha256 != digest(&host_key)
            || business.issued_at_unix_ms > now || business.expires_at_unix_ms <= now
            || view.set_id != set || !nestlink_protocol::valid_id(set) || started.elapsed() >= Duration::from_secs(5)
        { return Err(SdkError::Trust); }
        let path = crate::network_management::decode_network_grant(&view.path.path)?;
        let policy_epoch = GrantClaims::decode_canonical(&path.claims)?.scope().policy_epoch;
        let revoked = BTreeSet::new();
        let context = NetworkVerification { authority_key: &pin.authority_key, deployment_id: &self.trust.deployment_id,
            space_id: &pin.space_id, policy_epoch, now_ms: now, revoked_grant_ids: &revoked };
        let grants = verify_remote_route_set_grants(&context, &view, permit)?;
        let mut deadline = started + Duration::from_secs(30);
        for transit in &grants.transits {
            let (authorization, _owner) = RouteAuthorization::remote(&context, &grants.path, &grants.connectivity, transit, permit)?;
            deadline = deadline.min(authorization.deadline());
        }
        if Instant::now() >= deadline { return Err(SdkError::Timeout); }
        Ok(VerifiedRemoteRouteSet { pin: pin.clone(), deployment: self.trust.deployment_id.clone(), security_epoch: self.health.security_epoch,
            origin: self.origin.as_str().into(), login_session: self.login.as_ref().ok_or(SdkError::SignIn)?.principal.session_id.clone(),
            local_device: local.device_id.clone(), local_key: local.identity.public_key(), peer_key: *peer_key,
            policy_epoch, permit_digest: permit.digest(), grants, fingerprint: original_fingerprint(&view)?, view, fetched: started, deadline })
    }
}
