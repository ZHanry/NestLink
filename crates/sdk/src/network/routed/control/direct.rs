//! A current signed direct path admitted to the original native socket owner.
use super::*;
use crate::network::{LegacyConnection, LegacyEndpoint};
use nestlink_policy::PathSet;
use nestlink_protocol::api::NetworkRemotePathView;

/// Obtained only from authenticated management readback and a local space pin.
/// Membership never replaces the independently approved business permit.
pub struct VerifiedRemoteDirect {
    pin: PinnedNetworkSpace,
    permit: VerifiedPermit,
    local_device: String,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    origin: String,
    login_session: String,
    security_epoch: u64,
    view: NetworkRemotePathView,
    fingerprint: [u8; 32],
    transport_group: [u8; 32],
    fetched: Instant,
    deadline: Instant,
}
impl VerifiedRemoteDirect {
    pub fn path_grant_id(&self) -> &str { &self.view.path.grant_id }
    pub fn deadline(&self) -> Instant { self.deadline }
    pub fn membership_grant_ids(&self) -> [&str; 2] {
        [&self.view.controller_membership.grant_id, &self.view.host_membership.grant_id]
    }
    fn bound_to(&self, sdk: &Sdk, local: &DeviceIdentity, peer: &[u8; 32]) -> bool {
        self.origin == sdk.origin.as_str()
            && self.security_epoch == sdk.health.security_epoch
            && self.permit.claims().deployment_id == sdk.trust.deployment_id
            && self.permit.issuer() == sdk.trust.permit_issuer
            && local.device_id == self.local_device
            && local.identity.public_key() == self.local_key
            && peer == &self.peer_key
            && sdk.login.as_ref().is_some_and(|login| login.principal.session_id == self.login_session)
            && Instant::now() < self.deadline
    }
    /// One current server transaction checks membership, consent and revocation.
    /// A changed response cannot silently replace this transport group's scope.
    pub async fn check_current(&self, sdk: &Sdk, local: &DeviceIdentity, peer: &[u8; 32]) -> Result<(), SdkError> {
        if !self.bound_to(sdk, local, peer) { return Err(SdkError::Trust); }
        let view = tokio::time::timeout_at(self.deadline, sdk.network_remote_path(self.pin.space_id(), self.path_grant_id()))
            .await.map_err(|_| SdkError::Timeout)??;
        if !self.bound_to(sdk, local, peer) || response_digest(&view)? != self.fingerprint {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    /// Reuses native ICE, the original Scheduler and ChannelRuntime. Direct-only
    /// admission cannot discover a relay or carry a later relay migration.
    #[allow(clippy::too_many_arguments)]
    pub async fn establish(
        self,
        mut endpoint: LegacyEndpoint,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer: &[u8; 32],
        mut options: crate::native::NativeMediaSessionOptions,
        stun: Vec<SocketAddr>,
        cancel: watch::Receiver<bool>,
    ) -> Result<(LegacyConnection, Self), SessionEstablishError> {
        if !self.bound_to(sdk, local, peer)
            || self.fetched.elapsed() >= Duration::from_secs(5)
            || endpoint.native().verified_permit().digest() != self.permit.digest()
            || !options.session.local_paths.contains(Path::Direct)
            || options.relay_node_id.is_some()
        {
            endpoint.close_and_wait(Instant::now() + Duration::from_secs(5)).await.map_err(RemoteError::from)?;
            return Err(SdkError::Trust.into());
        }
        options.session.local_paths = PathSet::DIRECT;
        if let Err(error) = endpoint.bind_network_direct(self.path_grant_id().into(), self.transport_group, self.deadline) {
            endpoint.close_and_wait(Instant::now() + Duration::from_secs(5)).await.map_err(RemoteError::from)?;
            return Err(error.into());
        }
        let mut session = endpoint.establish_with_media(sdk, local, options, &[], stun, cancel).await?;
        if let Err(error) = self.check_current(sdk, local, peer).await {
            session.close_and_wait(StopReason::Revoked, Instant::now() + Duration::from_secs(5)).await?;
            return Err(error.into());
        }
        Ok((session, self))
    }
}
impl Sdk {
    /// A GET, rather than a peer-supplied certificate, supplies freshness.
    pub async fn verified_network_remote_direct(
        &self, pin: &PinnedNetworkSpace, local: &DeviceIdentity,
        permit: &VerifiedPermit, peer: &[u8; 32], path_id: &str,
    ) -> Result<VerifiedRemoteDirect, SdkError> {
        let started = Instant::now();
        let view = self.network_remote_path(pin.space_id(), path_id).await?;
        self.verify_direct_readback(pin, local, permit, peer, path_id, view, started)
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::network::routed) fn verify_direct_readback(
        &self, pin: &PinnedNetworkSpace, local: &DeviceIdentity,
        permit: &VerifiedPermit, peer: &[u8; 32], path_id: &str,
        view: NetworkRemotePathView, started: Instant,
    ) -> Result<VerifiedRemoteDirect, SdkError> {
        let now = unix_ms()?;
        let business = permit.claims();
        let controller = business.controller_device_id == local.device_id;
        let host = business.host_device_id == local.device_id;
        let (controller_key, host_key) = if controller { (local.identity.public_key(), *peer) }
            else { (*peer, local.identity.public_key()) };
        if controller == host || permit.issuer() != self.trust.permit_issuer
            || business.deployment_id != self.trust.deployment_id
            || business.security_epoch != self.health.security_epoch
            || business.controller_key_sha256 != digest(&controller_key)
            || business.host_key_sha256 != digest(&host_key)
            || business.issued_at_unix_ms > now || business.expires_at_unix_ms <= now
            || !business.paths.contains(&(Path::Direct as i32))
            || view.request_id != business.session_id || view.path.grant_id != path_id
            || !nestlink_protocol::valid_id(path_id) || started.elapsed() >= Duration::from_secs(5)
        { return Err(SdkError::Trust); }
        let signed = crate::network_management::decode_network_grant(&view.path)?;
        let epoch = GrantClaims::decode_canonical(&signed.claims)?.scope().policy_epoch;
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: pin.authority_key(), deployment_id: &self.trust.deployment_id,
            space_id: pin.space_id(), policy_epoch: epoch, now_ms: now, revoked_grant_ids: &revoked,
        };
        let mut members = Vec::with_capacity(2);
        for (view, installation, key) in [
            (&view.controller_membership, &business.controller_device_id, &controller_key),
            (&view.host_membership, &business.host_device_id, &host_key),
        ] {
            let grant = verify_network_grant(&crate::network_management::decode_network_grant(view)?, &context)?;
            let GrantClaims::Membership(member) = grant.claims() else { return Err(SdkError::Trust); };
            let membership_epoch = member.membership_epoch;
            members.push(VerifiedMembership::from_grant(grant, &context, installation, key, membership_epoch)?);
        }
        let path = VerifiedNetworkPath::from_grants(&context, [members.remove(0), members.remove(0)],
            verify_network_grant(&crate::network_management::decode_network_grant(&view.connectivity)?, &context)?,
            verify_network_grant(&signed, &context)?, permit.digest())?;
        path.check_route(&context, &[])?;
        if path.purpose() != nestlink_protocol::network::Purpose::RemoteControl
            || !path.claims().policy.allow_direct || !path.claims().policy.relays.is_empty()
            || path.claims().policy.max_hops != 0
        { return Err(SdkError::Trust); }
        let remaining = path.claims().scope.expires_at_ms.checked_sub(now).ok_or(SdkError::Trust)?;
        let deadline = started + Duration::from_millis(remaining.min(60_000));
        if Instant::now() >= deadline { return Err(SdkError::Timeout); }
        Ok(VerifiedRemoteDirect {
            pin: pin.clone(), permit: permit.clone(), local_device: local.device_id.clone(),
            local_key: local.identity.public_key(), peer_key: *peer, origin: self.origin.as_str().into(),
            login_session: self.login.as_ref().ok_or(SdkError::SignIn)?.principal.session_id.clone(),
            security_epoch: self.health.security_epoch, fingerprint: response_digest(&view)?,
            transport_group: path.transport_group_id(), view, fetched: started, deadline,
        })
    }
}
