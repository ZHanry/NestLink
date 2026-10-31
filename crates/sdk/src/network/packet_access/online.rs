//! The original online one-use claim and live management snapshot owner. A
//! saved JSON response can never claim a new packet budget or renew this owner.
use super::*;
use crate::{DeviceIdentity, Sdk, SdkError, network::routed::PinnedNetworkSpace};
use nestlink_identity::{digest, network::verify_network_grant};
use nestlink_protocol::network_access::{NetworkAccessStart, NetworkAccessView};
use std::collections::BTreeSet;

pub struct OnlinePacketAccess {
    pin: PinnedNetworkSpace,
    deployment: String,
    origin: String,
    login_session: String,
    security_epoch: u64,
    local_device: String,
    local_public: [u8; 32],
    owner_id: String,
    grant_id: String,
    original: [u8; 32],
    fetched: Instant,
    policy: VerifiedPacketAccess,
}
impl OnlinePacketAccess {
    /// The caller must obtain `approved_digest` by an explicit local user
    /// choice. Neither a directory listing nor management issuance implies it.
    /// `owner_id` is a new UUID for this exact process lifetime. Reuse, including
    /// a retry after a lost POST response, fails closed at the durable server.
    pub async fn start(
        sdk: &Sdk,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        grant_id: &str,
        approved_digest: [u8; 32],
        owner_id: String,
    ) -> Result<Self, SdkError> {
        if !nestlink_protocol::valid_id(grant_id) || !nestlink_protocol::valid_id(&owner_id)
            || approved_digest == [0; 32]
        { return Err(SdkError::Invalid); }
        let login_session = sdk.login.as_ref().ok_or(SdkError::SignIn)?.principal.session_id.clone();
        let started = Instant::now();
        let view = tokio::time::timeout(Duration::from_secs(2), sdk.network_access(pin.space_id(), grant_id))
            .await.map_err(|_| SdkError::Timeout)??;
        let policy = verify(sdk, pin, local, grant_id, approved_digest, &view)?;
        if started.elapsed() >= Duration::from_secs(2) { return Err(SdkError::Timeout); }
        tokio::time::timeout(Duration::from_secs(2), sdk.start_network_access(pin.space_id(), grant_id,
            NetworkAccessStart { installation_id: local.device_id.clone(), owner_id: owner_id.clone() }))
            .await.map_err(|_| SdkError::Timeout)??;
        // A consumed claim is never retried or replaced. Re-read only the
        // original graph and address epochs after the irreversible one-use POST.
        let mut owner = Self { pin: pin.clone(), deployment: sdk.trust.deployment_id.clone(),
            origin: sdk.origin.as_str().into(), login_session, security_epoch: sdk.health.security_epoch,
            local_device: local.device_id.clone(), local_public: local.identity.public_key(),
            owner_id, grant_id: grant_id.into(), original: fingerprint(&view)?, fetched: started, policy };
        if let Err(error) = owner.refresh(sdk).await { owner.stop(); return Err(error); }
        Ok(owner)
    }
    pub fn owner_id(&self) -> &str { &self.owner_id }
    pub fn grant_id(&self) -> &str { &self.grant_id }
    pub fn business_digest(&self) -> [u8; 32] { self.policy.business_digest() }
    pub fn transport_group(&self) -> [u8; 32] { self.policy.path.transport_group_id() }
    pub fn remote_peer(&self) -> PeerId { self.policy.remote_peer() }
    pub fn local_hosts(&self) -> [IpAddr; 2] {
        if self.policy.local == self.policy.claims.source { self.policy.source.hosts } else { self.policy.destination.hosts }
    }
    pub fn remote_hosts(&self) -> [IpAddr; 2] {
        if self.policy.local == self.policy.claims.source { self.policy.destination.hosts } else { self.policy.source.hosts }
    }
    pub fn spent_bytes(&self) -> u64 { self.policy.spent_bytes() }
    pub fn remaining_lifetime(&self) -> Duration { self.policy.deadline.saturating_duration_since(Instant::now()) }
    pub fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction {
        if self.policy.local == self.policy.path.peers().first {
            nestlink_protocol::network_datagram::Direction::FirstToSecond
        } else { nestlink_protocol::network_datagram::Direction::SecondToFirst }
    }
    pub fn stop(&mut self) { self.policy.stop(); }
    fn bound_to(&self, sdk: &Sdk) -> bool {
        !self.policy.stopped && self.deployment == sdk.trust.deployment_id
            && self.origin == sdk.origin.as_str() && self.security_epoch == sdk.health.security_epoch
            && sdk.login.as_ref().is_some_and(|login| login.principal.session_id == self.login_session)
            && Instant::now() < self.policy.deadline
    }
    /// Invoke at least once per second. Failure and observation gaps permanently
    /// stop this original budget, including when the center later recovers.
    pub async fn refresh(&mut self, sdk: &Sdk) -> Result<(), SdkError> {
        let result = self.refresh_inner(sdk).await;
        if result.is_err() { self.stop(); }
        result
    }
    async fn refresh_inner(&mut self, sdk: &Sdk) -> Result<(), SdkError> {
        if !self.bound_to(sdk) || self.fetched.elapsed() >= DIRECTORY_FRESHNESS {
            return Err(SdkError::Trust);
        }
        let view = tokio::time::timeout(self.remaining_lifetime().min(Duration::from_secs(2)),
            sdk.network_access(self.pin.space_id(), &self.grant_id))
            .await.map_err(|_| SdkError::Timeout)??;
        if !self.bound_to(sdk) || fingerprint(&view)? != self.original || self.fetched.elapsed() >= DIRECTORY_FRESHNESS {
            return Err(SdkError::Trust);
        }
        let revoked = BTreeSet::new();
        let context = self.context(&revoked)?;
        let source = PacketPeerAuthority::from_directory(&context, self.policy.source.member.clone(), &view.address_directory, self.policy.source.exports.clone())?;
        let destination = PacketPeerAuthority::from_directory(&context, self.policy.destination.member.clone(), &view.address_directory, self.policy.destination.exports.clone())?;
        self.policy.refresh_addresses(&context, source, destination)?;
        self.fetched = Instant::now();
        Ok(())
    }
    fn context<'a>(&'a self, revoked: &'a BTreeSet<String>) -> Result<NetworkVerification<'a>, SdkError> {
        let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_millis())
            .map_err(io::Error::other)?;
        Ok(NetworkVerification { authority_key: self.pin.authority_key(), deployment_id: &self.deployment,
            space_id: self.pin.space_id(), policy_epoch: self.policy.claims.scope.policy_epoch,
            now_ms, revoked_grant_ids: revoked })
    }
    fn admission(&mut self, packet: &[u8], remote: bool) -> io::Result<PacketAdmission> {
        if self.fetched.elapsed() >= DIRECTORY_FRESHNESS { self.stop(); return Err(denied("raw IP online observation gap")); }
        let revoked = BTreeSet::new();
        // Copy only public context so the mutable packet budget never aliases
        // an externally supplied authorization snapshot.
        let pin = self.pin.clone();
        let deployment = self.deployment.clone();
        let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(denied)?.as_millis()).map_err(denied)?;
        let context = NetworkVerification { authority_key: pin.authority_key(), deployment_id: &deployment,
            space_id: pin.space_id(), policy_epoch: self.policy.claims.scope.policy_epoch, now_ms, revoked_grant_ids: &revoked };
        if remote { self.policy.admit_remote(&context, self.policy.remote_peer(), packet) } else { self.policy.admit_local(&context, packet) }
    }
    pub fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { self.admission(packet, false) }
    pub fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { self.admission(packet, true) }
    pub fn matches_local(&self, local: &DeviceIdentity) -> bool {
        local.device_id == self.local_device && local.identity.public_key() == self.local_public
    }
}

fn fingerprint(view: &NetworkAccessView) -> Result<[u8; 32], SdkError> {
    Ok(digest(&serde_json::to_vec(&(&view.source_membership, &view.destination_membership,
        &view.access, &view.connectivity, &view.path))?))
}
fn verify(
    sdk: &Sdk, pin: &PinnedNetworkSpace, local: &DeviceIdentity, grant_id: &str,
    approved: [u8; 32], view: &NetworkAccessView,
) -> Result<VerifiedPacketAccess, SdkError> {
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_millis()).map_err(io::Error::other)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification { authority_key: pin.authority_key(), deployment_id: &sdk.trust.deployment_id,
        space_id: pin.space_id(), policy_epoch: view.address_directory.space.policy_epoch, now_ms, revoked_grant_ids: &revoked };
    let access = verify_network_grant(&crate::network_management::decode_network_grant(&view.access)?, &context)?;
    if access.digest() != approved || access.claims().scope().grant_id != grant_id {
        return Err(SdkError::Trust);
    }
    let mut members = Vec::new();
    for value in [&view.source_membership, &view.destination_membership] {
        let grant = verify_network_grant(&crate::network_management::decode_network_grant(value)?, &context)?;
        let GrantClaims::Membership(member) = grant.claims() else { return Err(SdkError::Trust); };
        let (id, key, epoch) = (member.installation_id.clone(), member.public_key, member.membership_epoch);
        members.push(VerifiedMembership::from_grant(grant, &context, &id, &key, epoch)?);
    }
    let local_member = members.iter().find(|member| member.claims().installation_id == local.device_id).ok_or(SdkError::Trust)?;
    if local_member.claims().public_key != local.identity.public_key() { return Err(SdkError::Trust); }
    let source = PacketPeerAuthority::from_directory(&context, members[0].clone(), &view.address_directory, vec![])?;
    let destination = PacketPeerAuthority::from_directory(&context, members[1].clone(), &view.address_directory, vec![])?;
    let connectivity = verify_network_grant(&crate::network_management::decode_network_grant(&view.connectivity)?, &context)?;
    let path_grant = verify_network_grant(&crate::network_management::decode_network_grant(&view.path)?, &context)?;
    let path = VerifiedNetworkPath::from_grants(&context, [members.remove(0), members.remove(0)], connectivity.clone(), path_grant, approved)?;
    path.check_route(&context, &[])?;
    if !path.claims().policy.relays.is_empty() || path.claims().policy.max_hops != 0 { return Err(SdkError::Trust); }
    Ok(VerifiedPacketAccess::new(&context, path, connectivity, access, PeerId(local.identity.fingerprint()), source, destination)?)
}
