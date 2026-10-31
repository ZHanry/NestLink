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
    subnet_mappings: Vec<nestlink_protocol::subnet::management::SubnetMappingView>,
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
        if !nestlink_protocol::valid_id(grant_id)
            || !nestlink_protocol::valid_id(&owner_id)
            || approved_digest == [0; 32]
        {
            return Err(SdkError::Invalid);
        }
        let login_session = sdk
            .login
            .as_ref()
            .ok_or(SdkError::SignIn)?
            .principal
            .session_id
            .clone();
        let started = Instant::now();
        let view = tokio::time::timeout(
            Duration::from_secs(2),
            sdk.network_access(pin.space_id(), grant_id),
        )
        .await
        .map_err(|_| SdkError::Timeout)??;
        let policy = verify(sdk, pin, local, grant_id, approved_digest, &view)?;
        if started.elapsed() >= Duration::from_secs(2) {
            return Err(SdkError::Timeout);
        }
        tokio::time::timeout(
            Duration::from_secs(2),
            sdk.start_network_access(
                pin.space_id(),
                grant_id,
                NetworkAccessStart {
                    installation_id: local.device_id.clone(),
                    owner_id: owner_id.clone(),
                },
            ),
        )
        .await
        .map_err(|_| SdkError::Timeout)??;
        // A consumed claim is never retried or replaced. Re-read only the
        // original graph and address epochs after the irreversible one-use POST.
        let mut owner = Self {
            pin: pin.clone(),
            deployment: sdk.trust.deployment_id.clone(),
            origin: sdk.origin.as_str().into(),
            login_session,
            security_epoch: sdk.health.security_epoch,
            local_device: local.device_id.clone(),
            local_public: local.identity.public_key(),
            owner_id,
            grant_id: grant_id.into(),
            original: fingerprint(&view)?,
            fetched: started,
            policy,
            subnet_mappings: view.subnet_mappings.clone(),
        };
        if let Err(error) = owner.refresh(sdk).await {
            owner.stop();
            return Err(error);
        }
        Ok(owner)
    }
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn business_digest(&self) -> [u8; 32] {
        self.policy.business_digest()
    }
    pub fn transport_group(&self) -> [u8; 32] {
        self.policy.path.transport_group_id()
    }
    pub fn remote_peer(&self) -> PeerId {
        self.policy.remote_peer()
    }
    pub fn local_hosts(&self) -> [IpAddr; 2] {
        if self.policy.local == self.policy.claims.source {
            self.policy.source.hosts
        } else {
            self.policy.destination.hosts
        }
    }
    pub fn remote_hosts(&self) -> [IpAddr; 2] {
        if self.policy.local == self.policy.claims.source {
            self.policy.destination.hosts
        } else {
            self.policy.source.hosts
        }
    }
    pub fn spent_bytes(&self) -> u64 {
        self.policy.spent_bytes()
    }
    pub fn remaining_lifetime(&self) -> Duration {
        self.policy
            .deadline
            .saturating_duration_since(Instant::now())
    }
    pub fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction {
        if self.policy.local == self.policy.path.peers().first {
            nestlink_protocol::network_datagram::Direction::FirstToSecond
        } else {
            nestlink_protocol::network_datagram::Direction::SecondToFirst
        }
    }
    pub fn stop(&mut self) {
        self.policy.stop();
    }
    fn bound_to(&self, sdk: &Sdk) -> bool {
        !self.policy.stopped
            && self.deployment == sdk.trust.deployment_id
            && self.origin == sdk.origin.as_str()
            && self.security_epoch == sdk.health.security_epoch
            && sdk
                .login
                .as_ref()
                .is_some_and(|login| login.principal.session_id == self.login_session)
            && Instant::now() < self.policy.deadline
    }
    /// Invoke at least once per second. Failure and observation gaps permanently
    /// stop this original budget, including when the center later recovers.
    pub async fn refresh(&mut self, sdk: &Sdk) -> Result<(), SdkError> {
        let result = self.refresh_inner(sdk).await;
        if result.is_err() {
            self.stop();
        }
        result
    }
    async fn refresh_inner(&mut self, sdk: &Sdk) -> Result<(), SdkError> {
        if !self.bound_to(sdk) || self.fetched.elapsed() >= DIRECTORY_FRESHNESS {
            return Err(SdkError::Trust);
        }
        let view = tokio::time::timeout(
            self.remaining_lifetime().min(Duration::from_secs(2)),
            sdk.network_access(self.pin.space_id(), &self.grant_id),
        )
        .await
        .map_err(|_| SdkError::Timeout)??;
        if !self.bound_to(sdk)
            || fingerprint(&view)? != self.original
            || self.fetched.elapsed() >= DIRECTORY_FRESHNESS
        {
            return Err(SdkError::Trust);
        }
        let revoked = BTreeSet::new();
        let pin = self.pin.clone();
        let deployment = self.deployment.clone();
        let context = Self::context(
            &pin,
            &deployment,
            self.policy.claims.scope.policy_epoch,
            &revoked,
        )?;
        let [source_exports,destination_exports] = mapping_exports(&context, &view, [&self.policy.source.member,&self.policy.destination.member], &self.policy.access)?;
        let source = PacketPeerAuthority::from_directory(
            &context,
            self.policy.source.member.clone(),
            &view.address_directory,
            source_exports,
        )?;
        let destination = PacketPeerAuthority::from_directory(
            &context,
            self.policy.destination.member.clone(),
            &view.address_directory,
            destination_exports,
        )?;
        self.policy
            .refresh_addresses(&context, source, destination)?;
        self.subnet_mappings = view.subnet_mappings;
        self.fetched = Instant::now();
        Ok(())
    }
    fn context<'a>(
        pin: &'a PinnedNetworkSpace,
        deployment: &'a str,
        policy_epoch: u64,
        revoked: &'a BTreeSet<String>,
    ) -> Result<NetworkVerification<'a>, SdkError> {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_millis(),
        )
        .map_err(io::Error::other)?;
        Ok(NetworkVerification {
            authority_key: pin.authority_key(),
            deployment_id: deployment,
            space_id: pin.space_id(),
            policy_epoch,
            now_ms,
            revoked_grant_ids: revoked,
        })
    }
    fn admission(&mut self, packet: &[u8], remote: bool) -> io::Result<PacketAdmission> {
        if self.fetched.elapsed() >= DIRECTORY_FRESHNESS {
            self.stop();
            return Err(denied("raw IP online observation gap"));
        }
        let revoked = BTreeSet::new();
        // Copy only public context so the mutable packet budget never aliases
        // an externally supplied authorization snapshot.
        let pin = self.pin.clone();
        let deployment = self.deployment.clone();
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(denied)?
                .as_millis(),
        )
        .map_err(denied)?;
        let context = NetworkVerification {
            authority_key: pin.authority_key(),
            deployment_id: &deployment,
            space_id: pin.space_id(),
            policy_epoch: self.policy.claims.scope.policy_epoch,
            now_ms,
            revoked_grant_ids: &revoked,
        };
        if remote {
            self.policy
                .admit_remote(&context, self.policy.remote_peer(), packet)
        } else {
            self.policy.admit_local(&context, packet)
        }
    }
    pub fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> {
        self.admission(packet, false)
    }
    pub fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> {
        self.admission(packet, true)
    }
    pub fn matches_local(&self, local: &DeviceIdentity) -> bool {
        local.device_id == self.local_device && local.identity.public_key() == self.local_public
    }

    /// Build the privileged adapter's immutable configuration from this exact
    /// live one-use owner. The caller supplies a second explicit local mapping
    /// approval, exact interfaces and original physical carrier endpoints.
    pub fn subnet_plan(&self, consent: crate::network::subnet::SubnetLocalConsent, interfaces: crate::network::subnet::SubnetInterfaces, physical_endpoints: &[IpAddr]) -> io::Result<crate::network::subnet::VerifiedSubnetPlan> {
        use nestlink_identity::subnet::{SubnetGatewayState,verify_subnet_mapping};
        if self.policy.stopped || self.fetched.elapsed()>=DIRECTORY_FRESHNESS || Instant::now()>=self.policy.deadline {return Err(denied("original subnet business owner is no longer current"));}
        let mapping = self.subnet_mappings.iter().find(|mapping| mapping.gateway.public_key==self.local_public).ok_or_else(|| denied("this installation has no explicitly bound local subnet"))?;
        let revoked = BTreeSet::new();
        let context = Self::context(&self.pin,&self.deployment,self.policy.claims.scope.policy_epoch,&revoked).map_err(denied)?;
        let gateway = SubnetGatewayState {node_id:&mapping.gateway.node_id,public_key:&mapping.gateway.public_key,incarnation:&mapping.gateway.incarnation,
            mapping_revision:mapping.gateway.mapping_revision,lease_expires_at_ms:mapping.gateway.lease_expires_at_ms};
        let export = verify_network_grant(&crate::network_management::decode_network_grant(&mapping.route_export).map_err(denied)?,&context).map_err(denied)?;
        let verified = verify_subnet_mapping(&mapping.mapping,&context,export,&gateway).map_err(denied)?;
        let plan = crate::network::subnet::VerifiedSubnetPlan::new(&context,&gateway,verified,self.policy.access.clone(),consent,interfaces,physical_endpoints)?;
        if plan.view().owner_id!=self.owner_id {return Err(denied("subnet approval belongs to another original packet owner"));}
        Ok(plan)
    }
}

fn fingerprint(view: &NetworkAccessView) -> Result<[u8; 32], SdkError> {
    Ok(digest(&serde_json::to_vec(&(
        &view.source_membership,
        &view.destination_membership,
        &view.access,
        &view.connectivity,
        &view.path,
        view.subnet_mappings.iter().map(|mapping| (&mapping.mapping,&mapping.route_export)).collect::<Vec<_>>(),
    ))?))
}
fn verify(
    sdk: &Sdk,
    pin: &PinnedNetworkSpace,
    local: &DeviceIdentity,
    grant_id: &str,
    approved: [u8; 32],
    view: &NetworkAccessView,
) -> Result<VerifiedPacketAccess, SdkError> {
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis(),
    )
    .map_err(io::Error::other)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: pin.authority_key(),
        deployment_id: &sdk.trust.deployment_id,
        space_id: pin.space_id(),
        policy_epoch: view.address_directory.space.policy_epoch,
        now_ms,
        revoked_grant_ids: &revoked,
    };
    let access = verify_network_grant(
        &crate::network_management::decode_network_grant(&view.access)?,
        &context,
    )?;
    if access.digest() != approved || access.claims().scope().grant_id != grant_id {
        return Err(SdkError::Trust);
    }
    let mut members = Vec::new();
    for value in [&view.source_membership, &view.destination_membership] {
        let grant = verify_network_grant(
            &crate::network_management::decode_network_grant(value)?,
            &context,
        )?;
        let GrantClaims::Membership(member) = grant.claims() else {
            return Err(SdkError::Trust);
        };
        let (id, key, epoch) = (
            member.installation_id.clone(),
            member.public_key,
            member.membership_epoch,
        );
        members.push(VerifiedMembership::from_grant(
            grant, &context, &id, &key, epoch,
        )?);
    }
    let local_member = members
        .iter()
        .find(|member| member.claims().installation_id == local.device_id)
        .ok_or(SdkError::Trust)?;
    if local_member.claims().public_key != local.identity.public_key() {
        return Err(SdkError::Trust);
    }
    let [source_exports,destination_exports] = mapping_exports(&context,view,[&members[0],&members[1]],&access)?;
    let source = PacketPeerAuthority::from_directory(
        &context,
        members[0].clone(),
        &view.address_directory,
        source_exports,
    )?;
    let destination = PacketPeerAuthority::from_directory(
        &context,
        members[1].clone(),
        &view.address_directory,
        destination_exports,
    )?;
    let connectivity = verify_network_grant(
        &crate::network_management::decode_network_grant(&view.connectivity)?,
        &context,
    )?;
    let path_grant = verify_network_grant(
        &crate::network_management::decode_network_grant(&view.path)?,
        &context,
    )?;
    let path = VerifiedNetworkPath::from_grants(
        &context,
        [members.remove(0), members.remove(0)],
        connectivity.clone(),
        path_grant,
        approved,
    )?;
    path.check_route(&context, &[])?;
    if !path.claims().policy.relays.is_empty() || path.claims().policy.max_hops != 0 {
        return Err(SdkError::Trust);
    }
    Ok(VerifiedPacketAccess::new(
        &context,
        path,
        connectivity,
        access,
        PeerId(local.identity.fingerprint()),
        source,
        destination,
    )?)
}

fn mapping_exports(context: &NetworkVerification<'_>, view: &NetworkAccessView, members: [&VerifiedMembership;2], access: &VerifiedNetworkGrant) -> Result<[Vec<VerifiedNetworkGrant>;2],SdkError> {
    use nestlink_identity::subnet::{SubnetGatewayState,verify_subnet_mapping};
    let GrantClaims::NetworkAccess(business) = access.claims() else {return Err(SdkError::Trust);};
    if view.subnet_mappings.len()>2 {return Err(SdkError::Trust);}
    let mut result = [Vec::new(),Vec::new()];
    for mapping in &view.subnet_mappings {
        let policy = &mapping.policy;
        if policy.authority_public_key != URL_SAFE_NO_PAD.encode(context.authority_key)
            || policy.deployment_id != context.deployment_id || policy.space_id != context.space_id || policy.policy_epoch != context.policy_epoch
            || policy.observed_at_unix_ms > context.now_ms || context.now_ms-policy.observed_at_unix_ms >= DIRECTORY_FRESHNESS.as_millis() as u64 {
            return Err(SdkError::Trust);
        }
        let export = verify_network_grant(&crate::network_management::decode_network_grant(&mapping.route_export)?,context)?;
        let gateway = SubnetGatewayState {node_id:&mapping.gateway.node_id,public_key:&mapping.gateway.public_key,incarnation:&mapping.gateway.incarnation,
            mapping_revision:mapping.gateway.mapping_revision,lease_expires_at_ms:mapping.gateway.lease_expires_at_ms};
        let verified = verify_subnet_mapping(&mapping.mapping,context,export.clone(),&gateway)?;
        let claims = verified.claims();
        let endpoint = members.iter().position(|member| member.peer()==claims.gateway && member.claims().public_key==claims.gateway_public_key).ok_or(SdkError::Trust)?;
        let prefixes = if endpoint==0 {&business.source_prefixes} else {&business.destination_prefixes};
        if !result[endpoint].is_empty() || prefixes.as_slice()!=[claims.alias]
            || business.scope.not_before_ms<claims.scope.not_before_ms || business.scope.expires_at_ms>verified.effective_expires_at_ms(&gateway)
            || business.scope.grant_id==claims.scope.grant_id || business.scope.grant_id==mapping.route_export.grant_id {
            return Err(SdkError::Trust);
        }
        result[endpoint].push(export);
    }
    Ok(result)
}
