//! One standard client's key binding around the original one-use packet owner.
//! This type cannot be cloned or deserialized into another packet budget.
use super::{
    packet_access::{OnlinePacketAccess, PacketAdmission},
    routed::PinnedNetworkSpace,
};
use crate::{DeviceIdentity, Sdk, SdkError};
use nestlink_identity::{
    network::{NetworkVerification, verify_network_grant},
    wireguard::{
        VerifiedWireGuardClientBinding, WireGuardPortalState, verify_wireguard_client_binding,
    },
};
use nestlink_protocol::{
    network::{GrantClaims, PeerId},
    wireguard::management::WireGuardClientBindingView,
};
use std::{
    collections::BTreeSet,
    io,
    net::Ipv4Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const FRESHNESS: Duration = Duration::from_secs(5);

pub struct OnlineWireGuardClient {
    binding: VerifiedWireGuardClientBinding,
    packet: OnlinePacketAccess,
    pin: PinnedNetworkSpace,
    original_signed: nestlink_protocol::wireguard::SignedWireGuardClientBinding,
    fetched: Instant,
    binding_deadline: Instant,
    portal_deadline: Instant,
    stopped: bool,
}
impl OnlineWireGuardClient {
    /// Verify a fresh management response for explicit local review/export.
    /// This does not consume an online start or grant any OS/packet owner.
    pub fn inspect(sdk:&Sdk,pin:&PinnedNetworkSpace,local:&DeviceIdentity,id:&str,view:&WireGuardClientBindingView)->Result<VerifiedWireGuardClientBinding,SdkError> {
        Ok(verify(sdk,pin,local,id,view)?.0)
    }
    /// `approved_binding` and `approved_access` must come from two explicit
    /// local choices. Downloading a credential or knowing a WG key is not one.
    pub async fn start(
        sdk: &Sdk,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        id: &str,
        approved_binding: [u8; 32],
        approved_access: [u8; 32],
        owner_id: String,
    ) -> Result<Self, SdkError> {
        let started = Instant::now();
        let view = tokio::time::timeout(
            Duration::from_secs(2),
            sdk.wireguard_client_binding(pin.space_id(), id),
        )
        .await
        .map_err(|_| SdkError::Timeout)??;
        let (binding, binding_deadline, portal_deadline) = verify(sdk, pin, local, id, &view)?;
        if binding.digest() != approved_binding
            || binding.claims().access_digest != approved_access
            || started.elapsed() >= Duration::from_secs(2)
        {
            return Err(SdkError::Trust);
        }
        let packet = OnlinePacketAccess::start(
            sdk,
            pin,
            local,
            &binding.claims().access_grant_id,
            approved_access,
            owner_id,
        )
        .await?;
        let mut owner = Self {
            binding,
            packet,
            pin: pin.clone(),
            original_signed: view.binding,
            fetched: started,
            binding_deadline,
            portal_deadline,
            stopped: false,
        };
        owner.refresh(sdk, local).await?;
        Ok(owner)
    }
    pub fn claims(&self) -> &nestlink_protocol::wireguard::WireGuardClientBindingClaims {
        self.binding.claims()
    }
    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding.digest()
    }
    pub fn business_digest(&self) -> [u8; 32] {
        self.packet.business_digest()
    }
    pub fn client_address(&self) -> Ipv4Addr {
        self.binding.claims().client_address
    }
    pub fn client_public_key(&self) -> [u8; 32] {
        self.binding.claims().client_public_key
    }
    pub fn owner_id(&self) -> &str {
        self.packet.owner_id()
    }
    pub fn remote_peer(&self) -> PeerId {
        self.packet.remote_peer()
    }
    pub fn transport_group(&self) -> [u8; 32] {
        self.packet.transport_group()
    }
    pub fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction {
        self.packet.wire_direction()
    }
    pub fn spent_bytes(&self) -> u64 {
        self.packet.spent_bytes()
    }
    pub fn remaining_lifetime(&self) -> Duration {
        if self.stopped {
            Duration::ZERO
        } else {
            self.packet
                .remaining_lifetime()
                .min(
                    self.binding_deadline
                        .saturating_duration_since(Instant::now()),
                )
                .min(
                    self.portal_deadline
                        .saturating_duration_since(Instant::now()),
                )
        }
    }
    /// Fixed business/binding lifetime for a journaled OS plan. A same-boot
    /// portal lease is refreshed separately and still constrains every packet
    /// through `current`; this never extends either signed authority deadline.
    pub fn remaining_authorization_lifetime(&self) -> Duration {
        if self.stopped {Duration::ZERO} else {
            self.packet.remaining_lifetime().min(self.binding_deadline.saturating_duration_since(Instant::now()))
        }
    }
    pub fn stop(&mut self) {
        self.stopped = true;
        self.packet.stop();
    }
    /// A transient or ambiguous failure is terminal for this original owner.
    /// Recovery requires a newly approved original packet grant and key binding.
    pub async fn refresh(&mut self, sdk: &Sdk, local: &DeviceIdentity) -> Result<(), SdkError> {
        let result = self.refresh_inner(sdk, local).await;
        if result.is_err() {
            self.stop();
        }
        result
    }
    async fn refresh_inner(&mut self, sdk: &Sdk, local: &DeviceIdentity) -> Result<(), SdkError> {
        if self.stopped || self.fetched.elapsed() >= FRESHNESS || !self.packet.matches_local(local)
        {
            return Err(SdkError::Trust);
        }
        let view = tokio::time::timeout(
            self.remaining_lifetime().min(Duration::from_secs(2)),
            sdk.wireguard_client_binding(self.pin.space_id(), &self.claims().scope.grant_id),
        )
        .await
        .map_err(|_| SdkError::Timeout)??;
        let (current, binding_deadline, portal_deadline) =
            verify(sdk, &self.pin, local, &self.claims().scope.grant_id, &view)?;
        if view.binding != self.original_signed
            || current.digest() != self.binding.digest()
            || self.fetched.elapsed() >= FRESHNESS
        {
            return Err(SdkError::Trust);
        }
        self.packet.refresh(sdk).await?;
        self.binding_deadline = self.binding_deadline.min(binding_deadline);
        self.portal_deadline = portal_deadline;
        self.fetched = Instant::now();
        Ok(())
    }
    fn current(&mut self) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis();
        if self.stopped
            || self.fetched.elapsed() >= FRESHNESS
            || self.remaining_lifetime().is_zero()
            || now >= u128::from(self.claims().scope.expires_at_ms)
        {
            self.stop();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original WireGuard client owner expired or lost its online observation",
            ));
        }
        Ok(())
    }
    /// The caller may submit only complete packets from its one exact kernel
    /// WG/TUN owner. The original parser still binds source, L3/L4 and quota.
    pub fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> {
        self.current()?;
        self.packet.admit_local(packet)
    }
    pub fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> {
        self.current()?;
        self.packet.admit_remote(packet)
    }
}
fn verify(
    sdk: &Sdk,
    pin: &PinnedNetworkSpace,
    local: &DeviceIdentity,
    id: &str,
    view: &WireGuardClientBindingView,
) -> Result<(VerifiedWireGuardClientBinding, Instant, Instant), SdkError> {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)?;
    let policy = &view.policy;
    if policy.space_id != pin.space_id()
        || policy.deployment_id != sdk.trust.deployment_id
        || policy.authority_public_key
            != base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                pin.authority_key(),
            )
        || policy.observed_at_unix_ms > now
        || now - policy.observed_at_unix_ms >= FRESHNESS.as_millis() as u64
    {
        return Err(SdkError::Trust);
    }
    let claims = nestlink_protocol::wireguard::WireGuardClientBindingClaims::decode_canonical(
        &view.binding.claims,
    )?;
    if claims.scope.grant_id != id
        || claims.installation_id != local.device_id
        || claims.portal_public_key != local.identity.public_key()
        || sdk
            .principal()
            .is_none_or(|actor| actor.account_id != claims.account_id)
    {
        return Err(SdkError::Trust);
    }
    let mappings = &view.packet_access.subnet_mappings;
    let mapping = mappings
        .iter()
        .find(|value| {
            value.gateway.node_id == claims.portal_node_id
                && value.gateway.public_key == claims.portal_public_key
        })
        .ok_or(SdkError::Trust)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: pin.authority_key(),
        deployment_id: &sdk.trust.deployment_id,
        space_id: pin.space_id(),
        policy_epoch: policy.policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let access = verify_network_grant(
        &crate::network_management::decode_network_grant(&view.packet_access.access)?,
        &context,
    )?;
    if !matches!(access.claims(), GrantClaims::NetworkAccess(_)) {
        return Err(SdkError::Trust);
    }
    let portal = WireGuardPortalState {
        node_id: &mapping.gateway.node_id,
        public_key: &mapping.gateway.public_key,
        incarnation: &mapping.gateway.incarnation,
        lease_expires_at_ms: mapping.gateway.lease_expires_at_ms,
        client_revision: claims.client_revision,
    };
    let verified = verify_wireguard_client_binding(&view.binding, &context, access, &portal)?;
    let instant = Instant::now();
    let binding_deadline =
        instant + Duration::from_millis(verified.claims().scope.expires_at_ms - now);
    let portal_deadline = instant + Duration::from_millis(portal.lease_expires_at_ms - now);
    Ok((verified, binding_deadline, portal_deadline))
}
