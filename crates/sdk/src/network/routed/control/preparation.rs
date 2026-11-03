//! Private, pinned preparation owner. A directory response never installs trust.
use super::*;
use nestlink_identity::network::remote_preparation_grant_ids;
use nestlink_protocol::{
    api::{NetworkPolicyView, NetworkRemotePreparationRequest, NetworkRemotePreparationView},
    network::{SCHEMA_VERSION, SpaceRole},
};

pub struct VerifiedRemotePreparation {
    pin: PinnedNetworkSpace,
    permit: VerifiedPermit,
    binding: NetworkRemotePreparationRequest,
    view: NetworkRemotePreparationView,
    members: [VerifiedMembership; 2],
    local_device: String,
    local_key: [u8; 32],
    origin: String,
    login_session: String,
    fingerprint: [u8; 32],
    deadline: Instant,
}
impl VerifiedRemotePreparation {
    pub fn policy(&self) -> &NetworkPolicyView { &self.view.policy }
    pub fn deadline(&self) -> Instant { self.deadline }
    pub fn request_id(&self) -> &str { &self.view.request_id }
    pub fn connection_generation(&self) -> u64 { self.view.connection_generation }
    pub fn permit_digest(&self) -> [u8; 32] { self.permit.digest() }
    pub fn membership_grant_ids(&self) -> [&str; 2] {
        [&self.view.controller_membership.grant_id, &self.view.host_membership.grant_id]
    }
    pub fn membership_epochs(&self) -> [u64; 2] {
        [self.members[0].claims().membership_epoch, self.members[1].claims().membership_epoch]
    }
    pub fn installation_ids(&self) -> [&str; 2] {
        [&self.members[0].claims().installation_id, &self.members[1].claims().installation_id]
    }
    pub fn roles(&self) -> [SpaceRole; 2] {
        [self.members[0].claims().role, self.members[1].claims().role]
    }
    pub fn expires_at_unix_ms(&self) -> u64 { self.members[0].claims().scope.expires_at_ms }

    /// A saved local preview must re-read the exact pair before its one-use
    /// approval is consumed. This cannot replace a changed permit or login.
    pub async fn check_current(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
    ) -> Result<(), SdkError> {
        if !self.bound_to(sdk, local, permit) { return Err(SdkError::Trust); }
        let current = tokio::time::timeout_at(self.deadline,
            sdk.read_network_remote_preparation(self.pin.space_id(), self.request_id(), self.binding.clone()),
        ).await.map_err(|_| SdkError::Timeout)??;
        if !self.bound_to(sdk, local, permit) || response_digest(&current)? != self.fingerprint {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    fn bound_to(&self, sdk: &Sdk, local: &DeviceIdentity, permit: &VerifiedPermit) -> bool {
        Instant::now() < self.deadline
            && self.origin == sdk.origin.as_str()
            && self.view.policy.deployment_id == sdk.trust.deployment_id
            && self.permit.digest() == permit.digest()
            && permit.issuer() == sdk.trust.permit_issuer
            && permit.claims().security_epoch == sdk.health.security_epoch
            && self.local_device == local.device_id
            && self.local_key == local.identity.public_key()
            && sdk.login.as_ref().is_some_and(|login| login.principal.session_id == self.login_session)
    }
}

impl Sdk {
    /// One fixed POST, then only exact GET after a lost/ambiguous response.
    /// The operator must supply an already approved local pin.
    pub async fn prepare_network_remote(
        &self,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        expected_space_revision: u64,
        expected_policy_epoch: u64,
    ) -> Result<VerifiedRemotePreparation, SdkError> {
        self.remote_preparation(pin, local, permit, expected_space_revision, expected_policy_epoch, true).await
    }
    pub async fn network_remote_preparation(
        &self,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        expected_space_revision: u64,
        expected_policy_epoch: u64,
    ) -> Result<VerifiedRemotePreparation, SdkError> {
        self.remote_preparation(pin, local, permit, expected_space_revision, expected_policy_epoch, false).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn remote_preparation(
        &self,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        expected_space_revision: u64,
        expected_policy_epoch: u64,
        issue: bool,
    ) -> Result<VerifiedRemotePreparation, SdkError> {
        let started = Instant::now();
        let claims = permit.claims();
        let now = unix_ms()?;
        let local_controller = local.device_id == claims.controller_device_id;
        let local_host = local.device_id == claims.host_device_id;
        let local_digest = digest(&local.identity.public_key());
        if local_controller == local_host
            || permit.issuer() != self.trust.permit_issuer
            || claims.deployment_id != self.trust.deployment_id
            || claims.security_epoch != self.health.security_epoch
            || claims.issued_at_unix_ms > now || claims.expires_at_unix_ms <= now
            || !claims.paths.iter().any(|path| [Path::Direct as i32, Path::Relay as i32].contains(path))
            || (local_controller && claims.controller_key_sha256 != local_digest)
            || (local_host && claims.host_key_sha256 != local_digest)
        { return Err(SdkError::Trust); }
        let login_session = self.login.as_ref().ok_or(SdkError::SignIn)?.principal.session_id.clone();
        let binding = NetworkRemotePreparationRequest {
            expected_space_revision, expected_policy_epoch,
            connection_generation: claims.connection_generation,
            permit_sha256: URL_SAFE_NO_PAD.encode(permit.digest()),
        };
        let ids = remote_preparation_grant_ids(pin.space_id(), &claims.session_id, &binding)?;
        let setup_deadline = started + Duration::from_millis((claims.expires_at_unix_ms - now).min(5_000));
        let view = tokio::time::timeout_at(setup_deadline, async {
            if issue {
                if let Ok(view) = self.issue_network_remote_preparation(pin.space_id(), &claims.session_id, binding.clone()).await {
                    return Ok::<_, SdkError>(view);
                }
            }
            self.read_network_remote_preparation(pin.space_id(), &claims.session_id, binding.clone()).await
        }).await.map_err(|_| SdkError::Timeout)??;
        let now = unix_ms()?;
        if Instant::now() >= setup_deadline
            || view.request_id != claims.session_id
            || view.connection_generation != binding.connection_generation
            || view.permit_sha256 != binding.permit_sha256
            || view.policy.schema_version != SCHEMA_VERSION
            || view.policy.deployment_id != self.trust.deployment_id
            || view.policy.space_id != pin.space_id()
            || view.policy.authority_public_key != URL_SAFE_NO_PAD.encode(pin.authority_key())
            || view.policy.revision != expected_space_revision
            || view.policy.policy_epoch != expected_policy_epoch
            || view.policy.observed_at_unix_ms > now
            || view.controller_membership.grant_id != ids[0]
            || view.host_membership.grant_id != ids[1]
        { return Err(SdkError::Trust); }
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: pin.authority_key(), deployment_id: &self.trust.deployment_id,
            space_id: pin.space_id(), policy_epoch: expected_policy_epoch,
            now_ms: now, revoked_grant_ids: &revoked,
        };
        let mut members = Vec::with_capacity(2);
        for (grant_view, installation, expected_digest) in [
            (&view.controller_membership, &claims.controller_device_id, &claims.controller_key_sha256),
            (&view.host_membership, &claims.host_device_id, &claims.host_key_sha256),
        ] {
            let signed = crate::network_management::decode_network_grant(grant_view)?;
            let grant = verify_network_grant(&signed, &context)?;
            let GrantClaims::Membership(member) = grant.claims() else { return Err(SdkError::Trust); };
            let key = member.public_key;
            let epoch = member.membership_epoch;
            if digest(&key).as_slice() != expected_digest.as_slice()
                || (installation == &local.device_id && key != local.identity.public_key())
                || member.scope.not_before_ms != view.policy.observed_at_unix_ms
                || member.scope.expires_at_ms > claims.expires_at_unix_ms
                || member.scope.expires_at_ms.saturating_sub(member.scope.not_before_ms) > 60_000
            { return Err(SdkError::Trust); }
            members.push(VerifiedMembership::from_grant(grant, &context, installation, &key, epoch)?);
        }
        let controller = members.remove(0);
        let host = members.remove(0);
        let expires = controller.claims().scope.expires_at_ms;
        if expires != host.claims().scope.expires_at_ms { return Err(SdkError::Trust); }
        let remaining = expires.checked_sub(now).filter(|value| *value > 0).ok_or(SdkError::Trust)?;
        let deadline = started + Duration::from_millis(remaining.min(60_000));
        if Instant::now() >= deadline { return Err(SdkError::Timeout); }
        let fingerprint = response_digest(&view)?;
        Ok(VerifiedRemotePreparation {
            pin: pin.clone(), permit: permit.clone(), binding, view, members: [controller, host],
            local_device: local.device_id.clone(), local_key: local.identity.public_key(),
            origin: self.origin.as_str().into(), login_session, fingerprint, deadline,
        })
    }
}
