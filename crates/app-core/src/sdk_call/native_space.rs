//! One actor job borrows the existing SDK and retains the signed preview owner.
use super::*;
use crate::{NativeNetworkSettings, NativeRemotePreparationSettings, NativeRouteSetSettings,
    NativeSpaceConfirmation, NativeSpaceMode, NativeSpacePathSettings, NativeSpacePreview,
    NativeSpacePreviewRequest, NativeSpaceRelayChoice};
use nestlink_identity::VerifiedPermit;
use nestlink_sdk::{NodeDiscovery, network::routed::{PinnedNetworkSpace, VerifiedRemotePreparation}};
use std::time::{Duration, Instant};

pub(crate) struct PendingNativeSpace {
    pub public: NativeSpacePreview,
    pub runtime_id: String,
    pub generation: u64,
    preparation: VerifiedRemotePreparation,
    permit: VerifiedPermit,
    settings: NativeNetworkSettings,
    deadline: Instant,
    _discovery: Option<NodeDiscovery>,
}

pub(crate) struct ApprovedNativeSpace {
    pub expected_revision: u64,
    pub settings: NativeNetworkSettings,
}
impl PendingNativeSpace {
    pub(crate) fn expired(&self) -> bool { Instant::now() >= self.deadline }
}

pub(super) async fn preview(response: &mut Response, identity: &DeviceIdentity,
    request: NativeSpacePreviewRequest, native: &crate::NativeSessionConfig,
    fence: &DispatchFence) -> Result<(), Failure> {
    let remote = read(response.sdk.remote(&request.request_id), fence).await?;
    if remote.status != "approved" || remote.connection_generation != request.expected_connection_generation
        || ![remote.controller_device_id.as_str(), remote.host_device_id.as_str()].contains(&identity.device_id.as_str()) {
        return Err(Failure::local(FailureKind::Trust));
    }
    let permit = read(response.sdk.current_native_permit(identity, &request.request_id), fence).await?;
    if permit.claims().connection_generation != request.expected_connection_generation {
        return Err(Failure::local(FailureKind::Trust));
    }
    let path = match request.mode { NativeSpaceMode::Direct => nestlink_protocol::Path::Direct,
        NativeSpaceMode::Relays => nestlink_protocol::Path::Relay };
    if !permit.claims().paths.contains(&(path as i32)) {
        return Err(Failure::local(FailureKind::Trust));
    }
    let details = read(response.sdk.space_details(&request.space_id), fence).await?;
    let key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, request.trusted_authority_key);
    if details.space.authority_public_key != key || details.space.revision != request.expected_space_revision
        || details.space.policy_epoch != request.expected_policy_epoch || details.space.archived {
        return Err(Failure::local(FailureKind::Trust));
    }
    let pin = PinnedNetworkSpace::new(request.space_id.clone(), request.trusted_authority_key).map_err(Failure::from)?;
    let preparation = write(response.sdk.prepare_network_remote(&pin, identity, &permit,
        request.expected_space_revision, request.expected_policy_epoch), &mut response.effect, fence).await?;
    let mut deadline = preparation.deadline();
    let mut expires = preparation.expires_at_unix_ms();
    let mut relay_choices = Vec::new();
    let mut discovery = None;
    if request.mode == NativeSpaceMode::Relays {
        if native.pcp_gateway.is_some() { return Err(Failure::local(FailureKind::Invalid)); }
        let started = Instant::now();
        let signed = read(response.sdk.discover_relay_nodes(identity, &permit), fence).await?;
        deadline = deadline.min(started + Duration::from_secs(5));
        expires = expires.min(unix_ms()?.saturating_add(deadline.saturating_duration_since(Instant::now()).as_millis() as u64));
        relay_choices = signed.nodes().iter().map(|node| NativeSpaceRelayChoice {
            node_id: node.node_id.clone(), runtime_generation: node.runtime_generation,
            expires_at_unix_ms: node.expires_at_unix_ms,
        }).collect();
        discovery = Some(signed);
    }
    fence.check()?;
    let public = NativeSpacePreview {
        nonce: random_id(), context: request.context, space_id: request.space_id,
        deployment_id: preparation.policy().deployment_id.clone(), authority_key: request.trusted_authority_key,
        request_id: request.request_id, connection_generation: preparation.connection_generation(),
        permit_sha256: preparation.permit_digest(), membership_epochs: preparation.membership_epochs(),
        installation_ids: preparation.installation_ids().map(str::to_owned), roles: preparation.roles(),
        expected_network_revision: request.expected_network_revision,
        expires_at_unix_ms: expires, mode: request.mode, relay_choices,
    };
    response.native_space_preview = Some(PendingNativeSpace { public, runtime_id: request.runtime_id,
        generation: fence.expected, preparation, permit, settings: native.network_settings(), deadline,
        _discovery: discovery });
    Ok(())
}

pub(super) async fn confirm(response: &mut Response, identity: &DeviceIdentity,
    confirmation: NativeSpaceConfirmation, pending: PendingNativeSpace,
    fence: &DispatchFence) -> Result<(), Failure> {
    if pending.generation != fence.expected || pending.runtime_id != confirmation.runtime_id
        || pending.public.nonce != confirmation.nonce || pending.public.context != confirmation.context
        || Instant::now() >= pending.deadline {
        return Err(Failure::local(FailureKind::Superseded));
    }
    let permit = read(response.sdk.current_native_permit(identity, &pending.public.request_id), fence).await?;
    if permit.digest() != pending.permit.digest() || permit.claims().expires_at_unix_ms <= unix_ms()? {
        return Err(Failure::local(FailureKind::Trust));
    }
    read(pending.preparation.check_current(&response.sdk, identity, &permit), fence).await?;
    let mut settings = pending.settings;
    let members = pending.preparation.membership_grant_ids();
    let direct = NativeSpacePathSettings { deployment_id: pending.public.deployment_id.clone(),
        space_id: pending.public.space_id.clone(), authority_key: pending.public.authority_key,
        controller_membership_grant_id: members[0].into(), host_membership_grant_id: members[1].into() };
    match pending.public.mode {
        NativeSpaceMode::Direct => {
            if confirmation.node_ids.is_some() { return Err(Failure::local(FailureKind::Invalid)); }
            settings.space_path = Some(direct); settings.route_set = None;
        }
        NativeSpaceMode::Relays => {
            let nodes = confirmation.node_ids.ok_or_else(|| Failure::local(FailureKind::Invalid))?;
            if nodes[0] == nodes[1] || nodes.iter().any(|id| !pending.public.relay_choices.iter()
                .any(|node| node.node_id == *id && node.expires_at_unix_ms > unix_ms().unwrap_or(u64::MAX))) {
                return Err(Failure::local(FailureKind::Trust));
            }
            settings.space_path = None;
            settings.route_set = Some(NativeRouteSetSettings { deployment_id: direct.deployment_id,
                space_id: direct.space_id, authority_key: direct.authority_key,
                controller_membership_grant_id: direct.controller_membership_grant_id,
                host_membership_grant_id: direct.host_membership_grant_id, node_ids: nodes });
        }
    }
    settings.preparation = Some(NativeRemotePreparationSettings {
        request_id: pending.public.request_id, connection_generation: pending.public.connection_generation,
        permit_sha256: pending.public.permit_sha256, space_revision: pending.preparation.policy().revision,
        policy_epoch: pending.preparation.policy().policy_epoch, expires_at_unix_ms: pending.preparation.expires_at_unix_ms(),
    });
    settings.validate().map_err(|_| Failure::local(FailureKind::Invalid))?;
    fence.check()?;
    if Instant::now() >= pending.deadline { return Err(Failure::local(FailureKind::Timeout)); }
    response.approved_native_space = Some(ApprovedNativeSpace {
        expected_revision: pending.public.expected_network_revision, settings,
    });
    Ok(())
}
