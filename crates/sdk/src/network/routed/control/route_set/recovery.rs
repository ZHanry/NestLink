//! Explicit safe application recovery. This creates a new proved generation;
//! it does not advertise Quinn connection or arbitrary request continuity.
use super::*;
use super::continuation::{ContinuousRouteSetSession, RouteSetRecoveryProposal};
use crate::{ReconnectedPermit, native::{NativeMediaEvidence, NativeSessionControl}, native_recovery::{RecoveryError, Signals, binding}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::reconnection;
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, api::{NetworkRouteRecoveryChoice, NetworkRemoteRelayRequest, NetworkRemotePathRequest, RelayAllocationRequest, ReconnectionChoice}};
use nestlink_remote::{CleanupStatus, ReconnectionBudget, SessionLifecycle, StopReport};
use nestlink_session::{EndpointRole, Session};
use nestlink_transport_stream::owner::TaskOwner;

/// Independent local consent and current platform/media evidence. A successor
/// retains the old deadline and cannot broaden these permissions or paths.
pub struct RouteSetRecoveryConfig {
    pub bind: SocketAddr,
    pub address_policy: AddressPolicy,
    pub permissions: Vec<Permission>,
    pub capabilities: Vec<String>,
    pub local_paths: PathSet,
    pub stop: watch::Receiver<Option<StopReason>>,
    pub cancel: watch::Receiver<bool>,
    pub media: Option<NativeMediaEvidence>,
}
/// Unique stopped original owner plus the original, non-renewable budget.
/// It can only be obtained after real business/platform/carrier cleanup.
pub struct RouteSetRecoverySource {
    original: Box<ContinuousRouteSetSession>,
    budget: ReconnectionBudget,
    preferred: usize,
}
impl RouteSetRecoverySource {
    pub fn permit(&self) -> &VerifiedPermit { self.budget.permit() }
    pub fn deadline(&self) -> std::time::Instant { self.budget.deadline() }
    fn choice(&self, index: usize) -> Result<NetworkRouteRecoveryChoice, SdkError> {
        let route = &self.original.route;
        let candidate = route.candidates().into_iter().nth(index).ok_or(SdkError::Trust)?;
        if !candidate.available() { return Err(SdkError::Trust); }
        let path = URL_SAFE_NO_PAD.decode(&route.view.path.path.claims).map_err(|_| SdkError::Trust)?;
        let a = URL_SAFE_NO_PAD.decode(&route.view.members[0].transit.claims).map_err(|_| SdkError::Trust)?;
        let b = URL_SAFE_NO_PAD.decode(&route.view.members[1].transit.claims).map_err(|_| SdkError::Trust)?;
        Ok(NetworkRouteRecoveryChoice { version: 1, capability: reconnection::NETWORK_RECOVERY_CAPABILITY.into(),
            space_id: route.pin.space_id.clone(), route_set_id: route.set_id().into(),
            path_grant_id: route.path_grant_id().into(), original_fingerprint: URL_SAFE_NO_PAD.encode(reconnection::route_set_fingerprint(&path,[&a,&b])),
            transport_group: URL_SAFE_NO_PAD.encode(route.transport_group()), previous_path_epoch: 1,
            target_node_id: candidate.node().node_id.clone(), target_route_binding: URL_SAFE_NO_PAD.encode(candidate.route_binding()),
            expires_at_unix_ms: route.grants.path.claims().scope.expires_at_ms })
    }
}
fn validate_choice(previous: &VerifiedPermit, deadline: std::time::Instant, originals: &[NetworkRouteRecoveryChoice], choice: &ReconnectionChoice) -> Result<(),SdkError> {
    reconnection::validate_choice(previous.claims(),choice)?;
    let recovery = choice.network_recovery.as_ref().ok_or(SdkError::Trust)?;
    if Instant::now().into_std() >= deadline || unix_ms()? >= recovery.expires_at_unix_ms { return Err(SdkError::Timeout); }
    if !originals.contains(recovery) { return Err(SdkError::Trust); }
    Ok(())
}

/// The new ChannelRuntime owns its proved inner/outer transport and observers.
/// Consumers attach fresh platform owners and request a new video keyframe.
pub struct RecoveredNetworkSession {
    channels: ChannelRuntime,
    receipt: ReconnectedPermit,
    control: NativeSessionControl,
    cancel_guard: TaskOwner,
    close_deadline: Option<Instant>,
}
impl RecoveredNetworkSession {
    pub fn channels(&mut self) -> &mut ChannelRuntime { &mut self.channels }
    pub fn control(&self) -> NativeSessionControl { self.control.clone() }
    pub fn permit(&self) -> &VerifiedPermit { self.receipt.permit() }
    pub fn remaining_ms(&self) -> Result<u64, SdkError> { self.receipt.remaining_ms() }
    pub async fn wait_stopped(&mut self) -> Result<StopReport, RemoteError> {
        let report = self.channels.wait_stopped().await;
        let deadline = *self.close_deadline.get_or_insert_with(|| Instant::now()+Duration::from_secs(2));
        self.cancel_guard.close_and_wait(deadline).await.map_err(RemoteError::Cleanup)?;
        report
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<StopReport, RemoteError> {
        let deadline = *self.close_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(2));
        let _ = self.channels.lease_control().stop(reason);
        let report = self.channels.wait_stopped_before(deadline).await;
        self.cancel_guard.close_and_wait(deadline).await.map_err(RemoteError::Cleanup)?;
        report
    }
}
impl Drop for RecoveredNetworkSession {
    fn drop(&mut self) {
        let _ = self.channels.lease_control().stop(StopReason::ExplicitExit);
        self.cancel_guard.request_close();
    }
}
fn cancellation_guard(lease: nestlink_remote::LeaseControl, mut cancel: watch::Receiver<bool>) -> TaskOwner {
    struct StopOnDrop(nestlink_remote::LeaseControl);
    impl Drop for StopOnDrop { fn drop(&mut self) { let _ = self.0.stop(StopReason::ExplicitExit); } }
    TaskOwner::new(tokio::spawn(async move {
        let _stop = StopOnDrop(lease.clone());
        let mut stopped = lease.subscribe_stopped();
        if stopped.borrow().is_some() || stopped.has_changed().is_err() { return; }
        tokio::select! { biased;
            _ = cancelled(&mut cancel) => {},
            _ = stopped.changed() => {},
        }
    }))
}
impl ContinuousRouteSetSession {
    /// Invoke after application input/media/business cleanup. With no proposal,
    /// only an already failed recoverable generation may become a source.
    pub async fn into_recovery_source(mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32],
        proposal: Option<&RouteSetRecoveryProposal>) -> Result<RouteSetRecoverySource, SessionEstablishError> {
        let preferred = if let Some(proposal) = proposal {
            let current = self.status()?;
            if current.policy.proposal.as_ref() != Some(&proposal.proposal)
                || self.now()? >= proposal.proposal.deadline_ms()
                || self.index(proposal.proposal.to())? != proposal.candidate_index {
                return Err(SdkError::Trust.into());
            }
            proposal.candidate_index
        } else {
            if self.channels.lease_control().remaining().is_ok() { return Err(SdkError::Trust.into()); }
            1 - self.selected
        };
        let report = self.shutdown(StopReason::TransportLost).await?;
        if !matches!(report.reason, StopReason::TransportLost | StopReason::NetworkChanged)
            || matches!(report.cleanup, CleanupStatus::Failed(_)) { return Err(RemoteError::Stopped.into()); }
        let budget = self.channels.lease_control().reconnection_budget()?;
        if budget.permit().digest() != self.permit.digest() { return Err(SdkError::Trust.into()); }
        let deadline = self.route.deadline.min(Instant::from_std(budget.deadline()));
        let mut fresh = tokio::time::timeout_at(deadline, sdk.verified_network_remote_route_set(
            &self.route.pin, local, budget.permit(), peer_key, self.route.set_id())).await.map_err(|_| SdkError::Timeout)??;
        if fresh.fingerprint != self.route.fingerprint { return Err(SdkError::Trust.into()); }
        fresh.deadline = fresh.deadline.min(deadline);
        self.route = fresh;
        // A failed preferred target is never silently replaced by a new group.
        // Only the original still-admissible candidate may be signed.
        if self.route.candidate_for_admission(sdk,local,budget.permit(),peer_key,preferred).is_none() {
            return Err(SdkError::Trust.into());
        }
        Ok(RouteSetRecoverySource { original: Box::new(self), budget, preferred })
    }
}
fn establish_error(error: SessionEstablishError) -> RecoveryError {
    match error {
        SessionEstablishError::Sdk(error) => RecoveryError::Sdk(error),
        SessionEstablishError::Remote(error) => RecoveryError::Cleanup(error),
        SessionEstablishError::Cancelled => RecoveryError::Stopped(StopReason::ExplicitExit),
        _ => RecoveryError::Sdk(SdkError::Trust),
    }
}
fn retryable(error: &SdkError) -> bool {
    matches!(error, SdkError::Transport(_) | SdkError::Timeout | SdkError::BrowserTransport)
}
impl Sdk {
    /// Controller is the sole offer/reservation writer. Host accepts exactly one
    /// signed target in its current original group, even if both sides trigger
    /// recovery simultaneously. All retries retain one nonce and absolute end.
    pub async fn recover_network_route_set(&self, local: &DeviceIdentity, peer_key: &[u8;32],
        source: RouteSetRecoverySource, config: RouteSetRecoveryConfig) -> Result<RecoveredNetworkSession, RecoveryError> {
        let RouteSetRecoveryConfig { bind, address_policy, permissions, capabilities, local_paths, stop, cancel, media } = config;
        let mut signals = Signals { stop: stop.clone(), cancel: cancel.clone() };
        signals.check()?;
        if !local_paths.contains(Path::Relay) { return Err(SdkError::Trust.into()); }
        let previous = source.permit().clone();
        let original_deadline = source.deadline();
        // Only immutable verified metadata crosses shared borrows at await.
        // The stopped runtime remains a uniquely owned Send value in source.
        let pin = source.original.route.pin.clone();
        let policy_epoch = source.original.route.policy_epoch;
        let controller_membership = source.original.route.view.path.controller_membership.grant_id.clone();
        let host_membership = source.original.route.view.path.host_membership.grant_id.clone();
        let original_targets = source.original.route.candidates().map(|candidate| (candidate.node().node_id.clone(),candidate.relay()));
        let original_choices: Vec<_> = (0..2).filter_map(|index|source.choice(index).ok()).collect();
        let role = if local.device_id == previous.claims().controller_device_id { EndpointRole::Controller }
            else if local.device_id == previous.claims().host_device_id { EndpointRole::Host }
            else { return Err(SdkError::Trust.into()); };
        // Validate independent local consent before either endpoint signs.
        let clock = nestlink_remote::RuntimeClock::default();
        Session::activate(previous.clone(), binding(&previous, &permissions, &capabilities, local_paths, media.as_ref(), &local.device_id)?,
            Path::Relay, 0, clock.sample().map_err(RemoteError::from)?).map_err(SdkError::from)?;
        let receipt = match role {
            EndpointRole::Controller => {
                let attempt = self.prepare_network_reconnection(local, &source.budget, source.choice(source.preferred)?)?;
                signals.guard(async { Ok(self.coordinate_reconnection_controller(&attempt, peer_key, || false).await?) }).await?
            }
            EndpointRole::Host => signals.guard(async {
                Ok(self.coordinate_reconnection_host_checked(local, &previous, peer_key, || false,
                    Some(original_deadline), |choice| validate_choice(&previous,original_deadline,&original_choices,choice)).await?)
            }).await?,
        };
        validate_choice(&previous,original_deadline,&original_choices,receipt.choice())?;
        signals.check()?;
        let recovery = receipt.choice().network_recovery.as_ref().ok_or(SdkError::Trust)?;
        let id = |purpose| reconnection::network_recovery_id(previous.claims(), receipt.choice(), purpose).map_err(SdkError::from);
        let allocation = id("allocation")?;
        let request = NetworkRemoteRelayRequest {
            path: NetworkRemotePathRequest { connectivity_grant_id: id("connectivity")?, path_grant_id: id("path")?,
                controller_membership_grant_id: controller_membership,
                host_membership_grant_id: host_membership,
                expected_policy_epoch: policy_epoch, expires_at_unix_ms: recovery.expires_at_unix_ms },
            transit_grant_id: id("transit")?, allocation: RelayAllocationRequest { allocation_id: allocation.clone(),
                node_id: recovery.target_node_id.clone(), device_id: local.device_id.clone(), signature: String::new() },
        };
        if matches!(role, EndpointRole::Controller) {
            loop {
                let result = signals.guard(async { Ok(receipt.bounded(self.reserve_network_remote_relay(
                    &recovery.space_id,local,receipt.permit(),request.clone())).await?) }).await;
                match result {
                    Ok(_) => break,
                    Err(RecoveryError::Sdk(error)) if retryable(&error) || matches!(error, SdkError::Api(reqwest::StatusCode::CONFLICT,_)) => {
                        // The fixed GET recovers a committed POST response. It
                        // never retries with another request or byte allowance.
                        match signals.guard(async { Ok(receipt.bounded(self.verified_network_remote_relay(
                            &pin,local,receipt.permit(),peer_key,&allocation)).await?) }).await {
                            Ok(_) => break,
                            Err(RecoveryError::Sdk(error)) if retryable(&error) || matches!(error,SdkError::Api(reqwest::StatusCode::FORBIDDEN,_)) => {},
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => return Err(error),
                }
                signals.guard(async { receipt.remaining_ms()?; tokio::time::sleep(Duration::from_millis(50)).await; Ok(()) }).await?;
            }
        }
        let route = loop {
            let result = signals.guard(async { Ok(receipt.bounded(self.verified_network_remote_relay(
                &pin,local,receipt.permit(),peer_key,&allocation)).await?) }).await;
            match result {
                Ok(route) => break route,
                Err(RecoveryError::Sdk(error)) if retryable(&error) || matches!(error,SdkError::Api(reqwest::StatusCode::FORBIDDEN,_)) => {},
                Err(error) => return Err(error),
            }
            signals.guard(async { receipt.remaining_ms()?; tokio::time::sleep(Duration::from_millis(50)).await; Ok(()) }).await?;
        };
        // Validate the new authority against the signed fixed target before I/O.
        let original_target = original_targets.iter().find(|(node,_)| *node == recovery.target_node_id).ok_or(SdkError::Trust)?;
        let same_relay = matches!(route.transit.claims(), GrantClaims::Transit(transit) if transit.relay == original_target.1);
        if !same_relay || route.view.node.node_id != recovery.target_node_id || route.path.claims().scope.expires_at_ms != recovery.expires_at_unix_ms
            || route.view.path.path.grant_id != request.path.path_grant_id || route.view.transit.grant_id != request.transit_grant_id
            || route.view.path.connectivity.grant_id != request.path.connectivity_grant_id
            || route.policy_epoch != policy_epoch { return Err(SdkError::Trust.into()); }
        let deadline = Instant::from_std(original_deadline).min(route.deadline());
        let clock = receipt.runtime_clock()?;
        let session = Session::activate(receipt.permit().clone(), binding(receipt.permit(),&permissions,&capabilities,local_paths,media.as_ref(),&local.device_id)?,
            Path::Relay,0,clock.sample().map_err(RemoteError::from)?).map_err(SdkError::from)?;
        // Transport cancellation is handled inside the existing establishment
        // owner so it can join actual cleanup; do not drop its future in guard.
        let lifetime_cancel = cancel.clone();
        let mut channels = self.connect_network_remote_relay(route,bind,local,peer_key,
            SessionSetup { session, path: Path::Relay, role, clock, lifecycle: SessionLifecycle::new(stop) },
            &address_policy,cancel,deadline).await.map_err(establish_error)?;
        if let Err(error) = signals.check().and_then(|_| receipt.remaining_ms().map(|_|()).map_err(RecoveryError::from)) {
            channels.shutdown(StopReason::Revoked).await?;
            return Err(error);
        }
        let control = NativeSessionControl::from_routed(channels.lease_control(),channels.path_observation(),receipt.permit().claims().lease_sequence);
        let cancel_guard = cancellation_guard(channels.lease_control(),lifetime_cancel);
        drop(source);
        Ok(RecoveredNetworkSession { channels, receipt, control, cancel_guard, close_deadline: None })
    }
}
