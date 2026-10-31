//! Caller-driven continuous owner for one proved route-set business session.
//! The original ChannelRuntime remains its business/carrier owner. One bounded
//! standby has only node admission and inner TLS, never a business channel.
use super::*;
use nestlink_connectivity::{Scheduler, continuation::*, observation::{LocalPathMeasurements, LocalQuicSample, PathObservationBinding, PathObservationSnapshot}};
use nestlink_remote::{PathObservation, StopReport};
use nestlink_transport_quic::routed::{AdjacencyEndpoint, RoutedEstablishment, RoutedTransport};
use nestlink_transport_stream::owner::TaskOwner;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone, Debug)]
pub struct RouteSetRecoveryProposal {
    pub proposal: SwitchProposal,
    pub candidate_index: usize,
    /// This is a recovery suggestion, never a capability to send business data
    /// on the standby. Recovery requires fresh business/network admission and
    /// must use the existing application recovery rules without replaying I/O.
    pub requires_fresh_business_admission: bool,
}
#[derive(Clone, Debug)]
pub struct RouteSetContinuationStatus {
    pub policy: ContinuationStatus,
    pub recovery: Option<RouteSetRecoveryProposal>,
}

struct Standby {
    index: usize,
    bound: SocketAddr,
    node: Option<AdjacencyEndpoint>,
    inner: Option<RoutedEstablishment>,
    transport: Option<RoutedTransport>,
    revocation: Option<Arc<RouteRevocation>>,
    stop_guardian: Option<TaskOwner>,
    measurements: LocalPathMeasurements,
    close_deadline: Option<Instant>,
}
impl Standby {
    fn request_close(&self) {
        if let Some(revocation) = &self.revocation { revocation.revoke(); }
        if let Some(transport) = &self.transport { transport.request_close(); }
        if let Some(inner) = &self.inner { inner.request_close(); }
        if let Some(guardian) = &self.stop_guardian { guardian.request_close(); }
    }
    async fn close(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(guardian) = &self.stop_guardian { guardian.close_and_wait(deadline).await?; }
        self.stop_guardian = None;
        if let Some(transport) = &mut self.transport { transport.close_and_wait(deadline).await?; }
        self.transport = None;
        if let Some(inner) = &mut self.inner { inner.close_and_wait(deadline).await?; }
        self.inner = None;
        if let Some(node) = &mut self.node { node.close_and_wait(deadline).await?; }
        self.node = None;
        self.revocation = None;
        Ok(())
    }
}
struct PendingRetirement { token: RetirementToken, deadline: Instant }
struct RevokeOnDrop(Arc<RouteRevocation>);
impl Drop for RevokeOnDrop { fn drop(&mut self) { self.0.revoke(); } }
fn standby_guardian(revocation: Arc<RouteRevocation>, lease: nestlink_remote::LeaseControl, mut cancel: watch::Receiver<bool>, deadline: Instant) -> TaskOwner {
    TaskOwner::new(tokio::spawn(async move {
        let _revoke = RevokeOnDrop(revocation);
        let mut stopped = lease.subscribe_stopped();
        if stopped.borrow().is_some() || stopped.has_changed().is_err() || cancel_is_stopped(&cancel) { return; }
        tokio::select! { biased;
            _ = stopped.changed() => {},
            _ = cancelled(&mut cancel) => {},
            _ = tokio::time::sleep_until(deadline) => {},
        }
    }))
}

/// Poll at least once per second while retained; each poll executes actual
/// readback/work and returns a recovery proposal for the original application
/// owner. It does not spawn another scheduler or change the active carrier.
/// Cancellation retains pending physical owners and their original receipts;
/// the next poll retires interrupted work before scheduling anything else.
pub struct ContinuousRouteSetSession {
    pub(super) channels: ChannelRuntime,
    control: crate::native::NativeSessionControl,
    observation: PathObservation,
    pub(super) route: VerifiedRemoteRouteSet,
    pub(super) permit: VerifiedPermit,
    scheduler: Scheduler,
    group: OriginalGroup,
    originals: Vec<OriginalRoute>,
    keys: Vec<RouteIdentity>,
    pub(super) selected: usize,
    bind: SocketAddr,
    address_policy: AddressPolicy,
    cancel: watch::Receiver<bool>,
    started: Instant,
    refreshed: Instant,
    active_feedback: Option<std::time::Instant>,
    standby: Option<Standby>,
    interrupted: Option<WorkToken>,
    close_deadline: Option<Instant>,
    pending_retirements: Vec<PendingRetirement>,
    attempted_members: BTreeSet<usize>,
}

impl Sdk {
    /// Both endpoints must explicitly select the same original active member
    /// and drive their returned owners to prepare/probe the common standby.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_continuing_network_remote_route_candidate(
        &self, route: VerifiedRemoteRouteSet, selected: usize, bind: SocketAddr,
        local: &DeviceIdentity, peer_key: &[u8;32], setup: SessionSetup,
        address_policy: &AddressPolicy, cancel: watch::Receiver<bool>, deadline: Instant,
        constraints: QualityConstraints,
    ) -> Result<ContinuousRouteSetSession, SessionEstablishError> {
        let started = Instant::now();
        let permit = setup.session.current_verified_permit().clone();
        let mut channels = self.connect_original_route_candidate(&route, selected, bind, local, peer_key,
            setup, address_policy, cancel.clone(), deadline).await?;
        let construct = (|| -> Result<_, SessionEstablishError> {
            let observation = channels.path_observation().ok_or(SdkError::Invalid)?;
            let group = OriginalGroup {
                business_grant_digest: permit.digest(), business_generation: permit.claims().connection_generation,
                path_grant_id: route.path_grant_id().into(), transport_group: route.transport_group(),
                purpose: nestlink_protocol::network::Purpose::RemoteControl,
                allowed_paths: nestlink_policy::PathSet::RELAY,
                deadline_ms: ms_between(started, route.deadline)?,
            };
            let originals: Vec<_> = route.candidates().into_iter().map(|candidate| OriginalRoute {
                binding: PathObservationBinding {
                    business_grant_digest: group.business_grant_digest, business_generation: group.business_generation,
                    path_grant_id: Some(group.path_grant_id.clone()), transport_group: Some(group.transport_group),
                    route_binding: Some(candidate.route_binding()), purpose: group.purpose,
                    path: nestlink_protocol::Path::Relay, candidate: None, network_generation: None,
                },
            }).collect();
            let keys: Vec<_> = originals.iter().filter_map(OriginalRoute::identity).collect();
            let active = *keys.get(selected).ok_or(SdkError::Invalid)?;
            if observation.binding() != &originals[selected].binding { return Err(SdkError::Trust.into()); }
            let scheduler = Scheduler::for_established_group(1, ms_between(started, Instant::now())?,
                group.clone(), originals.clone(), active, constraints)?;
            Ok((observation, group, originals, keys, scheduler))
        })();
        let (observation, group, originals, keys, scheduler) = match construct {
            Ok(value) => value,
            Err(error) => { channels.shutdown(StopReason::Revoked).await?; return Err(error); }
        };
        let refreshed = route.fetched;
        let control = crate::native::NativeSessionControl::from_routed(channels.lease_control(),channels.path_observation(),permit.claims().lease_sequence);
        Ok(ContinuousRouteSetSession { channels, control, observation, route, permit, scheduler, group, originals, keys,
            selected, bind, address_policy: address_policy.clone(), cancel, started, refreshed,
            active_feedback: None, standby: None, interrupted: None, close_deadline: None, pending_retirements: Vec::new(),
            attempted_members: BTreeSet::from([selected]) })
    }
}

fn ms_between(start: Instant, at: Instant) -> Result<u64, SdkError> {
    at.checked_duration_since(start).and_then(|d| u64::try_from(d.as_millis()).ok()).ok_or(SdkError::Invalid)
}
impl ContinuousRouteSetSession {
    pub fn channels(&mut self) -> &mut ChannelRuntime { &mut self.channels }
    pub fn control(&self) -> crate::native::NativeSessionControl { self.control.clone() }
    pub fn permit(&self) -> &VerifiedPermit { &self.permit }
    pub async fn wait_stopped(&mut self) -> Result<StopReport, SessionEstablishError> {
        let report = self.channels.wait_stopped().await;
        let deadline = *self.close_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(2));
        self.scheduler.stop_continuation(nestlink_protocol::ErrorCode::PolicyRevoked);
        self.clear_standby(deadline).await?;
        Ok(report?)
    }
    /// Local diagnostic receipt target; retaining it grants no network I/O.
    pub fn standby_local_addr(&self) -> Option<SocketAddr> { self.standby.as_ref().map(|slot| slot.bound) }
    pub(super) fn now(&self) -> Result<u64, SdkError> { ms_between(self.started, Instant::now()) }
    pub(super) fn index(&self, key: RouteIdentity) -> Result<usize, SdkError> { self.keys.iter().position(|k| *k == key).ok_or(SdkError::Trust) }
    pub(super) fn status(&self) -> Result<RouteSetContinuationStatus, SdkError> {
        let policy = self.scheduler.continuation_status().ok_or(SdkError::Invalid)?;
        let recovery = policy.proposal.clone().map(|proposal| {
            Ok::<_, SdkError>(RouteSetRecoveryProposal { candidate_index: self.index(proposal.to())?, proposal,
                requires_fresh_business_admission: true })
        }).transpose()?;
        Ok(RouteSetContinuationStatus { policy, recovery })
    }
    fn step(&mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32], input: ContinuationInput) -> Result<ContinuationDecision, SdkError> {
        let now = self.now()?;
        let available: Vec<_> = (0..self.keys.len()).filter(|index|
            (!self.attempted_members.contains(index) || *index == self.selected || self.standby.as_ref().is_some_and(|slot| slot.index == *index))
                && self.route.candidate_for_admission(sdk, local, &self.permit, peer_key, *index).is_some()).map(|index| self.keys[index]).collect();
        Ok(self.scheduler.advance_continuation(now, CurrentAuthority { original: &self.group, checked_at_ms: now,
            current: self.route.is_current_for(sdk, local, &self.permit, peer_key), available_routes: &available }, input))
    }
    async fn clear_standby(&mut self, deadline: Instant) -> Result<(), SessionEstablishError> {
        if let Some(standby) = &mut self.standby { standby.close(deadline).await.map_err(RemoteError::Cleanup)?; }
        self.standby = None;
        Ok(())
    }
    async fn consume(&mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32], decision: ContinuationDecision) -> Result<Vec<WorkToken>, SessionEstablishError> {
        let mut work = Vec::new();
        self.collect(decision, &mut work);
        while let Some(pending) = self.pending_retirements.first() {
            let token = pending.token.clone();
            let deadline = pending.deadline;
            if token.route() == self.keys[self.selected] {
                // Only the original runtime's joined physical carrier receipt
                // can acknowledge active retirement. stop/Drop is insufficient.
                self.channels.wait_stopped_before(deadline).await?;
            } else { self.clear_standby(deadline).await?; }
            let receipt = self.step(sdk, local, peer_key, ContinuationInput::Retired(token))?;
            self.pending_retirements.remove(0);
            self.collect(receipt, &mut work);
        }
        Ok(work)
    }
    fn collect(&mut self, decision: ContinuationDecision, work: &mut Vec<WorkToken>) {
        for action in decision.actions {
            match action {
                ContinuationAction::Prepare(token) | ContinuationAction::Probe(token) => work.push(token),
                ContinuationAction::Retire(token) => {
                    if token.route() == self.keys[self.selected] {
                        let _ = self.channels.lease_control().stop(StopReason::Revoked);
                    } else if let Some(standby) = &self.standby { standby.request_close(); }
                    if !self.pending_retirements.iter().any(|pending| pending.token == token) {
                        self.pending_retirements.push(PendingRetirement { token, deadline: Instant::now() + Duration::from_secs(2) });
                    }
                }
                ContinuationAction::Terminal(_) => { let _ = self.channels.lease_control().stop(StopReason::Revoked); }
                _ => {},
            }
        }
    }
    /// Execute one bounded continuous turn using the actual current SDK/login.
    /// A returned proposal is for safe application recovery; this owner offers
    /// no Commit API until authenticated bilateral W14 switching is available.
    pub async fn poll(&mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32], demand: bool) -> Result<RouteSetContinuationStatus, SessionEstablishError> {
        self.consume(sdk, local, peer_key, ContinuationDecision::default()).await?;
        if let Some(work) = self.interrupted.clone() {
            self.clear_standby(Instant::now() + Duration::from_secs(2)).await?;
            let decision = self.step(sdk, local, peer_key, ContinuationInput::WorkFailed { work, code: nestlink_protocol::ErrorCode::RelayUnavailable })?;
            self.interrupted = None;
            self.consume(sdk, local, peer_key, decision).await?;
        }
        if cancel_is_stopped(&self.cancel) || self.channels.lease_control().remaining().is_err() {
            let decision = self.scheduler.stop_continuation(nestlink_protocol::ErrorCode::PolicyRevoked);
            self.consume(sdk, local, peer_key, decision).await?;
            return Ok(self.status()?);
        }
        if self.refreshed.elapsed() >= Duration::from_secs(1) {
            let refreshed = tokio::time::timeout_at(self.route.deadline.min(Instant::now() + Duration::from_secs(2)),
                self.route.refresh_current(sdk, local, &self.permit, peer_key)).await;
            match refreshed {
                Ok(Ok(route)) => { self.refreshed = route.fetched; self.route = route; }
                _ => {
                    let decision = self.scheduler.stop_continuation(nestlink_protocol::ErrorCode::PolicyRevoked);
                    self.consume(sdk, local, peer_key, decision).await?;
                    return Ok(self.status()?);
                }
            }
        }
        if let Some((at, snapshot)) = self.observation.timed_snapshot()
            && self.active_feedback.is_none_or(|old| at > old) {
            self.active_feedback = Some(at);
            if let Some(observer) = self.scheduler.continuation_status().and_then(|s| s.active_observer) {
                let observed_at_ms = ms_between(self.started, Instant::from_std(at))?;
                let decision = self.step(sdk, local, peer_key, ContinuationInput::Feedback { observer, observed_at_ms, snapshot: Box::new(snapshot) })?;
                self.consume(sdk, local, peer_key, decision).await?;
            }
        }
        let decision = self.step(sdk, local, peer_key, ContinuationInput::Tick { demand })?;
        let work = self.consume(sdk, local, peer_key, decision).await?;
        for token in work {
            self.interrupted = Some(token.clone());
            let mut cancel = self.cancel.clone();
            let mut stopped = self.channels.lease_control().subscribe_stopped();
            let deadline = (self.started + Duration::from_millis(token.deadline_ms())).min(self.route.deadline);
            let result = tokio::select! { biased;
                _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
                _ = stopped.changed() => Err(RemoteError::Stopped.into()),
                result = tokio::time::timeout_at(deadline, self.execute(sdk, local, peer_key, &token)) => result.map_err(|_| SdkError::Timeout).map_err(SessionEstablishError::from).and_then(|r| r),
            };
            let decision = match result {
                Ok((observed_at_ms, snapshot)) => self.step(sdk, local, peer_key,
                    ContinuationInput::WorkCompleted { work: token, observed_at_ms, snapshot: Box::new(snapshot) })?,
                Err(error) => {
                    self.clear_standby(Instant::now() + Duration::from_secs(2)).await?;
                    self.step(sdk, local, peer_key, ContinuationInput::WorkFailed { work: token, code: failure_code(&error) })?
                }
            };
            self.interrupted = None;
            self.consume(sdk, local, peer_key, decision).await?;
        }
        Ok(self.status()?)
    }
    async fn execute(&mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32], work: &WorkToken) -> Result<(u64, PathObservationSnapshot), SessionEstablishError> {
        let index = self.index(work.route())?;
        let deadline = (self.started + Duration::from_millis(work.deadline_ms())).min(self.route.deadline);
        if Instant::now() >= deadline || self.route.candidate_for_admission(sdk, local, &self.permit, peer_key, index).is_none() {
            return Err(SdkError::Trust.into());
        }
        if work.kind() == WorkKind::Prepare {
            let candidate = self.route.candidate_for_admission(sdk, local, &self.permit, peer_key, index).ok_or(SdkError::Trust)?;
            let node = candidate.node();
            let uri = url::Url::parse(node.endpoints.quic_uri.as_deref().ok_or(SdkError::Trust)?).map_err(|_| SdkError::Invalid)?;
            let addresses = crate::native::resolve_signed_node_host(uri.host().ok_or(SdkError::Invalid)?, uri.port().filter(|p| *p != 0).ok_or(SdkError::Invalid)?).await?;
            if addresses.iter().any(|address| { let ip = address.ip().to_canonical();
                if ip.is_loopback() { !(self.route.pin.allow_loopback_node && node.endpoints.allow_loopback) }
                else { !self.address_policy.allows(ip) } }) { return Err(SdkError::Trust.into()); }
            let address = addresses.into_iter().find(|a| a.is_ipv4() == self.bind.is_ipv4()).ok_or(SdkError::Invalid)?;
            let revoked = BTreeSet::new();
            let context = NetworkVerification { authority_key: &self.route.pin.authority_key, deployment_id: &self.route.deployment,
                space_id: &self.route.pin.space_id, policy_epoch: self.route.policy_epoch, now_ms: unix_ms()?, revoked_grant_ids: &revoked };
            let (authorization, revocation) = RouteAuthorization::remote(&context, &self.route.grants.path,
                &self.route.grants.connectivity, &self.route.grants.transits[index], &self.permit).map_err(RemoteError::from)?;
            if authorization.binding_digest() != candidate.route_binding() || authorization.relay() != candidate.relay() { return Err(SdkError::Trust.into()); }
            let node = AdjacencyEndpoint::bind_node(SocketAddr::new(self.bind.ip(), 0), &local.identity, candidate.relay()).map_err(SdkError::NodeQuic)?;
            let bound = node.local_addr().map_err(SdkError::ServiceIo)?;
            let revocation = Arc::new(revocation);
            let stop_guardian = standby_guardian(revocation.clone(), self.channels.lease_control(), self.cancel.clone(), self.route.deadline);
            self.standby = Some(Standby { index, bound, node: Some(node), inner: None, transport: None, revocation: Some(revocation),
                stop_guardian: Some(stop_guardian), measurements: LocalPathMeasurements::default(), close_deadline: None });
            // Node Pair/seen admits an original endpoint role only once. A
            // timeout is not permission to replay this reserved allocation.
            self.attempted_members.insert(index);
            let slot = self.standby.as_mut().ok_or(SdkError::Invalid)?;
            let adjacency = slot.node.as_mut().ok_or(SdkError::Invalid)?.connect_node(address, &local.identity,
                &local.device_id, candidate.allocation_id(), candidate.route_binding(), deadline).await.map_err(SdkError::NodeQuic)?;
            slot.node = None;
            slot.inner = Some(RoutedEstablishment::new(authorization, adjacency));
            let inner = slot.inner.as_mut().ok_or(SdkError::Invalid)?;
            inner.establish(&local.identity, deadline).await.map_err(SdkError::NodeQuic)?;
            slot.transport = Some(inner.take_transport().map_err(SdkError::ServiceIo)?);
            slot.inner = None;
            let now = ms_between(self.started, Instant::now())?;
            sample(slot, now)?;
            Ok((now, slot.measurements.snapshot(&self.originals[index].binding, now, false)))
        } else {
            let slot = self.standby.as_mut().filter(|slot| slot.index == index).ok_or(SdkError::Invalid)?;
            let connection = slot.transport.as_ref().ok_or(SdkError::Invalid)?.connection().map_err(SdkError::ServiceIo)?;
            let previous_acks = connection.stats().frame_rx.acks;
            // Limited encrypted transport control only. Quinn supplies genuine
            // ACK-derived RTT; this is not an application echo or capacity test.
            connection.send_datagram(bytes::Bytes::from_static(b"NestLink/W13/probe"))
                .map_err(|_| SdkError::ServiceIo(io::Error::new(io::ErrorKind::ConnectionAborted, "standby control probe unavailable")))?;
            loop {
                if connection.close_reason().is_some() {
                    return Err(SdkError::ServiceIo(io::ErrorKind::ConnectionAborted.into()).into());
                }
                let now = ms_between(self.started, Instant::now())?;
                let stats = connection.stats();
                slot.measurements.observe(now, LocalQuicSample { rtt: connection.rtt(), received_ack_frames: stats.frame_rx.acks,
                    sent_packets: stats.path.sent_packets, lost_packets: stats.path.lost_packets, business_tx_bytes: 0 });
                if stats.frame_rx.acks > previous_acks {
                    let at = slot.measurements.rtt_observed_at_ms(now).ok_or(SdkError::Invalid)?;
                    return Ok((at, slot.measurements.snapshot(&self.originals[index].binding, now, false)));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    /// Consume a still-current recovery suggestion by retiring the old business
    /// generation and every spare before the application's existing recovery
    /// coordinator requests fresh permits/grants. No old requests are replayed
    /// and no unproved spare is exposed as a ChannelRuntime.
    pub async fn retire_for_recovery(&mut self, sdk: &Sdk, local: &DeviceIdentity, peer_key: &[u8;32], proposal: &RouteSetRecoveryProposal) -> Result<StopReport, SessionEstablishError> {
        let current = self.status()?;
        if current.policy.proposal.as_ref() != Some(&proposal.proposal)
            || self.now()? >= proposal.proposal.deadline_ms()
            || self.index(proposal.proposal.to())? != proposal.candidate_index
            || self.route.candidate_for_admission(sdk, local, &self.permit, peer_key, proposal.candidate_index).is_none() {
            return Err(SdkError::Trust.into());
        }
        self.shutdown(StopReason::TransportLost).await
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<StopReport, SessionEstablishError> {
        let deadline = *self.close_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(2));
        let _ = self.channels.lease_control().stop(reason);
        self.scheduler.stop_continuation(nestlink_protocol::ErrorCode::PolicyRevoked);
        let standby = self.clear_standby(deadline).await;
        let active = self.channels.wait_stopped_before(deadline).await;
        standby?;
        Ok(active?)
    }
}
impl Drop for ContinuousRouteSetSession {
    fn drop(&mut self) {
        let _ = self.channels.lease_control().stop(StopReason::ExplicitExit);
        if let Some(standby) = &self.standby { standby.request_close(); }
    }
}
fn failure_code(error: &SessionEstablishError) -> nestlink_protocol::ErrorCode {
    use nestlink_protocol::ErrorCode;
    match error {
        SessionEstablishError::Cancelled | SessionEstablishError::Remote(RemoteError::Stopped)
            | SessionEstablishError::Sdk(SdkError::Trust | SdkError::Proof(_)) => ErrorCode::PolicyRevoked,
        SessionEstablishError::Sdk(SdkError::Invalid) => ErrorCode::InvalidMessage,
        SessionEstablishError::Sdk(SdkError::NodeQuic(error)) => {
            if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied) {
                ErrorCode::IdentityMismatch
            } else if error.downcast_ref::<quinn::ConnectionError>().is_some_and(|error| matches!(error, quinn::ConnectionError::TransportError(_))) {
                ErrorCode::ProtocolMismatch
            } else { ErrorCode::RelayUnavailable }
        }
        SessionEstablishError::Remote(RemoteError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => ErrorCode::IdentityMismatch,
        _ => ErrorCode::RelayUnavailable,
    }
}
fn sample(slot: &mut Standby, now: u64) -> Result<(), SdkError> {
    let connection = slot.transport.as_ref().ok_or(SdkError::Invalid)?.connection().map_err(SdkError::ServiceIo)?;
    let stats = connection.stats();
    slot.measurements.observe(now, LocalQuicSample { rtt: connection.rtt(), received_ack_frames: stats.frame_rx.acks,
        sent_packets: stats.path.sent_packets, lost_packets: stats.path.lost_packets, business_tx_bytes: 0 });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_security_and_cancel_are_terminal_while_unreachable_transport_is_not() {
        use nestlink_protocol::ErrorCode;
        assert_eq!(failure_code(&SessionEstablishError::Sdk(SdkError::Trust)), ErrorCode::PolicyRevoked);
        assert_eq!(failure_code(&SessionEstablishError::Cancelled), ErrorCode::PolicyRevoked);
        assert_eq!(failure_code(&SessionEstablishError::Sdk(SdkError::NodeQuic(Box::new(io::Error::from(io::ErrorKind::PermissionDenied))))), ErrorCode::IdentityMismatch);
        assert_eq!(failure_code(&SessionEstablishError::Remote(RemoteError::Io(io::ErrorKind::PermissionDenied.into()))), ErrorCode::IdentityMismatch);
        assert_eq!(failure_code(&SessionEstablishError::Sdk(SdkError::Timeout)), ErrorCode::RelayUnavailable);
        assert_eq!(failure_code(&SessionEstablishError::Remote(RemoteError::Io(io::ErrorKind::ConnectionRefused.into()))), ErrorCode::RelayUnavailable);
    }
}
