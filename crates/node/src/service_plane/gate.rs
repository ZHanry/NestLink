use super::Error;
use crate::service_usage::ServiceUsageStore;
use crate::{
    control::{NodeControl, ServiceNodePermit},
    meter::{Counters, Meter},
};
use nestlink_identity::service_plane::VerifiedServiceLease;
use nestlink_protocol::{ContractError, ErrorCode, service_plane::ServiceLeaseClaims, valid_id};
use nestlink_session::ClockSample;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct PublicationContext {
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    /// Must come from a pinned policy-issuer delegation, not the lease payload.
    pub service_lease_issuer: [u8; 32],
}
pub struct ServicePublication {
    shared: Arc<Shared>,
}
#[derive(Clone)]
pub struct ServicePublicationHandle {
    shared: Arc<Shared>,
}
struct Shared {
    state: Mutex<State>,
    signal: watch::Sender<bool>,
}
struct State {
    started: Instant,
    verified: VerifiedServiceLease,
    lease_deadline: Instant,
    resource_deadline: Option<Instant>,
    last_clock: ClockSample,
    stopped: bool,
    meter: Meter,
    usage_store: Option<Arc<ServiceUsageStore>>,
    grant_id: String,
    grant_ceiling: u64,
    active_flows: u64,
    drain_progress: watch::Sender<u64>,
}
/// Opaque proof that the stopped publication had no remaining flow permits.
/// Only the service publication owner can construct this token.
pub struct ServiceDrainToken {
    pub(crate) grant_id: String,
    pub(crate) grant_sha256: [u8; 32],
    pub(crate) publication_id: String,
    pub(crate) publication_generation: u64,
    pub(crate) edge_runtime_id: String,
    pub(crate) edge_runtime_generation: u64,
}
pub struct ServiceFlowPermit {
    publication: ServicePublicationHandle,
    node: Option<ServiceNodePermit>,
    target_stop: Option<watch::Receiver<bool>>,
    last_activity: Mutex<Instant>,
}
pub(crate) fn rejected(code: ErrorCode) -> ContractError {
    ContractError::new(code, "service publication stopped or admission refused")
}
fn wall_clock() -> Result<u64, ContractError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rejected(ErrorCode::LeaseExpired))?
        .as_millis()
        .try_into()
        .map_err(|_| rejected(ErrorCode::LeaseExpired))
}
fn deadline(
    lease: &ServiceLeaseClaims,
    request_started: Instant,
    now: Instant,
    wall: u64,
) -> Result<Instant, ContractError> {
    signed_deadline(lease.issued_at_unix_ms, lease.expires_at_unix_ms, request_started, now, wall)
}
/// The signed remaining time already excludes response latency. Intersect its
/// receipt-relative end with the original request's signed lifetime, as the
/// independent NodeGate does. This never creates time after either bound.
pub(super) fn signed_deadline(issued: u64, expires: u64, request_started: Instant, now: Instant, wall: u64) -> Result<Instant, ContractError> {
    if request_started > now || issued > wall {
        return Err(ContractError::new(ErrorCode::LeaseExpired, "service signed deadline has a future request or issuance"));
    }
    let remaining = expires
        .checked_sub(wall)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| ContractError::new(ErrorCode::LeaseExpired, "service signed expiry passed before receipt"))?;
    let lifetime = expires.checked_sub(issued).filter(|lifetime| *lifetime > 0).ok_or_else(|| rejected(ErrorCode::LeaseExpired))?;
    let signed = now.checked_add(Duration::from_millis(remaining)).ok_or_else(|| rejected(ErrorCode::LeaseExpired))?;
    request_started.checked_add(Duration::from_millis(lifetime))
        .map(|request_end| request_end.min(signed))
        .filter(|end| *end > now)
        .ok_or_else(|| ContractError::new(ErrorCode::LeaseExpired, "service original request lifetime passed before receipt"))
}
impl State {
    fn live(&mut self) -> Result<Instant, ContractError> {
        if self.stopped {
            return Err(rejected(ErrorCode::PolicyRevoked));
        }
        let now = Instant::now();
        let sample = ClockSample {
            monotonic_ms: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| rejected(ErrorCode::LeaseExpired))?,
            unix_ms: wall_clock()?,
        };
        if sample.monotonic_ms < self.last_clock.monotonic_ms
            || sample.unix_ms < self.last_clock.unix_ms
            || sample.unix_ms.saturating_sub(self.last_clock.unix_ms)
                > sample
                    .monotonic_ms
                    .saturating_sub(self.last_clock.monotonic_ms)
                    .saturating_add(1000)
        {
            self.stopped = true;
            return Err(ContractError::new(ErrorCode::LeaseExpired, "service publication clock observation regressed or diverged"));
        }
        let end = self
            .resource_deadline
            .map_or(self.lease_deadline, |d| d.min(self.lease_deadline));
        if now >= end {
            self.stopped = true;
            return Err(ContractError::new(ErrorCode::LeaseExpired, "service publication original effective deadline passed"));
        }
        self.last_clock = sample;
        Ok(end)
    }
}
impl ServicePublication {
    pub fn new(
        verified: VerifiedServiceLease,
        context: &PublicationContext,
        request_started: Instant,
    ) -> Result<Self, Error> {
        Self::new_inner(verified, context, request_started, None)
    }
    pub(crate) fn new_with_usage_store(
        verified: VerifiedServiceLease,
        context: &PublicationContext,
        request_started: Instant,
        usage_store: Arc<ServiceUsageStore>,
    ) -> Result<Self, Error> {
        Self::new_inner(verified, context, request_started, Some(usage_store))
    }
    fn new_inner(
        verified: VerifiedServiceLease,
        context: &PublicationContext,
        request_started: Instant,
        usage_store: Option<Arc<ServiceUsageStore>>,
    ) -> Result<Self, Error> {
        let c = verified.claims();
        if !valid_id(&context.deployment_id)
            || c.deployment_id != context.deployment_id
            || c.security_epoch != context.security_epoch
            || c.policy_revision != context.policy_revision
            || verified.issuer() != context.service_lease_issuer
        {
            return Err(rejected(ErrorCode::IdentityMismatch).into());
        }
        let started = Instant::now();
        let wall = wall_clock()?;
        let lease_deadline = deadline(c, request_started, started, wall)?;
        let grant: nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims =
            nestlink_protocol::service_plane::decode_service_message(
                &c.usage_grant.claims,
                nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
            )?;
        let mut meter = Meter::default();
        if let Some(store) = &usage_store {
            let durable = store
                .activate(&verified)
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
            meter.restore(crate::meter::Counters {
                admitted_bytes: durable.admitted_bytes,
                opened_connections: durable.opened_connections,
                closed_connections: durable.closed_connections,
            })?;
        }
        let (signal, _) = watch::channel(false);
        let (drain_progress, _) = watch::channel(0u64);
        Ok(Self {
            shared: Arc::new(Shared {
                signal,
                state: Mutex::new(State {
                    started,
                    verified,
                    lease_deadline,
                    resource_deadline: None,
                    last_clock: ClockSample {
                        monotonic_ms: 0,
                        unix_ms: wall,
                    },
                    stopped: false,
                    meter,
                    usage_store,
                    grant_id: grant.grant_id,
                    grant_ceiling: grant.byte_ceiling,
                    active_flows: 0,
                    drain_progress,
                }),
            }),
        })
    }
    pub fn handle(&self) -> ServicePublicationHandle {
        ServicePublicationHandle {
            shared: self.shared.clone(),
        }
    }
    /// Identical leases may accompany fresh snapshots, but never extend the
    /// original lease deadline. A changed binding or expired owner is terminal.
    pub fn renew(
        &self,
        verified: VerifiedServiceLease,
        request_started: Instant,
    ) -> Result<(), Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        state.live()?;
        if state.verified.binding() != verified.binding()
            || state.verified.issuer() != verified.issuer()
        {
            state.stopped = true;
            self.shared.signal.send_replace(true);
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let old_sequence = state.verified.claims().lease_sequence;
        if verified.claims().lease_sequence < old_sequence {
            return Err(ContractError::new(
                ErrorCode::ReplayRejected,
                "service publication lease sequence regressed",
            )
            .into());
        }
        if verified.claims().lease_sequence == old_sequence
            && verified.digest() != state.verified.digest()
        {
            return Err(ContractError::new(
                ErrorCode::ReplayRejected,
                "service publication same sequence changed",
            )
            .into());
        }
        if verified.claims().lease_sequence == old_sequence {
            return Ok(());
        }
        let now = Instant::now();
        let end = deadline(verified.claims(), request_started, now, wall_clock()?)?;
        state.verified = verified;
        state.lease_deadline = end;
        self.shared.signal.send_replace(false);
        Ok(())
    }
    /// Only an already verified node resource snapshot may supply this cap.
    /// Snapshot absence/revocation is handled by revoking the owning object.
    pub(crate) fn cap_by_resource_snapshot(&self, deadline: Instant) -> Result<(), Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        state.live()?;
        if deadline <= Instant::now() {
            return Err(ContractError::new(ErrorCode::LeaseExpired, "service snapshot deadline passed before installation").into());
        }
        state.resource_deadline = Some(deadline);
        self.shared.signal.send_replace(false);
        Ok(())
    }
    pub fn revoke(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            if let Some(store) = &state.usage_store {
                // Stop the durable admission gate before waking flow owners.
                // Failure leaves the grant unresolved and cannot be sealed.
                let _ = store.request_stop(&state.grant_id);
            }
            state.stopped = true;
        }
        self.shared.signal.send_replace(true);
    }
}
impl Drop for ServicePublication {
    fn drop(&mut self) {
        self.revoke();
    }
}
impl ServicePublicationHandle {
    pub(crate) fn deadline(&self) -> Result<Instant, Error> {
        self.shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?
            .live()
            .map_err(Into::into)
    }
    pub(crate) fn changes(&self) -> watch::Receiver<bool> {
        self.shared.signal.subscribe()
    }
    pub fn lease(&self) -> Result<VerifiedServiceLease, Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        state.live()?;
        Ok(state.verified.clone())
    }
    pub fn counters(&self) -> Result<Counters, Error> {
        Ok(self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?
            .meter
            .counters())
    }
    pub fn is_stopped(&self) -> Result<bool, Error> {
        Ok(self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?
            .stopped)
    }
    /// Waits until the owner has revoked this exact publication and every
    /// flow permit has been dropped after its durable close. This token is a
    /// necessary drain condition; the edge supervisor still joins its workers
    /// and closes the matching QUIC connection before submitting it.
    pub async fn wait_drained(&self) -> Result<ServiceDrainToken, Error> {
        let mut progress = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?
            .drain_progress
            .subscribe();
        loop {
            {
                let state = self
                    .shared
                    .state
                    .lock()
                    .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
                if !state.stopped {
                    return Err(rejected(ErrorCode::PolicyRevoked).into());
                }
                if state.active_flows == 0 {
                    return drain_token(&state.verified);
                }
            }
            progress
                .changed()
                .await
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        }
    }
    /// Nonblocking form used by the edge supervisor for retired publications
    /// that never had an attachment or live flow.
    pub fn try_drain_token(&self) -> Result<Option<ServiceDrainToken>, Error> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        if !state.stopped || state.active_flows != 0 {
            return Ok(None);
        }
        drain_token(&state.verified).map(Some)
    }
    pub fn reserve_edge(
        &self,
        node: &NodeControl,
        source: IpAddr,
    ) -> Result<ServiceFlowPermit, Error> {
        let lease = self.lease()?;
        let node = node.reserve_service_capacity(&lease)?;
        self.reserve(Some(source), None, Some(node), None)
    }
    pub(crate) fn reserve_host(
        &self,
        source: IpAddr,
        target_stop: watch::Receiver<bool>,
    ) -> Result<ServiceFlowPermit, Error> {
        self.reserve(Some(source), None, None, Some(target_stop))
    }
    pub(super) fn reserve_private(
        &self,
        lease: &nestlink_identity::services::private::VerifiedPrivateServiceLease,
        target_stop: watch::Receiver<bool>,
    ) -> Result<ServiceFlowPermit, Error> {
        self.reserve(None, Some(lease), None, Some(target_stop))
    }
    fn reserve(
        &self,
        source: Option<IpAddr>,
        private: Option<&nestlink_identity::services::private::VerifiedPrivateServiceLease>,
        node: Option<ServiceNodePermit>,
        target_stop: Option<watch::Receiver<bool>>,
    ) -> Result<ServiceFlowPermit, Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        state.live()?;
        let admitted = match (source, private) {
            (Some(source), None) => state.verified.claims().permits_source(source),
            (None, Some(private)) => {
                private.check_time(wall_clock()?)?;
                private.lease().digest() == state.verified.digest()
                    && private.lease().issuer() == state.verified.issuer()
            }
            _ => false,
        };
        if !admitted || target_stop.as_ref().is_some_and(|s| *s.borrow()) {
            return Err(rejected(ErrorCode::PermissionRequired).into());
        }
        if state.meter.counters().admitted_bytes
            >= state
                .verified
                .claims()
                .effective_limits()
                .maximum_bytes
                .min(state.grant_ceiling)
        {
            return Err(Error::Quota);
        }
        let maximum = u32::from(
            state
                .verified
                .claims()
                .effective_limits()
                .maximum_connections,
        );
        let active_flows = state
            .active_flows
            .checked_add(1)
            .filter(|active| *active <= u64::from(maximum))
            .ok_or_else(|| rejected(ErrorCode::CapacityExceeded))?;
        if let Some(store) = &state.usage_store {
            let durable = store
                .reserve(&state.grant_id)
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
            state.meter.restore(crate::meter::Counters {
                admitted_bytes: durable.admitted_bytes,
                opened_connections: durable.opened_connections,
                closed_connections: durable.closed_connections,
            })?;
        } else {
            state.meter.reserve(maximum)?;
        }
        state.active_flows = active_flows;
        Ok(ServiceFlowPermit {
            publication: self.clone(),
            node,
            target_stop,
            last_activity: Mutex::new(Instant::now()),
        })
    }
}
fn drain_token(verified: &VerifiedServiceLease) -> Result<ServiceDrainToken, Error> {
    let claims = verified.claims();
    let grant: nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims =
        nestlink_protocol::service_plane::decode_service_message(
            &claims.usage_grant.claims,
            nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
        )?;
    Ok(ServiceDrainToken {
        grant_id: grant.grant_id,
        grant_sha256: nestlink_identity::digest(&claims.usage_grant.claims),
        publication_id: claims.publication_id.clone(),
        publication_generation: claims.publication_generation,
        edge_runtime_id: claims.edge_runtime_id.clone(),
        edge_runtime_generation: claims.edge_runtime_generation,
    })
}
impl ServiceFlowPermit {
    pub fn lease(&self) -> Result<VerifiedServiceLease, Error> {
        self.publication.lease()
    }
    pub fn check_live(&self) -> Result<(), Error> {
        self.live_deadline().map(|_| ())
    }
    fn live_deadline(&self) -> Result<Instant, Error> {
        if self
            .target_stop
            .as_ref()
            .is_some_and(|s| *s.borrow() || s.has_changed().is_err())
        {
            return Err(rejected(ErrorCode::PolicyRevoked).into());
        }
        let node_deadline = self
            .node
            .as_ref()
            .map(ServiceNodePermit::deadline)
            .transpose()?;
        let mut state = self
            .publication
            .shared
            .state
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        let mut end = state.live()?;
        if let Some(node) = node_deadline {
            end = end.min(node);
        }
        let activity = *self
            .last_activity
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
        let idle = activity
            .checked_add(Duration::from_secs(u64::from(
                state
                    .verified
                    .claims()
                    .effective_limits()
                    .idle_timeout_seconds,
            )))
            .ok_or_else(|| rejected(ErrorCode::LeaseExpired))?;
        end = end.min(idle);
        if Instant::now() >= end {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        Ok(end)
    }
    pub async fn wait_stopped(&self) {
        let mut publication = self.publication.shared.signal.subscribe();
        let mut node = self.node.as_ref().map(ServiceNodePermit::stopped);
        let mut target = self.target_stop.clone();
        loop {
            let Ok(end) = self.live_deadline() else {
                return;
            };
            tokio::select! { biased;
                _=optional_change(&mut node)=>{},
                _=optional_change(&mut target)=>{},
                _=publication.changed()=>{},
                _=tokio::time::sleep_until(end.into())=>{},
                _=tokio::time::sleep(Duration::from_millis(25))=>{},
            }
        }
    }
    /// Account both directions against one shared publication budget. Empty UDP
    /// datagrams consume one budget unit so they cannot bypass rate/byte limits.
    pub(crate) async fn charge(&self, payload_bytes: usize) -> Result<(), Error> {
        loop {
            match self.try_charge(payload_bytes) {
                Ok(()) => return Ok(()),
                Err(Error::Authorization(error)) if error.code == ErrorCode::CapacityExceeded => {
                    tokio::select! { biased;
                        _=self.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
                        _=tokio::time::sleep(Duration::from_millis(10))=>{},
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    pub(crate) fn try_charge(&self, payload_bytes: usize) -> Result<(), Error> {
        self.check_live()?;
        let charged = u64::try_from(payload_bytes.max(1))
            .map_err(|_| rejected(ErrorCode::CapacityExceeded))?;
        {
            let state = self
                .publication
                .shared
                .state
                .lock()
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
            if state
                .meter
                .counters()
                .admitted_bytes
                .checked_add(charged)
                .is_none_or(|n| {
                    n > state
                        .verified
                        .claims()
                        .effective_limits()
                        .maximum_bytes
                        .min(state.grant_ceiling)
                })
            {
                return Err(Error::Quota);
            }
        }
        let operation = || {
            let mut state = self
                .publication
                .shared
                .state
                .lock()
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
            state.live()?;
            let limits = state.verified.claims().effective_limits();
            if state
                .meter
                .counters()
                .admitted_bytes
                .checked_add(charged)
                .is_none_or(|n| n > limits.maximum_bytes.min(state.grant_ceiling))
            {
                return Err(rejected(ErrorCode::CapacityExceeded));
            }
            let now = state.last_clock.monotonic_ms;
            let grant_id = state.grant_id.clone();
            let store = state.usage_store.clone();
            state
                .meter
                .admit_durable(charged, limits.bytes_per_second, now, |counters| {
                    if let Some(store) = store {
                        let durable = store
                            .admit(&grant_id, charged)
                            .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
                        if durable.admitted_bytes != counters.admitted_bytes {
                            return Err(rejected(ErrorCode::PolicyRevoked));
                        }
                    }
                    Ok(())
                })
        };
        if let Some(node) = &self.node {
            node.admit(charged, operation)?;
        } else {
            operation()?;
        }
        Ok(())
    }
    pub(crate) fn activity(&self) -> Result<(), Error> {
        self.check_live()?;
        *self
            .last_activity
            .lock()
            .map_err(|_| rejected(ErrorCode::PolicyRevoked))? = Instant::now();
        Ok(())
    }
    pub(crate) fn chunk_budget(&self) -> Result<usize, Error> {
        let lease = self.lease()?;
        let remaining = {
            let state = self
                .publication
                .shared
                .state
                .lock()
                .map_err(|_| rejected(ErrorCode::PolicyRevoked))?;
            lease
                .claims()
                .effective_limits()
                .maximum_bytes
                .min(state.grant_ceiling)
                .saturating_sub(state.meter.counters().admitted_bytes)
        };
        let node_rate = self
            .node
            .as_ref()
            .map(ServiceNodePermit::byte_rate)
            .transpose()?
            .unwrap_or(u64::MAX);
        let budget = remaining
            .max(1)
            .min(lease.claims().effective_limits().bytes_per_second)
            .min(node_rate)
            .min(16 * 1024);
        usize::try_from(budget)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| rejected(ErrorCode::CapacityExceeded).into())
    }
    pub(crate) fn is_edge(&self) -> bool {
        self.node.is_some()
    }
}
impl Drop for ServiceFlowPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.publication.shared.state.lock() {
            if let Some(store) = &state.usage_store {
                match store.close(&state.grant_id) {
                    Ok(durable) => {
                        let _ = state.meter.restore(crate::meter::Counters {
                            admitted_bytes: durable.admitted_bytes,
                            opened_connections: durable.opened_connections,
                            closed_connections: durable.closed_connections,
                        });
                    }
                    Err(_) => {
                        state.stopped = true;
                        self.publication.shared.signal.send_replace(true);
                    }
                }
            } else {
                state.meter.close();
            }
            if let Some(active) = state.active_flows.checked_sub(1) {
                state.active_flows = active;
                state.drain_progress.send_replace(active);
            } else {
                state.stopped = true;
                self.publication.shared.signal.send_replace(true);
            }
        }
    }
}
async fn optional_change(receiver: &mut Option<watch::Receiver<bool>>) {
    if let Some(receiver) = receiver {
        let _ = receiver.changed().await;
    } else {
        std::future::pending::<()>().await;
    }
}
