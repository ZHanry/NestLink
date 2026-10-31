//! Optional pure policy held by the existing Scheduler after establishment.
//! Inputs are observations, never admission grants or carrier capabilities.
//! The original transport owner must recheck typed authority before every
//! action and acknowledge actual preparation, switching and physical cleanup.
use super::{Outcome, Scheduler, error};
use crate::observation::{
    OBSERVATION_FRESHNESS_MS, PathObservationBinding, PathObservationSnapshot,
};
use nestlink_policy::PathSet;
use nestlink_protocol::{CANDIDATE_COUNT, ContractError, ErrorCode, network::Purpose};
use std::collections::BTreeSet;

pub const IMPROVEMENT_PERCENT: u128 = 15;
pub const IMPROVEMENT_HOLD_MS: u64 = 2_000;
pub const SWITCH_COOLDOWN_MS: u64 = 10_000;
pub const PREPARE_BUDGET_MS: u64 = 2_000;
pub const PROBE_BUDGET_MS: u64 = 700;
pub const PROPOSAL_BUDGET_MS: u64 = 2_000;
pub const BUSY_PROBE_INTERVAL_MS: u64 = 1_000;
pub const MAX_IDLE_PROBE_INTERVAL_MS: u64 = 30_000;

/// One immutable admission group. Construct only from the original verified
/// authority. This policy copy neither verifies nor extends its credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalGroup {
    pub business_grant_digest: [u8; 32],
    pub business_generation: u64,
    pub path_grant_id: String,
    pub transport_group: [u8; 32],
    pub purpose: Purpose,
    pub allowed_paths: PathSet,
    /// Original deadline in the owner's monotonic clock domain.
    pub deadline_ms: u64,
}

/// A route is never identified or deduplicated by its socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteIdentity {
    pub transport_group: [u8; 32],
    pub route_binding: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct OriginalRoute {
    pub binding: PathObservationBinding,
}
impl OriginalRoute {
    pub fn identity(&self) -> Option<RouteIdentity> {
        Some(RouteIdentity {
            transport_group: self.binding.transport_group?,
            route_binding: self.binding.route_binding?,
        })
    }
}

/// Optional hard limits require known fresh measurements. Offered business TX
/// and packet-window counters are intentionally not capacity or loss ratios.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QualityConstraints {
    pub minimum_available_bytes_per_second: Option<u64>,
    pub maximum_cost: Option<u64>,
    pub maximum_rtt: Option<std::time::Duration>,
    pub maximum_smoothed_rtt_change: Option<std::time::Duration>,
}

/// A synchronous owner check for this transition, not a cached authorization
/// lease. The SDK adapter must call its typed currentness/admission gates at
/// checked_at_ms; availability is distinct from locally measured reachability.
pub struct CurrentAuthority<'a> {
    pub original: &'a OriginalGroup,
    pub checked_at_ms: u64,
    pub current: bool,
    pub available_routes: &'a [RouteIdentity],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkKind {
    Prepare,
    Probe,
}

/// One physical owner incarnation. Repreparing the same original route gets a
/// new token, so late samples from its retired predecessor cannot revive it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationToken {
    sequence: u64,
    route: RouteIdentity,
    created_at_ms: u64,
}
impl ObservationToken {
    pub fn route(&self) -> RouteIdentity {
        self.route
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkToken {
    sequence: u64,
    epoch: u64,
    route: RouteIdentity,
    kind: WorkKind,
    deadline_ms: u64,
    started_at_ms: u64,
    observer: ObservationToken,
}
impl WorkToken {
    pub fn route(&self) -> RouteIdentity {
        self.route
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn kind(&self) -> WorkKind {
        self.kind
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub fn observer(&self) -> &ObservationToken {
        &self.observer
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchReason {
    SustainedImprovement,
    ActiveFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchProposal {
    sequence: u64,
    epoch: u64,
    from: RouteIdentity,
    to: RouteIdentity,
    reason: SwitchReason,
    deadline_ms: u64,
}
impl SwitchProposal {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn from(&self) -> RouteIdentity {
        self.from
    }
    pub fn to(&self) -> RouteIdentity {
        self.to
    }
    pub fn reason(&self) -> SwitchReason {
        self.reason
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementToken {
    sequence: u64,
    epoch: u64,
    route: RouteIdentity,
}
impl RetirementToken {
    pub fn route(&self) -> RouteIdentity {
        self.route
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuationAction {
    Prepare(WorkToken),
    Probe(WorkToken),
    ProposeSwitch(SwitchProposal),
    CancelProposal(SwitchProposal),
    Retire(RetirementToken),
    /// No currently proved, permitted standby can serve the failed active path.
    Unavailable,
    Terminal(ErrorCode),
}

pub enum ContinuationInput {
    Tick {
        demand: bool,
    },
    /// Actual local feedback for the active or already prepared standby owner.
    /// observed_at_ms is when genuine feedback arrived, never the time a cached
    /// snapshot was read. Unknown/expired individual fields must remain None.
    Feedback {
        observer: ObservationToken,
        observed_at_ms: u64,
        snapshot: Box<PathObservationSnapshot>,
    },
    /// Preparation/probe completion must carry the exact outstanding token and
    /// original route binding. Successful admission alone is not an RTT sample.
    WorkCompleted {
        work: WorkToken,
        observed_at_ms: u64,
        snapshot: Box<PathObservationSnapshot>,
    },
    WorkFailed {
        work: WorkToken,
        code: ErrorCode,
    },
    RouteFailed {
        observer: ObservationToken,
        code: ErrorCode,
    },
    /// Only W14's original owner may submit this after actual bilateral switch
    /// success and its synchronous current-authority check. No I/O runs here.
    Commit(SwitchProposal),
    RejectProposal(SwitchProposal),
    /// Receipt for completed physical cleanup, not merely a Drop request.
    Retired(RetirementToken),
}

#[derive(Clone, Debug, Default)]
pub struct ContinuationDecision {
    pub actions: Vec<ContinuationAction>,
    pub rejected: Option<ErrorCode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuationStatus {
    pub epoch: u64,
    pub active: Option<RouteIdentity>,
    pub standby: Option<RouteIdentity>,
    pub active_observer: Option<ObservationToken>,
    pub standby_observer: Option<ObservationToken>,
    pub outstanding_work: Option<WorkToken>,
    pub proposal: Option<SwitchProposal>,
    pub pending_retirements: usize,
    pub terminal: Option<ErrorCode>,
}

#[derive(Clone)]
struct Feedback {
    at_ms: u64,
    snapshot: PathObservationSnapshot,
}
struct Route {
    original: OriginalRoute,
    feedback: Option<Feedback>,
    failed: bool,
    retry_at_ms: u64,
    observer: Option<ObservationToken>,
}
pub(super) struct Continuation {
    group: OriginalGroup,
    constraints: QualityConstraints,
    routes: Vec<Route>,
    active: RouteIdentity,
    active_failed: bool,
    standby: Option<RouteIdentity>,
    standby_ready: bool,
    work: Option<WorkToken>,
    proposal: Option<SwitchProposal>,
    retirements: Vec<RetirementToken>,
    epoch: u64,
    sequence: u64,
    last_ms: u64,
    last_switch_ms: Option<u64>,
    improvement: Option<(RouteIdentity, u64)>,
    next_probe_ms: u64,
    probe_interval_ms: u64,
    demand: bool,
    cursor: usize,
    unavailable_reported: bool,
    terminal: Option<ErrorCode>,
    actions: Vec<ContinuationAction>,
}

impl Scheduler {
    /// Resume an already established original group, using this same Scheduler
    /// type and state owner. Unlike the legacy race, no address dedup occurs.
    /// This constructor performs no handshake and confers no carrier authority.
    pub fn for_established_group(
        generation: u64,
        now_ms: u64,
        group: OriginalGroup,
        routes: Vec<OriginalRoute>,
        active: RouteIdentity,
        constraints: QualityConstraints,
    ) -> Result<Self, ContractError> {
        let continuation =
            Continuation::new(generation, now_ms, group, routes, active, constraints)?;
        Ok(Self {
            generation,
            start_ms: now_ms,
            end_ms: continuation.group.deadline_ms,
            paths: continuation.group.allowed_paths,
            candidates: Vec::new(),
            pending: BTreeSet::new(),
            active: BTreeSet::new(),
            deadlines: Vec::new(),
            outcome: Outcome::Continuing,
            failures: Vec::new(),
            continuation: Some(continuation),
        })
    }

    /// The established transport owner supplies its exact winning route. A
    /// known native candidate must equal the legacy winner; absent routed
    /// candidate metadata is not inferred from an address or treated as a pin.
    pub fn enable_continuation(
        &mut self,
        now_ms: u64,
        group: OriginalGroup,
        routes: Vec<OriginalRoute>,
        active: RouteIdentity,
        constraints: QualityConstraints,
    ) -> Result<(), ContractError> {
        let Outcome::Connected(winner) = &self.outcome else {
            return Err(error(
                ErrorCode::ReplayRejected,
                "continuation requires an established race",
            ));
        };
        if self.continuation.is_some()
            || group.allowed_paths != self.paths
            || now_ms < self.start_ms
        {
            return Err(error(
                ErrorCode::PermissionRequired,
                "continuation cannot replace original paths or clock",
            ));
        }
        let continuation =
            Continuation::new(self.generation, now_ms, group, routes, active, constraints)?;
        if continuation
            .route(active)
            .and_then(|r| r.original.binding.candidate.as_ref())
            .is_some_and(|candidate| candidate != winner)
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "continuation winner differs from original candidate",
            ));
        }
        self.pending.clear();
        self.active.clear();
        self.outcome = Outcome::Continuing;
        self.continuation = Some(continuation);
        Ok(())
    }

    pub fn continuation_status(&self) -> Option<ContinuationStatus> {
        self.continuation.as_ref().map(Continuation::status)
    }
    pub fn advance_continuation(
        &mut self,
        now_ms: u64,
        authority: CurrentAuthority<'_>,
        input: ContinuationInput,
    ) -> ContinuationDecision {
        let Some(continuation) = self.continuation.as_mut() else {
            return ContinuationDecision {
                actions: Vec::new(),
                rejected: Some(ErrorCode::InvalidMessage),
            };
        };
        let decision = continuation.advance(now_ms, authority, input);
        if self.outcome != Outcome::NetworkChanged
            && let Some(code) = continuation.terminal
        {
            self.outcome = Outcome::Failed(code);
        }
        decision
    }
    pub fn stop_continuation(&mut self, code: ErrorCode) -> ContinuationDecision {
        let Some(continuation) = self.continuation.as_mut() else {
            return ContinuationDecision::default();
        };
        continuation.terminate(code);
        if self.outcome != Outcome::NetworkChanged {
            self.outcome = Outcome::Failed(code);
        }
        continuation.decision(None)
    }
}

impl Continuation {
    fn new(
        generation: u64,
        now_ms: u64,
        group: OriginalGroup,
        originals: Vec<OriginalRoute>,
        active: RouteIdentity,
        constraints: QualityConstraints,
    ) -> Result<Self, ContractError> {
        if generation == 0
            || group.business_generation == 0
            || group.business_grant_digest == [0; 32]
            || group.transport_group == [0; 32]
            || !nestlink_protocol::valid_id(&group.path_grant_id)
            || group.allowed_paths.is_empty()
            || group.deadline_ms <= now_ms
            || originals.is_empty()
            || originals.len() > CANDIDATE_COUNT as usize
        {
            return Err(error(
                ErrorCode::InvalidMessage,
                "invalid original continuation group",
            ));
        }
        let mut seen = BTreeSet::new();
        for original in &originals {
            let b = &original.binding;
            let key = original.identity().ok_or_else(|| {
                error(
                    ErrorCode::IdentityMismatch,
                    "missing original route identity",
                )
            })?;
            if key.transport_group != group.transport_group
                || key.route_binding == [0; 32]
                || !seen.insert(key)
                || b.business_grant_digest != group.business_grant_digest
                || b.business_generation != group.business_generation
                || b.path_grant_id.as_deref() != Some(group.path_grant_id.as_str())
                || b.purpose != group.purpose
                || !group.allowed_paths.contains(b.path)
                || b.network_generation.is_some_and(|g| g != generation)
            {
                return Err(error(
                    ErrorCode::IdentityMismatch,
                    "route does not belong to original immutable group",
                ));
            }
            if let Some(candidate) = &b.candidate {
                candidate.validate()?;
                if candidate.path() != b.path
                    || candidate.generation != generation
                    || b.network_generation != Some(generation)
                {
                    return Err(error(
                        ErrorCode::ReplayRejected,
                        "route candidate generation or path mismatch",
                    ));
                }
            }
        }
        if !seen.contains(&active) {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "active original route is absent",
            ));
        }
        Ok(Self {
            group,
            constraints,
            routes: originals
                .into_iter()
                .map(|original| {
                    let observer =
                        (original.identity() == Some(active)).then_some(ObservationToken {
                            sequence: 1,
                            route: active,
                            created_at_ms: now_ms,
                        });
                    Route {
                        original,
                        feedback: None,
                        failed: false,
                        retry_at_ms: now_ms,
                        observer,
                    }
                })
                .collect(),
            active,
            active_failed: false,
            standby: None,
            standby_ready: false,
            work: None,
            proposal: None,
            retirements: Vec::new(),
            epoch: 1,
            sequence: 1,
            last_ms: now_ms,
            last_switch_ms: None,
            improvement: None,
            next_probe_ms: now_ms,
            probe_interval_ms: BUSY_PROBE_INTERVAL_MS,
            demand: false,
            cursor: 0,
            unavailable_reported: false,
            terminal: None,
            actions: Vec::new(),
        })
    }
    fn status(&self) -> ContinuationStatus {
        ContinuationStatus {
            epoch: self.epoch,
            active: (!self.active_failed && self.terminal.is_none()).then_some(self.active),
            standby: self.standby,
            outstanding_work: self.work.clone(),
            proposal: self.proposal.clone(),
            active_observer: (!self.active_failed && self.terminal.is_none())
                .then(|| self.route(self.active).and_then(|r| r.observer.clone()))
                .flatten(),
            standby_observer: self
                .standby
                .filter(|_| self.standby_ready)
                .and_then(|key| self.route(key))
                .and_then(|r| r.observer.clone()),
            pending_retirements: self.retirements.len(),
            terminal: self.terminal,
        }
    }
    fn route(&self, key: RouteIdentity) -> Option<&Route> {
        self.routes
            .iter()
            .find(|r| r.original.identity() == Some(key))
    }
    fn route_mut(&mut self, key: RouteIdentity) -> Option<&mut Route> {
        self.routes
            .iter_mut()
            .find(|r| r.original.identity() == Some(key))
    }
    fn sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
    fn cancel_proposal(&mut self) {
        if let Some(proposal) = self.proposal.take() {
            self.actions
                .push(ContinuationAction::CancelProposal(proposal));
        }
    }
    fn retire(&mut self, route: RouteIdentity) {
        if self.retirements.iter().any(|r| r.route == route) {
            return;
        }
        if self.route(route).is_none_or(|r| r.observer.is_none()) {
            return;
        }
        if let Some(original) = self.route_mut(route) {
            original.observer = None;
            original.feedback = None;
        }
        let token = RetirementToken {
            sequence: self.sequence(),
            epoch: self.epoch,
            route,
        };
        self.retirements.push(token.clone());
        self.actions.push(ContinuationAction::Retire(token));
    }
    pub(super) fn terminate(&mut self, code: ErrorCode) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(code);
        self.cancel_proposal();
        self.work = None;
        self.improvement = None;
        self.retire(self.active);
        if let Some(standby) = self.standby.take() {
            self.retire(standby);
        }
        self.standby_ready = false;
        self.actions.push(ContinuationAction::Terminal(code));
    }
    fn decision(&mut self, rejected: Option<ErrorCode>) -> ContinuationDecision {
        ContinuationDecision {
            actions: std::mem::take(&mut self.actions),
            rejected,
        }
    }
    fn fresh(&self, key: RouteIdentity, now_ms: u64) -> Option<&Feedback> {
        self.route(key)?.feedback.as_ref().filter(|f| {
            now_ms
                .checked_sub(f.at_ms)
                .is_some_and(|age| age < OBSERVATION_FRESHNESS_MS)
                && !f.snapshot.stopped
        })
    }
    fn within_limits(&self, key: RouteIdentity, now_ms: u64) -> bool {
        let Some(f) = self.fresh(key, now_ms) else {
            return false;
        };
        let c = self.constraints;
        c.minimum_available_bytes_per_second.is_none_or(|min| {
            f.snapshot
                .available_bytes_per_second
                .is_some_and(|v| v >= min)
        }) && c
            .maximum_cost
            .is_none_or(|max| f.snapshot.cost.is_some_and(|v| v <= max))
            && c.maximum_rtt
                .is_none_or(|max| f.snapshot.rtt.is_some_and(|v| v <= max))
            && c.maximum_smoothed_rtt_change
                .is_none_or(|max| f.snapshot.smoothed_rtt_change.is_some_and(|v| v <= max))
    }
    fn improved(&self, standby: RouteIdentity, now_ms: u64) -> bool {
        if !self.within_limits(standby, now_ms) {
            return false;
        }
        let Some(a) = self.fresh(self.active, now_ms).and_then(|f| f.snapshot.rtt) else {
            return false;
        };
        let Some(b) = self.fresh(standby, now_ms).and_then(|f| f.snapshot.rtt) else {
            return false;
        };
        a.as_nanos() > 0 && b.as_nanos() * 100 <= a.as_nanos() * (100 - IMPROVEMENT_PERCENT)
    }
    fn feedback(
        &mut self,
        observer: &ObservationToken,
        observed_at_ms: u64,
        snapshot: PathObservationSnapshot,
        now_ms: u64,
    ) -> Result<(), ErrorCode> {
        let route = RouteIdentity {
            transport_group: snapshot
                .binding
                .transport_group
                .ok_or(ErrorCode::IdentityMismatch)?,
            route_binding: snapshot
                .binding
                .route_binding
                .ok_or(ErrorCode::IdentityMismatch)?,
        };
        if route != self.active && !(self.standby == Some(route) && self.standby_ready) {
            return Err(ErrorCode::ReplayRejected);
        }
        let original = self.route_mut(route).ok_or(ErrorCode::IdentityMismatch)?;
        if original.original.binding != snapshot.binding {
            return Err(ErrorCode::IdentityMismatch);
        }
        if original.failed
            || original.observer.as_ref() != Some(observer)
            || observer.route != route
        {
            return Err(ErrorCode::ReplayRejected);
        }
        if observed_at_ms > now_ms
            || observed_at_ms < observer.created_at_ms
            || original
                .feedback
                .as_ref()
                .is_some_and(|f| observed_at_ms <= f.at_ms)
        {
            return Err(ErrorCode::ReplayRejected);
        }
        if now_ms - observed_at_ms >= OBSERVATION_FRESHNESS_MS {
            original.feedback = None;
        } else {
            original.feedback = Some(Feedback {
                at_ms: observed_at_ms,
                snapshot,
            });
        }
        Ok(())
    }
    fn fail_route(&mut self, route: RouteIdentity, now_ms: u64) {
        if let Some(r) = self.route_mut(route) {
            r.failed = true;
            r.feedback = None;
            r.retry_at_ms = now_ms.saturating_add(BUSY_PROBE_INTERVAL_MS);
        }
        self.improvement = None;
        if route == self.active {
            self.active_failed = true;
            self.retire(route);
        }
        if self.standby == Some(route) {
            self.cancel_proposal();
            self.work = None;
            self.standby = None;
            self.standby_ready = false;
            self.retire(route);
        }
    }
    fn advance(
        &mut self,
        now_ms: u64,
        authority: CurrentAuthority<'_>,
        input: ContinuationInput,
    ) -> ContinuationDecision {
        let schedule_work = matches!(&input, ContinuationInput::Tick { .. });
        // Cleanup receipts remain consumable after any terminal fact; they can
        // only remove exact pending owners and cannot start or revive work.
        if let ContinuationInput::Retired(token) = &input {
            if let Some(index) = self.retirements.iter().position(|r| r == token) {
                self.retirements.remove(index);
            } else {
                return self.decision(Some(ErrorCode::ReplayRejected));
            }
            if self.terminal.is_some() {
                return self.decision(None);
            }
        }
        if self.terminal.is_some() {
            return self.decision(Some(ErrorCode::ReplayRejected));
        }
        if now_ms < self.last_ms {
            self.terminate(ErrorCode::ReplayRejected);
            return self.decision(Some(ErrorCode::ReplayRejected));
        }
        self.last_ms = now_ms;
        if now_ms >= self.group.deadline_ms {
            self.terminate(ErrorCode::LeaseExpired);
            return self.decision(Some(ErrorCode::LeaseExpired));
        }
        if authority.original != &self.group || !authority.current {
            self.terminate(ErrorCode::PolicyRevoked);
            return self.decision(Some(ErrorCode::PolicyRevoked));
        }
        if authority.checked_at_ms != now_ms
            || authority.available_routes.len() > self.routes.len()
            || authority
                .available_routes
                .iter()
                .any(|key| self.route(*key).is_none())
            || authority
                .available_routes
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != authority.available_routes.len()
        {
            self.improvement = None;
            return self.decision(Some(ErrorCode::ReplayRejected));
        }
        // Sequence exhaustion cannot wrap a work/proposal/retirement identity.
        if self.sequence > u64::MAX - 8 || self.epoch == u64::MAX {
            self.terminate(ErrorCode::CapacityExceeded);
            return self.decision(Some(ErrorCode::CapacityExceeded));
        }
        if !authority.available_routes.contains(&self.active) && !self.active_failed {
            self.fail_route(self.active, now_ms);
        }
        if let Some(standby) = self.standby
            && !authority.available_routes.contains(&standby)
        {
            self.fail_route(standby, now_ms);
        }
        if let Some(work) = &self.work
            && now_ms >= work.deadline_ms
        {
            let route = work.route;
            self.fail_route(route, now_ms);
        }
        // A gap cannot be hidden by replacing stale feedback with a fresh
        // sample: reset the hold before accepting the new measurement.
        if let Some(standby) = self.standby
            && !self.improved(standby, now_ms)
        {
            self.improvement = None;
        }
        if let Some(proposal) = &self.proposal {
            let current = now_ms < proposal.deadline_ms
                && self.within_limits(proposal.to, now_ms)
                && match proposal.reason {
                    SwitchReason::ActiveFailure => self.active_failed,
                    SwitchReason::SustainedImprovement => {
                        !self.active_failed
                            && self.improvement.is_some()
                            && self.improved(proposal.to, now_ms)
                    }
                };
            if !current {
                self.cancel_proposal();
            }
        }
        let result = match input {
            ContinuationInput::Tick { demand } => {
                if demand && !self.demand {
                    self.next_probe_ms = now_ms;
                }
                self.demand = demand;
                if demand {
                    self.probe_interval_ms = BUSY_PROBE_INTERVAL_MS;
                }
                Ok(())
            }
            ContinuationInput::Feedback {
                observer,
                observed_at_ms,
                snapshot,
            } => {
                let stopped = snapshot.stopped;
                let route = snapshot
                    .binding
                    .route_binding
                    .map(|route_binding| RouteIdentity {
                        transport_group: self.group.transport_group,
                        route_binding,
                    });
                let result = self.feedback(&observer, observed_at_ms, *snapshot, now_ms);
                if result.is_ok()
                    && stopped
                    && let Some(route) = route
                {
                    self.fail_route(route, now_ms);
                }
                result
            }
            ContinuationInput::WorkCompleted {
                work,
                observed_at_ms,
                snapshot,
            } => {
                if self.work.as_ref() != Some(&work)
                    || work.epoch != self.epoch
                    || now_ms >= work.deadline_ms
                    || self.standby != Some(work.route)
                {
                    Err(ErrorCode::ReplayRejected)
                } else {
                    // Validate before consuming the token or admitting a hot
                    // standby. Invalid feedback cannot count as preparation.
                    let valid = self
                        .route(work.route)
                        .is_some_and(|r| r.original.binding == snapshot.binding)
                        && !snapshot.stopped
                        && observed_at_ms <= now_ms
                        && observed_at_ms >= work.started_at_ms
                        && now_ms - observed_at_ms < OBSERVATION_FRESHNESS_MS;
                    if !valid {
                        Err(ErrorCode::IdentityMismatch)
                    } else {
                        let was_ready = self.standby_ready;
                        self.standby_ready = true;
                        let result =
                            self.feedback(&work.observer, observed_at_ms, *snapshot, now_ms);
                        if result.is_ok() {
                            self.work = None;
                            if work.kind == WorkKind::Prepare {
                                self.next_probe_ms = now_ms.saturating_add(self.probe_interval_ms);
                            }
                            if let Some(route) = self.route_mut(work.route) {
                                route.failed = false;
                            }
                        } else {
                            self.standby_ready = was_ready;
                        }
                        result
                    }
                }
            }
            ContinuationInput::WorkFailed { work, code } => {
                if self.work.as_ref() != Some(&work) || work.epoch != self.epoch {
                    Err(ErrorCode::ReplayRejected)
                } else {
                    if super::terminal_failure(code) {
                        self.terminate(code);
                    } else {
                        self.fail_route(work.route, now_ms);
                    }
                    Ok(())
                }
            }
            ContinuationInput::RouteFailed { observer, code } => {
                let route = observer.route;
                if (route != self.active && self.standby != Some(route))
                    || self
                        .route(route)
                        .is_none_or(|r| r.observer.as_ref() != Some(&observer))
                {
                    Err(ErrorCode::ReplayRejected)
                } else {
                    if super::terminal_failure(code) {
                        self.terminate(code);
                    } else {
                        self.fail_route(route, now_ms);
                    }
                    Ok(())
                }
            }
            ContinuationInput::Commit(proposal) => self.commit(proposal, now_ms),
            ContinuationInput::RejectProposal(proposal) => {
                if self.proposal.as_ref() != Some(&proposal) {
                    Err(ErrorCode::ReplayRejected)
                } else {
                    self.cancel_proposal();
                    self.improvement = None;
                    Ok(())
                }
            }
            ContinuationInput::Retired(_) => Ok(()),
        };
        if let Err(code) = result {
            self.improvement = None;
            self.cancel_proposal();
            return self.decision(Some(code));
        }
        if self.terminal.is_none() {
            self.progress(now_ms, authority.available_routes, schedule_work);
        }
        self.decision(None)
    }
    fn commit(&mut self, proposal: SwitchProposal, now_ms: u64) -> Result<(), ErrorCode> {
        if self.proposal.as_ref() != Some(&proposal)
            || proposal.epoch != self.epoch
            || now_ms >= proposal.deadline_ms
            || proposal.from != self.active
            || self.standby != Some(proposal.to)
            || !self.standby_ready
            || !self.within_limits(proposal.to, now_ms)
            || (proposal.reason == SwitchReason::SustainedImprovement
                && (!self.improved(proposal.to, now_ms)
                    || !self.hold_satisfied(proposal.to, now_ms)))
        {
            return Err(ErrorCode::ReplayRejected);
        }
        let old = self.active;
        self.active = proposal.to;
        self.active_failed = false;
        self.standby = None;
        self.standby_ready = false;
        self.work = None;
        self.proposal = None;
        self.epoch += 1;
        self.last_switch_ms = Some(now_ms);
        self.improvement = None;
        self.unavailable_reported = false;
        self.retire(old);
        Ok(())
    }
    fn progress(&mut self, now_ms: u64, available: &[RouteIdentity], schedule_work: bool) {
        if let Some(standby) = self.standby
            && self.standby_ready
        {
            let eligible = self.within_limits(standby, now_ms);
            let better = !self.active_failed && self.improved(standby, now_ms);
            if !better {
                self.improvement = None;
            }
            let reason = if self.active_failed && eligible {
                Some(SwitchReason::ActiveFailure)
            } else if better {
                self.improvement.get_or_insert((standby, now_ms));
                self.hold_satisfied(standby, now_ms)
                    .then_some(SwitchReason::SustainedImprovement)
            } else {
                None
            };
            if let Some(proposal) = &self.proposal
                && (proposal.reason == SwitchReason::SustainedImprovement && !better || !eligible)
            {
                self.cancel_proposal();
            }
            if self.work.is_none()
                && self.proposal.is_none()
                && let Some(reason) = reason
            {
                let mut deadline_ms = now_ms
                    .saturating_add(PROPOSAL_BUDGET_MS)
                    .min(self.group.deadline_ms);
                if let Some(feedback) = self.fresh(standby, now_ms) {
                    deadline_ms =
                        deadline_ms.min(feedback.at_ms.saturating_add(OBSERVATION_FRESHNESS_MS));
                }
                if reason == SwitchReason::SustainedImprovement
                    && let Some(feedback) = self.fresh(self.active, now_ms)
                {
                    deadline_ms =
                        deadline_ms.min(feedback.at_ms.saturating_add(OBSERVATION_FRESHNESS_MS));
                }
                let proposal = SwitchProposal {
                    sequence: self.sequence(),
                    epoch: self.epoch,
                    from: self.active,
                    to: standby,
                    reason,
                    deadline_ms,
                };
                self.proposal = Some(proposal.clone());
                self.actions
                    .push(ContinuationAction::ProposeSwitch(proposal));
            }
        }
        if self.active_failed && self.proposal.is_none() && !self.unavailable_reported {
            self.actions.push(ContinuationAction::Unavailable);
            self.unavailable_reported = true;
        }
        if self.proposal.is_some() || self.work.is_some() || !self.retirements.is_empty() {
            return;
        }
        if !schedule_work {
            return;
        }
        if let Some(standby) = self.standby {
            if now_ms >= self.next_probe_ms {
                self.start_work(standby, WorkKind::Probe, now_ms);
                if !self.demand {
                    self.probe_interval_ms =
                        (self.probe_interval_ms * 2).min(MAX_IDLE_PROBE_INTERVAL_MS);
                }
                self.next_probe_ms = now_ms.saturating_add(self.probe_interval_ms);
            }
        } else if self.demand || self.active_failed {
            for offset in 0..self.routes.len() {
                let index = (self.cursor + offset) % self.routes.len();
                let route = &self.routes[index];
                let Some(key) = route.original.identity() else {
                    continue;
                };
                if key != self.active && available.contains(&key) && now_ms >= route.retry_at_ms {
                    self.cursor = (index + 1) % self.routes.len();
                    self.standby = Some(key);
                    self.standby_ready = false;
                    self.start_work(key, WorkKind::Prepare, now_ms);
                    break;
                }
            }
        }
    }
    fn hold_satisfied(&self, standby: RouteIdentity, now_ms: u64) -> bool {
        self.improvement.is_some_and(|(key, since)| {
            key == standby
                && self
                    .fresh(self.active, now_ms)
                    .zip(self.fresh(standby, now_ms))
                    .is_some_and(|(a, b)| {
                        a.at_ms.min(b.at_ms).saturating_sub(since) >= IMPROVEMENT_HOLD_MS
                    })
        }) && self
            .last_switch_ms
            .is_none_or(|at| now_ms - at >= SWITCH_COOLDOWN_MS)
    }
    fn start_work(&mut self, route: RouteIdentity, kind: WorkKind, now_ms: u64) {
        let budget = match kind {
            WorkKind::Prepare => PREPARE_BUDGET_MS,
            WorkKind::Probe => PROBE_BUDGET_MS,
        };
        let sequence = self.sequence();
        let observer = if kind == WorkKind::Prepare {
            let observer = ObservationToken {
                sequence,
                route,
                created_at_ms: now_ms,
            };
            if let Some(original) = self.route_mut(route) {
                original.observer = Some(observer.clone());
                original.feedback = None;
                original.failed = false;
            }
            observer
        } else {
            let Some(observer) = self.route(route).and_then(|r| r.observer.clone()) else {
                self.terminate(ErrorCode::InternalError);
                return;
            };
            observer
        };
        let work = WorkToken {
            sequence,
            epoch: self.epoch,
            route,
            kind,
            observer,
            started_at_ms: now_ms,
            deadline_ms: now_ms.saturating_add(budget).min(self.group.deadline_ms),
        };
        self.work = Some(work.clone());
        self.actions.push(match kind {
            WorkKind::Prepare => ContinuationAction::Prepare(work),
            WorkKind::Probe => ContinuationAction::Probe(work),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{BusinessThroughputWindow, PacketLossWindow};
    use nestlink_protocol::{
        Path,
        api::{Candidate, CandidateKind, Transport},
    };
    use std::time::Duration;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn group() -> OriginalGroup {
        OriginalGroup {
            business_grant_digest: [1; 32],
            business_generation: 7,
            path_grant_id: "30000000-0000-4000-8000-000000000003".into(),
            transport_group: [2; 32],
            purpose: Purpose::RemoteControl,
            allowed_paths: PathSet::RELAY,
            deadline_ms: 60_000,
        }
    }
    fn originals(group: &OriginalGroup) -> Result<Vec<OriginalRoute>> {
        // Same socket hint, two different authenticated original route pins.
        let candidate = Candidate {
            kind: CandidateKind::Relay,
            transport: Transport::Quic,
            address: "127.0.0.1:28744".parse()?,
            generation: 1,
        };
        Ok([3, 4]
            .into_iter()
            .map(|id| OriginalRoute {
                binding: PathObservationBinding {
                    business_grant_digest: group.business_grant_digest,
                    business_generation: group.business_generation,
                    path_grant_id: Some(group.path_grant_id.clone()),
                    transport_group: Some(group.transport_group),
                    route_binding: Some([id; 32]),
                    purpose: group.purpose,
                    path: Path::Relay,
                    candidate: Some(candidate.clone()),
                    network_generation: Some(1),
                },
            })
            .collect())
    }
    fn snapshot(binding: &PathObservationBinding, rtt: Option<u64>) -> PathObservationSnapshot {
        PathObservationSnapshot {
            binding: binding.clone(),
            stopped: false,
            rtt: rtt.map(Duration::from_millis),
            smoothed_rtt_change: None,
            packet_loss: None,
            business_tx: None,
            available_bytes_per_second: None,
            cost: None,
        }
    }
    fn work(decision: &ContinuationDecision) -> Result<WorkToken> {
        decision
            .actions
            .iter()
            .find_map(|a| match a {
                ContinuationAction::Prepare(work) | ContinuationAction::Probe(work) => {
                    Some(work.clone())
                }
                _ => None,
            })
            .ok_or_else(|| "missing work action".into())
    }
    fn proposal(decision: &ContinuationDecision) -> Option<SwitchProposal> {
        decision.actions.iter().find_map(|a| match a {
            ContinuationAction::ProposeSwitch(p) => Some(p.clone()),
            _ => None,
        })
    }
    fn retirements(decision: &ContinuationDecision) -> Vec<RetirementToken> {
        decision
            .actions
            .iter()
            .filter_map(|a| match a {
                ContinuationAction::Retire(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }
    struct Harness {
        scheduler: Scheduler,
        group: OriginalGroup,
        routes: Vec<OriginalRoute>,
        keys: Vec<RouteIdentity>,
    }
    impl Harness {
        fn new(constraints: QualityConstraints) -> Result<Self> {
            let group = group();
            let routes = originals(&group)?;
            let keys: Vec<_> = routes.iter().filter_map(OriginalRoute::identity).collect();
            let scheduler = Scheduler::for_established_group(
                1,
                0,
                group.clone(),
                routes.clone(),
                keys[0],
                constraints,
            )?;
            Ok(Self {
                scheduler,
                group,
                routes,
                keys,
            })
        }
        fn step(&mut self, at: u64, input: ContinuationInput) -> ContinuationDecision {
            self.scheduler.advance_continuation(
                at,
                CurrentAuthority {
                    original: &self.group,
                    checked_at_ms: at,
                    current: true,
                    available_routes: &self.keys,
                },
                input,
            )
        }
        fn status(&self) -> Result<ContinuationStatus> {
            self.scheduler
                .continuation_status()
                .ok_or_else(|| "missing continuation".into())
        }
        fn feed(
            &mut self,
            at: u64,
            index: usize,
            rtt: Option<u64>,
        ) -> Result<ContinuationDecision> {
            let status = self.status()?;
            let observer = if status.active == Some(self.keys[index]) {
                status.active_observer
            } else {
                status.standby_observer
            }
            .ok_or("missing local observation owner")?;
            Ok(self.step(
                at,
                ContinuationInput::Feedback {
                    observer,
                    observed_at_ms: at,
                    snapshot: Box::new(snapshot(&self.routes[index].binding, rtt)),
                },
            ))
        }
        fn fail(&mut self, at: u64, index: usize, code: ErrorCode) -> Result<ContinuationDecision> {
            let status = self.status()?;
            let observer = if status.active == Some(self.keys[index]) {
                status.active_observer
            } else {
                status.standby_observer
            }
            .ok_or("missing failed owner")?;
            Ok(self.step(at, ContinuationInput::RouteFailed { observer, code }))
        }
        fn complete(
            &mut self,
            at: u64,
            token: WorkToken,
            rtt: Option<u64>,
        ) -> Result<ContinuationDecision> {
            let index = self
                .keys
                .iter()
                .position(|key| *key == token.route)
                .ok_or("unknown work route")?;
            Ok(self.step(
                at,
                ContinuationInput::WorkCompleted {
                    work: token,
                    observed_at_ms: at,
                    snapshot: Box::new(snapshot(&self.routes[index].binding, rtt)),
                },
            ))
        }
        fn warm(&mut self, standby_rtt: Option<u64>) -> Result<WorkToken> {
            let prepare = work(&self.step(0, ContinuationInput::Tick { demand: true }))?;
            assert_eq!(prepare.kind(), WorkKind::Prepare);
            assert_eq!(prepare.route(), self.keys[1]);
            assert_eq!(
                self.complete(1, prepare.clone(), standby_rtt)?.rejected,
                None
            );
            assert_eq!(self.feed(1, 0, Some(100))?.rejected, None);
            Ok(prepare)
        }
        fn normal_proposal(&mut self) -> Result<SwitchProposal> {
            self.warm(Some(85))?;
            assert!(proposal(&self.feed(2_000, 0, Some(100))?).is_none());
            assert!(proposal(&self.feed(2_000, 1, Some(85))?).is_none());
            assert!(proposal(&self.feed(2_001, 0, Some(100))?).is_none());
            proposal(&self.feed(2_001, 1, Some(85))?)
                .ok_or_else(|| "missing sustained switch".into())
        }
    }

    #[test]
    fn same_address_routes_remain_independent_and_cross_group_or_direct_only_is_rejected() -> Result
    {
        let mut h = Harness::new(QualityConstraints::default())?;
        assert_eq!(h.routes[0].binding.candidate, h.routes[1].binding.candidate);
        assert_ne!(h.keys[0], h.keys[1]);
        h.warm(None)?;
        assert_eq!(h.status()?.active, Some(h.keys[0]));
        assert_eq!(h.status()?.standby, Some(h.keys[1]));
        assert!(h.scheduler.poll(1).is_empty());
        let mut routed_without_native_hints = h.routes.clone();
        for route in &mut routed_without_native_hints {
            route.binding.candidate = None;
            route.binding.network_generation = None;
        }
        assert!(
            Scheduler::for_established_group(
                1,
                0,
                h.group.clone(),
                routed_without_native_hints,
                h.keys[0],
                QualityConstraints::default()
            )
            .is_ok()
        );
        for mutation in 0..6 {
            let mut group = h.group.clone();
            let mut routes = h.routes.clone();
            match mutation {
                0 => group.allowed_paths = PathSet::DIRECT,
                1 => routes[1].binding.transport_group = Some([9; 32]),
                2 => routes[1].binding.purpose = Purpose::PrivateService,
                3 => routes[1] = routes[0].clone(),
                4 => routes[1].binding.business_generation += 1,
                _ => routes[1].binding.network_generation = Some(2),
            }
            assert!(
                Scheduler::for_established_group(
                    1,
                    0,
                    group,
                    routes,
                    h.keys[0],
                    QualityConstraints::default()
                )
                .is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn fifteen_percent_requires_two_seconds_of_fresh_samples_and_explicit_owner_commit() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let proposed = h.normal_proposal()?;
        assert_eq!(proposed.reason(), SwitchReason::SustainedImprovement);
        assert_eq!(h.status()?.active, Some(h.keys[0]));
        let committed = h.step(2_002, ContinuationInput::Commit(proposed.clone()));
        assert_eq!(committed.rejected, None);
        assert_eq!(h.status()?.active, Some(h.keys[1]));
        assert_eq!(h.status()?.epoch, 2);
        assert_eq!(retirements(&committed).len(), 1);
        assert_eq!(
            h.step(2_003, ContinuationInput::Commit(proposed)).rejected,
            Some(ErrorCode::ReplayRejected)
        );
        // A pending old physical owner prevents another standby allocation.
        assert!(
            h.step(2_004, ContinuationInput::Tick { demand: true })
                .actions
                .is_empty()
        );
        Ok(())
    }
    #[test]
    fn transient_improvement_unknown_rtt_and_stale_gap_cannot_satisfy_the_hold() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        h.warm(Some(86))?;
        h.feed(2_001, 0, Some(100))?;
        assert!(proposal(&h.feed(2_001, 1, Some(86))?).is_none());
        h.feed(2_002, 1, Some(80))?;
        h.feed(3_000, 1, Some(95))?;
        h.feed(3_001, 1, Some(80))?;
        assert!(proposal(&h.feed(4_002, 0, Some(100))?).is_none());
        h.feed(4_003, 1, None)?;
        assert!(h.status()?.proposal.is_none());
        h.feed(4_004, 1, Some(80))?;
        // No poll during this gap: expired measurements must still reset hold.
        h.feed(7_004, 0, Some(100))?;
        assert!(proposal(&h.feed(7_004, 1, Some(80))?).is_none());
        h.feed(9_003, 0, Some(100))?;
        assert!(proposal(&h.feed(9_003, 1, Some(80))?).is_none());
        h.feed(9_004, 0, Some(100))?;
        assert!(proposal(&h.feed(9_004, 1, Some(80))?).is_some());
        Ok(())
    }
    #[test]
    fn switch_cooldown_blocks_optimization_but_a_real_active_failure_can_bypass_it() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let first = h.normal_proposal()?;
        let committed = h.step(2_002, ContinuationInput::Commit(first));
        let retired = retirements(&committed)
            .into_iter()
            .next()
            .ok_or("missing retirement")?;
        h.step(2_003, ContinuationInput::Retired(retired));
        let prepare = work(&h.step(2_004, ContinuationInput::Tick { demand: true }))?;
        assert_eq!(prepare.route(), h.keys[0]);
        h.complete(2_005, prepare, Some(60))?;
        h.feed(2_005, 1, Some(100))?;
        for at in [4_005, 6_005, 8_005, 10_005, 12_001] {
            assert!(proposal(&h.feed(at, 1, Some(100))?).is_none());
            assert!(proposal(&h.feed(at, 0, Some(60))?).is_none());
        }
        let failure = h.fail(12_001, 1, ErrorCode::RelayUnavailable)?;
        let failover = proposal(&failure).ok_or("failure must bypass remaining cooldown")?;
        assert_eq!(failover.reason(), SwitchReason::ActiveFailure);
        assert_eq!(h.status()?.active, None);
        assert_eq!(h.status()?.epoch, 2);
        h.step(12_001, ContinuationInput::Commit(failover));
        assert_eq!(h.status()?.active, Some(h.keys[0]));
        assert_eq!(h.status()?.epoch, 3);
        Ok(())
    }
    #[test]
    fn normal_optimization_resumes_only_after_the_original_ten_second_cooldown() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let p = h.normal_proposal()?;
        let committed = h.step(2_002, ContinuationInput::Commit(p));
        for token in retirements(&committed) {
            h.step(2_003, ContinuationInput::Retired(token));
        }
        let w = work(&h.step(2_004, ContinuationInput::Tick { demand: true }))?;
        h.complete(2_005, w, Some(60))?;
        h.feed(2_005, 1, Some(100))?;
        for at in [4_005, 6_005, 8_005, 10_005, 12_001] {
            assert!(proposal(&h.feed(at, 1, Some(100))?).is_none());
            assert!(proposal(&h.feed(at, 0, Some(60))?).is_none());
        }
        assert!(proposal(&h.feed(12_002, 1, Some(100))?).is_some());
        Ok(())
    }
    #[test]
    fn unknown_capacity_or_cost_and_offered_tx_never_satisfy_hard_constraints() -> Result {
        for constraints in [
            QualityConstraints {
                minimum_available_bytes_per_second: Some(1),
                ..Default::default()
            },
            QualityConstraints {
                maximum_cost: Some(10),
                ..Default::default()
            },
            QualityConstraints {
                maximum_smoothed_rtt_change: Some(Duration::from_millis(10)),
                ..Default::default()
            },
        ] {
            let mut h = Harness::new(constraints)?;
            let w = h.warm(Some(1))?;
            let mut sample = snapshot(&h.routes[1].binding, Some(1));
            sample.business_tx = Some(BusinessThroughputWindow {
                duration_ms: 1,
                payload_bytes: u64::MAX,
            });
            sample.packet_loss = Some(PacketLossWindow {
                duration_ms: 1,
                sent_packets: 0,
                newly_declared_lost_packets: 100,
            });
            h.step(
                2,
                ContinuationInput::Feedback {
                    observer: w.observer().clone(),
                    observed_at_ms: 2,
                    snapshot: Box::new(sample),
                },
            );
            let failed = h.fail(3, 0, ErrorCode::RelayUnavailable)?;
            assert!(proposal(&failed).is_none());
            assert!(failed.actions.contains(&ContinuationAction::Unavailable));
            assert_eq!(h.status()?.active, None);
        }
        Ok(())
    }
    #[test]
    fn forged_binding_future_sample_rollback_and_stale_authority_are_rejected() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let w = h.warm(Some(80))?;
        let mut wrong = snapshot(&h.routes[1].binding, Some(1));
        wrong.binding.business_generation += 1;
        assert_eq!(
            h.step(
                2,
                ContinuationInput::Feedback {
                    observer: w.observer().clone(),
                    observed_at_ms: 2,
                    snapshot: Box::new(wrong)
                }
            )
            .rejected,
            Some(ErrorCode::IdentityMismatch)
        );
        assert_eq!(
            h.step(
                3,
                ContinuationInput::Feedback {
                    observer: w.observer().clone(),
                    observed_at_ms: 4,
                    snapshot: Box::new(snapshot(&h.routes[1].binding, Some(1)))
                }
            )
            .rejected,
            Some(ErrorCode::ReplayRejected)
        );
        assert_eq!(
            h.step(
                3,
                ContinuationInput::Feedback {
                    observer: w.observer().clone(),
                    observed_at_ms: 1,
                    snapshot: Box::new(snapshot(&h.routes[1].binding, Some(1)))
                }
            )
            .rejected,
            Some(ErrorCode::ReplayRejected)
        );
        let stale = h.scheduler.advance_continuation(
            4,
            CurrentAuthority {
                original: &h.group,
                checked_at_ms: 3,
                current: true,
                available_routes: &h.keys,
            },
            ContinuationInput::Tick { demand: true },
        );
        assert_eq!(stale.rejected, Some(ErrorCode::ReplayRejected));
        let reversed = h.step(3, ContinuationInput::Tick { demand: true });
        assert_eq!(reversed.rejected, Some(ErrorCode::ReplayRejected));
        assert_eq!(h.status()?.terminal, Some(ErrorCode::ReplayRejected));
        assert_eq!(retirements(&reversed).len(), 2);
        assert_eq!(
            h.complete(5, w, Some(1))?.rejected,
            Some(ErrorCode::ReplayRejected)
        );
        Ok(())
    }
    #[test]
    fn revoked_changed_or_expired_authority_and_network_changes_cannot_be_revived() -> Result {
        for mutation in 0..5 {
            let mut h = Harness::new(QualityConstraints::default())?;
            let p = h.normal_proposal()?;
            let mut observed = h.group.clone();
            let mut current = true;
            let mut at = 2_002;
            match mutation {
                0 => current = false,
                1 => observed.deadline_ms += 1,
                2 => observed.purpose = Purpose::PrivateService,
                3 => at = h.group.deadline_ms,
                _ => h.scheduler.network_changed(2),
            }
            let rejected = h.scheduler.advance_continuation(
                at,
                CurrentAuthority {
                    original: &observed,
                    checked_at_ms: at,
                    current,
                    available_routes: &h.keys,
                },
                ContinuationInput::Commit(p.clone()),
            );
            assert!(rejected.rejected.is_some());
            assert!(h.status()?.terminal.is_some());
            assert_eq!(h.status()?.active, None);
            assert!(proposal(&h.step(at, ContinuationInput::Commit(p))).is_none());
        }
        Ok(())
    }
    #[test]
    fn idle_probes_back_off_have_one_original_deadline_and_late_work_has_no_effect() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let prepare = h.warm(None)?;
        assert_eq!(prepare.deadline_ms(), PREPARE_BUDGET_MS);
        assert!(
            h.step(1, ContinuationInput::Tick { demand: false })
                .actions
                .is_empty()
        );
        let first = work(&h.step(1_001, ContinuationInput::Tick { demand: false }))?;
        assert_eq!(first.kind(), WorkKind::Probe);
        assert_eq!(first.deadline_ms(), 1_001 + PROBE_BUDGET_MS);
        assert!(
            h.step(1_002, ContinuationInput::Tick { demand: false })
                .actions
                .is_empty()
        );
        assert_eq!(
            h.step(
                1_002,
                ContinuationInput::WorkCompleted {
                    work: first.clone(),
                    observed_at_ms: 1_000,
                    snapshot: Box::new(snapshot(&h.routes[1].binding, None))
                }
            )
            .rejected,
            Some(ErrorCode::IdentityMismatch)
        );
        assert_eq!(h.status()?.outstanding_work.as_ref(), Some(&first));
        h.complete(1_003, first, None)?;
        assert!(
            h.step(3_000, ContinuationInput::Tick { demand: false })
                .actions
                .is_empty()
        );
        let second = work(&h.step(3_001, ContinuationInput::Tick { demand: false }))?;
        let timed_out = h.step(
            second.deadline_ms(),
            ContinuationInput::Tick { demand: false },
        );
        assert_eq!(retirements(&timed_out).len(), 1);
        assert_eq!(
            h.complete(3_702, second, Some(1))?.rejected,
            Some(ErrorCode::ReplayRejected)
        );
        assert_eq!(h.status()?.standby, None);
        assert!(
            h.step(4_000, ContinuationInput::Tick { demand: true })
                .actions
                .is_empty()
        );
        let receipt = retirements(&timed_out)
            .into_iter()
            .next()
            .ok_or("missing probe cleanup receipt")?;
        h.step(4_001, ContinuationInput::Retired(receipt.clone()));
        assert_eq!(
            h.step(4_001, ContinuationInput::Retired(receipt)).rejected,
            Some(ErrorCode::ReplayRejected)
        );
        let new = work(&h.step(5_000, ContinuationInput::Tick { demand: true }))?;
        assert_ne!(new.observer(), prepare.observer());
        h.complete(5_001, new, Some(80))?;
        // Same group, same original route and a fresh timestamp still cannot
        // make a previous physical owner's delayed sample current.
        assert_eq!(
            h.step(
                5_002,
                ContinuationInput::Feedback {
                    observer: prepare.observer().clone(),
                    observed_at_ms: 5_002,
                    snapshot: Box::new(snapshot(&h.routes[1].binding, Some(1)))
                }
            )
            .rejected,
            Some(ErrorCode::ReplayRejected)
        );
        assert_eq!(
            h.step(
                5_003,
                ContinuationInput::RouteFailed {
                    observer: prepare.observer().clone(),
                    code: ErrorCode::IdentityMismatch
                }
            )
            .rejected,
            Some(ErrorCode::ReplayRejected)
        );
        assert_eq!(h.status()?.terminal, None);
        assert_eq!(h.status()?.standby, Some(h.keys[1]));
        Ok(())
    }
    #[test]
    fn vanished_target_cancels_a_pending_proposal_and_late_commit_is_rejected() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        let p = h.normal_proposal()?;
        let available = [h.keys[0]];
        let withdrawn = h.scheduler.advance_continuation(
            2_002,
            CurrentAuthority {
                original: &h.group,
                checked_at_ms: 2_002,
                current: true,
                available_routes: &available,
            },
            ContinuationInput::Commit(p),
        );
        assert_eq!(withdrawn.rejected, Some(ErrorCode::ReplayRejected));
        assert!(
            withdrawn
                .actions
                .iter()
                .any(|a| matches!(a, ContinuationAction::CancelProposal(_)))
        );
        assert_eq!(retirements(&withdrawn).len(), 1);
        assert_eq!(h.status()?.active, Some(h.keys[0]));
        assert!(h.status()?.proposal.is_none());
        Ok(())
    }
    #[test]
    fn proposal_has_a_fixed_deadline_and_fresh_feedback_cannot_reactivate_its_old_token() -> Result
    {
        let mut h = Harness::new(QualityConstraints::default())?;
        let p = h.normal_proposal()?;
        assert_eq!(p.deadline_ms(), 2_001 + PROPOSAL_BUDGET_MS);
        let expired = h.step(p.deadline_ms(), ContinuationInput::Commit(p.clone()));
        assert_eq!(expired.rejected, Some(ErrorCode::ReplayRejected));
        assert!(
            expired
                .actions
                .contains(&ContinuationAction::CancelProposal(p.clone()))
        );
        h.feed(4_002, 0, Some(100))?;
        h.feed(4_002, 1, Some(85))?;
        assert_eq!(
            h.step(4_003, ContinuationInput::Commit(p)).rejected,
            Some(ErrorCode::ReplayRejected)
        );
        assert_eq!(h.status()?.active, Some(h.keys[0]));
        assert!(h.status()?.proposal.is_none());
        Ok(())
    }
    #[test]
    fn known_hard_limits_can_admit_failure_recovery_but_security_failure_is_terminal() -> Result {
        let constraints = QualityConstraints {
            minimum_available_bytes_per_second: Some(1_000),
            maximum_cost: Some(10),
            maximum_rtt: Some(Duration::from_millis(90)),
            maximum_smoothed_rtt_change: Some(Duration::from_millis(5)),
        };
        let mut h = Harness::new(constraints)?;
        let w = h.warm(Some(80))?;
        let mut measured = snapshot(&h.routes[1].binding, Some(80));
        measured.available_bytes_per_second = Some(1_000);
        measured.cost = Some(10);
        measured.smoothed_rtt_change = Some(Duration::from_millis(5));
        assert_eq!(
            h.step(
                2,
                ContinuationInput::Feedback {
                    observer: w.observer().clone(),
                    observed_at_ms: 2,
                    snapshot: Box::new(measured)
                }
            )
            .rejected,
            None
        );
        assert!(proposal(&h.fail(3, 0, ErrorCode::RelayUnavailable)?).is_some());
        let terminal = h.fail(4, 1, ErrorCode::IdentityMismatch)?;
        assert_eq!(h.status()?.terminal, Some(ErrorCode::IdentityMismatch));
        assert!(
            terminal
                .actions
                .iter()
                .any(|a| matches!(a, ContinuationAction::CancelProposal(_)))
        );
        assert!(h.status()?.proposal.is_none());
        assert_eq!(h.status()?.active, None);
        Ok(())
    }
    #[test]
    fn opt_in_attaches_to_the_existing_successful_scheduler_once_and_preserves_the_winner() -> Result
    {
        let group = group();
        let routes = originals(&group)?;
        let active = routes[0].identity().ok_or("missing route")?;
        let candidate = routes[0]
            .binding
            .candidate
            .clone()
            .ok_or("missing native candidate")?;
        let mut scheduler = Scheduler::new(1, 0, PathSet::RELAY, vec![candidate])?;
        assert!(
            scheduler
                .enable_continuation(
                    0,
                    group.clone(),
                    routes.clone(),
                    active,
                    QualityConstraints::default()
                )
                .is_err()
        );
        let attempt = scheduler
            .poll(0)
            .into_iter()
            .next()
            .ok_or("missing original race attempt")?;
        scheduler.finish(attempt.id, true, "proved", ErrorCode::InternalError, 1);
        scheduler.enable_continuation(
            2,
            group.clone(),
            routes.clone(),
            active,
            QualityConstraints::default(),
        )?;
        assert_eq!(*scheduler.outcome(), Outcome::Continuing);
        assert!(
            scheduler
                .enable_continuation(3, group, routes, active, QualityConstraints::default())
                .is_err()
        );
        scheduler.finish(
            attempt.id,
            true,
            "late duplicate",
            ErrorCode::InternalError,
            3,
        );
        assert_eq!(*scheduler.outcome(), Outcome::Continuing);
        assert_eq!(
            scheduler
                .continuation_status()
                .ok_or("missing continuation")?
                .active,
            Some(active)
        );
        Ok(())
    }
    #[test]
    fn idle_backoff_is_capped_and_no_work_can_outlive_the_original_group() -> Result {
        let mut h = Harness::new(QualityConstraints::default())?;
        h.warm(None)?;
        for (at, next) in [
            (1_001, 3_001),
            (3_001, 7_001),
            (7_001, 15_001),
            (15_001, 31_001),
            (31_001, 61_001),
        ] {
            let w = work(&h.step(at, ContinuationInput::Tick { demand: false }))?;
            assert_eq!(w.kind(), WorkKind::Probe);
            assert!(w.deadline_ms() <= h.group.deadline_ms);
            h.complete(at + 1, w, None)?;
            if next < h.group.deadline_ms {
                assert!(
                    h.step(next - 1, ContinuationInput::Tick { demand: false })
                        .actions
                        .is_empty()
                );
            }
        }
        assert!(
            h.step(59_999, ContinuationInput::Tick { demand: false })
                .actions
                .is_empty()
        );
        assert_eq!(
            h.step(60_000, ContinuationInput::Tick { demand: true })
                .rejected,
            Some(ErrorCode::LeaseExpired)
        );
        assert_eq!(h.status()?.terminal, Some(ErrorCode::LeaseExpired));

        let mut group = group();
        group.deadline_ms = 500;
        let routes = originals(&group)?;
        let keys: Vec<_> = routes.iter().filter_map(OriginalRoute::identity).collect();
        let mut scheduler = Scheduler::for_established_group(
            1,
            0,
            group.clone(),
            routes,
            keys[0],
            QualityConstraints::default(),
        )?;
        let w = work(&scheduler.advance_continuation(
            100,
            CurrentAuthority {
                original: &group,
                checked_at_ms: 100,
                current: true,
                available_routes: &keys,
            },
            ContinuationInput::Tick { demand: true },
        ))?;
        assert_eq!(w.deadline_ms(), 500);
        Ok(())
    }
}
