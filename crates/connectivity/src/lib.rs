//! Bounded candidate scheduling. NAT descriptions never decide reachability.
use nestlink_policy::PathSet;
pub use nestlink_protocol::api::{Candidate, CandidateKind, Transport};
use nestlink_protocol::{
    CANDIDATE_ATTEMPT_MS, CANDIDATE_COUNT, CONNECTION_BUDGET_MS, ContractError, ErrorCode,
    PARALLEL_ATTEMPTS, Path, RELAY_START_MS,
};
use std::collections::BTreeSet;
#[derive(Debug, Clone)]
pub struct Attempt {
    pub id: usize,
    pub candidate: Candidate,
    pub deadline_ms: u64,
}
#[derive(Debug, Clone)]
pub struct Failure {
    pub candidate: Candidate,
    pub stage: String,
    pub code: ErrorCode,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Checking,
    Connected(Candidate),
    Failed(ErrorCode),
    NetworkChanged,
}
pub struct Scheduler {
    generation: u64,
    start_ms: u64,
    end_ms: u64,
    paths: PathSet,
    candidates: Vec<Candidate>,
    pending: BTreeSet<usize>,
    active: BTreeSet<usize>,
    deadlines: Vec<u64>,
    outcome: Outcome,
    failures: Vec<Failure>,
}
impl Scheduler {
    pub fn new(
        generation: u64,
        start_ms: u64,
        paths: PathSet,
        mut candidates: Vec<Candidate>,
    ) -> Result<Self, ContractError> {
        if generation == 0 || paths.is_empty() || candidates.len() > CANDIDATE_COUNT as usize {
            return Err(error(
                ErrorCode::CapacityExceeded,
                "candidate generation, path set or count is invalid",
            ));
        }
        for candidate in &candidates {
            candidate.validate()?;
            if candidate.generation != generation {
                return Err(error(
                    ErrorCode::ReplayRejected,
                    "candidate belongs to a previous network generation",
                ));
            }
        }
        candidates.retain(|candidate| paths.contains(candidate.path()));
        candidates
            .sort_by_key(|candidate| (candidate.kind, candidate.transport, candidate.address));
        candidates.dedup_by(|a, b| {
            a.address == b.address && a.transport == b.transport && a.kind == b.kind
        });
        let len = candidates.len();
        let end_ms = start_ms
            .checked_add(CONNECTION_BUDGET_MS)
            .ok_or_else(|| error(ErrorCode::InvalidMessage, "connection clock overflow"))?;
        Ok(Self {
            generation,
            start_ms,
            end_ms,
            paths,
            candidates,
            pending: (0..len).collect(),
            active: BTreeSet::new(),
            deadlines: vec![0; len],
            outcome: Outcome::Checking,
            failures: Vec::new(),
        })
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub fn failures(&self) -> &[Failure] {
        &self.failures
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn poll(&mut self, now_ms: u64) -> Vec<Attempt> {
        if self.outcome != Outcome::Checking {
            return vec![];
        }
        if now_ms < self.start_ms {
            self.outcome = Outcome::NetworkChanged;
            self.active.clear();
            return vec![];
        }
        let expired: Vec<_> = self
            .active
            .iter()
            .copied()
            .filter(|id| now_ms >= self.deadlines[*id])
            .collect();
        for id in expired {
            let code = if self.candidates[id].path() == Path::Direct {
                ErrorCode::DirectUnavailable
            } else {
                ErrorCode::RelayUnavailable
            };
            self.finish(id, false, "timeout", code, now_ms);
        }
        if now_ms >= self.end_ms {
            self.fail();
            return vec![];
        }
        let mut ready = Vec::new();
        let has_relay = self.candidates.iter().any(|c| c.path() == Path::Relay);
        let pending: Vec<_> = self.pending.iter().copied().collect();
        for id in pending {
            if self.active.len() >= PARALLEL_ATTEMPTS as usize {
                break;
            }
            let candidate = &self.candidates[id];
            let active_direct = self
                .active
                .iter()
                .filter(|id| self.candidates[**id].path() == Path::Direct)
                .count();
            if has_relay
                && candidate.path() == Path::Direct
                && active_direct >= (PARALLEL_ATTEMPTS - 1) as usize
            {
                continue;
            }
            let delay = if candidate.path() == Path::Relay && self.paths.contains(Path::Direct) {
                RELAY_START_MS
            } else if candidate.path() == Path::Direct {
                match candidate.kind {
                    CandidateKind::Lan => 0,
                    CandidateKind::Ipv6 => 250,
                    CandidateKind::Reflexive => 500,
                    CandidateKind::Relay => 0,
                }
            } else {
                0
            };
            if now_ms < self.start_ms + delay {
                continue;
            }
            self.pending.remove(&id);
            let deadline_ms = now_ms.saturating_add(CANDIDATE_ATTEMPT_MS).min(self.end_ms);
            self.deadlines[id] = deadline_ms;
            self.active.insert(id);
            ready.push(Attempt {
                id,
                candidate: candidate.clone(),
                deadline_ms,
            });
        }
        if self.pending.is_empty() && self.active.is_empty() {
            self.fail();
        }
        ready
    }
    pub fn finish(&mut self, id: usize, success: bool, stage: &str, code: ErrorCode, now_ms: u64) {
        if self.outcome != Outcome::Checking || !self.active.remove(&id) {
            return;
        }
        if success && now_ms < self.deadlines[id] && now_ms < self.end_ms {
            self.outcome = Outcome::Connected(self.candidates[id].clone());
            self.active.clear();
            return;
        }
        self.failures.push(Failure {
            candidate: self.candidates[id].clone(),
            stage: stage.chars().take(128).collect(),
            code,
        });
    }
    pub fn network_changed(&mut self, new_generation: u64) {
        if new_generation != self.generation {
            self.active.clear();
            self.outcome = Outcome::NetworkChanged;
        }
    }
    fn fail(&mut self) {
        self.active.clear();
        self.outcome = Outcome::Failed(if self.paths == PathSet::DIRECT {
            ErrorCode::DirectUnavailable
        } else if self
            .candidates
            .iter()
            .any(|c| c.path() == Path::Relay && c.transport == Transport::WebRtc)
        {
            ErrorCode::TurnUnreachable
        } else {
            ErrorCode::RelayUnavailable
        });
    }
}
fn error(code: ErrorCode, detail: &'static str) -> ContractError {
    ContractError::new(code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(
        kind: CandidateKind,
        transport: Transport,
        address: &str,
    ) -> Result<Candidate, Box<dyn std::error::Error>> {
        Ok(Candidate {
            kind,
            transport,
            address: address.parse()?,
            generation: 1,
        })
    }
    #[test]
    fn relay_only_never_attempts_direct_and_old_network_results_are_ignored()
    -> Result<(), Box<dyn std::error::Error>> {
        let direct = candidate(CandidateKind::Lan, Transport::Quic, "127.0.0.1:28743")?;
        let relay = candidate(CandidateKind::Relay, Transport::Wss, "127.0.0.1:443")?;
        let mut scheduler = Scheduler::new(1, 0, PathSet::RELAY, vec![direct, relay.clone()])?;
        let attempts = scheduler.poll(0);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].candidate, relay);
        scheduler.network_changed(2);
        scheduler.finish(0, true, "handshake", ErrorCode::InternalError, 1);
        assert_eq!(*scheduler.outcome(), Outcome::NetworkChanged);
        Ok(())
    }
    #[test]
    fn direct_only_has_full_budget_and_no_relay_leak() -> Result<(), Box<dyn std::error::Error>> {
        let direct = candidate(
            CandidateKind::Reflexive,
            Transport::Tls,
            "192.168.10.2:28743",
        )?;
        let relay = candidate(CandidateKind::Relay, Transport::Wss, "127.0.0.1:443")?;
        let mut scheduler = Scheduler::new(1, 0, PathSet::DIRECT, vec![direct, relay])?;
        assert!(scheduler.poll(0).is_empty());
        let attempts = scheduler.poll(500);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].deadline_ms, 6500);
        assert!(scheduler.poll(1000).is_empty());
        assert_eq!(*scheduler.outcome(), Outcome::Checking);
        scheduler.poll(6500);
        assert_eq!(
            *scheduler.outcome(),
            Outcome::Failed(ErrorCode::DirectUnavailable)
        );
        Ok(())
    }
    #[test]
    fn direct_preferred_races_authorized_relay_after_two_seconds()
    -> Result<(), Box<dyn std::error::Error>> {
        let direct = candidate(CandidateKind::Lan, Transport::Quic, "127.0.0.1:28743")?;
        let relay = candidate(CandidateKind::Relay, Transport::Wss, "127.0.0.1:443")?;
        let mut scheduler = Scheduler::new(1, 0, PathSet::BOTH, vec![relay, direct])?;
        assert_eq!(scheduler.poll(0).len(), 1);
        assert!(scheduler.poll(1999).is_empty());
        let relay = scheduler.poll(2000);
        assert_eq!(relay.len(), 1);
        scheduler.finish(
            relay[0].id,
            true,
            "mutual-tls",
            ErrorCode::InternalError,
            3000,
        );
        assert!(matches!(scheduler.outcome(),Outcome::Connected(c)if c.path()==Path::Relay));
        Ok(())
    }
}
