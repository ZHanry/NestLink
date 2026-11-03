//! One bounded bilateral transcript. This verifies installation signatures;
//! callers still own current business/path authorization and physical I/O.
use super::{fresh_challenge, verify};
use crate::{ContractError, ErrorCode, InstallationIdentity, digest};
use nestlink_protocol::{
    network::PeerId,
    network_migration::{Binding, Envelope, Kind, MAX_CONTROL_LIFETIME_MS, MAX_DRAIN_MS},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Waiting,
    Proposed,
    Accepted,
    Committing,
    Committed,
    Closed,
}

/// A signature transcript receipt, never a socket or a new authorization.
/// An incomplete Commit may already have reached the peer: timeout requires
/// safe recovery or stop, never an uncoordinated rollback to an old path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub binding: Binding,
    pub proposal: [u8; 32],
    pub challenge: [u8; 32],
    pub committed_at_unix_ms: u64,
    pub old_path_drain_until_unix_ms: u64,
    pub authority_expires_at_unix_ms: u64,
}
impl Committed {
    /// Revocation/currentness takes precedence over any finite receive grace.
    pub fn accepts_path_epoch(&self, epoch: u64, now_ms: u64, current: bool) -> bool {
        current && now_ms >= self.committed_at_unix_ms
            && now_ms < self.authority_expires_at_unix_ms && (epoch == self.binding.next_path_epoch
            || (epoch == self.binding.previous_path_epoch
                && now_ms >= self.committed_at_unix_ms
                && now_ms < self.old_path_drain_until_unix_ms))
    }
}

pub struct Transcript {
    expected: Binding,
    local: PeerId,
    remote_key: [u8; 32],
    authority_expiry_ms: u64,
    last_ms: u64,
    phase: Phase,
    proposal: Option<Envelope>,
    accepted: Option<Envelope>,
    commit: Option<Envelope>,
    committed: Option<Envelope>,
    receipt: Option<Committed>,
}

fn rejected(code: ErrorCode) -> ContractError {
    ContractError::new(code, "path migration transcript refused")
}

impl Transcript {
    pub fn new(
        expected: Binding,
        local: PeerId,
        remote_key: [u8; 32],
        authority_expiry_ms: u64,
        now_ms: u64,
    ) -> Result<Self, ContractError> {
        expected.validate()?;
        let remote = PeerId(digest(&remote_key));
        if !expected.peers.contains(local) || !expected.peers.contains(remote) || local == remote
            || now_ms >= authority_expiry_ms
        {
            return Err(rejected(ErrorCode::IdentityMismatch));
        }
        Ok(Self {
            expected, local, remote_key, authority_expiry_ms, last_ms: now_ms,
            phase: Phase::Waiting, proposal: None, accepted: None,
            commit: None, committed: None, receipt: None,
        })
    }
    pub fn phase(&self) -> Phase { self.phase }
    pub fn leader(&self) -> bool { self.local == self.expected.peers.first }
    pub fn receipt(&self) -> Option<&Committed> { self.receipt.as_ref() }
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.receipt = None;
    }
    fn check(&mut self, now_ms: u64, current: bool) -> Result<(), ContractError> {
        let code = if !current { Some(ErrorCode::PolicyRevoked) }
            else if now_ms < self.last_ms { Some(ErrorCode::ReplayRejected) }
            else if now_ms >= self.authority_expiry_ms
                || self.proposal.as_ref().is_some_and(|proposal| now_ms >= proposal.binding.expires_at_unix_ms)
            { Some(ErrorCode::LeaseExpired) }
            else if self.phase == Phase::Closed { Some(ErrorCode::ReplayRejected) }
            else { None };
        if let Some(code) = code { self.close(); return Err(rejected(code)); }
        self.last_ms = now_ms;
        Ok(())
    }
    fn signed(
        &self, identity: &InstallationIdentity, mut envelope: Envelope,
    ) -> Result<Envelope, ContractError> {
        if PeerId(identity.fingerprint()) != self.local {
            return Err(rejected(ErrorCode::IdentityMismatch));
        }
        envelope.signature = identity.sign_network_migration(&envelope)?;
        Ok(envelope)
    }
    pub fn propose(
        &mut self, identity: &InstallationIdentity, now_ms: u64, current: bool,
    ) -> Result<Envelope, ContractError> {
        self.check(now_ms, current)?;
        if !self.leader() { return Err(rejected(ErrorCode::PermissionRequired)); }
        if let Some(proposal) = &self.proposal { return Ok(proposal.clone()); }
        let mut binding = self.expected.clone();
        binding.expires_at_unix_ms = self.authority_expiry_ms.min(
            now_ms.checked_add(MAX_CONTROL_LIFETIME_MS).ok_or_else(|| rejected(ErrorCode::LeaseExpired))?
        );
        let proposal = self.signed(identity, Envelope {
            kind: Kind::Proposal, binding, proposal: fresh_challenge(),
            challenge: [0; 32], signature: [0; 64],
        })?;
        self.proposal = Some(proposal.clone());
        self.phase = Phase::Proposed;
        Ok(proposal)
    }
    /// The ordered peer pair elects one proposal writer. Both application
    /// owners may trigger concurrently; the second waits for the first rather
    /// than creating competing reservations or a second transition identity.
    pub fn receive(
        &mut self, identity: &InstallationIdentity, envelope: &Envelope,
        now_ms: u64, current: bool,
    ) -> Result<Option<Envelope>, ContractError> {
        let result = self.receive_inner(identity, envelope, now_ms, current);
        if result.is_err() { self.close(); }
        result
    }
    fn receive_inner(
        &mut self, identity: &InstallationIdentity, envelope: &Envelope,
        now_ms: u64, current: bool,
    ) -> Result<Option<Envelope>, ContractError> {
        self.check(now_ms, current)?;
        verify(envelope, &self.remote_key)?;
        if !self.expected.same_scope(&envelope.binding)
            || envelope.binding.expires_at_unix_ms > self.authority_expiry_ms
            || envelope.binding.expires_at_unix_ms <= now_ms
            || envelope.binding.expires_at_unix_ms - now_ms > MAX_CONTROL_LIFETIME_MS
            || self.proposal.as_ref().is_some_and(|original| original.binding != envelope.binding
                || original.proposal != envelope.proposal)
        { return Err(rejected(ErrorCode::ReplayRejected)); }
        match envelope.kind {
            Kind::Proposal if !self.leader() => {
                if let Some(accepted) = &self.accepted { return Ok(Some(accepted.clone())); }
                if self.phase != Phase::Waiting { return Err(rejected(ErrorCode::ReplayRejected)); }
                let accepted = self.signed(identity, Envelope {
                    kind: Kind::Accepted, challenge: fresh_challenge(),
                    signature: [0; 64], ..envelope.clone()
                })?;
                self.proposal = Some(envelope.clone());
                self.accepted = Some(accepted.clone());
                self.phase = Phase::Accepted;
                Ok(Some(accepted))
            }
            Kind::Accepted if self.leader() => {
                if self.accepted.as_ref().is_some_and(|original| original != envelope) {
                    return Err(rejected(ErrorCode::ReplayRejected));
                }
                if let Some(commit) = &self.commit { return Ok(Some(commit.clone())); }
                if self.phase != Phase::Proposed { return Err(rejected(ErrorCode::ReplayRejected)); }
                let commit = self.signed(identity, Envelope {
                    kind: Kind::Commit, signature: [0; 64], ..envelope.clone()
                })?;
                self.accepted = Some(envelope.clone());
                self.commit = Some(commit.clone());
                self.phase = Phase::Committing;
                Ok(Some(commit))
            }
            Kind::Commit if !self.leader() => {
                if self.accepted.as_ref().is_none_or(|accepted| accepted.challenge != envelope.challenge) {
                    return Err(rejected(ErrorCode::ReplayRejected));
                }
                if let Some(committed) = &self.committed { return Ok(Some(committed.clone())); }
                if self.phase != Phase::Accepted { return Err(rejected(ErrorCode::ReplayRejected)); }
                let committed = self.signed(identity, Envelope {
                    kind: Kind::Committed, signature: [0; 64], ..envelope.clone()
                })?;
                self.commit = Some(envelope.clone());
                self.committed = Some(committed.clone());
                self.record(envelope, now_ms);
                Ok(Some(committed))
            }
            Kind::Committed if self.leader() => {
                if self.commit.as_ref().is_none_or(|commit| commit.challenge != envelope.challenge)
                    || !matches!(self.phase, Phase::Committing | Phase::Committed)
                { return Err(rejected(ErrorCode::ReplayRejected)); }
                if self.committed.as_ref().is_some_and(|original| original != envelope) {
                    return Err(rejected(ErrorCode::ReplayRejected));
                }
                if self.receipt.is_none() { self.record(envelope, now_ms); }
                self.committed = Some(envelope.clone());
                Ok(None)
            }
            _ => Err(rejected(ErrorCode::ReplayRejected)),
        }
    }
    fn record(&mut self, envelope: &Envelope, now_ms: u64) {
        self.phase = Phase::Committed;
        self.receipt = Some(Committed {
            binding: envelope.binding.clone(), proposal: envelope.proposal,
            challenge: envelope.challenge, committed_at_unix_ms: now_ms,
            old_path_drain_until_unix_ms: now_ms.saturating_add(MAX_DRAIN_MS).min(self.authority_expiry_ms),
            authority_expires_at_unix_ms: self.authority_expiry_ms,
        });
    }
}

#[cfg(test)]
mod tests;
