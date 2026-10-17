//! Authorization lifecycle with terminal revocation and bounded leases.
use nestlink_identity::{VerifiedPermit, digest, verify_endpoint_proof};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    ContractError, EndpointProofClaims, ErrorCode, Path, Permission, SCHEMA_VERSION,
};
use rand_core::{OsRng, RngCore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    pub deployment_id: String,
    pub security_epoch: u64,
    pub session_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub controller_key_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub resource_id: String,
    pub policy_revision: u64,
    pub connection_generation: u64,
    pub capability_sha256: [u8; 32],
    pub granted_permissions: Vec<Permission>,
    pub supported_capabilities: Vec<String>,
    pub local_paths: PathSet,
}

#[derive(Debug, Clone, Copy)]
pub struct ClockSample {
    pub monotonic_ms: u64,
    pub unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Revoked,
    Expired,
    TransportLost,
    ProtocolViolation,
    NetworkChanged,
    PlatformChanged,
    Suspended,
    ClockInvalid,
    ExplicitExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Controller,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    AwaitingProof,
    Active,
    Stopped(StopReason),
}

// The platform must perform all these effects before reporting the stop complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopEffects {
    pub cancel_channels: bool,
    pub release_inputs: bool,
    pub discard_queues: bool,
    pub close_allocations: bool,
}

pub struct Session {
    binding: SessionBinding,
    permit: VerifiedPermit,
    path: Path,
    state: SessionState,
    deadline_ms: u64,
    last_monotonic_ms: u64,
    last_unix_ms: u64,
    last_request_ms: u64,
    proved: u8,
    challenge: [u8; 32],
}

impl Session {
    pub fn activate(
        permit: VerifiedPermit,
        binding: SessionBinding,
        path: Path,
        request_started_ms: u64,
        now: ClockSample,
    ) -> Result<Self, ContractError> {
        validate_binding(&permit, &binding, path)?;
        let deadline_ms = lease_deadline(&permit, request_started_ms, now)?;
        let mut challenge = [0; 32];
        OsRng.fill_bytes(&mut challenge);
        Ok(Self {
            binding,
            permit,
            path,
            state: SessionState::AwaitingProof,
            deadline_ms,
            last_monotonic_ms: now.monotonic_ms,
            last_unix_ms: now.unix_ms,
            last_request_ms: request_started_ms,
            proved: 0,
            challenge,
        })
    }

    /// Start endpoint proof after transport setup using an already retained
    /// authorization deadline. The elapsed setup time must not be charged again
    /// as though this were a delayed network response. No unbounded session is
    /// returned: the original local cap and current clock are checked first.
    pub fn activate_with_retained_deadline(
        permit: VerifiedPermit,
        binding: SessionBinding,
        path: Path,
        now: ClockSample,
        retained_deadline_ms: u64,
    ) -> Result<Self, ContractError> {
        let mut session = Self::activate(permit, binding, path, now.monotonic_ms, now)?;
        session.cap_deadline_ms(retained_deadline_ms)?;
        session.check_clock(now)?;
        Ok(session)
    }

    pub fn state(&self) -> SessionState {
        self.state
    }
    /// ICE may select a path after gathering. Selection can change only before
    /// either endpoint proof is consumed, within the original permit deadline.
    pub fn select_path_before_proof(
        &mut self,
        path: Path,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        self.check_clock(now)?;
        if self.state != SessionState::AwaitingProof || self.proved != 0 {
            return Err(error(
                ErrorCode::ReplayRejected,
                "path selection follows endpoint proof",
            ));
        }
        validate_binding(&self.permit, &self.binding, path)?;
        if self.path != path {
            self.path = path;
            OsRng.fill_bytes(&mut self.challenge);
        }
        Ok(())
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    /// Narrow an existing lease to an earlier locally retained deadline.
    pub fn cap_deadline_ms(&mut self, deadline_ms: u64) -> Result<(), ContractError> {
        self.check_live(self.last_monotonic_ms)?;
        self.deadline_ms = self.deadline_ms.min(deadline_ms);
        self.check_live(self.last_monotonic_ms)
    }
    /// A stopped connection can replace its transport only within its original
    /// local lease and with fresh control-plane consent from both endpoints.
    pub fn reconnection_permit(&self, now: ClockSample) -> Result<VerifiedPermit, ContractError> {
        if !matches!(
            self.state,
            SessionState::Stopped(StopReason::TransportLost | StopReason::NetworkChanged)
        ) || now.monotonic_ms < self.last_monotonic_ms
            || now.monotonic_ms >= self.deadline_ms
            || now.unix_ms < self.last_unix_ms
            || now.unix_ms >= self.permit.claims().expires_at_unix_ms
        {
            return Err(error(
                ErrorCode::LeaseExpired,
                "stopped session cannot reconnect",
            ));
        }
        Ok(self.permit.clone())
    }
    pub fn proof_transcript(&self) -> EndpointProofClaims {
        EndpointProofClaims {
            schema_version: SCHEMA_VERSION,
            permit_sha256: self.permit.digest().to_vec(),
            challenge: self.challenge.to_vec(),
            controller_key_sha256: self.binding.controller_key_sha256.to_vec(),
            host_key_sha256: self.binding.host_key_sha256.to_vec(),
            path: self.path as i32,
            connection_generation: self.binding.connection_generation,
        }
    }

    /// Identity and policy facts from the verified activation, without granting
    /// permission or reviving a stopped session.
    pub fn binding(&self) -> &SessionBinding {
        &self.binding
    }

    pub fn confirm_endpoint(
        &mut self,
        role: EndpointRole,
        public_key: &[u8; 32],
        signature: &[u8],
        monotonic_ms: u64,
    ) -> Result<(), ContractError> {
        self.check_live(monotonic_ms)?;
        let (bit, expected_key) = match role {
            EndpointRole::Controller => (1, self.binding.controller_key_sha256),
            EndpointRole::Host => (2, self.binding.host_key_sha256),
        };
        if self.proved & bit != 0 {
            return Err(error(
                ErrorCode::ReplayRejected,
                "endpoint proof already consumed",
            ));
        }
        if digest(public_key) != expected_key {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "wrong endpoint role key",
            ));
        }
        verify_endpoint_proof(&self.proof_transcript(), public_key, signature)?;
        self.proved |= bit;
        if self.proved == 3 {
            self.state = SessionState::Active;
        }
        Ok(())
    }

    pub fn authorize(
        &mut self,
        permission: Permission,
        path: Path,
        monotonic_ms: u64,
    ) -> Result<(), ContractError> {
        self.check_live(monotonic_ms)?;
        if self.state != SessionState::Active {
            return Err(error(
                ErrorCode::AuthRequired,
                "both endpoint key proofs required",
            ));
        }
        if path != self.path
            || !self
                .permit
                .claims()
                .permissions
                .contains(&(permission as i32))
        {
            return Err(error(
                ErrorCode::PermissionRequired,
                "channel permission or path denied",
            ));
        }
        Ok(())
    }

    /// Clone the actual verified envelope only while Input is authorized on
    /// this proved live session. This never renews or extends its deadline.
    pub fn current_input_permit(
        &mut self,
        path: Path,
        monotonic_ms: u64,
    ) -> Result<VerifiedPermit, ContractError> {
        self.authorize(Permission::Input, path, monotonic_ms)?;
        Ok(self.permit.clone())
    }

    // Caller correlates this response to the current authenticated renewal request.
    pub fn renew(
        &mut self,
        permit: VerifiedPermit,
        request_started_ms: u64,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        self.check_live(now.monotonic_ms)?;
        if now.unix_ms < self.last_unix_ms {
            self.stop(StopReason::ClockInvalid);
            return Err(error(
                ErrorCode::LeaseExpired,
                "wall clock moved backwards; reauthorization required",
            ));
        }
        validate_binding(&permit, &self.binding, self.path)?;
        if request_started_ms <= self.last_request_ms
            || permit.claims().lease_sequence <= self.permit.claims().lease_sequence
            || permit.claims().issued_at_unix_ms < self.permit.claims().issued_at_unix_ms
        {
            return Err(error(ErrorCode::ReplayRejected, "stale renewal response"));
        }
        // Renewal cannot silently add channels or alter path/capability authorization.
        if permit.claims().permissions != self.permit.claims().permissions
            || permit.claims().paths != self.permit.claims().paths
            || permit.claims().required_capabilities != self.permit.claims().required_capabilities
        {
            return Err(error(
                ErrorCode::PermissionRequired,
                "authorization changes require a new connection",
            ));
        }
        let deadline = lease_deadline(&permit, request_started_ms, now)?;
        self.permit = permit;
        self.deadline_ms = deadline;
        self.last_monotonic_ms = now.monotonic_ms;
        self.last_unix_ms = now.unix_ms;
        self.last_request_ms = request_started_ms;
        Ok(())
    }

    pub fn stop(&mut self, reason: StopReason) -> StopEffects {
        if !matches!(self.state, SessionState::Stopped(_)) {
            self.state = SessionState::Stopped(reason);
        }
        self.proved = 0;
        self.challenge.fill(0);
        StopEffects {
            cancel_channels: true,
            release_inputs: true,
            discard_queues: true,
            close_allocations: true,
        }
    }

    pub fn check_live(&mut self, monotonic_ms: u64) -> Result<(), ContractError> {
        if let SessionState::Stopped(reason) = self.state {
            return Err(error(
                if reason == StopReason::Revoked {
                    ErrorCode::PolicyRevoked
                } else {
                    ErrorCode::LeaseExpired
                },
                "session is terminal",
            ));
        }
        if monotonic_ms < self.last_monotonic_ms {
            self.stop(StopReason::ClockInvalid);
            return Err(error(
                ErrorCode::LeaseExpired,
                "monotonic clock moved backwards",
            ));
        }
        if monotonic_ms >= self.deadline_ms {
            self.stop(StopReason::Expired);
            return Err(error(ErrorCode::LeaseExpired, "session lease expired"));
        }
        self.last_monotonic_ms = monotonic_ms;
        Ok(())
    }

    /// Observe wall time even when no renewal or business frame is in progress.
    pub fn check_clock(&mut self, now: ClockSample) -> Result<(), ContractError> {
        self.check_live(now.monotonic_ms)?;
        if now.unix_ms < self.last_unix_ms {
            self.stop(StopReason::ClockInvalid);
            return Err(error(ErrorCode::LeaseExpired, "wall clock moved backwards"));
        }
        self.last_unix_ms = now.unix_ms;
        Ok(())
    }
}

fn validate_binding(
    permit: &VerifiedPermit,
    b: &SessionBinding,
    path: Path,
) -> Result<(), ContractError> {
    let c = permit.claims();
    if c.deployment_id != b.deployment_id
        || c.security_epoch != b.security_epoch
        || c.session_id != b.session_id
        || c.account_id != b.account_id
        || c.controller_device_id != b.controller_device_id
        || c.host_device_id != b.host_device_id
        || c.controller_key_sha256 != b.controller_key_sha256
        || c.host_key_sha256 != b.host_key_sha256
        || c.resource_id != b.resource_id
        || c.policy_revision != b.policy_revision
        || c.connection_generation != b.connection_generation
        || c.capability_sha256 != b.capability_sha256
    {
        return Err(error(
            ErrorCode::IdentityMismatch,
            "permit does not match the current request binding",
        ));
    }
    if c.required_capabilities
        .iter()
        .any(|v| !b.supported_capabilities.contains(v))
    {
        return Err(error(
            ErrorCode::ProtocolMismatch,
            "unknown required capability",
        ));
    }
    if c.permissions
        .iter()
        .any(|v| !b.granted_permissions.iter().any(|p| *p as i32 == *v))
    {
        return Err(error(
            ErrorCode::PermissionRequired,
            "permit exceeds locally approved permissions",
        ));
    }
    let paths = PathSet::from_wire(&c.paths)?.intersection(b.local_paths);
    if !paths.contains(path) {
        return Err(error(
            ErrorCode::PermissionRequired,
            "selected path is not permitted",
        ));
    }
    Ok(())
}

fn lease_deadline(
    permit: &VerifiedPermit,
    request_started_ms: u64,
    now: ClockSample,
) -> Result<u64, ContractError> {
    let c = permit.claims();
    if c.issued_at_unix_ms > now.unix_ms || request_started_ms > now.monotonic_ms {
        return Err(error(
            ErrorCode::LeaseExpired,
            "future lease or request clock",
        ));
    }
    let remaining = c
        .expires_at_unix_ms
        .checked_sub(now.unix_ms)
        .filter(|v| *v > 0)
        .ok_or_else(|| error(ErrorCode::LeaseExpired, "permit expired"))?;
    let lifetime = c.expires_at_unix_ms - c.issued_at_unix_ms;
    let deadline = request_started_ms
        .checked_add(remaining.min(lifetime))
        .filter(|v| *v > now.monotonic_ms)
        .ok_or_else(|| error(ErrorCode::LeaseExpired, "lease response arrived too late"))?;
    Ok(deadline)
}

fn error(code: ErrorCode, reason: &'static str) -> ContractError {
    ContractError::new(code, reason)
}
