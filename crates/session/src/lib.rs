//! Authorization lifecycle with terminal revocation and bounded leases.
use nestlink_identity::{VerifiedPermit, digest, verify_endpoint_proof};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    ContractError, EndpointProofClaims, ErrorCode, Path, Permission, SCHEMA_VERSION,
};
use rand_core::{OsRng, RngCore};
#[cfg(all(feature = "media-runtime-test-support", not(debug_assertions)))]
compile_error!("media-runtime-test-support is restricted to debug regression builds");
#[cfg(feature = "media-runtime-test-support")]
pub const MEDIA_REGRESSION_REQUEST_ID: &str = "b4cc8c40-2812-4fb0-bd74-989c6b385401";
#[cfg(feature = "media-runtime-test-support")]
pub const MEDIA_REGRESSION_SESSION_ID: &str = "b4cc8c40-2812-4fb0-bd74-989c6b385402";

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
    pub media: Option<MediaSessionBinding>,
}

/// Validated signed-scope/local-announcement data. The provider must separately
/// retain and continuously check the actual probe owner and generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSessionBinding {
    internal_candidate: Option<
        nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate,
    >,
    direction: nestlink_protocol::media_authority::MediaDirection,
    probe: nestlink_protocol::media_authority::ProbeIdentity,
    expires_at_unix_ms: u64,
    formats: Vec<Vec<u8>>,
    sha256: Vec<u8>,
    device_id: String,
    revision: u64,
}
impl MediaSessionBinding {
    /// Local opt-in only. Existing signed scope and local evidence stay authoritative.
    pub fn with_internal_software_candidate(
        mut self,
        policy: nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate,
        permit: &VerifiedPermit,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        now_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        policy.authorize_permit(permit.claims())?;
        policy.authorize_announcement(local, now_unix_ms)?;
        if self.probe != local.probe
            || self.device_id != local.device_id
            || self.direction != local.direction
            || self.revision != local.revision
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "candidate local evidence changed",
            ));
        }
        self.internal_candidate = Some(policy);
        Ok(self)
    }
    pub fn from_local_announcement(
        permit: &VerifiedPermit,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: EndpointRole,
        now_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        use nestlink_protocol::media_authority::{MediaDirection, permit_formats};
        let claims = permit.claims();
        let signed = permit_formats(claims)?.ok_or_else(|| {
            error(
                ErrorCode::InvalidMessage,
                "media binding requires signed scope",
            )
        })?;
        let scope = frozen.validate()?;
        let available = local.validate(now_unix_ms)?;
        let (direction, device, revision) = match role {
            EndpointRole::Controller => (
                MediaDirection::Decode,
                &claims.controller_device_id,
                frozen.controller_revision,
            ),
            EndpointRole::Host => (
                MediaDirection::Encode,
                &claims.host_device_id,
                frozen.host_revision,
            ),
        };
        if frozen.version != claims.media_format_version
            || frozen.formats != claims.media_formats
            || frozen.sha256 != claims.media_format_sha256
            || scope != signed
            || local.direction != direction
            || &local.device_id != device
            || local.revision < revision
            || signed
                .formats()
                .iter()
                .any(|format| !available.formats().contains(format))
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "local media evidence does not cover frozen signed scope",
            ));
        }
        Ok(Self {
            internal_candidate: None,
            direction,
            probe: local.probe.clone(),
            expires_at_unix_ms: local.expires_at_unix_ms,
            formats: claims.media_formats.clone(),
            sha256: claims.media_format_sha256.clone(),
            device_id: device.clone(),
            revision: local.revision,
        })
    }
    /// Data validation only. A changed probe requires a new actual observation,
    /// a higher revision/generation, and provider-controlled stop/join of the old
    /// execution owner before replacement. Historical probe and live execution
    /// identities are distinct; this method establishes neither currentness.
    pub fn refresh_from_local_announcement(
        &self,
        permit: &VerifiedPermit,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: EndpointRole,
        now_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let mut next = Self::from_local_announcement(permit, frozen, local, role, now_unix_ms)?;
        if let Some(policy) = &self.internal_candidate {
            policy.authorize_permit(permit.claims())?;
            policy.authorize_announcement(local, now_unix_ms)?;
            next.internal_candidate = Some(policy.clone());
        }
        let replaced = next.probe != self.probe;
        if (replaced
            && (next.probe.generation <= self.probe.generation || next.revision <= self.revision))
            || next.direction != self.direction
            || next.device_id != self.device_id
            || next.formats != self.formats
            || next.sha256 != self.sha256
            || next.revision < self.revision
            || next.expires_at_unix_ms < self.expires_at_unix_ms
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "media refresh changed scope or did not advance probe evidence",
            ));
        }
        Ok(next)
    }
    pub fn local_direction(&self) -> nestlink_protocol::media_authority::MediaDirection {
        self.direction
    }
    pub fn backend(&self) -> &str {
        &self.probe.backend
    }
    pub fn probe_generation(&self) -> u64 {
        self.probe.generation
    }
    pub fn resource_id(&self) -> &str {
        &self.probe.resource_id
    }
    pub fn adapter_luid(&self) -> Option<u64> {
        self.probe.adapter_luid
    }
    pub fn driver_version(&self) -> Option<u64> {
        self.probe.driver_version
    }
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
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
    #[cfg(feature = "media-runtime-test-support")]
    media_regression: bool,
    binding: SessionBinding,
    permit: VerifiedPermit,
    path: Path,
    state: SessionState,
    deadline_ms: u64,
    lifetime_deadline_ms: Option<u64>,
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
        Self::activate_with_rollout(permit, binding, path, request_started_ms, now, false)
    }
    fn activate_with_rollout(
        permit: VerifiedPermit,
        binding: SessionBinding,
        path: Path,
        request_started_ms: u64,
        now: ClockSample,
        allow_regression: bool,
    ) -> Result<Self, ContractError> {
        validate_binding_with_rollout(&permit, &binding, path, allow_regression)?;
        if binding
            .media
            .as_ref()
            .is_some_and(|local| now.unix_ms >= local.expires_at_unix_ms)
        {
            return Err(error(
                ErrorCode::LeaseExpired,
                "local media evidence expired before activation",
            ));
        }
        let deadline_ms = lease_deadline(&permit, request_started_ms, now)?;
        let mut challenge = [0; 32];
        OsRng.fill_bytes(&mut challenge);
        Ok(Self {
            #[cfg(feature = "media-runtime-test-support")]
            media_regression: allow_regression,
            binding,
            permit,
            path,
            state: SessionState::AwaitingProof,
            deadline_ms,
            lifetime_deadline_ms: None,
            last_monotonic_ms: now.monotonic_ms,
            last_unix_ms: now.unix_ms,
            last_request_ms: request_started_ms,
            proved: 0,
            challenge,
        })
    }

    /// Explicit debug-only fixture entry. Normal activation always keeps rollout closed.
    #[cfg(feature = "media-runtime-test-support")]
    pub fn activate_media_runtime_regression(
        permit: VerifiedPermit,
        binding: SessionBinding,
        path: Path,
        request_started_ms: u64,
        now: ClockSample,
        request_id: &str,
    ) -> Result<Self, ContractError> {
        if request_id != MEDIA_REGRESSION_REQUEST_ID
            || binding.session_id != MEDIA_REGRESSION_SESSION_ID
            || permit.claims().session_id != MEDIA_REGRESSION_SESSION_ID
            || binding.media.is_none()
            || nestlink_protocol::media_authority::permit_formats(permit.claims())?.is_none()
        {
            return Err(error(
                ErrorCode::PlatformUnsupported,
                "unscoped media regression activation",
            ));
        }
        Self::activate_with_rollout(permit, binding, path, request_started_ms, now, true)
    }
    fn validate_current_binding(
        &self,
        permit: &VerifiedPermit,
        path: Path,
    ) -> Result<(), ContractError> {
        #[cfg(feature = "media-runtime-test-support")]
        let allow = self.media_regression;
        #[cfg(not(feature = "media-runtime-test-support"))]
        let allow = false;
        validate_binding_with_rollout(permit, &self.binding, path, allow)
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
    /// Scope from the already verified signature, never the latest device catalog.
    pub fn local_media_binding(&self) -> Option<&MediaSessionBinding> {
        self.binding.media.as_ref()
    }
    /// Caller must validate the actual retained owner immediately before this
    /// data update; any failed refresh terminates the existing session.
    pub fn refresh_local_media_binding(
        &mut self,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: EndpointRole,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        self.check_clock(now)?;
        let refreshed = self
            .binding
            .media
            .as_ref()
            .ok_or_else(|| {
                error(
                    ErrorCode::IdentityMismatch,
                    "session has no local media binding",
                )
            })?
            .refresh_from_local_announcement(&self.permit, frozen, local, role, now.unix_ms);
        match refreshed {
            Ok(binding) => {
                self.binding.media = Some(binding);
                Ok(())
            }
            Err(failure) => {
                self.stop(StopReason::PlatformChanged);
                Err(failure)
            }
        }
    }
    /// Prepare a complete successor on a private copy; publish binding and lease
    /// together only after every check passes. Failed preparation is terminal.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_with_local_media(
        &mut self,
        permit: VerifiedPermit,
        request_started_ms: u64,
        expected_sequence: u64,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: EndpointRole,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        self.check_clock(now)?;
        if self.permit.claims().lease_sequence != expected_sequence
            || expected_sequence.checked_add(1) != Some(permit.claims().lease_sequence)
        {
            return Err(error(ErrorCode::ReplayRejected, "renewal sequence changed"));
        }
        let mut candidate = Self {
            #[cfg(feature = "media-runtime-test-support")]
            media_regression: self.media_regression,
            binding: self.binding.clone(),
            permit: self.permit.clone(),
            path: self.path,
            state: self.state,
            deadline_ms: self.deadline_ms,
            lifetime_deadline_ms: self.lifetime_deadline_ms,
            last_monotonic_ms: self.last_monotonic_ms,
            last_unix_ms: self.last_unix_ms,
            last_request_ms: self.last_request_ms,
            proved: self.proved,
            challenge: self.challenge,
        };
        let prepared = candidate
            .refresh_local_media_binding(frozen, local, role, now)
            .and_then(|()| candidate.renew(permit, request_started_ms, now));
        match prepared {
            Ok(()) => {
                *self = candidate;
                Ok(())
            }
            Err(failure) => {
                self.stop(StopReason::PlatformChanged);
                Err(failure)
            }
        }
    }
    pub fn media_formats(
        &self,
    ) -> Result<Option<nestlink_protocol::media_format::FormatSet>, ContractError> {
        nestlink_protocol::media_authority::permit_formats(self.permit.claims())
    }
    pub fn negotiated_capability(&self, capability: &str) -> bool {
        self.permit
            .claims()
            .required_capabilities
            .iter()
            .any(|value| value == capability)
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
        self.validate_current_binding(&self.permit, path)?;
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
    /// Retain a non-renewable transport authority ceiling. A business permit
    /// renewal cannot extend the separate route permission that carries it.
    pub fn cap_lifetime_deadline_ms(&mut self, deadline_ms: u64) -> Result<(), ContractError> {
        self.lifetime_deadline_ms = Some(
            self.lifetime_deadline_ms.map_or(deadline_ms, |old| old.min(deadline_ms)),
        );
        self.cap_deadline_ms(deadline_ms)
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
    pub fn current_verified_permit(&self) -> &VerifiedPermit {
        &self.permit
    }
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

    pub fn is_setup_authorization(&self) -> bool {
        self.permit.claims().is_setup()
    }

    /// Establish lifecycle supervision for the proved setup control channel.
    /// This grants no media/input/business permission; those still use authorize.
    pub fn check_proved_setup(
        &mut self,
        path: Path,
        monotonic_ms: u64,
    ) -> Result<(), ContractError> {
        self.check_live(monotonic_ms)?;
        if !self.is_setup_authorization()
            || self.state != SessionState::Active
            || path != self.path
            || !self
                .permit
                .claims()
                .permissions
                .contains(&(Permission::View as i32))
        {
            return Err(error(
                ErrorCode::AuthRequired,
                "proved setup control channel required",
            ));
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
        if self.permit.claims().is_setup() {
            return Err(error(
                ErrorCode::AuthRequired,
                "setup authorization cannot start media, input or business channels",
            ));
        }
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
        self.validate_current_binding(&permit, self.path)?;
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
            || permit.claims().media_format_version != self.permit.claims().media_format_version
            || permit.claims().media_formats != self.permit.claims().media_formats
            || permit.claims().media_format_sha256 != self.permit.claims().media_format_sha256
        {
            return Err(error(
                ErrorCode::PermissionRequired,
                "authorization changes require a new connection",
            ));
        }
        let deadline = lease_deadline(&permit, request_started_ms, now)?;
        self.permit = permit;
        self.deadline_ms = self.lifetime_deadline_ms.map_or(deadline, |cap| deadline.min(cap));
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
        if self
            .binding
            .media
            .as_ref()
            .is_some_and(|local| now.unix_ms >= local.expires_at_unix_ms)
        {
            self.stop(StopReason::PlatformChanged);
            return Err(error(
                ErrorCode::LeaseExpired,
                "local media evidence expired",
            ));
        }
        self.last_unix_ms = now.unix_ms;
        Ok(())
    }
}

fn validate_binding_with_rollout(
    permit: &VerifiedPermit,
    b: &SessionBinding,
    path: Path,
    allow_regression: bool,
) -> Result<(), ContractError> {
    let c = permit.claims();
    if let Some(local) = &b.media {
        use nestlink_protocol::media_authority::MediaDirection;
        let device = match local.direction {
            MediaDirection::Encode => &c.host_device_id,
            MediaDirection::Decode => &c.controller_device_id,
        };
        if local.formats != c.media_formats
            || local.sha256 != c.media_format_sha256
            || &local.device_id != device
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "local media binding changed signed scope",
            ));
        }
    }
    let scoped_regression = {
        #[cfg(feature = "media-runtime-test-support")]
        {
            allow_regression
                && b.session_id == MEDIA_REGRESSION_SESSION_ID
                && c.session_id == MEDIA_REGRESSION_SESSION_ID
                && b.media.is_some()
        }
        #[cfg(not(feature = "media-runtime-test-support"))]
        {
            let _ = allow_regression;
            false
        }
    };
    let scoped_candidate = if let Some(local) = &b.media
        && let Some(policy) = &local.internal_candidate
    {
        policy.authorize_permit(c)?;
        if local.probe.backend != "cpu-software"
            || local.probe.adapter_luid.is_some()
            || local.probe.driver_version.is_some()
        {
            return Err(error(
                ErrorCode::PlatformUnsupported,
                "candidate requires actual local software evidence",
            ));
        }
        true
    } else {
        false
    };
    if nestlink_protocol::media_authority::permit_formats(c)?.is_some()
        && !scoped_regression
        && !scoped_candidate
    {
        return Err(error(
            ErrorCode::PlatformUnsupported,
            "signed media requires local direction evidence and selection runtime",
        ));
    }
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

#[cfg(all(test, feature = "media-runtime-test-support"))]
mod native_renewal_tests;

#[cfg(test)]
mod internal_software_candidate_tests;
