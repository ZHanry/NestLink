use nestlink_identity::{digest, nodes::verify_lease};
use nestlink_protocol::{ContractError, ErrorCode, NodeChallenge, NodeLeaseClaims, NodeRole};
use nestlink_session::ClockSample;

pub struct NodeGate {
    deployment: String,
    node: String,
    runtime: String,
    key_digest: [u8; 32],
    trusted_issuer: [u8; 32],
    roles: Vec<NodeRole>,
    claims: Option<NodeLeaseClaims>,
    deadline: u64,
    last_clock: Option<ClockSample>,
    last_request: Option<u64>,
    stopped: bool,
}
impl NodeGate {
    pub fn new(
        deployment: String,
        node: String,
        runtime: String,
        public_key: [u8; 32],
        trusted_issuer: [u8; 32],
        roles: Vec<NodeRole>,
    ) -> Result<Self, ContractError> {
        if !nestlink_protocol::valid_id(&deployment)
            || !nestlink_protocol::valid_id(&node)
            || !nestlink_protocol::valid_id(&runtime)
            || !nestlink_protocol::nodes::valid_roles(
                &roles.iter().map(|r| *r as i32).collect::<Vec<_>>(),
            )
        {
            return Err(error(ErrorCode::InvalidMessage));
        }
        Ok(Self {
            deployment,
            node,
            runtime,
            key_digest: digest(&public_key),
            trusted_issuer,
            roles,
            claims: None,
            deadline: 0,
            last_clock: None,
            last_request: None,
            stopped: false,
        })
    }
    pub fn accept(
        &mut self,
        bytes: &[u8],
        expected_challenge: &NodeChallenge,
        request_started_ms: u64,
        now: ClockSample,
    ) -> Result<(), ContractError> {
        expected_challenge.validate()?;
        if self.claims.is_some() {
            self.check_live(now)?;
        }
        if self.stopped {
            return Err(error(ErrorCode::PolicyRevoked));
        }
        let c = verify_lease(bytes, &self.trusted_issuer)?;
        if c.deployment_id != self.deployment
            || c.node_id != self.node
            || c.runtime_id != self.runtime
            || c.node_key_sha256 != self.key_digest
            || c.request_id != expected_challenge.request_id
            || c.nonce != expected_challenge.nonce
            || c.security_epoch != expected_challenge.security_epoch
            || expected_challenge.deployment_id != self.deployment
            || expected_challenge.node_id != self.node
            || expected_challenge.node_key_sha256 != self.key_digest
            || c.roles
                .iter()
                .any(|r| !self.roles.iter().any(|allowed| *allowed as i32 == *r))
        {
            return Err(error(ErrorCode::IdentityMismatch));
        }
        if let Some(old) = &self.claims {
            if c.security_epoch != old.security_epoch
                || c.policy_revision != old.policy_revision
                || c.runtime_generation != old.runtime_generation
                || c.roles != old.roles
                || c.max_connections != old.max_connections
                || c.bytes_per_second != old.bytes_per_second
                || c.server_forwarding_allowed != old.server_forwarding_allowed
                || c.public_ingress_allowed != old.public_ingress_allowed
            {
                self.stop();
                return Err(error(ErrorCode::PolicyRevoked));
            }
            if c.lease_sequence <= old.lease_sequence {
                return Err(error(ErrorCode::ReplayRejected));
            }
        }
        if request_started_ms > now.monotonic_ms
            || self.last_request.is_some_and(|v| request_started_ms <= v)
        {
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "node request monotonic clock is stale or invalid",
            ));
        }
        if c.issued_at_unix_ms > now.unix_ms {
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "node lease issuance is ahead of the local wall clock",
            ));
        }
        if expected_challenge.expires_at_unix_ms <= now.unix_ms {
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "node challenge expired before lease acceptance",
            ));
        }
        let remaining = c
            .expires_at_unix_ms
            .checked_sub(now.unix_ms)
            .filter(|n| *n > 0)
            .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
        let lifetime = c.expires_at_unix_ms - c.issued_at_unix_ms;
        // Response latency has already elapsed in the signed remaining time.
        // Bound its receipt-relative deadline by the original request lifetime.
        let signed_deadline = now
            .monotonic_ms
            .checked_add(remaining)
            .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
        let request_deadline = request_started_ms
            .checked_add(lifetime)
            .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
        let deadline = Some(signed_deadline.min(request_deadline))
            .filter(|n| *n > now.monotonic_ms)
            .ok_or_else(|| error(ErrorCode::LeaseExpired))?;
        self.claims = Some(c);
        self.deadline = deadline;
        self.last_clock = Some(now);
        self.last_request = Some(request_started_ms);
        Ok(())
    }
    pub fn check_live(&mut self, now: ClockSample) -> Result<(), ContractError> {
        if self.stopped {
            return Err(error(ErrorCode::PolicyRevoked));
        }
        if self.claims.is_none() {
            return Err(error(ErrorCode::AuthRequired));
        }
        if let Some(previous) = self.last_clock {
            let reason = if now.monotonic_ms < previous.monotonic_ms {
                Some("node monotonic clock rolled back")
            } else if now.unix_ms < previous.unix_ms {
                Some("node wall clock rolled back")
            } else if now.unix_ms.saturating_sub(previous.unix_ms)
                > now
                    .monotonic_ms
                    .saturating_sub(previous.monotonic_ms)
                    .saturating_add(1000)
            {
                Some("node wall and monotonic clocks diverged")
            } else {
                None
            };
            if let Some(reason) = reason {
                self.stop();
                return Err(ContractError::new(ErrorCode::LeaseExpired, reason));
            }
        }
        if now.monotonic_ms >= self.deadline
            || self.claims.as_ref().is_some_and(|claims| now.unix_ms >= claims.expires_at_unix_ms)
        {
            self.stop();
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "node local lease deadline expired",
            ));
        }
        self.last_clock = Some(now);
        Ok(())
    }
    /// Data services must also verify the separate resource/session permit.
    pub fn authorize_forwarding(
        &mut self,
        role: NodeRole,
        public_ingress: bool,
        now: ClockSample,
    ) -> Result<&NodeLeaseClaims, ContractError> {
        self.check_live(now)?;
        let c = self
            .claims
            .as_ref()
            .ok_or_else(|| error(ErrorCode::AuthRequired))?;
        if !c.roles.contains(&(role as i32))
            || !c.server_forwarding_allowed
            || (public_ingress && (role != NodeRole::NodeEdge || !c.public_ingress_allowed))
        {
            return Err(error(ErrorCode::PermissionRequired));
        }
        Ok(c)
    }
    pub fn stop(&mut self) {
        self.stopped = true;
        self.claims = None;
        self.deadline = 0;
    }
    pub(crate) fn deadline(&self) -> u64 {
        self.deadline
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline
    }
    pub(crate) fn trusted_policy_issuer(&self) -> [u8; 32] {
        self.trusted_issuer
    }
    pub fn current(&mut self, now: ClockSample) -> Result<&NodeLeaseClaims, ContractError> {
        self.check_live(now)?;
        self.claims
            .as_ref()
            .ok_or_else(|| error(ErrorCode::AuthRequired))
    }
}
fn error(code: ErrorCode) -> ContractError {
    ContractError::new(code, "node authorization rejected or stopped")
}
