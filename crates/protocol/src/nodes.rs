//! Contract checks for independent data-node control.
use crate::{
    ContractError, ErrorCode, NODE_LEASE_MS, NodeChallenge, NodeLeaseClaims, NodeRole,
    NodeUsageAckClaims, NodeUsageClaims, SCHEMA_VERSION, valid_id,
};
pub use crate::{NODE_CHALLENGE_MS, NODE_MESSAGE_BYTES};

pub fn valid_roles(roles: &[i32]) -> bool {
    !roles.is_empty()
        && roles.len() <= 2
        && roles.iter().all(|r| {
            matches!(
                NodeRole::try_from(*r),
                Ok(NodeRole::NodeRelay | NodeRole::NodeEdge)
            )
        })
        && (roles.len() != 2 || roles[0] < roles[1])
}
impl NodeChallenge {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || self.security_epoch == 0
            || [&self.deployment_id, &self.node_id, &self.request_id]
                .iter()
                .any(|s| !valid_id(s))
            || self.node_key_sha256.len() != 32
            || self.nonce.len() != 32
            || self.expires_at_unix_ms == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl NodeLeaseClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        let lifetime = self.expires_at_unix_ms.checked_sub(self.issued_at_unix_ms);
        if self.schema_version != SCHEMA_VERSION
            || self.security_epoch == 0
            || self.policy_revision == 0
            || self.lease_sequence == 0
            || self.runtime_generation == 0
            || [
                &self.deployment_id,
                &self.node_id,
                &self.request_id,
                &self.runtime_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || self.node_key_sha256.len() != 32
            || self.nonce.len() != 32
            || !valid_roles(&self.roles)
            || self.max_connections == 0
            || self.max_connections > 100_000
            || self.bytes_per_second == 0
            || self.bytes_per_second > 1024 * 1024 * 1024
            || lifetime.is_none_or(|n| n == 0 || n > NODE_LEASE_MS)
            || (self.public_ingress_allowed && !self.server_forwarding_allowed)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl NodeUsageClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [&self.deployment_id, &self.node_id, &self.runtime_id]
                .iter()
                .any(|s| !valid_id(s))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.policy_revision,
                self.lease_sequence,
                self.report_sequence,
                self.sampled_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || [
                self.opened_connections,
                self.closed_connections,
                self.admitted_bytes,
            ]
            .iter()
            .any(|n| *n > i64::MAX as u64)
            || self.closed_connections > self.opened_connections
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl NodeUsageAckClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [&self.deployment_id, &self.node_id, &self.runtime_id]
                .iter()
                .any(|s| !valid_id(s))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.report_sequence,
                self.accepted_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.report_sha256.len() != 32
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid node control claims")
}
