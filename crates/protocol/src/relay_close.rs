//! Cleanup receipts are terminal facts, never new forwarding authority.
use crate::{
    ContractError, ErrorCode, RelayCloseAckClaims, RelayCloseClaims, SCHEMA_VERSION, valid_id,
};
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid relay close metadata")
}
impl RelayCloseClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.runtime_id,
                &self.allocation_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.observed_grant_sequence,
                self.closed_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.allocation_binding_sha256.len() != 32
            || !(1..=2).contains(&self.opened_connections)
            || self.closed_connections != self.opened_connections
            || self.admitted_bytes > i64::MAX as u64
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl RelayCloseAckClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.runtime_id,
                &self.allocation_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.accepted_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.close_sha256.len() != 32
            || ![0, 2].contains(&self.released_endpoint_slots)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
