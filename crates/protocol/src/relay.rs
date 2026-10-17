//! Bounds for concrete native relay allocation leases.
use crate::{
    ContractError, ErrorCode, NODE_LEASE_MS, RelayAllocationClaims, RelayTransport, SCHEMA_VERSION,
    valid_id,
};
impl RelayAllocationClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.allocation_id,
                &self.session_id,
                &self.node_id,
                &self.runtime_id,
                &self.controller_device_id,
                &self.host_device_id,
                &self.controller_account_id,
                &self.host_account_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.connection_generation,
                self.policy_revision,
                self.quota_revision,
                self.grant_sequence,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || [
                &self.node_key_sha256,
                &self.controller_key_sha256,
                &self.host_key_sha256,
                &self.session_binding_sha256,
            ]
            .iter()
            .any(|s| s.len() != 32)
            || self.controller_device_id == self.host_device_id
            || self.node_endpoint_revision > i64::MAX as u64
            || self.controller_key_sha256 == self.host_key_sha256
            || self.transports.is_empty()
            || self.transports.len() > 2
            || self.transports.iter().enumerate().any(|(i, t)| {
                !matches!(
                    RelayTransport::try_from(*t),
                    Ok(RelayTransport::QuicDatagram | RelayTransport::WssStream)
                ) || self.transports[..i].contains(t)
            })
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > NODE_LEASE_MS)
            || !(1..=1073741824).contains(&self.bytes_per_second)
            || !(1..=1099511627776).contains(&self.bytes_per_allocation)
        {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid relay allocation claims",
            ));
        }
        Ok(())
    }
}
