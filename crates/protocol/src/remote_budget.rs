//! Cumulative remote business promises, independently signed and bound to the
//! original online permit. A budget grants no channel, path or lease lifetime.
use crate::{ContractError, ErrorCode, PermitClaims, Permission, valid_id};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "remote-cumulative-budget-v1";
pub const MAX_BYTES: usize = 8192;
pub const ONLINE_PROMISE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteUsageBudgetClaims {
    pub version: u16,
    pub reservation_id: String,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub session_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub controller_key_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub resource_id: String,
    pub connection_generation: u64,
    pub policy_revision: u64,
    pub capability_sha256: [u8; 32],
    pub permissions: Vec<i32>,
    pub paths: Vec<i32>,
    pub maximum_bytes: u64,
    pub maximum_file_write_bytes: u64,
    pub maximum_connection_attempts: u32,
}
impl RemoteUsageBudgetClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != 1
            || [
                &self.reservation_id, &self.deployment_id, &self.session_id,
                &self.account_id, &self.controller_device_id, &self.host_device_id,
                &self.resource_id,
            ].iter().any(|id| !valid_id(id))
            || self.maximum_bytes == 0 || self.maximum_bytes > i64::MAX as u64
            || self.maximum_file_write_bytes > self.maximum_bytes
            || self.maximum_connection_attempts == 0 || self.maximum_connection_attempts > 1024
            || self.security_epoch == 0 || self.policy_revision == 0 || self.connection_generation == 0
            || self.controller_key_sha256 == [0; 32] || self.host_key_sha256 == [0; 32]
            || self.controller_key_sha256 == self.host_key_sha256 || self.capability_sha256 == [0; 32]
            || self.controller_device_id == self.host_device_id
            || self.permissions.is_empty() || self.permissions.len() > 7
            || self.permissions.iter().enumerate().any(|(i,p)| {
                self.permissions[..i].contains(p)
                    || !matches!(Permission::try_from(*p), Ok(v) if v != Permission::Unspecified)
            })
            || self.paths.is_empty() || self.paths.len() > 2
            || self.paths.iter().enumerate().any(|(i,p)| {
                self.paths[..i].contains(p)
                    || !matches!(crate::Path::try_from(*p), Ok(crate::Path::Direct | crate::Path::Relay))
            })
            || (self.maximum_file_write_bytes > 0 && !self.permissions.contains(&(Permission::FileWrite as i32)))
        { return Err(invalid()); }
        Ok(())
    }
    pub fn check_permit(&self, c: &PermitClaims) -> Result<(), ContractError> {
        self.validate()?;
        if !c.required_capabilities.iter().any(|v| v == CAPABILITY)
            || self.deployment_id != c.deployment_id || self.security_epoch != c.security_epoch
            || self.session_id != c.session_id || self.account_id != c.account_id
            || self.controller_device_id != c.controller_device_id || self.host_device_id != c.host_device_id
            || self.controller_key_sha256.as_slice() != c.controller_key_sha256
            || self.host_key_sha256.as_slice() != c.host_key_sha256
            || self.resource_id != c.resource_id || self.connection_generation > c.connection_generation
            || self.policy_revision != c.policy_revision || self.capability_sha256.as_slice() != c.capability_sha256
            || self.permissions != c.permissions || self.paths != c.paths
        { return Err(invalid()); }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES { return Err(invalid()); }
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRemoteUsageBudget {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteBudgetQuota {
    pub scope: String,
    pub key: String,
    pub revision: u64,
    pub maximum_bytes: u64,
    pub maximum_file_write_bytes: u64,
    pub maximum_connection_attempts: u64,
    pub promised_bytes: u64,
    pub promised_file_write_bytes: u64,
    pub promised_connection_attempts: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteBudgetQuotaUpdate {
    pub expected_revision: u64,
    pub maximum_bytes: u64,
    pub maximum_file_write_bytes: u64,
    pub maximum_connection_attempts: u64,
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid original remote cumulative budget")
}
