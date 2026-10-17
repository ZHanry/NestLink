//! Offline recovery statements from an independently trusted cumulative ledger.
use crate::{ContractError, ErrorCode, SCHEMA_VERSION, service_plane::ServiceQuotaScope, valid_id};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SERVICE_QUOTA_RECOVERY_BYTES: usize = 16 * 1024 * 1024;
pub const SERVICE_QUOTA_RECOVERY_SCOPES: usize = 65_536;
pub const SERVICE_QUOTA_RECOVERY_VALIDITY_MS: u64 = 15 * 60 * 1000;
pub const SERVICE_QUOTA_RECOVERY_DRAIN_MS: u64 = crate::service_plane::SERVICE_LEASE_MS + 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaRecoveryFloor {
    pub scope: ServiceQuotaScope,
    pub scope_key: String,
    pub spent_bytes: u64,
    pub outstanding_bytes: u64,
}

/// This request describes only the restored snapshot's known lower bounds.
/// It cannot attest to usage or grants omitted by that snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaRecoveryRequest {
    pub schema_version: u32,
    pub deployment_id: String,
    pub restored_security_epoch: u64,
    pub policy_revision: u64,
    pub quota_revision: u64,
    pub known_grants_sha256: [u8; 32],
    pub floors: Vec<ServiceQuotaRecoveryFloor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaRecoveredTotal {
    pub scope: ServiceQuotaScope,
    pub scope_key: String,
    /// Lifetime spend plus all unresolved commitments, including grants absent
    /// from the restored snapshot. Unknown use must be charged conservatively.
    pub charged_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuotaReconciliationClaims {
    pub schema_version: u32,
    pub deployment_id: String,
    pub restored_security_epoch: u64,
    pub policy_revision: u64,
    pub quota_revision: u64,
    pub request_sha256: [u8; 32],
    pub ledger_id: String,
    pub checkpoint_id: String,
    pub checkpoint_sha256: [u8; 32],
    /// The external authority has closed all previous grant issuers and
    /// accounted for every historical grant, including uncertain full ceilings.
    pub all_prior_grants_accounted: bool,
    pub prior_authority_stopped_at_unix_ms: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub totals: Vec<ServiceQuotaRecoveredTotal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceQuotaReconciliation {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid external service quota reconciliation",
    )
}

fn number(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}

fn ordered<'a>(keys: impl Iterator<Item = (ServiceQuotaScope, &'a str)>) -> bool {
    let mut previous = None;
    for (scope, key) in keys {
        let next = (scope.as_str(), key);
        if !valid_id(key) || previous.is_some_and(|old| old >= next) {
            return false;
        }
        previous = Some(next);
    }
    true
}

impl ServiceQuotaRecoveryRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || !valid_id(&self.deployment_id)
            || !number(self.restored_security_epoch)
            || !number(self.policy_revision)
            || !number(self.quota_revision)
            || self.known_grants_sha256 == [0; 32]
            || self.floors.len() > SERVICE_QUOTA_RECOVERY_SCOPES
            || !ordered(self.floors.iter().map(|f| (f.scope, f.scope_key.as_str())))
            || self.floors.iter().any(|floor| {
                floor
                    .spent_bytes
                    .checked_add(floor.outstanding_bytes)
                    .is_none_or(|total| total > i64::MAX as u64)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl ServiceQuotaReconciliationClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || !valid_id(&self.deployment_id)
            || !valid_id(&self.ledger_id)
            || !valid_id(&self.checkpoint_id)
            || !number(self.restored_security_epoch)
            || !number(self.policy_revision)
            || !number(self.quota_revision)
            || self.request_sha256 == [0; 32]
            || self.checkpoint_sha256 == [0; 32]
            || !self.all_prior_grants_accounted
            || !number(self.prior_authority_stopped_at_unix_ms)
            || !number(self.issued_at_unix_ms)
            || !number(self.expires_at_unix_ms)
            || self
                .prior_authority_stopped_at_unix_ms
                .checked_add(SERVICE_QUOTA_RECOVERY_DRAIN_MS)
                .is_none_or(|end| end > self.issued_at_unix_ms)
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > SERVICE_QUOTA_RECOVERY_VALIDITY_MS
            || self.totals.len() > SERVICE_QUOTA_RECOVERY_SCOPES
            || !ordered(self.totals.iter().map(|t| (t.scope, t.scope_key.as_str())))
        {
            return Err(invalid());
        }
        let mut sums = [0u64; 4];
        for total in &self.totals {
            let index = match total.scope {
                ServiceQuotaScope::Account => 0,
                ServiceQuotaScope::Device => 1,
                ServiceQuotaScope::Node => 2,
                ServiceQuotaScope::Resource => 3,
            };
            sums[index] = sums[index]
                .checked_add(total.charged_bytes)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(invalid)?;
        }
        if sums.iter().any(|sum| *sum != sums[0]) {
            return Err(invalid());
        }
        Ok(())
    }
}
