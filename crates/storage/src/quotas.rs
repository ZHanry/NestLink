//! Persistent limits for the control process's opaque native WSS relay.
use crate::{StorageError, Store, accounts::Principal, auditing};
use nestlink_protocol::api::{RelayQuota, RelayQuotaLimits, RelayQuotaUpdate};
use rusqlite::params;

impl Store {
    /// Internal fact for relay admission and supervision; does not authorize forwarding.
    pub fn relay_quota_current(&self) -> Result<RelayQuota, StorageError> {
        let quota = self.connection.query_row("SELECT revision,max_allocations,max_account_endpoints,bytes_per_second,bytes_per_allocation FROM relay_quotas WHERE singleton=1", [], |r| Ok(RelayQuota {
            revision:r.get(0)?, limits:RelayQuotaLimits {max_allocations:r.get(1)?, max_account_endpoints:r.get(2)?, bytes_per_second:r.get(3)?, bytes_per_allocation:r.get(4)?}
        }))?;
        if !quota.limits.valid() || quota.revision == 0 {
            return Err(StorageError::Invalid("invalid stored relay quota"));
        }
        Ok(quota)
    }
    pub fn relay_quota(&self, actor: &Principal, now: u64) -> Result<RelayQuota, StorageError> {
        self.audit_admin(actor, now)?;
        self.relay_quota_current()
    }
    pub fn set_relay_quota(
        &mut self,
        actor: &Principal,
        update: RelayQuotaUpdate,
        now: u64,
    ) -> Result<RelayQuota, StorageError> {
        if !update.limits.valid() {
            return Err(StorageError::Invalid("invalid relay quota limits"));
        }
        let revision = update
            .expected_revision
            .checked_add(1)
            .filter(|r| update.expected_revision > 0 && *r <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let tx = self.connection.unchecked_transaction()?;
        self.audit_admin(actor, now)?;
        let limits = update.limits;
        if tx.execute("UPDATE relay_quotas SET revision=?1,max_allocations=?2,max_account_endpoints=?3,bytes_per_second=?4,bytes_per_allocation=?5 WHERE singleton=1 AND revision=?6", params![revision,limits.max_allocations,limits.max_account_endpoints,limits.bytes_per_second,limits.bytes_per_allocation,update.expected_revision])?!=1 {return Err(StorageError::Conflict);}
        auditing::record(
            &tx,
            "relay_quota_changed",
            "deployment",
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(RelayQuota { revision, limits })
    }
}
