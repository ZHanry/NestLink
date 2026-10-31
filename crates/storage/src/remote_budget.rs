//! Thin original remote permit transaction adaptation of durable quota promises.
//! Every promise is permanent, including expiry, revoke and lost responses.
use crate::{StorageError, Store, accounts::Principal};
use nestlink_protocol::{PermitClaims, Permission, remote_budget::*};
use rusqlite::{OptionalExtension, Transaction, params};

fn fixed(value: &[u8]) -> Result<[u8; 32], StorageError> {
    value.try_into().map_err(|_| StorageError::Conflict)
}
impl Store {
    pub fn remote_budget_quota(&self, actor: &Principal, scope: &str, key: &str, now: u64) -> Result<Option<RemoteBudgetQuota>, StorageError> {
        self.audit_admin(actor, now)?;
        if !["account", "device", "resource"].contains(&scope) || !nestlink_protocol::valid_id(key) { return Err(StorageError::Forbidden); }
        Ok(self.connection.query_row("SELECT revision,maximum_bytes,maximum_file_write_bytes,maximum_connection_attempts,COALESCE(promised_bytes,0),COALESCE(promised_file_write_bytes,0),COALESCE(promised_connection_attempts,0) FROM remote_budget_limits LEFT JOIN remote_budget_ledgers USING(scope_kind,scope_key) WHERE scope_kind=?1 AND scope_key=?2", params![scope,key], |r| Ok(RemoteBudgetQuota { scope: scope.into(), key:key.into(), revision:r.get(0)?,maximum_bytes:r.get(1)?,maximum_file_write_bytes:r.get(2)?,maximum_connection_attempts:r.get(3)?,promised_bytes:r.get(4)?,promised_file_write_bytes:r.get(5)?,promised_connection_attempts:r.get(6)? })).optional()?)
    }
    pub fn set_remote_budget_quota(&mut self, actor: &Principal, scope: &str, key: &str, update: RemoteBudgetQuotaUpdate, now: u64) -> Result<RemoteBudgetQuota, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        let original = self.remote_budget_quota(actor, scope, key, now)?;
        let revision = original.as_ref().map_or(0, |v| v.revision);
        let next = revision.checked_add(1).filter(|v| *v <= i64::MAX as u64).ok_or(StorageError::Conflict)?;
        if revision != update.expected_revision || update.maximum_bytes > i64::MAX as u64
            || update.maximum_file_write_bytes > update.maximum_bytes || update.maximum_connection_attempts > i64::MAX as u64
            || original.as_ref().is_some_and(|v| v.promised_bytes > update.maximum_bytes || v.promised_file_write_bytes > update.maximum_file_write_bytes || v.promised_connection_attempts > update.maximum_connection_attempts)
        { return Err(StorageError::Conflict); }
        tx.execute("INSERT INTO remote_budget_limits VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(scope_kind,scope_key) DO UPDATE SET maximum_bytes=excluded.maximum_bytes,maximum_file_write_bytes=excluded.maximum_file_write_bytes,maximum_connection_attempts=excluded.maximum_connection_attempts,revision=excluded.revision", params![scope,key,update.maximum_bytes,update.maximum_file_write_bytes,update.maximum_connection_attempts,next])?;
        tx.execute("INSERT OR IGNORE INTO remote_budget_ledgers(scope_kind,scope_key) VALUES(?1,?2)", params![scope,key])?;
        crate::auditing::record(&tx, "remote_cumulative_quota_changed", key, crate::auditing::management(actor))?;
        let result = self.remote_budget_quota(actor, scope, key, now)?.ok_or(StorageError::Conflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub(crate) fn reserve_remote_promise(
        &self, tx: &Transaction<'_>, permit: &PermitClaims,
        bytes: u64, file: u64, attempts: u32,
    ) -> Result<(), StorageError> {
        let fenced: bool = tx.query_row("SELECT restore_fenced FROM service_quota_settings WHERE singleton=1", [], |r| r.get(0))?;
        if fenced || bytes == 0 || bytes > i64::MAX as u64 || file > bytes || attempts == 0 {
            return Err(StorageError::RateLimited);
        }
        let host = self.device_record_at(&permit.host_device_id, permit.issued_at_unix_ms / 1000)?;
        let mut scopes = vec![
            ("account", permit.account_id.as_str(), 1024_u64 * 1024 * 1024 * 1024, 131072_u64),
            ("device", permit.controller_device_id.as_str(), 256 * 1024 * 1024 * 1024, 32768),
            ("device", permit.host_device_id.as_str(), 256 * 1024 * 1024 * 1024, 32768),
            ("resource", permit.resource_id.as_str(), 16 * 1024 * 1024 * 1024, 4096),
        ];
        if host.account != permit.account_id {
            scopes.push(("account", host.account.as_str(), 1024 * 1024 * 1024 * 1024, 131072));
        }
        for (scope, key, maximum, connections) in &scopes {
            tx.execute("INSERT OR IGNORE INTO remote_budget_limits VALUES(?1,?2,?3,?3,?4,1)", params![scope,key,maximum,connections])?;
            tx.execute("INSERT OR IGNORE INTO remote_budget_ledgers(scope_kind,scope_key) VALUES(?1,?2)", params![scope,key])?;
            let available: (u64,u64,u64) = tx.query_row("SELECT l.maximum_bytes-g.promised_bytes,l.maximum_file_write_bytes-g.promised_file_write_bytes,l.maximum_connection_attempts-g.promised_connection_attempts FROM remote_budget_limits l JOIN remote_budget_ledgers g USING(scope_kind,scope_key) WHERE scope_kind=?1 AND scope_key=?2", params![scope,key], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            if bytes > available.0 || file > available.1 || u64::from(attempts) > available.2 { return Err(StorageError::RateLimited); }
        }
        for (scope, key, _, _) in scopes {
            if tx.execute("UPDATE remote_budget_ledgers SET promised_bytes=promised_bytes+?1,promised_file_write_bytes=promised_file_write_bytes+?2,promised_connection_attempts=promised_connection_attempts+?3 WHERE scope_kind=?4 AND scope_key=?5", params![bytes,file,attempts,scope,key])? != 1 { return Err(StorageError::Conflict); }
        }
        Ok(())
    }
    pub(crate) fn ensure_remote_usage_budget(&self, tx: &Transaction<'_>, permit: &PermitClaims) -> Result<(), StorageError> {
        if !permit.required_capabilities.iter().any(|v| v == CAPABILITY) { return Ok(()); }
        if let Some(json) = tx.query_row("SELECT claims_json FROM remote_usage_budgets WHERE session_id=?1", [&permit.session_id], |r| r.get::<_,String>(0)).optional()? {
            serde_json::from_str::<RemoteUsageBudgetClaims>(&json)?.check_permit(permit)?;
            return Ok(());
        }
        if permit.lease_sequence != 1 { return Err(StorageError::Forbidden); }
        let file = if permit.permissions.contains(&(Permission::FileWrite as i32)) { ONLINE_PROMISE_BYTES } else { 0 };
        let claims = RemoteUsageBudgetClaims {
            version: 1, reservation_id: nestlink_auth::random_id(),
            deployment_id: permit.deployment_id.clone(), security_epoch: permit.security_epoch,
            session_id: permit.session_id.clone(), account_id: permit.account_id.clone(),
            controller_device_id: permit.controller_device_id.clone(), host_device_id: permit.host_device_id.clone(),
            controller_key_sha256: fixed(&permit.controller_key_sha256)?, host_key_sha256: fixed(&permit.host_key_sha256)?,
            resource_id: permit.resource_id.clone(), connection_generation: permit.connection_generation,
            policy_revision: permit.policy_revision, capability_sha256: fixed(&permit.capability_sha256)?,
            permissions: permit.permissions.clone(), paths: permit.paths.clone(),
            maximum_bytes: ONLINE_PROMISE_BYTES, maximum_file_write_bytes: file, maximum_connection_attempts: 64,
        };
        claims.check_permit(permit)?;
        self.reserve_remote_promise(tx, permit, claims.maximum_bytes, file, claims.maximum_connection_attempts)?;
        tx.execute("INSERT INTO remote_usage_budgets VALUES(?1,?2,?3)", params![claims.reservation_id,claims.session_id,serde_json::to_string(&claims)?])?;
        Ok(())
    }
    /// Called inside the same authenticated issuance/read transaction, before
    /// the server signs a response. No private-service or relay grant is minted.
    pub fn remote_usage_budget(&self, actor: &Principal, permit: &PermitClaims, now: u64) -> Result<Option<RemoteUsageBudgetClaims>, StorageError> {
        self.current_permit(actor, &permit.session_id, now)?;
        if !permit.required_capabilities.iter().any(|v| v == CAPABILITY) { return Ok(None); }
        let claims: String = self.connection.query_row("SELECT claims_json FROM remote_usage_budgets WHERE session_id=?1", [&permit.session_id], |r| r.get(0))?;
        let claims: RemoteUsageBudgetClaims = serde_json::from_str(&claims)?;
        claims.check_permit(permit)?;
        Ok(Some(claims))
    }
}
