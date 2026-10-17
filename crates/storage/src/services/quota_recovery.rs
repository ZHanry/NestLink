//! Offline, one-restore reconciliation. Ordinary quota edits never enter here.
use crate::{StorageError, Store, auditing};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{digest, service_quota_recovery::VerifiedServiceQuotaReconciliation};
use nestlink_protocol::{
    SCHEMA_VERSION,
    api::{AuditActor, ServiceDefinition},
    service_plane::{ServiceQuotaScope, encode_service_message},
    service_quota_recovery::{
        SERVICE_QUOTA_RECOVERY_BYTES, SERVICE_QUOTA_RECOVERY_SCOPES, ServiceQuotaRecoveryFloor,
        ServiceQuotaRecoveryRequest,
    },
};
use rusqlite::{Transaction, params};
use std::collections::BTreeMap;

fn scope(kind: &str) -> Result<ServiceQuotaScope, StorageError> {
    match kind {
        "account" => Ok(ServiceQuotaScope::Account),
        "device" => Ok(ServiceQuotaScope::Device),
        "node" => Ok(ServiceQuotaScope::Node),
        "resource" => Ok(ServiceQuotaScope::Resource),
        _ => Err(StorageError::Conflict),
    }
}

fn request(tx: &Transaction<'_>) -> Result<ServiceQuotaRecoveryRequest, StorageError> {
    let (deployment, epoch, policy, revision, fenced): (String, u64, u64, u64, bool) = tx.query_row(
        "SELECT d.id,d.security_epoch,d.policy_revision,q.revision,q.restore_fenced FROM deployment d CROSS JOIN service_quota_settings q WHERE d.singleton=1 AND q.singleton=1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    if !fenced {
        return Err(StorageError::Conflict);
    }
    let mut statement = tx.prepare(
        "WITH keys(scope_kind,scope_key) AS (
            SELECT scope_kind,scope_key FROM service_quota_limits
            UNION SELECT scope_kind,scope_key FROM service_quota_ledgers
            UNION SELECT 'account',account_id FROM service_usage_grants
            UNION SELECT 'device',host_device_id FROM service_usage_grants
            UNION SELECT 'node',node_id FROM service_usage_grants
            UNION SELECT 'resource',service_id FROM service_usage_grants
        ) SELECT k.scope_kind,k.scope_key,COALESCE(g.spent_bytes,0),
            COALESCE((SELECT SUM(grant_bytes-admitted_bytes) FROM service_usage_grants WHERE terminal=0 AND
              CASE k.scope_kind WHEN 'account' THEN account_id WHEN 'device' THEN host_device_id WHEN 'node' THEN node_id ELSE service_id END=k.scope_key),0)
          FROM keys k LEFT JOIN service_quota_ledgers g USING(scope_kind,scope_key)
          ORDER BY k.scope_kind,k.scope_key LIMIT ?1"
    )?;
    let rows = statement
        .query_map([SERVICE_QUOTA_RECOVERY_SCOPES + 1], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let floors = rows
        .into_iter()
        .map(|(kind, key, spent, outstanding)| {
            Ok(ServiceQuotaRecoveryFloor {
                scope: scope(&kind)?,
                scope_key: key,
                spent_bytes: spent,
                outstanding_bytes: outstanding,
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    let mut statement = tx.prepare(
        "SELECT grant_id,grant_sha256,grant_bytes,admitted_bytes,terminal FROM service_usage_grants ORDER BY grant_id LIMIT 65537"
    )?;
    let grants = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, bool>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if grants.len() > 65_536 {
        return Err(StorageError::Conflict);
    }
    let request = ServiceQuotaRecoveryRequest {
        schema_version: SCHEMA_VERSION,
        deployment_id: deployment,
        restored_security_epoch: epoch,
        policy_revision: policy,
        quota_revision: revision,
        known_grants_sha256: digest(&encode_service_message(
            &grants,
            SERVICE_QUOTA_RECOVERY_BYTES,
        )?),
        floors,
    };
    request.validate()?;
    Ok(request)
}

impl Store {
    /// Export while the control process is stopped under its deployment lease.
    /// This is a lower-bound request; it cannot clear the restore fence.
    pub fn service_quota_recovery_request(
        &mut self,
    ) -> Result<ServiceQuotaRecoveryRequest, StorageError> {
        let tx = self.connection.transaction()?;
        let result = request(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    /// Accept only a purpose-verified statement from the separately pinned
    /// external ledger. The CLI holds the offline deployment lease throughout.
    pub fn reconcile_service_quota_after_restore(
        &mut self,
        proof: &VerifiedServiceQuotaReconciliation,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        let current = request(&tx)?;
        proof.validate_for(&current, now_ms)?;
        let mut totals = proof
            .claims()
            .totals
            .iter()
            .map(|total| {
                (
                    (total.scope.as_str(), total.scope_key.as_str()),
                    total.charged_bytes,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for floor in &current.floors {
            let key = (floor.scope.as_str(), floor.scope_key.as_str());
            let charged = totals.get(&key).copied().ok_or(StorageError::Conflict)?;
            let minimum = floor
                .spent_bytes
                .checked_add(floor.outstanding_bytes)
                .ok_or(StorageError::Conflict)?;
            if charged < minimum {
                return Err(StorageError::Conflict);
            }
        }
        for total in &proof.claims().totals {
            // Preserve debts for IDs missing from the restored snapshot. A
            // later re-registration cannot silently regain an empty ledger.
            let default_limit =
                match Self::validate_quota_scope_key(&tx, total.scope, &total.scope_key) {
                    Ok(()) => {
                        let resource_limit = if total.scope == ServiceQuotaScope::Resource {
                            let json: String = tx.query_row(
                                "SELECT definition_json FROM services WHERE id=?1",
                                [&total.scope_key],
                                |row| row.get(0),
                            )?;
                            serde_json::from_str::<ServiceDefinition>(&json)?
                                .limits
                                .maximum_bytes
                        } else {
                            u64::MAX
                        };
                        Self::default_scope_limit(total.scope, resource_limit)
                    }
                    Err(StorageError::Forbidden) => 0,
                    Err(error) => return Err(error),
                };
            tx.execute(
                "INSERT OR IGNORE INTO service_quota_limits(scope_kind,scope_key,limit_bytes,revision) VALUES(?1,?2,?3,1)",
                params![total.scope.as_str(), total.scope_key, default_limit],
            )?;
        }
        for floor in &current.floors {
            // Keep each original unknown grant and its full outstanding
            // promise. Never manufacture a terminal node stop or refund it.
            let key = (floor.scope.as_str(), floor.scope_key.as_str());
            let charged = totals.remove(&key).ok_or(StorageError::Conflict)?;
            let spent = charged
                .checked_sub(floor.outstanding_bytes)
                .ok_or(StorageError::Conflict)?;
            tx.execute(
                "INSERT INTO service_quota_ledgers(scope_kind,scope_key,spent_bytes) VALUES(?1,?2,?3) ON CONFLICT(scope_kind,scope_key) DO UPDATE SET spent_bytes=excluded.spent_bytes",
                params![key.0,key.1,spent],
            )?;
        }
        for ((kind, key), charged) in totals {
            tx.execute(
                "INSERT INTO service_quota_ledgers(scope_kind,scope_key,spent_bytes) VALUES(?1,?2,?3)",
                params![kind,key,charged],
            )?;
        }
        if tx.execute(
            "UPDATE service_quota_settings SET restore_fenced=0,revision=revision+1 WHERE singleton=1 AND restore_fenced=1 AND revision=?1 AND revision<9223372036854775807",
            [current.quota_revision],
        )? != 1 { return Err(StorageError::Conflict); }
        auditing::record(
            &tx,
            "service_quota_restore_reconciled",
            &URL_SAFE_NO_PAD.encode(proof.claims_sha256()),
            AuditActor::LocalOperator,
        )?;
        tx.commit()?;
        Ok(())
    }
}
