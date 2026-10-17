//! Bounded, administrator-only metadata queries and persistent retention cursors.
use crate::{StorageError, Store, accounts::Principal, trusted::unix_ms};
use nestlink_protocol::api::{
    AuditActor, AuditEntry, AuditPage, AuditQuery, AuditRetention, AuditRetentionUpdate,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub const MAX_CLEANUP_ROWS: u16 = 500;
pub const MAX_PAGE_ROWS: u16 = 100;

pub(crate) fn management(actor: &Principal) -> AuditActor {
    AuditActor::Management {
        account_id: actor.account_id.clone(),
        session_id: actor.session_id.clone(),
    }
}

/// Only used after the domain operation has verified the device proof.
pub(crate) fn device(actor: &Principal, id: &str) -> AuditActor {
    AuditActor::Device {
        account_id: actor.account_id.clone(),
        session_id: actor.session_id.clone(),
        device_id: id.into(),
    }
}

fn validate_actor(tx: &Transaction<'_>, actor: &AuditActor) -> Result<(), StorageError> {
    let (account, session, device) = match actor {
        AuditActor::Legacy => {
            return Err(StorageError::Invalid("new audit actor cannot be legacy"));
        }
        AuditActor::LocalOperator | AuditActor::Unauthenticated => return Ok(()),
        AuditActor::Node {
            node_id,
            runtime_id,
            runtime_generation,
        } => {
            crate::require_id(node_id)?;
            crate::require_id(runtime_id)?;
            let same: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM node_runtimes r JOIN deployment d ON d.singleton=1 WHERE r.node_id=?1 AND r.runtime_id=?2 AND r.generation=?3 AND r.security_epoch=d.security_epoch)", params![node_id,runtime_id,runtime_generation], |r| r.get(0))?;
            return if same {
                Ok(())
            } else {
                Err(StorageError::Unauthorized)
            };
        }
        AuditActor::Management {
            account_id,
            session_id,
        } => (account_id, Some(session_id), None),
        AuditActor::Device {
            account_id,
            session_id,
            device_id,
        } => (account_id, Some(session_id), Some(device_id)),
        AuditActor::DeviceCredential {
            account_id,
            device_id,
        } => (account_id, None, Some(device_id)),
    };
    crate::require_id(account)?;
    if let Some(session) = session {
        crate::require_id(session)?;
        // Events such as logout/password change are appended after revocation in
        // this transaction. Check identity association, not post-operation status.
        let same: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM management_sessions m JOIN deployment d ON d.singleton=1 WHERE m.id=?1 AND m.account_id=?2 AND m.security_epoch=d.security_epoch)", params![session, account], |r| r.get(0))?;
        if !same {
            return Err(StorageError::Unauthorized);
        }
    }
    if let Some(device) = device {
        crate::require_id(device)?;
        let same: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1 AND account_id=?2)",
            params![device, account],
            |r| r.get(0),
        )?;
        if !same {
            return Err(StorageError::Forbidden);
        }
    }
    Ok(())
}

pub(crate) fn record(
    tx: &Transaction<'_>,
    event: &str,
    resource: &str,
    actor: AuditActor,
) -> Result<(), StorageError> {
    if event.is_empty()
        || event.len() > 64
        || !event.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
        || resource.is_empty()
        || resource.len() > 256
        || resource.chars().any(char::is_control)
    {
        return Err(StorageError::Invalid("invalid audit metadata"));
    }
    validate_actor(tx, &actor)?;
    let actor = serde_json::to_string(&actor)?;
    let sequence:Option<u64>=tx.query_row("UPDATE audit_settings SET high_watermark=high_watermark+1 WHERE singleton=1 AND high_watermark<9223372036854775807 RETURNING high_watermark",[],|r|r.get(0)).optional()?;
    let sequence = sequence.ok_or(StorageError::Conflict)?;
    tx.execute("INSERT INTO audit(sequence,event,resource_id,security_epoch,created_at,actor_json) SELECT ?1,?2,?3,security_epoch,unixepoch(),?4 FROM deployment WHERE singleton=1",params![sequence,event,resource,actor])?;
    Ok(())
}
impl Store {
    pub(crate) fn admin_identity(&self, actor: &Principal) -> Result<(), StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        let permitted: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM management_sessions m JOIN account_security x ON x.account_id=m.account_id JOIN accounts a ON a.id=m.account_id JOIN deployment d ON d.singleton=1 WHERE m.id=?1 AND m.account_id=?2 AND m.revoked=0 AND m.security_epoch=d.security_epoch AND a.disabled=0 AND x.is_admin=1)", params![actor.session_id, actor.account_id], |r| r.get(0))?;
        if !permitted {
            return Err(StorageError::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn validate_access(&self, actor: &Principal, now: u64) -> Result<(), StorageError> {
        self.validate_management_session(actor, now)?;
        let active: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM management_sessions WHERE id=?1 AND account_id=?2 AND access_expires>?3)", params![actor.session_id, actor.account_id, now], |r| r.get(0))?;
        if !active {
            return Err(StorageError::Unauthorized);
        }
        Ok(())
    }
    pub(crate) fn audit_admin(&self, actor: &Principal, now: u64) -> Result<(), StorageError> {
        self.validate_access(actor, now)?;
        self.admin_identity(actor)
    }
    fn retention_row(&self) -> Result<AuditRetention, StorageError> {
        let (revision,retention_seconds,high_watermark,pruned_through,last):(u64,u64,u64,u64,u64)=self.connection.query_row("SELECT revision,retention_seconds,high_watermark,pruned_through,last_cleanup_at FROM audit_settings WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        Ok(AuditRetention {
            revision,
            retention_seconds,
            high_watermark,
            pruned_through,
            last_cleanup_at_unix_ms: unix_ms(last)?,
        })
    }
    pub fn audit_retention(
        &self,
        actor: &Principal,
        now: u64,
    ) -> Result<AuditRetention, StorageError> {
        self.audit_admin(actor, now)?;
        self.retention_row()
    }
    pub fn set_audit_retention(
        &mut self,
        actor: &Principal,
        update: AuditRetentionUpdate,
        now: u64,
    ) -> Result<AuditRetention, StorageError> {
        if !(3600..=31_536_000).contains(&update.retention_seconds) {
            return Err(StorageError::Invalid(
                "audit retention must be between one hour and one year",
            ));
        }
        let next = update
            .expected_revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let tx = self.connection.unchecked_transaction()?;
        self.audit_admin(actor, now)?;
        if tx.execute("UPDATE audit_settings SET revision=?1,retention_seconds=?2 WHERE singleton=1 AND revision=?3",params![next,update.retention_seconds,update.expected_revision])?!=1 {return Err(StorageError::Conflict);}
        record(
            &tx,
            "audit_retention_changed",
            "deployment",
            management(actor),
        )?;
        let view = self.retention_row()?;
        tx.commit()?;
        Ok(view)
    }
    pub fn query_audit(
        &self,
        actor: &Principal,
        query: AuditQuery,
        now: u64,
    ) -> Result<AuditPage, StorageError> {
        if query.limit == 0 || query.limit > MAX_PAGE_ROWS || query.after_sequence > i64::MAX as u64
        {
            return Err(StorageError::Invalid("invalid audit page budget or cursor"));
        }
        let tx = self.connection.unchecked_transaction()?;
        self.audit_admin(actor, now)?;
        let epoch = self.security_epoch()?;
        if query.security_epoch != epoch {
            return Err(StorageError::Conflict);
        }
        let settings = self.retention_row()?;
        if query.after_sequence > settings.high_watermark {
            return Err(StorageError::Conflict);
        }
        let mut statement=tx.prepare("SELECT sequence,event,resource_id,security_epoch,created_at,actor_json FROM audit WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
        let rows = statement.query_map(
            params![query.after_sequence, u64::from(query.limit) + 1],
            |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut entries = Vec::with_capacity(usize::from(query.limit) + 1);
        for row in rows {
            let (sequence, event, resource_id, security_epoch, seconds, actor_json) = row?;
            entries.push(AuditEntry {
                sequence,
                event,
                resource_id,
                security_epoch,
                created_at_unix_ms: unix_ms(seconds)?,
                actor: serde_json::from_str(&actor_json)?,
            });
        }
        drop(statement);
        let more = entries.len() > usize::from(query.limit);
        entries.truncate(usize::from(query.limit));
        // Advancing an empty page to the high watermark accounts for retention
        // without a client endlessly polling an obsolete gap.
        let next_sequence = entries
            .last()
            .map_or(settings.high_watermark, |e| e.sequence);
        let page = AuditPage {
            entries,
            security_epoch: epoch,
            next_sequence,
            high_watermark: settings.high_watermark,
            pruned_through: settings.pruned_through,
            history_pruned: query.after_sequence < settings.pruned_through,
            more,
        };
        tx.commit()?;
        Ok(page)
    }
    /// One bounded service-maintenance transaction; never vacuums the live DB.
    pub fn cleanup_audit(&mut self, now: u64, budget: u16) -> Result<u64, StorageError> {
        unix_ms(now)?;
        if budget == 0 || budget > MAX_CLEANUP_ROWS {
            return Err(StorageError::Invalid("invalid audit cleanup budget"));
        }
        let tx = self.connection.unchecked_transaction()?;
        let settings = self.retention_row()?;
        if unix_ms(now)? < settings.last_cleanup_at_unix_ms {
            return Err(StorageError::Invalid(
                "audit maintenance clock moved backwards",
            ));
        }
        let cutoff = now.saturating_sub(settings.retention_seconds);
        let mut statement = tx.prepare(
            "SELECT sequence FROM audit WHERE created_at<=?1 ORDER BY created_at,sequence LIMIT ?2",
        )?;
        let selected = statement
            .query_map(params![cutoff, budget], |r| r.get::<_, u64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for id in &selected {
            tx.execute("DELETE FROM audit WHERE sequence=?1", [id])?;
        }
        let pruned = selected
            .iter()
            .copied()
            .max()
            .unwrap_or(settings.pruned_through)
            .max(settings.pruned_through);
        tx.execute(
            "UPDATE audit_settings SET pruned_through=?1,last_cleanup_at=?2 WHERE singleton=1",
            params![pruned, now],
        )?;
        tx.commit()?;
        Ok(selected.len() as u64)
    }
}

#[cfg(test)]
mod actor_tests {
    use super::*;
    #[test]
    fn new_records_reject_unknown_history_and_cross_account_device_attribution()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut s = Store::in_memory(&nestlink_auth::random_id())?;
        let a = nestlink_auth::random_id();
        let b = nestlink_auth::random_id();
        let device_id = nestlink_auth::random_id();
        s.add_account(&a, "actor")?;
        s.add_account(&b, "other")?;
        s.add_device(&device_id, &b, &[23; 32])?;
        {
            let tx = s.connection.transaction()?;
            let wrong = AuditActor::DeviceCredential {
                account_id: a,
                device_id: device_id.clone(),
            };
            assert!(matches!(
                record(&tx, "credential_rotated", "credential", wrong),
                Err(StorageError::Forbidden)
            ));
            assert!(record(&tx, "test_metadata", "deployment", AuditActor::Legacy).is_err());
            assert_eq!(
                tx.query_row("SELECT high_watermark FROM audit_settings", [], |r| r
                    .get::<_, u64>(0))?,
                0
            );
            let valid = AuditActor::DeviceCredential {
                account_id: b,
                device_id,
            };
            record(&tx, "credential_rotated", "credential", valid)?;
            tx.commit()?;
        }
        assert_eq!(s.audit_count()?, 1);
        assert!(
            s.connection
                .execute("UPDATE audit SET actor_json='not-json'", [])
                .is_err()
        );
        assert!(
            s.connection
                .execute(
                    "UPDATE audit SET actor_json=?1",
                    [format!("\"{}\"", "x".repeat(513))]
                )
                .is_err()
        );
        Ok(())
    }
}
