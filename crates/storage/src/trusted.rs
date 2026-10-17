//! Explicit host-key consent for subsequent access by one pinned installation.
use crate::{StorageError, Store, accounts::Principal, audit, require_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{digest, trust_transcript, verify_device_action};
use nestlink_protocol::api::{TrustChoice, TrustSubmission, TrustedDeviceView};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub const MAX_TRUST_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_HOST_TRUSTS: u64 = 256;

pub struct TrustUpdate {
    pub revision: u64,
    pub revoked_sessions: Vec<String>,
}

pub(crate) struct TrustAuthorization {
    pub(crate) revision: u64,
    pub(crate) permissions: Vec<i32>,
    pub(crate) paths: Vec<i32>,
    pub(crate) expires_at: u64,
}
struct TrustRow {
    revision: u64,
    permissions: String,
    paths: String,
    expires_at: u64,
    host_hash: Vec<u8>,
    controller_hash: Vec<u8>,
    host_key: Vec<u8>,
    controller_key: Vec<u8>,
}
pub(crate) fn unix_ms(now: u64) -> Result<u64, StorageError> {
    now.checked_mul(1000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StorageError::Invalid("invalid authorization clock"))
}

pub(crate) fn active_trust(
    connection: &Connection,
    host: &str,
    controller: &str,
    now: u64,
) -> Result<Option<TrustAuthorization>, StorageError> {
    let row = connection.query_row(
        "SELECT t.revision,t.permissions_json,t.paths_json,t.expires_at,t.host_key_sha256,t.controller_key_sha256,hx.public_key,cx.public_key
         FROM trusted_devices t JOIN deployment d ON d.singleton=1
         JOIN devices h ON h.id=t.host_device_id JOIN devices c ON c.id=t.controller_device_id
         JOIN device_details hx ON hx.device_id=h.id JOIN device_details cx ON cx.device_id=c.id
         JOIN accounts ha ON ha.id=h.account_id JOIN accounts ca ON ca.id=c.account_id
         WHERE t.host_device_id=?1 AND t.controller_device_id=?2 AND t.revoked=0
         AND t.security_epoch=d.security_epoch AND t.granted_at<=?3 AND t.expires_at>?3
         AND h.revoked=0 AND c.revoked=0 AND ha.disabled=0 AND ca.disabled=0
         AND t.host_key_sha256=h.key_sha256 AND t.controller_key_sha256=c.key_sha256",
        params![host,controller,unix_ms(now)?],
        |r| Ok(TrustRow { revision:r.get(0)?,permissions:r.get(1)?,paths:r.get(2)?,expires_at:r.get(3)?,host_hash:r.get(4)?,controller_hash:r.get(5)?,host_key:r.get(6)?,controller_key:r.get(7)? }),
    ).optional()?;
    let Some(row) = row else { return Ok(None) };
    if row.host_hash != digest(&row.host_key) || row.controller_hash != digest(&row.controller_key)
    {
        return Ok(None);
    }
    Ok(Some(TrustAuthorization {
        revision: row.revision,
        permissions: serde_json::from_str(&row.permissions)?,
        paths: serde_json::from_str(&row.paths)?,
        expires_at: row.expires_at,
    }))
}

impl Store {
    /// An active explicitly approved session supplies the exact key/permission
    /// context. The additional host signature is separate from login/approval.
    pub fn trust_remote(
        &mut self,
        actor: &Principal,
        id: &str,
        submission: TrustSubmission,
        now: u64,
    ) -> Result<TrustUpdate, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_management_session(actor, now)?;
        let permit = self.current_permit(actor, id, now)?;
        let host = self.device_record_at(&permit.host_device_id, now)?;
        if host.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let TrustChoice {
            expected_revision,
            expires_at_unix_ms,
        } = submission.choice;
        let now_ms = unix_ms(now)?;
        if expires_at_unix_ms <= now_ms || expires_at_unix_ms - now_ms > MAX_TRUST_MS {
            return Err(StorageError::Invalid(
                "trust lifetime must be within 30 days",
            ));
        }
        let revision = expected_revision
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let proof = trust_transcript(&permit, &actor.account_id, &submission.choice)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&submission.signature)
            .map_err(|_| StorageError::Invalid("invalid trust signature encoding"))?;
        verify_device_action(&proof, &host.public_key, &signature)?;
        let old: Option<u64> = tx.query_row(
            "SELECT revision FROM trusted_devices WHERE host_device_id=?1 AND controller_device_id=?2",
            params![permit.host_device_id,permit.controller_device_id], |r|r.get(0),
        ).optional()?;
        if old.unwrap_or(0) != expected_revision {
            return Err(StorageError::Conflict);
        }
        if old.is_none() {
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM trusted_devices WHERE host_device_id=?1",
                [&permit.host_device_id],
                |r| r.get(0),
            )?;
            if count >= MAX_HOST_TRUSTS {
                return Err(StorageError::RateLimited);
            }
        }
        tx.execute(
            "INSERT INTO trusted_devices(host_device_id,controller_device_id,host_key_sha256,controller_key_sha256,permissions_json,paths_json,revision,security_epoch,granted_at,expires_at,source_request_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(host_device_id,controller_device_id) DO UPDATE SET host_key_sha256=excluded.host_key_sha256,controller_key_sha256=excluded.controller_key_sha256,permissions_json=excluded.permissions_json,paths_json=excluded.paths_json,revision=excluded.revision,security_epoch=excluded.security_epoch,granted_at=excluded.granted_at,expires_at=excluded.expires_at,source_request_id=excluded.source_request_id,revoked=0",
            params![permit.host_device_id,permit.controller_device_id,permit.host_key_sha256,permit.controller_key_sha256,serde_json::to_string(&permit.permissions)?,serde_json::to_string(&permit.paths)?,revision,permit.security_epoch,now_ms,expires_at_unix_ms,id],
        )?;
        let revoked_sessions = invalidate_sessions(
            &tx,
            &permit.host_device_id,
            &permit.controller_device_id,
            now,
        )?;
        audit(
            &tx,
            "device_trust_granted",
            id,
            crate::auditing::device(actor, &permit.host_device_id),
        )?;
        tx.commit()?;
        Ok(TrustUpdate {
            revision,
            revoked_sessions,
        })
    }

    pub fn trusted_devices(
        &self,
        actor: &Principal,
        host: &str,
        now: u64,
    ) -> Result<Vec<TrustedDeviceView>, StorageError> {
        require_id(host)?;
        self.validate_management_session(actor, now)?;
        if self.device_record_at(host, now)?.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let mut statement = self.connection.prepare("SELECT controller_device_id,host_key_sha256,controller_key_sha256,permissions_json,paths_json,revision,expires_at FROM trusted_devices WHERE host_device_id=?1 ORDER BY controller_device_id LIMIT 256")?;
        let rows = statement.query_map([host], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, u64>(6)?,
            ))
        })?;
        let mut views = Vec::new();
        for row in rows {
            let (controller, host_key, controller_key, permissions, paths, revision, expires_at) =
                row?;
            let active = active_trust(&self.connection, host, &controller, now)?.is_some();
            views.push(TrustedDeviceView {
                host_device_id: host.into(),
                controller_device_id: controller,
                host_key_sha256: URL_SAFE_NO_PAD.encode(host_key),
                controller_key_sha256: URL_SAFE_NO_PAD.encode(controller_key),
                permissions: serde_json::from_str(&permissions)?,
                paths: serde_json::from_str(&paths)?,
                revision,
                expires_at_unix_ms: expires_at,
                active,
            });
        }
        Ok(views)
    }

    pub fn revoke_device_trust(
        &mut self,
        actor: &Principal,
        host: &str,
        controller: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<String>, StorageError> {
        require_id(host)?;
        require_id(controller)?;
        let tx = self.connection.unchecked_transaction()?;
        self.validate_management_session(actor, now)?;
        if self.device_record_at(host, now)?.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let next = expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        if tx.execute("UPDATE trusted_devices SET revoked=1,revision=?1 WHERE host_device_id=?2 AND controller_device_id=?3 AND revision=?4",params![next,host,controller,expected_revision])?!=1 { return Err(StorageError::Conflict); }
        let ids = invalidate_sessions(&tx, host, controller, now)?;
        audit(
            &tx,
            "device_trust_revoked",
            &format!("{host}/{controller}"),
            crate::auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(ids)
    }

    pub(crate) fn trust_expiration(&self, id: &str, now: u64) -> Result<Option<u64>, StorageError> {
        let (host,controller,revision):(String,String,Option<u64>)=self.connection.query_row("SELECT host_device_id,controller_device_id,trust_revision FROM remote_requests WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let Some(revision) = revision else {
            return Ok(None);
        };
        let trust = active_trust(&self.connection, &host, &controller, now)?
            .filter(|t| t.revision == revision)
            .ok_or(StorageError::Forbidden)?;
        Ok(Some(trust.expires_at))
    }
}

fn invalidate_sessions(
    tx: &Transaction<'_>,
    host: &str,
    controller: &str,
    now: u64,
) -> Result<Vec<String>, StorageError> {
    let mut statement=tx.prepare("SELECT id FROM remote_requests WHERE host_device_id=?1 AND controller_device_id=?2 AND trust_revision IS NOT NULL AND status='approved' AND (last_renewed+15>?3 OR (lease_sequence=0 AND expires>?3)) LIMIT 32")?;
    let ids = statement
        .query_map(params![host, controller, now], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    tx.execute("UPDATE remote_requests SET status='revoked' WHERE host_device_id=?1 AND controller_device_id=?2 AND trust_revision IS NOT NULL",params![host,controller])?;
    tx.execute("UPDATE sessions SET revoked=1 WHERE id IN (SELECT id FROM remote_requests WHERE host_device_id=?1 AND controller_device_id=?2 AND trust_revision IS NOT NULL)",params![host,controller])?;
    tx.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM remote_requests WHERE host_device_id=?1 AND controller_device_id=?2 AND trust_revision IS NOT NULL)",params![host,controller])?;
    Ok(ids)
}
