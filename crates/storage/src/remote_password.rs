//! Host-signed, scoped password authority. CPU work never holds the database lock.
use crate::{StorageError, Store, accounts::Principal, audit, require_id, trusted::unix_ms};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, hash_password, verify_password};
use nestlink_identity::{
    digest,
    remote_password::{configure_transcript, use_transcript},
    verify_device_action,
};
use nestlink_policy::PathSet;
use nestlink_protocol::api::{
    EnrollmentChallenge, RemotePasswordSettings, RemotePasswordSetup, RemotePasswordSubmission,
    RemotePasswordView, RemoteView,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub const MAX_PASSWORD_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const WINDOW_MS: u64 = 60_000;

pub struct PasswordUpdate {
    pub revision: u64,
    pub revoked_sessions: Vec<String>,
}
struct Stamp {
    actor: Principal,
    generation: u64,
    epoch: u64,
}
struct Configuration {
    stamp: Stamp,
    host: String,
    host_key: [u8; 32],
    challenge: EnrollmentChallenge,
    settings: RemotePasswordSettings,
    started: u64,
}
pub struct RemotePasswordDraft {
    configuration: Configuration,
    password: Secret,
}
pub struct RemotePasswordReplacement {
    configuration: Configuration,
    encoded: String,
}
impl RemotePasswordDraft {
    pub fn derive(self) -> Result<RemotePasswordReplacement, StorageError> {
        Ok(RemotePasswordReplacement {
            encoded: hash_password(self.password.expose())?,
            configuration: self.configuration,
        })
    }
}
struct AttemptState {
    stamp: Stamp,
    view: RemoteView,
    controller_key: [u8; 32],
    revision: u64,
    encoded: String,
    paths: Vec<i32>,
    started: u64,
}
pub struct RemotePasswordSnapshot {
    state: AttemptState,
    password: Secret,
}
pub struct RemotePasswordVerification {
    state: AttemptState,
    matched: bool,
}
impl RemotePasswordSnapshot {
    pub fn verify(self) -> RemotePasswordVerification {
        let matched = verify_password(self.password.expose(), &self.state.encoded).is_ok();
        RemotePasswordVerification {
            state: self.state,
            matched,
        }
    }
}
struct PasswordRow {
    revision: u64,
    encoded: Option<String>,
    key: Vec<u8>,
    permissions: Vec<i32>,
    paths: Vec<i32>,
    epoch: u64,
    configured: u64,
    expires: u64,
    window_start: u64,
    window_count: u64,
}

impl Store {
    fn password_stamp(&self, actor: &Principal, now: u64) -> Result<Stamp, StorageError> {
        self.validate_management_session(actor, now)?;
        let generation = self
            .connection
            .query_row(
                "SELECT generation FROM management_sessions WHERE id=?1 AND access_expires>?2",
                params![actor.session_id, now],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::Unauthorized)?;
        Ok(Stamp {
            actor: actor.clone(),
            generation,
            epoch: self.security_epoch()?,
        })
    }
    fn recheck_password_stamp(&self, stamp: &Stamp, now: u64) -> Result<(), StorageError> {
        let current = self.password_stamp(&stamp.actor, now)?;
        if current.generation != stamp.generation || current.epoch != stamp.epoch {
            return Err(StorageError::Unauthorized);
        }
        Ok(())
    }
    fn password_key(&self, id: &str, now: u64) -> Result<[u8; 32], StorageError> {
        let key = self.device_record_at(id, now)?.public_key;
        let stored: Vec<u8> =
            self.connection
                .query_row("SELECT key_sha256 FROM devices WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
        if stored != digest(&key) {
            return Err(StorageError::Forbidden);
        }
        Ok(key)
    }
    fn password_row(&self, host: &str) -> Result<Option<PasswordRow>, StorageError> {
        let row=self.connection.query_row("SELECT revision,encoded,host_key_sha256,permissions_json,paths_json,security_epoch,configured_at,expires_at,window_start,window_count FROM remote_passwords WHERE host_device_id=?1",[host],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u64>(5)?,r.get::<_,u64>(6)?,r.get::<_,u64>(7)?,r.get::<_,u64>(8)?,r.get::<_,u64>(9)?))).optional()?;
        row.map(
            |(
                revision,
                encoded,
                key,
                permissions,
                paths,
                epoch,
                configured,
                expires,
                window_start,
                window_count,
            )| {
                Ok(PasswordRow {
                    revision,
                    encoded,
                    key,
                    permissions: serde_json::from_str(&permissions)?,
                    paths: serde_json::from_str(&paths)?,
                    epoch,
                    configured,
                    expires,
                    window_start,
                    window_count,
                })
            },
        )
        .transpose()
    }
    fn password_active(
        &self,
        host: &str,
        row: &PasswordRow,
        now: u64,
    ) -> Result<bool, StorageError> {
        let now = unix_ms(now)?;
        Ok(row.encoded.is_some()
            && row.epoch == self.security_epoch()?
            && row.configured <= now
            && row.expires > now
            && row.key == digest(&self.password_key(host, now)?))
    }
    fn active_password(&self, host: &str, now: u64) -> Result<PasswordRow, StorageError> {
        let row = self.password_row(host)?.ok_or(StorageError::Forbidden)?;
        if !self.password_active(host, &row, now)? {
            return Err(StorageError::Forbidden);
        }
        Ok(row)
    }
    pub fn remote_password(
        &self,
        actor: &Principal,
        host: &str,
        now: u64,
    ) -> Result<RemotePasswordView, StorageError> {
        require_id(host)?;
        self.validate_management_session(actor, now)?;
        if self.device_record_at(host, now)?.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        self.password_view(host, now)
    }
    fn password_view(&self, host: &str, now: u64) -> Result<RemotePasswordView, StorageError> {
        let Some(row) = self.password_row(host)? else {
            return Ok(RemotePasswordView {
                revision: 0,
                permissions: vec![],
                paths: vec![],
                expires_at_unix_ms: 0,
                active: false,
            });
        };
        Ok(RemotePasswordView {
            active: self.password_active(host, &row, now)?,
            revision: row.revision,
            permissions: row.permissions,
            paths: row.paths,
            expires_at_unix_ms: row.expires,
        })
    }
    fn password_challenge(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<EnrollmentChallenge, StorageError> {
        let row:Option<(Vec<u8>,u64)>=self.connection.query_row("SELECT nonce,expires FROM enrollment_challenges WHERE id=?1 AND account_id=?2 AND consumed=0 AND expires>?3",params![id,actor.account_id,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (nonce, expires) = row.ok_or(StorageError::Unauthorized)?;
        Ok(EnrollmentChallenge {
            id: id.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            expires_at_unix_ms: unix_ms(expires)?,
        })
    }
    pub fn prepare_remote_password(
        &self,
        actor: &Principal,
        host: &str,
        mut body: RemotePasswordSetup,
        now: u64,
    ) -> Result<RemotePasswordDraft, StorageError> {
        require_id(host)?;
        let stamp = self.password_stamp(actor, now)?;
        let device = self.device_record_at(host, now)?;
        if device.account != actor.account_id || !device.capabilities.iter().any(|c| c == "host") {
            return Err(StorageError::Forbidden);
        }
        let settings = &body.choice.settings;
        crate::control::validate_permissions(&settings.permissions)?;
        if PathSet::from_wire(&settings.paths)?.is_empty()
            || !(12..=1024).contains(&body.choice.password.len())
        {
            return Err(StorageError::Invalid(
                "invalid remote password configuration",
            ));
        }
        let start = unix_ms(now)?;
        if settings.expected_revision >= i64::MAX as u64
            || settings.expires_at_unix_ms > i64::MAX as u64
            || settings.expires_at_unix_ms <= start
            || settings.expires_at_unix_ms - start > MAX_PASSWORD_MS
        {
            return Err(StorageError::Invalid(
                "remote password lifetime must be within 30 days",
            ));
        }
        if self.password_row(host)?.map_or(0, |r| r.revision) != settings.expected_revision {
            return Err(StorageError::Conflict);
        }
        let challenge = self.password_challenge(actor, &body.challenge_id, now)?;
        let proof = configure_transcript(&challenge, &actor.account_id, host, &body.choice)?;
        let host_key = self.password_key(host, now)?;
        verify_device_action(&proof, &host_key, &decode(&body.signature)?)?;
        Ok(RemotePasswordDraft {
            configuration: Configuration {
                stamp,
                host: host.into(),
                host_key,
                challenge,
                settings: body.choice.settings.clone(),
                started: start,
            },
            password: Secret::from_text(std::mem::take(&mut body.choice.password)),
        })
    }
    pub fn complete_remote_password(
        &mut self,
        replacement: RemotePasswordReplacement,
        now: u64,
    ) -> Result<PasswordUpdate, StorageError> {
        let c = replacement.configuration;
        let tx = self.connection.unchecked_transaction()?;
        self.recheck_password_stamp(&c.stamp, now)?;
        let time = unix_ms(now)?;
        if time < c.started
            || time >= c.settings.expires_at_unix_ms
            || self.password_key(&c.host, now)? != c.host_key
        {
            return Err(StorageError::Forbidden);
        }
        let challenge = self.password_challenge(&c.stamp.actor, &c.challenge.id, now)?;
        if challenge.nonce != c.challenge.nonce
            || challenge.expires_at_unix_ms != c.challenge.expires_at_unix_ms
        {
            return Err(StorageError::Unauthorized);
        }
        if self.password_row(&c.host)?.map_or(0, |r| r.revision) != c.settings.expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = c.settings.expected_revision + 1;
        tx.execute(
            "UPDATE enrollment_challenges SET consumed=1 WHERE id=?1",
            [&c.challenge.id],
        )?;
        // Keep existing budgets on rotation. A new password cannot reset a live attack window.
        tx.execute("INSERT INTO remote_passwords(host_device_id,revision,encoded,host_key_sha256,permissions_json,paths_json,security_epoch,configured_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(host_device_id) DO UPDATE SET revision=excluded.revision,encoded=excluded.encoded,host_key_sha256=excluded.host_key_sha256,permissions_json=excluded.permissions_json,paths_json=excluded.paths_json,security_epoch=excluded.security_epoch,configured_at=excluded.configured_at,expires_at=excluded.expires_at",params![c.host,revision,replacement.encoded,digest(&c.host_key),serde_json::to_string(&c.settings.permissions)?,serde_json::to_string(&c.settings.paths)?,c.stamp.epoch,time,c.settings.expires_at_unix_ms])?;
        let revoked_sessions = invalidate(&tx, &c.host, now)?;
        audit(
            &tx,
            "remote_password_configured",
            &c.host,
            crate::auditing::device(&c.stamp.actor, &c.host),
        )?;
        tx.commit()?;
        Ok(PasswordUpdate {
            revision,
            revoked_sessions,
        })
    }
    pub fn revoke_remote_password(
        &mut self,
        actor: &Principal,
        host: &str,
        revision: u64,
        now: u64,
    ) -> Result<PasswordUpdate, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.remote_password(actor, host, now)?;
        let next = revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        if tx.execute("UPDATE remote_passwords SET encoded=NULL,revision=?1 WHERE host_device_id=?2 AND revision=?3",params![next,host,revision])?!=1 {return Err(StorageError::Conflict);}
        let revoked_sessions = invalidate(&tx, host, now)?;
        audit(
            &tx,
            "remote_password_revoked",
            host,
            crate::auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(PasswordUpdate {
            revision: next,
            revoked_sessions,
        })
    }
    fn password_pending(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<RemoteView, StorageError> {
        self.validate_management_session(actor, now)?;
        self.check_request_login(id, now, Some(&actor.session_id))?;
        let view = self.remote(actor, id)?;
        if self
            .device_record_at(&view.controller_device_id, now)?
            .account
            != actor.account_id
            || view.status != "pending"
            || view.expires_at_unix_ms <= unix_ms(now)?
            || view.policy_revision != self.policy()?.0
        {
            return Err(StorageError::Forbidden);
        }
        self.device_record_at(&view.host_device_id, now)?;
        Ok(view)
    }
    pub fn remote_password_offer(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<RemotePasswordView, StorageError> {
        let view = self.password_pending(actor, id, now)?;
        self.password_view(&view.host_device_id, now)
    }
    pub fn remote_password_snapshot(
        &mut self,
        actor: &Principal,
        id: &str,
        mut body: RemotePasswordSubmission,
        now: u64,
    ) -> Result<RemotePasswordSnapshot, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        let stamp = self.password_stamp(actor, now)?;
        let view = self.password_pending(actor, id, now)?;
        if body.attempt.password.len() > 1024 {
            return Err(StorageError::Invalid("remote password too long"));
        }
        let controller_key = self.password_key(&view.controller_device_id, now)?;
        let proof = use_transcript(
            &self.deployment_id()?,
            stamp.epoch,
            &actor.account_id,
            &view,
            &body.attempt,
        )?;
        verify_device_action(&proof, &controller_key, &decode(&body.signature)?)?;
        let row = self.active_password(&view.host_device_id, now)?;
        if row.revision != body.attempt.expected_revision {
            return Err(StorageError::Conflict);
        }
        if view
            .permissions
            .iter()
            .any(|p| !row.permissions.contains(p))
        {
            return Err(StorageError::Forbidden);
        }
        let paths = PathSet::from_wire(&view.paths)?.intersection(PathSet::from_wire(&row.paths)?);
        if paths.is_empty() {
            return Err(StorageError::Forbidden);
        }
        let time = unix_ms(now)?;
        let (start, count) = reserve(row.window_start, row.window_count, time, 5)?;
        let account:Option<(u64,u64)>=tx.query_row("SELECT window_start,window_count FROM remote_password_account_limits WHERE account_id=?1",[&actor.account_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (a_start, a_count) = account.unwrap_or((0, 0));
        let (a_start, a_count) = reserve(a_start, a_count, time, 30)?;
        tx.execute(
            "UPDATE remote_passwords SET window_start=?1,window_count=?2 WHERE host_device_id=?3",
            params![start, count, view.host_device_id],
        )?;
        tx.execute("INSERT INTO remote_password_account_limits VALUES(?1,?2,?3) ON CONFLICT(account_id) DO UPDATE SET window_start=excluded.window_start,window_count=excluded.window_count",params![actor.account_id,a_start,a_count])?;
        // Reservation commits before releasing the DB for Argon2. Cancellation,
        // concurrent hashes and process restart cannot recover this attempt.
        audit(
            &tx,
            "remote_password_attempted",
            id,
            crate::auditing::device(actor, &view.controller_device_id),
        )?;
        tx.commit()?;
        Ok(RemotePasswordSnapshot {
            state: AttemptState {
                stamp,
                view,
                controller_key,
                revision: row.revision,
                encoded: row.encoded.ok_or(StorageError::Forbidden)?,
                paths: paths.to_wire(),
                started: time,
            },
            password: Secret::from_text(std::mem::take(&mut body.attempt.password)),
        })
    }
    pub fn complete_remote_password_access(
        &mut self,
        verified: RemotePasswordVerification,
        now: u64,
    ) -> Result<RemoteView, StorageError> {
        let a = verified.state;
        let tx = self.connection.unchecked_transaction()?;
        self.recheck_password_stamp(&a.stamp, now)?;
        let view = self.password_pending(&a.stamp.actor, &a.view.id, now)?;
        let row = self.active_password(&view.host_device_id, now)?;
        if unix_ms(now)? < a.started
            || row.revision != a.revision
            || row.encoded.as_ref() != Some(&a.encoded)
            || self.password_key(&view.controller_device_id, now)? != a.controller_key
            || serde_json::to_vec(&view)? != serde_json::to_vec(&a.view)?
        {
            return Err(StorageError::Forbidden);
        }
        if !verified.matched {
            audit(
                &tx,
                "remote_password_failed",
                &view.id,
                crate::auditing::device(&a.stamp.actor, &view.controller_device_id),
            )?;
            tx.commit()?;
            return Err(StorageError::Unauthorized);
        }
        let active:u64=tx.query_row("SELECT count(*) FROM remote_requests WHERE (controller_account_id=?1 OR host_device_id=?2) AND password_revision IS NOT NULL AND status='approved' AND (last_renewed+15>?3 OR (lease_sequence=0 AND expires>?3))",params![a.stamp.actor.account_id,view.host_device_id,now],|r|r.get(0))?;
        if active >= 32 {
            return Err(StorageError::RateLimited);
        }
        if tx.execute("UPDATE remote_requests SET status='approved',paths_json=?1,password_revision=?2,password_controller_key_sha256=?3 WHERE id=?4 AND status='pending'",params![serde_json::to_string(&a.paths)?,a.revision,digest(&a.controller_key),view.id])?!=1 {return Err(StorageError::Conflict);}
        tx.execute("INSERT INTO sessions(id,controller_device_id,host_device_id,connection_generation) VALUES(?1,?2,?3,1)",params![view.id,view.controller_device_id,view.host_device_id])?;
        audit(
            &tx,
            "remote_password_authorized",
            &view.id,
            crate::auditing::device(&a.stamp.actor, &view.controller_device_id),
        )?;
        tx.commit()?;
        self.remote(&a.stamp.actor, &view.id)
    }
    pub(crate) fn remote_password_expiration(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<u64>, StorageError> {
        let (host,controller,revision,key):(String,String,Option<u64>,Option<Vec<u8>>)=self.connection.query_row("SELECT host_device_id,controller_device_id,password_revision,password_controller_key_sha256 FROM remote_requests WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        let Some(revision) = revision else {
            return Ok(None);
        };
        let row = self.active_password(&host, now)?;
        if row.revision != revision
            || key.as_deref() != Some(digest(&self.password_key(&controller, now)?).as_slice())
        {
            return Err(StorageError::Forbidden);
        }
        Ok(Some(row.expires))
    }
}
fn decode(signature: &str) -> Result<Vec<u8>, StorageError> {
    URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| StorageError::Invalid("invalid signature encoding"))
}
fn reserve(start: u64, count: u64, now: u64, maximum: u64) -> Result<(u64, u64), StorageError> {
    if now < start {
        return Err(StorageError::RateLimited);
    }
    if now - start >= WINDOW_MS {
        return Ok((now, 1));
    }
    if count >= maximum {
        return Err(StorageError::RateLimited);
    }
    Ok((start, count + 1))
}
fn invalidate(tx: &Transaction<'_>, host: &str, now: u64) -> Result<Vec<String>, StorageError> {
    let mut statement=tx.prepare("SELECT id FROM remote_requests WHERE host_device_id=?1 AND password_revision IS NOT NULL AND status='approved' AND (last_renewed+15>?2 OR (lease_sequence=0 AND expires>?2)) LIMIT 32")?;
    let ids = statement
        .query_map(params![host, now], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    tx.execute("UPDATE remote_requests SET status='revoked' WHERE host_device_id=?1 AND password_revision IS NOT NULL",[host])?;
    tx.execute("UPDATE sessions SET revoked=1 WHERE id IN (SELECT id FROM remote_requests WHERE host_device_id=?1 AND password_revision IS NOT NULL)",[host])?;
    tx.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM remote_requests WHERE host_device_id=?1 AND password_revision IS NOT NULL)",[host])?;
    Ok(ids)
}
