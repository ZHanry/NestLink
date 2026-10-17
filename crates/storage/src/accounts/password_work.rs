//! CPU work owns immutable snapshots, never the SQLite connection or database lock.
use super::*;

pub struct LoginSnapshot {
    account: Option<String>,
    encoded: String,
    epoch: u64,
}
pub struct LoginVerification {
    snapshot: LoginSnapshot,
    matched: bool,
}
impl LoginSnapshot {
    pub fn verify(self, password: &str) -> LoginVerification {
        let matched = verify_password(password, &self.encoded).is_ok();
        LoginVerification {
            snapshot: self,
            matched,
        }
    }
}
pub struct PasswordSnapshot {
    actor: Principal,
    encoded: String,
    epoch: u64,
    generation: u64,
}
pub struct PasswordVerification {
    snapshot: PasswordSnapshot,
}
pub struct PasswordReplacement {
    verified: PasswordVerification,
    encoded: String,
}
pub struct MemberDraft {
    name: String,
    encoded: String,
}
impl MemberDraft {
    pub fn derive(name: &str, password: &str) -> Result<Self, StorageError> {
        Ok(Self {
            name: normalize_name(name)?,
            encoded: hash_password(password)?,
        })
    }
}
impl PasswordSnapshot {
    pub fn verify(self, password: &str) -> Result<PasswordVerification, StorageError> {
        verify_password(password, &self.encoded).map_err(|_| StorageError::Unauthorized)?;
        Ok(PasswordVerification { snapshot: self })
    }
}
impl PasswordVerification {
    pub fn actor(&self) -> &Principal {
        &self.snapshot.actor
    }
    pub fn replacement(self, password: &str) -> Result<PasswordReplacement, StorageError> {
        Ok(PasswordReplacement {
            verified: self,
            encoded: hash_password(password)?,
        })
    }
}
impl PasswordReplacement {
    pub fn actor(&self) -> &Principal {
        self.verified.actor()
    }
}
impl Store {
    pub fn login_snapshot(
        &self,
        name: &str,
        now: u64,
        dummy: &str,
    ) -> Result<LoginSnapshot, StorageError> {
        let name = normalize_name(name).unwrap_or_default();
        let row:Option<(String,String,u64)>=self.connection.query_row("SELECT a.id,s.password_hash,s.blocked_until FROM accounts a JOIN account_security s ON s.account_id=a.id WHERE a.name=?1",[name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let epoch = self.security_epoch()?;
        match row {
            Some((id, encoded, blocked)) if blocked <= now => Ok(LoginSnapshot {
                account: Some(id),
                encoded,
                epoch,
            }),
            Some(_) => Err(StorageError::RateLimited),
            None => Ok(LoginSnapshot {
                account: None,
                encoded: dummy.into(),
                epoch,
            }),
        }
    }
    pub fn complete_login(
        &mut self,
        verified: LoginVerification,
        _factor: Option<&str>,
        now: u64,
        _vault: &VaultKey,
    ) -> Result<LoginGrant, StorageError> {
        let snapshot = verified.snapshot;
        let Some(id) = snapshot.account else {
            let tx = self.connection.transaction()?;
            audit(&tx, "login_failed", "login", AuditActor::Unauthenticated)?;
            tx.commit()?;
            return Err(StorageError::Unauthorized);
        };
        let tx = self.connection.transaction()?;
        let row:Option<(String,bool,u64,u64)>=tx.query_row("SELECT s.password_hash,a.disabled,s.blocked_until,d.security_epoch FROM accounts a JOIN account_security s ON s.account_id=a.id JOIN deployment d ON d.singleton=1 WHERE a.id=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let (encoded, disabled, blocked, epoch) = row.ok_or(StorageError::Unauthorized)?;
        if encoded != snapshot.encoded || epoch != snapshot.epoch {
            return Err(StorageError::Unauthorized);
        }
        if blocked > now {
            return Err(StorageError::RateLimited);
        }
        if disabled || !verified.matched {
            tx.execute("UPDATE account_security SET failed_attempts=failed_attempts+1,blocked_until=CASE WHEN failed_attempts+1>=5 THEN ?2 ELSE blocked_until END WHERE account_id=?1",params![id,now+30])?;
            audit(&tx, "login_failed", &id, AuditActor::Unauthenticated)?;
            tx.commit()?;
            return Err(StorageError::Unauthorized);
        }
        tx.execute(
            "UPDATE account_security SET failed_attempts=0,blocked_until=0 WHERE account_id=?1",
            [&id],
        )?;
        let grant = issue_login(&tx, &id, now)?;
        audit(&tx, "login_succeeded", &id, management(&grant.principal))?;
        tx.commit()?;
        Ok(grant)
    }
    pub fn password_snapshot(&self, actor: &Principal) -> Result<PasswordSnapshot, StorageError> {
        let row:Option<(String,u64,u64)>=self.connection.query_row("SELECT x.password_hash,d.security_epoch,m.generation FROM account_security x JOIN accounts a ON a.id=x.account_id JOIN management_sessions m ON m.account_id=a.id JOIN deployment d ON d.singleton=1 WHERE a.id=?1 AND m.id=?2 AND m.revoked=0 AND a.disabled=0 AND m.security_epoch=d.security_epoch",params![actor.account_id,actor.session_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (encoded, epoch, generation) = row.ok_or(StorageError::Unauthorized)?;
        Ok(PasswordSnapshot {
            actor: actor.clone(),
            encoded,
            epoch,
            generation,
        })
    }
    pub fn complete_password_change(
        &mut self,
        replacement: PasswordReplacement,
        _factor: Option<&str>,
        now: u64,
        _vault: &VaultKey,
    ) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        revalidate(&tx, &replacement.verified, now)?;
        let actor = replacement.actor();
        tx.execute(
            "UPDATE account_security SET password_hash=?1 WHERE account_id=?2",
            params![replacement.encoded, actor.account_id],
        )?;
        tx.execute(
            "UPDATE management_sessions SET revoked=1 WHERE account_id=?1",
            [&actor.account_id],
        )?;
        audit(
            &tx,
            "password_changed",
            &actor.account_id,
            management(actor),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn complete_member(
        &mut self,
        actor: &Principal,
        draft: MemberDraft,
    ) -> Result<String, StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        let id = random_id();
        let tx = self.connection.unchecked_transaction()?;
        self.admin_identity(actor)?;
        tx.execute(
            "INSERT INTO accounts(id,name) VALUES(?1,?2)",
            params![id, draft.name],
        )?;
        tx.execute(
            "INSERT INTO account_security(account_id,password_hash) VALUES(?1,?2)",
            params![id, draft.encoded],
        )?;
        audit(&tx, "account_created", &id, management(actor))?;
        tx.commit()?;
        Ok(id)
    }
}
fn revalidate(
    tx: &Transaction<'_>,
    verified: &PasswordVerification,
    now: u64,
) -> Result<(), StorageError> {
    let snapshot = &verified.snapshot;
    let actor = &snapshot.actor;
    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM accounts a JOIN account_security x ON x.account_id=a.id JOIN management_sessions m ON m.account_id=a.id JOIN deployment d ON d.singleton=1 WHERE a.id=?1 AND m.id=?2 AND x.password_hash=?3 AND d.security_epoch=?4 AND m.generation=?5 AND m.revoked=0 AND a.disabled=0 AND m.security_epoch=d.security_epoch AND m.access_expires>?6)",params![actor.account_id,actor.session_id,snapshot.encoded,snapshot.epoch,snapshot.generation,now],|r|r.get(0))?;
    if active {
        Ok(())
    } else {
        Err(StorageError::Unauthorized)
    }
}
