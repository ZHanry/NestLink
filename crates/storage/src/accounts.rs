use super::{StorageError, Store, audit, require_id};
use crate::auditing::management;
use nestlink_auth::{
    Secret, VaultKey, base32_secret, hash_password, random_id, recovery_codes, recovery_hash,
    token, token_hash, verify_password, verify_totp,
};
use nestlink_protocol::api::AuditActor;
pub use nestlink_protocol::api::{AccountView, Principal};
mod password_work;
pub use password_work::{
    LoginSnapshot, LoginVerification, MemberDraft, PasswordReplacement, PasswordSnapshot,
    PasswordVerification,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub const ACCESS_SECONDS: u64 = 300;
pub const REFRESH_SECONDS: u64 = 604_800;

pub struct LoginGrant {
    pub principal: Principal,
    pub access_token: Secret,
    pub refresh_token: Secret,
    pub generation: u64,
    pub refresh_expires: u64,
}

impl Store {
    pub fn bootstrap_admin(&mut self, name: &str, password: &str) -> Result<String, StorageError> {
        let name = normalize_name(name)?;
        let encoded = hash_password(password)?;
        let id = random_id();
        let tx = self.connection.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM account_security WHERE is_admin=1",
            [],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(StorageError::Conflict);
        }
        tx.execute(
            "INSERT INTO accounts(id,name) VALUES(?1,?2)",
            params![id, name],
        )?;
        tx.execute(
            "INSERT INTO account_security(account_id,password_hash,is_admin) VALUES(?1,?2,1)",
            params![id, encoded],
        )?;
        audit(&tx, "admin_bootstrapped", &id, AuditActor::LocalOperator)?;
        tx.commit()?;
        Ok(id)
    }
    pub fn create_member(
        &mut self,
        actor: &Principal,
        name: &str,
        password: &str,
    ) -> Result<String, StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        self.complete_member(actor, MemberDraft::derive(name, password)?)
    }
    pub fn accounts(&self, actor: &Principal) -> Result<Vec<AccountView>, StorageError> {
        self.admin_identity(actor)?;
        let mut statement=self.connection.prepare("SELECT a.id,a.name,s.is_admin,a.disabled,s.totp_ciphertext IS NOT NULL FROM accounts a JOIN account_security s ON s.account_id=a.id ORDER BY a.name LIMIT 1000")?;
        Ok(statement
            .query_map([], |r| {
                Ok(AccountView {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    is_admin: r.get(2)?,
                    disabled: r.get(3)?,
                    totp_enabled: r.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }
    pub fn login(
        &mut self,
        name: &str,
        password: &str,
        factor: Option<&str>,
        now: u64,
        vault: &VaultKey,
        dummy_hash: &str,
    ) -> Result<LoginGrant, StorageError> {
        let verified = self.login_snapshot(name, now, dummy_hash)?.verify(password);
        self.complete_login(verified, factor, now, vault)
    }
    pub fn authenticate(&self, access: &str, now: u64) -> Result<Principal, StorageError> {
        if access.len() != 43 {
            return Err(StorageError::Unauthorized);
        }
        self.connection.query_row("SELECT a.id,s.id,a.name,x.is_admin,s.access_expires FROM management_sessions s JOIN accounts a ON a.id=s.account_id JOIN account_security x ON x.account_id=a.id JOIN deployment d ON d.singleton=1 WHERE s.access_sha256=?1 AND s.access_expires>?2 AND s.revoked=0 AND a.disabled=0 AND s.security_epoch=d.security_epoch",
            params![token_hash("access",access),now],|r|Ok(Principal{account_id:r.get(0)?,session_id:r.get(1)?,name:r.get(2)?,is_admin:r.get(3)?,access_expires:r.get(4)?})).optional()?.ok_or(StorageError::Unauthorized)
    }
    pub fn refresh_login(
        &mut self,
        refresh: &str,
        generation: u64,
        now: u64,
    ) -> Result<LoginGrant, StorageError> {
        if refresh.len() != 43 {
            return Err(StorageError::Unauthorized);
        }
        let tx = self.connection.transaction()?;
        let record:Option<(String,String)>=tx.query_row("SELECT s.id,s.account_id FROM management_sessions s JOIN accounts a ON a.id=s.account_id JOIN deployment d ON d.singleton=1 WHERE s.refresh_sha256=?1 AND s.generation=?2 AND s.refresh_expires>?3 AND s.revoked=0 AND a.disabled=0 AND s.security_epoch=d.security_epoch",params![token_hash("refresh",refresh),generation,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((session_id, account_id)) = record else {
            return Err(StorageError::Unauthorized);
        };
        let next = generation
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let access = token();
        let refresh = token();
        tx.execute("UPDATE management_sessions SET access_sha256=?1,refresh_sha256=?2,generation=?3,access_expires=?4,refresh_expires=?5 WHERE id=?6",params![token_hash("access",access.expose()),token_hash("refresh",refresh.expose()),next,now+ACCESS_SECONDS,now+REFRESH_SECONDS,session_id])?;
        let principal = principal_for(&tx, &account_id, &session_id, now + ACCESS_SECONDS)?;
        audit(&tx, "login_refreshed", &session_id, management(&principal))?;
        tx.commit()?;
        Ok(LoginGrant {
            principal,
            access_token: access,
            refresh_token: refresh,
            generation: next,
            refresh_expires: now + REFRESH_SECONDS,
        })
    }
    pub fn logout(&mut self, actor: &Principal) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        tx.execute(
            "UPDATE management_sessions SET revoked=1 WHERE id=?1 AND account_id=?2",
            params![actor.session_id, actor.account_id],
        )?;
        tx.execute(
            "UPDATE remote_requests SET status='revoked' WHERE management_session_id=?1",
            [&actor.session_id],
        )?;
        tx.execute("UPDATE sessions SET revoked=1 WHERE id IN (SELECT id FROM remote_requests WHERE management_session_id=?1)",[&actor.session_id])?;
        tx.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM sessions WHERE revoked=1)",[])?;
        audit(&tx, "login_revoked", &actor.session_id, management(actor))?;
        tx.commit()?;
        Ok(())
    }
    pub fn begin_totp(
        &mut self,
        actor: &Principal,
        password: &str,
        factor: Option<&str>,
        now: u64,
        vault: &VaultKey,
    ) -> Result<Secret, StorageError> {
        let verified = self.password_snapshot(actor)?.verify(password)?;
        self.complete_begin_totp(verified, factor, now, vault)
    }
    pub fn confirm_totp(
        &mut self,
        actor: &Principal,
        code: &str,
        now: u64,
        vault: &VaultKey,
    ) -> Result<Vec<Secret>, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now)?;
        let pending:Option<Vec<u8>>=tx.query_row("SELECT totp_pending FROM account_security WHERE account_id=?1 AND totp_pending_expires>?2",params![actor.account_id,now],|r|r.get(0)).optional()?.flatten();
        let pending = pending.ok_or(StorageError::Unauthorized)?;
        let plaintext = vault.decrypt(&actor.account_id, &pending)?;
        let step =
            verify_totp(&plaintext, code, now, None).map_err(|_| StorageError::Unauthorized)?;
        tx.execute("UPDATE account_security SET totp_ciphertext=?1,totp_pending=NULL,totp_pending_expires=NULL,totp_last_step=?2 WHERE account_id=?3",params![pending,step,actor.account_id])?;
        let codes = replace_recovery(&tx, &actor.account_id)?;
        tx.execute(
            "UPDATE management_sessions SET revoked=1 WHERE account_id=?1 AND id<>?2",
            params![actor.account_id, actor.session_id],
        )?;
        audit(&tx, "totp_enabled", &actor.account_id, management(actor))?;
        tx.commit()?;
        Ok(codes)
    }
    pub fn reset_recovery(
        &mut self,
        actor: &Principal,
        password: &str,
        factor: &str,
        now: u64,
        vault: &VaultKey,
    ) -> Result<Vec<Secret>, StorageError> {
        let verified = self.password_snapshot(actor)?.verify(password)?;
        self.complete_reset_recovery(verified, factor, now, vault)
    }
    pub fn change_password(
        &mut self,
        actor: &Principal,
        current: &str,
        replacement: &str,
        factor: Option<&str>,
        now: u64,
        vault: &VaultKey,
    ) -> Result<(), StorageError> {
        let verified = self
            .password_snapshot(actor)?
            .verify(current)?
            .replacement(replacement)?;
        self.complete_password_change(verified, factor, now, vault)
    }
    pub fn disable_account(
        &mut self,
        actor: &Principal,
        account_id: &str,
    ) -> Result<(), StorageError> {
        if !actor.is_admin || actor.account_id == account_id {
            return Err(StorageError::Forbidden);
        }
        require_id(account_id)?;
        let tx = self.connection.unchecked_transaction()?;
        self.admin_identity(actor)?;
        if tx.execute("UPDATE accounts SET disabled=1 WHERE id=?1", [account_id])? != 1 {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE management_sessions SET revoked=1 WHERE account_id=?1",
            [account_id],
        )?;
        tx.execute("UPDATE credentials SET revoked=1 WHERE device_id IN (SELECT id FROM devices WHERE account_id=?1)",[account_id])?;
        tx.execute(
            "UPDATE devices SET revoked=1 WHERE account_id=?1",
            [account_id],
        )?;
        tx.execute("UPDATE sessions SET revoked=1 WHERE controller_device_id IN (SELECT id FROM devices WHERE account_id=?1) OR host_device_id IN (SELECT id FROM devices WHERE account_id=?1)",[account_id])?;
        tx.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM sessions WHERE revoked=1)",[])?;
        tx.execute("UPDATE remote_requests SET status='revoked' WHERE controller_device_id IN (SELECT id FROM devices WHERE account_id=?1) OR host_device_id IN (SELECT id FROM devices WHERE account_id=?1)",[account_id])?;
        audit(&tx, "account_disabled", account_id, management(actor))?;
        tx.commit()?;
        Ok(())
    }
    pub fn totp_enabled(&self, actor: &Principal) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT totp_ciphertext IS NOT NULL FROM account_security WHERE account_id=?1",
            [&actor.account_id],
            |r| r.get(0),
        )?)
    }
}
fn zeroize_secret() -> impl std::ops::Deref<Target = [u8; 20]> {
    nestlink_auth::totp_secret()
}
fn normalize_name(name: &str) -> Result<String, StorageError> {
    let name = name.trim().to_lowercase();
    if !(3..=128).contains(&name.len())
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || "._-".contains(c))
    {
        return Err(StorageError::Invalid("invalid account name"));
    }
    Ok(name)
}
fn principal_for(
    tx: &Transaction<'_>,
    account: &str,
    session: &str,
    expires: u64,
) -> Result<Principal, StorageError> {
    Ok(tx.query_row("SELECT a.name,s.is_admin FROM accounts a JOIN account_security s ON s.account_id=a.id WHERE a.id=?1",[account],|r|Ok(Principal{account_id:account.into(),session_id:session.into(),name:r.get(0)?,is_admin:r.get(1)?,access_expires:expires}))?)
}
fn issue_login(tx: &Transaction<'_>, account: &str, now: u64) -> Result<LoginGrant, StorageError> {
    let session = random_id();
    let access = token();
    let refresh = token();
    tx.execute("INSERT INTO management_sessions(id,account_id,access_sha256,refresh_sha256,generation,security_epoch,access_expires,refresh_expires) SELECT ?1,?2,?3,?4,1,security_epoch,?5,?6 FROM deployment WHERE singleton=1",params![session,account,token_hash("access",access.expose()),token_hash("refresh",refresh.expose()),now+ACCESS_SECONDS,now+REFRESH_SECONDS])?;
    Ok(LoginGrant {
        principal: principal_for(tx, account, &session, now + ACCESS_SECONDS)?,
        access_token: access,
        refresh_token: refresh,
        generation: 1,
        refresh_expires: now + REFRESH_SECONDS,
    })
}
fn consume_factor(
    tx: &Transaction<'_>,
    account: &str,
    factor: Option<&str>,
    now: u64,
    vault: &VaultKey,
) -> Result<bool, StorageError> {
    let (ciphertext, last_step): (Option<Vec<u8>>, Option<u64>) = tx.query_row(
        "SELECT totp_ciphertext,totp_last_step FROM account_security WHERE account_id=?1",
        [account],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let Some(ciphertext) = ciphertext else {
        return Ok(false);
    };
    let code = factor.ok_or(StorageError::Unauthorized)?;
    if code.len() == 6 {
        let secret = vault.decrypt(account, &ciphertext)?;
        let step =
            verify_totp(&secret, code, now, last_step).map_err(|_| StorageError::Unauthorized)?;
        tx.execute(
            "UPDATE account_security SET totp_last_step=?1 WHERE account_id=?2",
            params![step, account],
        )?;
        return Ok(false);
    }
    if code.len() != 22 {
        return Err(StorageError::Unauthorized);
    }
    if tx.execute("UPDATE recovery_codes SET consumed=1 WHERE account_id=?1 AND code_sha256=?2 AND consumed=0",params![account,recovery_hash(account,code)])?!=1{return Err(StorageError::Unauthorized);}
    Ok(true)
}
fn audit_recovery(tx: &Transaction<'_>, actor: &Principal, used: bool) -> Result<(), StorageError> {
    if used {
        audit(
            tx,
            "recovery_code_consumed",
            &actor.account_id,
            management(actor),
        )?;
    }
    Ok(())
}
fn replace_recovery(tx: &Transaction<'_>, account: &str) -> Result<Vec<Secret>, StorageError> {
    let codes = recovery_codes();
    tx.execute("DELETE FROM recovery_codes WHERE account_id=?1", [account])?;
    for code in &codes {
        tx.execute(
            "INSERT INTO recovery_codes(account_id,code_sha256) VALUES(?1,?2)",
            params![account, recovery_hash(account, code.expose())],
        )?;
    }
    Ok(codes)
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn totp_and_recovery_are_consumed_once_and_enrollment_revokes_other_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = Store::in_memory(&random_id())?;
        let account = store.bootstrap_admin("admin", "test-only-password")?;
        let vault = VaultKey::from_bytes([8; 32]);
        let dummy = hash_password("dummy-only-password")?;
        let first = store.login("admin", "test-only-password", None, 1000, &vault, &dummy)?;
        let second = store.login("admin", "test-only-password", None, 1000, &vault, &dummy)?;
        store.begin_totp(&first.principal, "test-only-password", None, 1000, &vault)?;
        let encrypted: Vec<u8> = store.connection.query_row(
            "SELECT totp_pending FROM account_security WHERE account_id=?1",
            [&account],
            |r| r.get(0),
        )?;
        let plaintext = vault.decrypt(&account, &encrypted)?;
        let code = nestlink_auth::totp(&plaintext, 1000 / 30)?;
        let recovery = store.confirm_totp(&first.principal, &code, 1000, &vault)?;
        assert_eq!(recovery.len(), 10);
        assert!(
            store
                .authenticate(second.access_token.expose(), 1000)
                .is_err()
        );
        assert!(
            store
                .login(
                    "admin",
                    "test-only-password",
                    Some(&code),
                    1000,
                    &vault,
                    &dummy
                )
                .is_err()
        );
        assert!(
            store
                .login("admin", "test-only-password", None, 1000, &vault, &dummy)
                .is_err()
        );
        let recovered = store.login(
            "admin",
            "test-only-password",
            Some(recovery[0].expose()),
            1000,
            &vault,
            &dummy,
        )?;
        assert!(
            store
                .login(
                    "admin",
                    "test-only-password",
                    Some(recovery[0].expose()),
                    1000,
                    &vault,
                    &dummy
                )
                .is_err()
        );
        let next = nestlink_auth::totp(&plaintext, 1030 / 30)?;
        assert!(
            store
                .login(
                    "admin",
                    "test-only-password",
                    Some(&next),
                    1030,
                    &vault,
                    &dummy
                )
                .is_ok()
        );
        assert!(
            store
                .login(
                    "admin",
                    "test-only-password",
                    Some(&next),
                    1030,
                    &vault,
                    &dummy
                )
                .is_err()
        );
        let page = store.query_audit(
            &first.principal,
            nestlink_protocol::api::AuditQuery {
                security_epoch: store.security_epoch()?,
                after_sequence: 0,
                limit: 100,
            },
            1030,
        )?;
        let used: Vec<_> = page
            .entries
            .iter()
            .filter(|e| e.event == "recovery_code_consumed")
            .collect();
        assert_eq!(used.len(), 1);
        assert_eq!(used[0].actor, management(&recovered.principal));
        let text = serde_json::to_string(&page)?;
        for secret in recovery {
            assert!(!text.contains(secret.expose()));
        }
        assert!(!text.contains(base32_secret(&plaintext).expose()));
        Ok(())
    }
}
