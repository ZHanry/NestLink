use super::{StorageError, Store, audit, require_id};
use crate::auditing::management;
use nestlink_auth::{
    Secret, VaultKey, hash_password, random_id, token, token_hash, verify_password,
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
        let mut statement=self.connection.prepare("SELECT a.id,a.name,s.is_admin,a.disabled FROM accounts a JOIN account_security s ON s.account_id=a.id ORDER BY a.name LIMIT 1000")?;
        Ok(statement
            .query_map([], |r| {
                Ok(AccountView {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    is_admin: r.get(2)?,
                    disabled: r.get(3)?,
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
        self.rotate_login(refresh, generation, now, None)
    }
    pub fn refresh_login_recoverable(
        &mut self,
        refresh: &str,
        generation: u64,
        now: u64,
        vault: &VaultKey,
    ) -> Result<LoginGrant, StorageError> {
        self.rotate_login(refresh, generation, now, Some(vault))
    }
    pub fn restore_browser_login(
        &mut self,
        session: &str,
        refresh: &str,
        now: u64,
        vault: &VaultKey,
    ) -> Result<LoginGrant, StorageError> {
        require_id(session)?;
        let generation: u64 = self
            .connection
            .query_row(
                "SELECT generation FROM management_sessions WHERE id=?1 AND refresh_sha256=?2 UNION ALL SELECT previous_generation FROM management_refresh_receipts WHERE session_id=?1 AND previous_sha256=?2 LIMIT 1",
                params![session, token_hash("refresh", refresh)],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::Unauthorized)?;
        self.refresh_login_recoverable(refresh, generation, now, vault)
    }
    fn rotate_login(
        &mut self,
        refresh: &str,
        generation: u64,
        now: u64,
        vault: Option<&VaultKey>,
    ) -> Result<LoginGrant, StorageError> {
        if refresh.len() != 43 {
            return Err(StorageError::Unauthorized);
        }
        let previous_hash = token_hash("refresh", refresh);
        let tx = self.connection.transaction()?;
        let record:Option<(String,String)>=tx.query_row("SELECT s.id,s.account_id FROM management_sessions s JOIN accounts a ON a.id=s.account_id JOIN deployment d ON d.singleton=1 WHERE s.refresh_sha256=?1 AND s.generation=?2 AND s.refresh_expires>?3 AND s.revoked=0 AND a.disabled=0 AND s.security_epoch=d.security_epoch",params![token_hash("refresh",refresh),generation,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((session_id, account_id)) = record else {
            if let Some(vault) = vault {
                let receipt: Option<(String, Vec<u8>)> = tx.query_row(
                    "SELECT s.id,r.response_ciphertext FROM management_refresh_receipts r JOIN management_sessions s ON s.id=r.session_id JOIN accounts a ON a.id=s.account_id JOIN deployment d ON d.singleton=1 WHERE r.previous_sha256=?1 AND r.previous_generation=?2 AND r.expires>?3 AND s.generation=?2+1 AND s.refresh_expires>?3 AND s.revoked=0 AND a.disabled=0 AND s.security_epoch=d.security_epoch",
                    params![previous_hash, generation, now], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
                if let Some((session, cipher)) = receipt {
                    let plain = vault.decrypt_management(&session, &cipher)?;
                    let response: nestlink_protocol::api::LoginResponse =
                        serde_json::from_slice(&plain)?;
                    return Ok(LoginGrant {
                        principal: response.principal,
                        access_token: Secret::from_text(response.access_token),
                        refresh_token: Secret::from_text(response.refresh_token),
                        generation: response.generation,
                        refresh_expires: response.refresh_expires,
                    });
                }
            }
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
        if let Some(vault) = vault {
            let plain = zeroize::Zeroizing::new(serde_json::to_vec(
                &nestlink_protocol::api::LoginResponse {
                    principal: principal.clone(),
                    access_token: access.expose().into(),
                    refresh_token: refresh.expose().into(),
                    generation: next,
                    refresh_expires: now + REFRESH_SECONDS,
                },
            )?);
            let cipher = vault.encrypt_management(&session_id, &plain)?;
            tx.execute(
                "DELETE FROM management_refresh_receipts WHERE expires<=?1",
                [now],
            )?;
            tx.execute("INSERT INTO management_refresh_receipts VALUES(?1,?2,?3,?4,?5) ON CONFLICT(session_id) DO UPDATE SET previous_sha256=excluded.previous_sha256,previous_generation=excluded.previous_generation,response_ciphertext=excluded.response_ciphertext,expires=excluded.expires",
                params![session_id, previous_hash, generation, cipher, now + 30])?;
        }
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
        let tx =
            Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        self.admin_identity(actor)?;
        let owns_active_space: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_space_members m
             JOIN network_spaces s ON s.space_id=m.space_id
             JOIN network_authorities a ON a.space_id=s.space_id
             JOIN deployment d ON d.singleton=1
             WHERE m.account_id=?1 AND m.role='owner' AND m.revoked=0
             AND s.archived=0 AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch)",
            [account_id],
            |r| r.get(0),
        )?;
        if owns_active_space {
            // Persist the refusal without changing ownership or disabling the
            // account. The owner must first transfer or archive their spaces.
            audit(
                &tx,
                "account_disable_blocked_space_owner",
                account_id,
                management(actor),
            )?;
            tx.commit()?;
            return Err(StorageError::Conflict);
        }
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

#[cfg(test)]
mod password_only_migration {
    use super::*;

    #[test]
    fn upgrading_legacy_factor_state_preserves_passwords_and_retires_logins()
    -> Result<(), StorageError> {
        let deployment = random_id();
        let mut store = Store::in_memory(&deployment)?;
        let vault = VaultKey::from_bytes(nestlink_auth::random_bytes());
        let dummy = hash_password("migration-dummy-password")?;
        let account = store.bootstrap_admin("administrator", "migration-account-password")?;
        let old = store.login(
            "administrator",
            "migration-account-password",
            None,
            1000,
            &vault,
            &dummy,
        )?;
        store.connection.execute("UPDATE account_security SET totp_ciphertext=x'0102',totp_pending=x'0304',totp_pending_expires=2000,totp_last_step=32", [])?;
        store.connection.execute(
            "INSERT INTO recovery_codes(account_id,code_sha256) VALUES(?1,zeroblob(32))",
            [&account],
        )?;
        store
            .connection
            .execute("DROP TABLE browser_host_readiness", [])?;
        // Reconstruct v20 without objects introduced by later migrations.
        store.connection.execute_batch(
            "DROP VIEW all_relay_capacity; DROP TABLE network_topology_changes; DROP TABLE network_topology_cursors; DROP TABLE network_topology_heads; DROP TABLE network_topology_publishers; DROP TABLE node_relay_attributes; DROP TABLE space_service_rules; DROP TABLE space_service_bindings; DROP TABLE network_space_audit; DROP TABLE network_space_invitations; DROP TABLE network_space_members; DROP TABLE network_spaces; DROP TABLE network_remote_relays; DROP TABLE network_remote_paths; DROP TABLE network_grant_revocations; DROP TABLE network_grants; DROP TABLE network_memberships; DROP TABLE network_authority_key_history; DROP TABLE network_authorities; DROP TABLE remote_media_scopes; DROP TABLE device_media_announcements; DROP TABLE management_refresh_receipts; DROP INDEX remote_pending_inbox;",
        )?;
        store.connection.pragma_update(None, "user_version", 20)?;
        let Store { connection, .. } = store;
        let mut migrated = Store::initialize(connection, &deployment)?;
        let cleared: bool = migrated.connection.query_row("SELECT totp_ciphertext IS NULL AND totp_pending IS NULL AND totp_pending_expires IS NULL AND totp_last_step IS NULL FROM account_security", [], |row| row.get(0))?;
        assert!(cleared);
        assert_eq!(
            migrated
                .connection
                .query_row("SELECT count(*) FROM recovery_codes", [], |row| row
                    .get::<_, i64>(0))?,
            0
        );
        assert!(
            migrated
                .authenticate(old.access_token.expose(), 1001)
                .is_err()
        );
        let fresh = migrated.login(
            "administrator",
            "migration-account-password",
            None,
            1001,
            &vault,
            &dummy,
        )?;
        assert_eq!(fresh.principal.account_id, account);
        assert!(
            migrated
                .login(
                    "administrator",
                    "incorrect-password",
                    None,
                    1002,
                    &vault,
                    &dummy
                )
                .is_err()
        );
        Ok(())
    }
}
