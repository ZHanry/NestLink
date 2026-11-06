use crate::{StorageError, Store, accounts::Principal, audit, auditing::management};
use nestlink_protocol::api::LoginSessionView;
use rusqlite::params;

impl Store {
    pub(super) fn touch_login_metadata(&self, session: &str, now: u64) -> Result<(), StorageError> {
        self.connection.execute("UPDATE management_login_metadata SET last_active_at=?1 WHERE session_id=?2 AND last_active_at<?3",params![now,session,now.saturating_sub(60)])?;
        Ok(())
    }
    /// Bounded display metadata. These strings never confer device or network authority.
    pub fn record_login_metadata(
        &self,
        actor: &Principal,
        name: &str,
        client: &str,
        platform: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        self.validate_access(actor, now)?;
        if [name, client, platform]
            .iter()
            .any(|v| v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err(StorageError::Invalid("invalid login display metadata"));
        }
        self.connection.execute("INSERT INTO management_login_metadata(session_id,device_name,client,platform,created_at,last_active_at) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(session_id) DO NOTHING",params![actor.session_id,name,client,platform,now])?;
        Ok(())
    }

    pub fn login_sessions(
        &self,
        actor: &Principal,
        now: u64,
    ) -> Result<Vec<LoginSessionView>, StorageError> {
        self.validate_access(actor, now)?;
        self.touch_login_metadata(&actor.session_id, now)?;
        let mut statement=self.connection.prepare("SELECT s.id,m.device_name,m.client,m.platform,m.created_at,m.last_active_at,s.refresh_expires FROM management_sessions s JOIN deployment d ON d.singleton=1 LEFT JOIN management_login_metadata m ON m.session_id=s.id WHERE s.account_id=?1 AND s.revoked=0 AND s.refresh_expires>?2 AND s.security_epoch=d.security_epoch ORDER BY (s.id=?3) DESC,coalesce(m.last_active_at,0) DESC,s.id LIMIT 100")?;
        let entries = statement
            .query_map(params![actor.account_id, now, actor.session_id], |row| {
                let session_id: String = row.get(0)?;
                Ok(LoginSessionView {
                    current: session_id == actor.session_id,
                    session_id,
                    device_name: row.get(1)?,
                    client: row.get(2)?,
                    platform: row.get(3)?,
                    created_at: row.get(4)?,
                    last_active_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// Revoke only a login owned by this account. Never revoke a device identity or space member.
    pub fn revoke_login_session(
        &mut self,
        actor: &Principal,
        session: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        self.validate_access(actor, now)?;
        if !nestlink_protocol::valid_id(session) {
            return Err(StorageError::Invalid("invalid login session"));
        }
        let tx = self.connection.transaction()?;
        let count = tx.execute(
            "UPDATE management_sessions SET revoked=1 WHERE id=?1 AND account_id=?2 AND revoked=0",
            params![session, actor.account_id],
        )?;
        if count != 1 {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE remote_requests SET status='revoked' WHERE management_session_id=?1",
            [session],
        )?;
        tx.execute("UPDATE sessions SET revoked=1 WHERE id IN (SELECT id FROM remote_requests WHERE management_session_id=?1)",[session])?;
        tx.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM sessions WHERE revoked=1)",[])?;
        audit(&tx, "login_revoked", session, management(actor))?;
        tx.commit()?;
        Ok(())
    }
}
