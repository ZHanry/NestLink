use super::{StorageError, Store, audit, require_id};
use crate::{accounts::Principal, control::parse_mode};
use nestlink_policy::PeerPathMode;
pub use nestlink_protocol::api::PathLimit;
use rusqlite::{OptionalExtension, params};
impl Store {
    pub(crate) fn path_limit(&self, scope: &str, id: &str) -> Result<PeerPathMode, StorageError> {
        let mode: Option<String> = self
            .connection
            .query_row(
                "SELECT path_mode FROM path_limits WHERE scope=?1 AND resource_id=?2",
                params![scope, id],
                |r| r.get(0),
            )
            .optional()?;
        mode.as_deref()
            .map(parse_mode)
            .transpose()
            .map(|v| v.unwrap_or(PeerPathMode::DirectPreferred))
    }
    pub fn path_limits(&self, actor: &Principal) -> Result<Vec<PathLimit>, StorageError> {
        self.admin_identity(actor)?;
        let mut statement=self.connection.prepare("SELECT scope,resource_id,path_mode FROM path_limits ORDER BY scope,resource_id LIMIT 4096")?;
        Ok(statement
            .query_map([], |r| {
                Ok(PathLimit {
                    scope: r.get(0)?,
                    resource_id: r.get(1)?,
                    path_mode: r.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }
    pub fn set_path_limit(
        &mut self,
        actor: &Principal,
        scope: &str,
        id: &str,
        mode: &str,
        expected_revision: u64,
    ) -> Result<u64, StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        require_id(id)?;
        parse_mode(mode)?;
        let query = match scope {
            "account" => "SELECT count(*) FROM accounts WHERE id=?1 AND disabled=0",
            "device" | "resource" => "SELECT count(*) FROM devices WHERE id=?1 AND revoked=0",
            "login_session" => "SELECT count(*) FROM management_sessions WHERE id=?1 AND revoked=0",
            _ => return Err(StorageError::Invalid("unknown path policy scope")),
        };
        let count: i64 = self.connection.query_row(query, [id], |r| r.get(0))?;
        if count != 1 {
            return Err(StorageError::Forbidden);
        }
        let next = expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let tx = self.connection.unchecked_transaction()?;
        self.admin_identity(actor)?;
        if tx.execute(
            "UPDATE deployment SET policy_revision=?1 WHERE singleton=1 AND policy_revision=?2",
            params![next, expected_revision],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        tx.execute("INSERT INTO path_limits VALUES(?1,?2,?3) ON CONFLICT(scope,resource_id) DO UPDATE SET path_mode=excluded.path_mode",params![scope,id,mode])?;
        tx.execute("UPDATE sessions SET revoked=1", [])?;
        tx.execute("UPDATE leases SET revoked=1", [])?;
        tx.execute(
            "UPDATE remote_requests SET status='revoked' WHERE status IN ('pending','approved')",
            [],
        )?;
        audit(
            &tx,
            "path_limit_changed",
            &format!("{scope}/{id}"),
            crate::auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(next)
    }
}
