//! Product space delegation. Membership never issues a remote/session/service permit.
use crate::{StorageError, Store, accounts::Principal, audit, auditing, require_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{random_id, token, token_hash};
use nestlink_protocol::{network::SpaceRole, spaces::*};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
pub mod service_publication;

const MAX_SPACES: u64 = 256;
const MAX_MEMBERS: u64 = 4096;
const MAX_INVITATIONS: u64 = 4096;
const MAX_INVITATION_MS: u64 = 24 * 60 * 60 * 1000;
type SpaceRow = (String, bool, u64, u64, String, u64, u64, Vec<u8>, String);

fn role_name(role: SpaceRole) -> &'static str {
    match role {
        SpaceRole::Owner => "owner",
        SpaceRole::Admin => "admin",
        SpaceRole::Member => "member",
        SpaceRole::Guest => "guest",
    }
}

fn parse_role(role: &str) -> Result<SpaceRole, StorageError> {
    match role {
        "owner" => Ok(SpaceRole::Owner),
        "admin" => Ok(SpaceRole::Admin),
        "member" => Ok(SpaceRole::Member),
        "guest" => Ok(SpaceRole::Guest),
        _ => Err(StorageError::Invalid("invalid stored space role")),
    }
}

fn management(role: SpaceRole) -> bool {
    matches!(role, SpaceRole::Owner | SpaceRole::Admin)
}

fn delegated(actor: SpaceRole, target: SpaceRole, desired: SpaceRole) -> bool {
    actor == SpaceRole::Owner
        || (actor == SpaceRole::Admin
            && matches!(target, SpaceRole::Member | SpaceRole::Guest)
            && matches!(desired, SpaceRole::Member | SpaceRole::Guest))
}

fn clock(now: u64) -> Result<(), StorageError> {
    if now == 0 || now > i64::MAX as u64 {
        return Err(StorageError::Invalid("invalid space clock"));
    }
    Ok(())
}

fn read_space(
    connection: &Connection,
    actor: &Principal,
    id: &str,
    now: u64,
) -> Result<SpaceView, StorageError> {
    require_id(id)?;
    clock(now)?;
    let row: Option<SpaceRow> = connection.query_row(
        "SELECT s.name,s.archived,a.revision,a.policy_epoch,m.role,m.member_epoch,a.last_observed_ms,a.public_key,d.id
         FROM network_spaces s JOIN network_authorities a ON a.space_id=s.space_id
         JOIN network_space_members m ON m.space_id=s.space_id JOIN deployment d ON d.singleton=1
         WHERE s.space_id=?1 AND m.account_id=?2 AND m.revoked=0
         AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch",
        params![id, actor.account_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
    ).optional()?;
    let (name, archived, revision, policy_epoch, role, member_epoch, observed, key, deployment_id) =
        row.ok_or(StorageError::Forbidden)?;
    if now < observed {
        return Err(StorageError::Conflict);
    }
    Ok(SpaceView {
        space_id: id.into(),
        deployment_id,
        authority_public_key: URL_SAFE_NO_PAD.encode(key),
        name,
        archived,
        revision,
        policy_epoch,
        observed_at_unix_ms: now,
        role: parse_role(&role)?,
        member_epoch,
    })
}

fn writable(space: &SpaceView, expected: u64) -> Result<(), StorageError> {
    if space.archived {
        return Err(StorageError::Forbidden);
    }
    if space.revision != expected {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

fn advance(tx: &Transaction<'_>, space: &SpaceView, now: u64) -> Result<(), StorageError> {
    if tx.execute("UPDATE network_authorities SET revision=revision+1,policy_epoch=policy_epoch+1,last_observed_ms=?1
        WHERE space_id=?2 AND revision=?3 AND revision<9223372036854775807 AND policy_epoch<9223372036854775807",
        params![now, space.space_id, space.revision])? != 1 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub(crate) fn event(
    tx: &Transaction<'_>,
    actor: &Principal,
    space: &str,
    action: &str,
    target: &str,
    now: u64,
) -> Result<(), StorageError> {
    audit(tx, action, target, auditing::management(actor))?;
    tx.execute(
        "INSERT INTO network_space_audit(sequence,space_id,action,target_id,actor_account_id,at_ms)
        SELECT high_watermark,?1,?2,?3,?4,?5 FROM audit_settings WHERE singleton=1",
        params![space, action, target, actor.account_id, now],
    )?;
    Ok(())
}

fn member_record(
    connection: &Connection,
    space: &str,
    account: &str,
) -> Result<(SpaceRole, u64, bool, bool), StorageError> {
    require_id(account)?;
    let row: Option<(String, u64, bool, bool)> = connection.query_row(
        "SELECT m.role,m.member_epoch,m.revoked=0,a.disabled=0 FROM network_space_members m JOIN accounts a ON a.id=m.account_id WHERE m.space_id=?1 AND m.account_id=?2",
        params![space, account], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional()?;
    let (role, epoch, unrevoked, enabled) = row.ok_or(StorageError::Forbidden)?;
    Ok((parse_role(&role)?, epoch, unrevoked, enabled))
}

fn member(
    connection: &Connection,
    space: &str,
    account: &str,
) -> Result<(SpaceRole, u64, bool), StorageError> {
    let (role, epoch, unrevoked, enabled) = member_record(connection, space, account)?;
    Ok((role, epoch, unrevoked && enabled))
}

fn account_capacity(connection: &Connection, account: &str) -> Result<(), StorageError> {
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM network_space_members WHERE account_id=?1 AND revoked=0",
        [account],
        |r| r.get(0),
    )?;
    if count >= MAX_SPACES {
        return Err(StorageError::RateLimited);
    }
    Ok(())
}

fn update_device_roles(
    tx: &Transaction<'_>,
    space: &str,
    account: &str,
    role: SpaceRole,
    revoke: bool,
) -> Result<(), StorageError> {
    tx.execute("UPDATE network_memberships SET role=?1,membership_epoch=membership_epoch+1,revoked=MAX(revoked,?2)
        WHERE space_id=?3 AND installation_id IN (SELECT id FROM devices WHERE account_id=?4)",
        params![role_name(role), revoke, space, account])?;
    Ok(())
}

impl Store {
    pub fn create_space(
        &mut self,
        actor: &Principal,
        request: SpaceCreateRequest,
        authority_key: [u8; 32],
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        clock(now)?;
        let name = request.name.trim();
        if name.is_empty()
            || name.chars().count() > 80
            || name.chars().any(char::is_control)
            || authority_key == [0; 32]
        {
            return Err(StorageError::Invalid("invalid space name or authority"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        account_capacity(&tx, &actor.account_id)?;
        let id = random_id();
        tx.execute("INSERT INTO network_authorities(space_id,public_key,revision,policy_epoch,security_epoch,last_observed_ms) VALUES(?1,?2,1,1,?3,?4)",
            params![id, authority_key.as_slice(), self.security_epoch()?, now])?;
        tx.execute("INSERT INTO network_authority_key_history(space_id,public_key,signing_generation,activated_policy_epoch,activated_at_ms) VALUES(?1,?2,0,1,?3)",params![id,authority_key.as_slice(),now])?;
        tx.execute(
            "INSERT INTO network_spaces(space_id,name) VALUES(?1,?2)",
            params![id, name],
        )?;
        tx.execute("INSERT INTO network_space_members(space_id,account_id,role,member_epoch) VALUES(?1,?2,'owner',1)", params![id, actor.account_id])?;
        event(&tx, actor, &id, "network_space_created", &id, now)?;
        let view = read_space(&tx, actor, &id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn spaces(&self, actor: &Principal, now: u64) -> Result<Vec<SpaceView>, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now / 1000)?;
        let mut query = tx.prepare("SELECT m.space_id FROM network_space_members m JOIN network_authorities a ON a.space_id=m.space_id JOIN deployment d ON d.singleton=1 WHERE m.account_id=?1 AND m.revoked=0 AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch ORDER BY m.space_id LIMIT ?2")?;
        let ids = query
            .query_map(params![actor.account_id, MAX_SPACES + 1], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() as u64 > MAX_SPACES {
            return Err(StorageError::RateLimited);
        }
        ids.iter()
            .map(|id| read_space(&tx, actor, id, now))
            .collect()
    }

    pub fn space_details(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<SpaceDetails, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        let admin = management(space.role);
        let mut query = tx.prepare("SELECT m.account_id,a.name,m.role,m.member_epoch,(m.revoked=0 AND a.disabled=0)
            FROM network_space_members m JOIN accounts a ON a.id=m.account_id WHERE m.space_id=?1 AND (?2 OR m.account_id=?3) ORDER BY m.account_id LIMIT ?4")?;
        let rows = query.query_map(params![id, admin, actor.account_id, MAX_MEMBERS + 1], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (account_id, name, role, member_epoch, active) = row?;
            members.push(SpaceMemberView {
                account_id,
                name,
                role: parse_role(&role)?,
                member_epoch,
                active,
            });
        }
        if members.len() as u64 > MAX_MEMBERS {
            return Err(StorageError::RateLimited);
        }
        let mut query = tx.prepare("SELECT m.installation_id,d.account_id,COALESCE(x.name,d.id),m.role,m.membership_epoch,
            (m.revoked=0 AND d.revoked=0 AND a.disabled=0 AND (d.expires_at IS NULL OR d.expires_at>?4) AND x.public_key=m.public_key AND u.revoked=0 AND u.role=m.role)
            FROM network_memberships m JOIN devices d ON d.id=m.installation_id JOIN accounts a ON a.id=d.account_id
            LEFT JOIN device_details x ON x.device_id=d.id LEFT JOIN network_space_members u ON u.space_id=m.space_id AND u.account_id=d.account_id
            WHERE m.space_id=?1 AND (?2 OR d.account_id=?3) ORDER BY m.installation_id LIMIT ?5")?;
        let rows = query.query_map(
            params![id, admin, actor.account_id, now / 1000, MAX_MEMBERS + 1],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, Option<bool>>(5)?,
                ))
            },
        )?;
        let mut devices = Vec::new();
        for row in rows {
            let (installation_id, account_id, name, role, membership_epoch, active) = row?;
            devices.push(SpaceDeviceView {
                installation_id,
                account_id,
                name,
                role: parse_role(&role)?,
                membership_epoch,
                active: active.unwrap_or(false),
            });
        }
        if devices.len() as u64 > MAX_MEMBERS {
            return Err(StorageError::RateLimited);
        }
        let mut invitations = Vec::new();
        if admin {
            let mut query = tx.prepare("SELECT invitation_id,role,target_account_id,expires_at_ms,revoked,(consumed_by IS NOT NULL) FROM network_space_invitations WHERE space_id=?1 ORDER BY invitation_id LIMIT ?2")?;
            for row in query.query_map(params![id, MAX_INVITATIONS + 1], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, bool>(5)?,
                ))
            })? {
                let (invitation_id, role, target_account_id, expires_at_unix_ms, revoked, consumed) =
                    row?;
                invitations.push(SpaceInvitationView {
                    invitation_id,
                    role: parse_role(&role)?,
                    target_account_id,
                    expires_at_unix_ms,
                    revoked,
                    consumed,
                });
            }
        }
        if invitations.len() as u64 > MAX_INVITATIONS {
            return Err(StorageError::RateLimited);
        }
        Ok(SpaceDetails {
            space,
            members,
            devices,
            invitations,
        })
    }

    pub fn archive_space(
        &mut self,
        actor: &Principal,
        id: &str,
        request: SpaceRevisionRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        if space.role != SpaceRole::Owner {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE network_spaces SET archived=1 WHERE space_id=?1",
            [id],
        )?;
        tx.execute("UPDATE network_memberships SET revoked=1,membership_epoch=membership_epoch+1 WHERE space_id=?1", [id])?;
        tx.execute(
            "UPDATE network_space_invitations SET revoked=1 WHERE space_id=?1",
            [id],
        )?;
        advance(&tx, &space, now)?;
        service_publication::stop_publications(&tx, id, None, None)?;
        event(&tx, actor, id, "network_space_archived", id, now)?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn update_space_member(
        &mut self,
        actor: &Principal,
        id: &str,
        account: &str,
        request: SpaceMemberUpdate,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        let (old_role, epoch, active) = member(&tx, id, account)?;
        if !active || !delegated(space.role, old_role, request.role) || old_role == SpaceRole::Owner
        {
            return Err(StorageError::Forbidden);
        }
        if epoch != request.expected_member_epoch {
            return Err(StorageError::Conflict);
        }
        if request.role == SpaceRole::Owner {
            tx.execute("UPDATE network_space_members SET role='admin',member_epoch=member_epoch+1 WHERE space_id=?1 AND account_id=?2", params![id, actor.account_id])?;
            update_device_roles(&tx, id, &actor.account_id, SpaceRole::Admin, false)?;
            service_publication::stop_publications(&tx, id, Some(&actor.account_id), None)?;
        }
        tx.execute("UPDATE network_space_members SET role=?1,member_epoch=member_epoch+1 WHERE space_id=?2 AND account_id=?3", params![role_name(request.role), id, account])?;
        update_device_roles(&tx, id, account, request.role, false)?;
        service_publication::stop_publications(&tx, id, Some(account), None)?;
        advance(&tx, &space, now)?;
        event(&tx, actor, id, "network_space_member_changed", account, now)?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn remove_space_member(
        &mut self,
        actor: &Principal,
        id: &str,
        account: &str,
        request: SpaceMemberRemoval,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        // A disabled account cannot act, but its owner must still be able to
        // remove the durable membership and revoke every attached device.
        let (role, epoch, active, _) = member_record(&tx, id, account)?;
        if !active || role == SpaceRole::Owner || !delegated(space.role, role, role) {
            return Err(StorageError::Forbidden);
        }
        if epoch != request.expected_member_epoch {
            return Err(StorageError::Conflict);
        }
        tx.execute("UPDATE network_space_members SET revoked=1,member_epoch=member_epoch+1 WHERE space_id=?1 AND account_id=?2", params![id, account])?;
        update_device_roles(&tx, id, account, role, true)?;
        service_publication::stop_publications(&tx, id, Some(account), None)?;
        advance(&tx, &space, now)?;
        event(&tx, actor, id, "network_space_member_removed", account, now)?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn join_space_device(
        &mut self,
        actor: &Principal,
        id: &str,
        request: SpaceDeviceJoin,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(&request.installation_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        let device = self.device_record_at(&request.installation_id, now / 1000)?;
        let (target_role, _, active) = member(&tx, id, &device.account)?;
        if !active
            || (device.account != actor.account_id
                && !delegated(space.role, target_role, target_role))
        {
            return Err(StorageError::Forbidden);
        }
        let old: Option<u64> = tx.query_row("SELECT membership_epoch FROM network_memberships WHERE space_id=?1 AND installation_id=?2", params![id, request.installation_id], |r| r.get(0)).optional()?;
        if old.unwrap_or(0) != request.expected_membership_epoch {
            return Err(StorageError::Conflict);
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM network_memberships WHERE space_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if old.is_none() && count >= MAX_MEMBERS {
            return Err(StorageError::RateLimited);
        }
        let key_hash: Vec<u8> = tx.query_row(
            "SELECT key_sha256 FROM devices WHERE id=?1",
            [&request.installation_id],
            |r| r.get(0),
        )?;
        if key_hash != nestlink_identity::digest(&device.public_key) {
            return Err(StorageError::Forbidden);
        }
        let epoch = request
            .expected_membership_epoch
            .checked_add(1)
            .filter(|epoch| *epoch <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        tx.execute("INSERT INTO network_memberships(space_id,installation_id,public_key,membership_epoch,role,revoked) VALUES(?1,?2,?3,?4,?5,0)
            ON CONFLICT(space_id,installation_id) DO UPDATE SET public_key=excluded.public_key,membership_epoch=excluded.membership_epoch,role=excluded.role,revoked=0",
            params![id, request.installation_id, device.public_key.as_slice(), epoch, role_name(target_role)])?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            id,
            "network_space_device_joined",
            &request.installation_id,
            now,
        )?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn remove_space_device(
        &mut self,
        actor: &Principal,
        id: &str,
        installation: &str,
        request: SpaceDeviceRemoval,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(installation)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        let target: Option<(String, u64)> = tx.query_row("SELECT d.account_id,m.membership_epoch FROM network_memberships m JOIN devices d ON d.id=m.installation_id WHERE m.space_id=?1 AND m.installation_id=?2", params![id, installation], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let (account, epoch) = target.ok_or(StorageError::Forbidden)?;
        let (role, _, _) = member(&tx, id, &account)?;
        if account != actor.account_id && !delegated(space.role, role, role) {
            return Err(StorageError::Forbidden);
        }
        if epoch != request.expected_membership_epoch {
            return Err(StorageError::Conflict);
        }
        tx.execute("UPDATE network_memberships SET revoked=1,membership_epoch=membership_epoch+1 WHERE space_id=?1 AND installation_id=?2", params![id, installation])?;
        service_publication::stop_publications(&tx, id, None, Some(installation))?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            id,
            "network_space_device_removed",
            installation,
            now,
        )?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn invite_to_space(
        &mut self,
        actor: &Principal,
        id: &str,
        request: SpaceInvitationRequest,
        now: u64,
    ) -> Result<SpaceInvitationIssued, StorageError> {
        if let Some(account) = &request.target_account_id {
            require_id(account)?;
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        if request.role == SpaceRole::Owner || !delegated(space.role, request.role, request.role) {
            return Err(StorageError::Forbidden);
        }
        if request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms > i64::MAX as u64
            || request.expires_at_unix_ms - now > MAX_INVITATION_MS
        {
            return Err(StorageError::Invalid(
                "invitation must expire within one day",
            ));
        }
        if let Some(account) = &request.target_account_id {
            let active: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1 AND disabled=0)",
                [account],
                |r| r.get(0),
            )?;
            if !active {
                return Err(StorageError::Forbidden);
            }
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM network_space_invitations WHERE space_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if count >= MAX_INVITATIONS {
            return Err(StorageError::RateLimited);
        }
        let invitation_id = random_id();
        let secret = token();
        tx.execute("INSERT INTO network_space_invitations(space_id,invitation_id,token_hash,role,target_account_id,issuer_account_id,issuer_member_epoch,expires_at_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![id, invitation_id, token_hash("space-invitation", secret.expose()).as_slice(), role_name(request.role), request.target_account_id, actor.account_id, space.member_epoch, request.expires_at_unix_ms])?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            id,
            "network_space_invitation_created",
            &invitation_id,
            now,
        )?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(SpaceInvitationIssued {
            invitation: SpaceInvitationView {
                invitation_id,
                role: request.role,
                target_account_id: request.target_account_id,
                expires_at_unix_ms: request.expires_at_unix_ms,
                revoked: false,
                consumed: false,
            },
            token: secret.expose().into(),
            space: view,
        })
    }

    pub fn revoke_space_invitation(
        &mut self,
        actor: &Principal,
        id: &str,
        invitation: &str,
        request: SpaceRevisionRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(invitation)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        writable(&space, request.expected_revision)?;
        let role: Option<String> = tx
            .query_row(
                "SELECT role FROM network_space_invitations WHERE space_id=?1 AND invitation_id=?2",
                params![id, invitation],
                |r| r.get(0),
            )
            .optional()?;
        let role = parse_role(&role.ok_or(StorageError::Forbidden)?)?;
        if !delegated(space.role, role, role) {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE network_space_invitations SET revoked=1 WHERE space_id=?1 AND invitation_id=?2",
            params![id, invitation],
        )?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            id,
            "network_space_invitation_revoked",
            invitation,
            now,
        )?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn accept_space_invitation(
        &mut self,
        actor: &Principal,
        id: &str,
        invitation: &str,
        request: SpaceInvitationAcceptance,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(id)?;
        require_id(invitation)?;
        clock(now)?;
        if request.token.len() != 43 {
            return Err(StorageError::Forbidden);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let row: Option<(String, Option<String>, String, u64, u64)> = tx.query_row(
            "SELECT i.role,i.target_account_id,i.issuer_account_id,i.issuer_member_epoch,a.last_observed_ms
            FROM network_space_invitations i JOIN network_spaces s ON s.space_id=i.space_id
            JOIN network_authorities a ON a.space_id=s.space_id JOIN deployment d ON d.singleton=1
            WHERE i.space_id=?1 AND i.invitation_id=?2 AND i.token_hash=?3 AND i.revoked=0 AND i.consumed_by IS NULL AND i.expires_at_ms>?4
            AND s.archived=0 AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch",
            params![id, invitation, token_hash("space-invitation", &request.token).as_slice(), now],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional()?;
        let (role, target, issuer, issuer_epoch, last) = row.ok_or(StorageError::Forbidden)?;
        if now < last {
            return Err(StorageError::Conflict);
        }
        if target
            .as_ref()
            .is_some_and(|target| target != &actor.account_id)
        {
            return Err(StorageError::Forbidden);
        }
        let role = parse_role(&role)?;
        let (issuer_role, current_epoch, active) = member(&tx, id, &issuer)?;
        if !active || issuer_epoch != current_epoch || !delegated(issuer_role, role, role) {
            return Err(StorageError::Forbidden);
        }
        let old: Option<(u64, bool)> = tx.query_row("SELECT member_epoch,revoked FROM network_space_members WHERE space_id=?1 AND account_id=?2", params![id, actor.account_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        if old.is_some_and(|(_, revoked)| !revoked) {
            return Err(StorageError::Conflict);
        }
        account_capacity(&tx, &actor.account_id)?;
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM network_space_members WHERE space_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if old.is_none() && count >= MAX_MEMBERS {
            return Err(StorageError::RateLimited);
        }
        let epoch = old
            .map_or(0, |(epoch, _)| epoch)
            .checked_add(1)
            .filter(|epoch| *epoch <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        tx.execute("INSERT INTO network_space_members(space_id,account_id,role,member_epoch) VALUES(?1,?2,?3,?4)
            ON CONFLICT(space_id,account_id) DO UPDATE SET role=excluded.role,member_epoch=excluded.member_epoch,revoked=0", params![id, actor.account_id, role_name(role), epoch])?;
        tx.execute("UPDATE network_space_invitations SET consumed_by=?1 WHERE space_id=?2 AND invitation_id=?3", params![actor.account_id, id, invitation])?;
        // A rejoin changes account membership only; old devices stay revoked.
        let view = read_space(&tx, actor, id, now)?;
        advance(&tx, &view, now)?;
        event(
            &tx,
            actor,
            id,
            "network_space_invitation_accepted",
            invitation,
            now,
        )?;
        let view = read_space(&tx, actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn space_audit(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<Vec<SpaceAuditEntry>, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, id, now)?;
        if !management(space.role) {
            return Err(StorageError::Forbidden);
        }
        let mut query = tx.prepare("SELECT sequence,action,target_id,actor_account_id,at_ms FROM network_space_audit WHERE space_id=?1 ORDER BY sequence DESC LIMIT 100")?;
        let entries = query
            .query_map([id], |r| {
                Ok(SpaceAuditEntry {
                    sequence: r.get(0)?,
                    action: r.get(1)?,
                    target_id: r.get(2)?,
                    actor_account_id: r.get(3)?,
                    at_unix_ms: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }
}
