//! Durable online enable/review/reserve/consume for independent offline bundles.
//! Every mutation intersects the original private-service or remote authority in the
//! same SQLite IMMEDIATE transaction. Unused promises are never refunded.
use super::*;
use crate::services::private::OfflinePrivateAuthority;
use nestlink_auth::{random_bytes, random_id};
use nestlink_identity::{offline::*, verify_device_action};
use nestlink_protocol::offline::{management::*, *};

const MAX_HISTORY: u64 = 4096;
mod remote;
enum OriginalBusiness {
    Private(OfflinePrivateAuthority),
    Remote(nestlink_protocol::PermitClaims),
}
impl OriginalBusiness {
    fn table(&self) -> &'static str {
        match self { Self::Private(_) => "offline_bundles", Self::Remote(_) => "offline_remote_bundles" }
    }
}
struct Row {
    claims: OfflineGrantBundleClaims,
    account: String,
    login: String,
    digest: [u8; 32],
    authority: [u8; 32],
    approvals: [Option<OfflineEndpointApproval>; 2],
    challenges: [[u8; 32]; 2],
    consumed: [bool; 2],
    signed: Option<SignedOfflineGrantBundle>,
    revoked: bool,
    business_authority: OriginalBusiness,
}
fn settings(connection: &Connection, space: &str) -> Result<OfflinePolicyView, StorageError> {
    Ok(connection
        .query_row(
            "SELECT revision,enabled,revocation_epoch FROM offline_settings WHERE space_id=?1",
            [space],
            |r| {
                Ok(OfflinePolicyView {
                    revision: r.get(0)?,
                    enabled: r.get(1)?,
                    highest_revocation_epoch: r.get(2)?,
                })
            },
        )
        .optional()?
        .unwrap_or(OfflinePolicyView {
            revision: 0,
            enabled: false,
            highest_revocation_epoch: 1,
        }))
}
fn row(connection: &Connection, space: &str, id: &str) -> Result<Row, StorageError> {
    require_id(id)?;
    let private: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM offline_bundles WHERE space_id=?1 AND bundle_id=?2)", params![space,id], |r| r.get(0))?;
    let table = if private { "offline_bundles" } else { "offline_remote_bundles" };
    type Stored = (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
        Option<String>,
        Vec<u8>,
        Vec<u8>,
        bool,
        bool,
        Option<String>,
        bool,
    );
    let stored: Stored = connection.query_row(&format!("SELECT claims_json,requester_account,requester_login,draft_digest,authority_key,approval0,approval1,consume_challenge0,consume_challenge1,consumed0,consumed1,signed_json,revoked FROM {table} WHERE space_id=?1 AND bundle_id=?2"),params![space,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?))).optional()?.ok_or(StorageError::Forbidden)?;
    let (claims, account, login, hash, key, a, b, c, d, x, y, signed, revoked) = stored;
    let business_authority = if private {
        OriginalBusiness::Private(connection.query_row("SELECT private_rule_id,private_exposure_revision FROM offline_bundles WHERE space_id=?1 AND bundle_id=?2", params![space,id], |r| Ok(OfflinePrivateAuthority {rule_id: r.get(0)?, exposure_revision: r.get(1)?}))?)
    } else {
        let json: String=connection.query_row("SELECT original_permit_json FROM offline_remote_bundles WHERE space_id=?1 AND bundle_id=?2", params![space,id], |r|r.get(0))?;
        OriginalBusiness::Remote(serde_json::from_str(&json)?)
    };
    let claims: OfflineGrantBundleClaims = serde_json::from_str(&claims)?;
    claims.validate()?;
    let result = Row {
        claims,
        account,
        login,
        digest: hash.try_into().map_err(|_| StorageError::Conflict)?,
        authority: key.try_into().map_err(|_| StorageError::Conflict)?,
        approvals: [
            a.map(|v| serde_json::from_str(&v)).transpose()?,
            b.map(|v| serde_json::from_str(&v)).transpose()?,
        ],
        challenges: [
            c.try_into().map_err(|_| StorageError::Conflict)?,
            d.try_into().map_err(|_| StorageError::Conflict)?,
        ],
        consumed: [x, y],
        signed: signed.map(|v| serde_json::from_str(&v)).transpose()?,
        revoked,
        business_authority,
    };
    if result.claims.bundle_id != id
        || result.claims.space_id != space
        || offline_draft_digest(&result.authority, &result.claims)? != result.digest
    {
        return Err(StorageError::Conflict);
    }
    Ok(result)
}
fn endpoint<'a>(
    row: &'a Row,
    actor: &Principal,
    index: u8,
) -> Result<&'a OfflineMember, StorageError> {
    row.claims
        .members
        .get(usize::from(index))
        .filter(|m| m.account_id == actor.account_id)
        .ok_or(StorageError::Forbidden)
}
fn challenge(row: &Row, index: u8) -> Result<OfflineConsumeChallenge, StorageError> {
    let member = row
        .claims
        .members
        .get(usize::from(index))
        .ok_or(StorageError::Forbidden)?;
    Ok(OfflineConsumeChallenge {
        bundle_id: row.claims.bundle_id.clone(),
        endpoint: index,
        draft_digest: row.digest,
        process_nonce: member.process_nonce,
        challenge: row.challenges[usize::from(index)],
        expires_at_ms: row.claims.expires_at_ms,
    })
}
impl Store {
    fn offline_current(
        &self,
        tx: &Transaction<'_>,
        row: &Row,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let snapshot = read_snapshot(tx, &row.claims.space_id, now)?;
        let policy = settings(tx, &row.claims.space_id)?;
        let security = self.security_epoch()?;
        let quota_fenced: bool = tx.query_row(
            "SELECT restore_fenced FROM service_quota_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let c = &row.claims;
        let mut live = !row.revoked
            && !quota_fenced
            && policy.enabled
            && now >= c.issued_at_ms
            && now < c.expires_at_ms
            && snapshot.authority_key == row.authority
            && snapshot.policy_epoch == c.policy_epoch
            && security == c.security_epoch
            && policy.highest_revocation_epoch == c.highest_revocation_epoch;
        live &= c.members.iter().all(|m| {
            snapshot.member(&m.installation_id).is_some_and(|actual| {
                actual.active()
                    && actual.public_key() == m.public_key
                    && actual.membership_epoch() == m.membership_epoch
            })
        });
        if live {
            let current = match &row.business_authority {
                OriginalBusiness::Private(original) => self.offline_private_current(
                &row.account,
                &row.login,
                c,
                original,
                now,
                ),
                OriginalBusiness::Remote(original) => self.offline_remote_current(&row.account, &row.login, c, original, now),
            };
            match current {
                Ok(()) => {}
                Err(
                    StorageError::Forbidden
                    | StorageError::Unauthorized
                    | StorageError::Conflict
                    | StorageError::Proof(_),
                ) => live = false,
                Err(error) => return Err(error),
            }
        }
        if !live {
            tx.execute(
                &format!("UPDATE {} SET revoked=1 WHERE bundle_id=?1", row.business_authority.table()),
                [&c.bundle_id],
            )?;
        }
        observe(tx, &c.space_id, now)?;
        Ok(OfflineBundleView {
            claims: c.clone(),
            draft_digest: row.digest,
            authority_public_key: row.authority,
            approved: row.approvals.each_ref().map(Option::is_some),
            consumed: row.consumed,
            signed: row.signed.clone(),
            live,
            policy_epoch: snapshot.policy_epoch,
            security_epoch: security,
            highest_revocation_epoch: policy.highest_revocation_epoch,
            observed_at_ms: now,
        })
    }
    pub fn offline_policy(
        &mut self,
        actor: &Principal,
        space: &str,
        now: u64,
    ) -> Result<OfflinePolicyView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let member: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM network_space_members WHERE space_id=?1 AND account_id=?2 AND revoked=0)",params![space,actor.account_id],|r|r.get(0))?;
        if !member && !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        let result = settings(&tx, &snapshot.space_id)?;
        observe(&tx, space, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn set_offline_enabled(
        &mut self,
        actor: &Principal,
        space: &str,
        request: OfflineEnableUpdate,
        now: u64,
    ) -> Result<OfflinePolicyView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now)?)?;
        read_snapshot(&tx, space, now)?;
        let old = settings(&tx, space)?;
        if old.revision != request.expected_revision {
            return Err(StorageError::Conflict);
        }
        let result = OfflinePolicyView {
            revision: next(old.revision)?,
            enabled: request.enabled,
            highest_revocation_epoch: next(old.highest_revocation_epoch)?,
        };
        tx.execute("INSERT INTO offline_settings(space_id,revision,enabled,revocation_epoch) VALUES(?1,?2,?3,?4) ON CONFLICT(space_id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,revocation_epoch=excluded.revocation_epoch",params![space,result.revision,result.enabled,result.highest_revocation_epoch])?;
        tx.execute(
            "UPDATE offline_bundles SET revoked=1 WHERE space_id=?1",
            [space],
        )?;
        tx.execute("UPDATE offline_remote_bundles SET revoked=1 WHERE space_id=?1", [space])?;
        observe(&tx, space, now)?;
        auditing::record(
            &tx,
            "offline_enabled_changed",
            space,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn create_offline_private_draft(
        &mut self,
        actor: &Principal,
        space: &str,
        request: OfflinePrivateDraftRequest,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let policy = settings(&tx, space)?;
        if !policy.enabled || request.expected_policy_revision != snapshot.revision {
            return Err(StorageError::Conflict);
        }
        let count: u64 = tx.query_row(
            "SELECT (SELECT count(*) FROM offline_bundles WHERE space_id=?1)+(SELECT count(*) FROM offline_remote_bundles WHERE space_id=?1)",
            [space],
            |r| r.get(0),
        )?;
        if count >= MAX_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let (business, members, original) = self.offline_private_draft(actor, &request, now)?;
        let claims = OfflineGrantBundleClaims {
            bundle_version: OFFLINE_BUNDLE_VERSION,
            deployment_id: self.deployment_id()?,
            space_id: space.into(),
            bundle_id: random_id(),
            policy_epoch: snapshot.policy_epoch,
            security_epoch: self.security_epoch()?,
            highest_revocation_epoch: policy.highest_revocation_epoch,
            issued_at_ms: now,
            expires_at_ms: request.expires_at_ms,
            members,
            connection: OfflineConnection {
                connection_id: random_id(),
                path_id: random_id(),
                direct_transports: request.direct_transports,
            },
            business,
            resources: OfflineResourceReservation {
                reservation_id: random_id(),
                byte_limit: request.maximum_bytes,
                file_write_limit: 0,
                connection_limit: request.maximum_connections,
            },
        };
        claims.validate()?;
        self.offline_private_current(
            &actor.account_id,
            &actor.session_id,
            &claims,
            &original,
            now,
        )?;
        let hash = offline_draft_digest(&snapshot.authority_key, &claims)?;
        tx.execute("INSERT INTO offline_bundles(bundle_id,space_id,requester_account,requester_login,claims_json,draft_digest,authority_key,consume_challenge0,consume_challenge1,private_rule_id,private_exposure_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![claims.bundle_id,space,actor.account_id,actor.session_id,serde_json::to_string(&claims)?,hash,snapshot.authority_key,random_bytes::<32>(),random_bytes::<32>(),original.rule_id,original.exposure_revision])?;
        let result = self.offline_current(&tx, &row(&tx, space, &claims.bundle_id)?, now)?;
        auditing::record(
            &tx,
            "offline_draft_created",
            &claims.bundle_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn offline_bundle(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let stored = row(&tx, space, id)?;
        if !stored
            .claims
            .members
            .iter()
            .any(|m| m.account_id == actor.account_id)
            && !actor.is_admin
        {
            return Err(StorageError::Forbidden);
        }
        let result = self.offline_current(&tx, &stored, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn approve_offline_bundle(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        id: &str,
        approval: OfflineEndpointApproval,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let mut stored = row(&tx, space, id)?;
        endpoint(&stored, actor, approval.endpoint)?;
        let current = self.offline_current(&tx, &stored, now)?;
        if !current.live || stored.authority != signer.public_key() {
            return Err(StorageError::Forbidden);
        }
        verify_offline_endpoint_approval(&stored.authority, &stored.claims, &approval)?;
        let index = usize::from(approval.endpoint);
        if stored.approvals[index]
            .as_ref()
            .is_some_and(|old| old != &approval)
        {
            return Err(StorageError::Conflict);
        }
        let column = if index == 0 { "approval0" } else { "approval1" };
        tx.execute(
            &format!("UPDATE {} SET {column}=?1 WHERE bundle_id=?2", stored.business_authority.table()),
            params![serde_json::to_string(&approval)?, id],
        )?;
        stored.approvals[index] = Some(approval);
        if stored.signed.is_none()
            && let [Some(a), Some(b)] = &stored.approvals
        {
            verify_offline_endpoint_approvals(
                &stored.authority,
                &stored.claims,
                &[a.clone(), b.clone()],
            )?;
            match &stored.business_authority {
                OriginalBusiness::Private(_) => self.offline_private_reserve(&tx, &stored.claims)?,
                OriginalBusiness::Remote(original) => self.offline_remote_reserve(&tx, &stored.claims, original)?,
            }
            let signed = signer.sign_offline_bundle(&stored.claims)?;
            tx.execute(&format!("UPDATE {} SET signed_json=?1 WHERE bundle_id=?2 AND signed_json IS NULL", stored.business_authority.table()),params![serde_json::to_string(&signed)?,id])?;
            stored.signed = Some(signed);
        }
        let result = self.offline_current(&tx, &stored, now)?;
        auditing::record(
            &tx,
            "offline_endpoint_approved",
            id,
            auditing::device(actor, &stored.claims.members[index].installation_id),
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn offline_consume_challenge(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        index: u8,
        now: u64,
    ) -> Result<OfflineConsumeChallenge, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let stored = row(&tx, space, id)?;
        endpoint(&stored, actor, index)?;
        if !self.offline_current(&tx, &stored, now)?.live
            || stored.signed.is_none()
            || stored.consumed[usize::from(index)]
        {
            return Err(StorageError::Forbidden);
        }
        let result = challenge(&stored, index)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn consume_offline_bundle(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        request: OfflineConsumeRequest,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let mut stored = row(&tx, space, id)?;
        let member = endpoint(&stored, actor, request.endpoint)?;
        if request.draft_digest != stored.digest
            || request.process_nonce != member.process_nonce
            || !self.offline_current(&tx, &stored, now)?.live
            || stored.signed.is_none()
        {
            return Err(StorageError::Forbidden);
        }
        verify_device_action(
            &offline_consume_transcript(&stored.claims, &challenge(&stored, request.endpoint)?)?,
            &member.public_key,
            &request.signature,
        )?;
        let index = usize::from(request.endpoint);
        let column = if index == 0 { "consumed0" } else { "consumed1" };
        if tx.execute(&format!("UPDATE {} SET {column}=1 WHERE bundle_id=?1 AND {column}=0 AND signed_json IS NOT NULL AND revoked=0", stored.business_authority.table()),[id])? != 1 {return Err(StorageError::Conflict);}
        stored.consumed[index] = true;
        let result = self.offline_current(&tx, &stored, now)?;
        auditing::record(
            &tx,
            "offline_endpoint_consumed",
            id,
            auditing::device(actor, &stored.claims.members[index].installation_id),
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn revoke_offline_bundle(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let stored = row(&tx, space, id)?;
        if !stored
            .claims
            .members
            .iter()
            .any(|m| m.account_id == actor.account_id)
        {
            self.audit_admin(actor, now / 1000)?;
        }
        tx.execute(
            &format!("UPDATE {} SET revoked=1 WHERE bundle_id=?1", stored.business_authority.table()),
            [id],
        )?;
        tx.execute("UPDATE offline_settings SET revision=revision+1,revocation_epoch=revocation_epoch+1 WHERE space_id=?1",[space])?;
        let result = self.offline_current(&tx, &row(&tx, space, id)?, now)?;
        auditing::record(
            &tx,
            "offline_bundle_revoked",
            id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(result)
    }
}
