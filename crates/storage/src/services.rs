//! Persistent service definitions and separately signed local target consent.
//! An approved target is configuration, never evidence of a running listener.
use crate::{StorageError, Store, accounts::Principal, auditing, require_id, trusted::unix_ms};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{random_bytes, random_id};
use nestlink_identity::{
    digest,
    services::{decode_digest, definition_digest, verify_approval},
};
use nestlink_protocol::{
    NodeRole,
    api::*,
    services::{SERVICE_APPROVAL_LIFETIME_MS, SERVICE_CHALLENGE_MS, revision_valid},
};
use rusqlite::{OptionalExtension, params};
pub mod publication;
pub mod quota_recovery;

pub const MAX_ACCOUNT_SERVICES: u64 = 128;
pub const MAX_SERVICE_RECORDS: u64 = 4096;
pub const MAX_ACCOUNT_SERVICE_CHALLENGES: u64 = 16;
pub const MAX_SERVICE_CHALLENGES: u64 = 4096;

struct Record {
    id: String,
    account: String,
    login: String,
    revision: u64,
    definition: ServiceDefinition,
    hash: [u8; 32],
    revoked: bool,
}
struct Approval {
    login: String,
    revision: u64,
    policy: u64,
    epoch: u64,
    hash: Vec<u8>,
    host_hash: Vec<u8>,
    target: String,
    target_hash: Vec<u8>,
    issued: u64,
    expires: u64,
    proof: String,
    revoked: bool,
}
type ServiceRow = (String, String, u64, String, Vec<u8>, bool, String, String);
type ChallengeRow = (u64, u64, Vec<u8>, u64, u64);
fn next(revision: u64) -> Result<u64, StorageError> {
    revision
        .checked_add(1)
        .filter(|n| revision_valid(revision) && *n <= i64::MAX as u64)
        .ok_or(StorageError::Conflict)
}
impl Store {
    pub(crate) fn approved_space_service_definition(
        &self,
        id: &str,
        revision: u64,
        now_ms: u64,
    ) -> Result<(String, ServiceDefinition), StorageError> {
        let record = self.service_record(id)?;
        if record.revision != revision {
            return Err(StorageError::Conflict);
        }
        let approval = self
            .service_approval_row(id)?
            .ok_or(StorageError::Forbidden)?;
        if !self.service_approval_live(&record, &approval, now_ms / 1000)?
            || now_ms >= approval.expires
        {
            return Err(StorageError::Forbidden);
        }
        Ok((record.account, record.definition))
    }

    fn service_record(&self, id: &str) -> Result<Record, StorageError> {
        require_id(id)?;
        let row: Option<ServiceRow> = self.connection.query_row(
            "SELECT account_id,management_session_id,revision,definition_json,definition_sha256,revoked,host_device_id,edge_node_id FROM services WHERE id=?1",
            [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
        ).optional()?;
        let (account, login, revision, json, hash, revoked, host, edge) =
            row.ok_or(StorageError::Forbidden)?;
        let definition: ServiceDefinition = serde_json::from_str(&json)?;
        let hash: [u8; 32] = hash.try_into().map_err(|_| StorageError::Conflict)?;
        if !revision_valid(revision)
            || definition_digest(&definition)? != hash
            || definition.host_device_id != host
            || definition.edge_node_id != edge
        {
            return Err(StorageError::Conflict);
        }
        Ok(Record {
            id: id.into(),
            account,
            login,
            revision,
            definition,
            hash,
            revoked,
        })
    }
    fn service_owner(&self, actor: &Principal, id: &str, now: u64) -> Result<Record, StorageError> {
        self.validate_access(actor, now)?;
        let record = self.service_record(id)?;
        if record.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        Ok(record)
    }
    fn service_login_live(
        &self,
        account: &str,
        login: &str,
        now: u64,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM management_sessions m JOIN accounts a ON a.id=m.account_id JOIN deployment d ON d.singleton=1 WHERE m.id=?1 AND m.account_id=?2 AND m.revoked=0 AND m.refresh_expires>?3 AND m.security_epoch=d.security_epoch AND a.disabled=0)",
            params![login,account,now],|r|r.get(0))?)
    }
    fn service_endpoints(
        &self,
        account: &str,
        definition: &ServiceDefinition,
        now: u64,
    ) -> Result<[u8; 32], StorageError> {
        definition.validate()?;
        let host = self.device_record_at(&definition.host_device_id, now)?;
        if host.account != account
            || self
                .device_expiration_ms(&definition.host_device_id)?
                .is_some()
        {
            return Err(StorageError::Forbidden);
        }
        let roles: Option<String> = self
            .connection
            .query_row(
                "SELECT roles_json FROM data_nodes WHERE id=?1 AND revoked=0",
                [&definition.edge_node_id],
                |r| r.get(0),
            )
            .optional()?;
        let roles: Vec<i32> = serde_json::from_str(&roles.ok_or(StorageError::Forbidden)?)?;
        if !roles.contains(&(NodeRole::NodeEdge as i32)) {
            return Err(StorageError::Forbidden);
        }
        Ok(host.public_key)
    }
    fn service_approval_row(&self, id: &str) -> Result<Option<Approval>, StorageError> {
        Ok(self.connection.query_row(
            "SELECT management_session_id,service_revision,policy_revision,security_epoch,definition_sha256,host_key_sha256,target_id,target_sha256,approved_at,expires_at,proof_json,revoked FROM service_target_approvals WHERE service_id=?1",[id],
            |r|Ok(Approval {login:r.get(0)?,revision:r.get(1)?,policy:r.get(2)?,epoch:r.get(3)?,hash:r.get(4)?,host_hash:r.get(5)?,target:r.get(6)?,target_hash:r.get(7)?,issued:r.get(8)?,expires:r.get(9)?,proof:r.get(10)?,revoked:r.get(11)?}),
        ).optional()?)
    }
    fn service_approval_live(
        &self,
        record: &Record,
        approval: &Approval,
        now: u64,
    ) -> Result<bool, StorageError> {
        let now_ms = unix_ms(now)?;
        let (policy_revision, policy) = self.policy()?;
        if record.revoked
            || approval.revoked
            || approval.revision != record.revision
            || approval.hash != record.hash
            || approval.epoch != self.security_epoch()?
            || approval.policy != policy_revision
            || now_ms < approval.issued
            || now_ms >= approval.expires
            || policy.may_publish().is_err()
            || !self.service_login_live(&record.account, &record.login, now)?
            || !self.service_login_live(&record.account, &approval.login, now)?
        {
            return Ok(false);
        }
        let key = match self.service_endpoints(&record.account, &record.definition, now) {
            Ok(key) => key,
            Err(StorageError::Forbidden | StorageError::Unauthorized) => return Ok(false),
            Err(error) => return Err(error),
        };
        if approval.host_hash != digest(&key) {
            return Ok(false);
        }
        let (challenge, submission): (ServiceApprovalChallenge, ServiceTargetApproval) =
            serde_json::from_str(&approval.proof)?;
        if challenge.service_id != record.id
            || next(challenge.service_revision)? != record.revision
            || challenge.management_session_id != approval.login
            || challenge.account_id != record.account
            || challenge.host_device_id != record.definition.host_device_id
            || challenge.deployment_id != self.deployment_id()?
            || challenge.security_epoch != approval.epoch
            || challenge.policy_revision != approval.policy
            || decode_digest(&challenge.definition_sha256)? != record.hash
            || submission.challenge_id != challenge.id
            || submission.choice.target_id != approval.target
            || decode_digest(&submission.choice.target_sha256)?.as_slice() != approval.target_hash
            || submission.choice.expires_at_unix_ms != approval.expires
        {
            return Err(StorageError::Conflict);
        }
        let signature = crate::control::decode_signature(&submission.signature)?;
        verify_approval(&challenge, &submission.choice, &key, &signature)?;
        Ok(true)
    }
    fn service_view_record(&self, record: Record, now: u64) -> Result<ServiceView, StorageError> {
        let approval = self.service_approval_row(&record.id)?;
        let state = if record.revoked {
            ServiceApprovalState::Revoked
        } else if let Some(value) = &approval {
            if self.service_approval_live(&record, value, now)? {
                ServiceApprovalState::ApprovedTarget
            } else {
                ServiceApprovalState::Invalidated
            }
        } else {
            ServiceApprovalState::Pending
        };
        let now_ms = now.checked_mul(1000).ok_or(StorageError::Conflict)?;
        let publication = self.service_publication_status(&record.id, now_ms)?;
        Ok(ServiceView {
            id: record.id,
            account_id: record.account,
            management_session_id: record.login,
            revision: record.revision,
            definition: record.definition,
            definition_sha256: URL_SAFE_NO_PAD.encode(record.hash),
            approval: state,
            target_id: approval.as_ref().map(|a| a.target.clone()),
            target_sha256: approval
                .as_ref()
                .map(|a| URL_SAFE_NO_PAD.encode(&a.target_hash)),
            approval_expires_at_unix_ms: approval.map(|a| a.expires),
            publication,
        })
    }
    pub fn service(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<ServiceView, StorageError> {
        self.service_view_record(self.service_owner(actor, id, now)?, now)
    }
    pub fn services(
        &self,
        actor: &Principal,
        query: ServiceQuery,
        now: u64,
    ) -> Result<ServicePage, StorageError> {
        self.validate_access(actor, now)?;
        if query.security_epoch != self.security_epoch()? {
            return Err(StorageError::Conflict);
        }
        if !(1..=100).contains(&query.limit) {
            return Err(StorageError::Invalid("invalid service page budget"));
        }
        if let Some(after) = &query.after_id {
            require_id(after)?;
        }
        let mut statement=self.connection.prepare("SELECT id FROM services WHERE account_id=?1 AND (?2 IS NULL OR id>?2) ORDER BY id LIMIT ?3")?;
        let ids = statement
            .query_map(
                params![actor.account_id, query.after_id, u32::from(query.limit) + 1],
                |r| r.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let more = ids.len() > usize::from(query.limit);
        let mut services = Vec::with_capacity(usize::from(query.limit));
        for id in ids.into_iter().take(usize::from(query.limit)) {
            services.push(self.service_view_record(self.service_record(&id)?, now)?);
        }
        Ok(ServicePage {
            security_epoch: query.security_epoch,
            next_id: services.last().map(|v| v.id.clone()),
            services,
            more,
        })
    }
    pub fn create_service(
        &mut self,
        actor: &Principal,
        body: ServiceCreate,
        now: u64,
    ) -> Result<ServiceView, StorageError> {
        require_id(&body.id)?;
        body.definition.validate()?;
        let hash = definition_digest(&body.definition)?;
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now)?;
        self.service_endpoints(&actor.account_id, &body.definition, now)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM services WHERE id=?1)",
            [&body.id],
            |r| r.get(0),
        )?;
        if exists {
            let record = self.service_owner(actor, &body.id, now)?;
            if record.revision != 1
                || record.revoked
                || record.hash != hash
                || record.login != actor.session_id
            {
                return Err(StorageError::Conflict);
            }
            return self.service_view_record(record, now);
        }
        let (account,total):(u64,u64)=tx.query_row("SELECT (SELECT count(*) FROM services WHERE account_id=?1),(SELECT count(*) FROM services)",[&actor.account_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if account >= MAX_ACCOUNT_SERVICES || total >= MAX_SERVICE_RECORDS {
            return Err(StorageError::RateLimited);
        }
        tx.execute("INSERT INTO services(id,account_id,management_session_id,host_device_id,edge_node_id,revision,definition_json,definition_sha256) VALUES(?1,?2,?3,?4,?5,1,?6,?7)",params![body.id,actor.account_id,actor.session_id,body.definition.host_device_id,body.definition.edge_node_id,serde_json::to_string(&body.definition)?,hash])?;
        auditing::record(
            &tx,
            "service_created",
            &body.id,
            auditing::management(actor),
        )?;
        let view = self.service(actor, &body.id, now)?;
        tx.commit()?;
        Ok(view)
    }
    pub fn update_service(
        &mut self,
        actor: &Principal,
        id: &str,
        body: ServiceUpdate,
        now: u64,
    ) -> Result<ServiceView, StorageError> {
        body.definition.validate()?;
        let revision = next(body.expected_revision)?;
        let hash = definition_digest(&body.definition)?;
        let tx = self.connection.unchecked_transaction()?;
        let record = self.service_owner(actor, id, now)?;
        if record.revoked || record.revision != body.expected_revision {
            return Err(StorageError::Conflict);
        }
        self.service_endpoints(&actor.account_id, &body.definition, now)?;
        if tx.execute("UPDATE services SET management_session_id=?1,host_device_id=?2,edge_node_id=?3,revision=?4,definition_json=?5,definition_sha256=?6 WHERE id=?7 AND revision=?8 AND revoked=0",params![actor.session_id,body.definition.host_device_id,body.definition.edge_node_id,revision,serde_json::to_string(&body.definition)?,hash,id,body.expected_revision])?!=1 {return Err(StorageError::Conflict);}
        tx.execute(
            "UPDATE service_target_approvals SET revoked=1 WHERE service_id=?1",
            [id],
        )?;
        tx.execute(
            "DELETE FROM service_approval_challenges WHERE service_id=?1",
            [id],
        )?;
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
            [id],
        )?;
        auditing::record(&tx, "service_changed", id, auditing::management(actor))?;
        let view = self.service(actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }
    pub fn revoke_service(
        &mut self,
        actor: &Principal,
        id: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<ServiceView, StorageError> {
        let revision = next(expected_revision)?;
        let tx = self.connection.unchecked_transaction()?;
        let record = self.service_owner(actor, id, now)?;
        if record.revoked && record.revision == revision {
            return self.service_view_record(record, now);
        }
        if record.revoked || record.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        tx.execute(
            "UPDATE services SET revoked=1,revision=?1 WHERE id=?2 AND revision=?3",
            params![revision, id, expected_revision],
        )?;
        tx.execute(
            "UPDATE service_target_approvals SET revoked=1 WHERE service_id=?1",
            [id],
        )?;
        tx.execute(
            "DELETE FROM service_approval_challenges WHERE service_id=?1",
            [id],
        )?;
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
            [id],
        )?;
        auditing::record(&tx, "service_revoked", id, auditing::management(actor))?;
        let view = self.service(actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }
    pub fn service_approval_challenge(
        &mut self,
        actor: &Principal,
        id: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<ServiceApprovalChallenge, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        let record = self.service_owner(actor, id, now)?;
        if record.revoked || record.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        self.service_endpoints(&record.account, &record.definition, now)?;
        if !self.service_login_live(&record.account, &record.login, now)? {
            return Err(StorageError::Unauthorized);
        }
        let (policy_revision, policy) = self.policy()?;
        policy.may_publish()?;
        let now_ms = unix_ms(now)?;
        let expires = now_ms
            .checked_add(SERVICE_CHALLENGE_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        tx.execute(
            "DELETE FROM service_approval_challenges WHERE consumed=1 OR expires_at<=?1",
            [now_ms],
        )?;
        let (account,total):(u64,u64)=tx.query_row("SELECT (SELECT count(*) FROM service_approval_challenges WHERE account_id=?1),(SELECT count(*) FROM service_approval_challenges)",[&actor.account_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if account >= MAX_ACCOUNT_SERVICE_CHALLENGES || total >= MAX_SERVICE_CHALLENGES {
            return Err(StorageError::RateLimited);
        }
        let challenge = ServiceApprovalChallenge {
            id: random_id(),
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            policy_revision,
            account_id: actor.account_id.clone(),
            management_session_id: actor.session_id.clone(),
            host_device_id: record.definition.host_device_id,
            service_id: id.into(),
            service_revision: record.revision,
            definition_sha256: URL_SAFE_NO_PAD.encode(record.hash),
            nonce: URL_SAFE_NO_PAD.encode(random_bytes::<32>()),
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: expires,
        };
        tx.execute("INSERT INTO service_approval_challenges(id,service_id,account_id,management_session_id,service_revision,policy_revision,security_epoch,nonce,issued_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![challenge.id,id,actor.account_id,actor.session_id,record.revision,policy_revision,challenge.security_epoch,decode_digest(&challenge.nonce)?,now_ms,expires])?;
        tx.commit()?;
        Ok(challenge)
    }
    pub fn approve_service_target(
        &mut self,
        actor: &Principal,
        id: &str,
        body: ServiceTargetApproval,
        now: u64,
    ) -> Result<ServiceView, StorageError> {
        require_id(&body.challenge_id)?;
        let tx = self.connection.unchecked_transaction()?;
        let record = self.service_owner(actor, id, now)?;
        if record.revoked || record.revision != body.choice.expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = next(record.revision)?;
        let key = self.service_endpoints(&record.account, &record.definition, now)?;
        if !self.service_login_live(&record.account, &record.login, now)? {
            return Err(StorageError::Unauthorized);
        }
        let (policy_revision, policy) = self.policy()?;
        policy.may_publish()?;
        let now_ms = unix_ms(now)?;
        let row:Option<ChallengeRow>=tx.query_row("SELECT policy_revision,security_epoch,nonce,issued_at,expires_at FROM service_approval_challenges WHERE id=?1 AND service_id=?2 AND account_id=?3 AND management_session_id=?4 AND service_revision=?5 AND consumed=0",params![body.challenge_id,id,actor.account_id,actor.session_id,record.revision],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (old_policy, epoch, nonce, issued, expires) = row.ok_or(StorageError::Conflict)?;
        if old_policy != policy_revision
            || epoch != self.security_epoch()?
            || now_ms < issued
            || now_ms >= expires
            || body.choice.expires_at_unix_ms <= now_ms
            || body.choice.expires_at_unix_ms - issued > SERVICE_APPROVAL_LIFETIME_MS
        {
            return Err(StorageError::Forbidden);
        }
        let challenge = ServiceApprovalChallenge {
            id: body.challenge_id.clone(),
            deployment_id: self.deployment_id()?,
            security_epoch: epoch,
            policy_revision,
            account_id: record.account.clone(),
            management_session_id: actor.session_id.clone(),
            host_device_id: record.definition.host_device_id.clone(),
            service_id: id.into(),
            service_revision: record.revision,
            definition_sha256: URL_SAFE_NO_PAD.encode(record.hash),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            issued_at_unix_ms: issued,
            expires_at_unix_ms: expires,
        };
        let signature = crate::control::decode_signature(&body.signature)?;
        verify_approval(&challenge, &body.choice, &key, &signature)?;
        if tx.execute(
            "UPDATE service_approval_challenges SET consumed=1 WHERE id=?1 AND consumed=0",
            [&body.challenge_id],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        if tx.execute(
            "UPDATE services SET revision=?1 WHERE id=?2 AND revision=?3 AND revoked=0",
            params![revision, id, record.revision],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        let proof = serde_json::to_string(&(&challenge, &body))?;
        tx.execute("INSERT INTO service_target_approvals VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0) ON CONFLICT(service_id) DO UPDATE SET management_session_id=excluded.management_session_id,service_revision=excluded.service_revision,policy_revision=excluded.policy_revision,security_epoch=excluded.security_epoch,definition_sha256=excluded.definition_sha256,host_key_sha256=excluded.host_key_sha256,target_id=excluded.target_id,target_sha256=excluded.target_sha256,approved_at=excluded.approved_at,expires_at=excluded.expires_at,proof_json=excluded.proof_json,revoked=0",params![id,actor.session_id,revision,policy_revision,epoch,record.hash,digest(&key),body.choice.target_id,decode_digest(&body.choice.target_sha256)?,now_ms,body.choice.expires_at_unix_ms,proof])?;
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
            [id],
        )?;
        auditing::record(
            &tx,
            "service_target_approved",
            id,
            auditing::device(actor, &record.definition.host_device_id),
        )?;
        let view = self.service(actor, id, now)?;
        tx.commit()?;
        Ok(view)
    }
}
