use super::{StorageError, Store, audit, require_id};
use crate::accounts::Principal;
use crate::auditing;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{random_bytes, random_id};
use nestlink_identity::{digest, verify_device_action};
use nestlink_policy::{PathSet, PeerPathMode, PolicyScopes};
use nestlink_protocol::api::{
    ApprovalChoice, DeviceDescriptor, DeviceRegistration, RemotePeerKeys, RemoteRequest,
    RenewalSubmission,
};
pub use nestlink_protocol::api::{DeviceView, EnrollmentChallenge, RemoteView};
use nestlink_protocol::{
    DeviceAction, DeviceActionClaims, Permission, PermitClaims, SCHEMA_VERSION, SESSION_LEASE_MS,
};
use rusqlite::{OptionalExtension, params};

/// Browser endpoints are deliberately short lived and cannot request a longer lease.
pub const BROWSER_ENDPOINT_LIFETIME_SECONDS: u64 = 10 * 60;
/// Bound simultaneously active browser endpoints per management account.
pub const MAX_ACTIVE_BROWSER_ENDPOINTS_PER_ACCOUNT: i64 = 16;
type RemoteRow = (
    String,
    String,
    String,
    String,
    Vec<u8>,
    u64,
    u64,
    String,
    u64,
    u64,
    Option<u64>,
    Option<u64>,
);

impl Store {
    pub fn remote_event_accounts(&self, id: &str) -> Result<Vec<String>, StorageError> {
        let pair:(String,String)=self.connection.query_row("SELECT r.controller_account_id,h.account_id FROM remote_requests r JOIN devices h ON h.id=r.host_device_id WHERE r.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        Ok(if pair.0 == pair.1 {
            vec![pair.0]
        } else {
            vec![pair.0, pair.1]
        })
    }
    pub fn deployment_id(&self) -> Result<String, StorageError> {
        Ok(self
            .connection
            .query_row("SELECT id FROM deployment WHERE singleton=1", [], |r| {
                r.get(0)
            })?)
    }
    pub fn enrollment_challenge(
        &mut self,
        actor: &Principal,
        now: u64,
    ) -> Result<EnrollmentChallenge, StorageError> {
        self.connection.execute(
            "DELETE FROM enrollment_challenges WHERE expires<=?1 OR consumed=1",
            [now],
        )?;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM enrollment_challenges WHERE account_id=?1",
            [&actor.account_id],
            |r| r.get(0),
        )?;
        if count >= 16 {
            return Err(StorageError::RateLimited);
        }
        let id = random_id();
        let nonce = random_bytes::<32>();
        let expires = now + 60;
        self.connection.execute(
            "INSERT INTO enrollment_challenges(id,account_id,nonce,expires) VALUES(?1,?2,?3,?4)",
            params![id, actor.account_id, nonce, expires],
        )?;
        Ok(EnrollmentChallenge {
            id,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            expires_at_unix_ms: expires * 1000,
        })
    }
    pub fn registration_transcript(
        &self,
        actor: &Principal,
        submission: &DeviceRegistration,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        let record:Option<(Vec<u8>,u64)>=self.connection.query_row("SELECT nonce,expires FROM enrollment_challenges WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",params![submission.challenge_id,actor.account_id,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (nonce, expires) = record.ok_or(StorageError::Unauthorized)?;
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Register as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: actor.account_id.clone(),
            device_id: submission.device.id.clone(),
            resource_id: submission.challenge_id.clone(),
            challenge: nonce,
            payload_sha256: digest(&serde_json::to_vec(&submission.device)?).to_vec(),
            expires_at_unix_ms: expires * 1000,
        })
    }
    pub fn register_device(
        &mut self,
        actor: &Principal,
        submission: DeviceRegistration,
        now: u64,
    ) -> Result<(), StorageError> {
        validate_descriptor(&submission.device)?;
        let public_key = key(&submission.device.public_key)?;
        let transcript = self.registration_transcript(actor, &submission, now)?;
        verify_device_action(
            &transcript,
            &public_key,
            &decode_signature(&submission.signature)?,
        )?;
        let tx = self.connection.transaction()?;
        if tx.execute("UPDATE enrollment_challenges SET consumed=1 WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",params![submission.challenge_id,actor.account_id,now])?!=1{return Err(StorageError::Unauthorized);}
        tx.execute(
            "INSERT INTO devices(id,account_id,key_sha256) VALUES(?1,?2,?3)",
            params![submission.device.id, actor.account_id, digest(&public_key)],
        )?;
        tx.execute(
            "INSERT INTO device_details VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                submission.device.id,
                public_key,
                submission.device.name,
                submission.device.platform,
                serde_json::to_string(&submission.device.capabilities)?,
                submission.device.path_mode
            ],
        )?;
        audit(
            &tx,
            "device_registered",
            &submission.device.id,
            auditing::device(actor, &submission.device.id),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn browser_endpoint_transcript(
        &self,
        actor: &Principal,
        submission: &nestlink_protocol::api::BrowserEndpointRegistration,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        let record: Option<(Vec<u8>, u64)> = self
            .connection
            .query_row(
                "SELECT nonce,expires FROM enrollment_challenges WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",
                params![submission.challenge_id, actor.account_id, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (nonce, expires) = record.ok_or(StorageError::Unauthorized)?;
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::RegisterBrowserEndpoint as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: actor.account_id.clone(),
            device_id: submission.device.id.clone(),
            resource_id: submission.challenge_id.clone(),
            challenge: nonce,
            payload_sha256: digest(&serde_json::to_vec(&submission.device)?).to_vec(),
            expires_at_unix_ms: expires * 1000,
        })
    }
    pub fn register_browser_endpoint(
        &mut self,
        actor: &Principal,
        submission: nestlink_protocol::api::BrowserEndpointRegistration,
        now: u64,
    ) -> Result<nestlink_protocol::api::BrowserEndpointLease, StorageError> {
        validate_descriptor(&submission.device)?;
        if submission.device.platform != "web"
            || !submission
                .device
                .capabilities
                .iter()
                .any(|c| c == "controller")
            || !submission.device.capabilities.iter().any(|c| c == "vp8")
            || submission.device.capabilities.iter().any(|c| c == "host")
        {
            return Err(StorageError::Invalid(
                "browser endpoint must be a non-host controller",
            ));
        }
        let public_key = key(&submission.device.public_key)?;
        let transcript = self.browser_endpoint_transcript(actor, &submission, now)?;
        verify_device_action(
            &transcript,
            &public_key,
            &decode_signature(&submission.signature)?,
        )?;
        let expires = now
            .checked_add(BROWSER_ENDPOINT_LIFETIME_SECONDS)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let expires_at_unix_ms = expires
            .checked_mul(1000)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let tx = self.connection.transaction()?;
        let active_endpoints: i64 = tx.query_row(
            "SELECT count(*) FROM devices d JOIN device_details x ON x.device_id=d.id WHERE d.account_id=?1 AND d.revoked=0 AND d.expires_at>?2 AND x.platform='web'",
            params![actor.account_id, now],
            |row| row.get(0),
        )?;
        if active_endpoints >= MAX_ACTIVE_BROWSER_ENDPOINTS_PER_ACCOUNT {
            return Err(StorageError::RateLimited);
        }
        if tx.execute(
            "UPDATE enrollment_challenges SET consumed=1 WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",
            params![submission.challenge_id, actor.account_id, now],
        )? != 1
        {
            return Err(StorageError::Unauthorized);
        }
        tx.execute(
            "INSERT INTO devices(id,account_id,key_sha256,expires_at) VALUES(?1,?2,?3,?4)",
            params![
                submission.device.id,
                actor.account_id,
                digest(&public_key),
                expires
            ],
        )?;
        tx.execute(
            "INSERT INTO device_details VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                submission.device.id,
                public_key,
                submission.device.name,
                submission.device.platform,
                serde_json::to_string(&submission.device.capabilities)?,
                submission.device.path_mode
            ],
        )?;
        audit(
            &tx,
            "browser_endpoint_registered",
            &submission.device.id,
            auditing::device(actor, &submission.device.id),
        )?;
        tx.commit()?;
        Ok(nestlink_protocol::api::BrowserEndpointLease {
            device_id: submission.device.id,
            expires_at_unix_ms,
        })
    }
    pub fn devices(&self, actor: &Principal) -> Result<Vec<DeviceView>, StorageError> {
        self.devices_at(
            actor,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
        )
    }
    pub fn devices_at(&self, actor: &Principal, now: u64) -> Result<Vec<DeviceView>, StorageError> {
        let mut statement = self.connection.prepare("SELECT d.id,x.name,x.platform,x.public_key,x.capabilities_json,x.path_mode,d.revoked FROM devices d JOIN device_details x ON x.device_id=d.id WHERE d.account_id=?1 AND (d.expires_at IS NULL OR d.expires_at>?2) ORDER BY x.name LIMIT 1000")?;
        let rows = statement.query_map(params![actor.account_id, now], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, bool>(6)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, name, platform, public_key, capabilities, path_mode, revoked) = row?;
            result.push(DeviceView {
                device: DeviceDescriptor {
                    id,
                    name,
                    platform,
                    public_key: URL_SAFE_NO_PAD.encode(public_key),
                    capabilities: serde_json::from_str(&capabilities)?,
                    path_mode,
                },
                revoked,
            });
        }
        Ok(result)
    }
    pub fn create_remote(
        &mut self,
        actor: &Principal,
        request: RemoteRequest,
        now: u64,
    ) -> Result<RemoteView, StorageError> {
        self.create_remote_kind(actor, request, now, false)
    }
    pub fn create_trusted_remote(
        &mut self,
        actor: &Principal,
        request: RemoteRequest,
        now: u64,
    ) -> Result<RemoteView, StorageError> {
        self.create_remote_kind(actor, request, now, true)
    }
    fn create_remote_kind(
        &mut self,
        actor: &Principal,
        request: RemoteRequest,
        now: u64,
        trusted: bool,
    ) -> Result<RemoteView, StorageError> {
        require_id(&request.id)?;
        require_id(&request.controller_device_id)?;
        require_id(&request.host_device_id)?;
        validate_permissions(&request.permissions)?;
        let tx = self.connection.unchecked_transaction()?;
        self.validate_management_session(actor, now)?;
        let requested_mode = parse_mode(&request.path_mode)?;
        let controller = self.device_record_at(&request.controller_device_id, now)?;
        let host = self.device_record_at(&request.host_device_id, now)?;
        if controller.account != actor.account_id
            || request.controller_device_id == request.host_device_id
        {
            return Err(StorageError::Forbidden);
        }
        if !controller.capabilities.iter().any(|v| v == "controller")
            || !host.capabilities.iter().any(|v| v == "host")
        {
            return Err(StorageError::Invalid("endpoint capability unavailable"));
        }
        let mut common: Vec<String> = controller
            .capabilities
            .iter()
            .filter(|v| host.capabilities.contains(v))
            .cloned()
            .collect();
        common.sort();
        if !common.iter().any(|v| v == "vp8") {
            return Err(StorageError::Invalid(
                "VP8 interoperability capability required",
            ));
        }
        let (revision, global) = self.policy()?;
        let mut paths = PolicyScopes {
            global,
            account: self.path_limit("account", &actor.account_id)?,
            device: self.path_limit("device", &request.controller_device_id)?,
            resource: self.path_limit("resource", &request.host_device_id)?,
            session: requested_mode,
            controller_local: controller.mode,
            host_local: host.mode,
        }
        .effective_paths()?
        .intersection(mode_paths(self.path_limit("account", &host.account)?))
        .intersection(mode_paths(
            self.path_limit("login_session", &actor.session_id)?,
        ));
        let trust = if trusted {
            let trust = crate::trusted::active_trust(
                &tx,
                &request.host_device_id,
                &request.controller_device_id,
                now,
            )?
            .ok_or(StorageError::Forbidden)?;
            if request
                .permissions
                .iter()
                .any(|permission| !trust.permissions.contains(permission))
            {
                return Err(StorageError::Forbidden);
            }
            paths = paths.intersection(PathSet::from_wire(&trust.paths)?);
            Some(trust)
        } else {
            None
        };
        if paths.is_empty() {
            return Err(StorageError::Forbidden);
        }
        let request_json = serde_json::to_string(&request)?;
        let existing: Option<(String, String, Option<u64>)> = self
            .connection
            .query_row(
                "SELECT controller_account_id,request_json,trust_revision FROM remote_requests WHERE id=?1",
                [&request.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((account, original, original_trust)) = existing {
            if account == actor.account_id
                && original == request_json
                && original_trust.is_some() == trusted
            {
                return self.remote(actor, &request.id);
            }
            return Err(StorageError::Conflict);
        }
        let pending:i64=self.connection.query_row("SELECT count(*) FROM remote_requests WHERE controller_account_id=?1 AND status='pending' AND expires>?2",params![actor.account_id,now],|r|r.get(0))?;
        if pending >= 8 {
            return Err(StorageError::RateLimited);
        }
        if trusted {
            let active:u64=tx.query_row("SELECT count(*) FROM remote_requests WHERE (controller_account_id=?1 OR host_device_id=?2) AND trust_revision IS NOT NULL AND status='approved' AND (last_renewed+15>?3 OR (lease_sequence=0 AND expires>?3))",params![actor.account_id,request.host_device_id,now],|r|r.get(0))?;
            if active >= 32 {
                return Err(StorageError::RateLimited);
            }
        }
        tx.execute("INSERT INTO remote_requests(id,controller_device_id,host_device_id,controller_account_id,permissions_json,paths_json,capability_sha256,nonce,policy_revision,expires,status,request_json,management_session_id,trust_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![request.id,request.controller_device_id,request.host_device_id,actor.account_id,serde_json::to_string(&request.permissions)?,serde_json::to_string(&paths.to_wire())?,digest(&serde_json::to_vec(&common)?),random_bytes::<32>(),revision,now+60,if trusted{"approved"}else{"pending"},request_json,actor.session_id,trust.map(|trust|trust.revision)])?;
        if trusted {
            tx.execute("INSERT INTO sessions(id,controller_device_id,host_device_id,connection_generation) VALUES(?1,?2,?3,1)",params![request.id,request.controller_device_id,request.host_device_id])?;
        }
        audit(
            &tx,
            if trusted {
                "remote_trusted"
            } else {
                "remote_requested"
            },
            &request.id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        self.remote(actor, &request.id)
    }
    pub fn remote(&self, actor: &Principal, id: &str) -> Result<RemoteView, StorageError> {
        require_id(id)?;
        let record:Option<RemoteRow>=self.connection.query_row("SELECT r.controller_device_id,r.host_device_id,r.permissions_json,r.paths_json,r.nonce,r.policy_revision,r.expires,r.status,r.lease_sequence,r.connection_generation,r.trust_revision,r.password_revision FROM remote_requests r JOIN devices h ON h.id=r.host_device_id WHERE r.id=?1 AND (r.controller_account_id=?2 OR h.account_id=?2)",params![id,actor.account_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?))).optional()?;
        let (
            c,
            h,
            permissions,
            paths,
            nonce,
            policy_revision,
            expires,
            status,
            lease_sequence,
            connection_generation,
            trust_revision,
            password_revision,
        ) = record.ok_or(StorageError::Forbidden)?;
        Ok(RemoteView {
            id: id.into(),
            controller_device_id: c,
            host_device_id: h,
            permissions: serde_json::from_str(&permissions)?,
            paths: serde_json::from_str(&paths)?,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            policy_revision,
            expires_at_unix_ms: expires * 1000,
            status,
            lease_sequence,
            connection_generation,
            trust_revision,
            password_revision,
        })
    }
    /// Reveal only the two public endpoint keys of an active, account-visible
    /// session. Cross-account approval does not expose either device directory.
    pub fn remote_peer_keys(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<RemotePeerKeys, StorageError> {
        let claims = self.current_permit(actor, id, now)?;
        let controller = self.device_record_at(&claims.controller_device_id, now)?;
        let host = self.device_record_at(&claims.host_device_id, now)?;
        Ok(RemotePeerKeys {
            session_id: claims.session_id,
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            controller_public_key: URL_SAFE_NO_PAD.encode(controller.public_key),
            host_public_key: URL_SAFE_NO_PAD.encode(host.public_key),
        })
    }

    pub fn pending_remote(&self, actor: &Principal) -> Result<Vec<RemoteView>, StorageError> {
        let mut statement=self.connection.prepare("SELECT r.id FROM remote_requests r JOIN devices h ON h.id=r.host_device_id WHERE h.account_id=?1 AND r.status='pending' ORDER BY r.expires LIMIT 100")?;
        let ids = statement
            .query_map([&actor.account_id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.remote(actor, id)).collect()
    }
    pub fn approval_transcript(
        &self,
        actor: &Principal,
        id: &str,
        choice: &ApprovalChoice,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        let view = self.remote(actor, id)?;
        let host = self.device_record_at(&view.host_device_id, now)?;
        if host.account != actor.account_id
            || view.status != "pending"
            || view.expires_at_unix_ms <= now * 1000
            || view.policy_revision != self.policy()?.0
        {
            return Err(StorageError::Forbidden);
        }
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Approve as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: actor.account_id.clone(),
            device_id: view.host_device_id,
            resource_id: id.into(),
            challenge: URL_SAFE_NO_PAD
                .decode(view.nonce)
                .map_err(|_| StorageError::Invalid("invalid nonce"))?,
            payload_sha256: digest(&serde_json::to_vec(choice)?).to_vec(),
            expires_at_unix_ms: view.expires_at_unix_ms,
        })
    }
    pub fn approve_remote(
        &mut self,
        actor: &Principal,
        id: &str,
        choice: ApprovalChoice,
        signature: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let transcript = self.approval_transcript(actor, id, &choice, now)?;
        let host = self.device_record_at(&transcript.device_id, now)?;
        verify_device_action(&transcript, &host.public_key, &decode_signature(signature)?)?;
        let view = self.remote(actor, id)?;
        if choice.approved {
            validate_permissions(&choice.permissions)?;
            PathSet::from_wire(&choice.paths)?;
            if choice
                .permissions
                .iter()
                .any(|p| !view.permissions.contains(p))
                || choice.paths.iter().any(|p| !view.paths.contains(p))
            {
                return Err(StorageError::Forbidden);
            }
        }
        let tx = self.connection.transaction()?;
        if tx.execute("UPDATE remote_requests SET status=?1,permissions_json=?2,paths_json=?3 WHERE id=?4 AND status='pending'",params![if choice.approved{"approved"}else{"rejected"},serde_json::to_string(&choice.permissions)?,serde_json::to_string(&choice.paths)?,id])?!=1{return Err(StorageError::Conflict);}
        if choice.approved {
            tx.execute("INSERT INTO sessions(id,controller_device_id,host_device_id,connection_generation) VALUES(?1,?2,?3,1)",params![id,view.controller_device_id,view.host_device_id])?;
        }
        audit(
            &tx,
            if choice.approved {
                "remote_approved"
            } else {
                "remote_rejected"
            },
            id,
            auditing::device(actor, &transcript.device_id),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn initial_permit(
        &mut self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<PermitClaims, StorageError> {
        self.check_request_login(id, now, Some(&actor.session_id))?;
        let view = self.remote(actor, id)?;
        let controller = self.device_record_at(&view.controller_device_id, now)?;
        if controller.account != actor.account_id
            || view.status != "approved"
            || view.expires_at_unix_ms <= now * 1000
        {
            return Err(StorageError::Forbidden);
        }
        if view.lease_sequence != 0 {
            let json: String = self.connection.query_row(
                "SELECT last_permit_json FROM remote_requests WHERE id=?1",
                [id],
                |r| r.get(0),
            )?;
            let claims: PermitClaims = serde_json::from_str(&json)?;
            self.device_record_at(&view.host_device_id, now)?;
            let controller_expiry = self.device_expiration_ms(&view.controller_device_id)?;
            let host_expiry = self.device_expiration_ms(&view.host_device_id)?;
            if claims.lease_sequence != 1
                || claims.expires_at_unix_ms <= now * 1000
                || controller_expiry.is_some_and(|expires| claims.expires_at_unix_ms > expires)
                || host_expiry.is_some_and(|expires| claims.expires_at_unix_ms > expires)
                || view.policy_revision != self.policy()?.0
                || !self.session_is_active_at(id, now)?
            {
                return Err(StorageError::Forbidden);
            }
            return Ok(claims);
        }
        self.issue_permit(actor, id, 1, now)
    }
    pub fn current_permit(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<PermitClaims, StorageError> {
        self.remote(actor, id)?; // Account visibility is independent of resource liveness.
        self.current_resource_permit(id, now.checked_mul(1000).ok_or(StorageError::Conflict)?)
    }
    pub(crate) fn current_resource_permit(
        &self,
        id: &str,
        now_ms: u64,
    ) -> Result<PermitClaims, StorageError> {
        self.check_request_login(id, now_ms / 1000, None)?;
        if !self.session_is_active_at(id, now_ms / 1000)? {
            return Err(StorageError::Forbidden);
        }
        let (status,sequence,revision,json):(String,u64,u64,Option<String>)=self.connection.query_row("SELECT status,lease_sequence,policy_revision,last_permit_json FROM remote_requests WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if status != "approved" || sequence == 0 || revision != self.policy()?.0 {
            return Err(StorageError::Forbidden);
        }
        let json = json.ok_or(StorageError::Forbidden)?;
        let claims: PermitClaims = serde_json::from_str(&json)?;
        claims.validate()?;
        let generation: u64 = self.connection.query_row("SELECT r.connection_generation FROM remote_requests r JOIN sessions s ON s.id=r.id WHERE r.id=?1 AND r.connection_generation=s.connection_generation", [id], |r| r.get(0))?;
        let controller = self.device_record_at(&claims.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&claims.host_device_id, now_ms / 1000)?;
        if claims.expires_at_unix_ms <= now_ms
            || claims.issued_at_unix_ms > now_ms
            || claims.security_epoch != self.security_epoch()?
            || claims.policy_revision != revision
            || claims.lease_sequence != sequence
            || claims.connection_generation != generation
            || claims.session_id != id
            || claims.deployment_id != self.deployment_id()?
            || claims.controller_key_sha256 != digest(&controller.public_key)
            || claims.host_key_sha256 != digest(&host.public_key)
            || claims.account_id != controller.account
        {
            return Err(StorageError::Forbidden);
        }
        Ok(claims)
    }
    pub fn renewal_transcript(
        &self,
        actor: &Principal,
        id: &str,
        sequence: u64,
        host: bool,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        self.check_request_login(id, now, Some(&actor.session_id))?;
        let current = self.current_permit(actor, id, now)?;
        let view = self.remote(actor, id)?;
        let controller = self.device_record_at(&view.controller_device_id, now)?;
        let endpoint = self.device_record_at(
            if host {
                &view.host_device_id
            } else {
                &view.controller_device_id
            },
            now,
        )?;
        let last: u64 = self.connection.query_row(
            "SELECT last_renewed FROM remote_requests WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        if controller.account != actor.account_id
            || view.status != "approved"
            || sequence != view.lease_sequence + 1
            || last == 0
            || now < last
            || now >= last + 15
        {
            return Err(StorageError::Forbidden);
        }
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Renew as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: endpoint.account,
            device_id: if host {
                view.host_device_id
            } else {
                view.controller_device_id
            },
            resource_id: id.into(),
            challenge: URL_SAFE_NO_PAD
                .decode(view.nonce)
                .map_err(|_| StorageError::Invalid("invalid nonce"))?,
            payload_sha256: digest(&sequence.to_be_bytes()).to_vec(),
            expires_at_unix_ms: current.expires_at_unix_ms,
        })
    }
    pub fn renew_permit(
        &mut self,
        actor: &Principal,
        id: &str,
        submission: RenewalSubmission,
        now: u64,
    ) -> Result<PermitClaims, StorageError> {
        let c = self.renewal_transcript(actor, id, submission.lease_sequence, false, now)?;
        let h = self.renewal_transcript(actor, id, submission.lease_sequence, true, now)?;
        verify_device_action(
            &c,
            &self.device_record_at(&c.device_id, now)?.public_key,
            &decode_signature(&submission.controller_signature)?,
        )?;
        verify_device_action(
            &h,
            &self.device_record_at(&h.device_id, now)?.public_key,
            &decode_signature(&submission.host_signature)?,
        )?;
        self.issue_permit(actor, id, submission.lease_sequence, now)
    }
    fn issue_permit(
        &mut self,
        actor: &Principal,
        id: &str,
        sequence: u64,
        now: u64,
    ) -> Result<PermitClaims, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.check_request_login(id, now, Some(&actor.session_id))?;
        let view = self.remote(actor, id)?;
        let c = self.device_record_at(&view.controller_device_id, now)?;
        let h = self.device_record_at(&view.host_device_id, now)?;
        if c.account != actor.account_id
            || !self.session_is_active_at(id, now)?
            || view.policy_revision != self.policy()?.0
        {
            return Err(StorageError::Forbidden);
        }
        let capability: Vec<u8> = self.connection.query_row(
            "SELECT capability_sha256 FROM remote_requests WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        let controller_expiry = self.device_expiration_ms(&view.controller_device_id)?;
        let host_expiry = self.device_expiration_ms(&view.host_device_id)?;
        let mut required_capabilities = vec!["vp8".to_owned()];
        if view.permissions.contains(&(Permission::Audio as i32)) {
            required_capabilities.push("opus".to_owned());
        }
        let claims = PermitClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            session_id: id.into(),
            account_id: actor.account_id.clone(),
            controller_device_id: view.controller_device_id,
            host_device_id: view.host_device_id,
            controller_key_sha256: digest(&c.public_key).to_vec(),
            host_key_sha256: digest(&h.public_key).to_vec(),
            resource_id: id.into(),
            permissions: view.permissions,
            paths: view.paths,
            policy_revision: view.policy_revision,
            connection_generation: view.connection_generation,
            lease_sequence: sequence,
            issued_at_unix_ms: now * 1000,
            expires_at_unix_ms: (now * 1000 + SESSION_LEASE_MS)
                .min(self.trust_expiration(id, now)?.unwrap_or(u64::MAX))
                .min(
                    self.remote_password_expiration(id, now)?
                        .unwrap_or(u64::MAX),
                )
                .min(controller_expiry.unwrap_or(u64::MAX))
                .min(host_expiry.unwrap_or(u64::MAX)),
            capability_sha256: capability,
            required_capabilities,
        };
        claims.validate()?;
        if tx.execute("UPDATE remote_requests SET lease_sequence=?1,last_renewed=?2,last_permit_json=?5 WHERE id=?3 AND lease_sequence=?4 AND status='approved'",params![sequence,now,id,sequence-1,serde_json::to_string(&claims)?])?!=1{return Err(StorageError::Conflict);}
        tx.execute("INSERT INTO leases(id,session_id,security_epoch) VALUES(?1,?1,?2) ON CONFLICT(id) DO UPDATE SET security_epoch=excluded.security_epoch WHERE leases.revoked=0",params![id,claims.security_epoch])?;
        if sequence == 1 {
            audit(&tx, "remote_permit_issued", id, auditing::management(actor))?;
        }
        tx.commit()?;
        Ok(claims)
    }
    pub fn revoke_remote(&mut self, actor: &Principal, id: &str) -> Result<(), StorageError> {
        self.remote(actor, id)?;
        let tx = self.connection.transaction()?;
        if tx.execute(
            "UPDATE remote_requests SET status='revoked' WHERE id=?1 AND status<>'revoked'",
            [id],
        )? == 0
        {
            return Ok(());
        }
        tx.execute("UPDATE sessions SET revoked=1 WHERE id=?1", [id])?;
        tx.execute("UPDATE leases SET revoked=1 WHERE session_id=?1", [id])?;
        audit(&tx, "remote_revoked", id, auditing::management(actor))?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn device_record_at(
        &self,
        id: &str,
        now: u64,
    ) -> Result<DeviceRecord, StorageError> {
        let row:Option<(String,Vec<u8>,String,String)>=self.connection.query_row("SELECT d.account_id,x.public_key,x.capabilities_json,x.path_mode FROM devices d JOIN device_details x ON x.device_id=d.id JOIN accounts a ON a.id=d.account_id WHERE d.id=?1 AND d.revoked=0 AND a.disabled=0 AND (d.expires_at IS NULL OR d.expires_at>?2)",params![id,now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let (account, key, capabilities, mode) = row.ok_or(StorageError::Forbidden)?;
        Ok(DeviceRecord {
            account,
            public_key: key
                .try_into()
                .map_err(|_| StorageError::Invalid("invalid stored key"))?,
            capabilities: serde_json::from_str(&capabilities)?,
            mode: parse_mode(&mode)?,
        })
    }
    pub(crate) fn device_expiration_ms(&self, id: &str) -> Result<Option<u64>, StorageError> {
        let expires: Option<u64> = self.connection.query_row(
            "SELECT expires_at FROM devices WHERE id=?1 AND revoked=0",
            [id],
            |r| r.get(0),
        )?;
        expires
            .map(|value| {
                value
                    .checked_mul(1000)
                    .filter(|millis| *millis <= i64::MAX as u64)
                    .ok_or(StorageError::Conflict)
            })
            .transpose()
    }
    pub(crate) fn check_request_login(
        &self,
        id: &str,
        now: u64,
        expected_session: Option<&str>,
    ) -> Result<(), StorageError> {
        let original:Option<String>=self.connection.query_row("SELECT m.id FROM remote_requests r JOIN management_sessions m ON m.id=r.management_session_id JOIN accounts a ON a.id=m.account_id JOIN deployment d ON d.singleton=1 WHERE r.id=?1 AND m.revoked=0 AND m.refresh_expires>?2 AND m.security_epoch=d.security_epoch AND a.disabled=0",params![id,now],|row|row.get(0)).optional()?;
        if original
            .as_ref()
            .is_none_or(|session| expected_session.is_some_and(|expected| session != expected))
        {
            return Err(StorageError::Forbidden);
        }
        self.trust_expiration(id, now)?;
        self.remote_password_expiration(id, now)?;
        Ok(())
    }
}
pub(crate) struct DeviceRecord {
    pub(crate) account: String,
    pub(crate) public_key: [u8; 32],
    pub(crate) capabilities: Vec<String>,
    mode: PeerPathMode,
}
pub(crate) fn parse_mode(value: &str) -> Result<PeerPathMode, StorageError> {
    match value {
        "direct_only" => Ok(PeerPathMode::DirectOnly),
        "direct_preferred" => Ok(PeerPathMode::DirectPreferred),
        "relay_only" => Ok(PeerPathMode::RelayOnly),
        _ => Err(StorageError::Invalid("invalid path mode")),
    }
}
fn mode_paths(mode: PeerPathMode) -> PathSet {
    match mode {
        PeerPathMode::DirectOnly => PathSet::DIRECT,
        PeerPathMode::DirectPreferred => PathSet::BOTH,
        PeerPathMode::RelayOnly => PathSet::RELAY,
    }
}
fn key(encoded: &str) -> Result<[u8; 32], StorageError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StorageError::Invalid("invalid key encoding"))?
        .try_into()
        .map_err(|_| StorageError::Invalid("invalid key length"))
}
pub(crate) fn decode_signature(encoded: &str) -> Result<Vec<u8>, StorageError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StorageError::Invalid("invalid signature encoding"))?;
    if bytes.len() != 64 {
        return Err(StorageError::Invalid("invalid signature length"));
    }
    Ok(bytes)
}
fn validate_descriptor(device: &DeviceDescriptor) -> Result<(), StorageError> {
    require_id(&device.id)?;
    key(&device.public_key)?;
    parse_mode(&device.path_mode)?;
    if device.name.is_empty()
        || device.name.len() > 128
        || device.name.chars().any(char::is_control)
        || !["windows", "linux-x11", "linux-wayland", "android", "web"]
            .contains(&device.platform.as_str())
        || device.capabilities.is_empty()
        || device.capabilities.len() > 32
        || device.capabilities.iter().enumerate().any(|(i, c)| {
            c.is_empty()
                || c.len() > 64
                || !c
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                || device.capabilities[..i].contains(c)
        })
    {
        return Err(StorageError::Invalid("invalid device descriptor"));
    }
    Ok(())
}
pub(crate) fn validate_permissions(permissions: &[i32]) -> Result<(), StorageError> {
    if permissions.is_empty()
        || permissions.len() > 7
        || permissions.iter().enumerate().any(|(i, p)| {
            !matches!(Permission::try_from(*p),Ok(v) if v!=Permission::Unspecified)
                || permissions[..i].contains(p)
        })
    {
        return Err(StorageError::Invalid("invalid permissions"));
    }
    Ok(())
}
