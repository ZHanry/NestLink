//! Monotonic signed announcements and immutable request scope.
use crate::accounts::Principal;
use crate::{StorageError, Store};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{digest, verify_device_action};
use nestlink_protocol::api::{MediaAnnouncementSubmission, MediaApprovalChoice};
use nestlink_protocol::media_authority::{FrozenMediaScope, MediaAnnouncement, MediaDirection};
use nestlink_protocol::{DeviceAction, DeviceActionClaims, SCHEMA_VERSION};
use rusqlite::{OptionalExtension, params};

impl Store {
    pub fn media_announcement_transcript(
        &self,
        actor: &Principal,
        submission: &MediaAnnouncementSubmission,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        self.validate_management_session(actor, now)?;
        let a = &submission.announcement;
        a.validate(now.saturating_mul(1000))?;
        let device = self.device_record_at(&a.device_id, now)?;
        let role = match a.direction {
            MediaDirection::Encode => "host",
            MediaDirection::Decode => "controller",
        };
        if device.account != actor.account_id
            || !device.capabilities.iter().any(|v| v == role)
            || self.device_expiration_ms(&a.device_id)?.is_some()
        {
            return Err(StorageError::Forbidden);
        }
        let record:Option<(Vec<u8>,u64)>=self.connection.query_row(
            "SELECT nonce,expires FROM enrollment_challenges WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",
            params![submission.challenge_id,actor.account_id,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (nonce, expires) = record.ok_or(StorageError::Unauthorized)?;
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::AnnounceMedia as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: actor.account_id.clone(),
            device_id: a.device_id.clone(),
            resource_id: submission.challenge_id.clone(),
            challenge: nonce,
            payload_sha256: digest(&serde_json::to_vec(a)?).to_vec(),
            expires_at_unix_ms: expires.saturating_mul(1000),
        })
    }
    pub fn replace_media_announcement(
        &mut self,
        actor: &Principal,
        submission: MediaAnnouncementSubmission,
        now: u64,
    ) -> Result<(), StorageError> {
        let transcript = self.media_announcement_transcript(actor, &submission, now)?;
        let device = self.device_record_at(&transcript.device_id, now)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&submission.signature)
            .map_err(|_| StorageError::Invalid("invalid media signature"))?;
        verify_device_action(&transcript, &device.public_key, &signature)?;
        let a = submission.announcement;
        let json = serde_json::to_string(&a)?;
        if json.len() > 65536 {
            return Err(StorageError::Invalid("media announcement too large"));
        }
        let tx = self.connection.transaction()?;
        let previous:Option<(u64,u64,String)>=tx.query_row("SELECT revision,probe_generation,json FROM device_media_announcements WHERE device_id=?1 AND direction=?2",params![a.device_id,a.direction.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((revision, generation, json)) = previous {
            let old: MediaAnnouncement = serde_json::from_str(&json)?;
            if a.revision <= revision
                || a.probe.generation < generation
                || (a.probe.generation == generation
                    && (a.probe != old.probe
                        || (!a.formats.is_empty() && a.formats != old.formats)))
            {
                return Err(StorageError::Conflict);
            }
        }
        if tx.execute("UPDATE enrollment_challenges SET consumed=1 WHERE id=?1 AND account_id=?2 AND expires>?3 AND consumed=0",params![submission.challenge_id,actor.account_id,now])?!=1 {return Err(StorageError::Unauthorized);}
        tx.execute("INSERT INTO device_media_announcements(device_id,direction,revision,json,sha256,expires_at_unix_ms,probe_generation,action_json,signature) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(device_id,direction) DO UPDATE SET revision=excluded.revision,json=excluded.json,sha256=excluded.sha256,expires_at_unix_ms=excluded.expires_at_unix_ms,probe_generation=excluded.probe_generation,action_json=excluded.action_json,signature=excluded.signature",params![a.device_id,a.direction.as_str(),a.revision,json,digest(json.as_bytes()),a.expires_at_unix_ms,a.probe.generation,serde_json::to_string(&transcript)?,signature])?;
        crate::audit(
            &tx,
            "device_media_announced",
            &a.device_id,
            crate::auditing::device(actor, &a.device_id),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn media_announcement(
        &self,
        actor: &Principal,
        id: &str,
        direction: MediaDirection,
        now: u64,
    ) -> Result<Option<MediaAnnouncement>, StorageError> {
        self.validate_management_session(actor, now)?;
        let device = self.device_record_at(id, now)?;
        if device.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let Some(announcement) = self.stored_media_announcement(id, direction, now)? else {
            return Ok(None);
        };
        let now_ms = now.saturating_mul(1000);
        // Only expiry is relaxed for the authenticated management read. Validate
        // every other syntax/backend/set condition before returning absence.
        // Zero expiry still fails validation and cannot masquerade as missing.
        announcement.validate(now_ms.min(announcement.expires_at_unix_ms.saturating_sub(1)))?;
        if announcement.expires_at_unix_ms <= now_ms {
            return Ok(None);
        }
        Ok(Some(announcement))
    }
    pub(crate) fn current_media_announcement(
        &self,
        id: &str,
        direction: MediaDirection,
        now: u64,
    ) -> Result<Option<MediaAnnouncement>, StorageError> {
        let Some(announcement) = self.stored_media_announcement(id, direction, now)? else {
            return Ok(None);
        };
        announcement.validate(now.saturating_mul(1000))?;
        Ok(Some(announcement))
    }
    // Provenance, device liveness and identity verification are shared by both
    // reads. Management expiry handling must never catch an arbitrary error.
    fn stored_media_announcement(
        &self,
        id: &str,
        direction: MediaDirection,
        now: u64,
    ) -> Result<Option<MediaAnnouncement>, StorageError> {
        let device = self.device_record_at(id, now)?;
        let row:Option<(String,Vec<u8>,String,Vec<u8>)>=self.connection.query_row("SELECT json,sha256,action_json,signature FROM device_media_announcements WHERE device_id=?1 AND direction=?2",params![id,direction.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((json, hash, action_json, signature)) = row else {
            return Ok(None);
        };
        let action: DeviceActionClaims = serde_json::from_str(&action_json)?;
        if action.action != DeviceAction::AnnounceMedia as i32
            || action.device_id != id
            || action.account_id != device.account
            || action.security_epoch != self.security_epoch()?
            || action.deployment_id != self.deployment_id()?
            || action.payload_sha256 != digest(json.as_bytes())
        {
            return Err(StorageError::Forbidden);
        }
        verify_device_action(&action, &device.public_key, &signature)?;
        if digest(json.as_bytes()).as_slice() != hash {
            return Err(StorageError::Invalid("stored media digest mismatch"));
        }
        let a: MediaAnnouncement = serde_json::from_str(&json)?;
        if a.device_id != id || a.direction != direction {
            return Err(StorageError::Invalid("stored media identity mismatch"));
        }
        Ok(Some(a))
    }
    pub(crate) fn intersect_media(
        &self,
        controller: &str,
        host: &str,
        now: u64,
    ) -> Result<FrozenMediaScope, StorageError> {
        let c = self
            .current_media_announcement(controller, MediaDirection::Decode, now)?
            .ok_or(StorageError::Forbidden)?;
        let h = self
            .current_media_announcement(host, MediaDirection::Encode, now)?
            .ok_or(StorageError::Forbidden)?;
        let set = h
            .validate(now.saturating_mul(1000))?
            .intersection(&c.validate(now.saturating_mul(1000))?);
        let scope = FrozenMediaScope {
            version: 2,
            controller_revision: c.revision,
            host_revision: h.revision,
            formats: set
                .formats()
                .iter()
                .map(|f| f.encode())
                .collect::<Result<Vec<_>, _>>()?,
            sha256: set.digest().to_vec(),
        };
        scope.validate()?;
        Ok(scope)
    }
    pub fn remote_media_scope(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<Option<FrozenMediaScope>, StorageError> {
        self.validate_management_session(actor, now)?;
        self.remote(actor, id)?;
        self.frozen_media_scope(id)
    }
    pub(crate) fn frozen_media_scope(
        &self,
        id: &str,
    ) -> Result<Option<FrozenMediaScope>, StorageError> {
        let row: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT json,sha256 FROM remote_media_scopes WHERE request_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((json, hash)) = row else {
            return Ok(None);
        };
        let scope: FrozenMediaScope = serde_json::from_str(&json)?;
        scope.validate()?;
        if hash != scope.sha256 {
            return Err(StorageError::Invalid(
                "stored request media digest mismatch",
            ));
        }
        Ok(Some(scope))
    }
    pub(crate) fn require_media_still_available(
        &self,
        id: &str,
        scope: &FrozenMediaScope,
        now: u64,
    ) -> Result<(), StorageError> {
        let endpoints: (String, String) = self.connection.query_row(
            "SELECT controller_device_id,host_device_id FROM remote_requests WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let current = self
            .intersect_media(&endpoints.0, &endpoints.1, now)?
            .validate()?;
        if scope
            .validate()?
            .formats()
            .iter()
            .any(|f| !current.contains(f))
        {
            return Err(StorageError::Forbidden);
        }
        Ok(())
    }
    pub fn media_approval_transcript(
        &self,
        actor: &Principal,
        id: &str,
        choice: &MediaApprovalChoice,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        self.validate_management_session(actor, now)?;
        self.check_request_login(id, now, None)?;
        let scope = self
            .frozen_media_scope(id)?
            .ok_or(StorageError::Forbidden)?;
        if choice.media_format_sha256 != scope.sha256 {
            return Err(StorageError::Forbidden);
        }
        let mut claims = self.approval_transcript_base(actor, id, &choice.choice, now)?;
        // Separate signed shape binds explicit reviewed digest and frozen revisions.
        claims.payload_sha256 = digest(&serde_json::to_vec(&(
            "nestlink/media-approval/v2",
            choice,
            &scope,
        ))?)
        .to_vec();
        Ok(claims)
    }
}

impl Store {
    pub(crate) fn validate_issued_media_scope(
        &self,
        id: &str,
        claims: &nestlink_protocol::PermitClaims,
        now: u64,
    ) -> Result<(), StorageError> {
        claims.validate()?;
        match (
            nestlink_protocol::media_authority::permit_formats(claims)?,
            self.frozen_media_scope(id)?,
        ) {
            (None, None) => Ok(()),
            (Some(set), Some(scope)) => {
                if !self.media_issuance_enabled_for_request(id)
                    || set.digest().as_slice() != scope.sha256
                    || claims.media_formats != scope.formats
                {
                    return Err(StorageError::Forbidden);
                }
                self.require_media_still_available(id, &scope, now)
            }
            _ => Err(StorageError::Forbidden),
        }
    }
}

impl Store {
    pub(crate) fn media_issuance_enabled_for_request(&self, id: &str) -> bool {
        #[cfg(test)]
        {
            nestlink_protocol::media_authority::PRODUCTION_ISSUANCE_ENABLED
                || self.media_regression_requests.contains(id)
        }
        #[cfg(not(test))]
        {
            let _ = id;
            nestlink_protocol::media_authority::PRODUCTION_ISSUANCE_ENABLED
        }
    }
    /// Explicit test admission of one future request on this in-memory Store.
    /// It bypasses only the rollout flag, never a proof, scope or liveness check.
    #[cfg(test)]
    pub(crate) fn admit_media_regression_request(&mut self, id: &str) -> Result<(), StorageError> {
        if !nestlink_protocol::valid_id(id) || !self.connection.is_autocommit() {
            return Err(StorageError::Forbidden);
        }
        let database_file: String = self.connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )?;
        if !database_file.is_empty() {
            return Err(StorageError::Forbidden);
        }
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM remote_requests WHERE id=?1)",
            [id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(StorageError::Conflict);
        }
        self.media_regression_requests.insert(id.to_owned());
        Ok(())
    }
}
