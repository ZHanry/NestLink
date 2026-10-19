//! Complete local display consent before starting a browser's short lease.
use crate::{StorageError, Store, accounts::Principal, audit, auditing};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{digest, verify_device_action};
use nestlink_protocol::{DeviceAction, DeviceActionClaims, SCHEMA_VERSION, api::*};
use rusqlite::params;

impl Store {
    fn browser_preparation_view(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<RemoteView, StorageError> {
        self.validate_management_session(actor, now)?;
        self.check_request_login(id, now, None)?;
        let view = self.remote(actor, id)?;
        self.device_record_at(&view.host_device_id, now)?;
        self.device_record_at(&view.controller_device_id, now)?;
        if view.status != "approved"
            || view.connection_generation == 0
            || view.expires_at_unix_ms <= now.saturating_mul(1000)
            || view.policy_revision != self.policy()?.0
            || !self.is_browser_controller(&view.controller_device_id)?
        {
            return Err(StorageError::Forbidden);
        }
        Ok(view)
    }

    pub(crate) fn is_browser_controller(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT platform='web' FROM device_details WHERE device_id=?1",
            [id],
            |row| row.get(0),
        )?)
    }

    pub fn ready_browser_remote(
        &self,
        actor: &Principal,
        host_id: &str,
        now: u64,
    ) -> Result<Vec<RemoteView>, StorageError> {
        self.validate_management_session(actor, now)?;
        if self.device_record_at(host_id, now)?.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let mut statement = self.connection.prepare(
            "SELECT r.id FROM remote_requests r JOIN device_details c ON c.device_id=r.controller_device_id WHERE r.host_device_id=?1 AND r.status='approved' AND r.lease_sequence=0 AND r.expires>?2 AND c.platform='web' ORDER BY r.expires,r.id LIMIT 32",
        )?;
        let ids = statement
            .query_map(params![host_id, now], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids
            .into_iter()
            .filter_map(|id| self.browser_preparation_view(actor, &id, now).ok())
            .collect())
    }

    pub fn browser_host_readiness(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<BrowserHostReadiness, StorageError> {
        let view = self.browser_preparation_view(actor, id, now)?;
        let ready = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM browser_host_readiness WHERE request_id=?1 AND connection_generation=?2 AND ready_until>?3)",
            params![id, view.connection_generation, now],
            |row| row.get(0),
        )?;
        Ok(BrowserHostReadiness {
            ready,
            connection_generation: view.connection_generation,
        })
    }

    pub fn browser_host_readiness_transcript(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<DeviceActionClaims, StorageError> {
        let view = self.browser_preparation_view(actor, id, now)?;
        if view.lease_sequence != 0
            || self.device_record_at(&view.host_device_id, now)?.account != actor.account_id
        {
            return Err(StorageError::Forbidden);
        }
        Ok(DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::PrepareBrowserHost as i32,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            account_id: actor.account_id.clone(),
            device_id: view.host_device_id,
            resource_id: view.id,
            challenge: URL_SAFE_NO_PAD
                .decode(view.nonce)
                .map_err(|_| StorageError::Invalid("invalid nonce"))?,
            payload_sha256: digest(&view.connection_generation.to_be_bytes()).to_vec(),
            expires_at_unix_ms: view.expires_at_unix_ms,
        })
    }

    pub fn mark_browser_host_ready(
        &mut self,
        actor: &Principal,
        id: &str,
        body: BrowserHostReadinessSubmission,
        now: u64,
    ) -> Result<BrowserHostReadiness, StorageError> {
        let proof = self.browser_host_readiness_transcript(actor, id, now)?;
        verify_device_action(
            &proof,
            &self.device_record_at(&proof.device_id, now)?.public_key,
            &crate::control::decode_signature(&body.signature)?,
        )?;
        let view = self.remote(actor, id)?;
        let tx = self.connection.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO browser_host_readiness VALUES(?1,?2,?3) ON CONFLICT(request_id) DO UPDATE SET connection_generation=excluded.connection_generation,ready_until=excluded.ready_until",
            params![id, view.connection_generation, view.expires_at_unix_ms / 1000],
        )?;
        audit(
            &tx,
            "browser_host_prepared",
            id,
            auditing::device(actor, &proof.device_id),
        )?;
        tx.commit()?;
        self.browser_host_readiness(actor, id, now)
    }
}
