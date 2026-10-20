use crate::{StorageError, Store, accounts::Principal};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{relay_transcript, signal_transcript, verify_device_action};
use nestlink_protocol::api::{SignalSubmission, SignalView};
use rusqlite::{OptionalExtension, params};

impl Store {
    /// Discover native offers for this account's enrolled host only. An offer
    /// is a wake-up hint; the host must still verify the permit and peer proof.
    pub fn ready_native_remote(
        &self,
        actor: &Principal,
        host_id: &str,
        now: u64,
    ) -> Result<Vec<nestlink_protocol::api::RemoteView>, StorageError> {
        self.validate_management_session(actor, now)?;
        let host = self.device_record_at(host_id, now)?;
        if host.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let mut statement = self.connection.prepare(
            "SELECT r.id FROM remote_requests r JOIN remote_signals s ON s.session_id=r.id AND s.device_id=r.controller_device_id WHERE r.host_device_id=?1 AND r.status='approved' AND r.expires>?2 AND s.received_at>=?3 ORDER BY s.received_at DESC,r.id LIMIT 32",
        )?;
        let ids = statement
            .query_map(params![host_id, now, now.saturating_sub(30)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut ready = Vec::new();
        for id in ids {
            // Revocation, login expiry and policy changes are checked again at
            // discovery. They are also checked during endpoint establishment.
            let Ok(permit) = self.current_permit(actor, &id, now) else {
                continue;
            };
            let signals = self.remote_signals(actor, &id, now)?;
            if signals.iter().any(|signal| {
                let payload = &signal.submission.payload;
                signal.submission.device_id == permit.controller_device_id
                    && payload.connection_generation == permit.connection_generation
                    && payload.lease_sequence == permit.lease_sequence
                    && payload.description.is_none()
                    && !payload.candidates.is_empty()
            }) {
                ready.push(self.remote(actor, &id)?);
            }
        }
        Ok(ready)
    }

    pub fn validate_management_session(
        &self,
        actor: &Principal,
        now: u64,
    ) -> Result<(), StorageError> {
        let active: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM management_sessions m JOIN accounts a ON a.id=m.account_id JOIN deployment d ON d.singleton=1 WHERE m.id=?1 AND m.account_id=?2 AND m.revoked=0 AND m.refresh_expires>?3 AND m.security_epoch=d.security_epoch AND a.disabled=0)",params![actor.session_id,actor.account_id,now],|r|r.get(0))?;
        if active {
            Ok(())
        } else {
            Err(StorageError::Unauthorized)
        }
    }
    pub fn authorize_relay(
        &self,
        actor: &Principal,
        id: &str,
        device_id: &str,
        nonce: &[u8],
        signature: &str,
        now: u64,
    ) -> Result<nestlink_protocol::PermitClaims, StorageError> {
        self.validate_management_session(actor, now)?;
        let permit = self.current_permit(actor, id, now)?;
        let device = self.device_record_at(device_id, now)?;
        if device.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if device_id == permit.controller_device_id {
            self.check_request_login(id, now, Some(&actor.session_id))?;
        }
        let proof = relay_transcript(&permit, &actor.account_id, device_id, nonce)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| StorageError::Invalid("invalid relay signature"))?;
        verify_device_action(&proof, &device.public_key, &signature)?;
        Ok(permit)
    }
    pub fn submit_signal(
        &mut self,
        actor: &Principal,
        id: &str,
        submission: SignalSubmission,
        now: u64,
    ) -> Result<(), StorageError> {
        let permit = self.current_permit(actor, id, now)?;
        let device = self.device_record_at(&submission.device_id, now)?;
        if device.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let proof = signal_transcript(
            &permit,
            &actor.account_id,
            &submission.device_id,
            &submission.payload,
        )?;
        let signature = URL_SAFE_NO_PAD
            .decode(&submission.signature)
            .map_err(|_| StorageError::Invalid("invalid signal signature"))?;
        verify_device_action(&proof, &device.public_key, &signature)?;
        // Relay candidates in signaling are signed hints only. Native clients
        // must map them back to a current signed node descriptor and dial only
        // a locally verified allocation route; the peer's address grants no
        // relay authority by itself.
        let view = SignalView {
            account_id: actor.account_id.clone(),
            public_key: URL_SAFE_NO_PAD.encode(device.public_key),
            submission,
        };
        let json = serde_json::to_string(&view)?;
        if json.len() > 98304 {
            return Err(StorageError::Invalid("signal exceeds storage budget"));
        }
        let payload = &view.submission.payload;
        let tx = self.connection.transaction()?;
        if let Some(answer) = payload
            .description
            .as_ref()
            .filter(|description| description.kind == "answer")
        {
            if view.submission.device_id != permit.host_device_id {
                return Err(StorageError::Forbidden);
            }
            let offer_json: Option<String> = tx
                .query_row(
                    "SELECT signal_json FROM remote_signals WHERE session_id=?1 AND device_id=?2",
                    params![id, permit.controller_device_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(offer_json) = offer_json else {
                return Err(StorageError::Conflict);
            };
            let offer_view: SignalView = serde_json::from_str(&offer_json)?;
            let current_offer = &offer_view.submission.payload;
            let is_current_offer = current_offer
                .description
                .as_ref()
                .is_some_and(|description| {
                    description.kind == "offer"
                        && answer.in_reply_to_sequence == Some(current_offer.description_sequence())
                });
            if offer_view.submission.device_id != permit.controller_device_id || !is_current_offer {
                return Err(StorageError::Conflict);
            }
        }
        let previous: Option<(u64,u64,u64,String)> = tx.query_row(
            "SELECT network_generation,sequence,lease_sequence,signal_json FROM remote_signals WHERE session_id=?1 AND device_id=?2",
            params![id,view.submission.device_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        if let Some((network, sequence, lease, original)) = previous {
            if original == json {
                return Ok(());
            }
            if payload.network_generation < network
                || payload.sequence <= sequence
                || payload.lease_sequence < lease
            {
                return Err(StorageError::Conflict);
            }
            let previous: SignalView = serde_json::from_str(&original)?;
            if network == payload.network_generation
                && (payload.ice.is_some() || previous.submission.payload.ice.is_some())
            {
                let old = &previous.submission.payload;
                if payload.description_sequence() != old.description_sequence()
                    || payload.description != old.description
                {
                    return Err(StorageError::Conflict);
                }
                let (Some(old_ice), Some(new_ice)) = (&old.ice, &payload.ice) else {
                    return Err(StorageError::Conflict);
                };
                let mut cursor = nestlink_protocol::ice::IceSnapshotCursor::default();
                cursor.apply(old_ice)?;
                cursor.apply(new_ice)?;
            }
        }
        let recent: Option<u64> = tx
            .query_row(
                "SELECT received_at FROM remote_signals WHERE session_id=?1 AND device_id=?2",
                params![id, view.submission.device_id],
                |r| r.get(0),
            )
            .optional()?;
        if recent.is_some_and(|last| now < last) {
            return Err(StorageError::Conflict);
        }
        tx.execute("INSERT INTO remote_signals(session_id,device_id,network_generation,sequence,lease_sequence,received_at,signal_json) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(session_id,device_id) DO UPDATE SET network_generation=excluded.network_generation,sequence=excluded.sequence,lease_sequence=excluded.lease_sequence,received_at=excluded.received_at,signal_json=excluded.signal_json",params![id,view.submission.device_id,payload.network_generation,payload.sequence,payload.lease_sequence,now,json])?;
        tx.execute("DELETE FROM remote_signals WHERE rowid IN (SELECT g.rowid FROM remote_signals g JOIN remote_requests r ON r.id=g.session_id WHERE r.status<>'approved' OR (r.expires<=?1 AND r.last_renewed<?2) ORDER BY g.rowid LIMIT 256)",params![now,now.saturating_sub(60)])?;
        tx.commit()?;
        Ok(())
    }
    pub fn cleanup_remote_signals(&mut self, now: u64) -> Result<usize, StorageError> {
        Ok(self.connection.execute("DELETE FROM remote_signals WHERE rowid IN (SELECT g.rowid FROM remote_signals g JOIN remote_requests r ON r.id=g.session_id WHERE r.status<>'approved' OR (r.expires<=?1 AND r.last_renewed<?2) ORDER BY g.rowid LIMIT 256)",params![now,now.saturating_sub(60)])?)
    }
    pub fn remote_signals(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<Vec<SignalView>, StorageError> {
        let permit = self.current_permit(actor, id, now)?;
        let mut statement = self.connection.prepare("SELECT signal_json FROM remote_signals WHERE session_id=?1 AND lease_sequence=?2 ORDER BY device_id LIMIT 2")?;
        let rows = statement
            .query_map(params![id, permit.lease_sequence], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.iter()
            .map(|json| Ok(serde_json::from_str(json)?))
            .collect()
    }
}
