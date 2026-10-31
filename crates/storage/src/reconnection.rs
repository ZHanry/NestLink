//! Both endpoint proofs, generation CAS and lost-response receipts share one transaction.
use crate::{StorageError, Store, accounts::Principal, audit, auditing, control::decode_signature};
use nestlink_identity::{reconnection, verify_device_action};
use nestlink_protocol::{
    PermitClaims,
    api::{ReconnectionApproval, ReconnectionOffer, ReconnectionState, ReconnectionSubmission},
};
use rusqlite::{OptionalExtension, params};

pub struct ReconnectionReceipt {
    pub previous: PermitClaims,
    pub next: PermitClaims,
    pub submission: ReconnectionSubmission,
}
impl Store {
    fn reconnection_access(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
        controller: bool,
    ) -> Result<PermitClaims, StorageError> {
        self.validate_management_session(actor, now)?;
        let current = self.current_permit(actor, id, now)?;
        if controller || actor.account_id == current.account_id {
            self.check_request_login(id, now, Some(&actor.session_id))?;
        }
        if controller && current.account_id != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        Ok(current)
    }
    fn verify_reconnection_proof(
        &self,
        previous: &PermitClaims,
        choice: &nestlink_protocol::api::ReconnectionChoice,
        host: bool,
        signature: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let id = if host {
            &previous.host_device_id
        } else {
            &previous.controller_device_id
        };
        let device = self.device_record_at(id, now)?;
        let transcript = reconnection::transcript(previous, id, choice)?;
        verify_device_action(
            &transcript,
            &device.public_key,
            &decode_signature(signature)?,
        )?;
        Ok(())
    }
    pub fn offer_reconnection(
        &mut self,
        actor: &Principal,
        id: &str,
        offer: ReconnectionOffer,
        now: u64,
    ) -> Result<(), StorageError> {
        self.offer_reconnection_at_ms(actor,id,offer,now.checked_mul(1000).ok_or(StorageError::Conflict)?)
    }
    pub fn offer_reconnection_at_ms(&mut self, actor: &Principal, id: &str, offer: ReconnectionOffer,
        now_ms: u64) -> Result<(), StorageError> {
        let now = now_ms / 1000;
        let tx = self.connection.unchecked_transaction()?;
        let current = self.reconnection_access(actor, id, now, true)?;
        self.verify_reconnection_proof(
            &current,
            &offer.choice,
            false,
            &offer.controller_signature,
            now,
        )?;
        self.validate_network_recovery_choice(&tx, &current, &offer.choice, now_ms)?;
        let previous: Option<(String, String)> = tx.query_row("SELECT previous_permit_json,offer_json FROM reconnection_offers WHERE session_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let json = serde_json::to_string(&offer)?;
        if let Some((permit, old)) = previous
            && serde_json::from_str::<PermitClaims>(&permit)? == current
        {
            if old == json {
                tx.commit()?;
                return Ok(());
            }
            return Err(StorageError::Conflict);
        }
        tx.execute("INSERT INTO reconnection_offers(session_id,previous_permit_json,offer_json) VALUES(?1,?2,?3) ON CONFLICT(session_id) DO UPDATE SET previous_permit_json=excluded.previous_permit_json,offer_json=excluded.offer_json,host_signature=NULL", params![id,serde_json::to_string(&current)?,json])?;
        audit(
            &tx,
            "remote_reconnection_offered",
            id,
            auditing::device(actor, &current.controller_device_id),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn approve_reconnection(
        &mut self,
        actor: &Principal,
        id: &str,
        approval: ReconnectionApproval,
        now: u64,
    ) -> Result<(), StorageError> {
        self.approve_reconnection_at_ms(actor,id,approval,now.checked_mul(1000).ok_or(StorageError::Conflict)?)
    }
    pub fn approve_reconnection_at_ms(&mut self, actor: &Principal, id: &str, approval: ReconnectionApproval,
        now_ms: u64) -> Result<(), StorageError> {
        let now = now_ms / 1000;
        let tx = self.connection.unchecked_transaction()?;
        // A same-account host may use its own login. Only the controller must use the original login.
        self.validate_management_session(actor, now)?;
        let current = self.current_permit(actor, id, now)?;
        if self.device_record_at(&current.host_device_id, now)?.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let row: Option<(String,String,Option<String>)> = tx.query_row("SELECT previous_permit_json,offer_json,host_signature FROM reconnection_offers WHERE session_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (previous, offer, recorded) = row.ok_or(StorageError::Conflict)?;
        let offer: ReconnectionOffer = serde_json::from_str(&offer)?;
        if serde_json::from_str::<PermitClaims>(&previous)? != current
            || offer.choice != approval.choice
        {
            return Err(StorageError::Conflict);
        }
        self.verify_reconnection_proof(
            &current,
            &approval.choice,
            true,
            &approval.host_signature,
            now,
        )?;
        self.validate_network_recovery_choice(&tx, &current, &approval.choice, now_ms)?;
        if let Some(recorded) = recorded {
            if recorded == approval.host_signature {
                tx.commit()?;
                return Ok(());
            }
            return Err(StorageError::Conflict);
        }
        tx.execute("UPDATE reconnection_offers SET host_signature=?2 WHERE session_id=?1 AND host_signature IS NULL", params![id,approval.host_signature])?;
        audit(
            &tx,
            "remote_reconnection_approved",
            id,
            auditing::device(actor, &current.host_device_id),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn receipt(&self, id: &str) -> Result<Option<ReconnectionReceipt>, StorageError> {
        let row: Option<(Vec<u8>,String,String,String)> = self.connection.query_row("SELECT request_sha256,previous_permit_json,next_permit_json,submission_json FROM reconnection_receipts WHERE session_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        row.map(|(hash, previous, next, submission)| {
            let receipt = ReconnectionReceipt {
                previous: serde_json::from_str(&previous)?,
                next: serde_json::from_str(&next)?,
                submission: serde_json::from_str(&submission)?,
            };
            if hash != reconnection::request_digest(&receipt.submission)? {
                return Err(StorageError::Conflict);
            }
            reconnection::validate_successor(
                &receipt.previous,
                &receipt.next,
                &receipt.submission.choice,
            )?;
            Ok(receipt)
        })
        .transpose()
    }
    pub fn reconnection_state(
        &self,
        actor: &Principal,
        id: &str,
        now: u64,
    ) -> Result<(ReconnectionState, Option<ReconnectionReceipt>), StorageError> {
        self.reconnection_state_at_ms(actor,id,now.checked_mul(1000).ok_or(StorageError::Conflict)?)
    }
    pub fn reconnection_state_at_ms(&self, actor: &Principal, id: &str, now_ms: u64)
        -> Result<(ReconnectionState,Option<ReconnectionReceipt>),StorageError> {
        let now = now_ms / 1000;
        self.validate_management_session(actor, now)?;
        let current = self.current_permit(actor, id, now)?;
        let row: Option<(String,String,Option<String>)> = self.connection.query_row("SELECT previous_permit_json,offer_json,host_signature FROM reconnection_offers WHERE session_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((previous, offer, host_signature)) = row
            && serde_json::from_str::<PermitClaims>(&previous)? == current
        {
            return Ok((
                ReconnectionState {
                    offer: Some(serde_json::from_str(&offer)?),
                    host_signature,
                    grant: None,
                },
                None,
            ));
        }
        if let Some(receipt) = self.receipt(id)?
            && receipt.next == current
        {
            let tx = self.connection.unchecked_transaction()?;
            self.validate_network_recovery_choice(&tx, &receipt.previous, &receipt.submission.choice, now_ms)?;
            tx.commit()?;
            let state = ReconnectionState {
                offer: Some(ReconnectionOffer {
                    choice: receipt.submission.choice.clone(),
                    controller_signature: receipt.submission.controller_signature.clone(),
                }),
                host_signature: Some(receipt.submission.host_signature.clone()),
                grant: None,
            };
            return Ok((state, Some(receipt)));
        }
        Ok((
            ReconnectionState {
                offer: None,
                host_signature: None,
                grant: None,
            },
            None,
        ))
    }
    pub fn reconnect_permit(
        &mut self,
        actor: &Principal,
        id: &str,
        submission: ReconnectionSubmission,
        now: u64,
    ) -> Result<ReconnectionReceipt, StorageError> {
        self.reconnect_permit_at_ms(actor,id,submission,now.checked_mul(1000).ok_or(StorageError::Conflict)?)
    }
    pub fn reconnect_permit_at_ms(&mut self, actor: &Principal, id: &str, submission: ReconnectionSubmission,
        now_ms: u64) -> Result<ReconnectionReceipt,StorageError> {
        let now = now_ms / 1000;
        let tx = self.connection.unchecked_transaction()?;
        let current = self.reconnection_access(actor, id, now, true)?;
        let request_digest = reconnection::request_digest(&submission)?;
        if let Some(receipt) = self.receipt(id)?
            && receipt.next == current
            && receipt.submission == submission
        {
            self.validate_network_recovery_choice(&tx, &receipt.previous, &submission.choice, now_ms)?;
            self.verify_reconnection_proof(
                &receipt.previous,
                &submission.choice,
                false,
                &submission.controller_signature,
                now,
            )?;
            self.verify_reconnection_proof(
                &receipt.previous,
                &submission.choice,
                true,
                &submission.host_signature,
                now,
            )?;
            tx.commit()?;
            return Ok(receipt);
        }
        self.verify_reconnection_proof(
            &current,
            &submission.choice,
            false,
            &submission.controller_signature,
            now,
        )?;
        self.verify_reconnection_proof(
            &current,
            &submission.choice,
            true,
            &submission.host_signature,
            now,
        )?;
        self.validate_network_recovery_choice(&tx, &current, &submission.choice, now_ms)?;
        let mut next = current.clone();
        next.connection_generation = submission.choice.connection_generation;
        next.lease_sequence = submission.choice.lease_sequence;
        next.issued_at_unix_ms = now.checked_mul(1000).ok_or(StorageError::Conflict)?;
        reconnection::validate_successor(&current, &next, &submission.choice)?;
        let next_json = serde_json::to_string(&next)?;
        if tx.execute("UPDATE remote_requests SET connection_generation=?2,lease_sequence=?3,last_renewed=?4,last_permit_json=?5 WHERE id=?1 AND status='approved' AND connection_generation=?6 AND lease_sequence=?7", params![id,next.connection_generation,next.lease_sequence,now,next_json,current.connection_generation,current.lease_sequence])? != 1 { return Err(StorageError::Conflict); }
        if tx.execute("UPDATE sessions SET connection_generation=?2 WHERE id=?1 AND connection_generation=?3 AND revoked=0", params![id,next.connection_generation,current.connection_generation])? != 1 { return Err(StorageError::Conflict); }
        tx.execute("DELETE FROM remote_signals WHERE session_id=?1", [id])?;
        tx.execute("INSERT INTO reconnection_receipts VALUES(?1,?2,?3,?4,?5) ON CONFLICT(session_id) DO UPDATE SET request_sha256=excluded.request_sha256,previous_permit_json=excluded.previous_permit_json,next_permit_json=excluded.next_permit_json,submission_json=excluded.submission_json", params![id,request_digest,serde_json::to_string(&current)?,next_json,serde_json::to_string(&submission)?])?;
        audit(
            &tx,
            "remote_reconnected",
            id,
            auditing::device(actor, &current.controller_device_id),
        )?;
        tx.commit()?;
        Ok(ReconnectionReceipt {
            previous: current,
            next,
            submission,
        })
    }
}
