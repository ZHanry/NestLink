//! Signed terminal facts may retire one exact promised relay allocation.
use crate::{StorageError, Store, audit, relay_reservations::RelayLifecycle};
use nestlink_identity::{digest, node_closes::verify_relay_close, relay::allocation_binding};
use nestlink_protocol::{
    RELAY_CLOSE_MESSAGE_BYTES, RelayAllocationClaims, RelayCloseAckClaims, RelayCloseClaims,
    SCHEMA_VERSION, SignedRelayClose, api::AuditActor, decode_bounded,
};
use prost::Message;
use rusqlite::{OptionalExtension, params};

impl Store {
    pub fn accept_relay_close(
        &mut self,
        lifecycle: &RelayLifecycle,
        signed: &SignedRelayClose,
        now_ms: u64,
    ) -> Result<RelayCloseAckClaims, StorageError> {
        let untrusted: RelayCloseClaims =
            decode_bounded(&signed.claims, RELAY_CLOSE_MESSAGE_BYTES)?;
        untrusted.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid relay close clock"));
        }
        lifecycle.check_clock(now_ms)?;
        let tx = self.connection.unchecked_transaction()?;
        type Reservation = (String, Vec<u8>, u64, bool, String, u64);
        let row: Option<Reservation> = tx.query_row(
            "SELECT r.claims_json,n.public_key,r.promised_until,r.closed,r.control_runtime_id,t.started_at FROM relay_reservations r JOIN data_nodes n ON n.id=r.node_id JOIN node_runtimes t ON t.node_id=r.node_id AND t.runtime_id=r.runtime_id AND t.generation=r.runtime_generation AND t.security_epoch=r.security_epoch WHERE r.id=?1 AND r.kind='node'",
            [&untrusted.allocation_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional()?;
        let (json, key, promised_until, closed, control_runtime, node_started) =
            row.ok_or(StorageError::Forbidden)?;
        let key: [u8; 32] = key.try_into().map_err(|_| StorageError::Conflict)?;
        let c = verify_relay_close(signed, &key)?;
        let grant: RelayAllocationClaims = serde_json::from_str(&json)?;
        grant.validate()?;
        if c.deployment_id != self.deployment_id()?
            || c.security_epoch != self.security_epoch()?
            || c.allocation_id != grant.allocation_id
            || c.deployment_id != grant.deployment_id
            || c.security_epoch != grant.security_epoch
            || c.node_id != grant.node_id
            || c.runtime_id != grant.runtime_id
            || c.runtime_generation != grant.runtime_generation
            || grant.node_key_sha256 != digest(&key)
            || c.allocation_binding_sha256 != allocation_binding(&grant)?
            || c.observed_grant_sequence > grant.grant_sequence
            || c.admitted_bytes > grant.bytes_per_allocation
            || c.closed_at_unix_ms < node_started
            || c.closed_at_unix_ms > now_ms.saturating_add(1000)
        {
            return Err(StorageError::Forbidden);
        }
        let close_digest = digest(&signed.claims);
        type PriorReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
        let prior: Option<PriorReceipt> = tx
            .query_row(
                "SELECT close_digest,close_claims,close_signature,ack_claims FROM relay_close_receipts WHERE allocation_id=?1",
                [&c.allocation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((hash, claims, signature, bytes)) = prior {
            if hash != close_digest || claims != signed.claims || signature != signed.signature {
                return Err(StorageError::Conflict);
            }
            let original: RelayCloseAckClaims = decode_bounded(&bytes, RELAY_CLOSE_MESSAGE_BYTES)?;
            original.validate()?;
            if original.close_sha256 != close_digest
                || original.allocation_id != c.allocation_id
                || original.deployment_id != c.deployment_id
                || original.security_epoch != c.security_epoch
                || original.node_id != c.node_id
                || original.runtime_id != c.runtime_id
                || original.runtime_generation != c.runtime_generation
                || original.accepted_at_unix_ms > now_ms
            {
                return Err(StorageError::Conflict);
            }
            return Ok(original);
        }
        if closed {
            return Err(StorageError::Conflict);
        }
        // Exact acknowledged facts survive a control restart. A new fact can
        // release only this live control owner's promise after its restore fence.
        self.resume_relay_reservations(lifecycle, now_ms)?;
        if control_runtime != lifecycle.runtime_id {
            return Err(StorageError::Forbidden);
        }
        let ack = RelayCloseAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            node_id: c.node_id.clone(),
            runtime_id: c.runtime_id.clone(),
            runtime_generation: c.runtime_generation,
            allocation_id: c.allocation_id.clone(),
            close_sha256: close_digest.to_vec(),
            accepted_at_unix_ms: now_ms,
            released_endpoint_slots: if promised_until > now_ms { 2 } else { 0 },
        };
        ack.validate()?;
        let changed=tx.execute("UPDATE relay_reservations SET closed=1,promised_until=MIN(promised_until,?1) WHERE id=?2 AND closed=0 AND control_runtime_id=?3",params![now_ms,c.allocation_id,lifecycle.runtime_id])?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        tx.execute("INSERT INTO relay_close_receipts(allocation_id,close_digest,close_claims,close_signature,accepted_at,ack_claims) VALUES(?1,?2,?3,?4,?5,?6)",params![c.allocation_id,close_digest.as_slice(),signed.claims,signed.signature,now_ms,ack.encode_to_vec()])?;
        audit(
            &tx,
            "node_relay_closed",
            &c.allocation_id,
            AuditActor::Node {
                node_id: c.node_id,
                runtime_id: c.runtime_id,
                runtime_generation: c.runtime_generation,
            },
        )?;
        tx.commit()?;
        Ok(ack)
    }
}
