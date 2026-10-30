//! Shared, durable allocation/endpoint reservations for combined and independent relays.
use crate::{StorageError, Store, accounts::Principal, auditing, require_id};
use nestlink_auth::random_id;
use nestlink_identity::{
    digest,
    relay::{allocation_transcript, session_binding},
    verify_device_action,
};
use nestlink_protocol::{
    NODE_LEASE_MS, NodeRole, Path, PermitClaims, RelayAllocationClaims, RelayTransport,
    SCHEMA_VERSION, SESSION_LEASE_MS,
    api::{RelayAllocationRequest, RelayHello, RelayQuota, RelayReservationUsage},
};
use rusqlite::{OptionalExtension, params};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
const HOLD_MARGIN_MS: u64 = 1000;
const MAX_HISTORY: u64 = 65536;

/// A process-local monotonic barrier prevents restore/restart from making
/// previously promised capacity available before all old leases can expire.
pub struct RelayLifecycle {
    pub runtime_id: String,
    epoch: u64,
    started: Instant,
    started_unix: u64,
    clock: Mutex<(u64, bool)>,
    fenced: bool,
}

impl RelayLifecycle {
    pub fn check_clock(&self, now_ms: u64) -> Result<(), StorageError> {
        let mut clock = self.clock.lock().map_err(|_| StorageError::Conflict)?;
        let elapsed: u64 = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| StorageError::Conflict)?;
        if clock.1
            || now_ms < clock.0
            || now_ms.saturating_sub(self.started_unix).abs_diff(elapsed) > HOLD_MARGIN_MS
        {
            clock.1 = true;
            return Err(StorageError::Conflict);
        }
        clock.0 = now_ms;
        Ok(())
    }
    pub fn ready(&self) -> bool {
        !self.fenced
            || self.started.elapsed() >= Duration::from_millis(SESSION_LEASE_MS + HOLD_MARGIN_MS)
    }
}
#[derive(Clone, Debug)]
pub struct CombinedReservation {
    pub allocation_id: String,
    pub connection_id: String,
    pub runtime_id: String,
    pub role: u8,
    pub quota_revision: u64,
}

impl Store {
    pub fn relay_lifecycle(&mut self, now_ms: u64) -> Result<RelayLifecycle, StorageError> {
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Conflict);
        }
        let tx = self.connection.unchecked_transaction()?;
        let restored: bool = self.connection.query_row(
            "SELECT restore_fenced FROM relay_reservation_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let prior: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_reservations WHERE closed=0) OR EXISTS(SELECT 1 FROM turn_grants WHERE closed=0) OR EXISTS(SELECT 1 FROM network_remote_relays)",
            [],
            |r| r.get(0),
        )?;
        let lifecycle = RelayLifecycle {
            runtime_id: random_id(),
            epoch: self.security_epoch()?,
            started: Instant::now(),
            started_unix: now_ms,
            clock: Mutex::new((now_ms, false)),
            fenced: restored || prior,
        };
        tx.execute("UPDATE relay_reservation_settings SET restore_fenced=?1,control_runtime_id=?2 WHERE singleton=1",params![lifecycle.fenced,lifecycle.runtime_id])?;
        tx.commit()?;
        Ok(lifecycle)
    }
    pub fn resume_relay_reservations(
        &self,
        lifecycle: &RelayLifecycle,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        lifecycle.check_clock(now_ms)?;
        if !lifecycle.ready() || lifecycle.epoch != self.security_epoch()? {
            return Err(StorageError::RateLimited);
        }
        let (fenced,runtime):(bool,Option<String>)=self.connection.query_row("SELECT restore_fenced,control_runtime_id FROM relay_reservation_settings WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if runtime.as_deref() != Some(&lifecycle.runtime_id) {
            return Err(StorageError::Conflict);
        }
        if fenced {
            // After a monotonic maximum-lease wait, old promises are physically
            // expired even when the restored snapshot's wall clock is ahead.
            self.connection.execute("DELETE FROM relay_reservation_connections WHERE reservation_id IN (SELECT id FROM relay_reservations WHERE control_runtime_id<>?1)",[&lifecycle.runtime_id])?;
            self.connection.execute("UPDATE relay_reservations SET closed=1,promised_until=?1 WHERE control_runtime_id<>?2",params![now_ms,lifecycle.runtime_id])?;
            self.connection.execute(
                "UPDATE turn_grants SET closed=1,promised_until=?1 WHERE control_runtime_id<>?2",
                params![now_ms, lifecycle.runtime_id],
            )?;
            self.connection.execute(
                "UPDATE network_remote_relays SET closed=1,promised_until=?1 WHERE control_runtime_id<>?2",
                params![now_ms, lifecycle.runtime_id],
            )?;
            self.connection.execute(
                "UPDATE relay_reservation_settings SET restore_fenced=0 WHERE singleton=1",
                [],
            )?;
        }
        Ok(())
    }
    fn held_until(expires: u64) -> Result<u64, StorageError> {
        expires
            .checked_add(HOLD_MARGIN_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)
    }
    pub(crate) fn reserve_capacity(
        &self,
        quota: &RelayQuota,
        controller: &str,
        host: &str,
        node: Option<(&str, u32)>,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let total: u32 = self.connection.query_row(
            "SELECT (SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1)+(SELECT count(*) FROM turn_grants WHERE promised_until>?1)",
            [now_ms],
            |r| r.get(0),
        )?;
        if total >= u32::from(quota.limits.max_allocations) {
            return Err(StorageError::RateLimited);
        }
        for account in [controller, host] {
            let held:u32=self.connection.query_row("SELECT (SELECT COALESCE(sum((controller_account_id=?1)+(host_account_id=?1)),0) FROM all_relay_capacity WHERE promised_until>?2)+(SELECT count(*) FROM turn_grants WHERE account_id=?1 AND promised_until>?2)",params![account,now_ms],|r|r.get(0))?;
            let added = if controller == host { 2 } else { 1 };
            if held
                .checked_add(added)
                .is_none_or(|n| n > u32::from(quota.limits.max_account_endpoints))
            {
                return Err(StorageError::RateLimited);
            }
        }
        if let Some((id, maximum)) = node {
            let held: u32 = self.connection.query_row(
                "SELECT (SELECT count(*)*2 FROM all_relay_capacity WHERE node_id=?1 AND promised_until>?2)+(SELECT count(*) FROM turn_grants WHERE node_id=?1 AND promised_until>?2)",
                params![id, now_ms],
                |r| r.get(0),
            )?;
            if held.checked_add(2).is_none_or(|n| n > maximum) {
                return Err(StorageError::RateLimited);
            }
        }
        if self
            .connection
            .query_row("SELECT count(*) FROM all_relay_capacity", [], |r| {
                r.get::<_, u64>(0)
            })?
            >= MAX_HISTORY
        {
            return Err(StorageError::RateLimited);
        }
        Ok(())
    }
    pub fn relay_reservation_usage(
        &self,
        actor: &Principal,
        now_ms: u64,
    ) -> Result<RelayReservationUsage, StorageError> {
        self.audit_admin(actor, now_ms / 1000)?;
        let (total,node,combined):(u32,u32,u32)=self.connection.query_row("SELECT count(*),COALESCE(sum(kind='node'),0),COALESCE(sum(kind='combined'),0) FROM all_relay_capacity WHERE promised_until>?1",[now_ms],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let turn: u32 = self.connection.query_row(
            "SELECT count(*) FROM turn_grants WHERE promised_until>?1",
            [now_ms],
            |r| r.get(0),
        )?;
        Ok(RelayReservationUsage {
            security_epoch: self.security_epoch()?,
            held_allocations: total + turn,
            held_endpoint_slots: total * 2 + turn,
            independent_allocations: node,
            combined_allocations: combined,
            turn_allocations: turn,
            restore_fenced: self.connection.query_row(
                "SELECT restore_fenced FROM relay_reservation_settings WHERE singleton=1",
                [],
                |r| r.get(0),
            )?,
        })
    }
    /// Verify endpoint possession and reserve both account slots in one transaction.
    pub fn reserve_combined_relay(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        session: &str,
        proof: (&RelayHello, &[u8]),
        now_ms: u64,
    ) -> Result<(PermitClaims, CombinedReservation, RelayQuota), StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        let (hello, nonce) = proof;
        let permit = self.authorize_relay(
            actor,
            session,
            &hello.device_id,
            nonce,
            &hello.signature,
            now_ms / 1000,
        )?;
        if permit.issued_at_unix_ms > now_ms || permit.expires_at_unix_ms <= now_ms {
            return Err(StorageError::Forbidden);
        }
        let controller = self.device_record_at(&permit.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&permit.host_device_id, now_ms / 1000)?;
        let quota = self.relay_quota_current()?;
        let binding = session_binding(&permit)?;
        // Expired orphan rows remain tombstones; no allocation ID is recycled.
        tx.execute(
            "UPDATE relay_reservations SET closed=1 WHERE kind='combined' AND promised_until<=?1",
            [now_ms],
        )?;
        type Existing = (String, u64, u64, Vec<u8>, u64);
        let existing:Option<Existing>=tx.query_row("SELECT id,security_epoch,quota_revision,binding_digest,promised_until FROM relay_reservations WHERE kind='combined' AND session_id=?1 AND runtime_id=?2 AND connection_generation=?3 AND closed=0",params![session,lifecycle.runtime_id,permit.connection_generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let allocation = if let Some((id, epoch, revision, old_binding, held)) = existing {
            if epoch != permit.security_epoch
                || revision != quota.revision
                || old_binding != binding
                || held <= now_ms
            {
                return Err(StorageError::Conflict);
            }
            id
        } else {
            self.reserve_capacity(&quota, &controller.account, &host.account, None, now_ms)?;
            let id = random_id();
            tx.execute("INSERT INTO relay_reservations(id,kind,session_id,security_epoch,controller_account_id,host_account_id,runtime_id,control_runtime_id,runtime_generation,connection_generation,policy_revision,quota_revision,binding_digest,promised_until) VALUES(?1,'combined',?2,?3,?4,?5,?6,?6,0,?7,?8,?9,?10,?11)",params![id,session,permit.security_epoch,controller.account,host.account,lifecycle.runtime_id,permit.connection_generation,permit.policy_revision,quota.revision,binding.as_slice(),Self::held_until(permit.expires_at_unix_ms)?])?;
            auditing::record(
                &tx,
                "relay_allocation_reserved",
                &id,
                auditing::device(actor, &hello.device_id),
            )?;
            id
        };
        let role = if hello.device_id == permit.controller_device_id {
            1
        } else {
            2
        };
        let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM relay_reservation_connections WHERE reservation_id=?1 AND role=?2 AND expires_at>?3)",params![allocation,role,now_ms],|r|r.get(0))?;
        if live {
            return Err(StorageError::Conflict);
        }
        let connection = random_id();
        tx.execute("INSERT INTO relay_reservation_connections(reservation_id,role,connection_id,lease_sequence,expires_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(reservation_id,role) DO UPDATE SET connection_id=excluded.connection_id,lease_sequence=excluded.lease_sequence,expires_at=excluded.expires_at",params![allocation,role,connection,permit.lease_sequence,permit.expires_at_unix_ms])?;
        tx.execute(
            "UPDATE relay_reservations SET promised_until=MAX(promised_until,?1) WHERE id=?2",
            params![Self::held_until(permit.expires_at_unix_ms)?, allocation],
        )?;
        tx.commit()?;
        Ok((
            permit,
            CombinedReservation {
                allocation_id: allocation,
                connection_id: connection,
                runtime_id: lifecycle.runtime_id.clone(),
                role,
                quota_revision: quota.revision,
            },
            quota,
        ))
    }
    /// Checks alone never extend a connection or its capacity promise.
    pub fn renew_combined_relay(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        reservation: &CombinedReservation,
        now_ms: u64,
    ) -> Result<(PermitClaims, RelayQuota), StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        self.validate_management_session(actor, now_ms / 1000)?;
        type Current = (String, u64, u64, Vec<u8>, u64, u64);
        let row:Option<Current>=tx.query_row("SELECT r.session_id,r.security_epoch,r.quota_revision,r.binding_digest,c.lease_sequence,c.expires_at FROM relay_reservations r JOIN relay_reservation_connections c ON c.reservation_id=r.id WHERE r.id=?1 AND r.kind='combined' AND r.runtime_id=?2 AND r.closed=0 AND c.role=?3 AND c.connection_id=?4",params![reservation.allocation_id,lifecycle.runtime_id,reservation.role,reservation.connection_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let (session, epoch, revision, binding, sequence, expires) =
            row.ok_or(StorageError::Conflict)?;
        let current = self.current_permit(actor, &session, now_ms / 1000)?;
        let quota = self.relay_quota_current()?;
        let device = if reservation.role == 1 {
            &current.controller_device_id
        } else {
            &current.host_device_id
        };
        if self.device_record_at(device, now_ms / 1000)?.account != actor.account_id
            || reservation.runtime_id != lifecycle.runtime_id
            || epoch != current.security_epoch
            || revision != quota.revision
            || revision != reservation.quota_revision
            || !current.paths.contains(&(Path::Relay as i32))
            || binding != session_binding(&current)?
            || current.lease_sequence < sequence
            || current.issued_at_unix_ms > now_ms
            || current.expires_at_unix_ms <= now_ms
            || expires <= now_ms
        {
            return Err(StorageError::Forbidden);
        }
        if reservation.role == 1 {
            self.check_request_login(&session, now_ms / 1000, Some(&actor.session_id))?;
        }
        if current.lease_sequence > sequence {
            tx.execute("UPDATE relay_reservation_connections SET lease_sequence=?1,expires_at=?2 WHERE reservation_id=?3 AND role=?4 AND connection_id=?5",params![current.lease_sequence,current.expires_at_unix_ms,reservation.allocation_id,reservation.role,reservation.connection_id])?;
            tx.execute(
                "UPDATE relay_reservations SET promised_until=MAX(promised_until,?1) WHERE id=?2",
                params![
                    Self::held_until(current.expires_at_unix_ms)?,
                    reservation.allocation_id
                ],
            )?;
        }
        tx.commit()?;
        Ok((current, quota))
    }
    /// Service-owned acknowledgment after the corresponding I/O futures end.
    /// Stale cleanup never deletes a replacement's connection or releases twice.
    pub fn close_combined_relay(
        &mut self,
        reservation: &CombinedReservation,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Conflict);
        }
        let tx = self.connection.unchecked_transaction()?;
        let removed=tx.execute("DELETE FROM relay_reservation_connections WHERE reservation_id=?1 AND role=?2 AND connection_id=?3 AND EXISTS(SELECT 1 FROM relay_reservations WHERE id=?1 AND kind='combined' AND runtime_id=?4)",params![reservation.allocation_id,reservation.role,reservation.connection_id,reservation.runtime_id])?;
        if removed == 1 {
            tx.execute("UPDATE relay_reservations SET closed=1,promised_until=MIN(promised_until,?1) WHERE id=?2 AND NOT EXISTS(SELECT 1 FROM relay_reservation_connections WHERE reservation_id=?2)",params![now_ms,reservation.allocation_id])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn reserve_node_relay(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        session: &str,
        request: RelayAllocationRequest,
        now_ms: u64,
    ) -> Result<RelayAllocationClaims, StorageError> {
        require_id(&request.allocation_id)?;
        require_id(&request.node_id)?;
        require_id(&request.device_id)?;
        self.validate_access(actor, now_ms / 1000)?;
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_remote_relays WHERE allocation_id=?1)",
            [&request.allocation_id],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(StorageError::Conflict);
        }
        let permit = self.current_permit(actor, session, now_ms / 1000)?;
        if permit.issued_at_unix_ms > now_ms || permit.expires_at_unix_ms <= now_ms {
            return Err(StorageError::Forbidden);
        }
        let endpoint = self.device_record_at(&request.device_id, now_ms / 1000)?;
        if endpoint.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if request.device_id == permit.controller_device_id {
            self.check_request_login(session, now_ms / 1000, Some(&actor.session_id))?;
        }
        let signature = super::control::decode_signature(&request.signature)?;
        verify_device_action(
            &allocation_transcript(
                &permit,
                &actor.account_id,
                &request.device_id,
                &request.allocation_id,
                &request.node_id,
            )?,
            &endpoint.public_key,
            &signature,
        )?;
        let controller = self.device_record_at(&permit.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&permit.host_device_id, now_ms / 1000)?;
        type Node = (Vec<u8>, String, u32, u64, Option<String>, u64, u64, u64);
        let node:Option<Node>=tx.query_row("SELECT public_key,roles_json,max_connections,bytes_per_second,runtime_id,runtime_generation,last_issued_at,lease_policy_revision FROM data_nodes WHERE id=?1 AND revoked=0",[&request.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let (key, roles, maximum, rate, runtime, generation, last, policy) =
            node.ok_or(StorageError::Forbidden)?;
        let roles: Vec<i32> = serde_json::from_str(&roles)?;
        if !roles.contains(&(NodeRole::NodeRelay as i32))
            || policy != permit.policy_revision
            || now_ms < last
            || now_ms >= last.saturating_add(NODE_LEASE_MS)
        {
            return Err(StorageError::Forbidden);
        }
        let runtime = runtime.ok_or(StorageError::Forbidden)?;
        let endpoints: Option<(u64, String)> = tx
            .query_row(
                "SELECT revision,endpoints_json FROM node_endpoints WHERE node_id=?1",
                [&request.node_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (node_endpoint_revision, transports) = if let Some((revision, json)) = endpoints {
            let e: nestlink_protocol::api::NodeEndpoints = serde_json::from_str(&json)?;
            e.validate()?;
            let mut transports = Vec::new();
            if e.quic_uri.is_some() {
                transports.push(RelayTransport::QuicDatagram as i32);
            }
            if e.wss_origin.is_some() {
                transports.push(RelayTransport::WssStream as i32);
            }
            if transports.is_empty() {
                return Err(StorageError::Forbidden);
            }
            (revision, transports)
        } else {
            (
                0,
                vec![
                    RelayTransport::QuicDatagram as i32,
                    RelayTransport::WssStream as i32,
                ],
            )
        };
        let quota = self.relay_quota_current()?;
        let binding = session_binding(&permit)?;
        let existing: Option<(String, bool, u64, Option<String>)> = tx
            .query_row(
                "SELECT kind,closed,promised_until,claims_json FROM relay_reservations WHERE id=?1",
                [&request.allocation_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let old = if let Some((kind, closed, _held, json)) = existing {
            if kind != "node" || closed {
                return Err(StorageError::Conflict);
            }
            let c: RelayAllocationClaims =
                serde_json::from_str(&json.ok_or(StorageError::Conflict)?)?;
            c.validate()?;
            if c.session_id != session
                || c.node_id != request.node_id
                || c.runtime_id != runtime
                || c.runtime_generation != generation
                || c.session_binding_sha256 != binding
                || c.quota_revision != quota.revision
                || c.node_endpoint_revision != node_endpoint_revision
                || c.transports != transports
                || c.expires_at_unix_ms <= now_ms
            {
                return Err(StorageError::Conflict);
            }
            if c.expires_at_unix_ms - now_ms >= 5000 {
                return Ok(c);
            }
            Some(c)
        } else {
            self.reserve_capacity(
                &quota,
                &controller.account,
                &host.account,
                Some((&request.node_id, maximum)),
                now_ms,
            )?;
            None
        };
        let expires = permit
            .expires_at_unix_ms
            .min(
                last.checked_add(NODE_LEASE_MS)
                    .ok_or(StorageError::Conflict)?,
            )
            .min(
                now_ms
                    .checked_add(NODE_LEASE_MS)
                    .ok_or(StorageError::Conflict)?,
            );
        if old
            .as_ref()
            .is_some_and(|c| expires <= c.expires_at_unix_ms)
        {
            return old.ok_or(StorageError::Conflict);
        }
        let c = RelayAllocationClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: permit.deployment_id,
            security_epoch: permit.security_epoch,
            allocation_id: request.allocation_id.clone(),
            session_id: session.into(),
            node_id: request.node_id,
            runtime_id: runtime,
            runtime_generation: generation,
            node_key_sha256: digest(&key).to_vec(),
            controller_device_id: permit.controller_device_id,
            host_device_id: permit.host_device_id,
            controller_key_sha256: permit.controller_key_sha256,
            host_key_sha256: permit.host_key_sha256,
            controller_account_id: controller.account,
            host_account_id: host.account,
            connection_generation: permit.connection_generation,
            policy_revision: permit.policy_revision,
            quota_revision: quota.revision,
            session_binding_sha256: binding.to_vec(),
            transports,
            node_endpoint_revision,
            grant_sequence: old.as_ref().map_or(Ok(1), |c| {
                c.grant_sequence
                    .checked_add(1)
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or(StorageError::Conflict)
            })?,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: expires,
            bytes_per_second: quota.limits.bytes_per_second.min(rate),
            bytes_per_allocation: quota.limits.bytes_per_allocation,
        };
        c.validate()?;
        let held = Self::held_until(expires)?;
        if old.is_some() {
            tx.execute("UPDATE relay_reservations SET promised_until=MAX(promised_until,?1),claims_json=?2 WHERE id=?3",params![held,serde_json::to_string(&c)?,c.allocation_id])?;
        } else {
            tx.execute("INSERT INTO relay_reservations(id,kind,session_id,security_epoch,controller_account_id,host_account_id,node_id,runtime_id,runtime_generation,connection_generation,policy_revision,quota_revision,binding_digest,promised_until,claims_json,control_runtime_id) VALUES(?1,'node',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",params![c.allocation_id,c.session_id,c.security_epoch,c.controller_account_id,c.host_account_id,c.node_id,c.runtime_id,c.runtime_generation,c.connection_generation,c.policy_revision,c.quota_revision,binding.as_slice(),held,serde_json::to_string(&c)?,lifecycle.runtime_id])?;
        }
        auditing::record(
            &tx,
            if old.is_some() {
                "relay_allocation_renewed"
            } else {
                "relay_allocation_reserved"
            },
            &c.allocation_id,
            auditing::device(actor, &request.device_id),
        )?;
        tx.commit()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests;
