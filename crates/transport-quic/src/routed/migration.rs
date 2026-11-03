//! Actual original-inner endpoint rebind after candidate control driver release.
use super::*;
use crate::migration::{CommittedMigration, connection_binding};
use nestlink_protocol::network_migration::packet::Mode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct PathChange {
    pub previous_path_epoch: u64,
    pub path_epoch: u64,
    pub original_inner_stable_id: usize,
    pub inner_stable_id: usize,
    pub inner_tls_binding: [u8; 32],
    pub old_path_drain_limit_ms: u64,
    pub old_path_cleanup_ms: u64,
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
fn now_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

impl RoutedTransport {
    fn candidate_scope(&self, candidate: &Self) -> io::Result<()> {
        let original = self.raw.as_ref().ok_or_else(not_connected)?.authorization();
        let next = candidate
            .raw
            .as_ref()
            .ok_or_else(not_connected)?
            .authorization();
        original.check_live()?;
        next.check_live()?;
        if self.close_deadline.is_some()
            || candidate.close_deadline.is_some()
            || self.packet_hub.is_none()
            || candidate.packet_hub.is_none()
            || self.migration_mode != Some(Mode::Business(self.path_epoch))
            || candidate.migration_mode != Some(Mode::Control)
            || self.path_epoch == 0
            || original.migration_scope().is_none()
            || original.migration_scope() != next.migration_scope()
            || original.peers() != next.peers()
            || original.binding_digest() == next.binding_digest()
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Enable at most one bounded physical-loss hold only after the independent
    /// actual standby is prepared. No lease or candidate authority is renewed.
    pub fn arm_prepared_migration(&mut self, candidate: &Self) -> io::Result<()> {
        self.candidate_scope(candidate)?;
        self.gate.as_ref().ok_or_else(not_connected)?.arm()
    }
    pub fn path_epoch(&self) -> u64 {
        self.path_epoch
    }
    /// Advisory fact from the actual original receive/send gate. It grants no
    /// candidate permission and never extends the one original loss deadline.
    pub fn held_path_loss_deadline(&self) -> Option<Instant> {
        self.gate.as_ref()?.held_loss_deadline()
    }
    /// The caller transfers the actual candidate owner, not its socket clone.
    /// An incomplete future retains all original/candidate/draining receipts in
    /// this owner. The enclosing business owner must stop or resume cleanup.
    pub async fn migrate(
        &mut self,
        candidate: RoutedTransport,
        receipt: &CommittedMigration,
        deadline: Instant,
    ) -> io::Result<PathChange> {
        if self.pending_migration.is_some() || self.draining.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.pending_migration = Some(Box::new(candidate));
        self.migrate_pending(receipt, deadline).await
    }
    async fn migrate_pending(
        &mut self,
        receipt: &CommittedMigration,
        deadline: Instant,
    ) -> io::Result<PathChange> {
        let pending = self.pending_migration.as_ref().ok_or_else(not_connected)?;
        self.candidate_scope(pending)?;
        let binding = receipt.binding();
        let original = self.raw.as_ref().ok_or_else(not_connected)?.authorization();
        let next = pending
            .raw
            .as_ref()
            .ok_or_else(not_connected)?
            .authorization();
        let original_connection = self.connection()?;
        let stable_id = original_connection.stable_id();
        let exporter = connection_binding(original_connection)?;
        if !original
            .migration_scope()
            .is_some_and(|scope| scope.matches(binding))
            || binding.original_route != original.binding_digest()
            || binding.candidate_route != next.binding_digest()
            || binding.peers != original.peers()
            || binding.original_connection != exporter
            || binding.control_connection != connection_binding(pending.connection()?)?
            || binding.previous_path_epoch != self.path_epoch
            || self.path_epoch.checked_add(1) != Some(binding.next_path_epoch)
            || now_ms()? >= binding.expires_at_unix_ms
            || Instant::now() >= deadline
        {
            return Err(denied());
        }
        let deadline = deadline.min(original.deadline()).min(next.deadline());
        // Independent endpoint queues prevent an early original business CID
        // from reaching the still-running control endpoint on the other peer.
        let business = pending
            .packet_hub
            .as_ref()
            .ok_or_else(not_connected)?
            .view(Mode::Business(binding.next_path_epoch));
        let gate_authority = next.retained();
        let original_gate = self.gate.as_ref().ok_or_else(not_connected)?.clone();
        let sender = original_gate.failure_sender()?;
        let new_gate = migration_gate::Socket::new(business, gate_authority);
        new_gate.set_failure_sender(sender)?;
        let pending = self.pending_migration.as_mut().ok_or_else(not_connected)?;
        if let Some(connection) = &pending.connection {
            connection.close(0u32.into(), b"control transcript complete");
        }
        if let Some(endpoint) = &pending.endpoint {
            endpoint.close(0u32.into(), b"control endpoint detaching");
        }
        pending.connection = None;
        pending.endpoint = None;
        // This receipt belongs only to the control endpoint and its writable
        // pollers. The original raw carrier and both demux queues remain owned.
        wait_socket_released(&mut pending.released, deadline)
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("migration candidate endpoint release: {error}"),
                )
            })?;
        pending
            .raw
            .as_ref()
            .ok_or_else(not_connected)?
            .authorization()
            .check_live()?;
        self.raw
            .as_ref()
            .ok_or_else(not_connected)?
            .authorization()
            .check_live()?;
        if now_ms()? >= binding.expires_at_unix_ms || Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let (socket, released) = crate::service::socket::tracked(new_gate.clone());
        self.endpoint
            .as_ref()
            .ok_or_else(not_connected)?
            .rebind_abstract(socket)?;
        self.gate = Some(new_gate);
        let old_gate = original_gate;
        // Store both real tracked receipts immediately after rebind, before
        // any subsequent fallible gate operation can return to the caller.
        pending.released = self.released.replace(released);
        pending.gate = Some(old_gate.clone());
        // Old raw-path errors after commit cannot overwrite the current path's
        // lifecycle. Terminal business stop separately revokes every carrier.
        let (isolated, _) = tokio::sync::watch::channel(None);
        old_gate.set_failure_sender(isolated)?;
        let drain_until = old_gate.drain()?;
        // The draining owner and Quinn's previous socket now retain the gate.
        // A local clone also retains Hub -> raw -> outer Connection, so keeping
        // it across old.close_and_wait would prevent its physical UDP receipt
        // from completing until this very function returned.
        drop(old_gate);
        let began = Instant::now();
        std::mem::swap(&mut self.raw, &mut pending.raw);
        std::mem::swap(&mut self.packet_hub, &mut pending.packet_hub);
        std::mem::swap(&mut self.adjacency, &mut pending.adjacency);
        std::mem::swap(&mut self.receiver, &mut pending.receiver);
        pending.migration_mode = self.migration_mode;
        pending.path_epoch = self.path_epoch;
        self.migration_mode = Some(Mode::Business(binding.next_path_epoch));
        self.path_epoch = binding.next_path_epoch;
        self.draining = self.pending_migration.take();
        // No timer restart on cancellation: the deadline remains in old_gate.
        tokio::time::sleep_until(drain_until).await;
        if let Some(old) = &mut self.draining {
            old.close_and_wait_boxed(deadline).await.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("migration old carrier cleanup: {error}"),
                )
            })?;
        }
        self.draining = None;
        let connection = self.connection()?;
        if connection.stable_id() != stable_id || connection_binding(connection)? != exporter {
            return Err(denied());
        }
        Ok(PathChange {
            previous_path_epoch: binding.previous_path_epoch,
            path_epoch: self.path_epoch,
            original_inner_stable_id: stable_id,
            inner_stable_id: connection.stable_id(),
            inner_tls_binding: exporter,
            old_path_drain_limit_ms: u64::try_from(
                drain_until.saturating_duration_since(began).as_millis(),
            )
            .unwrap_or(u64::MAX),
            old_path_cleanup_ms: u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}
