//! Ownership spans DB response loss, handshake failure and cancelled I/O tasks.
use crate::{Store, now_ms};
use nestlink_storage::relay_reservations::CombinedReservation;
use std::sync::{Arc, Mutex};
pub(super) struct ReservedConnection {
    store: Arc<Mutex<Store>>,
    runtime: tokio::runtime::Handle,
    reservation: CombinedReservation,
}
impl ReservedConnection {
    pub(super) fn new(
        store: Arc<Mutex<Store>>,
        runtime: tokio::runtime::Handle,
        reservation: CombinedReservation,
    ) -> Self {
        Self {
            store,
            runtime,
            reservation,
        }
    }
    pub(super) fn reservation(&self) -> &CombinedReservation {
        &self.reservation
    }
}
impl Drop for ReservedConnection {
    fn drop(&mut self) {
        let store = self.store.clone();
        let reservation = self.reservation.clone();
        self.runtime.spawn_blocking(move || {
            if let (Ok(mut store), Ok(now)) = (store.lock(), now_ms()) {
                // Failure preserves the original bounded capacity promise.
                let _ = store.close_combined_relay(&reservation, now);
            }
        });
    }
}
