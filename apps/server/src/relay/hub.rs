use super::{CHUNK, Output, failed};
use nestlink_auth::random_id;
use nestlink_protocol::api::{RelayQuota, RelayUsage};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

struct Slot {
    id: String,
    account: String,
    sender: mpsc::Sender<Output>,
    stop: watch::Sender<bool>,
}
struct Pair {
    controller: Option<Slot>,
    host: Option<Slot>,
    window: Instant,
    window_bytes: u64,
    total_bytes: u64,
}
struct State {
    quota: RelayQuota,
    pairs: HashMap<String, Pair>,
    runtime_id: String,
    report_sequence: u64,
    admitted_bytes: u64,
    closed_allocations: u64,
    failed: bool,
}
pub(crate) struct RelayHub {
    state: Mutex<State>,
}
pub(super) struct Registration {
    hub: Arc<RelayHub>,
    session: String,
    pub(super) id: String,
    pub(super) quota_revision: u64,
    pub(super) stopped: watch::Receiver<bool>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.hub.remove(&self.session, &self.id);
    }
}
fn stop_pair(pair: Pair) {
    for slot in [pair.controller, pair.host].into_iter().flatten() {
        let _ = slot.stop.send(true);
        let _ = slot.sender.try_send(Output::Stopped);
    }
}
impl State {
    fn advance(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(failed());
        }
        match self.report_sequence.checked_add(1) {
            Some(next) => {
                self.report_sequence = next;
                Ok(())
            }
            None => {
                self.failed = true;
                Err(failed())
            }
        }
    }
    fn synchronize(&mut self, quota: RelayQuota) -> io::Result<()> {
        if self.failed || !quota.limits.valid() || quota.revision == 0 {
            return Err(failed());
        }
        if quota.revision < self.quota.revision {
            return Ok(());
        }
        if quota.revision == self.quota.revision {
            return if quota == self.quota {
                Ok(())
            } else {
                Err(failed())
            };
        }
        let closed = self
            .closed_allocations
            .checked_add(self.pairs.len() as u64)
            .ok_or_else(failed)?;
        self.advance()?;
        self.quota = quota;
        self.closed_allocations = closed;
        for (_, pair) in self.pairs.drain() {
            stop_pair(pair);
        }
        Ok(())
    }
}
impl RelayHub {
    pub(crate) fn new(quota: RelayQuota) -> Self {
        Self {
            state: Mutex::new(State {
                quota,
                pairs: HashMap::new(),
                runtime_id: random_id(),
                report_sequence: 0,
                admitted_bytes: 0,
                closed_allocations: 0,
                failed: false,
            }),
        }
    }
    pub(crate) fn synchronize(&self, quota: RelayQuota) -> io::Result<()> {
        self.state.lock().map_err(|_| failed())?.synchronize(quota)
    }
    pub(crate) fn usage(&self) -> io::Result<RelayUsage> {
        let state = self.state.lock().map_err(|_| failed())?;
        if state.failed {
            return Err(failed());
        }
        Ok(RelayUsage {
            runtime_id: state.runtime_id.clone(),
            report_sequence: state.report_sequence,
            quota_revision: state.quota.revision,
            allocations: state.pairs.len() as u16,
            endpoints: state
                .pairs
                .values()
                .map(|p| u16::from(p.controller.is_some()) + u16::from(p.host.is_some()))
                .sum(),
            admitted_bytes: state.admitted_bytes,
            closed_allocations: state.closed_allocations,
        })
    }
    pub(super) fn register(
        self: &Arc<Self>,
        session: &str,
        account: &str,
        controller: bool,
        quota: RelayQuota,
    ) -> io::Result<(Registration, mpsc::Receiver<Output>)> {
        let mut state = self.state.lock().map_err(|_| failed())?;
        state.synchronize(quota)?;
        if quota.revision != state.quota.revision {
            return Err(failed());
        }
        let count = state
            .pairs
            .values()
            .flat_map(|p| [p.controller.as_ref(), p.host.as_ref()])
            .flatten()
            .filter(|s| s.account == account)
            .count();
        if count >= usize::from(quota.limits.max_account_endpoints)
            || (!state.pairs.contains_key(session)
                && state.pairs.len() >= usize::from(quota.limits.max_allocations))
        {
            return Err(failed());
        }
        if state.pairs.get(session).is_some_and(|p| {
            if controller {
                p.controller.is_some()
            } else {
                p.host.is_some()
            }
        }) {
            return Err(failed());
        }
        state.advance()?;
        let pair = state.pairs.entry(session.into()).or_insert_with(|| Pair {
            controller: None,
            host: None,
            window: Instant::now(),
            window_bytes: 0,
            total_bytes: 0,
        });
        let slot = if controller {
            &mut pair.controller
        } else {
            &mut pair.host
        };
        let id = random_id();
        let (sender, receiver) = mpsc::channel(8);
        let (stop, stopped) = watch::channel(false);
        *slot = Some(Slot {
            id: id.clone(),
            account: account.into(),
            sender,
            stop,
        });
        if let (Some(c), Some(h)) = (&pair.controller, &pair.host)
            && (c.sender.try_send(Output::Ready).is_err()
                || h.sender.try_send(Output::Ready).is_err())
        {
            if let Some(pair) = state.pairs.remove(session) {
                stop_pair(pair);
                state.closed_allocations =
                    state.closed_allocations.checked_add(1).ok_or_else(failed)?;
            }
            return Err(failed());
        }
        Ok((
            Registration {
                hub: self.clone(),
                session: session.into(),
                id,
                quota_revision: quota.revision,
                stopped,
            },
            receiver,
        ))
    }
    fn remove(&self, session: &str, id: &str) {
        if let Ok(mut state) = self.state.lock() {
            let matching = state.pairs.get(session).is_some_and(|p| {
                [p.controller.as_ref(), p.host.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|s| s.id == id)
            });
            if matching && let Some(pair) = state.pairs.remove(session) {
                if state.advance().is_err() {
                    state.failed = true;
                }
                match state.closed_allocations.checked_add(1) {
                    Some(next) => state.closed_allocations = next,
                    None => state.failed = true,
                }
                stop_pair(pair);
            }
        }
    }
    pub(super) fn destination(
        &self,
        session: &str,
        id: &str,
        size: usize,
    ) -> io::Result<mpsc::Sender<Output>> {
        if size == 0 || size > CHUNK {
            return Err(failed());
        }
        let mut state = self.state.lock().map_err(|_| failed())?;
        if state.failed {
            return Err(failed());
        }
        let next_sequence = state.report_sequence.checked_add(1).ok_or_else(failed)?;
        let next_bytes = state
            .admitted_bytes
            .checked_add(size as u64)
            .ok_or_else(failed)?;
        let limits = state.quota.limits;
        let pair = state.pairs.get_mut(session).ok_or_else(failed)?;
        if pair.window.elapsed() >= Duration::from_secs(1) {
            pair.window = Instant::now();
            pair.window_bytes = 0;
        }
        let count = size as u64;
        if pair.window_bytes.saturating_add(count) > limits.bytes_per_second
            || pair.total_bytes.saturating_add(count) > limits.bytes_per_allocation
        {
            return Err(failed());
        }
        let peer = if pair.controller.as_ref().is_some_and(|s| s.id == id) {
            pair.host.as_ref()
        } else if pair.host.as_ref().is_some_and(|s| s.id == id) {
            pair.controller.as_ref()
        } else {
            None
        }
        .ok_or_else(failed)?;
        let sender = peer.sender.clone();
        pair.window_bytes += count;
        pair.total_bytes += count;
        state.report_sequence = next_sequence;
        state.admitted_bytes = next_bytes;
        Ok(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use nestlink_protocol::api::RelayQuotaLimits;
    fn quota() -> RelayQuota {
        RelayQuota {
            revision: 1,
            limits: RelayQuotaLimits {
                max_allocations: 2,
                max_account_endpoints: 2,
                bytes_per_second: 10,
                bytes_per_allocation: 20,
            },
        }
    }
    #[tokio::test]
    async fn duplicate_endpoint_and_closed_peer_do_not_leave_an_allocation() -> io::Result<()> {
        let hub = Arc::new(RelayHub::new(quota()));
        let (controller, mut c) = hub.register("session", "controller", true, quota())?;
        assert!(
            hub.register("session", "controller", true, quota())
                .is_err()
        );
        let (host, mut h) = hub.register("session", "host", false, quota())?;
        assert!(matches!(c.recv().await, Some(Output::Ready)));
        assert!(matches!(h.recv().await, Some(Output::Ready)));
        hub.destination("session", &controller.id, 3)?
            .send(Output::Data(Bytes::from_static(b"tls")))
            .await
            .map_err(io::Error::other)?;
        assert!(matches!(h.recv().await,Some(Output::Data(b)) if b==b"tls"[..]));
        let usage = hub.usage()?;
        assert_eq!(
            (usage.allocations, usage.endpoints, usage.admitted_bytes),
            (1, 2, 3)
        );
        assert_eq!(hub.usage()?, usage);
        drop(host);
        assert!(matches!(c.recv().await, Some(Output::Stopped)));
        assert!(hub.destination("session", &controller.id, 1).is_err());
        assert_eq!(hub.usage()?.closed_allocations, 1);
        drop(controller);
        assert_eq!(hub.usage()?.closed_allocations, 1);
        Ok(())
    }
    #[tokio::test]
    async fn quota_revision_closes_waiting_and_paired_slots_without_reviving_old_registrations()
    -> io::Result<()> {
        let hub = Arc::new(RelayHub::new(quota()));
        let (old, mut output) = hub.register("same", "account", true, quota())?;
        let mut updated = quota();
        updated.revision = 2;
        updated.limits.max_allocations = 1;
        hub.synchronize(updated)?;
        assert!(matches!(output.recv().await, Some(Output::Stopped)));
        assert!(hub.register("same", "account", true, quota()).is_err());
        let (new, _) = hub.register("same", "account", true, updated)?;
        drop(old);
        assert_eq!(hub.usage()?.allocations, 1);
        hub.synchronize(quota())?;
        assert_eq!(hub.usage()?.quota_revision, 2);
        let mut conflict = updated;
        conflict.limits.bytes_per_second = 1;
        assert!(hub.synchronize(conflict).is_err());
        drop(new);
        Ok(())
    }
    #[test]
    fn limits_apply_to_combined_directions_and_rate_window_does_not_refund_total() -> io::Result<()>
    {
        let hub = Arc::new(RelayHub::new(quota()));
        let (c, _c_output) = hub.register("session", "account", true, quota())?;
        let (h, _h_output) = hub.register("session", "other", false, quota())?;
        hub.destination("session", &c.id, 6)?;
        hub.destination("session", &h.id, 4)?;
        assert!(hub.destination("session", &c.id, 1).is_err());
        hub.state
            .lock()
            .map_err(|_| failed())?
            .pairs
            .get_mut("session")
            .ok_or_else(failed)?
            .window = Instant::now() - Duration::from_secs(2);
        hub.destination("session", &h.id, 10)?;
        hub.state
            .lock()
            .map_err(|_| failed())?
            .pairs
            .get_mut("session")
            .ok_or_else(failed)?
            .window = Instant::now() - Duration::from_secs(2);
        assert!(hub.destination("session", &c.id, 1).is_err());
        assert_eq!(hub.usage()?.admitted_bytes, 20);
        let (_extra, _extra_output) = hub.register("extra", "account", true, quota())?;
        assert!(hub.register("overflow", "account", true, quota()).is_err());
        Ok(())
    }
    #[tokio::test]
    async fn full_payload_queue_cannot_hide_quota_revocation() -> io::Result<()> {
        let hub = Arc::new(RelayHub::new(quota()));
        let (mut waiting, _output) = hub.register("session", "account", true, quota())?;
        let sender = hub
            .state
            .lock()
            .map_err(|_| failed())?
            .pairs
            .get("session")
            .ok_or_else(failed)?
            .controller
            .as_ref()
            .ok_or_else(failed)?
            .sender
            .clone();
        for _ in 0..8 {
            sender
                .try_send(Output::Data(Bytes::from_static(b"queued")))
                .map_err(io::Error::other)?;
        }
        let mut changed = quota();
        changed.revision = 2;
        changed.limits.max_allocations = 0;
        hub.synchronize(changed)?;
        tokio::time::timeout(Duration::from_millis(100), waiting.stopped.changed())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert!(*waiting.stopped.borrow());
        assert!(hub.register("another", "account", true, changed).is_err());
        assert_eq!(hub.usage()?.allocations, 0);
        Ok(())
    }
}
