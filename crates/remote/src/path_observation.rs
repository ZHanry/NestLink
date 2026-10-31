//! One read-only observer of the original proved inner Quinn connection. The
//! containing ChannelRuntime retains and joins its task alongside its original
//! carrier owner; observation never opens streams or extends a lease.
use crate::{LeaseControl, queues::Queue};
use nestlink_connectivity::observation::{
    LocalPathMeasurements, LocalQuicSample, PathObservationBinding, PathObservationSnapshot,
};
use nestlink_transport_stream::owner::TaskOwner;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;

const POLL_PERIOD: Duration = Duration::from_millis(500);

/// Cloning this handle retains only local measurements, never a Quinn
/// connection, task owner, admission capability or mutable watch sender.
#[derive(Clone)]
pub struct PathObservation {
    binding: Arc<PathObservationBinding>,
    measurements: watch::Receiver<LocalPathMeasurements>,
    terminal: watch::Receiver<Option<crate::StopReport>>,
    started: Instant,
    stopped: Arc<AtomicBool>,
}
impl PathObservation {
    pub fn binding(&self) -> &PathObservationBinding {
        &self.binding
    }
    /// Recompute freshness at read time, including when a stalled executor has
    /// emitted no new update. Closed/stopped owners expose no live metrics.
    pub fn snapshot(&self) -> PathObservationSnapshot {
        let stopped = self.stopped.load(Ordering::Acquire)
            || self.terminal.borrow().is_some()
            || self.terminal.has_changed().is_err()
            || self.measurements.has_changed().is_err();
        self.measurements
            .borrow()
            .snapshot(&self.binding, elapsed_ms(self.started), stopped)
    }
    /// The actual local ACK observation instant and currently fresh values.
    /// Cached reads keep the same time; terminal state returns None.
    pub fn timed_snapshot(&self) -> Option<(Instant, PathObservationSnapshot)> {
        let stopped = self.stopped.load(Ordering::Acquire)
            || self.terminal.borrow().is_some()
            || self.terminal.has_changed().is_err()
            || self.measurements.has_changed().is_err();
        if stopped { return None; }
        let measurements = self.measurements.borrow();
        let now_ms = elapsed_ms(self.started);
        let at_ms = measurements.rtt_observed_at_ms(now_ms)?;
        Some((self.started.checked_add(Duration::from_millis(at_ms))?,
            measurements.snapshot(&self.binding, now_ms, false)))
    }
    /// New samples and terminal sender closure wake observers. Read snapshot
    /// after either result so final state remains observable after cleanup.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        tokio::select! { biased;
            result = self.terminal.changed() => result,
            result = self.measurements.changed() => result,
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
struct StoppedOnDrop(Arc<AtomicBool>);
impl Drop for StoppedOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(crate) struct PathObservationOwner {
    observation: PathObservation,
    task: TaskOwner,
}
impl PathObservationOwner {
    pub(crate) fn start(
        binding: PathObservationBinding,
        connection: quinn::Connection,
        lease: &LeaseControl,
        business_tx: Arc<Queue>,
    ) -> Self {
        let started = Instant::now();
        let stopped = Arc::new(AtomicBool::new(false));
        let (sender, measurements) = watch::channel(LocalPathMeasurements::default());
        let mut terminal = lease.subscribe_stopped();
        let observation = PathObservation {
            binding: Arc::new(binding),
            measurements,
            terminal: terminal.clone(),
            started,
            stopped: stopped.clone(),
        };
        let task = TaskOwner::new(tokio::spawn(async move {
            let _stopped = StoppedOnDrop(stopped);
            let mut interval = tokio::time::interval(POLL_PERIOD);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                if terminal.borrow().is_some()
                    || terminal.has_changed().is_err()
                    || connection.close_reason().is_some()
                {
                    return;
                }
                tokio::select! { biased;
                    _ = terminal.changed() => return,
                    _ = connection.closed() => return,
                    _ = interval.tick() => {},
                }
                if terminal.borrow().is_some()
                    || terminal.has_changed().is_err()
                    || connection.close_reason().is_some()
                {
                    return;
                }
                let stats = connection.stats();
                let sample = LocalQuicSample {
                    rtt: connection.rtt(),
                    received_ack_frames: stats.frame_rx.acks,
                    sent_packets: stats.path.sent_packets,
                    lost_packets: stats.path.lost_packets,
                    business_tx_bytes: business_tx.business_transmitted_bytes(),
                };
                sender
                    .send_modify(|measurements| measurements.observe(elapsed_ms(started), sample));
            }
        }));
        Self { observation, task }
    }
    pub(crate) fn observation(&self) -> PathObservation {
        self.observation.clone()
    }
    pub(crate) fn request_close(&self) {
        self.observation.stopped.store(true, Ordering::Release);
        self.task.request_close();
    }
    pub(crate) async fn close_and_wait(&self, deadline: tokio::time::Instant) -> io::Result<()> {
        self.request_close();
        self.task.close_and_wait(deadline).await
    }
}
impl Drop for PathObservationOwner {
    fn drop(&mut self) {
        self.request_close();
    }
}
