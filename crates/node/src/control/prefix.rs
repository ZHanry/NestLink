//! Explicit local approval and real TCP reachability for one exact host export.
//! This owner grants neither NetworkAccess nor permission to forward packets.
use super::{Error, NodeControl, sample};
use nestlink_protocol::{
    NodeLeaseClaims, api::NetworkNodeTopologyAuthority, network::IpPrefix,
    network_topology::TopologyPublisherClaims,
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle, time::Instant};

const PERIOD: Duration = Duration::from_millis(500);
const PROBE_BUDGET: Duration = Duration::from_millis(700);
const FRESH_MS: u64 = 1000;
const CHECK_PERIOD: Duration = Duration::from_millis(25);
const MAX_CLEANUP: Duration = Duration::from_secs(5);
// Mature Tokio permits bound physical probe tasks across all local choices.
// The physical task retains the permit; requesting abort cannot refund it.
static PROBE_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

/// A local administrator's choice is a concrete address and port, never a
/// remotely supplied hostname or a subnet scan. It is deliberately not Clone
/// or Deserialize; constructing it is the explicit local approval boundary.
pub struct LocalPrefixChoice {
    prefix: IpPrefix,
    target: SocketAddr,
}

impl LocalPrefixChoice {
    pub fn approve(prefix: IpPrefix, target: SocketAddr) -> Result<Self, Error> {
        prefix.validate()?;
        let host_bits = if prefix.network.is_ipv4() { 32 } else { 128 };
        if prefix.prefix_len != host_bits
            || prefix.network != target.ip()
            || target.port() == 0
            || matches!(target.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
        {
            return Err(Error::Configuration);
        }
        Ok(Self { prefix, target })
    }
}

#[derive(Clone)]
pub(super) struct PrefixEvidence {
    pub prefix: IpPrefix,
    pub expires_at_ms: u64,
    pub deadline_ms: u64,
    continuity: u64,
}

#[derive(Default)]
struct Measurement {
    terminal: bool,
    continuity: u64,
    evidence: Option<PrefixEvidence>,
}

impl Measurement {
    fn withdraw(&mut self) {
        if self.evidence.take().is_some() {
            // Saturation cannot restore an older observation: it is terminal.
            if let Some(next) = self.continuity.checked_add(1) {
                self.continuity = next;
            } else {
                self.terminal = true;
            }
        }
    }

    fn expire(&mut self, now: nestlink_session::ClockSample) {
        if self.evidence.as_ref().is_some_and(|evidence| {
            now.unix_ms >= evidence.expires_at_ms || now.monotonic_ms >= evidence.deadline_ms
        }) {
            self.withdraw();
        }
    }
}

struct Binding {
    control: Arc<NodeControl>,
    authority: NetworkNodeTopologyAuthority,
    lease: NodeLeaseClaims,
    expires_at_ms: u64,
    deadline_ms: u64,
    choice: LocalPrefixChoice,
}

impl Binding {
    fn matches(&self, control: &NodeControl, authority: &NetworkNodeTopologyAuthority) -> bool {
        let mut normalized = authority.clone();
        for (current, original) in normalized.neighbors.iter_mut().zip(&self.authority.neighbors) {
            current.expires_at_ms = original.expires_at_ms;
        }
        std::ptr::eq(Arc::as_ptr(&self.control), control) && normalized == self.authority
    }

    fn check(&self, control: &NodeControl, authority: &NetworkNodeTopologyAuthority) -> Result<(), Error> {
        if !self.matches(control, authority) {
            return Err(Error::Control);
        }
        control.check_network_topology_authority(&self.authority)?;
        let mut state = control.state.lock().map_err(|_| Error::Control)?;
        let now = sample(control.started)?;
        if !state.ready || *control.stopped.borrow() {
            return Err(Error::Control);
        }
        let lease = state.gate.current(now)?;
        if lease.deployment_id != self.lease.deployment_id
            || lease.node_id != self.lease.node_id
            || lease.node_key_sha256 != self.lease.node_key_sha256
            || lease.runtime_id != self.lease.runtime_id
            || lease.runtime_generation != self.lease.runtime_generation
            || lease.security_epoch != self.lease.security_epoch
            || lease.policy_revision != self.lease.policy_revision
            || lease.lease_sequence < self.lease.lease_sequence
            || now.unix_ms >= self.expires_at_ms
            || now.monotonic_ms >= self.deadline_ms
        {
            return Err(Error::Control);
        }
        Ok(())
    }
}

/// Owns one fixed, explicitly approved TCP probe task and its original current
/// delegation. Dropping this owner withdraws evidence and aborts its task;
/// successful `close` additionally proves that the physical task has joined.
pub struct LocalPrefixOwner {
    binding: Arc<Binding>,
    measurement: Arc<Mutex<Measurement>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    close_deadline: Option<Instant>,
    close_failure: Option<(io::ErrorKind, String)>,
}

impl LocalPrefixOwner {
    pub fn start(
        control: Arc<NodeControl>,
        authority: &NetworkNodeTopologyAuthority,
        choice: LocalPrefixChoice,
    ) -> Result<Self, Error> {
        control.check_network_topology_authority(authority)?;
        let claims = TopologyPublisherClaims::decode_canonical(&authority.publisher.claims)?;
        if !claims.allowed_prefixes.contains(&choice.prefix) {
            return Err(Error::Configuration);
        }
        let publisher_deadline = control.network_topology_observation_deadline(authority)?;
        let (lease, deadline_ms) = {
            let mut state = control.state.lock().map_err(|_| Error::Control)?;
            let now = sample(control.started)?;
            let lease = state.gate.current(now)?.clone();
            (lease, publisher_deadline.min(state.gate.deadline_ms()))
        };
        // The authenticated publisher's exact export proofs cap its expiry.
        // Neither a refreshed snapshot nor a renewed lease can move this cap.
        let binding = Arc::new(Binding {
            expires_at_ms: claims.scope.expires_at_ms.min(lease.expires_at_unix_ms),
            deadline_ms,
            lease,
            control,
            authority: authority.clone(),
            choice,
        });
        binding.check(&binding.control, authority)?;
        let slot = PROBE_SLOTS.try_acquire().map_err(|_| Error::Control)?;
        let measurement = Arc::new(Mutex::new(Measurement::default()));
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(binding.clone(), measurement.clone(), stopped, slot));
        Ok(Self {
            binding,
            measurement,
            stop,
            task: Some(task),
            close_deadline: None,
            close_failure: None,
        })
    }

    pub fn revoke(&self) {
        self.stop.send_replace(true);
        if let Ok(mut measurement) = self.measurement.lock() {
            measurement.terminal = true;
            measurement.withdraw();
        }
    }

    /// Current observed TCP reachability, suitable for local status displays.
    /// A true value is neither forwarding authority nor a future guarantee.
    pub fn is_reachable(&self) -> bool {
        self.evidence(&self.binding.control, &self.binding.authority).is_ok()
    }

    pub(super) fn evidence(
        &self,
        control: &NodeControl,
        authority: &NetworkNodeTopologyAuthority,
    ) -> Result<PrefixEvidence, Error> {
        if !self.binding.matches(control, authority) {
            return Err(Error::Control);
        }
        if self.binding.check(control, authority).is_err() || *self.stop.borrow() {
            self.revoke();
            return Err(Error::Control);
        }
        let mut measurement = self.measurement.lock().map_err(|_| Error::Control)?;
        measurement.expire(sample(control.started)?);
        if measurement.terminal {
            return Err(Error::Control);
        }
        measurement.evidence.clone().ok_or(Error::Control)
    }

    pub(super) fn check_evidence(
        &self,
        control: &NodeControl,
        authority: &NetworkNodeTopologyAuthority,
        original: &PrefixEvidence,
    ) -> Result<(), Error> {
        let current = self.evidence(control, authority)?;
        let now = sample(control.started)?;
        if current.prefix != original.prefix
            || current.continuity != original.continuity
            || now.unix_ms >= original.expires_at_ms
            || now.monotonic_ms >= original.deadline_ms
        {
            return Err(Error::Control);
        }
        Ok(())
    }

    /// Cancellation retains the original join handle and first cleanup
    /// deadline. A retry cannot mint a new cleanup budget or claim release
    /// merely because an abort request was sent.
    pub async fn close(&mut self, budget: Duration) -> io::Result<()> {
        self.revoke();
        if let Some((kind, message)) = &self.close_failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let deadline = *self
            .close_deadline
            .get_or_insert_with(|| Instant::now() + budget.min(MAX_CLEANUP));
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        task.abort();
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "local prefix probe release pending"));
        }
        let joined = tokio::time::timeout_at(deadline, task)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local prefix probe release pending"))?;
        self.task = None;
        if Instant::now() >= deadline {
            let message = "local prefix probe released after its cleanup deadline".to_owned();
            self.close_failure = Some((io::ErrorKind::TimedOut, message.clone()));
            return Err(io::Error::new(io::ErrorKind::TimedOut, message));
        }
        match joined {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => {
                let message = error.to_string();
                self.close_failure = Some((io::ErrorKind::Other, message.clone()));
                Err(io::Error::other(message))
            }
        }
    }
}

impl Drop for LocalPrefixOwner {
    fn drop(&mut self) {
        self.revoke();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run(
    binding: Arc<Binding>,
    measurement: Arc<Mutex<Measurement>>,
    mut stopped: watch::Receiver<bool>,
    slot: tokio::sync::SemaphorePermit<'static>,
) {
    let _slot = slot;
    let mut node_stopped = binding.control.stopped();
    let mut tick = tokio::time::interval(CHECK_PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let probes = probe_loop(&binding, &measurement);
    tokio::pin!(probes);
    loop {
        tokio::select! {
            biased;
            _ = stopped.changed() => break,
            _ = node_stopped.changed() => break,
            _ = tick.tick() => {
                if *stopped.borrow()
                    || *node_stopped.borrow()
                    || binding.check(&binding.control, &binding.authority).is_err()
                {
                    break;
                }
            }
            _ = &mut probes => break,
        }
    }
    if let Ok(mut measurement) = measurement.lock() {
        measurement.terminal = true;
        measurement.withdraw();
    }
}

async fn probe_loop(binding: &Binding, measurement: &Mutex<Measurement>) {
    loop {
        if binding.check(&binding.control, &binding.authority).is_err() {
            return;
        }
        let started = Instant::now();
        let Ok(now) = sample(binding.control.started) else {
            return;
        };
        // Tokio owns address selection and TCP cancellation. There is no
        // payload, DNS lookup, remote target selection or application tunnel.
        let result = tokio::time::timeout(
            PROBE_BUDGET,
            tokio::net::TcpStream::connect(binding.choice.target),
        )
        .await;
        let reachable = match result {
            Ok(Ok(stream)) => {
                drop(stream);
                true
            }
            _ => false,
        };
        if binding.check(&binding.control, &binding.authority).is_err() {
            return;
        }
        let Ok(completed) = sample(binding.control.started) else {
            return;
        };
        {
            let Ok(mut measurement) = measurement.lock() else {
                return;
            };
            measurement.expire(completed);
            if measurement.terminal {
                return;
            }
            if reachable {
                let Some(expires_at_ms) = now.unix_ms.checked_add(FRESH_MS) else {
                    return;
                };
                let Some(deadline_ms) = now.monotonic_ms.checked_add(FRESH_MS) else {
                    return;
                };
                let evidence = PrefixEvidence {
                    prefix: binding.choice.prefix,
                    expires_at_ms: expires_at_ms.min(binding.expires_at_ms),
                    deadline_ms: deadline_ms.min(binding.deadline_ms),
                    continuity: measurement.continuity,
                };
                if completed.unix_ms < evidence.expires_at_ms
                    && completed.monotonic_ms < evidence.deadline_ms
                {
                    measurement.evidence = Some(evidence);
                }
            } else {
                measurement.withdraw();
            }
        }
        tokio::time::sleep_until(started + PERIOD).await;
    }
}

#[cfg(test)]
mod tests;
