//! OS network notifications are facts that invalidate candidates, never grants.
pub mod path;
#[cfg(target_os = "android")]
use std::sync::{Arc, Mutex};
#[cfg(any(target_os = "android", test))]
use std::time::Instant;
use std::{io, time::Duration};
use tokio::{sync::watch, task::JoinHandle};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Started,
    Interface,
    Address,
    Route,
    Resumed,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkState {
    pub generation: u64,
    pub available: bool,
    pub reason: Reason,
}

/// Android's default-network observation from ConnectivityManager. Addresses,
/// routes, DNS and capabilities are carried as facts so an `available` flag
/// cannot stand in for an observed network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformNetworkFacts {
    pub network_handle: i64,
    pub interface_name: String,
    pub link_addresses: Vec<PlatformLinkAddress>,
    pub routes: Vec<PlatformRoute>,
    pub dns_servers: Vec<String>,
    pub has_internet: bool,
    pub validated: bool,
    pub not_metered: bool,
    pub not_restricted: bool,
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformLinkAddress {
    pub address: String,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformRoute {
    pub destination: String,
    pub prefix_length: u8,
    pub gateway: Option<String>,
}

#[cfg(any(target_os = "android", test))]
struct AndroidObservationTracker {
    state: NetworkState,
    facts: Option<PlatformNetworkFacts>,
    clocks: Option<(u64, u64)>,
    last_observation: Option<Instant>,
}

#[cfg(any(target_os = "android", test))]
impl AndroidObservationTracker {
    fn new() -> Self {
        Self {
            state: NetworkState {
                generation: 1,
                available: false,
                reason: Reason::Unavailable,
            },
            facts: None,
            clocks: None,
            last_observation: None,
        }
    }

    #[cfg(target_os = "android")]
    fn observe(
        &mut self,
        facts: Option<PlatformNetworkFacts>,
        observer_active: bool,
        elapsed_realtime_ms: u64,
        uptime_ms: u64,
    ) -> Option<NetworkState> {
        self.observe_at(
            facts,
            observer_active,
            elapsed_realtime_ms,
            uptime_ms,
            Instant::now(),
        )
    }

    fn observe_at(
        &mut self,
        facts: Option<PlatformNetworkFacts>,
        observer_active: bool,
        elapsed_realtime_ms: u64,
        uptime_ms: u64,
        now: Instant,
    ) -> Option<NetworkState> {
        let observation_expired = self.last_observation.is_some_and(|observed| {
            self.state.available
                && now.saturating_duration_since(observed) >= ANDROID_OBSERVATION_TIMEOUT
        });
        let mut resumed = false;
        if let Some((previous_elapsed, previous_uptime)) = self.clocks {
            match (
                elapsed_realtime_ms.checked_sub(previous_elapsed),
                uptime_ms.checked_sub(previous_uptime),
            ) {
                (Some(elapsed), Some(awake)) => {
                    resumed = elapsed.saturating_sub(awake) > 200;
                }
                _ => {
                    self.clocks = Some((elapsed_realtime_ms, uptime_ms));
                    self.facts = None;
                    self.last_observation = None;
                    return self.advance(false, Reason::Unavailable);
                }
            }
        }
        self.clocks = Some((elapsed_realtime_ms, uptime_ms));

        let usable_facts = facts.filter(|facts| facts.is_usable());
        if !observer_active || usable_facts.is_none() {
            self.facts = None;
            self.last_observation = None;
            return self.advance(false, Reason::Unavailable);
        }

        let usable_facts = usable_facts?;
        let facts_changed = self.facts.as_ref() != Some(&usable_facts);
        self.facts = Some(usable_facts);
        self.last_observation = Some(now);
        if resumed {
            self.advance(true, Reason::Resumed)
        } else if observation_expired || facts_changed || !self.state.available {
            self.advance(true, Reason::Route)
        } else {
            None
        }
    }

    fn expire_if_stale(&mut self, now: Instant) -> Option<NetworkState> {
        let stale = self.last_observation.is_some_and(|observed| {
            now.saturating_duration_since(observed) >= ANDROID_OBSERVATION_TIMEOUT
        });
        if !stale {
            return None;
        }
        self.last_observation = None;
        self.facts = None;
        self.advance(false, Reason::Unavailable)
    }

    fn advance(&mut self, available: bool, reason: Reason) -> Option<NetworkState> {
        if !available && !self.state.available {
            return None;
        }
        let Some(generation) = self
            .state
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= i64::MAX as u64)
        else {
            self.state.available = false;
            self.state.reason = Reason::Unavailable;
            self.facts = None;
            return Some(self.state);
        };
        self.state = NetworkState {
            generation,
            available,
            reason: if available {
                reason
            } else {
                Reason::Unavailable
            },
        };
        Some(self.state)
    }
}

#[cfg(any(target_os = "android", test))]
impl PlatformNetworkFacts {
    fn is_usable(&self) -> bool {
        if self.network_handle <= 0
            || self.interface_name.is_empty()
            || self.interface_name.len() > 64
            || !self
                .interface_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || !self.has_internet
            || !self.not_restricted
            || self.link_addresses.is_empty()
            || self.routes.is_empty()
            || self.dns_servers.is_empty()
            || self.link_addresses.len() > 64
            || self.routes.len() > 128
            || self.dns_servers.len() > 16
            || self.transports.len() > 8
            || self.transports.iter().any(|transport| {
                transport.is_empty()
                    || transport.len() > 32
                    || !transport
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            })
        {
            return false;
        }

        let mut addresses = Vec::with_capacity(self.link_addresses.len());
        for address in &self.link_addresses {
            let Some(ip) = parse_platform_ip(&address.address) else {
                return false;
            };
            let maximum = if ip.is_ipv4() { 32 } else { 128 };
            if address.prefix_length > maximum
                || ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
            {
                return false;
            }
            addresses.push(ip);
        }

        let routes_are_valid = self.routes.iter().all(|route| {
            let Some(destination) = parse_platform_ip(&route.destination) else {
                return false;
            };
            let maximum = if destination.is_ipv4() { 32 } else { 128 };
            route.prefix_length <= maximum
                && route.gateway.as_deref().is_none_or(|gateway| {
                    parse_platform_ip(gateway)
                        .is_some_and(|gateway| gateway.is_ipv4() == destination.is_ipv4())
                })
        });
        if !routes_are_valid {
            return false;
        }

        let has_matching_default_route = self.routes.iter().any(|route| {
            let Some(destination) = parse_platform_ip(&route.destination) else {
                return false;
            };
            route.prefix_length == 0
                && destination.is_unspecified()
                && addresses
                    .iter()
                    .any(|address| address.is_ipv4() == destination.is_ipv4())
        });
        if !has_matching_default_route {
            return false;
        }

        self.dns_servers.iter().all(|server| {
            parse_platform_ip(server)
                .is_some_and(|address| !address.is_unspecified() && !address.is_multicast())
        })
    }
}

#[cfg(any(target_os = "android", test))]
fn parse_platform_ip(value: &str) -> Option<std::net::IpAddr> {
    value
        .split('%')
        .next()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
}
/// One monitor per daemon; watch retains one latest value regardless of event
/// flood. Each endpoint captures a baseline before constructing its sockets.
pub struct NetworkMonitor {
    sender: watch::Sender<NetworkState>,
    task: JoinHandle<()>,
    #[cfg(windows)]
    _registration: windows::Registration,
    #[cfg(target_os = "android")]
    android_observation: Arc<Mutex<AndroidObservationTracker>>,
}
impl NetworkMonitor {
    #[cfg(any(windows, target_os = "linux"))]
    pub fn start() -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let (sender, _) = watch::channel(NetworkState {
            generation: 1,
            available: true,
            reason: Reason::Started,
        });
        #[cfg(windows)]
        let clocks = windows::clocks()?;
        #[cfg(target_os = "linux")]
        let clocks = linux::clocks()?;
        #[cfg(windows)]
        let registration = windows::Registration::new(sender.clone())?;
        #[cfg(windows)]
        let task = tokio::spawn(windows::run(sender.clone(), clocks));
        #[cfg(target_os = "linux")]
        let socket = linux::subscribe()?;
        #[cfg(target_os = "linux")]
        let task = tokio::spawn(linux::run(socket, sender.clone(), clocks));
        Ok(Self {
            sender,
            task,
            #[cfg(windows)]
            _registration: registration,
        })
    }
    /// Android reports ConnectivityManager facts through JNI. A bounded
    /// watchdog expires observations if Kotlin stops sending fresh snapshots;
    /// callbacks and Activity lifecycle events alone do not prove the observer
    /// is still alive.
    #[cfg(target_os = "android")]
    pub fn start() -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let (sender, _) = watch::channel(NetworkState {
            generation: 1,
            available: false,
            reason: Reason::Unavailable,
        });
        let android_observation = Arc::new(Mutex::new(AndroidObservationTracker::new()));
        let watchdog_observation = android_observation.clone();
        let watchdog_sender = sender.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(ANDROID_WATCHDOG_INTERVAL);
            loop {
                interval.tick().await;
                let state = match watchdog_observation.lock() {
                    Ok(mut tracker) => tracker.expire_if_stale(Instant::now()),
                    Err(_) => {
                        changed(&watchdog_sender, Reason::Unavailable);
                        None
                    }
                };
                if let Some(state) = state {
                    watchdog_sender.send_replace(state);
                }
            }
        });
        Ok(Self {
            sender,
            task,
            android_observation,
        })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    pub fn start() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "desktop network monitor requires Windows or Linux; Android uses platform lifecycle facts",
        ))
    }
    /// Report Android's observed default-network facts and dual monotonic
    /// clocks. A fact change, lost observer, invalid snapshot, clock rollback,
    /// or suspend advances the generation so current leases and pending dials
    /// cannot survive on an old network observation.
    pub fn report_platform_facts(
        &self,
        facts: Option<PlatformNetworkFacts>,
        observer_active: bool,
        elapsed_realtime_ms: u64,
        uptime_ms: u64,
    ) {
        #[cfg(target_os = "android")]
        {
            let Ok(mut tracker) = self.android_observation.lock() else {
                changed(&self.sender, Reason::Unavailable);
                return;
            };
            if let Some(state) =
                tracker.observe(facts, observer_active, elapsed_realtime_ms, uptime_ms)
            {
                self.sender.send_replace(state);
            }
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = (facts, observer_active, elapsed_realtime_ms, uptime_ms);
            changed(&self.sender, Reason::Unavailable);
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<NetworkState> {
        self.sender.subscribe()
    }

    /// A trusted local policy change invalidates previously gathered candidates.
    /// It never turns an unavailable network into an available one. Android's
    /// observation tracker shares the advance so its next callback cannot roll
    /// the generation back to a value from before the policy change.
    pub fn invalidate_generation(&self) -> io::Result<u64> {
        #[cfg(target_os = "android")]
        {
            let mut tracker = self.android_observation.lock().map_err(|_| {
                changed(&self.sender, Reason::Unavailable);
                io::Error::other("network observation is unavailable")
            })?;
            let result = invalidate_state(&mut tracker.state);
            self.sender.send_replace(tracker.state);
            result
        }
        #[cfg(not(target_os = "android"))]
        {
            let mut result = Err(io::Error::other("network generation was not advanced"));
            self.sender
                .send_modify(|state| result = invalidate_state(state));
            result
        }
    }
}

fn invalidate_state(state: &mut NetworkState) -> io::Result<u64> {
    match state
        .generation
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
    {
        Some(next) => {
            state.generation = next;
            state.reason = if state.available {
                Reason::Route
            } else {
                Reason::Unavailable
            };
            Ok(next)
        }
        None => {
            state.available = false;
            state.reason = Reason::Unavailable;
            Err(io::Error::other("network generation is exhausted"))
        }
    }
}
impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        changed(&self.sender, Reason::Unavailable);
        self.task.abort();
    }
}
fn changed(sender: &watch::Sender<NetworkState>, reason: Reason) {
    sender.send_modify(|state| {
        if !state.available {
            return;
        }
        if let Some(next) = state
            .generation
            .checked_add(1)
            .filter(|g| *g <= i64::MAX as u64)
        {
            state.generation = next;
            state.reason = reason;
            if reason == Reason::Unavailable {
                state.available = false;
            }
        } else {
            state.available = false;
            state.reason = Reason::Unavailable;
        }
    });
}
#[cfg(any(target_os = "windows", target_os = "linux", test))]
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(any(target_os = "android", test))]
const ANDROID_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "android")]
const ANDROID_WATCHDOG_INTERVAL: Duration = Duration::from_millis(250);
/// Compare deltas, not absolute offsets or wall time. The first clock includes
/// suspend, the second excludes it. Sampling jitter below 200 ms is tolerated.
#[cfg(any(target_os = "windows", target_os = "linux", test))]
struct ResumeDetector {
    previous: Option<(u64, u64)>,
}
#[cfg(any(target_os = "windows", target_os = "linux", test))]
impl ResumeDetector {
    #[cfg(test)]
    fn new() -> Self {
        Self { previous: None }
    }
    fn sample(&mut self, including: u64, active: u64) -> io::Result<bool> {
        let resumed = if let Some((p_including, p_active)) = self.previous {
            let elapsed = including
                .checked_sub(p_including)
                .ok_or_else(|| io::Error::other("system clock moved back"))?;
            let awake = active
                .checked_sub(p_active)
                .ok_or_else(|| io::Error::other("system clock moved back"))?;
            elapsed.saturating_sub(awake) > 200
        } else {
            false
        };
        self.previous = Some((including, active));
        Ok(resumed)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn local_policy_invalidation_preserves_availability_and_closes_on_exhaustion()
    -> std::io::Result<()> {
        for available in [false, true] {
            let mut state = super::NetworkState {
                generation: 8,
                available,
                reason: super::Reason::Started,
            };
            assert_eq!(super::invalidate_state(&mut state)?, 9);
            assert_eq!(state.available, available);
            assert_eq!(
                state.reason,
                if available {
                    super::Reason::Route
                } else {
                    super::Reason::Unavailable
                }
            );
            state.generation = i64::MAX as u64;
            assert!(super::invalidate_state(&mut state).is_err());
            assert!(!state.available);
            assert_eq!(state.generation, i64::MAX as u64);
        }
        Ok(())
    }

    use super::*;

    fn android_facts() -> PlatformNetworkFacts {
        PlatformNetworkFacts {
            network_handle: 17,
            interface_name: "wlan0".to_owned(),
            link_addresses: vec![PlatformLinkAddress {
                address: "192.168.1.20".to_owned(),
                prefix_length: 24,
            }],
            routes: vec![PlatformRoute {
                destination: "0.0.0.0".to_owned(),
                prefix_length: 0,
                gateway: Some("192.168.1.1".to_owned()),
            }],
            dns_servers: vec!["192.168.1.1".to_owned()],
            has_internet: true,
            validated: true,
            not_metered: true,
            not_restricted: true,
            transports: vec!["wifi".to_owned()],
        }
    }

    #[test]
    fn android_requires_real_address_route_and_dns_facts() {
        let facts = android_facts();
        assert!(facts.is_usable());

        let mut no_route = facts.clone();
        no_route.routes.clear();
        assert!(!no_route.is_usable());

        let mut no_dns = facts.clone();
        no_dns.dns_servers.clear();
        assert!(!no_dns.is_usable());

        let mut mismatched_route = facts;
        mismatched_route.routes[0].destination = "::".to_owned();
        assert!(!mismatched_route.is_usable());
    }

    #[test]
    fn android_fact_changes_observer_loss_and_suspend_advance_generation() {
        let mut tracker = AndroidObservationTracker::new();
        let facts = android_facts();
        let observed_at = Instant::now();
        assert!(!tracker.state.available);

        let initial = tracker.observe_at(Some(facts.clone()), true, 1_000, 900, observed_at);
        assert_eq!(
            initial,
            Some(NetworkState {
                generation: 2,
                available: true,
                reason: Reason::Route,
            }),
        );
        assert_eq!(
            tracker.observe_at(
                Some(facts.clone()),
                true,
                1_250,
                1_150,
                observed_at + Duration::from_millis(250),
            ),
            None,
        );

        let mut changed_route = facts.clone();
        changed_route.routes[0].gateway = Some("192.168.1.254".to_owned());
        let changed = tracker.observe_at(
            Some(changed_route),
            true,
            1_500,
            1_400,
            observed_at + Duration::from_millis(500),
        );
        assert_eq!(changed.map(|state| state.generation), Some(3));

        let lost = tracker.observe_at(
            None,
            false,
            1_600,
            1_500,
            observed_at + Duration::from_millis(600),
        );
        assert_eq!(lost.map(|state| state.available), Some(false));
        let restored = tracker.observe_at(
            Some(facts.clone()),
            true,
            1_700,
            1_600,
            observed_at + Duration::from_millis(700),
        );
        assert_eq!(restored.map(|state| state.available), Some(true));

        let resumed = tracker.observe_at(
            Some(facts.clone()),
            true,
            11_700,
            1_700,
            observed_at + Duration::from_millis(10_700),
        );
        assert_eq!(resumed.map(|state| state.reason), Some(Reason::Resumed));

        let rollback = tracker.observe_at(
            Some(facts),
            true,
            100,
            1_800,
            observed_at + Duration::from_millis(10_800),
        );
        assert_eq!(rollback.map(|state| state.available), Some(false));
    }

    #[test]
    fn android_watchdog_expires_silent_observer_and_requires_fresh_recovery() {
        let mut tracker = AndroidObservationTracker::new();
        let facts = android_facts();
        let observed_at = Instant::now();
        assert_eq!(
            tracker.observe_at(Some(facts.clone()), true, 1_000, 900, observed_at),
            Some(NetworkState {
                generation: 2,
                available: true,
                reason: Reason::Route,
            }),
        );

        assert_eq!(
            tracker.expire_if_stale(
                observed_at + ANDROID_OBSERVATION_TIMEOUT - Duration::from_millis(1),
            ),
            None,
        );
        let Some(expired) = tracker.expire_if_stale(observed_at + ANDROID_OBSERVATION_TIMEOUT)
        else {
            panic!("silent Android observer must expire");
        };
        assert_eq!(expired.generation, 3);
        assert!(!expired.available);
        assert_eq!(expired.reason, Reason::Unavailable);
        assert_eq!(
            tracker.expire_if_stale(observed_at + ANDROID_OBSERVATION_TIMEOUT * 2),
            None,
        );

        let recovered = tracker.observe_at(
            Some(facts),
            true,
            1_001,
            901,
            observed_at + ANDROID_OBSERVATION_TIMEOUT + Duration::from_millis(1),
        );
        assert_eq!(recovered.map(|state| state.generation), Some(4));
        assert_eq!(recovered.map(|state| state.available), Some(true));
    }

    #[test]
    fn delayed_android_heartbeat_invalidates_epoch_even_if_watchdog_was_not_scheduled() {
        let mut tracker = AndroidObservationTracker::new();
        let facts = android_facts();
        let observed_at = Instant::now();
        let _ = tracker.observe_at(Some(facts.clone()), true, 1_000, 900, observed_at);

        let recovered_at = observed_at + ANDROID_OBSERVATION_TIMEOUT + Duration::from_millis(1);
        let recovered = tracker.observe_at(Some(facts), true, 4_001, 3_901, recovered_at);
        assert_eq!(recovered.map(|state| state.generation), Some(3));
        assert_eq!(recovered.map(|state| state.reason), Some(Reason::Route));
        assert_eq!(recovered.map(|state| state.available), Some(true));
    }

    #[test]
    fn suspend_delta_invalidates_without_wall_clock_and_old_state_never_revives() -> io::Result<()>
    {
        let mut detector = ResumeDetector::new();
        assert!(!detector.sample(1000, 100)?);
        assert!(!detector.sample(1250, 350)?);
        assert!(detector.sample(11_500, 600)?);
        assert!(detector.sample(10_000, 700).is_err());
        let (sender, _) = watch::channel(NetworkState {
            generation: i64::MAX as u64,
            available: true,
            reason: Reason::Started,
        });
        changed(&sender, Reason::Route);
        assert!(!sender.borrow().available);
        changed(&sender, Reason::Address);
        assert!(!sender.borrow().available);
        Ok(())
    }
    #[cfg(any(windows, target_os = "linux"))]
    #[tokio::test]
    async fn actual_os_subscription_and_drop_invalidates_all_observers() -> io::Result<()> {
        for _ in 0..8 {
            let monitor = NetworkMonitor::start()?;
            let mut receiver = monitor.subscribe();
            assert!(receiver.borrow().available);
            drop(monitor);
            tokio::time::timeout(Duration::from_secs(1), receiver.changed())
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            assert!(!receiver.borrow().available);
            assert_eq!(receiver.borrow().reason, Reason::Unavailable);
        }
        Ok(())
    }
}
