//! Select one carrier for both endpoints before committing allocation resources.
use nestlink_auth::random_id;
use nestlink_node::control::{NodeControl, RelayEndpointCandidate, RelayResourceReservation};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "relay pairing stopped or refused",
    )
}
struct Waiting {
    token: String,
    candidate: RelayEndpointCandidate,
    sender: oneshot::Sender<RelayResourceReservation>,
}
/// Both listeners of a node must share this selector and its socket budget.
pub struct RelaySelector {
    control: Arc<NodeControl>,
    sockets: Arc<Semaphore>,
    pending: Mutex<HashMap<String, Vec<Waiting>>>,
    rates: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}
impl RelaySelector {
    pub fn new(control: Arc<NodeControl>) -> Arc<Self> {
        Arc::new(Self {
            control,
            sockets: Arc::new(Semaphore::new(256)),
            pending: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
        })
    }
    pub(crate) fn control(&self) -> Arc<NodeControl> {
        self.control.clone()
    }
    pub(crate) fn socket(&self, ip: IpAddr) -> io::Result<OwnedSemaphorePermit> {
        let mut rates = self.rates.lock().map_err(|_| refused())?;
        rates.retain(|_, (start, _)| start.elapsed() < Duration::from_secs(60));
        if !rates.contains_key(&ip) && rates.len() >= 1024 {
            return Err(refused());
        }
        let (_, count) = rates.entry(ip).or_insert((Instant::now(), 0));
        if *count >= 120 {
            return Err(refused());
        }
        *count += 1;
        self.sockets
            .clone()
            .try_acquire_owned()
            .map_err(|_| refused())
    }
    pub fn pending_candidates(&self) -> io::Result<usize> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| refused())?
            .values()
            .map(Vec::len)
            .sum())
    }
    pub(crate) fn register(
        self: &Arc<Self>,
        candidate: RelayEndpointCandidate,
    ) -> io::Result<Selection> {
        let stopped = Box::pin(candidate.wait_stopped());
        let allocation = candidate.allocation_id().to_owned();
        let token = random_id();
        let (sender, receiver) = oneshot::channel();
        let selection = Selection {
            selector: self.clone(),
            allocation: allocation.clone(),
            token: token.clone(),
            receiver,
            stopped,
            pairing_until: tokio::time::Instant::now() + Duration::from_secs(5),
        };
        let mut pending = self.pending.lock().map_err(|_| refused())?;
        // Canceled futures do not retain a slot or prevent another resolved
        // address from reaching the same authorized carrier.
        pending.retain(|_, entries| {
            entries.retain(|e| !e.sender.is_closed());
            !entries.is_empty()
        });
        if (pending.len() >= 128 && !pending.contains_key(&allocation))
            || pending.values().map(Vec::len).sum::<usize>() >= 256
        {
            // Avoid running Selection::drop while this mutex is held.
            drop(pending);
            return Err(refused());
        }
        let entries = pending.entry(allocation.clone()).or_default();
        let peer = entries.iter().position(|e| {
            e.candidate.transport() == candidate.transport()
                && e.candidate.is_controller() != candidate.is_controller()
        });
        if let Some(index) = peer {
            let peer = entries.swap_remove(index);
            let current = Waiting {
                token,
                candidate,
                sender,
            };
            // Losing candidates have no reservations; dropping them cannot
            // close the selected pair or refund the control capacity promise.
            pending.remove(&allocation);
            if !peer.sender.is_closed() && !current.sender.is_closed() {
                let commit = || -> io::Result<()> {
                    let a = peer.candidate.reserve().map_err(|_| refused())?;
                    let b = current.candidate.reserve().map_err(|_| refused())?;
                    peer.sender.send(a).map_err(|_| refused())?;
                    current.sender.send(b).map_err(|_| refused())?;
                    Ok(())
                };
                // Any partial commit or failed handoff drops its guards and
                // terminally closes both roles. A used UUID is never recycled.
                let _ = commit();
            }
        } else {
            entries.push(Waiting {
                token,
                candidate,
                sender,
            });
        }
        drop(pending);
        Ok(selection)
    }
}
pub(crate) struct Selection {
    selector: Arc<RelaySelector>,
    allocation: String,
    token: String,
    receiver: oneshot::Receiver<RelayResourceReservation>,
    stopped: Pin<Box<dyn Future<Output = ()> + Send>>,
    pairing_until: tokio::time::Instant,
}
impl Selection {
    pub(crate) async fn wait(mut self) -> io::Result<RelayResourceReservation> {
        tokio::select! { biased;
            // A successful commit occupies this role, so its preparation
            // waiter may now stop; the resource guard owns validity from here.
            result = &mut self.receiver => result.map_err(|_| refused()),
            _ = &mut self.stopped => Err(refused()),
            _ = tokio::time::sleep_until(self.pairing_until) => Err(refused()),
        }
    }
}
impl Drop for Selection {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.selector.pending.lock()
            && let Some(entries) = pending.get_mut(&self.allocation)
        {
            entries.retain(|e| e.token != self.token);
            if entries.is_empty() {
                pending.remove(&self.allocation);
            }
        }
    }
}

#[cfg(test)]
#[path = "../../../crates/node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;

#[cfg(test)]
mod tests {
    use super::{service_usage_directory::ServiceUsageDirectory, *};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use nestlink_node::control::NodeConfig;
    use nestlink_protocol::NodeRole;
    fn selector() -> io::Result<(Arc<RelaySelector>, ServiceUsageDirectory)> {
        // The pump cannot run during these synchronous budget checks. This
        // setup authorizes no forwarding and does not touch platform input.
        let mut service_usage_directory = ServiceUsageDirectory::new()?;
        let control = NodeControl::start(
            NodeConfig {
                deployment_id: random_id(),
                node_id: random_id(),
                control_origin: "http://127.0.0.1:9".into(),
                trusted_policy_issuer: URL_SAFE_NO_PAD.encode([4; 32]),
                identity_key_file: "unused-budget-fixture".into(),
                service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            nestlink_identity::nodes::NodeIdentity::generate(),
        )
        .map_err(io::Error::other)?;
        service_usage_directory.track(&control)?;
        Ok((
            RelaySelector::new(Arc::new(control)),
            service_usage_directory,
        ))
    }
    #[tokio::test]
    async fn socket_budget_is_shared_and_recovered_only_when_each_owned_permit_drops()
    -> io::Result<()> {
        let (selector, _service_usage_directory) = selector()?;
        let other_listener = selector.clone();
        let mut sockets = Vec::new();
        for n in 0..256u16 {
            let ip = IpAddr::from([127, 1, (n / 256) as u8, (n % 256) as u8]);
            sockets.push(if n < 128 {
                selector.socket(ip)?
            } else {
                other_listener.socket(ip)?
            });
        }
        assert!(selector.socket([127, 2, 0, 1].into()).is_err());
        assert!(other_listener.socket([127, 2, 0, 2].into()).is_err());
        sockets.pop();
        let recovered = other_listener.socket([127, 2, 0, 3].into())?;
        assert!(selector.socket([127, 2, 0, 4].into()).is_err());
        drop(recovered);
        drop(sockets);
        assert_eq!(selector.sockets.available_permits(), 256);
        selector.control.stop();
        Ok(())
    }
    #[tokio::test]
    async fn both_listeners_consume_the_same_per_ip_attempt_budget_and_finite_ip_table()
    -> io::Result<()> {
        let (selector, _service_usage_directory) = selector()?;
        let other_listener = selector.clone();
        let ip = IpAddr::from([127, 0, 0, 1]);
        for _ in 0..60 {
            drop(selector.socket(ip)?);
            drop(other_listener.socket(ip)?);
        }
        assert!(selector.socket(ip).is_err());
        assert!(other_listener.socket(ip).is_err());
        for n in 1..1024u16 {
            drop(selector.socket([127, 2, (n / 256) as u8, (n % 256) as u8].into())?);
        }
        assert!(other_listener.socket([127, 3, 0, 1].into()).is_err());
        assert_eq!(selector.rates.lock().map_err(|_| refused())?.len(), 1024);
        selector.control.stop();
        Ok(())
    }
}
