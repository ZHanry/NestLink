//! Independent allocation-bound datagram forwarding; never decrypts inner QUIC.
use crate::relay_selector::RelaySelector;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{random_bytes, random_id};
use nestlink_node::control::{
    Error as NodeError, NodeControl, RelayEndpointCandidate, RelayEndpointProof,
    RelayResourceReservation,
};
use nestlink_protocol::{
    ContractError, ErrorCode, NODE_MESSAGE_BYTES, NodeRole, RelayTransport, SignedRelayAllocation,
    api::{NodeRelayChallenge, NodeRelayHello, RelayReady},
    decode_bounded, relay_datagram,
};
use nestlink_transport_quic::node::{read_message, write_message};
use std::{
    collections::HashMap,
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinSet};
mod chain;
mod topology;
mod network;

fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "node QUIC relay stopped or refused",
    )
}
const FULL: &str = "node QUIC datagram buffer full";
struct Slot {
    token: String,
    connection: quinn::Connection,
    ready: watch::Sender<bool>,
}
type Pair = [Option<Slot>; 2];
#[derive(Default)]
struct Hub {
    pairs: Mutex<HashMap<String, Pair>>,
}
struct Registration {
    hub: Arc<Hub>,
    allocation: String,
    token: String,
}
struct RelayIo {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    streams: Option<(quinn::SendStream, quinn::RecvStream)>,
    registration: Option<Registration>,
    guard: Option<RelayResourceReservation>,
}
impl Drop for RelayIo {
    fn drop(&mut self) {
        self.streams.take();
        self.registration.take();
        // Quinn close stops the public API immediately, but its socket driver
        // can retain a previously buffered UDP transmit. Endpoint idle is the
        // public drain witness; a timeout must never be treated as clean I/O.
        self.connection.close(1u32.into(), b"relay I/O stopped");
        if let Some(guard) = self.guard.take() {
            let cleanup = guard.defer_io_confirmation();
            let endpoint = self.endpoint.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if tokio::time::timeout(
                        Duration::from_millis(nestlink_protocol::NODE_RELAY_CLOSE_IO_DRAIN_MS),
                        endpoint.wait_idle(),
                    )
                    .await
                    .is_ok()
                    {
                        cleanup.confirm_stopped();
                    }
                });
            }
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut pairs) = self.hub.pairs.lock()
            && pairs
                .get(&self.allocation)
                .is_some_and(|p| p.iter().flatten().any(|s| s.token == self.token))
            && let Some(pair) = pairs.remove(&self.allocation)
        {
            for slot in pair.into_iter().flatten() {
                slot.connection.close(1u32.into(), b"relay pair stopped");
            }
        }
    }
}
impl Hub {
    fn register(
        self: &Arc<Self>,
        guard: &RelayResourceReservation,
        connection: &quinn::Connection,
    ) -> io::Result<(Registration, watch::Receiver<bool>)> {
        let mut pairs = self.pairs.lock().map_err(|_| failed())?;
        let allocation = guard.allocation_id();
        if pairs.len() >= 128 && !pairs.contains_key(allocation) {
            return Err(failed());
        }
        let pair = pairs
            .entry(allocation.into())
            .or_insert_with(|| [None, None]);
        let role = usize::from(!guard.is_controller());
        if pair[role].is_some() {
            return Err(failed());
        }
        let token = random_id();
        let (ready, receiver) = watch::channel(false);
        pair[role] = Some(Slot {
            token: token.clone(),
            connection: connection.clone(),
            ready,
        });
        if pair.iter().all(Option::is_some) {
            for slot in pair.iter().flatten() {
                slot.ready.send_replace(true);
            }
        }
        Ok((
            Registration {
                hub: self.clone(),
                allocation: allocation.into(),
                token,
            },
            receiver,
        ))
    }
    fn peer(&self, r: &Registration) -> io::Result<quinn::Connection> {
        let pairs = self.pairs.lock().map_err(|_| failed())?;
        let pair = pairs.get(&r.allocation).ok_or_else(failed)?;
        let index = pair
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.token == r.token))
            .ok_or_else(failed)?;
        Ok(pair[1 - index]
            .as_ref()
            .ok_or_else(failed)?
            .connection
            .clone())
    }
}
struct Close(quinn::Connection);
impl Drop for Close {
    fn drop(&mut self) {
        self.0.close(1u32.into(), b"relay socket ended");
    }
}
struct Owner {
    endpoint: quinn::Endpoint,
    control: Arc<NodeControl>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.control.stop();
        self.endpoint.close(1u32.into(), b"relay listener ended");
    }
}
/// Ending or canceling this listener owns terminal node stop and all its sockets.
pub async fn serve(
    endpoint: quinn::Endpoint,
    control: Arc<NodeControl>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    serve_with_selector(endpoint, RelaySelector::new(control), shutdown).await
}
pub async fn serve_with_selector(
    endpoint: quinn::Endpoint,
    selector: Arc<RelaySelector>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    serve_inner(endpoint, selector, None, None, shutdown).await
}
/// The production registered node identity signs reciprocal NRD2 possession;
/// all listeners of this node continue sharing the same RelaySelector.
pub async fn serve_with_chain_identity(
    endpoint: quinn::Endpoint,
    selector: Arc<RelaySelector>,
    identity: Arc<nestlink_identity::nodes::NodeIdentity>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    serve_inner(endpoint, selector, Some(identity), None, shutdown).await
}
/// The registered relay owns real adjacency observations and their periodic
/// signed reports alongside the original chain and legacy forwarding tasks.
pub async fn serve_with_topology_identity(
    endpoint: quinn::Endpoint,
    selector: Arc<RelaySelector>,
    identity: Arc<nestlink_identity::nodes::NodeIdentity>,
    reporter: Arc<nestlink_node::control::TopologyReporter>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    serve_inner(endpoint, selector, Some(identity), Some(reporter), shutdown).await
}
async fn serve_inner(
    endpoint: quinn::Endpoint,
    selector: Arc<RelaySelector>,
    identity: Option<Arc<nestlink_identity::nodes::NodeIdentity>>,
    reporter: Option<Arc<nestlink_node::control::TopologyReporter>>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let control = selector.control();
    let _owner = Owner {
        endpoint: endpoint.clone(),
        control: control.clone(),
    };
    let mut stopped = control.stopped();
    let hub = Arc::new(Hub::default());
    let mut tasks = JoinSet::new();
    let mut scan = tokio::time::interval(Duration::from_millis(100));
    scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut attempted = HashMap::<String, tokio::time::Instant>::new();
    let has_topology = identity.is_some() && reporter.is_some();
    let mut observing_finished = false;
    let observing = async {
        match (identity.clone(), reporter) {
            (Some(identity), Some(reporter)) => topology::run(endpoint.clone(), control.clone(), selector.clone(), identity, reporter).await,
            _ => std::future::pending().await,
        }
    };
    tokio::pin!(observing);
    tokio::pin!(shutdown);
    let result = loop {
        if *stopped.borrow() {
            break Err(failed());
        }
        tokio::select! { biased;
            _ = &mut shutdown => break Ok(()),
            _ = stopped.changed() => break Err(failed()),
            _ = &mut observing => { observing_finished = true; break Err(failed()); },
            result = tasks.join_next(), if !tasks.is_empty() => { if result.is_some_and(|r| r.is_err()) { break Err(failed()); } },
            _ = scan.tick(), if identity.is_some() => {
                let now=tokio::time::Instant::now();
                attempted.retain(|_,until|*until>now);
                if let Ok(routes)=control.network_chain_routes() {
                    for route in routes {
                        if route.binding.relay!=route.binding.chain.relays[0] || attempted.contains_key(&route.allocation_id) {continue;}
                        // The signed allocation ID and original wall expiry are
                        // never refreshed by retries or a new resource poll.
                        let wall=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
                            .and_then(|duration|u64::try_from(duration.as_millis()).ok());
                        let Some(remaining)=wall.and_then(|wall|route.binding.chain.expires_at_ms.checked_sub(wall)).filter(|remaining|*remaining>0) else {continue;};
                        if attempted.len()>=nestlink_protocol::NODE_RESOURCE_ALLOCATIONS as usize {break;}
                        let until=now+Duration::from_millis(remaining.min(30_000));
                        attempted.insert(route.allocation_id.clone(),until);
                        let control=control.clone();let hub=hub.clone();let selector=selector.clone();let endpoint=endpoint.clone();
                        let Some(identity)=identity.clone() else {break;};
                        tasks.spawn(async move {
                            let _=chain::outgoing(route,control,hub,selector,endpoint,identity,until).await;
                        });
                    }
                }
            },
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Err(failed()); };
                let ip = incoming.remote_address().ip();
                if control.authorize(NodeRole::NodeRelay, false).is_err() {
                    incoming.refuse(); continue;
                }
                let Ok(slot) = selector.socket(ip) else { incoming.refuse(); continue; };
                // Require QUIC address validation before allocating a handshake/task.
                if !incoming.remote_address_validated() { let _ = incoming.retry(); continue; }
                let hub = hub.clone(); let control = control.clone(); let selector = selector.clone(); let drain = endpoint.clone();let identity=identity.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(3), incoming).await {
                        let _close = Close(connection.clone());
                        let protocol = connection.handshake_data()
                            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                            .and_then(|data| data.protocol);
                        if protocol.as_deref()==Some(nestlink_protocol::network_topology::PROBE_ALPN) {
                            if let Some(identity)=identity {let _=topology::incoming(connection,control,identity).await;}
                        } else if protocol.as_deref()==Some(nestlink_protocol::network_datagram_v2::ALPN) {
                            if let Some(identity)=identity {let _=chain::incoming(connection,control,hub,selector,drain,identity).await;}
                        } else if protocol.as_deref() == Some(nestlink_protocol::network_datagram::ALPN) {
                            let _ = network::run(connection, control, hub, selector, drain).await;
                        } else if protocol.as_deref() == Some(relay_datagram::ALPN) {
                            let _ = run(connection, control, hub, selector, drain).await;
                        }
                    }
                });
            }
        }
    };
    let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    control.stop();
    endpoint.close(0u32.into(), b"node listener stopping");
    tasks.abort_all();
    let mut cleanup_error = None;
    if has_topology && !observing_finished {
        match tokio::time::timeout_at(cleanup_deadline, &mut observing).await {
            Ok(Ok(())) => {},
            Ok(Err(error)) => cleanup_error = Some(error),
            Err(error) => cleanup_error = Some(io::Error::other(error)),
        }
    }
    // Aborting requests cancellation. Joining each original task proves its
    // streams, queues, connections and resource guards have actually dropped.
    while let Some(joined) = tokio::time::timeout_at(cleanup_deadline, tasks.join_next())
        .await.map_err(io::Error::other)? {
        if joined.is_err_and(|error| !error.is_cancelled()) {
            cleanup_error = Some(failed());
        }
    }
    if let Some(error) = cleanup_error { Err(error) } else { result }
}
async fn admission(
    control: &NodeControl,
    hello: &NodeRelayHello,
    nonce: &[u8; 32],
) -> io::Result<RelayEndpointCandidate> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&hello.public_key)
        .map_err(|_| failed())?
        .try_into()
        .map_err(|_| failed())?;
    let signature = URL_SAFE_NO_PAD
        .decode(&hello.signature)
        .map_err(|_| failed())?;
    let ticket = URL_SAFE_NO_PAD
        .decode(&hello.allocation)
        .map_err(|_| failed())?;
    let _: SignedRelayAllocation =
        decode_bounded(&ticket, NODE_MESSAGE_BYTES).map_err(|_| failed())?;
    let until = Instant::now() + Duration::from_millis(700);
    loop {
        let result = control.prepare_relay_endpoint(
            &ticket,
            RelayEndpointProof {
                device_id: &hello.device_id,
                public_key: &key,
                transport: RelayTransport::QuicDatagram,
                signature: &signature,
            },
            nonce,
        );
        if let Ok(guard) = result {
            return Ok(guard);
        }
        if Instant::now() >= until {
            return Err(failed());
        }
        control
            .authorize(NodeRole::NodeRelay, false)
            .map_err(|_| failed())?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn run(
    connection: quinn::Connection,
    control: Arc<NodeControl>,
    hub: Arc<Hub>,
    selector: Arc<RelaySelector>,
    endpoint: quinn::Endpoint,
) -> io::Result<()> {
    let (mut write, mut read) =
        tokio::time::timeout(Duration::from_millis(500), connection.open_bi())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
    let nonce = random_bytes::<32>();
    tokio::time::timeout(
        Duration::from_millis(500),
        write_message(
            &mut write,
            &NodeRelayChallenge {
                nonce: URL_SAFE_NO_PAD.encode(nonce),
            },
        ),
    )
    .await
    .map_err(io::Error::other)??;
    let handshake = async {
        tokio::select! { biased;
            _ = connection.read_datagram() => Err(failed()),
            _ = connection.accept_bi() => Err(failed()),
            _ = connection.accept_uni() => Err(failed()),
            result = read_message::<NodeRelayHello>(&mut read) => result,
        }
    };
    let hello = tokio::time::timeout(Duration::from_secs(3), handshake)
        .await
        .map_err(io::Error::other)??;
    let candidate = tokio::select! { biased;
        _ = connection.closed() => return Err(failed()),
        _ = connection.read_datagram() => return Err(failed()),
        _ = connection.accept_bi() => return Err(failed()),
        _ = connection.accept_uni() => return Err(failed()),
        result = admission(&control, &hello, &nonce) => result?,
    };
    let selection = selector.register(candidate)?;
    let mut extra = [0u8; 1];
    let guard = tokio::select! { biased;
        _ = connection.closed() => return Err(failed()),
        _ = read.read(&mut extra) => return Err(failed()),
        _ = connection.read_datagram() => return Err(failed()),
        _ = connection.accept_bi() => return Err(failed()),
        _ = connection.accept_uni() => return Err(failed()),
        result = selection.wait() => result?,
    };
    let mut io = RelayIo {
        endpoint,
        connection,
        streams: Some((write, read)),
        registration: None,
        guard: Some(guard),
    };
    io.guard
        .as_ref()
        .ok_or_else(failed)?
        .check_live()
        .map_err(|_| failed())?;
    let (registration, mut paired) =
        hub.register(io.guard.as_ref().ok_or_else(failed)?, &io.connection)?;
    io.registration = Some(registration);
    let guard = io.guard.as_ref().ok_or_else(failed)?;
    let connection = &io.connection;
    let registration = io.registration.as_ref().ok_or_else(failed)?;
    let (write, read) = io.streams.as_mut().ok_or_else(failed)?;
    let pairing = async {
        loop {
            if *paired.borrow() {
                return Ok(());
            }
            paired.changed().await.map_err(|_| failed())?;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { biased;
            _ = guard.wait_stopped() => Err(failed()),
            _ = connection.closed() => Err(failed()),
            _ = connection.read_datagram() => Err(failed()),
            _ = connection.accept_bi() => Err(failed()),
            _ = connection.accept_uni() => Err(failed()),
            result = pairing => result,
        }
    })
    .await
    .map_err(io::Error::other)??;
    guard.check_live().map_err(|_| failed())?;
    tokio::time::timeout(
        Duration::from_millis(500),
        write_message(write, &RelayReady { ready: true }),
    )
    .await
    .map_err(io::Error::other)??;
    let peer = hub.peer(registration)?;
    let mut processed = 0u32;
    loop {
        tokio::select! { biased;
            _ = guard.wait_stopped() => return Err(failed()),
            _ = read.read(&mut extra) => return Err(failed()),
            _ = connection.accept_bi() => return Err(failed()),
            _ = connection.accept_uni() => return Err(failed()),
            result = connection.read_datagram() => {
                let bytes = result.map_err(io::Error::other)?;
                relay_datagram::decode(&bytes).map_err(io::Error::other)?;
                let admitted = guard.admit(bytes.len() as u64, || {
                    // Do not let Quinn silently evict an older admitted datagram.
                    // Congested UDP drops the new packet; it never waits in a reliable queue.
                    if peer.datagram_send_buffer_space() < bytes.len() {
                        return Err(ContractError::new(ErrorCode::CapacityExceeded, FULL));
                    }
                    peer.send_datagram(bytes).map_err(|_| ContractError::new(ErrorCode::LeaseExpired, "node QUIC peer closed"))
                });
                match admitted {
                    Ok(()) => {},
                    Err(NodeError::Authorization(e)) if e.reason == FULL => {},
                    Err(_) => return Err(failed()),
                }
            }
        }
        processed = (processed + 1) % 32;
        if processed == 0 {
            tokio::task::yield_now().await;
        }
    }
}
