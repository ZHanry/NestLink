//! Actions-only feasibility experiment, absent from production builds.
//! No migration negotiation, path epoch change or new route authority is added.
use super::*;
use crate::routed;
use nestlink_identity::{InstallationIdentity, digest};
use nestlink_transport_stream::{Channel, read_frame, write_frame};
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use serde_json::json;
use std::{
    fs, io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::sync::oneshot;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Reuse the signed fixture; its one-relay convenience entry points are unused here.
#[allow(dead_code)]
#[path = "../../tests/network_routed_socket/authority.rs"]
mod authority;

const FIRST: [&str; 2] = ["10.214.1.2:45001", "10.214.3.2:45003"];
const SECOND: [&str; 2] = ["10.214.2.2:45002", "10.214.4.2:45004"];
const RELAYS: [[&str; 2]; 2] = [
    ["10.214.1.1:4433", "10.214.2.1:4434"],
    ["10.214.3.1:4435", "10.214.4.1:4436"],
];
const RELAY_NAMES: [&str; 2] = ["relay_a", "relay_b"];
const PREFIX: &str = "routed::migration_experiment::";

fn fixture(namespace: bool) -> Result<PathBuf> {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_eq!(std::env::var("GITHUB_REPOSITORY")?, "ZHanry/NestLink");
    let root = PathBuf::from(std::env::var("NESTLINK_NETWORK_FIXTURE")?).canonicalize()?;
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    assert!(root.starts_with(&temporary) && root != temporary);
    if namespace {
        let actual = fs::read_link("/proc/self/ns/net")?;
        assert_ne!(actual.to_string_lossy(), std::env::var("NESTLINK_NETWORK_RUNNER_NAMESPACE")?);
        let status = fs::read_to_string("/proc/self/status")?;
        let uid = status.lines().find(|line| line.starts_with("Uid:")).ok_or("missing uid")?;
        assert_ne!(uid.split_whitespace().nth(1), Some("0"));
        assert_ne!(uid.split_whitespace().nth(2), Some("0"));
        println!("NESTLINK_MIGRATION namespace={actual:?} pid={} {uid}", std::process::id());
    }
    Ok(root)
}
fn identity(root: &Path, role: &str) -> Result<InstallationIdentity> {
    let mut seed: [u8; 32] = fs::read(root.join(format!("{role}.seed")))?
        .try_into().map_err(|_| "invalid fixture seed")?;
    Ok(InstallationIdentity::from_seed_zeroizing(&mut seed))
}
fn peer(root: &Path, role: &str) -> Result<PeerId> {
    Ok(PeerId(digest(&fs::read(root.join(format!("{role}.public")))?)))
}
fn mark(root: &Path, name: &str) -> Result {
    fs::write(root.join(format!("{name}.pending")), b"observed\n")?;
    fs::rename(root.join(format!("{name}.pending")), root.join(name))?;
    println!("NESTLINK_MIGRATION event={name}");
    Ok(())
}
async fn wait_mark(root: &Path, name: &str, deadline: Instant) -> Result {
    tokio::time::timeout_at(deadline, async {
        while !root.join(name).is_file() { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await?;
    assert_eq!(fs::read(root.join(name))?, b"observed\n");
    Ok(())
}
fn receipt(root: &Path, role: &str, facts: serde_json::Value) -> Result {
    fs::write(root.join(format!("{role}-receipt.json")), serde_json::to_vec_pretty(&facts)?)?;
    Ok(())
}
async fn rebind(address: SocketAddr, deadline: Instant) -> Result {
    tokio::time::timeout_at(deadline, async {
        loop {
            match UdpSocket::bind(address) {
                Ok(socket) => { drop(socket); return Ok::<_, io::Error>(()); }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => return Err(error),
            }
        }
    }).await??;
    Ok(())
}

#[derive(Debug, Default)]
struct PacketFacts {
    sent: AtomicU64,
    received: AtomicU64,
    maximum_sent: AtomicUsize,
    maximum_received: AtomicUsize,
}
impl PacketFacts {
    fn snapshot(&self) -> serde_json::Value {
        json!({"sent_packets":self.sent.load(Ordering::Relaxed),
            "received_packets":self.received.load(Ordering::Relaxed),
            "maximum_sent_bytes":self.maximum_sent.load(Ordering::Relaxed),
            "maximum_received_bytes":self.maximum_received.load(Ordering::Relaxed)})
    }
}
#[derive(Debug)]
struct MeasuredSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    facts: Arc<PacketFacts>,
}
impl AsyncUdpSocket for MeasuredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> { self.inner.clone().create_io_poller() }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)?;
        self.facts.sent.fetch_add(1, Ordering::Relaxed);
        self.facts.maximum_sent.fetch_max(transmit.contents.len(), Ordering::Relaxed);
        Ok(())
    }
    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &result {
            for item in meta.iter().take(*count) {
                self.facts.received.fetch_add(1, Ordering::Relaxed);
                self.facts.maximum_received.fetch_max(item.len, Ordering::Relaxed);
            }
        }
        result
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }
    fn may_fragment(&self) -> bool { self.inner.may_fragment() }
}

/// Test owner retains every original task, abstract socket and physical receipt.
struct Carrier {
    adjacency: Adjacency,
    socket: Option<Arc<dyn AsyncUdpSocket>>,
    receiver: TaskOwner,
    released: Option<oneshot::Receiver<()>>,
    revocation: RouteRevocation,
    facts: Arc<PacketFacts>,
    address: SocketAddr,
    deadline: Instant,
    close_deadline: Option<Instant>,
    closed: bool,
}
impl Carrier {
    fn new(authority: &authority::Authority, adjacency: Adjacency, address: SocketAddr, local: PeerId) -> Result<Self> {
        let (authorization, revocation) = authority.authorize()?;
        authorization.live()?;
        if adjacency.local() != local || Some(adjacency.remote()) != authorization.endpoint_relay(local) || !authorization.peers().contains(local) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let first = local == authorization.peers().first;
        let deadline = authorization.deadline();
        let (socket, receiver) = socket::RoutedSocket::new(authorization, adjacency.connection()?.clone(), first)?;
        let facts = Arc::new(PacketFacts::default());
        let measured = Arc::new(MeasuredSocket { inner: socket, facts: facts.clone() });
        let (socket, released) = crate::service::socket::tracked(measured);
        Ok(Self { adjacency, socket: Some(socket), receiver, released: Some(released), revocation, facts, address, deadline, close_deadline: None, closed: false })
    }
    fn take_socket(&mut self) -> Result<Arc<dyn AsyncUdpSocket>> { self.socket.take().ok_or_else(|| "socket already transferred".into()) }
    async fn close_and_wait(&mut self, deadline: Instant) -> Result {
        if self.closed { return Ok(()); }
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.revocation.revoke();
        self.adjacency.request_close();
        self.socket = None;
        self.receiver.close_and_wait(deadline).await?;
        if let Some(released) = self.released.as_mut() { tokio::time::timeout_at(deadline, released).await??; }
        self.released = None;
        self.adjacency.close_and_wait(deadline).await?;
        rebind(self.address, deadline).await?;
        self.closed = true;
        Ok(())
    }
}
impl Drop for Carrier {
    fn drop(&mut self) { self.revocation.revoke(); self.receiver.request_close(); self.adjacency.request_close(); }
}

fn stats(connection: &Connection, carrier: &Carrier, phase: &str, began: Instant) -> serde_json::Value {
    let stats = connection.stats();
    let outer = carrier.adjacency.connection().ok().map(|connection| {
        let stats = connection.stats();
        json!({"rtt_us":stats.path.rtt.as_micros(),"min_rtt_us":stats.path.min_rtt.as_micros(),
            "cwnd_bytes":stats.path.cwnd,"congestion_events":stats.path.congestion_events,
            "lost_packets":stats.path.lost_packets,"lost_bytes":stats.path.lost_bytes,
            "current_mtu_bytes":stats.path.current_mtu,"sent_plpmtud_probes":stats.path.sent_plpmtud_probes,
            "lost_plpmtud_probes":stats.path.lost_plpmtud_probes,"udp_tx_bytes":stats.udp_tx.bytes,"udp_rx_bytes":stats.udp_rx.bytes})
    });
    json!({"phase":phase,"elapsed_us":began.elapsed().as_micros(),"stable_id":connection.stable_id(),
        "rtt_us":stats.path.rtt.as_micros(),"min_rtt_us":stats.path.min_rtt.as_micros(),
        "cwnd_bytes":stats.path.cwnd,"congestion_events":stats.path.congestion_events,
        "lost_packets":stats.path.lost_packets,"lost_bytes":stats.path.lost_bytes,"sent_packets":stats.path.sent_packets,
        "current_mtu_bytes":stats.path.current_mtu,"sent_plpmtud_probes":stats.path.sent_plpmtud_probes,
        "lost_plpmtud_probes":stats.path.lost_plpmtud_probes,"black_holes_detected":stats.path.black_holes_detected,
        "udp_tx_bytes":stats.udp_tx.bytes,"udp_rx_bytes":stats.udp_rx.bytes,"logical_socket":carrier.facts.snapshot(),"outer_quic":outer})
}
fn exporter(connection: &Connection) -> Result<[u8; 32]> {
    let mut value = [0; 32];
    connection.export_keying_material(&mut value, b"NestLink/W14/isolated-feasibility", b"same-inner-connection")
        .map_err(|error| io::Error::other(format!("TLS exporter unavailable: {error:?}")))?;
    let hash = digest(&value);
    value.fill(0);
    Ok(hash)
}
async fn transfer(first: bool, send: &mut quinn::SendStream, read: &mut quinn::RecvStream, bytes: &[u8], phase: u8, round: u8, deadline: Instant) -> Result<u128> {
    let began = Instant::now();
    let mut body = Vec::with_capacity(bytes.len() + 2);
    body.extend_from_slice(&[phase, round]);
    body.extend_from_slice(bytes);
    // A real authenticated QUIC application stream carries fresh phase-tagged
    // file bytes and a digest receipt, never UDP echo or a replacement session.
    tokio::time::timeout_at(deadline, async {
        if first {
            write_frame(send, Channel::Control, &body).await?;
            let ack = read_frame(read).await?;
            assert_eq!(ack.channel, Channel::Control);
            assert_eq!(ack.payload, digest(&body));
        } else {
            let frame = read_frame(read).await?;
            assert_eq!(frame.channel, Channel::Control);
            assert_eq!(frame.payload, body);
            write_frame(send, Channel::Control, &digest(&body)).await?;
        }
        Ok::<_, io::Error>(())
    }).await??;
    Ok(began.elapsed().as_micros())
}

#[test]
#[ignore = "explicit GitHub-hosted W14 namespace orchestrator only"]
fn prepare_fixture() -> Result { authority::prepare_relays(&fixture(false)?, &RELAY_NAMES) }

async fn relay(index: usize) -> Result {
    let root = fixture(true)?;
    let role = RELAY_NAMES[index];
    let local = identity(&root, role)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let first = AdjacencyEndpoint::bind(RELAYS[index][0].parse()?, &local, peer(&root, "first")?)?;
    let second = AdjacencyEndpoint::bind(RELAYS[index][1].parse()?, &local, peer(&root, "second")?)?;
    mark(&root, &format!("{role}-ready"))?;
    let (first, second) = tokio::try_join!(first.accept(deadline), second.accept(deadline))?;
    let authority = authority::Authority::load_route(&root, index)?;
    let (authorization, stop) = authority.authorize()?;
    let mut relay = RelayForwarder::new(authorization, first, second)?;
    mark(&root, &format!("{role}-forwarding"))?;
    let result = {
        let run = relay.run();
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => result,
            result = wait_mark(&root, "stop-all", Instant::now() + Duration::from_secs(10)) => { result?; stop.revoke(); run.await }
        }
    };
    assert!(result.is_err());
    let forwarded = relay.forwarded_fragments();
    let charged = relay.charged_bytes();
    assert!(forwarded > 0 && charged > 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    relay.close_and_wait(deadline).await?;
    for address in RELAYS[index] { rebind(address.parse()?, deadline).await?; }
    receipt(&root, role, json!({"passed":true,"role":role,"forwarded_fragments":forwarded,"charged_bytes":charged,
        "explicit_close_completed":true,"released_udp_sockets":2,"rebound_udp_addresses":RELAYS[index]}))?;
    mark(&root, &format!("{role}-finished"))
}
#[tokio::test]
#[ignore = "explicit GitHub-hosted W14 namespace orchestrator only"]
async fn relay_a_process() -> Result { relay(0).await }
#[tokio::test]
#[ignore = "explicit GitHub-hosted W14 namespace orchestrator only"]
async fn relay_b_process() -> Result { relay(1).await }

async fn endpoint(first: bool) -> Result {
    let root = fixture(true)?;
    let case = std::env::var("NESTLINK_NETWORK_CASE")?;
    assert!(matches!(case.as_str(), "switch" | "cancel"));
    let role = if first { "first" } else { "second" };
    let local = identity(&root, role)?;
    let addresses = if first { FIRST } else { SECOND };
    let authorities = [authority::Authority::load_route(&root, 0)?, authority::Authority::load_route(&root, 1)?];
    assert_eq!(authorities[0].path.transport_group_id(), authorities[1].path.transport_group_id());
    assert_eq!(authorities[0].permit.digest(), authorities[1].permit.digest());
    assert_eq!(authorities[0].path.claims(), authorities[1].path.claims());
    assert_ne!(authorities[0].transit.digest(), authorities[1].transit.digest());
    let began = Instant::now();
    let setup = began + Duration::from_secs(5);
    let a = AdjacencyEndpoint::bind(addresses[0].parse()?, &local, peer(&root, RELAY_NAMES[0])?)?;
    let b = AdjacencyEndpoint::bind(addresses[1].parse()?, &local, peer(&root, RELAY_NAMES[1])?)?;
    let (a, b) = tokio::try_join!(a.connect(RELAYS[0][usize::from(!first)].parse()?, setup), b.connect(RELAYS[1][usize::from(!first)].parse()?, setup))?;
    let mut carriers = [Carrier::new(&authorities[0], a, addresses[0].parse()?, PeerId(local.fingerprint()))?,
        Carrier::new(&authorities[1], b, addresses[1].parse()?, PeerId(local.fingerprint()))?];
    let deadline = carriers[0].deadline.min(carriers[1].deadline);
    assert!(deadline > setup);
    mark(&root, &format!("{role}-two-authorized-carriers"))?;
    let remote = peer(&root, if first { "second" } else { "first" })?;
    let mut transport = transport_value();
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(wire::PACKET_BYTES as u16);
    mtud.minimum_change(1);
    mtud.interval(Duration::from_millis(500));
    transport.mtu_discovery_config(Some(mtud));
    let transport = Arc::new(transport);
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls::server_config(&local, remote.0)?)?));
    server.transport_config(transport.clone());
    server.migration(false);
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls::client_config(&local, remote.0)?)?));
    client.transport_config(transport);
    let mut settings = quinn::EndpointConfig::default();
    settings.max_udp_payload_size(wire::PACKET_BYTES as u16)?;
    let socket = carriers[0].take_socket()?;
    let destination = if first { "127.0.0.2:28744" } else { "127.0.0.1:28744" }.parse()?;
    let mut inner = Endpoint::new_with_abstract_socket(settings, Some(server), socket, Arc::new(quinn::TokioRuntime))?;
    inner.set_default_client_config(client);
    let connection = tokio::time::timeout_at(setup, async {
        if first { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inner.connect(destination, "peer.nestlink.invalid")?.await?) }
        else { Ok(inner.accept().await.ok_or("missing inner connection")?.await?) }
    }).await??;
    let stable_id = connection.stable_id();
    let original_exporter = exporter(&connection)?;
    let (mut send, mut read) = if first { connection.open_bi().await? } else { tokio::time::timeout_at(setup, connection.accept_bi()).await?? };
    let stream_id = send.id();
    let payload = fs::read(root.join("payload.bin"))?;
    assert_eq!(payload.len(), 32_768);
    let mut samples = Vec::new();
    let mut stream_roundtrips = Vec::new();
    for round in 0..4 {
        stream_roundtrips.push(json!({"phase":"old","round":round,"duration_us":transfer(first, &mut send, &mut read, &payload, 0, round, deadline).await?}));
        samples.push(stats(&connection, &carriers[0], "old", began));
    }
    mark(&root, &format!("{role}-old-stream-verified"))?;
    wait_mark(&root, "switch-now", deadline).await?;
    inner.rebind_abstract(carriers[1].take_socket()?)?;
    mark(&root, &format!("{role}-rebound-inner"))?;
    tokio::time::timeout_at(deadline, async {
        while carriers[1].facts.received.load(Ordering::Relaxed) == 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await?;
    carriers[0].close_and_wait(Instant::now() + Duration::from_secs(5)).await?;
    let old_counts = carriers[0].facts.snapshot();
    mark(&root, &format!("{role}-old-physical-released"))?;
    wait_mark(&root, "old-path-fully-closed", deadline).await?;
    for round in 0..8 {
        stream_roundtrips.push(json!({"phase":"new-after-old-release","round":round,"duration_us":transfer(first, &mut send, &mut read, &payload, 1, round, deadline).await?}));
        samples.push(stats(&connection, &carriers[1], "new-after-old-release", began));
        assert_eq!(connection.stable_id(), stable_id);
        assert_eq!(exporter(&connection)?, original_exporter);
        assert_eq!(send.id(), stream_id);
    }
    assert_eq!(old_counts, carriers[0].facts.snapshot());
    assert!(carriers[1].facts.maximum_sent.load(Ordering::Relaxed) > 1200);
    assert!(carriers[1].facts.maximum_received.load(Ordering::Relaxed) > 1200);
    assert!(connection.stats().path.sent_plpmtud_probes > 0);
    mark(&root, &format!("{role}-new-stream-verified"))?;
    let mut pending_read_cancelled = false;
    if case == "cancel" && first {
        let pending = read_frame(&mut read);
        tokio::pin!(pending);
        assert!(tokio::time::timeout(Duration::from_millis(150), &mut pending).await.is_err());
        mark(&root, "first-read-blocked")?;
        wait_mark(&root, "stop-all", deadline).await?;
        connection.close(0u32.into(), b"isolated experiment cancellation");
        inner.close(0u32.into(), b"isolated experiment cancellation");
        assert!(tokio::time::timeout(Duration::from_millis(500), &mut pending).await?.is_err());
        pending_read_cancelled = true;
    } else { wait_mark(&root, "stop-all", deadline).await?; }
    drop((send, read));
    connection.close(0u32.into(), b"isolated experiment finished");
    inner.close(0u32.into(), b"isolated experiment finished");
    let cleanup = Instant::now() + Duration::from_secs(5);
    tokio::time::timeout_at(cleanup, inner.wait_idle()).await?;
    drop((connection, inner));
    carriers[1].close_and_wait(cleanup).await?;
    receipt(&root, role, json!({"passed":true,"role":role,"prototype_test_filter_prefix":PREFIX,
        "same_inner_connection":true,"same_stream":true,"stable_id":stable_id,"stream_id":format!("{stream_id:?}"),"tls_exporter_sha256":original_exporter,
        "same_original_path_grant":true,"same_original_permit":true,"transport_group":authorities[0].path.transport_group_id(),
        "original_path_expires_at_ms":authorities[0].path.claims().scope.expires_at_ms,
        "original_path_epoch":wire::PATH_EPOCH,"production_migration_protocol_exercised":false,"business_endpoint_proof_exercised":false,
        "old_physical_closed_before_new_application_bytes":true,"old_counts_frozen":true,
        "application_file_bytes_before_switch":payload.len()*4,"application_file_bytes_after_old_closed":payload.len()*8,
        "application_payload_sha256":digest(&payload),"samples":samples,"stream_roundtrips":stream_roundtrips,
        "old_logical_socket":old_counts,"new_logical_socket":carriers[1].facts.snapshot(),
        "pending_read_cancelled":pending_read_cancelled,"explicit_close_completed":true,
        "joined_receiver_tasks":2,"abstract_socket_release_receipts":2,"released_udp_sockets":2,"rebound_udp_addresses":addresses}))?;
    mark(&root, &format!("{role}-finished"))
}
#[tokio::test]
#[ignore = "explicit GitHub-hosted W14 namespace orchestrator only"]
async fn first_process() -> Result { endpoint(true).await }
#[tokio::test]
#[ignore = "explicit GitHub-hosted W14 namespace orchestrator only"]
async fn second_process() -> Result { endpoint(false).await }
