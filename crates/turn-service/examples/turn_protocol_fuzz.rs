//! Loopback-only TURN wire-protocol mutation run. Defaults to the G2 24-hour
//! duration; `--duration-seconds` is useful for a short harness smoke check.

use nestlink_traversal::turn::TurnAuthorization;
use nestlink_turn_service::{RelayPortPool, TurnService, TurnServiceConfig};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    sync::watch,
    time::{Instant, interval_at, sleep, sleep_until, timeout},
};
use tokio_rustls::TlsConnector;

type FuzzResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const MAX_PACKET: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Counters {
    udp_datagrams: AtomicU64,
    udp_send_errors: AtomicU64,
    tcp_sessions: AtomicU64,
    tcp_connect_errors: AtomicU64,
    tcp_frames: AtomicU64,
    tls_sessions: AtomicU64,
    tls_handshake_errors: AtomicU64,
    tls_frames: AtomicU64,
}

#[tokio::main]
async fn main() -> FuzzResult {
    let duration = parse_duration()?;
    let (server_tls, client_tls) = tls_configs()?;
    let authorization = Arc::new(TurnAuthorization::new(64)?);
    let (online_tx, online_rx) = watch::channel(true);
    let config = TurnServiceConfig {
        realm: "turn-fuzz.invalid".to_owned(),
        udp_bind: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tcp_bind: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tls_bind: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tls_server_config: Some(Arc::new(server_tls)),
        relay_port_pools: vec![RelayPortPool {
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            min_port: 30_000,
            max_port: 30_255,
        }],
        max_connections: 32,
    };
    let worker_online = online_rx.clone();
    let (service, _) = TurnService::bind(config, Arc::clone(&authorization), online_rx).await?;
    let addresses = service.listen_addresses();
    let udp_address = addresses.udp.ok_or("TURN UDP listener missing")?;
    let tcp_address = addresses.tcp.ok_or("TURN TCP listener missing")?;
    let tls_address = addresses.tls.ok_or("TURN TLS listener missing")?;

    let started = Instant::now();
    let until = started + duration;
    let counters = Arc::new(Counters::default());
    let mut workers = vec![
        tokio::spawn(run_udp(
            udp_address,
            until,
            worker_online.clone(),
            Arc::clone(&counters),
            seed(1),
        )),
        tokio::spawn(run_tcp(
            tcp_address,
            until,
            worker_online.clone(),
            Arc::clone(&counters),
            seed(2),
        )),
        tokio::spawn(run_tls(
            tls_address,
            client_tls,
            until,
            worker_online,
            Arc::clone(&counters),
            seed(3),
        )),
    ];

    let mut progress = interval_at(
        Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let mut interrupted = false;
    loop {
        tokio::select! {
            _ = sleep_until(until) => break,
            result = tokio::signal::ctrl_c() => {
                result?;
                interrupted = true;
                break;
            }
            _ = progress.tick() => print_progress(&counters, &authorization, started.elapsed()),
        }
    }

    online_tx.send_replace(false);
    for worker in workers.drain(..) {
        let result = timeout(Duration::from_secs(15), worker).await?;
        result??;
    }
    timeout(Duration::from_secs(30), service.shutdown()).await??;

    let elapsed = started.elapsed();
    let udp = counters.udp_datagrams.load(Ordering::Relaxed);
    let tcp = counters.tcp_sessions.load(Ordering::Relaxed);
    let tls = counters.tls_sessions.load(Ordering::Relaxed);
    let allocations = authorization.active_allocations();
    println!(
        "TURN_FUZZ_REPORT schema=1 elapsed_seconds={} interrupted={} udp_datagrams={} udp_send_errors={} tcp_sessions={} tcp_connect_errors={} tcp_frames={} tls_sessions={} tls_handshake_errors={} tls_frames={} active_allocations={}",
        elapsed.as_secs(),
        interrupted,
        udp,
        counters.udp_send_errors.load(Ordering::Relaxed),
        tcp,
        counters.tcp_connect_errors.load(Ordering::Relaxed),
        counters.tcp_frames.load(Ordering::Relaxed),
        tls,
        counters.tls_handshake_errors.load(Ordering::Relaxed),
        counters.tls_frames.load(Ordering::Relaxed),
        allocations,
    );
    if udp == 0 || tcp == 0 || tls == 0 || allocations != 0 {
        return Err(
            "TURN protocol fuzz run did not cover every transport or leaked an allocation".into(),
        );
    }
    Ok(())
}

fn parse_duration() -> FuzzResult<Duration> {
    let mut args = std::env::args().skip(1);
    const MAX_DURATION_SECONDS: u64 = 90 * 60;
    let mut seconds = MAX_DURATION_SECONDS;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--duration-seconds" => {
                seconds = args
                    .next()
                    .ok_or("--duration-seconds requires a value")?
                    .parse()?;
            }
            "--help" | "-h" => {
                println!(
                    "turn_protocol_fuzz [--duration-seconds N] (default: 5400; maximum: 5400)"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    if !(1..=MAX_DURATION_SECONDS).contains(&seconds) {
        return Err("duration must be between 1 second and 90 minutes".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn tls_configs() -> FuzzResult<(ServerConfig, Arc<ClientConfig>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = certified.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key.into())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((server, Arc::new(client)))
}

async fn run_udp(
    address: SocketAddr,
    until: Instant,
    mut online: watch::Receiver<bool>,
    counters: Arc<Counters>,
    mut random: u64,
) -> FuzzResult {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    while running(&online, until) {
        let packet = datagram(&mut random);
        if socket.send_to(&packet, address).await.is_ok() {
            counters.udp_datagrams.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.udp_send_errors.fetch_add(1, Ordering::Relaxed);
        }
        if !pause(Duration::from_millis(10), until, &mut online).await {
            break;
        }
    }
    Ok(())
}

async fn run_tcp(
    address: SocketAddr,
    until: Instant,
    mut online: watch::Receiver<bool>,
    counters: Arc<Counters>,
    mut random: u64,
) -> FuzzResult {
    while running(&online, until) {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(mut stream)) => {
                counters.tcp_sessions.fetch_add(1, Ordering::Relaxed);
                send_frames(&mut stream, &mut random, &counters.tcp_frames).await;
                let _ = timeout(CONNECT_TIMEOUT, stream.shutdown()).await;
            }
            _ => {
                counters.tcp_connect_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        if !pause(Duration::from_millis(250), until, &mut online).await {
            break;
        }
    }
    Ok(())
}

async fn run_tls(
    address: SocketAddr,
    client_config: Arc<ClientConfig>,
    until: Instant,
    mut online: watch::Receiver<bool>,
    counters: Arc<Counters>,
    mut random: u64,
) -> FuzzResult {
    let connector = TlsConnector::from(client_config);
    while running(&online, until) {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await;
        let result = match stream {
            Ok(Ok(stream)) => {
                let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
                timeout(CONNECT_TIMEOUT, connector.connect(server_name, stream)).await
            }
            _ => {
                counters
                    .tls_handshake_errors
                    .fetch_add(1, Ordering::Relaxed);
                if !pause(Duration::from_secs(1), until, &mut online).await {
                    break;
                }
                continue;
            }
        };
        match result {
            Ok(Ok(mut stream)) => {
                counters.tls_sessions.fetch_add(1, Ordering::Relaxed);
                send_frames(&mut stream, &mut random, &counters.tls_frames).await;
                let _ = timeout(CONNECT_TIMEOUT, stream.shutdown()).await;
            }
            _ => {
                counters
                    .tls_handshake_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        if !pause(Duration::from_secs(1), until, &mut online).await {
            break;
        }
    }
    Ok(())
}

async fn send_frames<S>(stream: &mut S, random: &mut u64, count: &AtomicU64)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let frames = 1 + (next(random) % 4) as usize;
    for _ in 0..frames {
        let frame = stream_frame(random);
        count.fetch_add(1, Ordering::Relaxed);
        if !matches!(
            timeout(CONNECT_TIMEOUT, stream.write_all(&frame)).await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

fn running(online: &watch::Receiver<bool>, until: Instant) -> bool {
    *online.borrow() && Instant::now() < until
}

async fn pause(delay: Duration, until: Instant, online: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = sleep(delay) => {},
        _ = sleep_until(until) => return false,
        changed = online.changed() => {
            if changed.is_err() || !*online.borrow() {
                return false;
            }
        }
    }
    running(online, until)
}

fn datagram(random: &mut u64) -> Vec<u8> {
    match next(random) % 4 {
        0 => {
            let length = next(random) as usize % MAX_PACKET;
            random_bytes(random, length)
        }
        1 => mutated_stun(random),
        2 => mutated_channel_data(random),
        _ => {
            let mut packet = stun_packet(random);
            let junk_length = next(random) as usize % 32;
            packet.extend(random_bytes(random, junk_length));
            mutate(random, packet)
        }
    }
}

fn stream_frame(random: &mut u64) -> Vec<u8> {
    match next(random) % 3 {
        0 => mutated_stun(random),
        1 => mutated_channel_data(random),
        _ => {
            let length = 4 + (next(random) as usize % 128);
            let mut frame = random_bytes(random, length);
            if frame.len() < 4 {
                frame.resize(4, 0);
            }
            frame[0] |= 0x80; // invalid TURN stream frame type
            frame
        }
    }
}

fn stun_packet(random: &mut u64) -> Vec<u8> {
    const METHODS: [u16; 9] = [
        0x0001, 0x0003, 0x0004, 0x0008, 0x0009, 0x0016, 0x0017, 0x0018, 0x0019,
    ];
    const ATTRIBUTES: [u16; 14] = [
        0x0006, 0x0008, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0019, 0x0020, 0x0025, 0x8022,
        0x8028, 0x8029, 0xc057,
    ];
    let mut packet = vec![0; 20];
    packet[..2].copy_from_slice(&METHODS[(next(random) as usize) % METHODS.len()].to_be_bytes());
    packet[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
    let transaction = random_bytes(random, 12);
    packet[8..20].copy_from_slice(&transaction);
    let attributes = (next(random) % 12) as usize;
    for _ in 0..attributes {
        let kind = ATTRIBUTES[(next(random) as usize) % ATTRIBUTES.len()];
        let length = (next(random) % 65) as usize;
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.extend(random_bytes(random, length));
        while !packet.len().is_multiple_of(4) {
            packet.push(next(random) as u8);
        }
    }
    let body_len = (packet.len() - 20) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());
    mutate(random, packet)
}

fn channel_data(random: &mut u64) -> Vec<u8> {
    let length = (next(random) % 1025) as usize;
    let channel = 0x4000 | (next(random) as u16 & 0x3fff);
    let mut frame = vec![(channel >> 8) as u8, 0, 0, 0];
    frame[1] = channel as u8;
    frame[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    frame.extend(random_bytes(random, length));
    while !frame.len().is_multiple_of(4) {
        frame.push(next(random) as u8);
    }
    frame
}

fn mutated_stun(random: &mut u64) -> Vec<u8> {
    let packet = stun_packet(random);
    mutate(random, packet)
}

fn mutated_channel_data(random: &mut u64) -> Vec<u8> {
    let frame = channel_data(random);
    mutate(random, frame)
}

fn mutate(random: &mut u64, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let changes = (next(random) % 6) as usize;
    for _ in 0..changes {
        let index = (next(random) as usize) % bytes.len();
        bytes[index] ^= next(random) as u8;
    }
    bytes
}

fn random_bytes(random: &mut u64, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    for byte in &mut bytes {
        *byte = next(random) as u8;
    }
    bytes
}

fn next(random: &mut u64) -> u64 {
    let mut value = *random;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *random = value.max(1);
    value
}

fn seed(stream: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    (now ^ (u64::from(std::process::id()) << 32) ^ stream).max(1)
}

fn print_progress(counters: &Counters, authorization: &TurnAuthorization, elapsed: Duration) {
    eprintln!(
        "TURN_FUZZ_PROGRESS elapsed_seconds={} udp_datagrams={} tcp_sessions={} tcp_frames={} tls_sessions={} tls_frames={} active_allocations={}",
        elapsed.as_secs(),
        counters.udp_datagrams.load(Ordering::Relaxed),
        counters.tcp_sessions.load(Ordering::Relaxed),
        counters.tcp_frames.load(Ordering::Relaxed),
        counters.tls_sessions.load(Ordering::Relaxed),
        counters.tls_frames.load(Ordering::Relaxed),
        authorization.active_allocations(),
    );
}
