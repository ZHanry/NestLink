//! Actions-only feasibility evidence, not the complete W09 product contract.
//! Mature ICE checks and Quinn use the same original OS UDP candidate socket.
#[path = "ice_quic/socket.rs"]
mod socket;
use socket::IceUdp;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, VerifiedPermit, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_remote::{RuntimeClock, SessionLifecycle, SessionSetup};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_stream::{Channel, tls};
use prost::Message;
use quinn::{AsyncUdpSocket, ClientConfig, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig}, udp::Transmit};
use std::{io, net::{SocketAddr, UdpSocket}, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use tokio::{sync::{mpsc, watch}, time::Instant};
use webrtc::{ice::{agent::{Agent, agent_config::AgentConfig},
    candidate::CandidateType, mdns::MulticastDnsMode, network_type::NetworkType,
    udp_network::{EphemeralUDP, UDPNetwork}}, util::Conn};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct AgentOwner { agent: Arc<Agent>, closed: bool }
impl AgentOwner {
    async fn gather(opened: Arc<AtomicUsize>) -> Result<(Self, SocketAddr)> {
        let mut network = EphemeralUDP::default();
        network.set_socket_factory(Arc::new(move |address| {
            let socket = UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            opened.fetch_add(1, Ordering::SeqCst);
            Ok(socket)
        }));
        let agent = Agent::new(AgentConfig {
            udp_network: UDPNetwork::Ephemeral(network), network_types: vec![NetworkType::Udp4],
            candidate_types: vec![CandidateType::Host], multicast_dns_mode: MulticastDnsMode::Disabled,
            include_loopback: true,
            ip_filter: Arc::new(Some(Box::new(|ip: std::net::IpAddr| ip.is_loopback()))),
            ..Default::default()
        }).await?;
        let owner = Self { agent: Arc::new(agent), closed: false };
        let (tx, mut rx) = mpsc::channel(8);
        owner.agent.on_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move { let _ = tx.send(candidate).await; })
        }));
        owner.agent.gather_candidates()?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while rx.recv().await.flatten().is_some() {}
        }).await?;
        let candidates = owner.agent.get_local_candidates().await?;
        assert_eq!(candidates.len(), 1, "freeze exactly one original candidate socket");
        let candidate = &candidates[0];
        let address = SocketAddr::new(candidate.address().parse()?, candidate.port());
        drop(candidates);
        Ok((owner, address))
    }
    async fn close(&mut self, deadline: Instant) -> Result {
        if !self.closed {
            tokio::time::timeout_at(deadline, self.agent.close()).await??;
            self.closed = true;
        }
        Ok(())
    }
}
impl Drop for AgentOwner {
    fn drop(&mut self) {
        if !self.closed && let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let agent = self.agent.clone();
            // Fallback for a failed assertion/setup only. Passing tests must
            // explicitly await close and rebind the original physical ports.
            runtime.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), agent.close()).await;
            });
        }
    }
}

struct Pair {
    agents: [AgentOwner; 2],
    original: [SocketAddr; 2],
    sockets: [Arc<IceUdp>; 2],
    endpoints: Option<[Endpoint; 2]>,
    opened: Arc<AtomicUsize>,
}
impl Pair {
    async fn new(controller: &InstallationIdentity, host: &InstallationIdentity, wrong_server: bool, wrong_client: bool) -> Result<Self> {
        let opened = Arc::new(AtomicUsize::new(0));
        let (a, address_a) = AgentOwner::gather(opened.clone()).await?;
        let (b, address_b) = AgentOwner::gather(opened.clone()).await?;
        assert_ne!(address_a, address_b);
        for candidate in b.agent.get_local_candidates().await? { a.agent.add_remote_candidate(&candidate)?; }
        for candidate in a.agent.get_local_candidates().await? { b.agent.add_remote_candidate(&candidate)?; }
        let (a_ufrag, a_pwd) = a.agent.get_local_user_credentials().await;
        let (b_ufrag, b_pwd) = b.agent.get_local_user_credentials().await;
        let (_cancel_a, a_rx) = mpsc::channel(1);
        let (_cancel_b, b_rx) = mpsc::channel(1);
        let (a_conn, b_conn) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(a.agent.dial(a_rx, b_ufrag, b_pwd), b.agent.accept(b_rx, a_ufrag, a_pwd))
        }).await??;
        assert_eq!(a_conn.local_addr()?, address_a);
        assert_eq!(b_conn.local_addr()?, address_b);
        assert_eq!(a_conn.remote_addr(), Some(address_b));
        assert_eq!(b_conn.remote_addr(), Some(address_a));
        let sockets = [IceUdp::new(a.agent.clone(), a_conn)?, IceUdp::new(b.agent.clone(), b_conn)?];
        let endpoints = [endpoint(sockets[0].clone(), controller, if wrong_server { [0; 32] } else { host.fingerprint() })?,
            endpoint(sockets[1].clone(), host, if wrong_client { [0; 32] } else { controller.fingerprint() })?];
        assert_eq!(endpoints[0].local_addr()?, address_a);
        assert_eq!(endpoints[1].local_addr()?, address_b);
        assert_eq!(opened.load(Ordering::SeqCst), 2, "Quinn must not bind another UDP socket");
        Ok(Self { agents: [a,b], original: [address_a,address_b], sockets, endpoints: Some(endpoints), opened })
    }
    fn endpoints(&self) -> Result<&[Endpoint; 2]> { self.endpoints.as_ref().ok_or_else(|| "endpoints already closed".into()) }
    async fn connections(&self) -> Result<(quinn::Connection, quinn::Connection)> {
        let endpoints = self.endpoints()?;
        tokio::time::timeout(Duration::from_secs(4), async {
            let accept = async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(endpoints[1].accept().await.ok_or("missing QUIC Initial")?.await?)
            };
            let connect = async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(endpoints[0].connect(self.original[1], "peer.nestlink.invalid")?.await?)
            };
            tokio::try_join!(connect, accept)
        }).await?
    }
    async fn close(&mut self) -> Result {
        let deadline = Instant::now() + Duration::from_secs(5);
        if let Some(endpoints) = self.endpoints.take() {
            for endpoint in &endpoints { endpoint.close(0u32.into(), b"ICE prototype owner close"); }
            for endpoint in &endpoints { tokio::time::timeout_at(deadline, endpoint.wait_idle()).await?; }
            drop(endpoints);
        }
        for socket in &self.sockets { socket.close_tasks(deadline).await?; }
        for agent in &mut self.agents { agent.close(deadline).await?; }
        let _original_owners_released = [UdpSocket::bind(self.original[0])?, UdpSocket::bind(self.original[1])?];
        assert_eq!(self.opened.load(Ordering::SeqCst), 2);
        println!("ICE_QUIC same_socket=true physical_rebind=true opened_udp_sockets=2");
        Ok(())
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        if let Some(endpoints) = &self.endpoints {
            for endpoint in endpoints { endpoint.close(1u32.into(), b"ICE prototype fixture dropped"); }
        }
    }
}
fn endpoint(socket: Arc<IceUdp>, identity: &InstallationIdentity, peer: [u8; 32]) -> Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport.initial_mtu(1200).min_mtu(1200).mtu_discovery_config(None);
    transport.max_concurrent_bidi_streams(16u8.into()).max_concurrent_uni_streams(8u8.into());
    transport.max_idle_timeout(Some(Duration::from_secs(3).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_millis(500)));
    let transport = Arc::new(transport);
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls::server_config(identity, peer)?)?));
    server.transport_config(transport.clone());
    server.migration(false);
    let mut endpoint = Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), Some(server), socket, Arc::new(quinn::TokioRuntime))?;
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls::client_config(identity, peer)?)?));
    client.transport_config(transport);
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

fn business(controller: &InstallationIdentity, host: &InstallationIdentity) -> Result<(VerifiedPermit, SessionBinding)> {
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        media: None, deployment_id: random_id(), security_epoch: 1, session_id: random_id(), account_id: random_id(),
        controller_device_id: random_id(), host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint(), host_key_sha256: host.fingerprint(),
        resource_id: random_id(), policy_revision: 1, connection_generation: 7, capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View, Permission::FileRead], supported_capabilities: vec!["vp8".into()], local_paths: PathSet::DIRECT,
    };
    let claims = PermitClaims {
        schema_version: SCHEMA_VERSION, deployment_id: binding.deployment_id.clone(), security_epoch: 1,
        session_id: binding.session_id.clone(), account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(), host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(), host_key_sha256: host.fingerprint().to_vec(),
        resource_id: binding.resource_id.clone(), permissions: vec![Permission::View as i32, Permission::FileRead as i32],
        paths: vec![Path::Direct as i32], policy_revision: 1, connection_generation: 7, lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms, expires_at_unix_ms: now.unix_ms + 15_000,
        capability_sha256: vec![9; 32], required_capabilities: vec!["vp8".into()],
        media_format_version: 0, media_formats: Vec::new(), media_format_sha256: Vec::new(),
    };
    let signer = PermitSigner::generate();
    Ok((verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?, binding))
}
fn setup(permit: VerifiedPermit, binding: SessionBinding, role: EndpointRole, stop: watch::Receiver<Option<StopReason>>) -> Result<SessionSetup> {
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    Ok(SessionSetup { session: Session::activate(permit, binding, Path::Direct, now.monotonic_ms, now)?,
        path: Path::Direct, role, clock, lifecycle: SessionLifecycle::new(stop) })
}

#[tokio::test]
async fn mature_ice_same_socket_carries_pinned_quic_and_real_file_channel_business() -> Result {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let mut pair = Pair::new(&controller, &host, false, false).await?;
    // Refuse arbitrary destinations, larger packets and GSO before enqueue.
    for mutation in 0..3 {
        let bytes = vec![0; if mutation == 1 { 1201 } else { 1200 }];
        let transmit = Transmit { destination: if mutation == 0 { "127.0.0.1:1".parse()? } else { pair.sockets[0].peer() },
            ecn: None, contents: &bytes, segment_size: if mutation == 2 { Some(600) } else { None }, src_ip: None };
        assert_eq!(pair.sockets[0].try_send(&transmit).err().map(|e| e.kind()), Some(io::ErrorKind::InvalidInput));
    }
    let (c_connection, h_connection) = pair.connections().await?;
    let (permit, binding) = business(&controller, &host)?;
    let (_keep, stop) = watch::channel(None);
    let host_key = host.public_key();
    let controller_key = controller.public_key();
    let (mut c, mut h) = tokio::try_join!(
        nestlink_remote::quic::authorize(c_connection, None, setup(permit.clone(), binding.clone(), EndpointRole::Controller, stop.clone())?, &controller, &host_key),
        nestlink_remote::quic::authorize(h_connection, None, setup(permit, binding, EndpointRole::Host, stop)?, &host, &controller_key),
    )?;
    let payload = vec![71; 32 * 1024];
    for _ in 0..8 {
        let (sent, received) = tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(h.send(Channel::FileRead, &payload), c.receive()) }).await?;
        sent?;
        let frame = received?;
        assert_eq!(frame.channel, Channel::FileRead);
        assert_eq!(frame.payload, payload);
    }
    assert!(c.send(Channel::Input, b"ICE connectivity is not business authority").await.is_err());
    let (sent, received, largest) = pair.sockets[1].counters();
    assert!(sent > 256 * 1024 && received > 0);
    assert_eq!(largest, 1200, "real QUIC Initial and packet budget use the selected ICE socket");
    c.lease_control().stop(StopReason::ExplicitExit)?;
    h.lease_control().stop(StopReason::ExplicitExit)?;
    let (c_report, h_report) = tokio::time::timeout(Duration::from_secs(5), async { tokio::try_join!(c.wait_stopped(), h.wait_stopped()) }).await??;
    assert_eq!(c_report.reason, StopReason::ExplicitExit);
    assert_eq!(h_report.reason, StopReason::ExplicitExit);
    drop((c,h));
    pair.close().await?;
    Ok(())
}

#[tokio::test]
async fn wrong_server_and_client_tls_pins_cannot_open_business_over_the_ice_pair() -> Result {
    for (wrong_server, wrong_client) in [(true,false), (false,true)] {
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let mut pair = Pair::new(&controller, &host, wrong_server, wrong_client).await?;
        let endpoints = pair.endpoints()?;
        let (c, h) = tokio::time::timeout(Duration::from_secs(4), async {
            let connect = endpoints[0].connect(pair.original[1], "peer.nestlink.invalid")?;
            let accept = async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(endpoints[1].accept().await.ok_or("missing wrong-key Initial")?.await) };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(tokio::join!(connect, accept))
        }).await??;
        let h = h?;
        // A bad server pin fails at the client; a bad client pin fails at the
        // server. A timeout is not accepted as evidence of certificate refusal.
        let refused = if wrong_server { c.as_ref().err() } else { h.as_ref().err() };
        assert!(matches!(refused, Some(quinn::ConnectionError::TransportError(_)) | Some(quinn::ConnectionError::ConnectionClosed(_))));
        drop((c,h));
        pair.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_mature_ice_checks_closes_the_original_candidate_socket() -> Result {
    let opened = Arc::new(AtomicUsize::new(0));
    let (mut owner, address) = AgentOwner::gather(opened.clone()).await?;
    let (cancel, rx) = mpsc::channel(1);
    {
        let checks = owner.agent.dial(rx, "unavailable-peer".into(), "unavailable-peer-password".into());
        tokio::pin!(checks);
        tokio::select! {
            _ = &mut checks => return Err("ICE checks ended before explicit cancellation".into()),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {},
        }
        cancel.send(()).await?;
        assert!(tokio::time::timeout(Duration::from_secs(2), checks).await?.is_err());
    }
    assert!(owner.agent.get_selected_candidate_pair().is_none());
    owner.close(Instant::now() + Duration::from_secs(5)).await?;
    let _original_owner_released = UdpSocket::bind(address)?;
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn cancelled_quinn_handshake_reaps_ice_io_and_both_original_udp_owners() -> Result {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let mut pair = Pair::new(&controller, &host, false, false).await?;
    {
        // The host application never accepts its incoming Initial. Cancellation
        // must also clean that endpoint's pending handshake resources.
        let endpoints = pair.endpoints()?;
        let connection = endpoints[0].connect(pair.original[1], "peer.nestlink.invalid")?;
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => return Err("QUIC handshake completed without endpoint acceptance".into()),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {},
        }
        // Dropping the original Connecting is the explicit setup cancellation;
        // endpoint/adapter/Agent owners below still require physical cleanup.
    }
    pair.close().await?;
    Ok(())
}
