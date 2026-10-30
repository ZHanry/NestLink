//! Signed bilateral native ICE followed by pinned Quinn on its original UDP
//! socket. One frozen candidate per endpoint bounds this initial dialect;
//! general candidate migration and advanced NAT strategies are separate work.
mod socket;
#[doc(hidden)]
pub use socket::IceUdp;
use super::*;
use nestlink_identity::InstallationIdentity;
use nestlink_platform_network::path::NetworkPathManager;
use nestlink_protocol::api::NativeIceParameters;
use nestlink_remote::TransportOwner;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, crypto::rustls::{QuicClientConfig, QuicServerConfig}};
use std::{io, net::UdpSocket};
use tokio::{sync::mpsc, time::Instant as TokioInstant};
use webrtc::ice::{agent::{Agent, agent_config::AgentConfig}, candidate::{CandidateType, Candidate as IceCandidate, candidate_base::unmarshal_candidate}, mdns::MulticastDnsMode, network_type::NetworkType, udp_network::{EphemeralUDP, UDPNetwork}, url::Url};

const CHECK_BUDGET: Duration = Duration::from_secs(3);
const CLEANUP_BUDGET: Duration = Duration::from_secs(5);

/// Physical ICE owner. Drop requests cleanup; only close_and_wait confirms it.
pub struct IceOwner {
    agent: Option<Arc<Agent>>,
    socket: Option<Arc<IceUdp>>,
    endpoint: Option<Endpoint>,
    original: Arc<Mutex<Vec<SocketAddr>>>,
    connected_socket: Arc<Mutex<Option<UdpSocket>>>,
    close_deadline: Option<TokioInstant>,
    closed: bool,
}
impl IceOwner {
    pub(super) fn failure(&self) -> io::Result<watch::Receiver<Option<io::ErrorKind>>> {
        self.socket.as_ref().map(|socket| socket.failure()).ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    async fn close(&mut self, deadline: TokioInstant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle()).await.map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.endpoint = None;
        if let Some(socket) = &self.socket {
            socket.close_tasks(deadline).await?;
        }
        self.socket = None;
        if let Some(agent) = &self.agent {
            tokio::time::timeout_at(deadline, agent.close()).await.map_err(|_| io::ErrorKind::TimedOut)?.map_err(io::Error::other)?;
        }
        self.agent = None;
        drop(self.connected_socket.lock().map_err(|_| io::Error::other("ICE owner poisoned"))?.take());
        let addresses = self.original.lock().map_err(|_| io::Error::other("ICE owner poisoned"))?.clone();
        for address in addresses {
            loop {
                if TokioInstant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                match UdpSocket::bind(address) {
                    Ok(rebound) => { drop(rebound); break; }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::time::sleep_until(deadline.min(TokioInstant::now() + Duration::from_millis(10))).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.closed = true;
        Ok(())
    }
}
impl TransportOwner for IceOwner {
    fn request_close(&self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"native ICE owner stopping");
        }
        if let Some(socket) = &self.socket {
            socket.request_close();
        }
    }
    fn close_and_wait(&mut self, deadline: TokioInstant) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(self.close(deadline))
    }
}
impl Drop for IceOwner {
    fn drop(&mut self) {
        self.request_close();
        if !self.closed && let Some(agent) = self.agent.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let deadline = self.close_deadline.unwrap_or(TokioInstant::now() + CLEANUP_BUDGET);
            runtime.spawn(async move { let _ = tokio::time::timeout_at(deadline, agent.close()).await; });
        }
    }
}

pub(super) struct Gathering {
    owner: IceOwner,
    pub(super) parameters: NativeIceParameters,
}
struct Preparation {
    owner: IceOwner,
}
impl Preparation {
    async fn new(endpoint: &NativeEndpoint, servers: &[SocketAddr]) -> Result<Self, DialError> {
        endpoint.check()?;
        if servers.len() > 4 { return Err(DialError::Binding); }
        let bound = endpoint.local_addr()?;
        let path = Arc::new(NetworkPathManager::from_default().map_err(|_| DialError::Setup)?);
        let ip = path.candidate_interfaces(bound).map_err(|_| DialError::NetworkChanged)?
            .into_iter().flat_map(|interface| interface.addresses)
            .find(|ip| safe_peer_address(*ip)).ok_or(DialError::Setup)?;
        let servers: Vec<_> = servers.iter().filter(|server| server.is_ipv4() == ip.is_ipv4()).copied().collect();
        let use_stun = !servers.is_empty();
        let original = Arc::new(Mutex::new(Vec::new()));
        let connected_socket = Arc::new(Mutex::new(None));
        let retained = connected_socket.clone();
        let observed = original.clone();
        let physical = path.clone();
        let mut network = EphemeralUDP::default();
        network.set_socket_factory(Arc::new(move |address| {
            if address.ip() != ip { return Err(io::ErrorKind::PermissionDenied.into()); }
            let mut addresses = observed.lock().map_err(|_| io::Error::other("ICE owner poisoned"))?;
            if !addresses.is_empty() { return Err(io::ErrorKind::AddrInUse.into()); }
            let socket = physical.bind_udp(address)?;
            *retained.lock().map_err(|_| io::Error::other("ICE owner poisoned"))? = Some(socket.try_clone()?);
            addresses.push(socket.local_addr()?);
            Ok(socket)
        }));
        let urls = servers.first().map(|server| Url::parse(&format!("stun:{server}"))).transpose().map_err(|_| DialError::Binding)?.into_iter().collect();
        let agent = Agent::new(AgentConfig {
            udp_network: UDPNetwork::Ephemeral(network),
            network_types: vec![if ip.is_ipv4() { NetworkType::Udp4 } else { NetworkType::Udp6 }],
            candidate_types: vec![if use_stun { CandidateType::ServerReflexive } else { CandidateType::Host }],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            include_loopback: false,
            ip_filter: Arc::new(Some(Box::new(move |candidate| candidate == ip))),
            urls,
            disconnected_timeout: Some(Duration::from_secs(5)),
            failed_timeout: Some(Duration::from_secs(5)),
            keepalive_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        }).await.map_err(|_| DialError::Setup)?;
        let owner = IceOwner { agent: Some(Arc::new(agent)), socket: None, endpoint: None, original, connected_socket, close_deadline: None, closed: false };
        Ok(Self { owner })
    }
    async fn gather(&mut self, endpoint: &NativeEndpoint) -> Result<NativeIceParameters, DialError> {
        let agent = self.owner.agent.as_ref().ok_or(DialError::Setup)?;
        let (tx, mut rx) = mpsc::channel(2);
        agent.on_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move { let _ = tx.send(candidate.is_some()).await; })
        }));
        agent.gather_candidates().map_err(|_| DialError::Setup)?;
        while rx.recv().await.ok_or(DialError::Setup)? {}
        endpoint.check()?;
        let candidates = agent.get_local_candidates().await.map_err(|_| DialError::Setup)?;
        if candidates.len() != 1 { return Err(DialError::Setup); }
        let (username_fragment, password) = agent.get_local_user_credentials().await;
        let parameters = NativeIceParameters { version: nestlink_protocol::native_ice::VERSION, username_fragment, password, candidate: candidates[0].marshal() };
        let address = parameters.address()?;
        if !endpoint.address_policy.allows(address.ip()) { return Err(DialError::Binding); }
        Ok(parameters)
    }
}

pub(super) async fn gather(endpoint: &NativeEndpoint, servers: &[SocketAddr], mut cancel: watch::Receiver<bool>) -> Result<Gathering, DialError> {
    if *cancel.borrow() || cancel.has_changed().is_err() { return Err(DialError::Cancelled); }
    // Agent construction opens no candidate socket with mDNS disabled. Keep
    // its owner outside the future that starts gathering, so timeout/cancel
    // can always await cleanup of the actual original sockets before fallback.
    let mut preparation = Preparation::new(endpoint, servers).await?;
    let deadline = TokioInstant::from_std(endpoint.authorization_deadline).min(TokioInstant::now() + CANDIDATE_GATHER_BUDGET);
    let result = tokio::select! { biased;
        _ = cancellation(&mut cancel) => Err(DialError::Cancelled),
        result = tokio::time::timeout_at(deadline, preparation.gather(endpoint)) => result.unwrap_or(Err(DialError::Setup)),
    };
    match result {
        Ok(parameters) => Ok(Gathering { owner: preparation.owner, parameters }),
        Err(error) => {
            if let Err(source) = preparation.owner.close(TokioInstant::now() + CLEANUP_BUDGET).await {
                return Err(DialError::Cleanup { primary: Box::new(error), source });
            }
            Err(error)
        }
    }
}

impl Gathering {
    pub(super) async fn close(mut self) -> Result<(), DialError> {
        self.owner.close(TokioInstant::now() + CLEANUP_BUDGET).await.map_err(|source| DialError::Cleanup { primary: Box::new(DialError::Setup), source })
    }

    pub(super) async fn connect(mut self, endpoint: &NativeEndpoint, local: &DeviceIdentity, peer: &NativeIceParameters, generation: u64, mut cancel: watch::Receiver<bool>) -> Result<NativeConnection, DialError> {
        let deadline = TokioInstant::from_std(endpoint.authorization_deadline).min(TokioInstant::now() + CHECK_BUDGET);
        let result = tokio::select! { biased;
            _ = cancellation(&mut cancel) => Err(DialError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.connect_inner(endpoint, local, peer, generation)) => result.unwrap_or(Err(DialError::Setup)),
        };
        match result {
            Ok((connection, candidate)) => {
                let quinn = self.owner.endpoint.as_ref().ok_or(DialError::Setup)?.clone();
                Ok(NativeConnection { transport: NativeTransport::Ice { connection, endpoint: quinn, carrier: Box::new(self.owner) }, candidate, failures: Vec::new(), network: endpoint.network_binding()?, authorization_deadline: endpoint.authorization_deadline })
            }
            Err(error) => {
                if let Err(source) = self.owner.close(TokioInstant::now() + CLEANUP_BUDGET).await {
                    return Err(DialError::Cleanup { primary: Box::new(error), source });
                }
                Err(error)
            }
        }
    }
    async fn connect_inner(&mut self, endpoint: &NativeEndpoint, local: &DeviceIdentity, peer: &NativeIceParameters, generation: u64) -> Result<(quinn::Connection, Candidate), DialError> {
        endpoint.check()?;
        let address = peer.address()?;
        if !endpoint.address_policy.allows(address.ip()) { return Err(DialError::Binding); }
        // This is a duplicate handle to the original OS socket, never a new
        // bind. Before ICE can receive a peer check, the kernel filters every
        // source except the single signed and locally approved peer tuple.
        // The mature agent cannot create peer-reflexive candidates from an
        // unapproved source. A changed NAT tuple must fall back or restart.
        self.owner.connected_socket.lock().map_err(|_| DialError::Setup)?
            .as_ref().ok_or(DialError::Setup)?.connect(address).map_err(|_| DialError::Setup)?;
        let agent = self.owner.agent.as_ref().ok_or(DialError::Setup)?.clone();
        let candidate: Arc<dyn IceCandidate + Send + Sync> = Arc::new(unmarshal_candidate(&peer.candidate).map_err(|_| DialError::Binding)?);
        agent.add_remote_candidate(&candidate).map_err(|_| DialError::Setup)?;
        let (_keep, cancel) = mpsc::channel(1);
        let conn = match endpoint.role {
            EndpointRole::Controller => agent.dial(cancel, peer.username_fragment.clone(), peer.password.clone()).await,
            EndpointRole::Host => agent.accept(cancel, peer.username_fragment.clone(), peer.password.clone()).await,
        }.map_err(|_| DialError::Setup)?;
        endpoint.check()?;
        let actual = conn.remote_addr().ok_or(DialError::Setup)?;
        if actual != address || !endpoint.address_policy.allows(actual.ip()) { return Err(DialError::Binding); }
        let socket = IceUdp::new(agent, conn).map_err(|_| DialError::Setup)?;
        let quinn = quinn_endpoint(socket.clone(), &local.identity, digest(&endpoint.peer_key)).map_err(|_| DialError::Setup)?;
        self.owner.socket = Some(socket);
        self.owner.endpoint = Some(quinn.clone());
        let connected = match endpoint.role {
            EndpointRole::Controller => quinn.connect(actual, "peer.nestlink.invalid").map_err(|_| DialError::Setup)?.await,
            EndpointRole::Host => quinn.accept().await.ok_or(DialError::Setup)?.await,
        }.map_err(|error| DialError::Failed { code: failure::classify(&error, ErrorCode::DirectUnavailable), failures: Vec::new() })?;
        endpoint.check()?;
        Ok((connected, inbound_candidate(actual, generation)))
    }
}

fn quinn_endpoint(socket: Arc<IceUdp>, local: &InstallationIdentity, peer: [u8; 32]) -> io::Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport.initial_mtu(1200).min_mtu(1200).mtu_discovery_config(None);
    transport.max_concurrent_bidi_streams(16u8.into()).max_concurrent_uni_streams(8u8.into());
    transport.send_window(512 * 1024);
    transport.datagram_receive_buffer_size(Some(32 * 1200));
    transport.datagram_send_buffer_size(16 * 1200);
    transport.keep_alive_interval(Some(Duration::from_secs(1)));
    let transport = Arc::new(transport);
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(nestlink_transport_stream::tls::server_config(local, peer).map_err(io::Error::other)?).map_err(io::Error::other)?));
    server.transport_config(transport.clone());
    server.migration(false);
    let mut endpoint = Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), Some(server), socket, Arc::new(quinn::TokioRuntime))?;
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(nestlink_transport_stream::tls::client_config(local, peer).map_err(io::Error::other)?).map_err(io::Error::other)?));
    client.transport_config(transport);
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}
