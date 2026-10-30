//! Signed bilateral native ICE followed by pinned Quinn on its original UDP
//! socket. One frozen candidate per endpoint bounds this initial dialect;
//! general candidate migration and advanced NAT strategies are separate work.
mod socket;
mod mapping;
use mapping::MappingOwner;
use super::*;
use nestlink_identity::InstallationIdentity;
use nestlink_platform_network::path::NetworkPathManager;
use nestlink_protocol::api::NativeIceParameters;
use nestlink_remote::TransportOwner;
use quinn::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
#[doc(hidden)]
pub use socket::IceUdp;
use std::{io, net::UdpSocket};
use tokio::{sync::mpsc, time::Instant as TokioInstant};
use webrtc::ice::{
    agent::{Agent, agent_config::AgentConfig},
    candidate::{Candidate as IceCandidate, CandidateType, candidate_base::unmarshal_candidate},
    mdns::MulticastDnsMode,
    network_type::NetworkType,
    udp_network::{EphemeralUDP, UDPNetwork},
    url::Url,
};

const CHECK_BUDGET: Duration = Duration::from_secs(3);
const CLEANUP_BUDGET: Duration = Duration::from_secs(5);

/// Physical ICE owner. Drop requests cleanup; only close_and_wait confirms it.
pub struct IceOwner {
    agent: Option<Arc<Agent>>,
    socket: Option<Arc<IceUdp>>,
    endpoint: Option<Endpoint>,
    original: Arc<Mutex<Vec<SocketAddr>>>,
    connected_socket: Arc<Mutex<Option<UdpSocket>>>,
    pending_socket: Arc<Mutex<Option<UdpSocket>>>,
    mapping: Option<MappingOwner>,
    close_deadline: Option<TokioInstant>,
    closed: bool,
}
impl IceOwner {
    pub(super) fn failure(&self) -> io::Result<watch::Receiver<Option<io::ErrorKind>>> {
        self.socket
            .as_ref()
            .map(|socket| socket.failure())
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    async fn close(&mut self, deadline: TokioInstant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.endpoint = None;
        if let Some(socket) = &self.socket {
            socket.close_tasks(deadline).await?;
        }
        self.socket = None;
        if let Some(agent) = &self.agent {
            tokio::time::timeout_at(deadline, agent.close())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(io::Error::other)?;
        }
        self.agent = None;
        if let Some(mapping) = &self.mapping {
            mapping.close_and_wait(deadline).await?;
        }
        self.mapping = None;
        drop(
            self.pending_socket
                .lock()
                .map_err(|_| io::Error::other("ICE owner poisoned"))?
                .take(),
        );
        drop(
            self.connected_socket
                .lock()
                .map_err(|_| io::Error::other("ICE owner poisoned"))?
                .take(),
        );
        let addresses = self
            .original
            .lock()
            .map_err(|_| io::Error::other("ICE owner poisoned"))?
            .clone();
        for address in addresses {
            loop {
                if TokioInstant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                match UdpSocket::bind(address) {
                    Ok(rebound) => {
                        drop(rebound);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::time::sleep_until(
                            deadline.min(TokioInstant::now() + Duration::from_millis(10)),
                        )
                        .await;
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
        if let Some(mapping) = &self.mapping {
            mapping.request_close();
        }
        if let Some(endpoint) = &self.endpoint {
            // Keep the original adapter alive while Quinn sends its terminal
            // authenticated close. Business channels already stop through the
            // session lifecycle; closing the writer here would discard that
            // close and leave the peer waiting for its consent timeout.
            endpoint.close(0u32.into(), b"native ICE owner stopping");
        } else if let Some(socket) = &self.socket {
            socket.request_close();
        }
    }
    fn close_and_wait(
        &mut self,
        deadline: TokioInstant,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(self.close(deadline))
    }
}
impl Drop for IceOwner {
    fn drop(&mut self) {
        self.request_close();
        // A dropped owner cannot await Quinn's drain. Request local task stop
        // unconditionally; this path supplies no physical-cleanup receipt.
        if let Some(socket) = &self.socket {
            socket.request_close();
        }
        if !self.closed
            && let Some(agent) = self.agent.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let deadline = self
                .close_deadline
                .unwrap_or(TokioInstant::now() + CLEANUP_BUDGET);
            runtime.spawn(async move {
                let _ = tokio::time::timeout_at(deadline, agent.close()).await;
            });
        }
    }
}

pub(super) struct Gathering {
    owner: IceOwner,
    pub(super) parameters: NativeIceParameters,
}
struct Preparation {
    owner: IceOwner,
    config: Option<AgentConfig>,
    external: Option<SocketAddr>,
}
impl Preparation {
    fn new(
        endpoint: &NativeEndpoint,
        servers: &[SocketAddr],
        pcp_gateway: Option<std::net::Ipv4Addr>,
    ) -> Result<Self, DialError> {
        endpoint.check()?;
        if servers.len() > 4 {
            return Err(DialError::Binding);
        }
        let bound = endpoint.local_addr()?;
        let path = Arc::new(NetworkPathManager::from_default().map_err(|_| DialError::Setup)?);
        let ip = path
            .candidate_interfaces(bound)
            .map_err(|_| DialError::NetworkChanged)?
            .into_iter()
            .flat_map(|interface| interface.addresses)
            .find(|ip| {
                safe_peer_address(*ip)
                    && (pcp_gateway.is_none() || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_private()))
            })
            .ok_or(DialError::Setup)?;
        let servers: Vec<_> = servers
            .iter()
            .filter(|server| server.is_ipv4() == ip.is_ipv4())
            .copied()
            .collect();
        let use_stun = !servers.is_empty() && pcp_gateway.is_none();
        let original = Arc::new(Mutex::new(Vec::new()));
        let connected_socket = Arc::new(Mutex::new(None));
        let pending_socket = Arc::new(Mutex::new(None));
        let mut owner = IceOwner {
            agent: None,
            socket: None,
            endpoint: None,
            original: original.clone(),
            connected_socket: connected_socket.clone(),
            pending_socket: pending_socket.clone(),
            mapping: None,
            close_deadline: None,
            closed: false,
        };
        if let Some(gateway) = pcp_gateway {
            // Retain the real candidate socket and its mapping cleanup owner
            // before the first cancelable request can create router state.
            let socket = path
                .bind_udp(SocketAddr::new(ip, 0))
                .map_err(|_| DialError::Setup)?;
            let local = socket.local_addr().map_err(|_| DialError::Setup)?;
            *connected_socket.lock().map_err(|_| DialError::Setup)? =
                Some(socket.try_clone().map_err(|_| DialError::Setup)?);
            original.lock().map_err(|_| DialError::Setup)?.push(local);
            *pending_socket.lock().map_err(|_| DialError::Setup)? = Some(socket);
            owner.mapping = Some(
                MappingOwner::new(gateway, local, endpoint.authorization_deadline)
                    .map_err(|_| DialError::Binding)?,
            );
        }
        let retained = connected_socket.clone();
        let supplied = pending_socket.clone();
        let observed = original.clone();
        let physical = path.clone();
        let mut network = EphemeralUDP::default();
        network.set_socket_factory(Arc::new(move |address| {
            // The mature srflx gatherer asks for a wildcard bind. Select the
            // already-approved local interface before opening that socket.
            let address = if address.ip().is_unspecified() && address.is_ipv4() == ip.is_ipv4() {
                SocketAddr::new(ip, address.port())
            } else {
                address
            };
            if address.ip() != ip {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if pcp_gateway.is_some() {
                let mut supplied = supplied
                    .lock()
                    .map_err(|_| io::Error::other("ICE owner poisoned"))?;
                let socket = supplied.as_ref().ok_or(io::ErrorKind::AddrInUse)?;
                if address.port() != 0 && address.port() != socket.local_addr()?.port() {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                return supplied.take().ok_or_else(|| io::ErrorKind::AddrInUse.into());
            }
            let mut addresses = observed
                .lock()
                .map_err(|_| io::Error::other("ICE owner poisoned"))?;
            if !addresses.is_empty() {
                return Err(io::ErrorKind::AddrInUse.into());
            }
            let socket = physical.bind_udp(address)?;
            *retained
                .lock()
                .map_err(|_| io::Error::other("ICE owner poisoned"))? = Some(socket.try_clone()?);
            addresses.push(socket.local_addr()?);
            Ok(socket)
        }));
        let urls = servers
            .first()
            .filter(|_| use_stun)
            .map(|server| Url::parse_url(&format!("stun:{server}")))
            .transpose()
            .map_err(|_| DialError::Binding)?
            .into_iter()
            .collect();
        let config = AgentConfig {
            udp_network: UDPNetwork::Ephemeral(network),
            network_types: vec![if ip.is_ipv4() {
                NetworkType::Udp4
            } else {
                NetworkType::Udp6
            }],
            candidate_types: vec![if use_stun || pcp_gateway.is_some() {
                CandidateType::ServerReflexive
            } else {
                CandidateType::Host
            }],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            include_loopback: false,
            ip_filter: Arc::new(Some(Box::new(move |candidate| candidate == ip))),
            urls,
            disconnected_timeout: Some(Duration::from_secs(5)),
            failed_timeout: Some(Duration::from_secs(5)),
            keepalive_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        Ok(Self { owner, config: Some(config), external: None })
    }
    async fn establish_mapping(
        &mut self,
        endpoint: &NativeEndpoint,
    ) -> Result<(), DialError> {
        if let Some(mapping) = &self.owner.mapping {
            let external = mapping.establish(&endpoint.address_policy).await
                .map_err(|_| DialError::Setup)?;
            let config = self.config.as_mut().ok_or(DialError::Setup)?;
            config.nat_1to1_ips = vec![external.ip().to_string()];
            config.nat_1to1_ip_candidate_type = CandidateType::ServerReflexive;
            self.external = Some(external);
        }
        endpoint.check()?;
        Ok(())
    }
    async fn prepare_agent(&mut self) -> Result<(), DialError> {
        let config = self.config.take().ok_or(DialError::Setup)?;
        // With mDNS disabled this constructor opens no candidate socket. As
        // in the existing path, finish construction before selecting cancel,
        // so every started internal agent task has its original close owner.
        let agent = Arc::new(Agent::new(config).await.map_err(|_| DialError::Setup)?);
        self.owner.agent = Some(agent.clone());
        if let Some(mapping) = &mut self.owner.mapping {
            mapping.start(agent).map_err(|_| DialError::Setup)?;
        }
        Ok(())
    }
    async fn gather(
        &mut self,
        endpoint: &NativeEndpoint,
    ) -> Result<NativeIceParameters, DialError> {
        let agent = self.owner.agent.as_ref().ok_or(DialError::Setup)?;
        let (tx, mut rx) = mpsc::channel(2);
        agent.on_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(candidate.is_some()).await;
            })
        }));
        agent.gather_candidates().map_err(|_| DialError::Setup)?;
        while rx.recv().await.ok_or(DialError::Setup)? {}
        endpoint.check()?;
        let candidates = agent
            .get_local_candidates()
            .await
            .map_err(|_| DialError::Setup)?;
        if candidates.len() != 1 {
            return Err(DialError::Setup);
        }
        let (username_fragment, password) = agent.get_local_user_credentials().await;
        let parameters = NativeIceParameters {
            version: nestlink_protocol::native_ice::VERSION,
            username_fragment,
            password,
            candidate: candidates[0].marshal(),
        };
        let address = parameters.address()?;
        if !endpoint.address_policy.allows(address.ip())
            || self.external.is_some_and(|external| external != address)
        {
            return Err(DialError::Binding);
        }
        Ok(parameters)
    }
}

pub(super) async fn gather(
    endpoint: &NativeEndpoint,
    servers: &[SocketAddr],
    pcp_gateway: Option<std::net::Ipv4Addr>,
    mut cancel: watch::Receiver<bool>,
) -> Result<Gathering, DialError> {
    if *cancel.borrow() || cancel.has_changed().is_err() {
        return Err(DialError::Cancelled);
    }
    // Keep the physical socket and exact mapping nonce outside the future
    // that establishes the mapping and constructs the mature ICE agent.
    let mut preparation = Preparation::new(endpoint, servers, pcp_gateway)?;
    let deadline = TokioInstant::from_std(endpoint.authorization_deadline)
        .min(TokioInstant::now() + CANDIDATE_GATHER_BUDGET);
    let prepared = tokio::select! { biased;
        _ = cancellation(&mut cancel) => Err(DialError::Cancelled),
        result = tokio::time::timeout_at(deadline, preparation.establish_mapping(endpoint)) => result.unwrap_or(Err(DialError::Setup)),
    };
    let prepared = match prepared {
        Ok(()) => preparation.prepare_agent().await,
        Err(error) => Err(error),
    };
    let result = match prepared {
        Ok(()) => tokio::select! { biased;
            _ = cancellation(&mut cancel) => Err(DialError::Cancelled),
            result = tokio::time::timeout_at(deadline, preparation.gather(endpoint)) => result.unwrap_or(Err(DialError::Setup)),
        },
        Err(error) => Err(error),
    };
    match result {
        Ok(parameters) => Ok(Gathering {
            owner: preparation.owner,
            parameters,
        }),
        Err(error) => {
            if let Err(source) = preparation
                .owner
                .close(TokioInstant::now() + CLEANUP_BUDGET)
                .await
            {
                return Err(DialError::Cleanup {
                    primary: Box::new(error),
                    source,
                });
            }
            Err(error)
        }
    }
}

impl Gathering {
    pub(super) async fn close(mut self) -> Result<(), DialError> {
        self.owner
            .close(TokioInstant::now() + CLEANUP_BUDGET)
            .await
            .map_err(|source| DialError::Cleanup {
                primary: Box::new(DialError::Setup),
                source,
            })
    }

    pub(super) async fn connect(
        mut self,
        endpoint: &NativeEndpoint,
        local: &DeviceIdentity,
        peer: &NativeIceParameters,
        generation: u64,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        let deadline = TokioInstant::from_std(endpoint.authorization_deadline)
            .min(TokioInstant::now() + CHECK_BUDGET);
        let result = tokio::select! { biased;
            _ = cancellation(&mut cancel) => Err(DialError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.connect_inner(endpoint, local, peer, generation)) => result.unwrap_or(Err(DialError::Setup)),
        };
        match result {
            Ok((connection, candidate)) => {
                let quinn = self
                    .owner
                    .endpoint
                    .as_ref()
                    .ok_or(DialError::Setup)?
                    .clone();
                Ok(NativeConnection {
                    transport: NativeTransport::Ice {
                        connection,
                        endpoint: quinn,
                        carrier: Box::new(self.owner),
                    },
                    candidate,
                    failures: Vec::new(),
                    network: endpoint.network_binding()?,
                    authorization_deadline: endpoint.authorization_deadline,
                })
            }
            Err(error) => {
                if let Err(source) = self.owner.close(TokioInstant::now() + CLEANUP_BUDGET).await {
                    return Err(DialError::Cleanup {
                        primary: Box::new(error),
                        source,
                    });
                }
                Err(error)
            }
        }
    }
    async fn connect_inner(
        &mut self,
        endpoint: &NativeEndpoint,
        local: &DeviceIdentity,
        peer: &NativeIceParameters,
        generation: u64,
    ) -> Result<(quinn::Connection, Candidate), DialError> {
        endpoint.check()?;
        let address = peer.address()?;
        if !endpoint.address_policy.allows(address.ip()) {
            return Err(DialError::Binding);
        }
        // This is a duplicate handle to the original OS socket, never a new
        // bind. Before ICE can receive a peer check, the kernel filters every
        // source except the single signed and locally approved peer tuple.
        // The mature agent cannot create peer-reflexive candidates from an
        // unapproved source. A changed NAT tuple must fall back or restart.
        self.owner
            .connected_socket
            .lock()
            .map_err(|_| DialError::Setup)?
            .as_ref()
            .ok_or(DialError::Setup)?
            .connect(address)
            .map_err(|_| DialError::Setup)?;
        let agent = self.owner.agent.as_ref().ok_or(DialError::Setup)?.clone();
        let candidate: Arc<dyn IceCandidate + Send + Sync> =
            Arc::new(unmarshal_candidate(&peer.candidate).map_err(|_| DialError::Binding)?);
        agent
            .add_remote_candidate(&candidate)
            .map_err(|_| DialError::Setup)?;
        let (_keep, cancel) = mpsc::channel(1);
        let conn: Arc<dyn webrtc::util::Conn + Send + Sync> = match endpoint.role {
            EndpointRole::Controller => agent
                .dial(
                    cancel,
                    peer.username_fragment.clone(),
                    peer.password.clone(),
                )
                .await
                .map_err(|_| DialError::Setup)?,
            EndpointRole::Host => agent
                .accept(
                    cancel,
                    peer.username_fragment.clone(),
                    peer.password.clone(),
                )
                .await
                .map_err(|_| DialError::Setup)?,
        };
        endpoint.check()?;
        let actual = conn.remote_addr().ok_or(DialError::Setup)?;
        if actual != address || !endpoint.address_policy.allows(actual.ip()) {
            return Err(DialError::Binding);
        }
        let socket = IceUdp::new(agent, conn).map_err(|_| DialError::Setup)?;
        let quinn = quinn_endpoint(socket.clone(), &local.identity, digest(&endpoint.peer_key))
            .map_err(|_| DialError::Setup)?;
        self.owner.socket = Some(socket);
        self.owner.endpoint = Some(quinn.clone());
        let connected = match endpoint.role {
            EndpointRole::Controller => {
                quinn
                    .connect(actual, "peer.nestlink.invalid")
                    .map_err(|_| DialError::Setup)?
                    .await
            }
            EndpointRole::Host => quinn.accept().await.ok_or(DialError::Setup)?.await,
        }
        .map_err(|error| DialError::Failed {
            code: failure::classify(&error, ErrorCode::DirectUnavailable),
            failures: Vec::new(),
        })?;
        endpoint.check()?;
        Ok((connected, inbound_candidate(actual, generation)))
    }
}

fn quinn_endpoint(
    socket: Arc<IceUdp>,
    local: &InstallationIdentity,
    peer: [u8; 32],
) -> io::Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None);
    transport
        .max_concurrent_bidi_streams(16u8.into())
        .max_concurrent_uni_streams(8u8.into());
    transport.send_window(512 * 1024);
    transport.datagram_receive_buffer_size(Some(32 * 1200));
    transport.datagram_send_buffer_size(16 * 1200);
    transport.keep_alive_interval(Some(Duration::from_secs(1)));
    let transport = Arc::new(transport);
    let mut server = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(
            nestlink_transport_stream::tls::server_config(local, peer).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?,
    ));
    server.transport_config(transport.clone());
    server.migration(false);
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let mut client = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(
            nestlink_transport_stream::tls::client_config(local, peer).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?,
    ));
    client.transport_config(transport);
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closing_before_agent_construction_releases_original_socket_and_unused_mapping()
    -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        let retained = socket.try_clone()?;
        let pending = Arc::new(Mutex::new(Some(socket)));
        // No create request has been sent. Closing this owner must not contact
        // a gateway, and must release both handles to its real UDP socket.
        let mapping = MappingOwner::new(
            std::net::Ipv4Addr::new(10, 32, 0, 1),
            SocketAddr::from(([10, 32, 0, 2], address.port())),
            Instant::now() + Duration::from_secs(10),
        )?;
        let mut owner = IceOwner {
            agent: None,
            socket: None,
            endpoint: None,
            original: Arc::new(Mutex::new(vec![address])),
            connected_socket: Arc::new(Mutex::new(Some(retained))),
            pending_socket: pending.clone(),
            mapping: Some(mapping),
            close_deadline: None,
            closed: false,
        };
        assert_eq!(UdpSocket::bind(address).err().map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse));
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        owner.close(deadline).await?;
        assert!(pending.lock().map_err(|_| io::Error::other("test lock poisoned"))?.is_none());
        let rebound = UdpSocket::bind(address)?;
        drop(rebound);
        owner.close(deadline).await?;
        assert_eq!(owner.close_deadline, Some(deadline));
        Ok(())
    }
}
