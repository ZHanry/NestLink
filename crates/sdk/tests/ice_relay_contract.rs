//! Real ICE candidates through the exact TURN client consumed by WebRTC.
//! The owned loopback path is a relay regression, not Internet P2P acceptance.
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc};
use webrtc::{
    ice::{
        agent::{Agent, agent_config::AgentConfig},
        candidate::CandidateType,
        mdns::MulticastDnsMode,
        network_type::NetworkType,
        udp_network::{ConnectivityEvent, EphemeralUDP, SocketStage, UDPNetwork},
        url::{ProtoType, SchemeType, Url},
    },
    turn::{
        self,
        auth::{AuthHandler, generate_auth_key},
        relay::relay_static::RelayAddressGeneratorStatic,
        server::{
            Server,
            config::{ConnConfig, ServerConfig},
        },
    },
    util::{Conn, vnet::net::Net},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct OwnedAuth;
impl AuthHandler for OwnedAuth {
    fn auth_handle(
        &self,
        user: &str,
        realm: &str,
        _: SocketAddr,
    ) -> std::result::Result<Vec<u8>, turn::Error> {
        if user != "owned-relay-check" || realm != "owned-relay-check" {
            return Err(turn::Error::ErrNoPermission);
        }
        Ok(generate_auth_key(user, realm, "owned-relay-check"))
    }
}

async fn gathered(config: AgentConfig) -> Result<Agent> {
    let agent = Agent::new(config).await?;
    let (tx, mut rx) = mpsc::channel(8);
    agent.on_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(candidate.is_none()).await;
        })
    }));
    agent.gather_candidates()?;
    tokio::time::timeout(Duration::from_secs(4), async {
        while rx.recv().await == Some(false) {}
    })
    .await?;
    if agent.get_local_candidates().await?.is_empty() {
        agent.close().await?;
        return Err("owned candidate gathering produced no candidates".into());
    }
    Ok(agent)
}

#[tokio::test]
async fn relay_ice_observer_accepts_payload_writes_and_transfers_both_directions() -> Result {
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let address = server_socket.local_addr()?;
    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn: server_socket,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                address: "127.0.0.1".into(),
                net: Arc::new(Net::new(None)),
            }),
        }],
        realm: "owned-relay-check".into(),
        auth_handler: Arc::new(OwnedAuth),
        channel_bind_timeout: Duration::from_secs(600),
        alloc_close_notify: None,
    })
    .await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let mut network = EphemeralUDP::default();
    network.set_connectivity_observer(Arc::new(move |kind, event| {
        if kind == CandidateType::Relay {
            observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
        }
    }));
    let relay = gathered(AgentConfig {
        urls: vec![Url {
            scheme: SchemeType::Turn,
            proto: ProtoType::Udp,
            host: address.ip().to_string(),
            port: address.port(),
            username: "owned-relay-check".into(),
            password: "owned-relay-check".into(),
        }],
        udp_network: UDPNetwork::Ephemeral(network),
        candidate_types: vec![CandidateType::Relay],
        network_types: vec![NetworkType::Udp4],
        include_loopback: true,
        multicast_dns_mode: MulticastDnsMode::Disabled,
        ..Default::default()
    })
    .await?;
    let direct = gathered(AgentConfig {
        candidate_types: vec![CandidateType::Host],
        network_types: vec![NetworkType::Udp4],
        include_loopback: true,
        ip_filter: Arc::new(Some(Box::new(|ip: IpAddr| ip.is_loopback()))),
        multicast_dns_mode: MulticastDnsMode::Disabled,
        ..Default::default()
    })
    .await?;
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        for (from, to) in [(&relay, &direct), (&direct, &relay)] {
            for candidate in from.get_local_candidates().await? {
                to.add_remote_candidate(&candidate)?;
            }
        }
        let (ru, rp) = relay.get_local_user_credentials().await;
        let (du, dp) = direct.get_local_user_credentials().await;
        let (_rc, rx) = mpsc::channel(1);
        let (_dc, dx) = mpsc::channel(1);
        let (rc, dc) = tokio::try_join!(relay.accept(rx, du, dp), direct.dial(dx, ru, rp))?;
        assert_eq!(relay.get_selected_candidate_pair().ok_or("missing selected relay")?.local.candidate_type(), CandidateType::Relay);
        let mut bytes = [0; 1280];
        for payload in [vec![1, 2, 3], vec![42; 1000], vec![7; 4]] {
            assert_eq!(rc.send(&payload).await?, payload.len());
            let size = dc.recv(&mut bytes).await?;
            assert_eq!(&bytes[..size], payload);
            assert_eq!(dc.send(&payload).await?, payload.len());
            let size = rc.recv(&mut bytes).await?;
            assert_eq!(&bytes[..size], payload);
        }
        let evidence = events.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(evidence.iter().any(|event| matches!(event, ConnectivityEvent::Socket(s) if s.stage == SocketStage::SendAccepted)));
        assert!(!evidence.iter().any(|event| matches!(event, ConnectivityEvent::Socket(s) if matches!(s.stage, SocketStage::SendShort | SocketStage::SendError))));
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }).await;
    relay.close().await?;
    direct.close().await?;
    server.close().await?;
    result??;
    Ok(())
}
