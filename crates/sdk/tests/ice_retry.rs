use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc, time::Instant};
use webrtc::{
    ice::{
        agent::{Agent, agent_config::AgentConfig},
        candidate::{
            Candidate, candidate_base::CandidateBaseConfig, candidate_host::CandidateHostConfig,
        },
        mdns::MulticastDnsMode,
        network_type::NetworkType,
        udp_network::{ConnectivityEvent, ConnectivityObserver, EphemeralUDP, UDPNetwork},
    },
    util::Conn,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn endpoint(observer: Option<ConnectivityObserver>) -> Result<(Agent, SocketAddr)> {
    let mut network = EphemeralUDP::default();
    if let Some(observer) = observer {
        network.set_connectivity_observer(observer);
    }
    endpoint_with_network(network).await
}

async fn endpoint_with_network(network: EphemeralUDP) -> Result<(Agent, SocketAddr)> {
    let agent = Agent::new(AgentConfig {
        udp_network: UDPNetwork::Ephemeral(network),
        network_types: vec![NetworkType::Udp4],
        candidate_types: vec![webrtc::ice::candidate::CandidateType::Host],
        multicast_dns_mode: MulticastDnsMode::Disabled,
        include_loopback: true,
        ip_filter: Arc::new(Some(Box::new(|ip: std::net::IpAddr| ip.is_loopback()))),
        ..Default::default()
    })
    .await?;
    let (tx, mut rx) = mpsc::channel(8);
    agent.on_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(candidate).await;
        })
    }));
    agent.gather_candidates()?;
    while rx.recv().await.flatten().is_some() {}
    let candidates = agent.get_local_candidates().await?;
    let candidate = candidates.first().ok_or("missing loopback candidate")?;
    Ok((
        agent,
        SocketAddr::new(candidate.address().parse()?, candidate.port()),
    ))
}

#[cfg(windows)]
#[tokio::test]
async fn unreachable_udp_candidate_does_not_end_the_production_socket_receiver() -> Result {
    use nestlink_platform_network::path::{NetworkPathManager, RoutePolicy};
    let paths = NetworkPathManager::new(RoutePolicy::System)?;
    let mut network = EphemeralUDP::default();
    network.set_socket_factory(Arc::new(move |address| paths.bind_udp(address)));
    let (a, _) = endpoint_with_network(network).await?;
    let (b, _) = endpoint(None).await?;
    let unused = UdpSocket::bind("127.0.0.1:0").await?;
    let closed_address = unused.local_addr()?;
    drop(unused);
    let local_candidates = a.get_local_candidates().await?;
    let socket = local_candidates
        .first()
        .and_then(|c| c.get_conn())
        .ok_or("missing candidate socket")?;
    // Windows reports ICMP Port Unreachable as WSAECONNRESET on the next
    // recv_from. The ICE receiver must still handle a later valid candidate.
    socket
        .send_to(b"unreachable-candidate", closed_address)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for candidate in b.get_local_candidates().await? {
        a.add_remote_candidate(&candidate)?;
    }
    for candidate in &local_candidates {
        b.add_remote_candidate(candidate)?;
    }
    let (a_ufrag, a_pwd) = a.get_local_user_credentials().await;
    let (b_ufrag, b_pwd) = b.get_local_user_credentials().await;
    let (_cancel_a, rx_a) = mpsc::channel(1);
    let (_cancel_b, rx_b) = mpsc::channel(1);
    let result = tokio::time::timeout(Duration::from_secs(4), async {
        let (a_conn, b_conn) =
            tokio::try_join!(a.accept(rx_a, b_ufrag, b_pwd), b.dial(rx_b, a_ufrag, a_pwd))?;
        b_conn.send(b"valid-peer-after-icmp").await?;
        let mut bytes = [0; 64];
        let length = a_conn.recv(&mut bytes).await?;
        assert_eq!(&bytes[..length], b"valid-peer-after-icmp");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    a.close().await?;
    b.close().await?;
    result??;
    Ok(())
}

fn proxy_candidate(address: SocketAddr) -> Result<Arc<dyn Candidate + Send + Sync>> {
    Ok(Arc::new(
        CandidateHostConfig {
            base_config: CandidateBaseConfig {
                network: "udp".into(),
                address: address.ip().to_string(),
                port: address.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    ))
}

#[tokio::test]
async fn direct_ice_recovers_when_the_first_four_seconds_of_checks_are_lost() -> Result {
    let (a, address_a) = endpoint(None).await?;
    let (b, address_b) = endpoint(None).await?;
    let forward_a = UdpSocket::bind("127.0.0.1:0").await?;
    let forward_b = UdpSocket::bind("127.0.0.1:0").await?;
    a.add_remote_candidate(&proxy_candidate(forward_a.local_addr()?)?)?;
    b.add_remote_candidate(&proxy_candidate(forward_b.local_addr()?)?)?;
    let open_at = Instant::now() + Duration::from_secs(4);
    let forwarder = tokio::spawn(async move {
        let mut buffer_a = [0; 2048];
        let mut buffer_b = [0; 2048];
        loop {
            tokio::select! {
                packet = forward_a.recv_from(&mut buffer_a) => {
                    let (length, source) = packet?;
                    if source == address_a && Instant::now() >= open_at {
                        forward_b.send_to(&buffer_a[..length], address_b).await?;
                    }
                }
                packet = forward_b.recv_from(&mut buffer_b) => {
                    let (length, source) = packet?;
                    if source == address_b && Instant::now() >= open_at {
                        forward_a.send_to(&buffer_b[..length], address_a).await?;
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    let (a_ufrag, a_pwd) = a.get_local_user_credentials().await;
    let (b_ufrag, b_pwd) = b.get_local_user_credentials().await;
    let (_a_cancel, a_rx) = mpsc::channel(1);
    let (_b_cancel, b_rx) = mpsc::channel(1);
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let (a_conn, b_conn) =
            tokio::try_join!(a.accept(a_rx, b_ufrag, b_pwd), b.dial(b_rx, a_ufrag, a_pwd),)?;
        a_conn.send(b"direct-after-initial-loss").await?;
        let mut received = [0; 64];
        let length = b_conn.recv(&mut received).await?;
        assert_eq!(&received[..length], b"direct-after-initial-loss");
        assert!(Instant::now() >= open_at);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    a.close().await?;
    b.close().await?;
    forwarder.abort();
    result??;
    Ok(())
}

#[tokio::test]
async fn ingress_evidence_records_rejected_udp_and_preserves_authenticated_connectivity() -> Result
{
    use webrtc::stun::{
        agent::TransactionId,
        attributes::ATTR_USERNAME,
        fingerprint::FINGERPRINT,
        integrity::MessageIntegrity,
        message::{BINDING_REQUEST, Message},
        textattrs::Username,
    };
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = events.clone();
    let observer: ConnectivityObserver = Arc::new(move |_, event| {
        observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    });
    let (a, address_a) = endpoint(Some(observer)).await?;
    let (b, _) = endpoint(None).await?;
    for candidate in b.get_local_candidates().await? {
        a.add_remote_candidate(&candidate)?;
    }
    for candidate in a.get_local_candidates().await? {
        b.add_remote_candidate(&candidate)?;
    }
    let (a_ufrag, a_pwd) = a.get_local_user_credentials().await;
    let (b_ufrag, b_pwd) = b.get_local_user_credentials().await;
    let (_cancel_a, rx_a) = mpsc::channel(1);
    let (_cancel_b, rx_b) = mpsc::channel(1);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let dial = async {
            let sender = UdpSocket::bind("127.0.0.1:0").await?;
            let mut message = Message::new();
            message.build(&[
                Box::new(TransactionId::new()),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(ATTR_USERNAME, "wrong:browser".into())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    "wrong-password".into(),
                )),
                Box::new(FINGERPRINT),
            ])?;
            sender.send_to(&message.raw, address_a).await?;
            loop {
                if events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&ConnectivityEvent::UsernameRejected)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(b.dial(rx_b, a_ufrag, a_pwd).await?)
        };
        let (a_conn, b_conn) = tokio::try_join!(
            async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    a.accept(rx_a, b_ufrag, b_pwd).await?,
                )
            },
            dial
        )?;
        b_conn.send(b"authenticated-after-rejection").await?;
        let mut bytes = [0; 64];
        let count = a_conn.recv(&mut bytes).await?;
        assert_eq!(&bytes[..count], b"authenticated-after-rejection");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    a.close().await?;
    b.close().await?;
    result??;
    let events = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(events.contains(&ConnectivityEvent::DatagramReceived));
    assert!(events.contains(&ConnectivityEvent::BindingRequestReceived));
    assert!(events.contains(&ConnectivityEvent::BindingResponseReceived));
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == ConnectivityEvent::UsernameRejected)
            .count(),
        1
    );
    Ok(())
}
