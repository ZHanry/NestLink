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
    },
    util::Conn,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn endpoint() -> Result<(Agent, SocketAddr)> {
    let agent = Agent::new(AgentConfig {
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
    let (a, address_a) = endpoint().await?;
    let (b, address_b) = endpoint().await?;
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
