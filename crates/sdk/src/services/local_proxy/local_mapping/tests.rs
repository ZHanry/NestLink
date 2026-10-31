use super::*;
use fast_socks5::{
    AuthenticationMethod,
    client::{Config, Socks5Stream},
};

fn udp_choice() -> Result<LocalProxyServiceChoice, Box<dyn std::error::Error>> {
    let mut entry = super::super::tests::entry()?;
    entry.service.definition.requested_ingress = ServiceIngress::Udp { port: 53 };
    entry.service.definition_sha256 = URL_SAFE_NO_PAD.encode(
        nestlink_identity::services::definition_digest(&entry.service.definition)?,
    );
    Ok(LocalProxyServiceChoice::from_local_choice(
        &entry,
        "dns.nestlink.internal",
        53,
        4096,
        Duration::from_secs(30),
    )?)
}

#[test]
fn udp_association_requires_explicit_endpoint_matching_authenticated_tcp_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let tcp: SocketAddr = "127.0.0.1:41000".parse()?;
    let exact: SocketAddr = "127.0.0.1:42000".parse()?;
    assert_eq!(association_peer(&TargetAddr::Ip(exact), tcp), Some(exact));
    for target in [
        TargetAddr::Ip("0.0.0.0:0".parse()?),
        TargetAddr::Ip("127.0.0.1:0".parse()?),
        TargetAddr::Ip("127.0.0.2:42000".parse()?),
        TargetAddr::Ip("[::1]:42000".parse()?),
        TargetAddr::Ip("192.0.2.1:42000".parse()?),
        TargetAddr::Domain("localhost".into(), 42000),
    ] {
        assert_eq!(association_peer(&target, tcp), None);
    }
    let v6: SocketAddr = "[::1]:41000".parse()?;
    let exact_v6: SocketAddr = "[::1]:42000".parse()?;
    assert_eq!(
        association_peer(&TargetAddr::Ip(exact_v6), v6),
        Some(exact_v6)
    );
    Ok(())
}

#[tokio::test]
async fn mature_udp_codec_admits_empty_and_max_payload_only_for_exact_peer_and_target()
-> Result<(), Box<dyn std::error::Error>> {
    let choice = udp_choice()?;
    let peer: SocketAddr = "127.0.0.1:42000".parse()?;
    let header = new_udp_header(("dns.nestlink.internal", 53))?;
    assert_eq!(
        admitted_packet(&choice, peer, peer, &header).await,
        Some(&[][..])
    );
    let payload = vec![0xa7; DatagramPacket::MAX_PAYLOAD];
    let mut maximum = header.clone();
    maximum.extend_from_slice(&payload);
    assert_eq!(
        admitted_packet(&choice, peer, peer, &maximum).await,
        Some(payload.as_slice())
    );
    let mut oversized = maximum;
    oversized.push(0);
    assert!(
        admitted_packet(&choice, peer, peer, &oversized)
            .await
            .is_none()
    );
    for source in ["127.0.0.1:42001", "127.0.0.2:42000", "192.0.2.1:42000"] {
        assert!(
            admitted_packet(&choice, peer, source.parse()?, &header)
                .await
                .is_none()
        );
    }
    for target in [
        TargetAddr::Domain("other.nestlink.internal".into(), 53),
        TargetAddr::Domain("dns.nestlink.internal".into(), 54),
        TargetAddr::Ip("127.0.0.1:53".parse()?),
    ] {
        let packet = new_udp_header(target)?;
        assert!(
            admitted_packet(&choice, peer, peer, &packet)
                .await
                .is_none()
        );
    }
    let mut fragment = header.clone();
    fragment[2] = 1;
    let mut reserved = header.clone();
    reserved[0] = 1;
    for packet in [&fragment[..], &reserved[..], &header[..2], &[]] {
        assert!(admitted_packet(&choice, peer, peer, packet).await.is_none());
    }
    Ok(())
}

#[test]
fn datagram_work_cap_counts_empty_packets_and_byte_cap_covers_both_directions() {
    let mut budget = LocalDatagramBudget {
        bytes: 0,
        events: 0,
        maximum_bytes: 10,
    };
    assert!(budget.admit_bytes(4));
    assert!(budget.admit_bytes(6));
    assert!(!budget.admit_bytes(1));
    assert_eq!(budget.bytes, 10);
    for _ in 0..MAX_DATAGRAM_EVENTS {
        assert!(budget.observe_event());
        assert!(budget.admit_bytes(0));
    }
    assert!(!budget.observe_event());
    assert_eq!(budget.bytes, 10);
    let mut overflow = LocalDatagramBudget {
        bytes: u64::MAX,
        events: u64::MAX,
        maximum_bytes: u64::MAX,
    };
    assert!(!overflow.admit_bytes(1));
    assert!(!overflow.observe_event());
}

async fn associate(
    command: Socks5Command,
    target: TargetAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let credentials = Arc::new(Credentials::new());
    let expected = credentials.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.map_err(|_| ())?;
        let (protocol, _) = authenticate_association(socket, &expected).await?;
        protocol.reply_success(address).await.map_err(|_| ())?;
        Ok::<_, ()>(())
    });
    let mut client = Socks5Stream::use_stream(
        TcpStream::connect(address).await?,
        Some(AuthenticationMethod::Password {
            username: credentials.username.expose().to_owned(),
            password: credentials.password.expose().to_owned(),
        }),
        Config::default(),
    )
    .await
    .map_err(|_| io::Error::other("standard client authentication failed"))?;
    let accepted = client.request(command, target).await.is_ok();
    assert_eq!(accepted, server.await?.is_ok());
    Ok(accepted)
}

#[tokio::test]
async fn mature_association_client_observes_exact_source_and_command_policy()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(SETUP_BUDGET, async {
        assert!(
            associate(
                Socks5Command::UDPAssociate,
                TargetAddr::Ip("127.0.0.1:42000".parse()?)
            )
            .await?
        );
        for target in [
            TargetAddr::Ip("0.0.0.0:0".parse()?),
            TargetAddr::Ip("127.0.0.1:0".parse()?),
            TargetAddr::Ip("127.0.0.2:42000".parse()?),
            TargetAddr::Domain("localhost".into(), 42000),
        ] {
            assert!(!associate(Socks5Command::UDPAssociate, target).await?);
        }
        assert!(
            !associate(
                Socks5Command::TCPConnect,
                TargetAddr::Ip("127.0.0.1:42000".parse()?)
            )
            .await?
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}
