use super::*;
use nestlink_traversal::turn::{
    TurnAction, TurnAllocationGrant, TurnPeerBindingActivation, TurnPurpose,
};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{net::IpAddr, sync::Arc, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::timeout,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn test_config(
    udp: bool,
    tcp: bool,
    tls: bool,
    tls_server_config: Option<Arc<ServerConfig>>,
) -> TurnServiceConfig {
    TurnServiceConfig {
        realm: "deployment.example".to_owned(),
        udp_bind: udp.then_some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tcp_bind: tcp.then_some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tls_bind: tls.then_some(SocketAddr::from(([127, 0, 0, 1], 0))),
        tls_server_config,
        relay_port_pools: vec![RelayPortPool {
            bind_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            public_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            min_port: 30000,
            max_port: 30100,
        }],
        max_connections: 32,
    }
}

fn binding_request() -> [u8; 20] {
    let mut request = [0; 20];
    request[1] = 0x01;
    request[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
    request[8..].copy_from_slice(&[
        0x4e, 0x65, 0x73, 0x74, 0x4c, 0x69, 0x6e, 0x6b, 0x54, 0x55, 0x52, 0x4e,
    ]);
    request
}

fn assert_binding_response(header: &[u8; 20]) -> TestResult {
    if u16::from_be_bytes([header[0], header[1]]) != 0x0101
        || u32::from_be_bytes(header[4..8].try_into()?) != 0x2112_a442
    {
        return Err("invalid STUN binding response".into());
    }
    Ok(())
}

fn test_tls_configs() -> TestResult<(Arc<ServerConfig>, Arc<ClientConfig>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((Arc::new(server), Arc::new(client)))
}

#[tokio::test]
async fn bind_rejects_an_offline_or_unmonitored_node() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let (_online_tx, offline_rx) = watch::channel(false);
    assert!(matches!(
        TurnService::bind(
            test_config(true, false, false, None),
            Arc::clone(&authorization),
            offline_rx,
        )
        .await,
        Err(TurnServiceError::Offline)
    ));

    let (online_tx, closed_rx) = watch::channel(true);
    drop(online_tx);
    assert!(matches!(
        TurnService::bind(
            test_config(true, false, false, None),
            authorization,
            closed_rx,
        )
        .await,
        Err(TurnServiceError::Offline)
    ));
    Ok(())
}

#[test]
fn turn_auth_stops_immediately_when_the_online_watch_changes() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let username = "1800000000:online-browser";
    let realm = "deployment.example";
    let mut grant = test_grant(
        "allocation-online-state",
        username,
        realm,
        "online-state-password",
    );
    grant.deadline = Instant::now() + Duration::from_secs(30);
    authorization.install_grant(grant)?;

    let client = SocketAddr::from(([192, 0, 2, 10], 54000));
    let (online_tx, online_rx) = watch::channel(true);
    let auth = ManagedAuth {
        authorization: Arc::clone(&authorization),
        online: online_rx,
    };
    assert!(auth.auth_handle(username, realm, client).is_ok());
    assert!(auth.authorize_allocation(username, realm, client));
    assert!(auth.allocation_ready(username, client));
    assert!(auth.authorize_operation(
        username,
        realm,
        client,
        AllocationOperation::Refresh,
        None,
        0,
    ));

    online_tx.send_replace(false);
    assert!(authorization.auth_key(username, realm).is_some());
    assert!(auth.auth_handle(username, realm, client).is_err());
    assert!(!auth.authorize_operation(
        username,
        realm,
        client,
        AllocationOperation::Refresh,
        None,
        0,
    ));
    authorization.allocation_closed(username, client);
    Ok(())
}

#[tokio::test]
async fn udp_tcp_and_tls_listeners_serve_stun_and_shutdown_cleanly() -> TestResult {
    let (server_tls, client_tls) = test_tls_configs()?;
    let authorization = Arc::new(TurnAuthorization::new(16)?);
    let (online_tx, online_rx) = watch::channel(true);
    let (service, _control) = TurnService::bind(
        test_config(true, true, true, Some(server_tls)),
        authorization,
        online_rx,
    )
    .await?;
    let addresses = service.listen_addresses();

    let udp_address = addresses.udp.ok_or("UDP listener missing")?;
    let udp_client = UdpSocket::bind("127.0.0.1:0").await?;
    udp_client.send_to(&binding_request(), udp_address).await?;
    let mut udp_response = [0; 1500];
    let (received, _) = timeout(
        Duration::from_secs(3),
        udp_client.recv_from(&mut udp_response),
    )
    .await??;
    assert!(received >= 20);
    assert_binding_response(udp_response[..20].try_into()?)?;

    let tcp_address = addresses.tcp.ok_or("TCP listener missing")?;
    let mut tcp_client = TcpStream::connect(tcp_address).await?;
    tcp_client.write_all(&binding_request()).await?;
    let mut tcp_response = [0; 20];
    timeout(
        Duration::from_secs(3),
        tcp_client.read_exact(&mut tcp_response),
    )
    .await??;
    assert_binding_response(&tcp_response)?;

    let tls_address = addresses.tls.ok_or("TLS listener missing")?;
    let tls_client = TcpStream::connect(tls_address).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    let mut tls_client = tokio_rustls::TlsConnector::from(client_tls)
        .connect(server_name, tls_client)
        .await?;
    tls_client.write_all(&binding_request()).await?;
    let mut tls_response = [0; 20];
    timeout(
        Duration::from_secs(3),
        tls_client.read_exact(&mut tls_response),
    )
    .await??;
    assert_binding_response(&tls_response)?;

    online_tx.send_replace(false);
    timeout(Duration::from_secs(3), async {
        loop {
            udp_client.send_to(&binding_request(), udp_address).await?;
            let mut response = [0; 1500];
            if timeout(
                Duration::from_millis(50),
                udp_client.recv_from(&mut response),
            )
            .await
            .is_err()
            {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    timeout(Duration::from_secs(3), async {
        loop {
            if TcpStream::connect(tcp_address).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn a_managed_udp_allocation_is_removed_by_online_revocation() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(2)?);
    let username = "1700000100:browser-1";
    let realm = "deployment.example";
    let password = "turn-test-password";
    let mut grant = test_grant("allocation-udp-1", username, realm, password);
    grant.deadline = Instant::now() + Duration::from_secs(30);
    let allocation_id = grant.allocation_id.clone();
    authorization.install_grant(grant)?;

    let (online_tx, online_rx) = watch::channel(true);
    let (service, control) = TurnService::bind(
        test_config(true, false, false, None),
        Arc::clone(&authorization),
        online_rx,
    )
    .await?;
    let address = service
        .listen_addresses()
        .udp
        .ok_or("UDP listener missing")?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN service test".to_owned(),
        rto_in_ms: 100,
        conn: socket,
        vnet: None,
    })
    .await?;
    client.listen().await?;
    let relay = timeout(Duration::from_secs(5), client.allocate()).await??;
    assert_eq!(authorization.active_allocations(), 1);
    assert!(
        relay
            .send_to(b"not paired", SocketAddr::from(([127, 0, 0, 1], 9)))
            .await
            .is_err()
    );

    control.revoke(&allocation_id).await?;
    timeout(Duration::from_secs(3), async {
        while authorization.active_allocations() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    drop(relay);
    client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn online_watch_revokes_a_live_udp_allocation_within_two_seconds() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let username = "1700000101:browser-online-revocation";
    let realm = "deployment.example";
    let password = "turn-online-revocation-password";
    let mut grant = test_grant("allocation-online-revocation", username, realm, password);
    grant.deadline = Instant::now() + Duration::from_secs(30);
    authorization.install_grant(grant)?;

    let (online_tx, online_rx) = watch::channel(true);
    let (service, _) = TurnService::bind(
        test_config(true, false, false, None),
        Arc::clone(&authorization),
        online_rx,
    )
    .await?;
    let address = service
        .listen_addresses()
        .udp
        .ok_or("UDP listener missing")?;
    let client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN online revocation test".to_owned(),
        rto_in_ms: 100,
        conn: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        vnet: None,
    })
    .await?;
    client.listen().await?;
    let relay = timeout(Duration::from_secs(5), client.allocate()).await??;
    assert_eq!(authorization.active_allocations(), 1);

    online_tx.send_replace(false);
    timeout(Duration::from_secs(2), async {
        while authorization.active_allocations() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(authorization.auth_key(username, realm).is_none());

    drop(relay);
    client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn exhausted_relay_port_budget_releases_the_allocation_slot() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let username = "1700000102:browser-port-budget";
    let realm = "deployment.example";
    let password = "turn-port-budget-password";
    let mut grant = test_grant("allocation-port-budget", username, realm, password);
    grant.deadline = Instant::now() + Duration::from_secs(30);
    authorization.install_grant(grant)?;

    let occupied_port = UdpSocket::bind("127.0.0.1:0").await?;
    let port = occupied_port.local_addr()?.port();
    let mut config = test_config(true, false, false, None);
    config.relay_port_pools[0].min_port = port;
    config.relay_port_pools[0].max_port = port;
    let (online_tx, online_rx) = watch::channel(true);
    let (service, _) = TurnService::bind(config, Arc::clone(&authorization), online_rx).await?;
    let address = service
        .listen_addresses()
        .udp
        .ok_or("UDP listener missing")?;

    let first_client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN port budget test".to_owned(),
        rto_in_ms: 100,
        conn: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        vnet: None,
    })
    .await?;
    first_client.listen().await?;
    assert!(
        timeout(Duration::from_secs(5), first_client.allocate())
            .await?
            .is_err()
    );
    assert_eq!(authorization.active_allocations(), 0);
    first_client.close().await?;

    drop(occupied_port);
    let retry_client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN port budget retry test".to_owned(),
        rto_in_ms: 100,
        conn: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        vnet: None,
    })
    .await?;
    retry_client.listen().await?;
    let relay = timeout(Duration::from_secs(5), retry_client.allocate()).await??;
    assert_eq!(authorization.active_allocations(), 1);

    drop(relay);
    retry_client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn managed_tcp_allocation_rejects_an_unpaired_peer() -> TestResult {
    run_stream_allocation(false).await
}

#[tokio::test]
async fn managed_tls_allocation_rejects_an_unpaired_peer() -> TestResult {
    run_stream_allocation(true).await
}

async fn run_stream_allocation(tls: bool) -> TestResult {
    let (tls_server, tls_client) = if tls {
        let (server, client) = test_tls_configs()?;
        (Some(server), Some(client))
    } else {
        (None, None)
    };
    let authorization = Arc::new(TurnAuthorization::new(2)?);
    let username = if tls {
        "1800000000:tls-browser"
    } else {
        "1800000000:tcp-browser"
    };
    let password = "turn-stream-test-password";
    let realm = "deployment.example";
    let allocation_id = if tls {
        "allocation-tls-1"
    } else {
        "allocation-tcp-1"
    };
    authorization.install_grant(test_grant(allocation_id, username, realm, password))?;

    let (online_tx, online_rx) = watch::channel(true);
    let (service, control) = TurnService::bind(
        test_config(false, !tls, tls, tls_server),
        Arc::clone(&authorization),
        online_rx,
    )
    .await?;
    let address = if tls {
        service
            .listen_addresses()
            .tls
            .ok_or("TLS listener missing")?
    } else {
        service
            .listen_addresses()
            .tcp
            .ok_or("TCP listener missing")?
    };
    let tcp = TcpStream::connect(address).await?;
    let conn: Arc<dyn Conn + Send + Sync> = if tls {
        let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
        let stream =
            tokio_rustls::TlsConnector::from(tls_client.ok_or("TLS client configuration missing")?)
                .connect(server_name, tcp)
                .await?;
        let local = stream.get_ref().0.local_addr()?;
        let peer = stream.get_ref().0.peer_addr()?;
        Arc::new(StreamConn::new(stream, local, peer))
    } else {
        let local = tcp.local_addr()?;
        let peer = tcp.peer_addr()?;
        Arc::new(StreamConn::new(tcp, local, peer))
    };

    let client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN stream test".to_owned(),
        rto_in_ms: 100,
        conn,
        vnet: None,
    })
    .await?;
    client.listen().await?;
    let relay = timeout(Duration::from_secs(5), client.allocate()).await??;
    assert_eq!(authorization.active_allocations(), 1);
    assert!(
        relay
            .send_to(b"not paired", SocketAddr::from(([127, 0, 0, 1], 9)))
            .await
            .is_err()
    );

    control.revoke(allocation_id).await?;
    timeout(Duration::from_secs(3), async {
        while authorization.active_allocations() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    drop(relay);
    client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn allocation_lease_expiry_closes_the_relay() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let username = "1800000000:short-browser";
    let password = "short-lease-password";
    let realm = "deployment.example";
    let mut grant = test_grant("allocation-expiring", username, realm, password);
    grant.deadline = Instant::now() + Duration::from_millis(800);
    authorization.install_grant(grant)?;
    let (online_tx, online_rx) = watch::channel(true);
    let (service, _) = TurnService::bind(
        test_config(true, false, false, None),
        Arc::clone(&authorization),
        online_rx,
    )
    .await?;
    let address = service
        .listen_addresses()
        .udp
        .ok_or("UDP listener missing")?;
    let client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN expiry test".to_owned(),
        rto_in_ms: 100,
        conn: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        vnet: None,
    })
    .await?;
    client.listen().await?;
    let relay = timeout(Duration::from_secs(4), client.allocate()).await??;
    assert_eq!(authorization.active_allocations(), 1);
    timeout(Duration::from_secs(3), async {
        while authorization.active_allocations() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    drop(relay);
    client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

#[tokio::test]
async fn peer_binding_expiry_closes_the_relay_without_expiring_the_grant() -> TestResult {
    let authorization = Arc::new(TurnAuthorization::new(1)?);
    let username = "1800000000:peer-expiring-browser";
    let password = "peer-expiry-password";
    let realm = "deployment.example";
    let allocation_id = "allocation-peer-expiring";
    let mut grant = test_grant(allocation_id, username, realm, password);
    grant.peer_allowlist.clear();
    grant.deadline = Instant::now() + Duration::from_secs(30);
    authorization.install_grant(grant)?;

    let (online_tx, online_rx) = watch::channel(true);
    let (service, _) = TurnService::bind(
        test_config(true, false, false, None),
        Arc::clone(&authorization),
        online_rx,
    )
    .await?;
    let address = service
        .listen_addresses()
        .udp
        .ok_or("UDP listener missing")?;
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr = client_socket.local_addr()?;
    let client = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: address.to_string(),
        turn_serv_addr: address.to_string(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: realm.to_owned(),
        software: "NestLink TURN peer-binding expiry test".to_owned(),
        rto_in_ms: 100,
        conn: client_socket,
        vnet: None,
    })
    .await?;
    client.listen().await?;
    let relay = timeout(Duration::from_secs(5), client.allocate()).await??;
    let peer = SocketAddr::from(([198, 51, 100, 10], 40000));
    authorization.activate_peer_binding(TurnPeerBindingActivation {
        allocation_id,
        session_id: "session-1",
        temporary_identity: "browser-1",
        generation: 1,
        connection_generation: 1,
        grant_sequence: 1,
        lease_sequence: 1,
        binding_sha256: [9; 32],
        issued_at_unix_ms: 1,
        deadline: Instant::now() + Duration::from_millis(800),
        peers: &[peer],
    })?;
    assert!(authorization.authorize_action(
        username,
        realm,
        client_addr,
        TurnAction::SendIndication,
        Some(peer),
        1,
    ));
    assert_eq!(authorization.active_allocations(), 1);

    timeout(Duration::from_secs(3), async {
        while authorization.active_allocations() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(authorization.auth_key(username, realm).is_some());
    assert!(authorization.expired_allocations().is_empty());

    drop(relay);
    client.close().await?;
    service.shutdown().await?;
    drop(online_tx);
    Ok(())
}

fn test_grant(
    allocation_id: &str,
    username: &str,
    realm: &str,
    password: &str,
) -> TurnAllocationGrant {
    let mut auth_key = [0_u8; 16];
    auth_key.copy_from_slice(&turn::auth::generate_auth_key(username, realm, password));
    TurnAllocationGrant {
        deployment_id: "deployment-1".to_owned(),
        node_id: "node-1".to_owned(),
        runtime_id: "runtime-1".to_owned(),
        allocation_id: allocation_id.to_owned(),
        session_id: "session-1".to_owned(),
        temporary_identity: "browser-1".to_owned(),
        purpose: TurnPurpose::BrowserWebRtc,
        generation: 1,
        connection_generation: 1,
        grant_sequence: 1,
        lease_sequence: 1,
        node_key_sha256: [1; 32],
        device_id: "browser-1".to_owned(),
        controller_device_id: "browser-1".to_owned(),
        host_device_id: "host-1".to_owned(),
        controller_key_sha256: [2; 32],
        host_key_sha256: [3; 32],
        permit_sha256: [4; 32],
        session_binding_sha256: [5; 32],
        policy_revision: 1,
        quota_revision: 1,
        endpoint_revision: 1,
        username: username.to_owned(),
        realm: realm.to_owned(),
        auth_key,
        peer_allowlist: vec![SocketAddr::from(([198, 51, 100, 10], 40000))],
        max_peers: 1,
        expires_at_unix_ms: 1_800_000_000_000,
        deadline: Instant::now() + Duration::from_secs(30),
        max_total_bytes: 16 * 1024 * 1024,
        max_bytes_per_second: 4 * 1024 * 1024,
    }
}
