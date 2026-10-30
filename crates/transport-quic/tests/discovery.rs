use nestlink_identity::InstallationIdentity;
use nestlink_transport_quic::{connect, discovery::OBSERVATION_TTL, discovery_endpoint, listener};
use nestlink_transport_stream::{Channel, read_frame, write_frame};
use nestlink_traversal::stun;
use std::{io, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{oneshot, watch},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn stun_observation_and_quic_use_the_same_real_udp_endpoint() -> Result {
    let stun_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let stun_address = stun_socket.local_addr()?;
    let (stop, receiver) = watch::channel(false);
    let stun_service = tokio::spawn(nestlink_traversal::server::serve(stun_socket, receiver));
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
    let server_address = server.local_addr()?;
    let (client, discovery) = discovery_endpoint(
        "127.0.0.1:0".parse()?,
        &controller,
        host.fingerprint(),
        vec![stun_address],
    )?;
    let observation = discovery
        .probe(stun_address, Duration::from_secs(2))
        .await?;
    assert_eq!(observation.reflexive, client.local_addr()?);
    let source = observation.reflexive;
    let host_task = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .ok_or_else(|| io::Error::other("no incoming"))?;
        let connection = incoming.await?;
        assert_eq!(connection.remote_address(), source);
        let (mut send, mut receive) = connection.accept_bi().await?;
        assert_eq!(read_frame(&mut receive).await?.payload, b"same-port");
        write_frame(&mut send, Channel::Control, b"ack").await?;
        send.finish()?;
        send.stopped().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = connect(&client, server_address, Duration::from_secs(3)).await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_frame(&mut send, Channel::Control, b"same-port").await?;
    assert_eq!(read_frame(&mut receive).await?.payload, b"ack");
    drop(receive);
    connection.close(0_u8.into(), b"complete");
    host_task.await??;
    stop.send(true)?;
    stun_service.await??;
    Ok(())
}

#[tokio::test]
async fn old_network_reply_and_reply_from_untrusted_source_cannot_replace_observation() -> Result {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let server_address = server.local_addr()?;
    let rogue = UdpSocket::bind("127.0.0.1:0").await?;
    let identity = InstallationIdentity::generate();
    let (_endpoint, discovery) = discovery_endpoint(
        "127.0.0.1:0".parse()?,
        &identity,
        InstallationIdentity::generate().fingerprint(),
        vec![server_address],
    )?;
    let (arrived, arrival) = oneshot::channel();
    let (advance, advanced) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 512];
        let (size, source) = server.recv_from(&mut bytes).await?;
        let old = bytes[..size].to_vec();
        let _ = arrived.send(());
        let _ = advanced.await;
        server
            .send_to(&stun::response(&old, "198.51.100.7:5555".parse()?)?, source)
            .await?;
        let (size, source) = server.recv_from(&mut bytes).await?;
        let request = &bytes[..size];
        rogue
            .send_to(
                &stun::response(request, "198.51.100.8:6666".parse()?)?,
                source,
            )
            .await?;
        server
            .send_to(&stun::response(request, source)?, source)
            .await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let socket = discovery.clone();
    let first =
        tokio::spawn(async move { socket.probe(server_address, Duration::from_secs(2)).await });
    arrival.await?;
    discovery.invalidate_network(2)?;
    advance.send(()).map_err(|_| "advance closed")?;
    assert_eq!(
        first.await?.err().ok_or("stale probe accepted")?.kind(),
        io::ErrorKind::Interrupted
    );
    let current = discovery
        .probe(server_address, Duration::from_secs(2))
        .await?;
    assert_eq!(current.network_generation, 2);
    assert_eq!(current.reflexive, current.local);
    assert!(discovery.invalidate_network(1).is_err());
    assert!(
        discovery
            .probe("127.0.0.1:1".parse()?, Duration::from_secs(1))
            .await
            .is_err()
    );
    task.await??;
    Ok(())
}

#[tokio::test]
async fn same_socket_observation_cache_keeps_its_original_expiry_and_generation() -> Result {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let server = UdpSocket::bind(bind).await?;
        let server_address = server.local_addr()?;
        let identity = InstallationIdentity::generate();
        let (_endpoint, discovery) = discovery_endpoint(
            bind.parse()?,
            &identity,
            InstallationIdentity::generate().fingerprint(),
            vec![server_address],
        )?;
        let (requests, mut received) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut bytes = [0; 512];
            for _ in 0..3 {
                let (length, source) = server.recv_from(&mut bytes).await?;
                server
                    .send_to(&stun::response(&bytes[..length], source)?, source)
                    .await?;
                requests.send(()).await.map_err(io::Error::other)?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let first = discovery
            .probe(server_address, Duration::from_secs(2))
            .await?;
        received.recv().await.ok_or("first request missing")?;
        let cached = discovery
            .probe(server_address, Duration::from_secs(2))
            .await?;
        assert_eq!(cached.observed_at, first.observed_at);
        assert_eq!(cached.expires_at, first.expires_at);
        assert_eq!(
            first.expires_at.duration_since(first.observed_at),
            OBSERVATION_TTL
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), received.recv())
                .await
                .is_err()
        );
        first.check_current(&discovery)?;
        tokio::time::sleep_until((first.expires_at + Duration::from_millis(20)).into()).await;
        assert!(first.check_current(&discovery).is_err());
        let fresh = discovery
            .probe(server_address, Duration::from_secs(2))
            .await?;
        received
            .recv()
            .await
            .ok_or("expired cache did not re-probe")?;
        assert!(fresh.observed_at > first.expires_at);
        discovery.invalidate_network(2)?;
        assert!(fresh.check_current(&discovery).is_err());
        let next = discovery
            .probe(server_address, Duration::from_secs(2))
            .await?;
        received
            .recv()
            .await
            .ok_or("new network did not re-probe")?;
        assert_eq!(next.network_generation, 2);
        assert_eq!(next.local, first.local);
        assert_eq!(next.reflexive, next.local);
        task.await??;
    }
    Ok(())
}
