use super::{test_support::*, *};
use nestlink_identity::{service_plane::verify_service_lease, services::local_target_digest};
use nestlink_protocol::{
    api::ServiceIngress,
    service_plane::{
        SERVICE_RESOURCE_MS, SERVICE_USAGE_BYTES, ServiceTunnelTransport,
        ServiceUsageBudgetGrantClaims, decode_service_message,
    },
};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};

#[test]
fn host_publication_enforces_the_signed_grant_ceiling_below_definition_maximum() -> TestResult {
    let mut fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let mut grant: ServiceUsageBudgetGrantClaims =
        decode_service_message(&fixture.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    grant.byte_ceiling = 11;
    fixture.claims.usage_grant = fixture.signer.sign_usage_budget_grant(&grant)?;
    assert!(fixture.claims.definition.limits.maximum_bytes > grant.byte_ceiling);

    let publication = fixture.publication()?;
    let handle = publication.handle();
    let (_target_stop, target_stop) = watch::channel(false);
    let flow = handle.reserve_host("127.0.0.1".parse()?, target_stop)?;
    assert_eq!(flow.chunk_budget()?, 11);
    flow.try_charge(11)?;
    assert!(flow.try_charge(1).is_err());
    assert_eq!(handle.counters()?.admitted_bytes, 11);
    drop(flow);
    publication.revoke();
    Ok(())
}

#[tokio::test]
async fn drain_token_waits_for_every_durable_flow_close() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let publication = fixture.publication()?;
    let handle = publication.handle();
    let (_target_stop, target_stop) = watch::channel(false);
    let flow = handle.reserve_host("127.0.0.1".parse()?, target_stop)?;
    flow.try_charge(19)?;

    publication.revoke();
    assert!(handle.try_drain_token()?.is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), handle.wait_drained())
            .await
            .is_err()
    );

    drop(flow);
    let token = tokio::time::timeout(Duration::from_secs(1), handle.wait_drained()).await??;
    assert_eq!(token.grant_id, id(12));
    assert_eq!(token.publication_id, id(2));
    assert_eq!(token.edge_runtime_id, id(10));
    let counters = handle.counters()?;
    assert_eq!(counters.admitted_bytes, 19);
    assert_eq!(counters.opened_connections, 1);
    assert_eq!(counters.closed_connections, 1);
    Ok(())
}

#[tokio::test]
async fn real_tcp_half_close_delivers_backend_response_after_request_fin() -> TestResult {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let carrier_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        backend.local_addr()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let mut visitor = TcpStream::connect(carrier_listener.local_addr()?).await?;
    let (carrier, peer) = carrier_listener.accept().await?;
    let lease = publication.handle().lease()?;
    let challenge = fixture.edge.challenge_service_tunnel(
        &lease,
        uuid::Uuid::new_v4().to_string(),
        peer,
        ServiceTunnelTransport::Stream,
        wall()?,
    )?;
    let prepared = owner.prepare(
        &publication.handle(),
        &challenge,
        &fixture.edge.public_key(),
        &fixture.host,
    )?;
    assert!(
        owner
            .prepare(
                &publication.handle(),
                &challenge,
                &fixture.edge.public_key(),
                &fixture.host
            )
            .is_err()
    );
    let bridge = tokio::spawn(prepared.forward_stream(carrier));
    let backend_task = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await?;
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await?;
        if request != b"request ending with FIN" {
            return Err(std::io::Error::other("request changed"));
        }
        socket.write_all(b"response after FIN").await?;
        socket.shutdown().await
    });
    visitor.write_all(b"request ending with FIN").await?;
    visitor.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), visitor.read_to_end(&mut response)).await??;
    assert_eq!(response, b"response after FIN");
    tokio::time::timeout(Duration::from_secs(2), bridge).await???;
    backend_task.await??;
    let counters = publication.handle().counters()?;
    assert_eq!(
        counters.admitted_bytes,
        (b"request ending with FIN".len() + b"response after FIN".len()) as u64
    );
    assert_eq!(counters.opened_connections, counters.closed_connections);
    Ok(())
}

#[tokio::test]
async fn expired_prepared_tunnel_never_connects_to_local_target() -> TestResult {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        backend.local_addr()?,
        8000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let prepared = fixture.prepare(&owner, &publication)?;
    tokio::time::sleep(Duration::from_millis(SERVICE_RESOURCE_MS + 100)).await;

    let (carrier, peer) = tokio::io::duplex(64);
    drop(peer);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), prepared.forward_stream(carrier))
            .await?
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backend.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn established_local_stream_can_outlive_challenge_deadline() -> TestResult {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        backend.local_addr()?,
        8000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let prepared = fixture.prepare(&owner, &publication)?;
    let (mut carrier, bridge_carrier) = tokio::io::duplex(128);
    let bridge = tokio::spawn(prepared.forward_stream(bridge_carrier));
    let (mut target, _) = tokio::time::timeout(Duration::from_secs(1), backend.accept()).await??;

    // The challenge controls tunnel establishment, not the lifetime of a
    // stream whose local target connection was accepted before expiry.
    tokio::time::sleep(Duration::from_millis(SERVICE_RESOURCE_MS + 100)).await;
    let backend_task = tokio::spawn(async move {
        let mut request = Vec::new();
        target.read_to_end(&mut request).await?;
        if request != b"after challenge expiry" {
            return Err(std::io::Error::other(
                "request changed after challenge expiry",
            ));
        }
        target.write_all(b"response after challenge expiry").await?;
        target.shutdown().await
    });
    carrier.write_all(b"after challenge expiry").await?;
    carrier.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), carrier.read_to_end(&mut response)).await??;
    assert_eq!(response, b"response after challenge expiry");
    tokio::time::timeout(Duration::from_secs(1), bridge).await???;
    backend_task.await??;
    Ok(())
}

#[tokio::test]
async fn local_revoke_cancels_idle_real_tcp_and_closes_owned_sockets() -> TestResult {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let carrier_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        backend.local_addr()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let prepared = fixture.prepare(&owner, &publication)?;
    let mut visitor = TcpStream::connect(carrier_listener.local_addr()?).await?;
    let (carrier, _) = carrier_listener.accept().await?;
    let bridge = tokio::spawn(prepared.forward_stream(carrier));
    let (mut target, _) = tokio::time::timeout(Duration::from_secs(1), backend.accept()).await??;
    owner.revoke();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), bridge)
            .await??
            .is_err()
    );
    for stream in [&mut visitor, &mut target] {
        let mut byte = [0; 1];
        let closed =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut byte)).await?;
        assert!(matches!(closed, Ok(0)) || closed.is_err());
    }
    assert_eq!(publication.handle().counters()?.closed_connections, 1);
    Ok(())
}

#[tokio::test]
async fn idle_lease_expiry_cancels_io_without_a_followup_packet() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        180,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let prepared = fixture.prepare(&owner, &publication)?;
    let (left, _left_peer) = tokio::io::duplex(1);
    let (right, _right_peer) = tokio::io::duplex(1);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        forward_streams(left, right, prepared.flow),
    )
    .await?;
    assert!(result.is_err());
    assert!(publication.handle().lease().is_err());
    // A terminal owner must not revive even with a later, correctly signed lease.
    let mut later = fixture.claims.clone();
    later.lease_sequence += 1;
    later.issued_at_unix_ms = wall()?;
    later.expires_at_unix_ms = later.issued_at_unix_ms + 1000;
    let verified =
        verify_service_lease(&fixture.signer.sign(&later)?, &fixture.signer.public_key())?;
    assert!(publication.renew(verified, Instant::now()).is_err());
    Ok(())
}

#[tokio::test]
async fn revoke_interrupts_a_blocked_write_and_releases_capacity_once() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let prepared = fixture.prepare(&owner, &publication)?;
    let (left, mut producer) = tokio::io::duplex(64);
    let (right, _blocked_consumer) = tokio::io::duplex(1);
    let bridge = tokio::spawn(forward_streams(left, right, prepared.flow));
    producer.write_all(&[7; 64]).await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if publication.handle().counters()?.admitted_bytes > 0 {
                return Ok::<(), Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    // The sink has one byte of capacity and is never read. This write cannot
    // finish on its own; revocation must interrupt the write future itself.
    owner.revoke();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), bridge)
            .await??
            .is_err()
    );
    let c = publication.handle().counters()?;
    assert_eq!(c.opened_connections, 1);
    assert_eq!(c.closed_connections, 1);
    Ok(())
}

#[test]
fn shared_connection_and_total_byte_budgets_cover_all_flows() -> TestResult {
    let mut fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    fixture.claims.definition.limits.maximum_bytes = 10;
    fixture.original.definition = fixture.claims.definition.clone();
    // Changing a definition requires an entirely fresh explicit local choice.
    fixture.claims.definition_sha256 =
        nestlink_identity::services::definition_digest(&fixture.claims.definition)?;
    fixture.original.definition_sha256 = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fixture.claims.definition_sha256)
    };
    fixture.claims.target_sha256 = local_target_digest(
        &fixture.original,
        &fixture.claims.target_id,
        "tcp",
        fixture.address,
    )?;
    fixture.refresh_usage_binding()?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let first = fixture.prepare(&owner, &publication)?;
    let second = fixture.prepare(&owner, &publication)?;
    assert!(fixture.prepare(&owner, &publication).is_err());
    first.flow.try_charge(6)?;
    second.flow.try_charge(4)?;
    assert!(matches!(first.flow.try_charge(1), Err(Error::Quota)));
    assert_eq!(publication.handle().counters()?.admitted_bytes, 10);
    drop(first);
    drop(second);
    assert_eq!(publication.handle().counters()?.closed_connections, 2);
    assert!(fixture.prepare(&owner, &publication).is_err());
    Ok(())
}

#[test]
fn target_keeps_revision_n_and_rejects_n_plus_one_reconstruction_or_wrong_issuer() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let lease = fixture.verified()?;
    assert!(owner.accepts(&lease));
    let mut n_plus_one = fixture.original.clone();
    n_plus_one.revision += 1;
    let reconstructed = LocalTargetOwner::from_local_choice(
        fixture.context.clone(),
        n_plus_one,
        fixture.claims.target_id.clone(),
        "tcp".into(),
        fixture.address,
        fixture.host.public_key(),
    )?;
    assert!(!reconstructed.accepts(&lease));
    let attacker =
        nestlink_identity::service_plane::ServiceLeaseSigner::from_master_seed(&[99; 32])?;
    let mut wrong_claims = fixture.claims.clone();
    let grant = nestlink_protocol::service_plane::decode_service_message(
        &wrong_claims.usage_grant.claims,
        nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
    )?;
    wrong_claims.usage_grant = attacker.sign_usage_budget_grant(&grant)?;
    let wrong = verify_service_lease(&attacker.sign(&wrong_claims)?, &attacker.public_key())?;
    assert!(!owner.accepts(&wrong));
    assert!(ServicePublication::new(wrong, &fixture.context, Instant::now()).is_err());
    Ok(())
}

#[tokio::test]
async fn identical_lease_replay_does_not_extend_original_deadline() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        240,
    )?;
    let publication = fixture.publication()?;
    let first = publication.handle().deadline()?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    publication.renew(fixture.verified()?, Instant::now())?;
    assert_eq!(publication.handle().deadline()?, first);
    Ok(())
}

#[tokio::test]
async fn udp_preserves_empty_and_maximum_packets_and_filters_foreign_peers() -> TestResult {
    let backend = UdpSocket::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Udp { port: 29100 },
        "udp",
        backend.local_addr()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let mapping = DatagramMapping::new(fixture.prepare(&owner, &publication)?).await?;
    let packet = |sequence, payload| DatagramPacket {
        mapping_id: mapping.mapping_id().into(),
        sequence,
        payload,
    };
    mapping.send_packet(&packet(1, Vec::new())).await?;
    let mut buffer = [0; 1201];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(1), backend.recv_from(&mut buffer)).await??;
    assert_eq!(length, 0);
    assert_eq!(publication.handle().counters()?.admitted_bytes, 1);
    backend.send_to(&[], peer).await?;
    let empty = tokio::time::timeout(Duration::from_secs(1), mapping.receive_reply()).await??;
    assert!(empty.payload.is_empty());
    assert_eq!(empty.sequence, 1);
    assert_eq!(publication.handle().counters()?.admitted_bytes, 2);
    let payload = vec![0xa5; DatagramPacket::MAX_PAYLOAD];
    mapping.send_packet(&packet(3, payload.clone())).await?;
    let (length, again) = backend.recv_from(&mut buffer).await?;
    assert_eq!(peer, again);
    assert_eq!(&buffer[..length], payload);
    // Legitimate out-of-order datagrams remain independent; duplicate packet 3
    // is rejected instead of creating a second target send.
    mapping
        .send_packet(&packet(2, b"out of order".to_vec()))
        .await?;
    assert!(
        mapping
            .send_packet(&packet(3, payload.clone()))
            .await
            .is_err()
    );
    assert_eq!(
        backend.recv_from(&mut buffer).await?.0,
        b"out of order".len()
    );
    let foreign = UdpSocket::bind("127.0.0.1:0").await?;
    foreign.send_to(b"foreign", peer).await?;
    backend.send_to(&payload, peer).await?;
    let reply = tokio::time::timeout(Duration::from_secs(1), mapping.receive_reply()).await??;
    assert_eq!(reply.payload, payload);
    assert_eq!(reply.encode()?.len(), 1200);
    assert!(
        mapping
            .send_packet(&packet(4, vec![1; DatagramPacket::MAX_PAYLOAD + 1]))
            .await
            .is_err()
    );
    backend
        .send_to(&vec![1; DatagramPacket::MAX_PAYLOAD + 1], peer)
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), mapping.receive_reply())
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn udp_idle_receive_is_cancelled_by_local_owner_drop() -> TestResult {
    let backend = UdpSocket::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        ServiceIngress::Udp { port: 29100 },
        "udp",
        backend.local_addr()?,
        5000,
    )?;
    let owner = fixture.owner()?;
    let publication = fixture.publication()?;
    let mapping = DatagramMapping::new(fixture.prepare(&owner, &publication)?).await?;
    let waiting = tokio::spawn(async move { mapping.receive_reply().await });
    tokio::task::yield_now().await;
    drop(owner);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), waiting)
            .await??
            .is_err()
    );
    assert_eq!(publication.handle().counters()?.closed_connections, 1);
    Ok(())
}
