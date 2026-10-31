//! Network ALPN adapter; business payloads remain end-to-end opaque.
use super::*;
use nestlink_protocol::{
    api::{NetworkNodeChallenge, NetworkNodeHello, NetworkNodeReady},
    network_datagram as wire,
};
use nestlink_transport_quic::routed::{FragmentReplayWindow, authenticated_peer_fingerprint};

fn decode<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| failed())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(failed());
    }
    bytes.try_into().map_err(|_| failed())
}
pub(super) async fn run(
    connection: quinn::Connection,
    control: Arc<NodeControl>,
    hub: Arc<Hub>,
    selector: Arc<RelaySelector>,
    endpoint: quinn::Endpoint,
) -> io::Result<()> {
    let tls_peer = authenticated_peer_fingerprint(&connection)?;
    if connection
        .max_datagram_size()
        .is_none_or(|size| size < wire::HEADER + wire::FRAGMENT_BYTES)
    {
        return Err(failed());
    }
    let setup_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let (mut write, mut read) = tokio::time::timeout_at(setup_deadline, connection.open_bi())
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
    let nonce = random_bytes::<32>();
    tokio::time::timeout_at(
        setup_deadline,
        write_message(
            &mut write,
            &NetworkNodeChallenge {
                schema_version: 1,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
            },
        ),
    )
    .await
    .map_err(io::Error::other)??;
    let hello = tokio::time::timeout_at(setup_deadline, async {
        tokio::select! { biased;
            _ = connection.read_datagram() => Err(failed()),
            _ = connection.accept_bi() => Err(failed()),
            _ = connection.accept_uni() => Err(failed()),
            hello = read_message::<NetworkNodeHello>(&mut read) => hello,
        }
    })
    .await
    .map_err(io::Error::other)??;
    if hello.schema_version != 1 {
        return Err(failed());
    }
    let binding = decode::<32>(&hello.binding_sha256)?;
    let public_key = decode::<32>(&hello.public_key)?;
    let signature = decode::<64>(&hello.signature)?;
    if nestlink_identity::digest(&public_key) != tls_peer { return Err(failed()); }
    nestlink_identity::network::verify_network_node_admission(
        &hello.allocation_id,&binding,&hello.device_id,&public_key,&nonce,&signature,
    ).map_err(|_| failed())?;
    // The authenticated management POST and resource push are independent.
    // Wait for this exact new ID before the single prepare/reserve operation;
    // never retry a consumed role, and never extend the original challenge end.
    let mut node_stopped = control.stopped();
    let mut waiting_byte = [0u8;1];
    loop {
        let snapshot = control.resource_snapshot().map_err(|_| failed())?;
        if snapshot.network_routes.iter().any(|resource|resource.allocation.as_ref()
            .is_some_and(|allocation|allocation.allocation_id==hello.allocation_id)) { break; }
        tokio::select! { biased;
            _ = connection.closed() => return Err(failed()),
            _ = node_stopped.changed() => return Err(failed()),
            _ = connection.read_datagram() => return Err(failed()),
            _ = connection.accept_bi() => return Err(failed()),
            _ = connection.accept_uni() => return Err(failed()),
            _ = read.read(&mut waiting_byte) => return Err(failed()),
            _ = tokio::time::sleep_until(setup_deadline) => return Err(failed()),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        }
    }
    let candidate = control
        .prepare_network_relay_endpoint(
            &hello.allocation_id,
            &binding,
            &tls_peer,
            RelayEndpointProof {
                device_id: &hello.device_id,
                public_key: &public_key,
                transport: RelayTransport::QuicDatagram,
                signature: &signature,
            },
            &nonce,
        )
        .map_err(|_| failed())?;
    let direction = candidate.network_direction().ok_or_else(failed)?;
    let selection = selector.register(candidate)?;
    let mut extra = [0; 1];
    let guard = tokio::select! { biased;
        _ = connection.closed() => return Err(failed()),
        _ = read.read(&mut extra) => return Err(failed()),
        _ = connection.read_datagram() => return Err(failed()),
        _ = connection.accept_bi() => return Err(failed()),
        _ = connection.accept_uni() => return Err(failed()),
        result = selection.wait() => result?,
    };
    let mut io = RelayIo {
        endpoint,
        connection,
        streams: Some((write, read)),
        registration: None,
        guard: Some(guard),
    };
    let (registration, mut paired) =
        hub.register(io.guard.as_ref().ok_or_else(failed)?, &io.connection)?;
    io.registration = Some(registration);
    let guard = io.guard.as_ref().ok_or_else(failed)?;
    let connection = &io.connection;
    let registration = io.registration.as_ref().ok_or_else(failed)?;
    let (write, read) = io.streams.as_mut().ok_or_else(failed)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            guard.check_live().map_err(|_| failed())?;
            if *paired.borrow() {
                return Ok::<_, io::Error>(());
            }
            tokio::select! { biased;
                _ = guard.wait_stopped() => return Err(failed()),
                _ = read.read(&mut extra) => return Err(failed()),
                _ = connection.read_datagram() => return Err(failed()),
                _ = connection.accept_bi() => return Err(failed()),
                _ = connection.accept_uni() => return Err(failed()),
                changed = paired.changed() => changed.map_err(|_| failed())?,
            }
        }
    })
    .await
    .map_err(io::Error::other)??;
    guard.check_live().map_err(|_| failed())?;
    tokio::time::timeout(
        Duration::from_millis(500),
        write_message(
            write,
            &NetworkNodeReady {
                schema_version: 1,
                allocation_id: hello.allocation_id,
                binding_sha256: URL_SAFE_NO_PAD.encode(binding),
            },
        ),
    )
    .await
    .map_err(io::Error::other)??;
    let peer = hub.peer(registration)?;
    let mut replay = FragmentReplayWindow::default();
    let mut processed = 0u32;
    loop {
        let bytes = tokio::select! { biased;
            _ = guard.wait_stopped() => return Err(failed()),
            _ = read.read(&mut extra) => return Err(failed()),
            _ = connection.accept_bi() => return Err(failed()),
            _ = connection.accept_uni() => return Err(failed()),
            bytes = connection.read_datagram() => bytes.map_err(io::Error::other)?,
        };
        let fragment = wire::decode(&bytes).map_err(io::Error::other)?;
        if fragment.binding != binding
            || fragment.direction != direction
            || fragment.remaining_hops != 1
        {
            return Err(failed());
        }
        if !replay.accept(&fragment)? {
            continue;
        }
        let mut bytes = bytes.to_vec();
        wire::forward(&mut bytes, binding, direction).map_err(io::Error::other)?;
        guard
            .admit(bytes.len() as u64, || {
                // A bounded congestion drop still consumes both directions' shared
                // original cumulative budget, including the route envelope.
                if peer.datagram_send_buffer_space() >= bytes.len() {
                    peer.send_datagram(bytes.into()).map_err(|_| {
                        ContractError::new(ErrorCode::LeaseExpired, "network node peer closed")
                    })?;
                }
                Ok(())
            })
            .map_err(|_| failed())?;
        processed = (processed + 1) % 32;
        if processed == 0 {
            tokio::task::yield_now().await;
        }
    }
}
