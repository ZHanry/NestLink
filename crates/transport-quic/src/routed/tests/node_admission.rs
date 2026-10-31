//! Real TLS admission, including publication arriving after the first dial.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::api::{NetworkNodeChallenge, NetworkNodeHello, NetworkNodeReady};
use nestlink_transport_stream::tls::CurrentClientPins;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const ALLOCATION: &str = "60000000-0000-4000-8000-000000000006";
const BINDING: [u8; 32] = [73; 32];

#[derive(Debug)]
struct Pins {
    peer: [u8; 32],
    ready: AtomicBool,
    denied: AtomicUsize,
    denied_event: tokio::sync::Notify,
}
impl Pins {
    fn new(peer: [u8; 32], ready: bool) -> Arc<Self> {
        Arc::new(Self {
            peer,
            ready: AtomicBool::new(ready),
            denied: AtomicUsize::new(0),
            denied_event: tokio::sync::Notify::new(),
        })
    }
}
impl CurrentClientPins for Pins {
    fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        let accepted = *fingerprint == self.peer && self.ready.load(Ordering::SeqCst);
        if !accepted {
            self.denied.fetch_add(1, Ordering::SeqCst);
            self.denied_event.notify_one();
        }
        accepted
    }
}
#[derive(Default)]
struct NodeStats {
    handshakes: usize,
    hellos: usize,
    remote: Option<SocketAddr>,
}

fn serve(
    node: &NodeIdentity,
    pins: Arc<Pins>,
    close_after_hello: bool,
    deadline: Instant,
) -> TestResult<(NetworkNodeListener, Abort<TestResult<NodeStats>>)> {
    let listener = node_listener("127.0.0.1:0".parse()?, node, pins)?;
    let endpoint = listener.endpoint()?.clone();
    let task = Abort(tokio::spawn(async move {
        let mut stats = NodeStats::default();
        loop {
            let Some(incoming) = tokio::time::timeout_at(deadline, endpoint.accept()).await? else {
                return Ok(stats);
            };
            stats.handshakes += 1;
            let Ok(connection) = tokio::time::timeout_at(deadline, incoming).await? else {
                continue;
            };
            stats.remote = Some(connection.remote_address());
            let (mut write, mut read) =
                tokio::time::timeout_at(deadline, connection.open_bi()).await??;
            let nonce = [29; 32];
            crate::node::write_message(
                &mut write,
                &NetworkNodeChallenge {
                    schema_version: 1,
                    nonce: URL_SAFE_NO_PAD.encode(nonce),
                },
            )
            .await?;
            let hello: NetworkNodeHello =
                tokio::time::timeout_at(deadline, crate::node::read_message(&mut read)).await??;
            stats.hellos += 1;
            assert_eq!(hello.schema_version, 1);
            assert_eq!(hello.allocation_id, ALLOCATION);
            assert_eq!(hello.device_id, INSTALLATIONS[0]);
            assert_eq!(hello.binding_sha256, URL_SAFE_NO_PAD.encode(BINDING));
            let public_key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&hello.public_key)?
                .try_into()
                .map_err(|_| "public key length")?;
            let signature: [u8; 64] = URL_SAFE_NO_PAD
                .decode(&hello.signature)?
                .try_into()
                .map_err(|_| "signature length")?;
            assert_eq!(
                authenticated_peer_fingerprint(&connection)?,
                nestlink_identity::digest(&public_key)
            );
            nestlink_identity::network::verify_network_node_admission(
                ALLOCATION,
                &BINDING,
                INSTALLATIONS[0],
                &public_key,
                &nonce,
                &signature,
            )?;
            if close_after_hello {
                connection.close(1u32.into(), b"allocation already consumed");
            } else {
                crate::node::write_message(
                    &mut write,
                    &NetworkNodeReady {
                        schema_version: 1,
                        allocation_id: ALLOCATION.into(),
                        binding_sha256: URL_SAFE_NO_PAD.encode(BINDING),
                    },
                )
                .await?;
                let _ = tokio::time::timeout_at(deadline, connection.closed()).await?;
            }
            return Ok(stats);
        }
    }));
    Ok((listener, task))
}

#[tokio::test]
async fn delayed_current_client_pin_keeps_the_same_udp_owner_and_sends_one_signed_hello()
-> TestResult {
    let identity = InstallationIdentity::generate();
    let node = NodeIdentity::generate();
    let pins = Pins::new(identity.fingerprint(), false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut listener, mut server) = serve(&node, pins.clone(), false, deadline)?;
    let mut owner = AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &identity,
        PeerId::from_public_key(&node.public_key()),
    )?;
    let local = owner.local_addr()?;
    let publish = pins.clone();
    let mut publication = Abort(tokio::spawn(async move {
        publish.denied_event.notified().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        publish.ready.store(true, Ordering::SeqCst);
    }));
    let mut adjacency = owner
        .connect_node(
            listener.local_addr()?,
            &identity,
            INSTALLATIONS[0],
            ALLOCATION,
            BINDING,
            deadline,
        )
        .await?;
    assert!(pins.denied.load(Ordering::SeqCst) >= 1);
    adjacency.close_and_wait(deadline).await?;
    let stats = tokio::time::timeout_at(deadline, &mut server.0).await???;
    tokio::time::timeout_at(deadline, &mut publication.0).await??;
    assert!(stats.handshakes >= 2);
    assert_eq!(stats.hellos, 1);
    assert_eq!(stats.remote, Some(local));
    listener.close_and_wait(deadline).await?;
    drop(std::net::UdpSocket::bind(local)?);
    Ok(())
}

#[tokio::test]
async fn a_wrong_fixed_node_pin_is_terminal_before_any_signed_hello() -> TestResult {
    let identity = InstallationIdentity::generate();
    let node = NodeIdentity::generate();
    let pins = Pins::new(identity.fingerprint(), true);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut listener, mut server) = serve(&node, pins, false, deadline)?;
    let mut owner = AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &identity,
        PeerId(InstallationIdentity::generate().fingerprint()),
    )?;
    let local = owner.local_addr()?;
    let result = owner
        .connect_node(
            listener.local_addr()?,
            &identity,
            INSTALLATIONS[0],
            ALLOCATION,
            BINDING,
            deadline,
        )
        .await;
    let error = result.err().ok_or("wrong node pin was accepted")?;
    assert!(matches!(
        error.downcast_ref::<quinn::ConnectionError>(),
        Some(quinn::ConnectionError::TransportError(_))
    ));
    owner.close_and_wait(deadline).await?;
    listener.request_close();
    let stats = tokio::time::timeout_at(deadline, &mut server.0).await???;
    assert_eq!(stats.handshakes, 1);
    assert_eq!(stats.hellos, 0);
    listener.close_and_wait(deadline).await?;
    drop(std::net::UdpSocket::bind(local)?);
    Ok(())
}

#[tokio::test]
async fn unavailable_dynamic_pin_never_extends_the_original_setup_deadline() -> TestResult {
    let identity = InstallationIdentity::generate();
    let node = NodeIdentity::generate();
    let pins = Pins::new(identity.fingerprint(), false);
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (mut listener, mut server) = serve(&node, pins.clone(), false, cleanup)?;
    let mut owner = AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &identity,
        PeerId::from_public_key(&node.public_key()),
    )?;
    let local = owner.local_addr()?;
    let original = Instant::now() + Duration::from_millis(400);
    let connected = tokio::time::timeout_at(
        original + Duration::from_secs(1),
        owner.connect_node(
            listener.local_addr()?,
            &identity,
            INSTALLATIONS[0],
            ALLOCATION,
            BINDING,
            original,
        ),
    )
    .await?;
    assert!(connected.is_err());
    assert!(pins.denied.load(Ordering::SeqCst) >= 2);
    owner.close_and_wait(cleanup).await?;
    listener.request_close();
    let stats = tokio::time::timeout_at(cleanup, &mut server.0).await???;
    assert_eq!(stats.hellos, 0);
    listener.close_and_wait(cleanup).await?;
    drop(std::net::UdpSocket::bind(local)?);
    Ok(())
}

#[tokio::test]
async fn application_rejection_after_hello_cannot_redial_or_reuse_the_owner() -> TestResult {
    let identity = InstallationIdentity::generate();
    let node = NodeIdentity::generate();
    let pins = Pins::new(identity.fingerprint(), true);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut listener, mut server) = serve(&node, pins, true, deadline)?;
    let mut owner = AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &identity,
        PeerId::from_public_key(&node.public_key()),
    )?;
    let local = owner.local_addr()?;
    for _ in 0..2 {
        assert!(
            owner
                .connect_node(
                    listener.local_addr()?,
                    &identity,
                    INSTALLATIONS[0],
                    ALLOCATION,
                    BINDING,
                    deadline,
                )
                .await
                .is_err()
        );
    }
    let stats = tokio::time::timeout_at(deadline, &mut server.0).await???;
    assert_eq!(stats.handshakes, 1);
    assert_eq!(stats.hellos, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), listener.endpoint()?.accept())
            .await
            .is_err()
    );
    owner.close_and_wait(deadline).await?;
    listener.close_and_wait(deadline).await?;
    drop(std::net::UdpSocket::bind(local)?);
    Ok(())
}
