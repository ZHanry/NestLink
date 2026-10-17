use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn packet(key: [u8; 16], payload: &[u8], reply: bool) -> Vec<u8> {
    let mut bytes = b"NSD1".to_vec();
    bytes.push(u8::from(reply));
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
#[tokio::test]
async fn actual_native_quic_routes_empty_and_mtu_payload_and_refuses_second_driver() -> Result {
    let edge = NodeIdentity::generate();
    let host = InstallationIdentity::generate();
    let endpoint = listener("127.0.0.1:0".parse()?, &edge)?;
    let address = endpoint.local_addr()?;
    let incoming = async {
        let incoming = endpoint
            .accept()
            .await
            .ok_or(io::ErrorKind::ConnectionAborted)?;
        incoming.await.map_err(io::Error::other)
    };
    let (server, connected) = tokio::join!(
        incoming,
        connect(
            address,
            &host,
            nestlink_identity::digest(&edge.public_key())
        )
    );
    let server = server?;
    let connected = connected?;
    assert!(supports_native(&server));
    assert!(supports_native(&connected.connection));
    let router = DatagramRouter::new();
    let key = [1; 16];
    let mut route = router.register(key)?;
    let copy = router.clone();
    let receive = server.clone();
    let mut driver = Abort(tokio::spawn(
        async move { copy.drive(&receive, false).await },
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !router.shared.driven.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(
        router.drive(&server, false).await.err().map(|e| e.kind()),
        Some(io::ErrorKind::AlreadyExists)
    );
    send(&connected.connection, packet([2; 16], b"unknown", false))?;
    send(&connected.connection, packet(key, b"wrong direction", true))?;
    send(&connected.connection, vec![0; 31])?;
    let empty = packet(key, &[], false);
    send(&connected.connection, empty.clone())?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), route.receive()).await?,
        Some(empty)
    );
    let maximum = packet(key, &vec![7; SERVICE_DATAGRAM_BYTES - 31], false);
    assert_eq!(maximum.len(), SERVICE_DATAGRAM_BYTES);
    send(&connected.connection, maximum.clone())?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), route.receive()).await?,
        Some(maximum)
    );
    assert!(send(&connected.connection, vec![0; SERVICE_DATAGRAM_BYTES + 1]).is_err());
    drop(route);
    let mut replacement = router.register(key)?;
    let after = packet(key, b"after route owner drop", false);
    send(&connected.connection, after.clone())?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), replacement.receive()).await?,
        Some(after)
    );
    connected
        .connection
        .close(0u32.into(), b"native test stopped");
    connected
        .endpoint
        .close(0u32.into(), b"native test stopped");
    endpoint.close(0u32.into(), b"native test stopped");
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut driver.0).await??;
    endpoint.wait_idle().await;
    connected.endpoint.wait_idle().await;
    assert!(replacement.receive().await.is_none());
    Ok(())
}
#[tokio::test]
async fn mapping_owners_bound_capacity_and_close_wakes_every_receiver() -> Result {
    let router = DatagramRouter::new();
    assert!(router.register([0; 16]).is_err());
    let mut routes = Vec::new();
    for n in 1..=MAX_MAPPINGS {
        let mut key = [0; 16];
        key[..8].copy_from_slice(&(n as u64).to_be_bytes());
        routes.push(router.register(key)?);
    }
    assert!(router.register([255; 16]).is_err());
    let mut duplicate = [0; 16];
    duplicate[..8].copy_from_slice(&1u64.to_be_bytes());
    assert!(router.register(duplicate).is_err());
    drop(routes.pop());
    routes.push(router.register([255; 16])?);
    router.close();
    for mut route in routes {
        assert!(route.receive().await.is_none());
    }
    assert!(router.register([255; 16]).is_err());
    Ok(())
}
