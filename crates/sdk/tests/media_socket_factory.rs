#![cfg(not(target_arch = "wasm32"))]
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use webrtc::ice::{udp_network::UdpSocketFactory, util::listen_udp_in_port_range_with_factory};
use webrtc::util::vnet::net::Net;

#[tokio::test]
async fn ice_factory_socket_is_retained_for_discovery_checks_and_following_data()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let factory: UdpSocketFactory = Arc::new(move |address| {
        counted.fetch_add(1, Ordering::SeqCst);
        std::net::UdpSocket::bind(address)
    });
    let conn = listen_udp_in_port_range_with_factory(
        &Arc::new(Net::new(None)),
        0,
        0,
        "127.0.0.1:0".parse()?,
        Some(&factory),
    )
    .await?;
    let local = conn.local_addr()?;
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = peer.local_addr()?;
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (length, from) = peer.recv_from(&mut buffer).await?;
        assert_eq!(from, local);
        let response = nestlink_traversal::stun::response(&buffer[..length], from)?;
        peer.send_to(&response, from).await?;
        for expected in [
            b"connectivity-check".as_slice(),
            b"following-media".as_slice(),
        ] {
            let (length, from) = peer.recv_from(&mut buffer).await?;
            assert_eq!(from, local);
            assert_eq!(&buffer[..length], expected);
            peer.send_to(&buffer[..length], from).await?;
        }
        Ok::<_, io::Error>(())
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mapped =
            webrtc::ice::util::get_xormapped_addr(&conn, peer_address, Duration::from_secs(1))
                .await?;
        assert_eq!(mapped.ip, local.ip());
        assert_eq!(mapped.port, local.port());
        for payload in [
            b"connectivity-check".as_slice(),
            b"following-media".as_slice(),
        ] {
            conn.send_to(payload, peer_address).await?;
            let mut buffer = [0; 64];
            let (length, from) = conn.recv_from(&mut buffer).await?;
            assert_eq!(from, peer_address);
            assert_eq!(&buffer[..length], payload);
        }
        server.await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    conn.close().await?;
    Ok(())
}
