use super::*;
use tokio::net::UdpSocket;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fixture() -> Result<PcpMapping> {
    let mut mapping = PcpMapping::new(
        Ipv4Addr::new(10, 32, 0, 1),
        "10.32.0.2:45001".parse()?,
        Instant::now() + Duration::from_secs(20),
    )?;
    // Only the test responder uses loopback. Production construction rejects
    // it before any control packet can be sent.
    mapping.gateway = Ipv4Addr::LOCALHOST;
    Ok(mapping)
}

fn lifetime(request: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(request[4..8].try_into()?))
}

fn response(request: &[u8], port: u16, lifetime: u32, wrong_nonce: bool) -> Result<Vec<u8>> {
    if request.len() != 60 || request[0] != 2 || request[1] != 1 {
        return Err("expected one PCP MAP request".into());
    }
    assert_eq!(request[36], 17, "only UDP may be requested");
    assert_ne!(&request[40..42], &[0, 0], "wildcard port deletion is forbidden");
    let mut reply = vec![0; 60];
    reply[0] = 2;
    reply[1] = 0x81;
    reply[4..8].copy_from_slice(&lifetime.to_be_bytes());
    reply[8..12].copy_from_slice(&1_u32.to_be_bytes());
    reply[24..44].copy_from_slice(&request[24..44]);
    if wrong_nonce { reply[24] ^= 1; }
    reply[42..44].copy_from_slice(&port.to_be_bytes());
    reply[54..56].copy_from_slice(&[0xff, 0xff]);
    reply[56..60].copy_from_slice(&[203, 0, 113, 7]);
    Ok(reply)
}

#[test]
fn only_explicit_private_gateway_and_bound_private_udp_ports_are_accepted() -> Result {
    let deadline = Instant::now() + Duration::from_secs(10);
    for gateway in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "203.0.113.1", "224.0.0.1"] {
        assert!(PcpMapping::new(gateway.parse()?, "10.32.0.2:45001".parse()?, deadline).is_err());
    }
    for local in ["10.32.0.2:0", "0.0.0.0:45001", "127.0.0.1:45001", "[fd00::2]:45001"] {
        assert!(PcpMapping::new("10.32.0.1".parse()?, local.parse()?, deadline).is_err());
    }
    assert!(PcpMapping::new("10.32.0.1".parse()?, "10.32.0.2:45001".parse()?, Instant::now()).is_err());
    Ok(())
}

/// This is L1 real-UDP component integration with a controlled protocol peer.
/// It is not a claim that a physical router or a kernel NAT was qualified.
#[tokio::test]
async fn pcp_nonce_renewal_failed_create_and_exact_release_use_the_mature_component() -> Result {
    let socket = UdpSocket::bind("127.0.0.1:5351").await?;
    let server = tokio::spawn(async move {
        let mut buffer = [0; 1100];
        // Create, same-tuple renewal, and nonce-specific deletion.
        let mut first_nonce = None;
        for index in 0..3 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(n, 60);
            let nonce = request[24..36].to_vec();
            if let Some(first) = &first_nonce { assert_eq!(first, &nonce); }
            else { first_nonce = Some(nonce); }
            let requested = lifetime(request)?;
            assert_eq!(requested == 0, index == 2);
            assert!(requested <= 120);
            let granted = if requested == 0 { 0 } else { requested.min(8) };
            socket.send_to(&response(request, 45001, granted, false)?, peer).await?;
        }
        // A changed external port must be rejected, then exactly deleted.
        for index in 0..2 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 1);
            socket.send_to(&response(request, 45002, if index == 0 { 8 } else { 0 }, false)?, peer).await?;
        }
        // Bad nonce is rejected by crab_nat itself; the original nonce is
        // retained so even this failed creation can be deleted precisely.
        for index in 0..2 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 1);
            socket.send_to(&response(request, 45001, if index == 0 { 8 } else { 0 }, index == 0)?, peer).await?;
        }
        // An excessive router lease may not extend the original permit.
        for index in 0..2 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 1);
            socket.send_to(&response(request, 45001, if index == 0 { 600 } else { 0 }, false)?, peer).await?;
        }
        // A tuple already signed for this owner cannot change during renewal.
        for index in 0..3 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 2);
            let mut reply = response(request, 45001, if index == 2 { 0 } else { 8 }, false)?;
            if index == 1 { reply[59] = 8; }
            socket.send_to(&reply, peer).await?;
        }
        // A rebooted gateway cannot silently replace an existing mapping.
        for index in 0..3 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 2);
            let mut reply = response(request, 45001, if index == 2 { 0 } else { 8 }, false)?;
            if index == 1 { reply[8..12].copy_from_slice(&0_u32.to_be_bytes()); }
            socket.send_to(&reply, peer).await?;
        }
        // A deletion response with a different nonce is no cleanup receipt.
        for index in 0..3 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index != 0);
            socket.send_to(&response(request, 45001, if index == 0 { 8 } else { 0 }, index == 1)?, peer).await?;
        }
        // After actual lease expiry this owner may only delete, never renew.
        for index in 0..2 {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(lifetime(request)? == 0, index == 1);
            socket.send_to(&response(request, 45001, if index == 0 { 2 } else { 0 }, false)?, peer).await?;
        }
        // Drop the create response after observing a real request. Cleanup
        // after cancel must use the exact nonce from that original request.
        let (n, _) = socket.recv_from(&mut buffer).await?;
        let canceled_nonce = buffer[24..36].to_vec();
        assert!(lifetime(&buffer[..n])? > 0);
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await?;
            let request = &buffer[..n];
            assert_eq!(&request[24..36], canceled_nonce.as_slice());
            if lifetime(request)? == 0 {
                socket.send_to(&response(request, 45001, 0, false)?, peer).await?;
                break;
            }
        }
        Result::Ok(())
    });
    let execution = async {
        let mut mapping = fixture()?;
        assert_eq!(mapping.establish_or_renew().await?, "203.0.113.7:45001".parse::<SocketAddr>()?);
        assert!(mapping.renewal_deadline()? < mapping.authorization_deadline);
        assert_eq!(mapping.establish_or_renew().await?, "203.0.113.7:45001".parse::<SocketAddr>()?);
        mapping.release().await?;
        assert!(!mapping.attempted);
        assert!(mapping.establish_or_renew().await.is_err());
        mapping.release().await?; // No second network deletion after its receipt.
        for _ in 0..3 {
            let mut refused = fixture()?;
            assert!(refused.establish_or_renew().await.is_err());
            assert!(refused.attempted);
            assert!(refused.establish_or_renew().await.is_err());
            refused.release().await?;
        }
        for _ in 0..2 {
            let mut changed = fixture()?;
            changed.establish_or_renew().await?;
            assert!(changed.establish_or_renew().await.is_err());
            assert!(changed.renewal_deadline().is_err());
            changed.release().await?;
        }
        let mut bad_delete = fixture()?;
        bad_delete.establish_or_renew().await?;
        assert!(bad_delete.release().await.is_err());
        assert!(bad_delete.attempted);
        assert!(bad_delete.establish_or_renew().await.is_err());
        bad_delete.release().await?;
        let mut expired = fixture()?;
        expired.establish_or_renew().await?;
        tokio::time::sleep(Duration::from_millis(2_050)).await;
        assert!(expired.renewal_deadline().is_err());
        assert!(expired.establish_or_renew().await.is_err());
        expired.release().await?;
        let mut canceled = fixture()?;
        assert!(tokio::time::timeout(Duration::from_millis(50), canceled.establish_or_renew()).await.is_err());
        assert!(canceled.attempted);
        assert!(canceled.establish_or_renew().await.is_err());
        canceled.release().await?;
        Result::Ok(())
    };
    let result = tokio::time::timeout(Duration::from_secs(10), execution).await;
    if !matches!(&result, Ok(Ok(()))) { server.abort(); }
    let server_result = tokio::time::timeout(Duration::from_secs(2), server).await;
    result??;
    server_result???;
    Ok(())
}
