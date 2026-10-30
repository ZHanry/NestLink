use super::*;
use nestlink_identity::{InstallationIdentity, PermitSigner, digest, verify_permit};
use nestlink_protocol::{Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_transport_quic::discovery_endpoint;
use nestlink_traversal::stun;
use prost::Message;
use tokio::{net::UdpSocket, sync::oneshot};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn permit(issued_at: u64, expires_at: u64, paths: &[Path]) -> Result<VerifiedPermit> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let host_id = nestlink_auth::random_id();
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: SCHEMA_VERSION,
        deployment_id: nestlink_auth::random_id(),
        security_epoch: 1,
        session_id: nestlink_auth::random_id(),
        account_id: nestlink_auth::random_id(),
        controller_device_id: nestlink_auth::random_id(),
        host_device_id: host_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: host_id,
        permissions: vec![Permission::View as i32],
        paths: paths.iter().map(|path| *path as i32).collect(),
        policy_revision: 1,
        connection_generation: 4,
        lease_sequence: 7,
        issued_at_unix_ms: issued_at,
        expires_at_unix_ms: expires_at,
        capability_sha256: digest(b"discovery-vp8").to_vec(),
        required_capabilities: vec!["vp8".into()],
    };
    let signer = PermitSigner::generate();
    Ok(verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?)
}

fn endpoint(bind: &str, server: SocketAddr) -> Result<(quinn::Endpoint, Arc<DiscoverySocket>)> {
    let local = InstallationIdentity::generate();
    Ok(discovery_endpoint(bind.parse()?, &local, InstallationIdentity::generate().fingerprint(), vec![server])?)
}

#[tokio::test]
async fn real_same_socket_candidates_keep_provenance_and_require_local_private_consent() -> Result {
    for (bind, mapped, consent, public) in [
        ("127.0.0.1:0", "192.168.50.2:5555", "192.168.50.0/24", false),
        ("[::1]:0", "[fd12:3456::2]:5555", "fd12:3456::/64", false),
        ("127.0.0.1:0", "198.51.100.7:5555", "198.51.100.0/24", true),
        ("[::1]:0", "[2001:db8::7]:5555", "2001:db8::/64", true),
    ] {
        let now = wall_ms()?;
        let authorized = permit(now, now + 15_000, &[Path::Direct])?;
        let server = UdpSocket::bind(bind).await?;
        let server_address = server.local_addr()?;
        let mapped: SocketAddr = mapped.parse()?;
        let (owner, socket) = endpoint(bind, server_address)?;
        let responder = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (length, source) = server.recv_from(&mut bytes).await?;
            server.send_to(&stun::response(&bytes[..length], mapped)?, source).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let denied = gather(&authorized, socket.clone(), vec![server_address]).await?;
        assert_eq!(denied.candidates.iter().any(|candidate| candidate.address == mapped), public);
        assert_eq!(denied.failed_stun, if public { vec![] } else { vec![server_address] });
        responder.await??;
        // This uses the exact same short-lived observation. Local consent does
        // not turn a second discovery call into a new server observation lease.
        let observation = socket.probe(server_address, Duration::from_secs(1)).await?;
        let policy = AddressPolicy::new(&[consent.into()])?;
        let mut allowed = gather_with_policy(&authorized, socket.clone(), vec![server_address], &policy).await?;
        let fact = allowed.facts().iter().find(|fact| fact.candidate.address == mapped).ok_or("approved STUN candidate missing")?;
        match &fact.source {
            CandidateSource::Stun {server, local} => {
                assert_eq!(*server, server_address);
                assert_eq!(*local, owner.local_addr()?);
            }
            _ => return Err("STUN provenance replaced by an interface guess".into()),
        }
        assert_eq!(fact.expires_at, observation.expires_at.min(allowed.deadline));
        allowed.check_current(&authorized, &socket)?;
        let (_other_owner, other_socket) = endpoint(bind, server_address)?;
        assert!(allowed.check_current(&authorized, &other_socket).is_err());
        let other = permit(now, now + 15_000, &[Path::Direct])?;
        assert!(allowed.check_current(&other, &socket).is_err());
        allowed.candidates[0].generation += 1;
        assert!(allowed.check_current(&authorized, &socket).is_err());
        socket.invalidate_network(2)?;
        assert!(denied.check_current(&authorized, &socket).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn invalid_permit_and_relay_only_never_probe_the_actual_stun_socket() -> Result {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let server_address = server.local_addr()?;
    let (_owner, socket) = endpoint("127.0.0.1:0", server_address)?;
    let now = wall_ms()?;
    for (issued, expires) in [(now - 20_000, now - 5_000), (now + 5_000, now + 20_000)] {
        let invalid = permit(issued, expires, &[Path::Direct])?;
        assert!(matches!(gather(&invalid, socket.clone(), vec![server_address]).await, Err(SdkError::Invalid)));
    }
    let relay = permit(now, now + 15_000, &[Path::Relay])?;
    let result = gather(&relay, socket, vec![server_address]).await?;
    assert!(result.candidates.is_empty());
    assert!(result.facts().is_empty());
    assert!(tokio::time::timeout(Duration::from_millis(100), server.recv_from(&mut [0; 512])).await.is_err());
    Ok(())
}

#[tokio::test]
async fn network_change_during_real_stun_reply_cannot_publish_old_candidates() -> Result {
    let now = wall_ms()?;
    let authorized = permit(now, now + 15_000, &[Path::Direct])?;
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let server_address = server.local_addr()?;
    let (_owner, socket) = endpoint("127.0.0.1:0", server_address)?;
    let (arrived, arrival) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let responder = tokio::spawn(async move {
        let mut bytes = [0; 512];
        let (length, source) = server.recv_from(&mut bytes).await?;
        let _ = arrived.send(());
        released.await?;
        server.send_to(&stun::response(&bytes[..length], "198.51.100.7:5555".parse()?)?, source).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let gathering_socket = socket.clone();
    let gathering = tokio::spawn(async move { gather(&authorized, gathering_socket, vec![server_address]).await });
    tokio::time::timeout(Duration::from_secs(1), arrival).await??;
    socket.invalidate_network(2)?;
    release.send(()).map_err(|_| "response gate closed")?;
    assert!(matches!(tokio::time::timeout(Duration::from_secs(1), gathering).await??, Err(SdkError::Invalid)));
    responder.await??;
    Ok(())
}
