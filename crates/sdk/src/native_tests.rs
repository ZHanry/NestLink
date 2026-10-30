use super::DeviceIdentity;
use super::native::*;
use nestlink_identity::{
    InstallationIdentity, PermitSigner, VerifiedPermit, digest, verify_permit,
};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    DiscoveredRelayNode, Path, Permission, PermitClaims, SCHEMA_VERSION,
    api::{Candidate, CandidateKind, Transport},
};
use nestlink_remote::{RuntimeClock, controller_proof, host_proof};
use nestlink_session::{Session, SessionBinding};
use prost::Message;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn permit(controller: &DeviceIdentity, host: &DeviceIdentity) -> Result<VerifiedPermit> {
    permit_with_paths(controller, host, vec![Path::Direct])
}
fn permit_with_paths(
    controller: &DeviceIdentity,
    host: &DeviceIdentity,
    paths: Vec<Path>,
) -> Result<VerifiedPermit> {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 77,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: controller.device_id.clone(),
        host_device_id: host.device_id.clone(),
        controller_key_sha256: digest(&controller.identity.public_key()).to_vec(),
        host_key_sha256: digest(&host.identity.public_key()).to_vec(),
        resource_id: host.device_id.clone(),
        permissions: vec![Permission::View as i32],
        paths: paths.into_iter().map(|path| path as i32).collect(),
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 15000,
        capability_sha256: digest(b"test-only-vp8").to_vec(),
        required_capabilities: vec!["vp8".into()],
    };
    let signer = PermitSigner::generate();
    Ok(verify_permit(
        &signer.sign(&claims)?.encode_to_vec(),
        &signer.public_key(),
    )?)
}
fn binding(p: &VerifiedPermit) -> Result<SessionBinding> {
    let c = p.claims();
    Ok(SessionBinding {
        media: None,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        session_id: c.session_id.clone(),
        account_id: c.account_id.clone(),
        controller_device_id: c.controller_device_id.clone(),
        host_device_id: c.host_device_id.clone(),
        controller_key_sha256: c
            .controller_key_sha256
            .clone()
            .try_into()
            .map_err(|_| "bad key")?,
        host_key_sha256: c
            .host_key_sha256
            .clone()
            .try_into()
            .map_err(|_| "bad key")?,
        resource_id: c.resource_id.clone(),
        policy_revision: c.policy_revision,
        connection_generation: c.connection_generation,
        capability_sha256: c
            .capability_sha256
            .clone()
            .try_into()
            .map_err(|_| "bad capability")?,
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    })
}
fn loopback_policy() -> Result<AddressPolicy> {
    let mut policy = AddressPolicy::new(&[])?;
    policy.test_loopback = true;
    Ok(policy)
}
#[test]
fn initial_relay_allocation_id_is_stable_across_permit_renewal_and_session_scoped() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = permit(&controller, &host)?;
    let claims = permit.claims().clone();
    let node = DiscoveredRelayNode {
        node_id: id(9),
        node_key_sha256: vec![4; 32],
        runtime_id: id(8),
        runtime_generation: 3,
        endpoint_revision: 7,
        quic_uri: "quic://192.0.2.8:443".into(),
        wss_origin: String::new(),
        allow_loopback: false,
        expires_at_unix_ms: claims.expires_at_unix_ms,
    };
    let initial = initial_relay_allocation_id(&claims, &node)?;

    let mut renewed = claims.clone();
    renewed.lease_sequence += 1;
    renewed.issued_at_unix_ms += 1_000;
    renewed.expires_at_unix_ms += 1_000;
    assert_eq!(initial_relay_allocation_id(&renewed, &node)?, initial);

    let mut another_session = claims.clone();
    another_session.session_id = id(10);
    assert_ne!(
        initial_relay_allocation_id(&another_session, &node)?,
        initial
    );
    let mut another_node = node.clone();
    another_node.node_id = id(11);
    assert_ne!(
        initial_relay_allocation_id(&claims, &another_node)?,
        initial
    );
    let mut new_endpoint = node.clone();
    new_endpoint.endpoint_revision += 1;
    assert_ne!(
        initial_relay_allocation_id(&claims, &new_endpoint)?,
        initial
    );
    Ok(())
}

#[tokio::test]
async fn peer_relay_markers_match_any_signed_address_for_their_transport() -> Result {
    let node = DiscoveredRelayNode {
        node_id: id(9),
        node_key_sha256: vec![4; 32],
        runtime_id: id(8),
        runtime_generation: 3,
        endpoint_revision: 7,
        quic_uri: "quic://192.0.2.8:443".into(),
        wss_origin: String::new(),
        allow_loopback: false,
        expires_at_unix_ms: 1,
    };
    let markers = [
        Candidate {
            address: "198.51.100.7:443".parse()?,
            kind: CandidateKind::Relay,
            transport: Transport::Quic,
            generation: 1,
        },
        Candidate {
            address: "192.0.2.8:443".parse()?,
            kind: CandidateKind::Relay,
            transport: Transport::Quic,
            generation: 1,
        },
    ];
    assert!(node_matches_relay_markers(&node, &markers).await?);

    let wrong_transport = [Candidate {
        address: "192.0.2.8:443".parse()?,
        kind: CandidateKind::Relay,
        transport: Transport::Wss,
        generation: 1,
    }];
    assert!(!node_matches_relay_markers(&node, &wrong_transport).await?);
    Ok(())
}

#[tokio::test]
async fn signed_relay_hint_cannot_become_a_route_without_a_local_verified_allocation() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = permit_with_paths(&controller, &host, vec![Path::Relay])?;
    let endpoint = NativeEndpoint::new(
        "0.0.0.0:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit,
        vec![],
        AddressPolicy::new(&[])?,
    )?;
    let hint = Candidate {
        address: "93.184.216.34:443".parse()?,
        kind: CandidateKind::Relay,
        transport: Transport::Quic,
        generation: 1,
    };
    let (_cancel_owner, cancel) = watch::channel(false);
    assert!(matches!(
        endpoint
            .dial_native_with_relays(&controller, &[], 1, vec![hint], cancel)
            .await,
        Err(DialError::Failed { failures, .. })
            if failures.iter().any(|failure| failure.stage == "relay-authority")
    ));
    Ok(())
}

fn candidate(address: SocketAddr, kind: CandidateKind, generation: u64) -> Candidate {
    Candidate {
        address,
        kind,
        transport: Transport::Quic,
        generation,
    }
}
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn sdk_authorization_owns_quic_channels_and_original_network_binding() -> Result {
    use nestlink_remote::{SessionLifecycle, SessionSetup, TransportMode};
    use nestlink_session::EndpointRole;
    use nestlink_transport_stream::Channel;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = permit(&controller, &host)?;
    let c_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit.clone(),
        vec![],
        loopback_policy()?,
    )?;
    let h_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &host,
        &controller.identity.public_key(),
        permit.clone(),
        vec![],
        AddressPolicy::new(&[])?,
    )?;
    let (_keep, cancel) = watch::channel(false);
    let (connected, accepted) = tokio::join!(
        c_endpoint.dial_native(
            &controller,
            None,
            4,
            vec![candidate(h_endpoint.local_addr()?, CandidateKind::Lan, 4)],
            cancel.clone()
        ),
        h_endpoint.accept(cancel)
    );
    let connected = connected?;
    let accepted = accepted?;
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let (_c_keep, c_stop) = watch::channel(None);
    let (_h_keep, h_stop) = watch::channel(None);
    let c_setup = SessionSetup {
        session: Session::activate(
            permit.clone(),
            binding(&permit)?,
            Path::Direct,
            now.monotonic_ms,
            now,
        )?,
        path: Path::Direct,
        role: EndpointRole::Controller,
        clock: clock.clone(),
        lifecycle: SessionLifecycle::new(c_stop),
    };
    let mut h_lifecycle = SessionLifecycle::new(h_stop);
    h_lifecycle.network = Some(h_endpoint.network_binding()?);
    let h_setup = SessionSetup {
        session: Session::activate(
            permit.clone(),
            binding(&permit)?,
            Path::Direct,
            now.monotonic_ms,
            now,
        )?,
        path: Path::Direct,
        role: EndpointRole::Host,
        clock,
        lifecycle: h_lifecycle,
    };
    let host_key = host.identity.public_key();
    let controller_key = controller.identity.public_key();
    let (mut c, mut h) = tokio::try_join!(
        connected.authorize(c_setup, &controller, &host_key),
        nestlink_remote::quic::authorize(accepted, None, h_setup, &host.identity, &controller_key)
    )?;
    assert_eq!(c.channels.mode(), TransportMode::QuicStreamsAndDatagrams);
    assert_eq!(c.candidate.path(), Path::Direct);
    h.send(Channel::Video, b"SDK-owned authorized channels")
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), c.channels.receive())
            .await??
            .payload,
        b"SDK-owned authorized channels"
    );
    c_endpoint.invalidate_network(2)?;
    tokio::time::timeout(Duration::from_secs(2), c.channels.wait_stopped()).await??;
    tokio::time::timeout(Duration::from_secs(2), h.wait_stopped()).await??;
    assert!(
        c.channels
            .send(Channel::Video, b"stale generation")
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn private_prefixes_never_allow_metadata_loopback_or_the_wrong_network() -> Result {
    let default = AddressPolicy::new(&[])?;
    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "192.168.10.20",
        "fd12:3456::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(!default.allows(address.parse()?));
    }
    let lan = AddressPolicy::new(&["192.168.10.0/24".into(), "fd12:3456::/32".into()])?;
    assert!(lan.allows("192.168.10.254".parse()?));
    assert!(!lan.allows("192.168.11.20".parse()?));
    assert!(lan.allows("fd12:3456:1234::1".parse()?));
    assert!(!lan.allows("fd12:7890::1".parse()?));
    let all = AddressPolicy::new(&["0.0.0.0/0".into(), "::/0".into()])?;
    for address in [
        "127.0.0.1",
        "168.63.129.16",
        "169.254.169.254",
        "fd00:ec2::254",
        "::1",
    ] {
        assert!(!all.allows(address.parse()?));
    }
    assert!(AddressPolicy::new(&["1.2.3.4/33".into()]).is_err());
    assert!(AddressPolicy::new(&["::/129".into()]).is_err());
    Ok(())
}
#[tokio::test]
async fn actual_quic_identity_failure_terminates_the_candidate_race() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = permit(&controller, &host)?;
    let controller_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit.clone(),
        vec![],
        loopback_policy()?,
    )?;
    let host_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &host,
        &controller.identity.public_key(),
        permit.clone(),
        vec![],
        AddressPolicy::new(&[])?,
    )?;
    let wrong = nestlink_transport_quic::listener(
        "127.0.0.1:0".parse()?,
        &InstallationIdentity::generate(),
        controller.identity.fingerprint(),
    )?;
    let wrong_address = wrong.local_addr()?;
    let _wrong_peer = Abort(tokio::spawn(async move {
        if let Some(incoming) = wrong.accept().await {
            let _ = incoming.await;
        }
    }));
    let (_keep, cancel) = watch::channel(false);
    let address = host_endpoint.local_addr()?;
    let candidates = vec![
        candidate(wrong_address, CandidateKind::Lan, 4),
        candidate(address, CandidateKind::Reflexive, 4),
    ];
    let result = controller_endpoint.dial(4, candidates, cancel).await;
    assert!(matches!(
        result,
        Err(DialError::Failed { code: nestlink_protocol::ErrorCode::IdentityMismatch, failures })
            if failures.iter().any(|failure| failure.candidate.address == wrong_address
                && failure.code == nestlink_protocol::ErrorCode::IdentityMismatch)
    ));
    Ok(())
}

#[tokio::test]
async fn actual_direct_tls_identity_failure_is_not_retried_as_network_unavailability() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit(&controller, &host)?,
        vec![],
        loopback_policy()?,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut declaration = candidate(listener.local_addr()?, CandidateKind::Lan, 4);
    declaration.transport = Transport::Tls;
    let wrong = InstallationIdentity::generate();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        nestlink_transport_stream::tls::server_config(
            &wrong,
            controller.identity.fingerprint(),
        )?,
    ));
    let server = async {
        let (tcp, _) = listener.accept().await?;
        assert!(acceptor.accept(tcp).await.is_err());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (_keep, cancel) = watch::channel(false);
    let (result, served) = tokio::join!(
        endpoint.dial_native(&controller, None, 4, vec![declaration], cancel),
        server
    );
    served?;
    assert!(matches!(
        result,
        Err(DialError::Failed { code: nestlink_protocol::ErrorCode::IdentityMismatch, failures })
            if failures.iter().any(|failure| failure.stage == "direct-tcp-tls"
                && failure.code == nestlink_protocol::ErrorCode::IdentityMismatch)
    ));
    Ok(())
}
#[tokio::test]
async fn network_change_and_cancellation_stop_real_pending_quic_attempts() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = permit(&controller, &host)?;
    assert!(
        NativeEndpoint::new(
            "127.0.0.1:0".parse()?,
            &controller,
            &InstallationIdentity::generate().public_key(),
            permit.clone(),
            vec![],
            loopback_policy()?
        )
        .is_err()
    );
    let endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit,
        vec![],
        loopback_policy()?,
    )?;
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let (_keep, cancel) = watch::channel(false);
    let socket = endpoint.discovery_socket().ok_or("missing direct socket")?;
    let change = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        socket.invalidate_network(2)
    });
    let started = Instant::now();
    let result = endpoint
        .dial(
            4,
            vec![candidate(blackhole.local_addr()?, CandidateKind::Lan, 4)],
            cancel.clone(),
        )
        .await;
    assert!(matches!(result, Err(DialError::NetworkChanged)));
    assert!(started.elapsed() < Duration::from_secs(1));
    change.await??;
    let fresh = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit_for_retry(&controller, &host)?,
        vec![],
        loopback_policy()?,
    )?;
    let (stop, cancel) = watch::channel(false);
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send_replace(true);
    });
    assert!(matches!(
        fresh
            .dial(
                4,
                vec![candidate(blackhole.local_addr()?, CandidateKind::Lan, 4)],
                cancel
            )
            .await,
        Err(DialError::Cancelled)
    ));
    cancel_task.await?;
    Ok(())
}
fn permit_for_retry(controller: &DeviceIdentity, host: &DeviceIdentity) -> Result<VerifiedPermit> {
    permit(controller, host)
}

#[tokio::test]
async fn udp_blackhole_direct_tls_proof_and_os_monitor_loss_stop_idle_channels() -> Result {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let p = permit(&controller, &host)?;
    let monitor = nestlink_platform_network::NetworkMonitor::start()?;
    let endpoint = NativeEndpoint::new_monitored(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        p.clone(),
        vec![],
        loopback_policy()?,
        &monitor,
    )?;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        nestlink_transport_stream::tls::server_config(
            &host.identity,
            controller.identity.fingerprint(),
        )?,
    ));
    let host_tls = async {
        let (tcp, _) = tcp.accept().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(acceptor.accept(tcp).await?)
    };
    let mut tls_candidate = candidate(address, CandidateKind::Lan, 9);
    tls_candidate.transport = Transport::Tls;
    let (_keep, cancel) = watch::channel(false);
    let started = Instant::now();
    let (connected, host_io) = tokio::try_join!(
        async {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                endpoint
                    .dial_native(
                        &controller,
                        None,
                        9,
                        vec![
                            candidate(udp.local_addr()?, CandidateKind::Lan, 9),
                            tls_candidate,
                        ],
                        cancel,
                    )
                    .await?,
            )
        },
        host_tls,
    )?;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(connected.candidate.transport, Transport::Tls);
    let NativeTransport::DirectTls(controller_io) = connected.transport else {
        return Err("expected direct TLS".into());
    };
    let (mut cr, mut cw) = tokio::io::split(controller_io);
    let (mut hr, mut hw) = tokio::io::split(host_io);
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let mut cs = Session::activate(p.clone(), binding(&p)?, Path::Direct, now.monotonic_ms, now)?;
    let mut hs = Session::activate(p.clone(), binding(&p)?, Path::Direct, now.monotonic_ms, now)?;
    let host_key = host.identity.public_key();
    let controller_key = controller.identity.public_key();
    tokio::try_join!(
        controller_proof(
            &mut cr,
            &mut cw,
            &mut cs,
            &controller.identity,
            &host_key,
            &clock
        ),
        host_proof(
            &mut hr,
            &mut hw,
            &mut hs,
            &host.identity,
            &controller_key,
            &clock
        ),
    )?;
    let (_keepc, stopc) = watch::channel(None);
    let (_keeph, stoph) = watch::channel(None);
    let mut lifecycle = nestlink_remote::SessionLifecycle::new(stopc);
    lifecycle.network = Some(connected.network);
    let mut c = nestlink_remote::AuthorizedConnection::with_lifecycle(
        cr,
        cw,
        cs,
        Path::Direct,
        clock.clone(),
        lifecycle,
    )?
    .into_channels();
    let mut h = nestlink_remote::AuthorizedConnection::new(hr, hw, hs, Path::Direct, clock, stoph)?
        .into_channels();
    h.send(
        nestlink_transport_stream::Channel::Video,
        b"direct-tls-proof",
    )
    .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), c.receive())
            .await??
            .payload,
        b"direct-tls-proof"
    );
    drop(monitor);
    let report = tokio::time::timeout(Duration::from_secs(2), c.wait_stopped()).await??;
    assert_eq!(report.reason, nestlink_session::StopReason::NetworkChanged);
    tokio::time::timeout(Duration::from_secs(2), h.wait_stopped()).await??;
    assert!(
        c.send(nestlink_transport_stream::Channel::Video, b"old-generation")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn pending_tcp_handshakes_are_closed_on_cancel_and_network_change() -> Result {
    use tokio::io::AsyncReadExt;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for network_change in [false, true] {
        let endpoint = NativeEndpoint::new(
            "127.0.0.1:0".parse()?,
            &controller,
            &host.identity.public_key(),
            permit(&controller, &host)?,
            vec![],
            loopback_policy()?,
        )?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut declaration = candidate(tcp.local_addr()?, CandidateKind::Lan, 4);
        declaration.transport = Transport::Tls;
        let (stop, cancel) = watch::channel(false);
        let attempt = endpoint.dial_native(&controller, None, 4, vec![declaration], cancel);
        let change = async {
            let (mut stream, _) = tcp.accept().await?;
            let mut hello = [0; 4096];
            assert!(stream.read(&mut hello).await? > 0);
            if network_change {
                endpoint.invalidate_network(2)?;
            } else {
                stop.send_replace(true);
            }
            // The pending TLS future must drop its TCP stream, rather than leave
            // a detached socket connecting after the race has stopped.
            let closed = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    match stream.read(&mut hello).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            })
            .await;
            assert!(closed.is_ok());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let started = Instant::now();
        let (outcome, changed) = tokio::join!(attempt, change);
        changed?;
        assert!(started.elapsed() < Duration::from_secs(2));
        if network_change {
            assert!(matches!(outcome, Err(DialError::NetworkChanged)));
        } else {
            assert!(matches!(outcome, Err(DialError::Cancelled)));
        }
    }
    Ok(())
}

#[tokio::test]
async fn losing_actual_os_monitor_stops_pending_tcp_race() -> Result {
    use nestlink_platform_network::NetworkMonitor;
    use tokio::io::AsyncReadExt;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let stun_address = stun.local_addr()?;
    let monitor = NetworkMonitor::start()?;
    let endpoint = NativeEndpoint::new_monitored(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit(&controller, &host)?,
        vec![stun_address],
        loopback_policy()?,
        &monitor,
    )?;
    let discovery = endpoint
        .discovery_socket()
        .ok_or("missing discovery socket")?;
    let generation = discovery.generation();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut c = candidate(tcp.local_addr()?, CandidateKind::Lan, 7);
    c.transport = Transport::Tls;
    let (_keep, cancel) = watch::channel(false);
    let lose_monitor = async {
        let (mut stream, _) = tcp.accept().await?;
        let mut hello = [0; 4096];
        assert!(stream.read(&mut hello).await? > 0);
        let mut packet = [0; 512];
        assert!(stun.recv_from(&mut packet).await?.0 > 0);
        drop(monitor);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (dialled, lost, probe) = tokio::join!(
        endpoint.dial_native(&controller, None, 7, vec![c], cancel.clone()),
        lose_monitor,
        discovery.probe(stun_address, Duration::from_secs(3))
    );
    lost?;
    assert!(probe.is_err());
    assert!(discovery.generation() > generation);
    assert!(matches!(dialled, Err(DialError::NetworkChanged)));
    assert!(matches!(
        endpoint.dial(7, vec![], cancel).await,
        Err(DialError::NetworkChanged)
    ));
    Ok(())
}
