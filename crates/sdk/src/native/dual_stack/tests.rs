use super::*;
use nestlink_identity::{PermitSigner, verify_permit};
use nestlink_protocol::{SCHEMA_VERSION, api::CandidateKind};
use nestlink_transport_stream::Channel;
use prost::Message;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fixture(paths: Vec<Path>) -> Result<(DeviceIdentity, DeviceIdentity, VerifiedPermit)> {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: SCHEMA_VERSION,
        deployment_id: nestlink_auth::random_id(),
        security_epoch: 1,
        session_id: nestlink_auth::random_id(),
        account_id: nestlink_auth::random_id(),
        controller_device_id: controller.device_id.clone(),
        host_device_id: host.device_id.clone(),
        controller_key_sha256: controller.identity.fingerprint().to_vec(),
        host_key_sha256: host.identity.fingerprint().to_vec(),
        resource_id: host.device_id.clone(),
        permissions: vec![Permission::View as i32],
        paths: paths.into_iter().map(|path| path as i32).collect(),
        policy_revision: 1,
        connection_generation: 4,
        lease_sequence: 7,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 15_000,
        capability_sha256: digest(b"dual-stack-vp8").to_vec(),
        required_capabilities: vec!["vp8".into()],
    };
    let signer = PermitSigner::generate();
    let permit = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
    Ok((controller, host, permit))
}

fn policy() -> Result<AddressPolicy> {
    let mut policy = AddressPolicy::new(&[])?;
    policy.test_loopback = true;
    Ok(policy)
}

fn setup(
    permit: &VerifiedPermit,
    role: EndpointRole,
    stop: watch::Receiver<Option<StopReason>>,
) -> Result<SessionSetup> {
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let options = NativeSessionOptions {
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    Ok(SessionSetup {
        session: Session::activate(
            permit.clone(),
            session_binding(permit, options, None, role, now.unix_ms)?,
            Path::Direct,
            now.monotonic_ms,
            now,
        )?,
        path: Path::Direct,
        role,
        clock,
        lifecycle: SessionLifecycle::new(stop),
    })
}

#[tokio::test]
async fn each_address_family_completes_native_proof_using_the_actual_winning_socket() -> Result {
    for ipv4 in [true, false] {
        let (controller, host, permit) = fixture(vec![Path::Direct])?;
        let mut controller_endpoint = NativeEndpoint::new_dual_stack(
            &controller,
            &host.identity.public_key(),
            permit.clone(),
            vec![],
            policy()?,
        )?;
        let mut host_endpoint = NativeEndpoint::new_dual_stack(
            &host,
            &controller.identity.public_key(),
            permit.clone(),
            vec![],
            policy()?,
        )?;
        let original_deadline = Instant::now() + Duration::from_secs(4);
        controller_endpoint.cap_authorization_deadline(original_deadline)?;
        host_endpoint.cap_authorization_deadline(original_deadline)?;
        let mut address = host_endpoint
            .local_addrs()?
            .into_iter()
            .find(|address| address.is_ipv4() == ipv4)
            .ok_or("requested family did not bind")?;
        address.set_ip(if ipv4 {
            IpAddr::from([127, 0, 0, 1])
        } else {
            IpAddr::from([0_u16, 0, 0, 0, 0, 0, 0, 1])
        });
        let candidate = Candidate {
            address,
            kind: if ipv4 {
                CandidateKind::Lan
            } else {
                CandidateKind::Ipv6
            },
            transport: Transport::Quic,
            generation: 1,
        };
        let (_cancel_owner, cancel) = watch::channel(false);
        let (dialed, accepted) = tokio::join!(
            controller_endpoint.dial_native_with_relays(
                &controller,
                &[],
                1,
                vec![candidate],
                cancel.clone()
            ),
            host_endpoint.accept_native(1, cancel),
        );
        let dialed = dialed?;
        let accepted = accepted?;
        for connection in [&dialed, &accepted] {
            let NativeTransport::Quic { endpoint, .. } = &connection.transport else {
                return Err("selected transport was not QUIC".into());
            };
            assert_eq!(endpoint.local_addr()?.is_ipv4(), ipv4);
            assert_eq!(connection.candidate.address.is_ipv4(), ipv4);
        }
        let (_controller_stop_owner, controller_stop) = watch::channel(None);
        let (_host_stop_owner, host_stop) = watch::channel(None);
        let host_key = host.identity.public_key();
        let controller_key = controller.identity.public_key();
        let (mut controller_session, mut host_session) = tokio::try_join!(
            dialed.authorize(
                setup(&permit, EndpointRole::Controller, controller_stop)?,
                &controller,
                &host_key
            ),
            accepted.authorize(
                setup(&permit, EndpointRole::Host, host_stop)?,
                &host,
                &controller_key
            ),
        )?;
        host_session
            .channels
            .send(Channel::Video, b"fresh mutual proof")
            .await?;
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                controller_session.channels.receive()
            )
            .await??
            .payload,
            b"fresh mutual proof"
        );
        controller_session
            .shutdown(StopReason::TransportLost)
            .await?;
        host_session.channels.wait_stopped().await?;
        for session in [&controller_session, &host_session] {
            assert!(
                session
                    .channels
                    .lease_control()
                    .reconnection_budget()?
                    .deadline()
                    <= original_deadline
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn both_sockets_capture_one_os_generation_and_invalidate_together() -> Result {
    let (controller, host, permit) = fixture(vec![Path::Direct])?;
    let monitor = NetworkMonitor::start()?;
    let generation = monitor.invalidate_generation()?;
    let endpoint = NativeEndpoint::new_dual_stack_monitored(
        &controller,
        &host.identity.public_key(),
        permit,
        vec![],
        AddressPolicy::new(&[])?,
        &monitor,
    )?;
    let sockets = endpoint.discovery_sockets();
    assert_eq!(sockets.len(), 2);
    assert!(
        sockets
            .iter()
            .all(|socket| socket.generation() == generation)
    );
    assert_eq!(endpoint.local_generation, generation);
    assert_eq!(endpoint.signal_sequence.load(Ordering::Acquire), 0);
    let first = endpoint.next_signal_sequence()?;
    let second = endpoint.next_signal_sequence()?;
    assert!(first > 0);
    assert!(second > first);
    monitor.invalidate_generation()?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while sockets
            .iter()
            .any(|socket| socket.generation() == generation)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(matches!(endpoint.check(), Err(DialError::NetworkChanged)));
    Ok(())
}

#[tokio::test]
async fn explicit_bind_and_relay_only_keep_their_original_socket_scope() -> Result {
    let (controller, host, permit) = fixture(vec![Path::Direct])?;
    for bound in ["127.0.0.1:0", "[::1]:0"] {
        let endpoint = NativeEndpoint::new(
            bound.parse()?,
            &controller,
            &host.identity.public_key(),
            permit.clone(),
            vec![],
            AddressPolicy::new(&[])?,
        )?;
        assert_eq!(endpoint.local_addrs()?.len(), 1);
        assert_eq!(endpoint.local_addr()?.is_ipv4(), bound.starts_with("127"));
    }
    let (controller, host, permit) = fixture(vec![Path::Relay])?;
    let endpoint = NativeEndpoint::new_dual_stack(
        &controller,
        &host.identity.public_key(),
        permit,
        vec![],
        AddressPolicy::new(&[])?,
    )?;
    assert!(endpoint.local_addrs()?.is_empty());
    assert!(endpoint.discovery_socket().is_none());
    Ok(())
}

#[tokio::test]
async fn first_family_cache_expiring_during_other_family_gather_is_not_published() -> Result {
    let v4_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let v6_server = tokio::net::UdpSocket::bind("[::1]:0").await?;
    let v4_address = v4_server.local_addr()?;
    let v6_address = v6_server.local_addr()?;
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = requests.clone();
    let (stop, mut stopped) = watch::channel(false);
    let responder = tokio::spawn(async move {
        let mut bytes = [0; 512];
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                packet = v4_server.recv_from(&mut bytes) => {
                    let (length, source) = packet?;
                    received.fetch_add(1, Ordering::SeqCst);
                    v4_server.send_to(&nestlink_traversal::stun::response(&bytes[..length], "198.51.100.7:5555".parse()?)?, source).await?;
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (controller, host, permit) = fixture(vec![Path::Direct])?;
    let endpoint = NativeEndpoint::new_dual_stack(
        &controller,
        &host.identity.public_key(),
        permit,
        vec![v4_address, v6_address],
        AddressPolicy::new(&[])?,
    )?;
    let v4 = endpoint
        .discovery_sockets()
        .into_iter()
        .find(|socket| socket.local_addr().is_ok_and(|address| address.is_ipv4()))
        .ok_or("IPv4 socket missing")?;
    let cached = v4.probe(v4_address, Duration::from_secs(2)).await?;
    tokio::time::sleep_until((cached.expires_at - Duration::from_secs(1)).into()).await;
    // IPv6 has an actual trusted socket, but intentionally gives no response.
    // Its two-second probe consumes the first family's remaining cache budget.
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint.gather_direct_candidates(vec![v4_address, v6_address]),
    )
    .await;
    stop.send(true)?;
    responder.await??;
    assert!(matches!(
        result?,
        Err(SessionEstablishError::Sdk(SdkError::Invalid))
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    drop(v6_server);
    Ok(())
}

#[test]
fn bounded_candidate_set_keeps_both_families_under_the_same_generation() -> Result {
    let candidates = |ipv4| -> Result<Vec<Candidate>> {
        (1..=32)
            .map(|number| {
                Ok(Candidate {
                    address: if ipv4 {
                        format!("198.51.100.{number}:443")
                    } else {
                        format!("[2001:db8::{number}]:443")
                    }
                    .parse()?,
                    kind: if ipv4 {
                        CandidateKind::Reflexive
                    } else {
                        CandidateKind::Ipv6
                    },
                    transport: Transport::Quic,
                    generation: 17,
                })
            })
            .collect()
    };
    let combined = interleave_families(candidates(true)?, candidates(false)?);
    assert_eq!(combined.len(), CANDIDATE_COUNT as usize);
    assert!(combined.iter().any(|candidate| candidate.address.is_ipv4()));
    assert!(combined.iter().any(|candidate| candidate.address.is_ipv6()));
    assert!(combined.iter().all(|candidate| candidate.generation == 17));
    let policy = AddressPolicy::new(&["192.168.0.0/16".into(), "fd00::/8".into()])?;
    assert!(!policy.allows("::ffff:192.168.12.1".parse()?));
    assert!(!policy.allows("::ffff:8.8.8.8".parse()?));
    assert!(!AddressPolicy::new(&[])?.allows("192.168.12.1".parse()?));
    assert!(!AddressPolicy::new(&[])?.allows("fd12::1".parse()?));
    Ok(())
}
