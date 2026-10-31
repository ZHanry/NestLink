//! Exercise the SDK adapter through physical QUIC neighbors and business proof.
#[path = "routed_tests/chain.rs"]
mod chain;
#[path = "routed_tests/route_set.rs"]
mod route_sets;
use super::{RemoteRouteAuthority, authorize_remote};
use crate::DeviceIdentity;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::random_id;
use nestlink_identity::{
    InstallationIdentity, PermitSigner, VerifiedPermit, digest,
    network::{
        NetworkAuthoritySigner, NetworkVerification, VerifiedMembership, VerifiedNetworkGrant,
        VerifiedNetworkPath, verify_network_grant,
    },
    verify_permit,
};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path, Permission, PermitClaims,
    network::{
        ConnectivityClaims, GrantClaims, GrantScope, MembershipClaims, PathClaims, PathPolicy,
        PeerId, PeerPair, Purpose, SpaceRole, TransitClaims,
    },
};
use nestlink_remote::{
    ChannelRuntime, RemoteError, RuntimeClock, SessionLifecycle, SessionSetup, StopHandler,
    TransportMode,
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopEffects, StopReason};
use nestlink_transport_quic::routed::{
    self, Adjacency, AdjacencyEndpoint, RelayForwarder, RouteAuthorization, RouteRevocation,
};
use nestlink_transport_stream::Channel;
use prost::Message;
use std::{
    collections::BTreeSet,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    time::Instant,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEPLOYMENT: &str = "10000000-0000-4000-8000-000000000001";
const SPACE: &str = "20000000-0000-4000-8000-000000000002";

struct Fixture {
    controller: DeviceIdentity,
    host: DeviceIdentity,
    relay: InstallationIdentity,
    issuer: [u8; 32],
    permit_signer: PermitSigner,
    permit: VerifiedPermit,
    connectivity: VerifiedNetworkGrant,
    path: VerifiedNetworkPath,
    transit: VerifiedNetworkGrant,
    now: u64,
    revoked: BTreeSet<String>,
    response: nestlink_protocol::api::NetworkRemoteRelayView,
}
impl Fixture {
    fn new(allow_relay: bool) -> Result<Self> {
        Self::with_route_lifetime(allow_relay, 12_000)
    }
    fn with_route_lifetime(allow_relay: bool, route_lifetime_ms: u64) -> Result<Self> {
        Self::with_peer_order(allow_relay, route_lifetime_ms, true)
    }
    fn with_peer_order(
        allow_relay: bool,
        route_lifetime_ms: u64,
        controller_first: bool,
    ) -> Result<Self> {
        let mut controller = DeviceIdentity::generate();
        let mut host = DeviceIdentity::generate();
        if (controller.identity.fingerprint() < host.identity.fingerprint()) != controller_first {
            std::mem::swap(&mut controller, &mut host);
        }
        let relay = InstallationIdentity::generate();
        let now = RuntimeClock::default().sample()?.unix_ms;
        let signer = NetworkAuthoritySigner::from_master_seed(&[83; 32])?;
        let issuer = signer.public_key();
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let permit_signer = PermitSigner::generate();
        let claims = PermitClaims {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: DEPLOYMENT.into(),
            security_epoch: 1,
            session_id: random_id(),
            account_id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            controller_key_sha256: controller.identity.fingerprint().to_vec(),
            host_key_sha256: host.identity.fingerprint().to_vec(),
            resource_id: random_id(),
            permissions: vec![Permission::View as i32, Permission::FileRead as i32],
            paths: if allow_relay {
                vec![Path::Direct as i32, Path::Relay as i32]
            } else {
                vec![Path::Direct as i32]
            },
            policy_revision: 1,
            connection_generation: 4,
            lease_sequence: 7,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 15_000,
            capability_sha256: digest(b"sdk-routed-vp8").to_vec(),
            required_capabilities: vec!["vp8".into()],
            media_format_version: 0,
            media_formats: Vec::new(),
            media_format_sha256: Vec::new(),
        };
        let permit = verify_permit(
            &permit_signer.sign(&claims)?.encode_to_vec(),
            &permit_signer.public_key(),
        )?;
        let scope = |id: u8| GrantScope {
            schema_version: 1,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            grant_id: format!("30000000-0000-4000-8000-{id:012x}"),
            policy_epoch: 9,
            not_before_ms: now,
            expires_at_ms: now + route_lifetime_ms,
        };
        let mut memberships = Vec::new();
        let mut member_views = Vec::new();
        let grant_view =
            |claims: &GrantClaims| -> Result<nestlink_protocol::api::NetworkGrantView> {
                let signed = signer.sign(claims)?;
                Ok(nestlink_protocol::api::NetworkGrantView {
                    schema_version: 1,
                    grant_id: claims.scope().grant_id.clone(),
                    claims: URL_SAFE_NO_PAD.encode(signed.claims),
                    signature: URL_SAFE_NO_PAD.encode(signed.signature),
                })
            };
        for (index, device) in [&controller, &host].into_iter().enumerate() {
            let member = MembershipClaims {
                scope: scope(index as u8 + 1),
                installation_id: device.device_id.clone(),
                peer: PeerId(device.identity.fingerprint()),
                public_key: device.identity.public_key(),
                membership_epoch: 1,
                role: SpaceRole::Member,
            };
            let signed = signer.sign(&GrantClaims::Membership(member.clone()))?;
            member_views.push(grant_view(&GrantClaims::Membership(member.clone()))?);
            memberships.push(VerifiedMembership::from_grant(
                verify_network_grant(&signed, &context)?,
                &context,
                &member.installation_id,
                &member.public_key,
                member.membership_epoch,
            )?);
        }
        let mut memberships = [memberships.remove(0), memberships.remove(0)];
        // Connectivity references follow canonical PeerPair order, independently
        // of the controller/host roles retained by the management response.
        memberships.sort_by_key(VerifiedMembership::peer);
        let peers = PeerPair::new(
            PeerId(controller.identity.fingerprint()),
            PeerId(host.identity.fingerprint()),
        )?;
        let connectivity = verify_network_grant(
            &signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
                scope: scope(3),
                peers,
                purpose: Purpose::RemoteControl,
                membership_digests: [memberships[0].digest(), memberships[1].digest()],
                business_grant_digest: permit.digest(),
            }))?,
            &context,
        )?;
        let path_grant = verify_network_grant(
            &signer.sign(&GrantClaims::Path(PathClaims {
                scope: scope(4),
                peers,
                purpose: Purpose::RemoteControl,
                connectivity_grant_digest: connectivity.digest(),
                policy: PathPolicy {
                    allow_direct: false,
                    relays: vec![PeerId(relay.fingerprint())],
                    max_hops: 1,
                },
            }))?,
            &context,
        )?;
        let path = VerifiedNetworkPath::from_grants(
            &context,
            memberships,
            connectivity.clone(),
            path_grant,
            permit.digest(),
        )?;
        let transit = verify_network_grant(
            &signer.sign(&GrantClaims::Transit(TransitClaims {
                scope: scope(5),
                peers,
                transport_group: path.transport_group_id(),
                route_id: "60000000-0000-4000-8000-000000000006".into(),
                relay: PeerId(relay.fingerprint()),
                previous: peers.first,
                next: peers.second,
                remaining_hops: 1,
                byte_limit: 2_000_000,
            }))?,
            &context,
        )?;
        let response = nestlink_protocol::api::NetworkRemoteRelayView {
            allocation_id: "60000000-0000-4000-8000-000000000006".into(),
            path: nestlink_protocol::api::NetworkRemotePathView {
                request_id: permit.claims().session_id.clone(),
                controller_membership: member_views.remove(0),
                host_membership: member_views.remove(0),
                connectivity: grant_view(connectivity.claims())?,
                path: grant_view(&GrantClaims::Path(path.claims().clone()))?,
            },
            transit: grant_view(transit.claims())?,
            node: nestlink_protocol::api::NodeEndpointsView {
                node_id: random_id(),
                revision: 1,
                endpoints: nestlink_protocol::api::NodeEndpoints {
                    quic_uri: Some("quic://127.0.0.1:28744".into()),
                    wss_origin: None,
                    allow_loopback: true,
                },
            },
        };
        Ok(Self {
            controller,
            host,
            relay,
            issuer,
            permit_signer,
            permit,
            connectivity,
            path,
            transit,
            now,
            revoked,
            response,
        })
    }
    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: self.now,
            revoked_grant_ids: &self.revoked,
        }
    }
    fn authority<'a>(&'a self, context: &'a NetworkVerification<'a>) -> RemoteRouteAuthority<'a> {
        RemoteRouteAuthority {
            context,
            path: &self.path,
            connectivity: &self.connectivity,
            transit: &self.transit,
        }
    }
    fn setup(
        &self,
        permit: &VerifiedPermit,
        role: EndpointRole,
        stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<SessionSetup> {
        let c = permit.claims();
        let binding = SessionBinding {
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            session_id: c.session_id.clone(),
            account_id: c.account_id.clone(),
            controller_device_id: c.controller_device_id.clone(),
            host_device_id: c.host_device_id.clone(),
            controller_key_sha256: c.controller_key_sha256.as_slice().try_into()?,
            host_key_sha256: c.host_key_sha256.as_slice().try_into()?,
            resource_id: c.resource_id.clone(),
            policy_revision: c.policy_revision,
            connection_generation: c.connection_generation,
            capability_sha256: c.capability_sha256.as_slice().try_into()?,
            granted_permissions: vec![Permission::View, Permission::FileRead],
            supported_capabilities: vec!["vp8".into()],
            local_paths: PathSet::BOTH,
            media: None,
        };
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        Ok(SessionSetup {
            // Start on Direct so success also proves the adapter selects Relay
            // within the same signed business scope before endpoint proof.
            session: Session::activate(
                permit.clone(),
                binding,
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
}

async fn neighbors(
    relay: &InstallationIdentity,
    peer: &InstallationIdentity,
    deadline: Instant,
) -> Result<(Adjacency, Adjacency, [SocketAddr; 2])> {
    let listener =
        AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, relay, PeerId(peer.fingerprint()))?;
    let connector =
        AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, peer, PeerId(relay.fingerprint()))?;
    let addresses = [listener.local_addr()?, connector.local_addr()?];
    let (accepted, connected) = tokio::try_join!(
        listener.accept(deadline),
        connector.connect(addresses[0], deadline)
    )?;
    Ok((accepted, connected, addresses))
}

struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn phase<T, E: std::fmt::Debug>(
    name: &str,
    result: std::result::Result<T, E>,
    peers: &[(&str, &ChannelRuntime)],
) -> std::result::Result<T, E> {
    if let Err(error) = &result {
        eprintln!("SDK routed first observed error at {name}: {error:?}");
        for (peer, channels) in peers {
            let report = channels.lease_control().subscribe_stopped();
            eprintln!(
                "SDK routed {peer} stop report at {name}: {:?}",
                *report.borrow()
            );
        }
    }
    result
}

fn report_pair(
    controller: &std::result::Result<ChannelRuntime, RemoteError>,
    host: &std::result::Result<ChannelRuntime, RemoteError>,
) {
    // Observe both establishment results before an early return can drop the
    // successful runtime and add a secondary ExplicitExit cleanup observation.
    eprintln!(
        "SDK routed controller authorization: {:?}",
        controller.as_ref().map(|_| "authorized")
    );
    eprintln!(
        "SDK routed host authorization: {:?}",
        host.as_ref().map(|_| "authorized")
    );
    for (peer, result) in [("controller", controller), ("host", host)] {
        if let Ok(channels) = result {
            let report = channels.lease_control().subscribe_stopped();
            eprintln!(
                "SDK routed {peer} stop report after paired authorization: {:?}",
                *report.borrow()
            );
        }
    }
}

fn original_path_observation(
    channels: &ChannelRuntime,
    permit: &VerifiedPermit,
    path: &VerifiedNetworkPath,
) -> Result<nestlink_remote::PathObservation> {
    let observation = channels
        .path_observation()
        .ok_or("missing original path observer")?;
    let binding = observation.binding();
    assert_eq!(binding.business_grant_digest, permit.digest());
    assert_eq!(
        binding.business_generation,
        permit.claims().connection_generation
    );
    assert_eq!(
        binding.path_grant_id.as_deref(),
        Some(path.claims().scope.grant_id.as_str())
    );
    assert_eq!(binding.transport_group, Some(path.transport_group_id()));
    assert!(binding.route_binding.is_some());
    assert_eq!(binding.purpose, path.purpose());
    assert_eq!(binding.path, Path::Relay);
    assert_eq!(binding.candidate, None);
    assert_eq!(binding.network_generation, None);
    Ok(observation)
}

#[tokio::test]
async fn existing_carrier_lifecycle_is_rejected_before_business_proof_and_releases_original_sockets()
-> Result {
    let f = Fixture::new(true)?;
    let context = f.context();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut relay, adjacency, addresses) =
        neighbors(&f.relay, &f.controller.identity, deadline).await?;
    let (_keep, stop) = watch::channel(None);
    let (_facts, carrier) = watch::channel(None);
    let mut setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
    setup.lifecycle.carrier = Some(carrier);
    let result = authorize_remote(
        f.authority(&context),
        adjacency,
        setup,
        &f.controller,
        &f.host.identity.public_key(),
        deadline,
    )
    .await;
    assert!(
        matches!(result, Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    relay.close_and_wait(deadline).await?;
    let _relay_rebound = std::net::UdpSocket::bind(addresses[0])?;
    let _controller_rebound = std::net::UdpSocket::bind(addresses[1])?;
    Ok(())
}

#[tokio::test]
async fn sdk_three_node_business_proof_limits_channels_and_releases_every_physical_socket() -> Result
{
    remote_payload_for_order(true).await
}

#[tokio::test]
async fn sdk_host_initiated_inner_quic_still_proves_controller_business_and_releases_original_sockets()
-> Result {
    remote_payload_for_order(false).await
}

async fn remote_payload_for_order(controller_first: bool) -> Result {
    let f = Fixture::with_peer_order(true, 12_000, controller_first)?;
    assert_eq!(
        f.controller.identity.fingerprint() < f.host.identity.fingerprint(),
        controller_first
    );
    let context = f.context();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (relay_controller, controller, controller_addresses) =
        neighbors(&f.relay, &f.controller.identity, deadline).await?;
    let (relay_host, host, host_addresses) =
        neighbors(&f.relay, &f.host.identity, deadline).await?;
    let (relay_authority, relay_stop) =
        RouteAuthorization::remote(&context, &f.path, &f.connectivity, &f.transit, &f.permit)?;
    let signed_deadline = relay_authority.deadline().into_std();
    let (relay_first, relay_second) = if controller_first {
        (relay_controller, relay_host)
    } else {
        (relay_host, relay_controller)
    };
    let mut relay = RelayForwarder::new(relay_authority, relay_first, relay_second)?;
    let mut forwarding = Abort(tokio::spawn(async move {
        let stopped = relay.run().await.is_err();
        let forwarded = relay.forwarded_fragments();
        let charged = relay.charged_bytes();
        relay
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        Ok::<_, io::Error>((stopped, forwarded, charged))
    }));
    let (_controller_keep, controller_stop) = watch::channel(None);
    let (_host_keep, host_stop) = watch::channel(None);
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let (controller, host) = tokio::join!(
        authorize_remote(
            f.authority(&context),
            controller,
            f.setup(&f.permit, EndpointRole::Controller, controller_stop)?,
            &f.controller,
            &host_key,
            deadline
        ),
        authorize_remote(
            f.authority(&context),
            host,
            f.setup(&f.permit, EndpointRole::Host, host_stop)?,
            &f.host,
            &controller_key,
            deadline
        ),
    );
    report_pair(&controller, &host);
    let mut controller = controller?;
    let mut host = host?;
    let observations = [
        original_path_observation(&controller, &f.permit, &f.path)?,
        original_path_observation(&host, &f.permit, &f.path)?,
    ];
    for channels in [&controller, &host] {
        assert_eq!(channels.mode(), TransportMode::QuicStreamsAndDatagrams);
        assert_eq!(
            channels.lease_control().current_native_permit()?.digest(),
            f.permit.digest()
        );
        // Independently sampled wall/monotonic conversion can round by 1 ms.
        assert!(
            channels.lease_control().current_deadline()?
                <= signed_deadline + Duration::from_millis(2)
        );
    }
    let payload = vec![39; 32_768];
    phase(
        "host FileRead enqueue",
        host.send(Channel::FileRead, &payload).await,
        &[("controller", &controller), ("host", &host)],
    )?;
    let received = phase(
        "controller FileRead receive deadline",
        tokio::time::timeout_at(deadline, controller.receive()).await,
        &[("controller", &controller), ("host", &host)],
    )?;
    let received = phase(
        "controller FileRead receive",
        received,
        &[("controller", &controller), ("host", &host)],
    )?;
    assert_eq!(received.channel, Channel::FileRead);
    assert_eq!(received.payload, payload);
    phase(
        "controller FileRead enqueue",
        controller
            .send(Channel::FileRead, b"authorized file request")
            .await,
        &[("controller", &controller), ("host", &host)],
    )?;
    let received = phase(
        "host FileRead receive deadline",
        tokio::time::timeout_at(deadline, host.receive()).await,
        &[("controller", &controller), ("host", &host)],
    )?;
    assert_eq!(
        phase(
            "host FileRead receive",
            received,
            &[("controller", &controller), ("host", &host)]
        )?
        .payload,
        b"authorized file request"
    );
    assert!(
        matches!(controller.send(Channel::Input, b"unapproved input").await,
        Err(RemoteError::Authorization(ref error)) if error.code == nestlink_protocol::ErrorCode::PermissionRequired)
    );
    assert!(matches!(host.claim_channel(Channel::Input),
        Err(RemoteError::Authorization(ref error)) if error.code == nestlink_protocol::ErrorCode::PermissionRequired));
    // Set both local terminal states before either side sends a close packet.
    controller.lease_control().stop(StopReason::ExplicitExit)?;
    host.lease_control().stop(StopReason::ExplicitExit)?;
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (controller_report, host_report) = tokio::time::timeout_at(cleanup, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(controller_report.reason, StopReason::ExplicitExit);
    assert_eq!(host_report.reason, StopReason::ExplicitExit);
    for observation in &observations {
        let stopped = observation.snapshot();
        assert!(stopped.stopped);
        assert_eq!(stopped.rtt, None);
        assert_eq!(stopped.binding, *observation.binding());
    }
    relay_stop.revoke();
    let (stopped, forwarded, charged) =
        tokio::time::timeout_at(cleanup, &mut forwarding.0).await???;
    assert!(stopped && forwarded > 0 && charged >= payload.len() as u64);
    for address in controller_addresses.into_iter().chain(host_addresses) {
        drop(std::net::UdpSocket::bind(address)?);
    }
    drop(observations);
    eprintln!(
        "SDK routed business proof: file_read_bytes={}, input_denied=true, forwarded_fragments={forwarded}, charged_bytes={charged}, released_udp_sockets=4",
        payload.len()
    );
    Ok(())
}

#[tokio::test]
async fn sdk_route_admission_rejects_another_business_permit_peer_key_and_direct_only_business()
-> Result {
    for fault in 0..3 {
        let f = Fixture::new(fault != 2)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut relay, controller, addresses) =
            neighbors(&f.relay, &f.controller.identity, deadline).await?;
        let permit = if fault == 0 {
            let mut claims = f.permit.claims().clone();
            claims.connection_generation += 1;
            verify_permit(
                &f.permit_signer.sign(&claims)?.encode_to_vec(),
                &f.permit_signer.public_key(),
            )?
        } else {
            f.permit.clone()
        };
        let peer_key = if fault == 1 {
            InstallationIdentity::generate().public_key()
        } else {
            f.host.identity.public_key()
        };
        let (_keep, stop) = watch::channel(None);
        let setup = f.setup(&permit, EndpointRole::Controller, stop)?;
        let (rejected, released) = tokio::join!(
            authorize_remote(
                f.authority(&context),
                controller,
                setup,
                &f.controller,
                &peer_key,
                deadline
            ),
            relay.close_and_wait(deadline),
        );
        released?;
        assert!(
            matches!(rejected, Err(RemoteError::Io(ref error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "fault {fault} must reject business authority, with successful physical cleanup: {:?}",
            rejected.as_ref().map(|_| "unexpectedly authorized")
        );
        for address in addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
    }
    Ok(())
}

type Forwarding = Abort<io::Result<u64>>;
struct Mesh {
    controller: Adjacency,
    host: Adjacency,
    relay_stop: RouteRevocation,
    forwarding: Forwarding,
    addresses: [SocketAddr; 4],
}
async fn mesh(f: &Fixture, deadline: Instant) -> Result<Mesh> {
    let (relay_controller, controller, a) =
        neighbors(&f.relay, &f.controller.identity, deadline).await?;
    let (relay_host, host, b) = neighbors(&f.relay, &f.host.identity, deadline).await?;
    let (authorization, relay_stop) = RouteAuthorization::remote(
        &f.context(),
        &f.path,
        &f.connectivity,
        &f.transit,
        &f.permit,
    )?;
    let mut relay = RelayForwarder::new(authorization, relay_controller, relay_host)?;
    let forwarding = Abort(tokio::spawn(async move {
        let stopped = relay.run().await.is_err();
        let forwarded = relay.forwarded_fragments();
        relay
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        if !stopped {
            return Err(io::Error::other(
                "relay unexpectedly ended without a terminal condition",
            ));
        }
        Ok(forwarded)
    }));
    Ok(Mesh {
        controller,
        host,
        relay_stop,
        forwarding,
        addresses: [a[0], a[1], b[0], b[1]],
    })
}
async fn finish_mesh(
    relay_stop: RouteRevocation,
    mut forwarding: Forwarding,
    addresses: [SocketAddr; 4],
    deadline: Instant,
) -> Result<u64> {
    relay_stop.revoke();
    let forwarded = tokio::time::timeout_at(deadline, &mut forwarding.0).await???;
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(forwarded)
}

// This one deadline fixture accepts Cleanup(TimedOut): the controller owner
// then has only requested Drop teardown, with no completion receipt. Wait for
// its real UDP release within the original final cleanup budget. The relay and
// host owners have explicit receipts and must still permit immediate rebinding.
async fn finish_mesh_after_incomplete_controller_cleanup(
    relay_stop: RouteRevocation,
    mut forwarding: Forwarding,
    addresses: [SocketAddr; 4],
    deadline: Instant,
) -> Result<u64> {
    relay_stop.revoke();
    let forwarded = tokio::time::timeout_at(deadline, &mut forwarding.0).await???;
    for (role, address) in [
        ("relay-controller", addresses[0]),
        ("controller", addresses[1]),
        ("relay-host", addresses[2]),
        ("host", addresses[3]),
    ] {
        if role == "controller" {
            eprintln!("SDK routed deadline cleanup phase=drop-release-wait role={role} address={address}");
            let socket = tokio::time::timeout_at(deadline, async {
                loop {
                    match std::net::UdpSocket::bind(address) {
                        Ok(socket) => return Ok(socket),
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut,
                format!("SDK routed deadline cleanup phase=drop-release-wait role={role} address={address}")))??;
            drop(socket);
        } else {
            drop(std::net::UdpSocket::bind(address).map_err(|error| {
                io::Error::new(error.kind(), format!("SDK routed deadline cleanup phase=receipt-rebind role={role} address={address}: {error}"))
            })?);
        }
        eprintln!("SDK routed deadline cleanup phase=rebound role={role} address={address}");
    }
    Ok(forwarded)
}

#[tokio::test]
async fn sdk_preflight_rejects_an_existing_stop_and_a_dropped_stop_source_with_socket_receipts()
-> Result {
    for closed in [false, true] {
        let f = Fixture::new(true)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut relay, controller, addresses) =
            neighbors(&f.relay, &f.controller.identity, deadline).await?;
        let (source, stop) = watch::channel(None);
        if !closed {
            source.send_replace(Some(StopReason::Revoked));
        }
        let source = (!closed).then_some(source);
        let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
        let peer_key = f.host.identity.public_key();
        let (rejected, released) = tokio::join!(
            authorize_remote(
                f.authority(&context),
                controller,
                setup,
                &f.controller,
                &peer_key,
                deadline
            ),
            relay.close_and_wait(deadline),
        );
        assert!(
            matches!(rejected, Err(RemoteError::Stopped)),
            "closed={closed}"
        );
        released?;
        for address in addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
        drop(source);
    }
    Ok(())
}

#[tokio::test]
async fn sdk_absolute_deadline_covers_business_proof_after_real_routed_quic_establishment() -> Result
{
    let f = Fixture::new(true)?;
    let context = f.context();
    let Mesh {
        controller,
        host,
        relay_stop,
        forwarding,
        addresses,
    } = mesh(&f, Instant::now() + Duration::from_secs(5)).await?;
    let (host_authority, host_stop) =
        RouteAuthorization::remote(&context, &f.path, &f.connectivity, &f.transit, &f.permit)?;
    let (_keep, stop) = watch::channel(None);
    let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
    let peer_key = f.host.identity.public_key();
    let deadline = Instant::now() + Duration::from_millis(1200);
    // The real peer completes inner TLS and deliberately withholds business
    // proof. The remote proof implementation's own budget is three seconds.
    let (rejected, peer) = tokio::time::timeout_at(deadline + Duration::from_millis(500), async {
        tokio::join!(
            authorize_remote(
                f.authority(&context),
                controller,
                setup,
                &f.controller,
                &peer_key,
                deadline
            ),
            routed::establish(host_authority, host, &f.host.identity, deadline),
        )
    })
    .await?;
    let mut peer = peer?;
    assert!(matches!(rejected,
        Err(RemoteError::Io(ref error) | RemoteError::Cleanup(ref error))
            if error.kind() == io::ErrorKind::TimedOut));
    tokio::time::timeout(Duration::from_secs(1), peer.connection()?.closed()).await?;
    host_stop.revoke();
    let cleanup = Instant::now() + Duration::from_secs(5);
    peer.close_and_wait(cleanup).await?;
    finish_mesh_after_incomplete_controller_cleanup(relay_stop, forwarding, addresses, cleanup).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_stop_interrupts_routed_establishment_before_the_inner_peer_starts() -> Result {
    let f = Fixture::new(true)?;
    let context = f.context();
    let deadline = Instant::now() + Duration::from_secs(5);
    let Mesh {
        controller,
        mut host,
        relay_stop,
        forwarding,
        addresses,
    } = mesh(&f, deadline).await?;
    let (source, stop) = watch::channel(None);
    let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
    let peer_key = f.host.identity.public_key();
    // The physical host adjacency is real and retained, while no inner peer
    // exists to answer the controller's routed QUIC Initial packets.
    let (completed, signalled) = tokio::time::timeout_at(deadline, async {
        tokio::join!(
            async {
                let result = authorize_remote(
                    f.authority(&context),
                    controller,
                    setup,
                    &f.controller,
                    &peer_key,
                    deadline,
                )
                .await;
                (Instant::now(), result)
            },
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let signalled = Instant::now();
                source.send_replace(Some(StopReason::Revoked));
                signalled
            },
        )
    })
    .await?;
    assert!(completed.0 >= signalled);
    assert!(completed.0.duration_since(signalled) < Duration::from_secs(1));
    assert!(matches!(completed.1, Err(RemoteError::Stopped)));
    let cleanup = Instant::now() + Duration::from_secs(5);
    host.close_and_wait(cleanup).await?;
    assert!(
        finish_mesh(relay_stop, forwarding, addresses, cleanup).await? > 0,
        "the relay must have actually forwarded inner establishment traffic"
    );
    Ok(())
}

#[tokio::test]
async fn sdk_waiting_business_proof_ignores_none_updates_and_stops_on_revocation_or_source_drop()
-> Result {
    for closed in [false, true] {
        let f = Fixture::new(true)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let Mesh {
            controller,
            host,
            relay_stop,
            forwarding,
            addresses,
        } = mesh(&f, deadline).await?;
        let (host_authority, host_stop) =
            RouteAuthorization::remote(&context, &f.path, &f.connectivity, &f.transit, &f.permit)?;
        let (source, stop) = watch::channel(None);
        let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
        let peer_key = f.host.identity.public_key();
        let (ready, established) = oneshot::channel();
        let (completed, signalled, peer) = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                async {
                    let result = authorize_remote(
                        f.authority(&context),
                        controller,
                        setup,
                        &f.controller,
                        &peer_key,
                        deadline,
                    )
                    .await;
                    (Instant::now(), result)
                },
                async move {
                    established.await?;
                    source.send_replace(None);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let signalled = Instant::now();
                    if closed {
                        drop(source);
                    } else {
                        source.send_replace(Some(StopReason::Revoked));
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(signalled)
                },
                async {
                    let peer =
                        routed::establish(host_authority, host, &f.host.identity, deadline).await?;
                    ready
                        .send(())
                        .map_err(|_| io::Error::other("proof wait was not observed"))?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(peer)
                },
            )
        })
        .await?;
        let signalled = signalled?;
        let mut peer = peer?;
        assert!(
            completed.0 >= signalled,
            "a None update must not cancel business proof"
        );
        assert!(
            completed.0.duration_since(signalled) < Duration::from_secs(1),
            "stop must interrupt proof before its independent three-second budget"
        );
        assert!(
            matches!(completed.1, Err(RemoteError::Stopped)),
            "closed={closed}"
        );
        tokio::time::timeout(Duration::from_secs(1), peer.connection()?.closed()).await?;
        host_stop.revoke();
        let cleanup = Instant::now() + Duration::from_secs(5);
        peer.close_and_wait(cleanup).await?;
        finish_mesh(relay_stop, forwarding, addresses, cleanup).await?;
    }
    Ok(())
}

struct StopSpy {
    checks: Arc<AtomicUsize>,
    stops: Arc<AtomicUsize>,
}
impl StopHandler for StopSpy {
    fn check(&mut self) -> io::Result<()> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stop(&mut self, reason: StopReason, effects: StopEffects) -> io::Result<()> {
        assert_eq!(reason, StopReason::Revoked);
        assert!(effects.cancel_channels && effects.close_allocations);
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn terminal_route_hook_revokes_the_same_authorization_before_returning_to_its_caller() -> Result {
    let f = Fixture::new(true)?;
    let (authorization, revocation) = RouteAuthorization::remote(
        &f.context(),
        &f.path,
        &f.connectivity,
        &f.transit,
        &f.permit,
    )?;
    let checks = Arc::new(AtomicUsize::new(0));
    let stops = Arc::new(AtomicUsize::new(0));
    let mut handler = super::RemoteRouteStop {
        revocation: Arc::new(revocation),
        deadline: authorization.deadline(),
        previous: Some(Box::new(StopSpy {
            checks: checks.clone(),
            stops: stops.clone(),
        })),
    };
    handler.check()?;
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    authorization.check_live()?;
    handler.stop(
        StopReason::Revoked,
        StopEffects {
            cancel_channels: true,
            release_inputs: true,
            discard_queues: true,
            close_allocations: true,
        },
    )?;
    // There is no await or transport-owner cleanup between these operations.
    assert_eq!(stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        authorization.check_live().err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[tokio::test]
async fn sdk_business_renewal_preserves_the_original_route_ceiling_and_synchronous_stop_handler()
-> Result {
    let f = Fixture::with_route_lifetime(true, 5000)?;
    let context = f.context();
    let deadline = Instant::now() + Duration::from_secs(4);
    let Mesh {
        controller,
        host,
        relay_stop,
        forwarding,
        addresses,
    } = mesh(&f, deadline).await?;
    let (_controller_keep, controller_stop) = watch::channel(None);
    let (_host_keep, host_stop) = watch::channel(None);
    let checks = Arc::new(AtomicUsize::new(0));
    let stops = Arc::new(AtomicUsize::new(0));
    let mut controller_setup = f.setup(&f.permit, EndpointRole::Controller, controller_stop)?;
    controller_setup.lifecycle.resources = Some(Box::new(StopSpy {
        checks: checks.clone(),
        stops: stops.clone(),
    }));
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let (controller, host) = tokio::join!(
        authorize_remote(
            f.authority(&context),
            controller,
            controller_setup,
            &f.controller,
            &host_key,
            deadline
        ),
        authorize_remote(
            f.authority(&context),
            host,
            f.setup(&f.permit, EndpointRole::Host, host_stop)?,
            &f.host,
            &controller_key,
            deadline
        ),
    );
    report_pair(&controller, &host);
    let mut controller = controller?;
    let mut host = host?;
    let controller_ceiling = phase(
        "controller original route ceiling",
        controller.lease_control().current_deadline(),
        &[("controller", &controller), ("host", &host)],
    )?;
    let host_ceiling = phase(
        "host original route ceiling",
        host.lease_control().current_deadline(),
        &[("controller", &controller), ("host", &host)],
    )?;
    // Make the renewal request later than activation on both runtime clocks.
    tokio::time::sleep(Duration::from_millis(2)).await;
    let mut claims = f.permit.claims().clone();
    claims.lease_sequence += 1;
    claims.issued_at_unix_ms = phase(
        "controller renewal clock",
        controller.lease_control().renewal_clock(),
        &[("controller", &controller), ("host", &host)],
    )?
    .unix_ms;
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 15_000;
    let renewed = verify_permit(
        &f.permit_signer.sign(&claims)?.encode_to_vec(),
        &f.permit_signer.public_key(),
    )?;
    for (name, channels) in [("controller", &controller), ("host", &host)] {
        let control = channels.lease_control();
        let clock = phase(
            &format!("{name} renewal request clock"),
            control.renewal_clock(),
            &[("controller", &controller), ("host", &host)],
        )?;
        phase(
            &format!("{name} business renewal"),
            control.renew(renewed.clone(), clock.monotonic_ms),
            &[("controller", &controller), ("host", &host)],
        )?;
        assert_eq!(control.current_native_permit()?.digest(), renewed.digest());
    }
    assert_eq!(
        controller.lease_control().current_deadline()?,
        controller_ceiling
    );
    assert_eq!(host.lease_control().current_deadline()?, host_ceiling);
    phase(
        "renewed host FileRead enqueue",
        host.send(
            Channel::FileRead,
            b"still inside the original route ceiling",
        )
        .await,
        &[("controller", &controller), ("host", &host)],
    )?;
    let received = phase(
        "renewed controller receive deadline",
        tokio::time::timeout_at(deadline, controller.receive()).await,
        &[("controller", &controller), ("host", &host)],
    )?;
    assert_eq!(
        phase(
            "renewed controller FileRead receive",
            received,
            &[("controller", &controller), ("host", &host)]
        )?
        .payload,
        b"still inside the original route ceiling"
    );
    assert!(checks.load(Ordering::SeqCst) > 0);
    controller.lease_control().stop(StopReason::Revoked)?;
    assert_eq!(
        stops.load(Ordering::SeqCst),
        1,
        "the caller's original cleanup must run before stop returns"
    );
    // The host has no local stop signal. The route hook closes its actual
    // transport and the existing remote lifecycle observes peer revocation.
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (controller_report, host_report) = tokio::time::timeout_at(cleanup, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(controller_report.reason, StopReason::Revoked);
    assert_eq!(host_report.reason, StopReason::Revoked);
    assert_eq!(stops.load(Ordering::SeqCst), 1);
    finish_mesh(relay_stop, forwarding, addresses, cleanup).await?;
    Ok(())
}

fn readback_sdk(f: &Fixture) -> Result<crate::Sdk> {
    use nestlink_protocol::api::{HealthResponse, LoginResponse, Principal};
    let issuer = f.permit_signer.public_key();
    let mut sdk = crate::Sdk {
        client: reqwest::Client::builder().no_proxy().build()?,
        origin: url::Url::parse("https://control.example.test")?,
        trust: crate::DeploymentTrust {
            deployment_id: DEPLOYMENT.into(),
            permit_issuer: issuer,
        },
        health: HealthResponse {
            product: "NestLink".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            api_base: nestlink_protocol::API_BASE.into(),
            alpn: nestlink_protocol::ALPN.into(),
            deployment_id: DEPLOYMENT.into(),
            security_epoch: 1,
            permit_issuer: URL_SAFE_NO_PAD.encode(issuer),
            node_policy_issuer: URL_SAFE_NO_PAD.encode(issuer),
            native_ice_version: 0,
        },
        login: None,
    };
    sdk.install_login(LoginResponse {
        principal: Principal {
            account_id: f.permit.claims().account_id.clone(),
            session_id: random_id(),
            name: "network-readback".into(),
            is_admin: false,
            access_expires: 9999999999,
        },
        access_token: "A".repeat(43),
        refresh_token: "B".repeat(43),
        generation: 1,
        refresh_expires: 9999999999,
    })?;
    Ok(sdk)
}

#[test]
fn management_readback_binds_both_device_roles_and_the_original_network_pin() -> Result {
    let f = Fixture::new(true)?;
    let sdk = readback_sdk(&f)?;
    let pin = super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    for (local, peer) in [(&f.controller, &f.host), (&f.host, &f.controller)] {
        let route = sdk.verify_relay_readback(
            &pin,
            local,
            &f.permit,
            &peer.identity.public_key(),
            &f.response.allocation_id,
            f.response.clone(),
            Instant::now(),
        )?;
        assert_eq!(route.allocation_id(), f.response.allocation_id);
        assert!(route.bound_to(&sdk, &f.permit));
        assert!(route.deadline() > Instant::now());
        assert!(route.deadline() <= Instant::now() + Duration::from_secs(12));
    }
    for pin in [
        super::PinnedNetworkSpace::new(SPACE.into(), [11; 32])?,
        super::PinnedNetworkSpace::new(random_id(), f.issuer)?,
    ] {
        assert!(
            sdk.verify_relay_readback(
                &pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &f.response.allocation_id,
                f.response.clone(),
                Instant::now()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn management_readback_rejects_retargeted_corrupted_and_obsolete_credentials() -> Result {
    let f = Fixture::new(true)?;
    let sdk = readback_sdk(&f)?;
    let pin = super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    let mut wrong_request = f.response.clone();
    wrong_request.path.request_id = random_id();
    let mut wrong_allocation = f.response.clone();
    wrong_allocation.allocation_id = random_id();
    let mut swapped_members = f.response.clone();
    std::mem::swap(
        &mut swapped_members.path.controller_membership,
        &mut swapped_members.path.host_membership,
    );
    let mut forged_transit = f.response.clone();
    forged_transit.transit.signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let mut missing_node = f.response.clone();
    missing_node.node.endpoints.quic_uri = None;
    for view in [
        wrong_request,
        wrong_allocation,
        swapped_members,
        forged_transit,
        missing_node,
    ] {
        assert!(
            sdk.verify_relay_readback(
                &pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &f.response.allocation_id,
                view,
                Instant::now()
            )
            .is_err()
        );
    }
    let mut claims = f.permit.claims().clone();
    claims.connection_generation += 1;
    let successor = verify_permit(
        &f.permit_signer.sign(&claims)?.encode_to_vec(),
        &f.permit_signer.public_key(),
    )?;
    assert!(
        sdk.verify_relay_readback(
            &pin,
            &f.controller,
            &successor,
            &f.host.identity.public_key(),
            &f.response.allocation_id,
            f.response.clone(),
            Instant::now()
        )
        .is_err()
    );
    assert!(
        sdk.verify_relay_readback(
            &pin,
            &f.controller,
            &f.permit,
            &InstallationIdentity::generate().public_key(),
            &f.response.allocation_id,
            f.response.clone(),
            Instant::now()
        )
        .is_err()
    );
    assert!(
        sdk.verify_relay_readback(
            &pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            &f.response.allocation_id,
            f.response.clone(),
            Instant::now() - Duration::from_secs(6)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn a_verified_readback_cannot_cross_logout_login_server_or_business_generation() -> Result {
    let f = Fixture::new(true)?;
    let mut sdk = readback_sdk(&f)?;
    let pin = super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    let route = sdk.verify_relay_readback(
        &pin,
        &f.controller,
        &f.permit,
        &f.host.identity.public_key(),
        &f.response.allocation_id,
        f.response.clone(),
        Instant::now(),
    )?;
    assert!(route.bound_to(&sdk, &f.permit));
    let mut different_login = readback_sdk(&f)?;
    assert!(!route.bound_to(&different_login, &f.permit));
    different_login.origin = url::Url::parse("https://other.example.test")?;
    assert!(!route.bound_to(&different_login, &f.permit));
    sdk.forget_login();
    assert!(!route.bound_to(&sdk, &f.permit));
    Ok(())
}

#[tokio::test]
async fn external_cancel_and_source_drop_interrupt_inner_setup_with_physical_cleanup() -> Result {
    for dropped in [false, true] {
        let f = Fixture::new(true)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let Mesh {
            controller,
            mut host,
            relay_stop,
            forwarding,
            addresses,
        } = mesh(&f, deadline).await?;
        let (_keep, stop) = watch::channel(None);
        let (source, cancel) = watch::channel(false);
        let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
        let peer_key = f.host.identity.public_key();
        // The physical peer exists, but does not start inner TLS. Cancellation
        // must end this wait before the five-second establishment deadline.
        let (completed, (signalled, _cancel_keep)) = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                async {
                    let result = super::authorize_remote_observed(
                        f.authority(&context),
                        controller,
                        setup,
                        &f.controller,
                        &peer_key,
                        deadline,
                        None,
                        Some(cancel),
                    )
                    .await;
                    (Instant::now(), result)
                },
                async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let signalled = Instant::now();
                    let keep = if dropped {
                        drop(source);
                        None
                    } else {
                        source.send_replace(true);
                        Some(source)
                    };
                    (signalled, keep)
                },
            )
        })
        .await?;
        assert!(
            matches!(completed.1, Err(RemoteError::Stopped)),
            "dropped={dropped}"
        );
        assert!(completed.0 >= signalled);
        assert!(completed.0.duration_since(signalled) < Duration::from_secs(3));
        let cleanup = Instant::now() + Duration::from_secs(5);
        host.close_and_wait(cleanup).await?;
        assert!(finish_mesh(relay_stop, forwarding, addresses, cleanup).await? > 0);
    }
    Ok(())
}

#[tokio::test]
async fn external_cancel_and_source_drop_interrupt_business_proof_with_physical_cleanup() -> Result
{
    for dropped in [false, true] {
        let f = Fixture::new(true)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let Mesh {
            controller,
            host,
            relay_stop,
            forwarding,
            addresses,
        } = mesh(&f, deadline).await?;
        let (host_authority, host_stop) =
            RouteAuthorization::remote(&context, &f.path, &f.connectivity, &f.transit, &f.permit)?;
        let (_keep, stop) = watch::channel(None);
        let (source, cancel) = watch::channel(false);
        let setup = f.setup(&f.permit, EndpointRole::Controller, stop)?;
        let peer_key = f.host.identity.public_key();
        let (ready, established) = oneshot::channel();
        let (completed, signal, peer) = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                async {
                    let result = super::authorize_remote_observed(
                        f.authority(&context),
                        controller,
                        setup,
                        &f.controller,
                        &peer_key,
                        deadline,
                        None,
                        Some(cancel),
                    )
                    .await;
                    (Instant::now(), result)
                },
                async move {
                    established.await?;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let signalled = Instant::now();
                    let keep = if dropped {
                        drop(source);
                        None
                    } else {
                        source.send_replace(true);
                        Some(source)
                    };
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((signalled, keep))
                },
                async {
                    // Complete actual inner QUIC and withhold business proof.
                    let peer =
                        routed::establish(host_authority, host, &f.host.identity, deadline).await?;
                    ready
                        .send(())
                        .map_err(|_| io::Error::other("proof wait was not observed"))?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(peer)
                },
            )
        })
        .await?;
        let (signalled, _cancel_keep) = signal?;
        let mut peer = peer?;
        assert!(
            matches!(completed.1, Err(RemoteError::Stopped)),
            "dropped={dropped}"
        );
        assert!(completed.0 >= signalled);
        assert!(completed.0.duration_since(signalled) < Duration::from_secs(3));
        host_stop.revoke();
        let cleanup = Instant::now() + Duration::from_secs(5);
        peer.close_and_wait(cleanup).await?;
        finish_mesh(relay_stop, forwarding, addresses, cleanup).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ready_current_readback_cannot_bypass_the_final_deadline_or_terminal_sources() -> Result {
    use crate::native::SessionEstablishError;
    let f = Fixture::new(true)?;
    let sdk = readback_sdk(&f)?;
    let pin = super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    let route = sdk.verify_relay_readback(
        &pin,
        &f.controller,
        &f.permit,
        &f.host.identity.public_key(),
        &f.response.allocation_id,
        f.response.clone(),
        Instant::now(),
    )?;
    let (stop_source, stop) = watch::channel(None);
    let (cancel_source, cancel) = watch::channel(false);
    // A ready inner future wins timeout_at even after its absolute deadline.
    // The same still-current response must fail the subsequent handoff check.
    let deadline = Instant::now() - Duration::from_millis(1);
    let current = tokio::time::timeout_at(deadline, std::future::ready(f.response.clone())).await?;
    assert!(route.bound_to(&sdk, &f.permit));
    assert!(
        route
            .validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline)
            .is_err()
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(
        route
            .validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline)
            .is_ok()
    );
    cancel_source.send_replace(true);
    assert!(matches!(
        route.validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline),
        Err(SessionEstablishError::Cancelled)
    ));
    let (cancel_source, cancel) = watch::channel(false);
    drop(cancel_source);
    assert!(matches!(
        route.validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline),
        Err(SessionEstablishError::Cancelled)
    ));
    let (_cancel_keep, cancel) = watch::channel(false);
    stop_source.send_replace(Some(StopReason::Revoked));
    assert!(matches!(
        route.validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline),
        Err(SessionEstablishError::Remote(RemoteError::Stopped))
    ));
    let (stop_source, stop) = watch::channel(None);
    drop(stop_source);
    assert!(matches!(
        route.validate_handoff(&sdk, &f.permit, &current, &stop, &cancel, deadline),
        Err(SessionEstablishError::Remote(RemoteError::Stopped))
    ));
    Ok(())
}
