//! Exercise the SDK adapter through physical QUIC neighbors and business proof.
use super::{RemoteRouteAuthority, authorize_remote};
use crate::DeviceIdentity;
use nestlink_auth::random_id;
use nestlink_identity::{
    InstallationIdentity, PermitSigner, VerifiedPermit, digest, verify_permit,
    network::{
        NetworkAuthoritySigner, NetworkVerification, VerifiedMembership, VerifiedNetworkGrant,
        VerifiedNetworkPath, verify_network_grant,
    },
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
    RemoteError, RuntimeClock, SessionLifecycle, SessionSetup, TransportMode,
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_quic::routed::{
    Adjacency, AdjacencyEndpoint, RelayForwarder, RouteAuthorization,
};
use nestlink_transport_stream::Channel;
use prost::Message;
use std::{collections::BTreeSet, io, net::SocketAddr, time::Duration};
use tokio::{sync::watch, time::Instant};

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
}
impl Fixture {
    fn new(allow_relay: bool) -> Result<Self> {
        let mut controller = DeviceIdentity::generate();
        let mut host = DeviceIdentity::generate();
        if controller.identity.fingerprint() > host.identity.fingerprint() {
            std::mem::swap(&mut controller, &mut host);
        }
        let relay = InstallationIdentity::generate();
        let now = RuntimeClock::default().sample()?.unix_ms;
        let signer = NetworkAuthoritySigner::from_master_seed(&[83; 32])?;
        let issuer = signer.public_key();
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &issuer, deployment_id: DEPLOYMENT, space_id: SPACE,
            policy_epoch: 9, now_ms: now, revoked_grant_ids: &revoked,
        };
        let permit_signer = PermitSigner::generate();
        let claims = PermitClaims {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: DEPLOYMENT.into(), security_epoch: 1, session_id: random_id(),
            account_id: random_id(), controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            controller_key_sha256: controller.identity.fingerprint().to_vec(),
            host_key_sha256: host.identity.fingerprint().to_vec(), resource_id: random_id(),
            permissions: vec![Permission::View as i32, Permission::FileRead as i32],
            paths: if allow_relay { vec![Path::Direct as i32, Path::Relay as i32] } else { vec![Path::Direct as i32] },
            policy_revision: 1, connection_generation: 4, lease_sequence: 7,
            issued_at_unix_ms: now, expires_at_unix_ms: now + 15_000,
            capability_sha256: digest(b"sdk-routed-vp8").to_vec(), required_capabilities: vec!["vp8".into()],
            media_format_version: 0, media_formats: Vec::new(), media_format_sha256: Vec::new(),
        };
        let permit = verify_permit(&permit_signer.sign(&claims)?.encode_to_vec(), &permit_signer.public_key())?;
        let scope = |id: u8| GrantScope {
            schema_version: 1, deployment_id: DEPLOYMENT.into(), space_id: SPACE.into(),
            grant_id: format!("30000000-0000-4000-8000-{id:012x}"), policy_epoch: 9,
            not_before_ms: now, expires_at_ms: now + 12_000,
        };
        let mut memberships = Vec::new();
        for (index, device) in [&controller, &host].into_iter().enumerate() {
            let member = MembershipClaims {
                scope: scope(index as u8 + 1), installation_id: device.device_id.clone(),
                peer: PeerId(device.identity.fingerprint()), public_key: device.identity.public_key(),
                membership_epoch: 1, role: SpaceRole::Member,
            };
            let signed = signer.sign(&GrantClaims::Membership(member.clone()))?;
            memberships.push(VerifiedMembership::from_grant(
                verify_network_grant(&signed, &context)?, &context, &member.installation_id,
                &member.public_key, member.membership_epoch,
            )?);
        }
        let memberships = [memberships.remove(0), memberships.remove(0)];
        let peers = PeerPair::new(PeerId(controller.identity.fingerprint()), PeerId(host.identity.fingerprint()))?;
        let connectivity = verify_network_grant(&signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
            scope: scope(3), peers, purpose: Purpose::RemoteControl,
            membership_digests: [memberships[0].digest(), memberships[1].digest()],
            business_grant_digest: permit.digest(),
        }))?, &context)?;
        let path_grant = verify_network_grant(&signer.sign(&GrantClaims::Path(PathClaims {
            scope: scope(4), peers, purpose: Purpose::RemoteControl,
            connectivity_grant_digest: connectivity.digest(),
            policy: PathPolicy { allow_direct: false, relays: vec![PeerId(relay.fingerprint())], max_hops: 1 },
        }))?, &context)?;
        let path = VerifiedNetworkPath::from_grants(&context, memberships, connectivity.clone(), path_grant, permit.digest())?;
        let transit = verify_network_grant(&signer.sign(&GrantClaims::Transit(TransitClaims {
            scope: scope(5), peers, transport_group: path.transport_group_id(),
            route_id: "60000000-0000-4000-8000-000000000006".into(), relay: PeerId(relay.fingerprint()),
            previous: peers.first, next: peers.second, remaining_hops: 1, byte_limit: 2_000_000,
        }))?, &context)?;
        Ok(Self { controller, host, relay, issuer, permit_signer, permit, connectivity, path, transit, now, revoked })
    }
    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.issuer, deployment_id: DEPLOYMENT, space_id: SPACE,
            policy_epoch: 9, now_ms: self.now, revoked_grant_ids: &self.revoked,
        }
    }
    fn authority<'a>(&'a self, context: &'a NetworkVerification<'a>) -> RemoteRouteAuthority<'a> {
        RemoteRouteAuthority { context, path: &self.path, connectivity: &self.connectivity, transit: &self.transit }
    }
    fn setup(
        &self,
        permit: &VerifiedPermit,
        role: EndpointRole,
        stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<SessionSetup> {
        let c = permit.claims();
        let binding = SessionBinding {
            deployment_id: c.deployment_id.clone(), security_epoch: c.security_epoch,
            session_id: c.session_id.clone(), account_id: c.account_id.clone(),
            controller_device_id: c.controller_device_id.clone(), host_device_id: c.host_device_id.clone(),
            controller_key_sha256: c.controller_key_sha256.as_slice().try_into()?,
            host_key_sha256: c.host_key_sha256.as_slice().try_into()?, resource_id: c.resource_id.clone(),
            policy_revision: c.policy_revision, connection_generation: c.connection_generation,
            capability_sha256: c.capability_sha256.as_slice().try_into()?,
            granted_permissions: vec![Permission::View, Permission::FileRead], supported_capabilities: vec!["vp8".into()],
            local_paths: PathSet::BOTH, media: None,
        };
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        Ok(SessionSetup {
            // Start on Direct so success also proves the adapter selects Relay
            // within the same signed business scope before endpoint proof.
            session: Session::activate(permit.clone(), binding, Path::Direct, now.monotonic_ms, now)?,
            path: Path::Direct, role, clock, lifecycle: SessionLifecycle::new(stop),
        })
    }
}

async fn neighbors(
    relay: &InstallationIdentity,
    peer: &InstallationIdentity,
    deadline: Instant,
) -> Result<(Adjacency, Adjacency, [SocketAddr; 2])> {
    let listener = AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, relay, PeerId(peer.fingerprint()))?;
    let connector = AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, peer, PeerId(relay.fingerprint()))?;
    let addresses = [listener.local_addr()?, connector.local_addr()?];
    let (accepted, connected) = tokio::try_join!(listener.accept(deadline), connector.connect(addresses[0], deadline))?;
    Ok((accepted, connected, addresses))
}

struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) { self.0.abort(); }
}

#[tokio::test]
async fn sdk_three_node_business_proof_limits_channels_and_releases_every_physical_socket() -> Result {
    let f = Fixture::new(true)?;
    let context = f.context();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (relay_controller, controller, controller_addresses) = neighbors(&f.relay, &f.controller.identity, deadline).await?;
    let (relay_host, host, host_addresses) = neighbors(&f.relay, &f.host.identity, deadline).await?;
    let (relay_authority, relay_stop) = RouteAuthorization::remote(&context, &f.path, &f.connectivity, &f.transit, &f.permit)?;
    let signed_deadline = relay_authority.deadline().into_std();
    let mut relay = RelayForwarder::new(relay_authority, relay_controller, relay_host)?;
    let mut forwarding = Abort(tokio::spawn(async move {
        let stopped = relay.run().await.is_err();
        let forwarded = relay.forwarded_fragments();
        let charged = relay.charged_bytes();
        relay.close_and_wait(Instant::now() + Duration::from_secs(5)).await?;
        Ok::<_, io::Error>((stopped, forwarded, charged))
    }));
    let (_controller_keep, controller_stop) = watch::channel(None);
    let (_host_keep, host_stop) = watch::channel(None);
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let (mut controller, mut host) = tokio::try_join!(
        authorize_remote(f.authority(&context), controller, f.setup(&f.permit, EndpointRole::Controller, controller_stop)?, &f.controller, &host_key, deadline),
        authorize_remote(f.authority(&context), host, f.setup(&f.permit, EndpointRole::Host, host_stop)?, &f.host, &controller_key, deadline),
    )?;
    for channels in [&controller, &host] {
        assert_eq!(channels.mode(), TransportMode::QuicStreamsAndDatagrams);
        assert_eq!(channels.lease_control().current_native_permit()?.digest(), f.permit.digest());
        // Independently sampled wall/monotonic conversion can round by 1 ms.
        assert!(channels.lease_control().reconnection_budget()?.deadline() <= signed_deadline + Duration::from_millis(2));
    }
    let payload = vec![39; 32_768];
    host.send(Channel::FileRead, &payload).await?;
    let received = tokio::time::timeout_at(deadline, controller.receive()).await??;
    assert_eq!(received.channel, Channel::FileRead);
    assert_eq!(received.payload, payload);
    controller.send(Channel::FileRead, b"authorized file request").await?;
    assert_eq!(tokio::time::timeout_at(deadline, host.receive()).await??.payload, b"authorized file request");
    assert!(matches!(controller.send(Channel::Input, b"unapproved input").await,
        Err(RemoteError::Authorization(ref error)) if error.code == nestlink_protocol::ErrorCode::PermissionRequired));
    assert!(matches!(host.claim_channel(Channel::Input),
        Err(RemoteError::Authorization(ref error)) if error.code == nestlink_protocol::ErrorCode::PermissionRequired));
    // Set both local terminal states before either side sends a close packet.
    controller.lease_control().stop(StopReason::ExplicitExit)?;
    host.lease_control().stop(StopReason::ExplicitExit)?;
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (controller_report, host_report) = tokio::time::timeout_at(cleanup, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    }).await??;
    assert_eq!(controller_report.reason, StopReason::ExplicitExit);
    assert_eq!(host_report.reason, StopReason::ExplicitExit);
    relay_stop.revoke();
    let (stopped, forwarded, charged) = tokio::time::timeout_at(cleanup, &mut forwarding.0).await???;
    assert!(stopped && forwarded > 0 && charged >= payload.len() as u64);
    for address in controller_addresses.into_iter().chain(host_addresses) {
        drop(std::net::UdpSocket::bind(address)?);
    }
    eprintln!("SDK routed business proof: file_read_bytes={}, input_denied=true, forwarded_fragments={forwarded}, charged_bytes={charged}, released_udp_sockets=4", payload.len());
    Ok(())
}

#[tokio::test]
async fn sdk_route_admission_rejects_another_business_permit_peer_key_and_direct_only_business() -> Result {
    for fault in 0..3 {
        let f = Fixture::new(fault != 2)?;
        let context = f.context();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut relay, controller, addresses) = neighbors(&f.relay, &f.controller.identity, deadline).await?;
        let permit = if fault == 0 {
            let mut claims = f.permit.claims().clone();
            claims.connection_generation += 1;
            verify_permit(&f.permit_signer.sign(&claims)?.encode_to_vec(), &f.permit_signer.public_key())?
        } else { f.permit.clone() };
        let peer_key = if fault == 1 { InstallationIdentity::generate().public_key() } else { f.host.identity.public_key() };
        let (_keep, stop) = watch::channel(None);
        let setup = f.setup(&permit, EndpointRole::Controller, stop)?;
        let (rejected, released) = tokio::join!(
            authorize_remote(f.authority(&context), controller, setup, &f.controller, &peer_key, deadline),
            relay.close_and_wait(deadline),
        );
        released?;
        assert!(matches!(rejected, Err(RemoteError::Io(ref error)) if error.kind() == io::ErrorKind::PermissionDenied), "fault {fault} must reject business authority, with successful physical cleanup");
        for address in addresses { drop(std::net::UdpSocket::bind(address)?); }
    }
    Ok(())
}
