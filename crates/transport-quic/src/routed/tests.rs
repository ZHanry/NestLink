use super::*;
use nestlink_identity::{
    PermitSigner, VerifiedPermit,
    network::{
        NetworkAuthoritySigner, NetworkVerification, VerifiedMembership, VerifiedNetworkGrant,
        VerifiedNetworkPath, verify_network_grant,
    },
    verify_permit,
};
use nestlink_protocol::{Permission, network::*, network_datagram as wire};
use prost::Message;
use std::{
    collections::BTreeSet,
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEPLOYMENT: &str = "10000000-0000-4000-8000-000000000001";
const SPACE: &str = "20000000-0000-4000-8000-000000000002";
const INSTALLATIONS: [&str; 2] = [
    "40000000-0000-4000-8000-000000000004",
    "50000000-0000-4000-8000-000000000005",
];

struct Fixture {
    first: InstallationIdentity,
    second: InstallationIdentity,
    relay: InstallationIdentity,
    signer: NetworkAuthoritySigner,
    key: [u8; 32],
    permit_signer: PermitSigner,
    permit: VerifiedPermit,
    connectivity: VerifiedNetworkGrant,
    memberships: [VerifiedMembership; 2],
    path: VerifiedNetworkPath,
    transit: TransitClaims,
    now: u64,
    revoked: BTreeSet<String>,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let mut first = InstallationIdentity::generate();
        let mut second = InstallationIdentity::generate();
        if first.fingerprint() > second.fingerprint() {
            std::mem::swap(&mut first, &mut second);
        }
        let relay = InstallationIdentity::generate();
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let signer = NetworkAuthoritySigner::from_master_seed(&[81; 32])?;
        let key = signer.public_key();
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &key,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let permit_signer = PermitSigner::from_seed([1; 32]);
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/vectors/session-permit-v1.json"
        ))?;
        let hex = vector["envelope_hex"]
            .as_str()
            .ok_or("missing permit vector")?;
        let envelope: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16))
            .collect::<std::result::Result<_, _>>()?;
        let template = verify_permit(&envelope, &permit_signer.public_key())?;
        let mut business = template.claims().clone();
        business.deployment_id = DEPLOYMENT.into();
        business.controller_device_id = INSTALLATIONS[0].into();
        business.host_device_id = INSTALLATIONS[1].into();
        business.controller_key_sha256 = first.fingerprint().to_vec();
        business.host_key_sha256 = second.fingerprint().to_vec();
        business.paths = vec![nestlink_protocol::Path::Relay as i32];
        business.permissions = vec![Permission::FileRead as i32];
        business.issued_at_unix_ms = now - 100;
        business.expires_at_unix_ms = now + 10_000;
        let permit = verify_permit(
            &permit_signer.sign(&business)?.encode_to_vec(),
            &permit_signer.public_key(),
        )?;
        let scope = |id: u8| GrantScope {
            schema_version: 1,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            grant_id: format!("30000000-0000-4000-8000-{id:012x}"),
            policy_epoch: 9,
            not_before_ms: now - 100,
            expires_at_ms: now + 10_000,
        };
        let mut members = Vec::new();
        for (index, identity) in [&first, &second].into_iter().enumerate() {
            let claims = MembershipClaims {
                scope: scope(index as u8 + 1),
                installation_id: INSTALLATIONS[index].into(),
                peer: PeerId(identity.fingerprint()),
                public_key: identity.public_key(),
                membership_epoch: 1,
                role: SpaceRole::Member,
            };
            let signed = signer.sign(&GrantClaims::Membership(claims.clone()))?;
            members.push(VerifiedMembership::from_grant(
                verify_network_grant(&signed, &context)?,
                &context,
                &claims.installation_id,
                &claims.public_key,
                1,
            )?);
        }
        let memberships = [members.remove(0), members.remove(0)];
        let peers = PeerPair::new(PeerId(first.fingerprint()), PeerId(second.fingerprint()))?;
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
            memberships.clone(),
            connectivity.clone(),
            path_grant,
            permit.digest(),
        )?;
        let transit = TransitClaims {
            scope: scope(5),
            peers,
            transport_group: path.transport_group_id(),
            route_id: "60000000-0000-4000-8000-000000000006".into(),
            relay: PeerId(relay.fingerprint()),
            previous: peers.first,
            next: peers.second,
            remaining_hops: 1,
            byte_limit: 2_000_000,
        };
        Ok(Self {
            first,
            second,
            relay,
            signer,
            key,
            permit_signer,
            permit,
            connectivity,
            memberships,
            path,
            transit,
            now,
            revoked,
        })
    }
    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.key,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: self.now,
            revoked_grant_ids: &self.revoked,
        }
    }
    fn signed(&self, claims: GrantClaims) -> TestResult<VerifiedNetworkGrant> {
        Ok(verify_network_grant(
            &self.signer.sign(&claims)?,
            &self.context(),
        )?)
    }
    fn authorization(&self) -> TestResult<(RouteAuthorization, RouteRevocation)> {
        Ok(RouteAuthorization::remote(
            &self.context(),
            &self.path,
            &self.connectivity,
            &self.signed(GrantClaims::Transit(self.transit.clone()))?,
            &self.permit,
        )?)
    }
}

mod chain;

#[test]
fn complete_binding_refuses_crossed_grants_actual_business_peers_adjacencies_and_stale_policy()
-> TestResult {
    let fixture = Fixture::new()?;
    let transit = fixture.signed(GrantClaims::Transit(fixture.transit.clone()))?;
    let (valid, owner) = fixture.authorization()?;
    assert!(valid.live().is_ok());
    let GrantClaims::Connectivity(mut wrong) = fixture.connectivity.claims().clone() else {
        return Err("wrong fixture kind".into());
    };
    wrong.scope.grant_id = "70000000-0000-4000-8000-000000000007".into();
    let crossed = fixture.signed(GrantClaims::Connectivity(wrong))?;
    assert!(
        RouteAuthorization::remote(
            &fixture.context(),
            &fixture.path,
            &crossed,
            &transit,
            &fixture.permit
        )
        .is_err()
    );
    for change_peer in [false, true] {
        let mut business = fixture.permit.claims().clone();
        if change_peer {
            business.host_key_sha256 = InstallationIdentity::generate().fingerprint().to_vec();
        } else {
            business.connection_generation += 1;
        }
        let other = verify_permit(
            &fixture.permit_signer.sign(&business)?.encode_to_vec(),
            &fixture.permit_signer.public_key(),
        )?;
        assert!(
            RouteAuthorization::remote(
                &fixture.context(),
                &fixture.path,
                &fixture.connectivity,
                &transit,
                &other
            )
            .is_err()
        );
    }
    for edit in 0..5 {
        let mut wrong = fixture.transit.clone();
        match edit {
            0 => wrong.transport_group = [1; 32],
            1 => wrong.next = PeerId(InstallationIdentity::generate().fingerprint()),
            2 => std::mem::swap(&mut wrong.previous, &mut wrong.next),
            3 => {
                wrong.peers = PeerPair::new(
                    wrong.previous,
                    PeerId(InstallationIdentity::generate().fingerprint()),
                )?
            }
            _ => wrong.scope.expires_at_ms += 1,
        }
        let wrong = fixture.signed(GrantClaims::Transit(wrong))?;
        assert!(
            RouteAuthorization::remote(
                &fixture.context(),
                &fixture.path,
                &fixture.connectivity,
                &wrong,
                &fixture.permit
            )
            .is_err()
        );
    }
    let mut route = fixture.transit.clone();
    route.route_id = "80000000-0000-4000-8000-000000000008".into();
    let route = fixture.signed(GrantClaims::Transit(route))?;
    let (different_route, _different_owner) = RouteAuthorization::remote(
        &fixture.context(),
        &fixture.path,
        &fixture.connectivity,
        &route,
        &fixture.permit,
    )?;
    assert_ne!(different_route.binding_digest(), valid.binding_digest());
    let mut bytes = wire::encode(
        valid.binding_digest(),
        wire::Direction::FirstToSecond,
        1,
        &[1; 1200],
    )?
    .remove(0);
    assert!(
        wire::forward(
            &mut bytes,
            different_route.binding_digest(),
            wire::Direction::FirstToSecond
        )
        .is_err()
    );
    let mut context = fixture.context();
    context.space_id = "90000000-0000-4000-8000-000000000009";
    assert!(
        RouteAuthorization::remote(
            &context,
            &fixture.path,
            &fixture.connectivity,
            &transit,
            &fixture.permit
        )
        .is_err()
    );
    context = fixture.context();
    context.policy_epoch += 1;
    assert!(
        RouteAuthorization::remote(
            &context,
            &fixture.path,
            &fixture.connectivity,
            &transit,
            &fixture.permit
        )
        .is_err()
    );
    context = fixture.context();
    context.now_ms += 20_000;
    assert!(
        RouteAuthorization::remote(
            &context,
            &fixture.path,
            &fixture.connectivity,
            &transit,
            &fixture.permit
        )
        .is_err()
    );
    let mut revoked = BTreeSet::new();
    revoked.insert(fixture.transit.scope.grant_id.clone());
    context = fixture.context();
    context.revoked_grant_ids = &revoked;
    assert!(
        RouteAuthorization::remote(
            &context,
            &fixture.path,
            &fixture.connectivity,
            &transit,
            &fixture.permit
        )
        .is_err()
    );
    owner.revoke();
    assert!(valid.live().is_err());
    let (authorization, owner) = fixture.authorization()?;
    drop(owner);
    assert!(authorization.live().is_err());
    Ok(())
}

async fn pair(
    local: &InstallationIdentity,
    remote: &InstallationIdentity,
    deadline: Instant,
) -> TestResult<(Adjacency, Adjacency, [SocketAddr; 2])> {
    let listener =
        AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, local, PeerId(remote.fingerprint()))?;
    let connector =
        AdjacencyEndpoint::bind("127.0.0.1:0".parse()?, remote, PeerId(local.fingerprint()))?;
    let addresses = [listener.local_addr()?, connector.local_addr()?];
    let (accepted, connected) = tokio::join!(
        listener.accept(deadline),
        connector.connect(addresses[0], deadline)
    );
    Ok((accepted?, connected?, addresses))
}
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn actual_three_node_quic_keeps_initial_and_full_ipv6_packet_opaque_over_smaller_outer_datagrams()
-> TestResult {
    let fixture = Fixture::new()?;
    let setup = Instant::now() + Duration::from_secs(3);
    let (at_relay_first, first, addresses_a) = pair(&fixture.relay, &fixture.first, setup).await?;
    let (at_relay_second, second, addresses_b) =
        pair(&fixture.relay, &fixture.second, setup).await?;
    let (relay_auth, relay_revoke) = fixture.authorization()?;
    let mut relay = RelayForwarder::new(relay_auth, at_relay_first, at_relay_second)?;
    let marker = b"opaque IPv6 acceptance payload";
    let mut relay_task = Abort(tokio::spawn(async move {
        let result = relay.run().await;
        let initial_packets = relay.initial_packets;
        let forwarded = relay.forwarded_fragments();
        let observed_plaintext = relay
            .captured
            .iter()
            .any(|fragment| fragment.windows(marker.len()).any(|part| part == marker));
        relay
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        Ok::<_, io::Error>((
            result.is_err(),
            initial_packets,
            forwarded,
            observed_plaintext,
        ))
    }));
    let (first_auth, first_revoke) = fixture.authorization()?;
    let (second_auth, second_revoke) = fixture.authorization()?;
    let (a, b) = tokio::join!(
        establish(first_auth, first, &fixture.first, setup),
        establish(second_auth, second, &fixture.second, setup)
    );
    let mut first = a?;
    let mut second = b?;
    assert!(
        first
            .connection()?
            .max_datagram_size()
            .is_some_and(|size| size >= 1280)
    );
    let mut ipv6 = vec![0; 1280];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&1240u16.to_be_bytes());
    ipv6[6] = 59;
    ipv6[7] = 64;
    ipv6[8] = 0xfd;
    ipv6[23] = 1;
    ipv6[24] = 0xfd;
    ipv6[39] = 2;
    ipv6[40..40 + marker.len()].copy_from_slice(marker);
    first.connection()?.send_datagram(ipv6.clone().into())?;
    let received = tokio::time::timeout_at(setup, second.connection()?.read_datagram()).await??;
    assert_eq!(received.as_ref(), ipv6);
    second
        .connection()?
        .send_datagram(b"reverse packet boundary".as_slice().into())?;
    assert_eq!(
        tokio::time::timeout_at(setup, first.connection()?.read_datagram())
            .await??
            .as_ref(),
        b"reverse packet boundary"
    );
    relay_revoke.revoke();
    first_revoke.revoke();
    second_revoke.revoke();
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (left, right) = tokio::join!(
        first.close_and_wait(cleanup),
        second.close_and_wait(cleanup)
    );
    left?;
    right?;
    let (stopped, initials, forwarded, plaintext) =
        tokio::time::timeout_at(cleanup, &mut relay_task.0).await???;
    assert!(stopped);
    assert!(initials > 0);
    assert!(forwarded >= 6);
    assert!(!plaintext);
    for address in addresses_a.into_iter().chain(addresses_b) {
        drop(std::net::UdpSocket::bind(address)?);
    }
    eprintln!(
        "W07 actual QUIC: >=1200-byte Initial count={initials}, full IPv6 packet=1280, outer UDP cap=1200, outer fragment cap={}, forwarded={forwarded}, plaintext_visible={plaintext}",
        wire::HEADER + wire::FRAGMENT_BYTES
    );
    Ok(())
}

#[tokio::test]
async fn live_revoke_and_sender_drop_stop_idle_forwarding_without_receiving_another_packet()
-> TestResult {
    for explicit in [false, true] {
        let fixture = Fixture::new()?;
        let setup = Instant::now() + Duration::from_secs(3);
        let (left, mut client_left, _) = pair(&fixture.relay, &fixture.first, setup).await?;
        let (right, mut client_right, _) = pair(&fixture.relay, &fixture.second, setup).await?;
        let (auth, owner) = fixture.authorization()?;
        let mut relay = RelayForwarder::new(auth, left, right)?;
        {
            let run = relay.run();
            tokio::pin!(run);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    run.as_mut().poll(cx).is_pending()
                ))
                .await
            );
            if explicit {
                owner.revoke();
            }
            drop(owner);
            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut run)
                    .await?
                    .is_err()
            );
        }
        let cleanup = Instant::now() + Duration::from_secs(5);
        relay.close_and_wait(cleanup).await?;
        client_left.close_and_wait(cleanup).await?;
        client_right.close_and_wait(cleanup).await?;
    }
    Ok(())
}

#[test]
fn routed_codec_and_shared_assembly_bound_full_packets_reordering_expiry_and_floods() -> TestResult
{
    use crate::fragments::{Fragment, Reassembly};
    let mut packets = Reassembly::new(
        wire::FRAGMENT_BYTES,
        wire::PENDING_PACKETS,
        wire::REPLAY_WINDOW,
        Duration::from_millis(wire::PACKET_AGE_MS),
    );
    let now = std::time::Instant::now();
    let insert = |packets: &mut Reassembly, bytes: &[u8], now| -> io::Result<_> {
        let fragment = wire::decode(bytes).map_err(io::Error::other)?;
        packets.insert(
            Fragment {
                packet: fragment.packet,
                length: fragment.length,
                index: fragment.index,
                payload: fragment.payload,
            },
            now,
        )
    };
    for size in [1, 900, 1200, 1280, wire::PACKET_BYTES] {
        let payload = vec![size as u8; size];
        let fragments = wire::encode(
            [7; 32],
            wire::Direction::FirstToSecond,
            size as u64,
            &payload,
        )?;
        let mut received = None;
        for fragment in fragments.iter().rev() {
            if let Some(packet) = insert(&mut packets, fragment, now)? {
                received = Some(packet.bytes);
            }
        }
        assert_eq!(received, Some(payload));
        for fragment in &fragments {
            assert!(insert(&mut packets, fragment, now)?.is_none());
        }
    }
    assert!(wire::encode([7; 32], wire::Direction::FirstToSecond, 1, &[]).is_err());
    assert!(
        wire::encode(
            [7; 32],
            wire::Direction::FirstToSecond,
            1,
            &[1; wire::PACKET_BYTES + 1]
        )
        .is_err()
    );
    let fragments = wire::encode([7; 32], wire::Direction::FirstToSecond, 2000, &[8; 1280])?;
    assert!(insert(&mut packets, &fragments[0], now)?.is_none());
    let late = now + Duration::from_millis(wire::PACKET_AGE_MS);
    assert!(insert(&mut packets, &fragments[1], late)?.is_none());
    assert!(insert(&mut packets, &fragments[0], late)?.is_none());
    for id in 2001..7000 {
        let fragment =
            wire::encode([7; 32], wire::Direction::FirstToSecond, id, &[9; 1280])?.remove(0);
        assert!(insert(&mut packets, &fragment, now)?.is_none());
        assert!(packets.pending_len() <= wire::PENDING_PACKETS);
        assert!(packets.finished_len() <= wire::REPLAY_WINDOW as usize + 1);
    }
    let valid = wire::encode([7; 32], wire::Direction::FirstToSecond, 1, &[4; 1280])?.remove(0);
    for (offset, value) in [(0, 0), (4, 2), (5, 2), (16, 255), (17, 1)] {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        assert!(wire::decode(&malformed).is_err());
    }
    let mut reflected = valid.clone();
    assert!(wire::forward(&mut reflected, [7; 32], wire::Direction::SecondToFirst).is_err());
    wire::forward(&mut reflected, [7; 32], wire::Direction::FirstToSecond)?;
    assert!(wire::forward(&mut reflected, [7; 32], wire::Direction::FirstToSecond).is_err());
    Ok(())
}

#[tokio::test]
async fn physical_relay_refuses_cross_binding_reflection_hop_replay_and_cumulative_overquota()
-> TestResult {
    for fault in 0..4 {
        let mut fixture = Fixture::new()?;
        if fault == 3 {
            fixture.transit.byte_limit = (wire::HEADER + 8 - 1) as u64;
        }
        let setup = Instant::now() + Duration::from_secs(3);
        let (left, mut source, _) = pair(&fixture.relay, &fixture.first, setup).await?;
        let (right, mut destination, _) = pair(&fixture.relay, &fixture.second, setup).await?;
        let (auth, _owner) = fixture.authorization()?;
        let binding = auth.binding_digest();
        let mut relay = RelayForwarder::new(auth, left, right)?;
        let mut packet =
            wire::encode(binding, wire::Direction::FirstToSecond, 1, &[3; 8])?.remove(0);
        match fault {
            0 => packet[20] ^= 1,
            1 => packet[4] = 1,
            2 => packet[5] = 0,
            _ => {}
        }
        source.connection()?.send_datagram(packet.into())?;
        assert!(tokio::time::timeout_at(setup, relay.run()).await?.is_err());
        assert_eq!(relay.forwarded_fragments(), 0);
        assert_eq!(relay.charged_bytes(), 0);
        let cleanup = Instant::now() + Duration::from_secs(5);
        relay.close_and_wait(cleanup).await?;
        source.close_and_wait(cleanup).await?;
        destination.close_and_wait(cleanup).await?;
    }
    Ok(())
}

#[tokio::test]
async fn signed_transit_expiry_is_a_fixed_monotonic_deadline_without_traffic() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.transit.scope.expires_at_ms = fixture.now + 1000;
    let (auth, _owner) = fixture.authorization()?;
    let original = auth.deadline();
    tokio::time::timeout(Duration::from_secs(2), auth.wait_stopped()).await?;
    assert_eq!(
        auth.live().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(auth.deadline(), original);
    Ok(())
}

#[tokio::test]
async fn actual_fragment_replay_does_not_forward_twice_and_both_directions_share_one_quota()
-> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.transit.byte_limit = (2 * (wire::HEADER + 8)) as u64;
    let setup = Instant::now() + Duration::from_secs(3);
    let (left, mut source, _) = pair(&fixture.relay, &fixture.first, setup).await?;
    let (right, mut destination, _) = pair(&fixture.relay, &fixture.second, setup).await?;
    let (auth, _owner) = fixture.authorization()?;
    let binding = auth.binding_digest();
    let mut relay = RelayForwarder::new(auth, left, right)?;
    let exchange = async {
        let first = wire::encode(binding, wire::Direction::FirstToSecond, 1, &[7; 8])?.remove(0);
        source.connection()?.send_datagram(first.clone().into())?;
        let received =
            tokio::time::timeout_at(setup, destination.connection()?.read_datagram()).await??;
        assert_eq!(wire::decode(&received)?.payload, &[7; 8]);
        source.connection()?.send_datagram(first.into())?;
        let reverse = wire::encode(binding, wire::Direction::SecondToFirst, 1, &[8; 8])?.remove(0);
        destination.connection()?.send_datagram(reverse.into())?;
        let received =
            tokio::time::timeout_at(setup, source.connection()?.read_datagram()).await??;
        assert_eq!(wire::decode(&received)?.payload, &[8; 8]);
        let excess = wire::encode(binding, wire::Direction::FirstToSecond, 2, &[9; 8])?.remove(0);
        source.connection()?.send_datagram(excess.into())?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (forwarded, exchanged) =
        tokio::join!(tokio::time::timeout_at(setup, relay.run()), exchange);
    exchanged?;
    assert!(forwarded?.is_err());
    assert_eq!(relay.forwarded_fragments(), 2);
    assert_eq!(relay.charged_bytes(), fixture.transit.byte_limit);
    let cleanup = Instant::now() + Duration::from_secs(5);
    relay.close_and_wait(cleanup).await?;
    source.close_and_wait(cleanup).await?;
    destination.close_and_wait(cleanup).await?;
    Ok(())
}

#[tokio::test]
async fn wrong_relay_key_cannot_create_an_authenticated_adjacency() -> TestResult {
    let fixture = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let listener = AdjacencyEndpoint::bind(
        "127.0.0.1:0".parse()?,
        &fixture.relay,
        PeerId(fixture.first.fingerprint()),
    )?;
    let address = listener.local_addr()?;
    let wrong = InstallationIdentity::generate();
    let connector = AdjacencyEndpoint::bind(
        "127.0.0.1:0".parse()?,
        &fixture.first,
        PeerId(wrong.fingerprint()),
    )?;
    let (accepted, connected) = tokio::join!(
        listener.accept(deadline),
        connector.connect(address, deadline)
    );
    assert!(accepted.is_err());
    assert!(connected.is_err());
    Ok(())
}

#[tokio::test]
async fn borrowed_routed_establishment_can_be_cancelled_without_losing_original_socket_receipts()
-> TestResult {
    let fixture = Fixture::new()?;
    let setup = Instant::now() + Duration::from_secs(3);
    let (mut relay, adjacency, addresses) = pair(&fixture.relay, &fixture.first, setup).await?;
    let (authorization, _revocation) = fixture.authorization()?;
    let mut owner = RoutedEstablishment::new(authorization, adjacency);
    {
        let establishment = owner.establish(&fixture.first, setup);
        tokio::pin!(establishment);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                establishment.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        // Cancel only the borrowed operation. The externally held owner keeps
        // the virtual receiver and the unique physical adjacency receipt.
    }
    assert!(owner.endpoint.is_some());
    assert!(owner.receiver.is_some());
    assert!(owner.adjacency.is_some());
    assert!(owner.take_transport().is_err());
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (released, relay_released) =
        tokio::join!(owner.close_and_wait(cleanup), relay.close_and_wait(cleanup),);
    released?;
    relay_released?;
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    assert!(
        owner.establish(&fixture.first, cleanup).await.is_err(),
        "one owner cannot start a replacement attempt after cancellation and cleanup"
    );
    Ok(())
}

#[tokio::test]
async fn explicit_routed_establishment_failures_retain_the_original_adjacency_for_cleanup()
-> TestResult {
    for wrong_identity in [false, true] {
        let fixture = Fixture::new()?;
        let setup = Instant::now() + Duration::from_secs(3);
        let (mut relay, adjacency, addresses) = pair(&fixture.relay, &fixture.first, setup).await?;
        let (authorization, _revocation) = fixture.authorization()?;
        let mut owner = RoutedEstablishment::new(authorization, adjacency);
        let identity = InstallationIdentity::generate();
        let deadline = if wrong_identity {
            setup
        } else {
            Instant::now() + Duration::from_millis(25)
        };
        let result = owner
            .establish(
                if wrong_identity {
                    &identity
                } else {
                    &fixture.first
                },
                deadline,
            )
            .await;
        let error = result
            .err()
            .ok_or("establishment unexpectedly succeeded without an inner peer")?;
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(if wrong_identity {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::TimedOut
            })
        );
        assert!(owner.adjacency.is_some());
        assert_eq!(
            owner.endpoint.is_some(),
            !wrong_identity,
            "the deadline case must have actually entered inner establishment"
        );
        assert!(owner.take_transport().is_err());
        let cleanup = Instant::now() + Duration::from_secs(5);
        let (released, relay_released) =
            tokio::join!(owner.close_and_wait(cleanup), relay.close_and_wait(cleanup),);
        released?;
        relay_released?;
        for address in addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_routed_close_preserves_its_first_deadline_while_a_physical_holder_remains()
-> TestResult {
    let fixture = Fixture::new()?;
    let setup = Instant::now() + Duration::from_secs(3);
    let (mut relay, adjacency, addresses) = pair(&fixture.relay, &fixture.first, setup).await?;
    // An external Quinn holder keeps the original physical endpoint alive;
    // closing the connection does not itself certify final socket release.
    let retained = adjacency.connection()?.clone();
    let (authorization, _revocation) = fixture.authorization()?;
    let mut owner = RoutedEstablishment::new(authorization, adjacency);
    {
        let establishment = owner.establish(&fixture.first, setup);
        tokio::pin!(establishment);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                establishment.as_mut().poll(cx).is_pending()
            ))
            .await
        );
    }
    let first_deadline = Instant::now() + Duration::from_millis(100);
    {
        let closing = owner.close_and_wait(first_deadline);
        tokio::pin!(closing);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                closing.as_mut().poll(cx).is_pending()
            ))
            .await
        );
    }
    assert_eq!(owner.close_deadline, Some(first_deadline));
    assert_eq!(
        std::net::UdpSocket::bind(addresses[1])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    relay
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    let replacement_budget = Instant::now() + Duration::from_secs(5);
    let rejected = owner.close_and_wait(replacement_budget).await;
    assert_eq!(
        rejected.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(owner.close_deadline, Some(first_deadline));
    assert!(
        Instant::now() < replacement_budget,
        "a retry must not consume a new five-second budget"
    );
    assert_eq!(
        std::net::UdpSocket::bind(addresses[1])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    drop(retained);
    drop(owner);
    // The earlier receipt failed. Confirm eventual Drop teardown separately
    // through actual rebinding, without claiming that the close wait succeeded.
    let released = Instant::now() + Duration::from_secs(2);
    tokio::time::timeout_at(released, async {
        loop {
            match std::net::UdpSocket::bind(addresses[1]) {
                Ok(socket) => {
                    drop(socket);
                    break Ok::<(), io::Error>(());
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(5)).await
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await??;
    drop(std::net::UdpSocket::bind(addresses[0])?);
    Ok(())
}
