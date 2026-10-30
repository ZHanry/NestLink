//! Actual QUIC carrier qualification; no management reservation is fabricated
//! by these component fixtures and no target acceptance is claimed.
use super::*;
use nestlink_identity::network::remote_chain_binding;
use nestlink_protocol::network_datagram_v2 as v2;

struct ChainFixture {
    base: Fixture,
    other_relay: InstallationIdentity,
    path: VerifiedNetworkPath,
    transits: [TransitClaims; 2],
}
impl ChainFixture {
    fn new() -> TestResult<Self> {
        let base = Fixture::new()?;
        let other_relay = InstallationIdentity::generate();
        let relays = [
            PeerId(base.relay.fingerprint()),
            PeerId(other_relay.fingerprint()),
        ];
        let mut claims = base.path.claims().clone();
        claims.policy.relays = relays.to_vec();
        claims.policy.relays.sort();
        claims.policy.max_hops = 2;
        let path = VerifiedNetworkPath::from_grants(
            &base.context(),
            base.memberships.clone(),
            base.connectivity.clone(),
            base.signed(GrantClaims::Path(claims))?,
            base.permit.digest(),
        )?;
        let mut first = base.transit.clone();
        first.transport_group = path.transport_group_id();
        first.next = relays[1];
        first.remaining_hops = 2;
        let mut second = first.clone();
        second.scope.grant_id = "30000000-0000-4000-8000-000000000009".into();
        second.relay = relays[1];
        second.previous = relays[0];
        second.next = path.peers().second;
        second.remaining_hops = 1;
        Ok(Self {
            base,
            other_relay,
            path,
            transits: [first, second],
        })
    }
    fn grants(&self) -> TestResult<[VerifiedNetworkGrant; 2]> {
        Ok([
            self.base
                .signed(GrantClaims::Transit(self.transits[0].clone()))?,
            self.base
                .signed(GrantClaims::Transit(self.transits[1].clone()))?,
        ])
    }
    fn authorization(&self) -> TestResult<(RouteAuthorization, RouteRevocation)> {
        Ok(RouteAuthorization::remote_chain(
            &self.base.context(),
            &self.path,
            &self.base.connectivity,
            &self.grants()?,
            &self.base.permit,
        )?)
    }
}

#[test]
fn full_chain_binds_both_hops_order_original_business_and_fixed_neighbors() -> TestResult {
    let f = ChainFixture::new()?;
    let grants = f.grants()?;
    let bind = |grants: &[VerifiedNetworkGrant]| {
        remote_chain_binding(
            &f.base.context(),
            &f.path,
            &f.base.connectivity,
            grants,
            &f.base.permit,
        )
    };
    let verified = bind(&grants)?;
    assert_eq!(verified.relays, [f.transits[0].relay, f.transits[1].relay]);
    for direction in [v2::Direction::FirstToSecond, v2::Direction::SecondToFirst] {
        let expected = if direction == v2::Direction::FirstToSecond {
            [2, 1]
        } else {
            [1, 2]
        };
        for (relay, hops) in verified.relays.iter().zip(expected) {
            assert_eq!(verified.remaining_hops(*relay, direction), Some(hops));
        }
    }
    assert_eq!(
        verified.adjacency(verified.relays[0]),
        Some((verified.peers.first, verified.relays[1]))
    );
    assert_eq!(
        verified.adjacency(verified.relays[1]),
        Some((verified.relays[0], verified.peers.second))
    );
    assert!(verified.adjacency(verified.peers.first).is_none());
    for invalid in [
        vec![],
        vec![grants[0].clone()],
        vec![grants[1].clone(), grants[0].clone()],
        vec![grants[0].clone(); 3],
    ] {
        assert!(bind(&invalid).is_err());
    }
    for change in 0..10 {
        let mut claims = f.transits.clone();
        match change {
            0 => claims[0].previous = f.path.peers().second,
            1 => claims[0].next = f.path.peers().second,
            2 => claims[0].remaining_hops = 1,
            3 => claims[1].previous = f.path.peers().first,
            4 => claims[1].next = f.path.peers().first,
            5 => claims[1].remaining_hops = 2,
            6 => claims[1].route_id = "60000000-0000-4000-8000-000000000099".into(),
            7 => claims[1].scope.grant_id = claims[0].scope.grant_id.clone(),
            8 => claims[1].transport_group = f.base.path.transport_group_id(),
            _ => claims[1].scope.expires_at_ms += 1,
        }
        let forged = [
            f.base.signed(GrantClaims::Transit(claims[0].clone()))?,
            f.base.signed(GrantClaims::Transit(claims[1].clone()))?,
        ];
        assert!(bind(&forged).is_err(), "accepted crossed hop {change}");
    }
    assert!(
        RouteAuthorization::remote(
            &f.base.context(),
            &f.path,
            &f.base.connectivity,
            &grants[0],
            &f.base.permit,
        )
        .is_err()
    );
    assert!(
        remote_chain_binding(
            &f.base.context(),
            &f.base.path,
            &f.base.connectivity,
            &grants,
            &f.base.permit,
        )
        .is_err()
    );
    let mut changed = f.transits[1].clone();
    changed.byte_limit -= 1;
    let updated = [
        grants[0].clone(),
        f.base.signed(GrantClaims::Transit(changed.clone()))?,
    ];
    let changed = bind(&updated)?;
    assert_ne!(changed.digest, verified.digest);
    assert_eq!(changed.byte_limit + 1, verified.byte_limit);
    let revoked = BTreeSet::from([f.transits[1].scope.grant_id.clone()]);
    let mut current = f.base.context();
    current.revoked_grant_ids = &revoked;
    assert!(
        remote_chain_binding(
            &current,
            &f.path,
            &f.base.connectivity,
            &grants,
            &f.base.permit
        )
        .is_err()
    );
    Ok(())
}

async fn chain_pair(
    local: &InstallationIdentity,
    remote: &InstallationIdentity,
    deadline: Instant,
) -> TestResult<(Adjacency, Adjacency, [SocketAddr; 2])> {
    let listener =
        AdjacencyEndpoint::bind_chain("127.0.0.1:0".parse()?, local, PeerId(remote.fingerprint()))?;
    let connector =
        AdjacencyEndpoint::bind_chain("127.0.0.1:0".parse()?, remote, PeerId(local.fingerprint()))?;
    let addresses = [listener.local_addr()?, connector.local_addr()?];
    let (accepted, connected) = tokio::join!(
        listener.accept(deadline),
        connector.connect(addresses[0], deadline)
    );
    Ok((accepted?, connected?, addresses))
}

fn run_relay(
    mut relay: RelayForwarder,
    marker: &'static [u8],
) -> Abort<io::Result<(u64, u64, bool)>> {
    Abort(tokio::spawn(async move {
        let result = relay.run().await;
        let initials = relay.initial_packets;
        let forwarded = relay.forwarded_fragments();
        let plaintext = relay
            .captured
            .iter()
            .any(|bytes| bytes.windows(marker.len()).any(|part| part == marker));
        relay
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        assert!(result.is_err());
        Ok((initials, forwarded, plaintext))
    }))
}

#[tokio::test]
async fn actual_four_node_chain_preserves_inner_quic_ipv6_streams_and_physical_release()
-> TestResult {
    let f = ChainFixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (left_in, left, addresses_a) = chain_pair(&f.base.relay, &f.base.first, deadline).await?;
    let (left_out, right_in, addresses_b) =
        chain_pair(&f.base.relay, &f.other_relay, deadline).await?;
    let (right_out, right, addresses_c) =
        chain_pair(&f.other_relay, &f.base.second, deadline).await?;
    let (left_auth, left_stop) = f.authorization()?;
    let (right_auth, right_stop) = f.authorization()?;
    let marker = b"four node end to end private payload";
    let mut left_task = run_relay(RelayForwarder::new(left_auth, left_in, left_out)?, marker);
    let mut right_task = run_relay(
        RelayForwarder::new(right_auth, right_in, right_out)?,
        marker,
    );
    let (first_auth, first_stop) = f.authorization()?;
    let (second_auth, second_stop) = f.authorization()?;
    let (first, second) = tokio::join!(
        establish(first_auth, left, &f.base.first, deadline),
        establish(second_auth, right, &f.base.second, deadline),
    );
    let mut first = first?;
    let mut second = second?;
    let mut packet = vec![0; 1280];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&1240u16.to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8] = 0xfd;
    packet[23] = 1;
    packet[24] = 0xfd;
    packet[39] = 2;
    packet[40..40 + marker.len()].copy_from_slice(marker);
    first.connection()?.send_datagram(packet.clone().into())?;
    assert_eq!(
        tokio::time::timeout_at(deadline, second.connection()?.read_datagram())
            .await??
            .as_ref(),
        packet
    );
    second
        .connection()?
        .send_datagram(marker.as_slice().into())?;
    assert_eq!(
        tokio::time::timeout_at(deadline, first.connection()?.read_datagram())
            .await??
            .as_ref(),
        marker
    );
    // These raw inner streams qualify transport only. Product callers must
    // still perform SessionPermit mutual proof before opening business data.
    let stream = async {
        let (mut write, mut read) = first.connection()?.open_bi().await?;
        write.write_all(marker).await?;
        write.finish()?;
        assert_eq!(read.read_to_end(1024).await?.as_slice(), marker);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let receive = async {
        let (mut write, mut read) = second.connection()?.accept_bi().await?;
        let bytes = read.read_to_end(1024).await?;
        assert_eq!(bytes.as_slice(), marker);
        write.write_all(&bytes).await?;
        write.finish()?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (a, b) = tokio::time::timeout_at(deadline, async { tokio::join!(stream, receive) }).await?;
    a?;
    b?;
    // One revoked relay closes its two fixed neighbors. That actual adjacency
    // loss propagates through the other relay to both original inner owners.
    left_stop.revoke();
    tokio::time::timeout(Duration::from_secs(2), first.connection()?.closed()).await?;
    tokio::time::timeout(Duration::from_secs(2), second.connection()?.closed()).await?;
    first_stop.revoke();
    second_stop.revoke();
    right_stop.revoke();
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (a, b) = tokio::join!(
        first.close_and_wait(cleanup),
        second.close_and_wait(cleanup)
    );
    a?;
    b?;
    for task in [&mut left_task, &mut right_task] {
        let (initials, forwarded, plaintext) =
            tokio::time::timeout_at(cleanup, &mut task.0).await???;
        assert!(initials > 0);
        assert!(forwarded >= 6);
        assert!(!plaintext);
    }
    for address in addresses_a
        .into_iter()
        .chain(addresses_b)
        .chain(addresses_c)
    {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(())
}

#[tokio::test]
async fn chain_authority_cannot_reinterpret_a_legacy_alpn_adjacency() -> TestResult {
    let f = ChainFixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut relay, endpoint, addresses) = pair(&f.base.relay, &f.base.first, deadline).await?;
    let (authorization, _stop) = f.authorization()?;
    let mut pending = RoutedEstablishment::new(authorization, endpoint);
    assert!(pending.establish(&f.base.first, deadline).await.is_err());
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (a, b) = tokio::join!(
        pending.close_and_wait(cleanup),
        relay.close_and_wait(cleanup)
    );
    a?;
    b?;
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(())
}

#[tokio::test]
async fn second_relay_refuses_cross_binding_reflection_and_wrong_authenticated_position()
-> TestResult {
    for fault in 0..4 {
        let mut f = ChainFixture::new()?;
        if fault == 3 {
            f.transits[1].byte_limit = 1;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let (left, mut peer_a, _) = chain_pair(&f.other_relay, &f.base.relay, deadline).await?;
        let (right, mut peer_b, _) = chain_pair(&f.other_relay, &f.base.second, deadline).await?;
        let (auth, _stop) = f.authorization()?;
        let mut bytes = v2::encode(
            auth.binding_digest(),
            v2::Direction::FirstToSecond,
            2,
            1,
            &[9],
        )?[0]
            .clone();
        bytes[5] = 1;
        match fault {
            0 => bytes[20] ^= 1,
            1 => bytes[4] = 1,
            2 => bytes[5] = 2,
            _ => {}
        }
        let mut relay = RelayForwarder::new(auth, left, right)?;
        peer_a.connection()?.send_datagram(bytes.into())?;
        assert!(
            tokio::time::timeout_at(deadline, relay.run())
                .await?
                .is_err()
        );
        assert_eq!(relay.forwarded_fragments(), 0);
        let cleanup = Instant::now() + Duration::from_secs(5);
        relay.close_and_wait(cleanup).await?;
        peer_a.close_and_wait(cleanup).await?;
        peer_b.close_and_wait(cleanup).await?;
    }
    Ok(())
}
