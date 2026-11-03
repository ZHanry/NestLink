//! Real signed migration owners retain their original receipts on cancellation.
//! These component regressions do not claim OS/network-namespace acceptance.
use super::*;
use crate::migration::{self, CommittedMigration};
use nestlink_identity::digest;
use nestlink_protocol::network_migration::{Binding, packet::REMOTE_ALPN};
use quinn::AsyncUdpSocket;
use std::{future::poll_fn, task::Poll};

struct MigrationFixture {
    base: Fixture,
    other_relay: InstallationIdentity,
    path: VerifiedNetworkPath,
    transits: [TransitClaims; 2],
}
impl MigrationFixture {
    fn new() -> TestResult<Self> {
        let base = Fixture::new()?;
        let other_relay = InstallationIdentity::generate();
        let mut claims = base.path.claims().clone();
        claims.policy.relays.push(PeerId(other_relay.fingerprint()));
        claims.policy.relays.sort();
        let path = VerifiedNetworkPath::from_grants(
            &base.context(),
            base.memberships.clone(),
            base.connectivity.clone(),
            base.signed(GrantClaims::Path(claims))?,
            base.permit.digest(),
        )?;
        let mut first = base.transit.clone();
        first.transport_group = path.transport_group_id();
        let mut second = first.clone();
        second.scope.grant_id = "30000000-0000-4000-8000-000000000009".into();
        second.route_id = "60000000-0000-4000-8000-000000000009".into();
        second.relay = PeerId(other_relay.fingerprint());
        Ok(Self {
            base,
            other_relay,
            path,
            transits: [first, second],
        })
    }
    fn authorization(&self, index: usize) -> TestResult<(RouteAuthorization, RouteRevocation)> {
        Ok(RouteAuthorization::remote(
            &self.base.context(),
            &self.path,
            &self.base.connectivity,
            &self
                .base
                .signed(GrantClaims::Transit(self.transits[index].clone()))?,
            &self.base.permit,
        )?)
    }
}

struct RoutePair {
    first: Option<RoutedTransport>,
    second: Option<RoutedTransport>,
    relay: Abort<(RelayForwarder, bool)>,
    revocations: [RouteRevocation; 3],
    addresses: [SocketAddr; 4],
}
impl RoutePair {
    async fn new(fixture: &MigrationFixture, index: usize, epoch: u64) -> TestResult<Self> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let relay_identity = if index == 0 {
            &fixture.base.relay
        } else {
            &fixture.other_relay
        };
        let (relay_first, first, addresses_a) =
            pair(relay_identity, &fixture.base.first, deadline).await?;
        let (relay_second, second, addresses_b) =
            pair(relay_identity, &fixture.base.second, deadline).await?;
        let (relay_authority, relay_revocation) = fixture.authorization(index)?;
        let mut forwarder = RelayForwarder::new(relay_authority, relay_first, relay_second)?;
        let relay = Abort(tokio::spawn(async move {
            let failed = forwarder.run().await.is_err();
            (forwarder, failed)
        }));
        let (first_authority, first_revocation) = fixture.authorization(index)?;
        let (second_authority, second_revocation) = fixture.authorization(index)?;
        let mut first = RoutedEstablishment::migratable(first_authority, first, epoch)?;
        let mut second = RoutedEstablishment::migratable(second_authority, second, epoch)?;
        tokio::try_join!(
            first.establish(&fixture.base.first, deadline),
            second.establish(&fixture.base.second, deadline),
        )?;
        Ok(Self {
            first: Some(first.take_transport()?),
            second: Some(second.take_transport()?),
            relay,
            revocations: [relay_revocation, first_revocation, second_revocation],
            addresses: [
                addresses_a[0],
                addresses_a[1],
                addresses_b[0],
                addresses_b[1],
            ],
        })
    }
    async fn close(&mut self, deadline: Instant) -> TestResult {
        for revocation in &self.revocations {
            revocation.revoke();
        }
        if let Some(first) = &mut self.first {
            first.close_and_wait(deadline).await?;
        }
        if let Some(second) = &mut self.second {
            second.close_and_wait(deadline).await?;
        }
        let (mut relay, failed) = tokio::time::timeout_at(deadline, &mut self.relay.0).await??;
        assert!(failed);
        relay.close_and_wait(deadline).await?;
        Ok(())
    }
}

async fn receipts(
    fixture: &MigrationFixture,
    original: &RoutePair,
    candidate: &RoutePair,
) -> TestResult<[CommittedMigration; 2]> {
    let first = original.first.as_ref().ok_or("original first")?;
    let first_control = candidate.first.as_ref().ok_or("candidate first")?;
    let second_control = candidate.second.as_ref().ok_or("candidate second")?;
    let binding = Binding {
        deployment: digest(DEPLOYMENT.as_bytes()),
        space: digest(SPACE.as_bytes()),
        session: digest(fixture.base.permit.claims().session_id.as_bytes()),
        permit: fixture.base.permit.digest(),
        path_grant: digest(&GrantClaims::Path(fixture.path.claims().clone()).signing_message()?),
        transport_group: fixture.path.transport_group_id(),
        peers: fixture.path.peers(),
        original_route: first
            .raw
            .as_ref()
            .ok_or("original raw")?
            .authorization()
            .binding_digest(),
        candidate_route: first_control
            .raw
            .as_ref()
            .ok_or("candidate raw")?
            .authorization()
            .binding_digest(),
        original_connection: migration::connection_binding(first.connection()?)?,
        control_connection: migration::connection_binding(first_control.connection()?)?,
        business_generation: fixture.base.permit.claims().connection_generation,
        previous_path_epoch: 1,
        next_path_epoch: 2,
        expires_at_unix_ms: fixture.path.claims().scope.expires_at_ms,
    };
    let (_keep_cancel, cancel) = tokio::sync::watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(2);
    let first_key = fixture.base.first.public_key();
    let second_key = fixture.base.second.public_key();
    let (first, second) = tokio::try_join!(
        migration::exchange(
            first_control.connection()?,
            REMOTE_ALPN,
            binding.clone(),
            &fixture.base.first,
            &second_key,
            cancel.clone(),
            deadline,
            || Ok(())
        ),
        migration::exchange(
            second_control.connection()?,
            REMOTE_ALPN,
            binding,
            &fixture.base.second,
            &first_key,
            cancel,
            deadline,
            || Ok(())
        ),
    )?;
    Ok([first, second])
}

fn in_use(address: SocketAddr) {
    assert_eq!(
        std::net::UdpSocket::bind(address)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
}
fn rebound(addresses: impl IntoIterator<Item = SocketAddr>) -> io::Result<()> {
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(())
}

#[tokio::test]
async fn retained_candidate_connection_or_endpoint_keeps_cancelled_detach_owned_until_real_cleanup()
-> TestResult {
    for retain_endpoint in [false, true] {
        let fixture = MigrationFixture::new()?;
        let mut original = RoutePair::new(&fixture, 0, 1).await?;
        let mut candidate = RoutePair::new(&fixture, 1, 0).await?;
        let [receipt, _peer_receipt] = receipts(&fixture, &original, &candidate).await?;
        let next = candidate.first.take().ok_or("candidate first")?;
        let retained_connection = if retain_endpoint {
            None
        } else {
            Some(next.connection()?.clone())
        };
        let retained_endpoint = if retain_endpoint {
            next.endpoint.clone()
        } else {
            None
        };
        let first = original.first.as_mut().ok_or("original first")?;
        first.arm_prepared_migration(&next)?;
        let stable_id = first.connection()?.stable_id();
        let binding = migration::connection_binding(first.connection()?)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        {
            let moving = first.migrate(next, &receipt, deadline);
            tokio::pin!(moving);
            assert!(poll_fn(|cx| Poll::Ready(moving.as_mut().poll(cx).is_pending())).await);
        }
        assert_eq!(first.path_epoch(), 1);
        assert_eq!(first.connection()?.stable_id(), stable_id);
        assert_eq!(migration::connection_binding(first.connection()?)?, binding);
        assert!(first.draining.is_none());
        let pending = first
            .pending_migration
            .as_ref()
            .ok_or("lost candidate owner")?;
        assert!(pending.connection.is_none());
        assert!(pending.endpoint.is_none());
        assert!(pending.released.is_some());
        assert!(pending.raw.is_some());
        in_use(candidate.addresses[1]);
        // Dropping the borrowed migration future did not acknowledge detach
        // or orphan its real endpoint/poller/physical cleanup receipts.
        drop((retained_connection, retained_endpoint));
        let cleanup = Instant::now() + Duration::from_secs(5);
        original.close(cleanup).await?;
        candidate.close(cleanup).await?;
        rebound(original.addresses.into_iter().chain(candidate.addresses))?;
    }
    Ok(())
}

async fn cancel_at_actual_drain(
    original: &mut RoutedTransport,
    candidate: RoutedTransport,
    receipt: &CommittedMigration,
) -> TestResult {
    let old_gate = original.gate.as_ref().ok_or("old gate")?.clone();
    let old_failure = old_gate.subscribe_failure()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let moving = original.migrate(candidate, receipt, deadline);
    tokio::pin!(moving);
    poll_fn(|cx| {
        if let Poll::Ready(result) = moving.as_mut().poll(cx) {
            return Poll::Ready(Err(io::Error::other(format!(
                "migration completed before drain cancellation: {result:?}"
            ))));
        }
        match old_gate.subscribe_failure() {
            // This exact production watch is isolated after successful
            // rebind and before its original absolute drain sleep. Checking
            // it in the same poll avoids a wall-clock scheduling guess.
            Ok(current) if !current.same_channel(&old_failure) => Poll::Ready(Ok(())),
            Ok(_) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn cancelling_after_real_rebind_retains_drain_and_current_revocation_still_bypasses_it()
-> TestResult {
    for revoke_during_drain in [false, true] {
        let fixture = MigrationFixture::new()?;
        let mut original = RoutePair::new(&fixture, 0, 1).await?;
        let mut candidate = RoutePair::new(&fixture, 1, 0).await?;
        let [first_receipt, second_receipt] = receipts(&fixture, &original, &candidate).await?;
        let first_candidate = candidate.first.take().ok_or("candidate first")?;
        let second_candidate = candidate.second.take().ok_or("candidate second")?;
        let first = original.first.as_mut().ok_or("original first")?;
        let second = original.second.as_mut().ok_or("original second")?;
        first.arm_prepared_migration(&first_candidate)?;
        second.arm_prepared_migration(&second_candidate)?;
        let stable_ids = [
            first.connection()?.stable_id(),
            second.connection()?.stable_id(),
        ];
        tokio::try_join!(
            cancel_at_actual_drain(first, first_candidate, &first_receipt),
            cancel_at_actual_drain(second, second_candidate, &second_receipt),
        )?;
        for (transport, stable_id) in [(&*first, stable_ids[0]), (&*second, stable_ids[1])] {
            assert_eq!(transport.path_epoch(), 2);
            assert_eq!(transport.connection()?.stable_id(), stable_id);
            assert!(transport.pending_migration.is_none());
            let old = transport.draining.as_ref().ok_or("lost drain owner")?;
            assert!(old.released.is_some());
            assert!(old.raw.is_some());
            assert!(transport.released.is_some());
        }
        if revoke_during_drain {
            candidate.revocations[1].revoke();
            let gate = first.gate.as_ref().ok_or("current gate")?;
            let raw = first.raw.as_ref().ok_or("current raw")?;
            let result = gate.try_send(&quinn::udp::Transmit {
                destination: raw.peer_addr(),
                ecn: None,
                contents: b"must not forward",
                segment_size: None,
                src_ip: None,
            });
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(
                *first.subscribe_failure().borrow(),
                Some(io::ErrorKind::PermissionDenied)
            );
        }
        let cleanup = Instant::now() + Duration::from_secs(5);
        original.close(cleanup).await?;
        candidate.close(cleanup).await?;
        rebound(original.addresses.into_iter().chain(candidate.addresses))?;
    }
    Ok(())
}

#[tokio::test]
async fn successful_safe_recovery_joins_both_control_drivers_before_revoking_their_raw_carriers()
-> TestResult {
    let fixture = MigrationFixture::new()?;
    let mut original = RoutePair::new(&fixture, 0, 1).await?;
    let mut candidate = RoutePair::new(&fixture, 1, 0).await?;
    let [first_receipt, second_receipt] = receipts(&fixture, &original, &candidate).await?;
    let first = candidate.first.as_mut().ok_or("candidate first")?;
    let second = candidate.second.as_mut().ok_or("candidate second")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    tokio::try_join!(
        first.finish_control_for_recovery(&first_receipt, deadline),
        second.finish_control_for_recovery(&second_receipt, deadline),
    )?;
    for transport in [&*first, &*second] {
        assert!(transport.connection.is_none());
        assert!(transport.endpoint.is_none());
        assert!(transport.released.is_none());
        assert!(transport.packet_hub.is_some());
        assert!(transport.raw.as_ref().ok_or("live raw carrier")?.authorization().check_live().is_ok());
        assert!(transport.subscribe_failure().borrow().is_none());
    }
    // Control driver release did not stand in for actual physical raw/outer
    // release. Those owners remain live until the subsequent complete stop.
    in_use(candidate.addresses[1]);
    in_use(candidate.addresses[3]);
    let cleanup = Instant::now() + Duration::from_secs(5);
    original.close(cleanup).await?;
    candidate.close(cleanup).await?;
    rebound(original.addresses.into_iter().chain(candidate.addresses))?;
    Ok(())
}
