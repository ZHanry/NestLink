//! Actual failed carriers and retained Quinn handles qualify release receipts.
use super::*;

#[tokio::test]
async fn only_the_explicit_retired_close_is_recoverable_and_unknown_application_closes_stay_denied() -> TestResult {
    for code in [RETIRED_CLOSE_CODE, 7] {
        let fixture = Fixture::new()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut relay, mut adjacency, addresses) = pair(&fixture.relay, &fixture.first, deadline).await?;
        let (authorization, _owner) = fixture.authorization()?;
        let (socket, receiver) = socket::RoutedSocket::new(authorization, adjacency.connection()?.clone(), true)?;
        let failure = socket.subscribe_failure();
        relay.connection()?.close(code.into(), b"actual authenticated node stop");
        assert_eq!(observed_failure(failure, deadline).await?, if code == RETIRED_CLOSE_CODE {
            io::ErrorKind::ConnectionAborted
        } else { io::ErrorKind::PermissionDenied });
        receiver.close_and_wait(deadline).await?;
        drop(socket);
        let (local, remote) = tokio::join!(adjacency.close_and_wait(deadline), relay.close_and_wait(deadline));
        local?;
        remote?;
        for address in addresses { drop(std::net::UdpSocket::bind(address)?); }
    }
    Ok(())
}

struct Connected {
    first: RoutedTransport,
    second: RoutedTransport,
    relay: Abort<(RelayForwarder, bool)>,
    addresses: [SocketAddr; 4],
    revocations: [RouteRevocation; 3],
}

impl Connected {
    async fn new(fixture: &Fixture) -> TestResult<Self> {
        let setup = Instant::now() + Duration::from_secs(3);
        let (relay_first, first, addresses_a) = pair(&fixture.relay, &fixture.first, setup).await?;
        let (relay_second, second, addresses_b) =
            pair(&fixture.relay, &fixture.second, setup).await?;
        let (relay_authorization, relay_revocation) = fixture.authorization()?;
        let mut forwarder = RelayForwarder::new(relay_authorization, relay_first, relay_second)?;
        let relay = Abort(tokio::spawn(async move {
            let failed = forwarder.run().await.is_err();
            (forwarder, failed)
        }));
        let (first_authorization, first_revocation) = fixture.authorization()?;
        let (second_authorization, second_revocation) = fixture.authorization()?;
        let (first, second) = tokio::join!(
            establish(first_authorization, first, &fixture.first, setup),
            establish(second_authorization, second, &fixture.second, setup),
        );
        let first = first?;
        let second = second?;
        first
            .connection()?
            .send_datagram(b"before carrier failure".as_slice().into())?;
        assert_eq!(
            tokio::time::timeout_at(setup, second.connection()?.read_datagram())
                .await??
                .as_ref(),
            b"before carrier failure",
        );
        Ok(Self {
            first,
            second,
            relay,
            addresses: [
                addresses_a[0],
                addresses_a[1],
                addresses_b[0],
                addresses_b[1],
            ],
            revocations: [relay_revocation, first_revocation, second_revocation],
        })
    }

    async fn close_relay(&mut self, deadline: Instant) -> TestResult {
        let (mut relay, failed) = tokio::time::timeout_at(deadline, &mut self.relay.0).await??;
        assert!(failed);
        relay.close_and_wait(deadline).await?;
        Ok(())
    }
}

async fn observed_failure(
    mut failure: tokio::sync::watch::Receiver<Option<io::ErrorKind>>,
    deadline: Instant,
) -> TestResult<io::ErrorKind> {
    let kind = tokio::time::timeout_at(deadline, async {
        loop {
            if let Some(kind) = *failure.borrow_and_update() {
                return Ok::<_, io::Error>(kind);
            }
            failure.changed().await.map_err(io::Error::other)?;
        }
    })
    .await??;
    Ok(kind)
}

#[tokio::test]
async fn abrupt_carrier_close_and_route_revocation_release_the_original_inner_and_physical_owners()
-> TestResult {
    for revoke in [false, true] {
        let fixture = Fixture::new()?;
        let mut connected = Connected::new(&fixture).await?;
        let cleanup = Instant::now() + Duration::from_secs(5);
        let failure = connected.first.subscribe_failure();
        // Enter Quinn's real idle wait before the failing abstract receive.
        // The retained Endpoint is released before asking our owner to close.
        {
            let endpoint = connected
                .first
                .endpoint
                .as_ref()
                .ok_or("inner endpoint")?
                .clone();
            let idle = endpoint.wait_idle();
            tokio::pin!(idle);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    idle.as_mut().poll(cx).is_pending(),
                ))
                .await
            );
            if revoke {
                connected.revocations[1].revoke();
            } else {
                // End the actual authenticated underlay without first closing
                // the inner endpoint or calling RoutedTransport::request_close.
                connected
                    .first
                    .adjacency
                    .connection()?
                    .close(7u32.into(), b"abrupt original underlay shutdown");
            }
            assert_eq!(
                observed_failure(failure, cleanup).await?,
                io::ErrorKind::PermissionDenied
            );
            assert!(
                tokio::time::timeout_at(cleanup, endpoint.accept())
                    .await?
                    .is_none()
            );
            // Locked Quinn 0.11.12 can leave an already-registered idle waiter
            // pending after its receive driver fails. That waiter is not used
            // as proof of socket release by the production owner.
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    idle.as_mut().poll(cx).is_pending(),
                ))
                .await
            );
        }
        let (first, second) = tokio::join!(
            connected.first.close_and_wait(cleanup),
            connected.second.close_and_wait(cleanup),
        );
        first?;
        second?;
        assert!(connected.first.released.is_none());
        assert!(connected.second.released.is_none());
        connected.close_relay(cleanup).await?;
        for address in connected.addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn external_inner_connection_and_endpoint_clones_keep_cancelled_cleanup_pending_without_a_new_budget()
-> TestResult {
    for retain_endpoint in [false, true] {
        let fixture = Fixture::new()?;
        let mut connected = Connected::new(&fixture).await?;
        let retained_connection = if retain_endpoint {
            None
        } else {
            Some(connected.first.connection()?.clone())
        };
        let retained_endpoint = if retain_endpoint {
            connected.first.endpoint.clone()
        } else {
            None
        };
        let original_deadline = Instant::now() + Duration::from_millis(100);
        // Complete the actual receiver join first, so the single poll below
        // reaches the retained socket receipt rather than task cancellation.
        connected
            .first
            .receiver
            .close_and_wait(original_deadline)
            .await?;
        {
            let closing = connected.first.close_and_wait(original_deadline);
            tokio::pin!(closing);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    closing.as_mut().poll(cx).is_pending(),
                ))
                .await
            );
        }
        assert_eq!(connected.first.close_deadline, Some(original_deadline));
        assert!(connected.first.connection.is_none());
        assert!(connected.first.endpoint.is_none());
        assert!(connected.first.released.is_some());
        assert_eq!(
            std::net::UdpSocket::bind(connected.addresses[1])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse),
        );
        let replacement_deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            connected
                .first
                .close_and_wait(replacement_deadline)
                .await
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut),
        );
        assert_eq!(connected.first.close_deadline, Some(original_deadline));
        assert!(Instant::now() < replacement_deadline);
        assert!(connected.first.released.is_some());
        drop((retained_connection, retained_endpoint));
        // The original receipt timed out. Drop may request eventual teardown,
        // but cannot turn that failed receipt into successful cleanup evidence.
        let cleanup = Instant::now() + Duration::from_secs(5);
        connected.second.close_and_wait(cleanup).await?;
        connected.close_relay(cleanup).await?;
        let addresses = connected.addresses;
        drop(connected);
        tokio::time::timeout_at(cleanup, async {
            loop {
                match std::net::UdpSocket::bind(addresses[1]) {
                    Ok(socket) => {
                        drop(socket);
                        return Ok::<_, io::Error>(());
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        for address in addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn routed_socket_release_waits_for_its_real_writable_poller_after_receiver_join() -> TestResult
{
    let fixture = Fixture::new()?;
    let setup = Instant::now() + Duration::from_secs(3);
    let (mut relay, mut adjacency, addresses) = pair(&fixture.relay, &fixture.first, setup).await?;
    let (authorization, _revocation) = fixture.authorization()?;
    let (socket, receiver) =
        socket::RoutedSocket::new(authorization, adjacency.connection()?.clone(), true)?;
    let (socket, mut released) = crate::service::socket::tracked(socket);
    let poller = socket.clone().create_io_poller();
    let cleanup = Instant::now() + Duration::from_secs(5);
    receiver.close_and_wait(cleanup).await?;
    drop(socket);
    assert!(matches!(
        released.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drop(poller);
    tokio::time::timeout_at(cleanup, &mut released).await??;
    let (local, remote) = tokio::join!(
        adjacency.close_and_wait(cleanup),
        relay.close_and_wait(cleanup),
    );
    local?;
    remote?;
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(())
}
