//! The finite gate never converts authority denial into recoverable path loss.
use super::*;
use crate::routed::migration_gate::Socket;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::IoSliceMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

#[derive(Debug)]
struct FaultSocket(Option<io::ErrorKind>);
impl UdpPoller for FaultSocket {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.map_or(Ok(()), |kind| Err(kind.into())))
    }
}
impl AsyncUdpSocket for FaultSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Self(self.0))
    }
    fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
        self.0.map_or(Ok(()), |kind| Err(kind.into()))
    }
    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        _: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0
            .map_or(Poll::Pending, |kind| Poll::Ready(Err(kind.into())))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(([127, 0, 0, 1], 28744).into())
    }
    fn may_fragment(&self) -> bool {
        false
    }
}
fn send(socket: &Socket) -> io::Result<()> {
    socket.try_send(&Transmit {
        destination: ([127, 0, 0, 2], 28744).into(),
        ecn: None,
        contents: b"existing encrypted inner packet",
        segment_size: None,
        src_ip: None,
    })
}

#[tokio::test]
async fn only_an_explicitly_prepared_gate_holds_physical_loss_once_and_never_renews_it()
-> TestResult {
    let fixture = Fixture::new()?;
    let (authorization, _revocation) = fixture.authorization()?;
    let unarmed = Socket::new(
        Arc::new(FaultSocket(Some(io::ErrorKind::ConnectionReset))),
        authorization,
    );
    assert_eq!(
        send(&unarmed).err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionReset)
    );
    assert_eq!(
        *unarmed.subscribe_failure()?.borrow(),
        Some(io::ErrorKind::ConnectionReset)
    );
    let (authorization, _revocation) = fixture.authorization()?;
    let gate = Socket::new(
        Arc::new(FaultSocket(Some(io::ErrorKind::ConnectionReset))),
        authorization,
    );
    gate.arm()?;
    let started = Instant::now();
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    let deadline = gate.held_loss_deadline().ok_or("physical hold missing")?;
    assert!(deadline >= started);
    assert!(
        deadline
            <= Instant::now()
                + Duration::from_millis(
                    nestlink_protocol::network_migration::MAX_CONTROL_LIFETIME_MS
                )
    );
    assert_eq!(*gate.subscribe_failure()?.borrow(), None);
    assert_eq!(
        gate.arm().err().map(|error| error.kind()),
        Some(io::ErrorKind::AlreadyExists)
    );
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            send(&gate).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(gate.held_loss_deadline(), Some(deadline));
    }
    tokio::time::sleep_until(deadline + Duration::from_millis(1)).await;
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionReset)
    );
    assert_eq!(gate.held_loss_deadline(), None);
    assert_eq!(
        *gate.subscribe_failure()?.borrow(),
        Some(io::ErrorKind::ConnectionReset)
    );
    Ok(())
}

#[tokio::test]
async fn revocation_and_original_expiry_precede_hold_and_repeated_drain_never_extends_grace()
-> TestResult {
    let fixture = Fixture::new()?;
    for fault in [io::ErrorKind::PermissionDenied, io::ErrorKind::InvalidData] {
        let (authorization, _revocation) = fixture.authorization()?;
        let gate = Socket::new(Arc::new(FaultSocket(Some(fault))), authorization);
        gate.arm()?;
        assert_eq!(send(&gate).err().map(|error| error.kind()), Some(fault));
        assert_eq!(gate.held_loss_deadline(), None);
    }
    let (authorization, revocation) = fixture.authorization()?;
    let gate = Socket::new(
        Arc::new(FaultSocket(Some(io::ErrorKind::BrokenPipe))),
        authorization,
    );
    gate.arm()?;
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    revocation.revoke();
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(gate.held_loss_deadline(), None);
    let (authorization, revocation) = fixture.authorization()?;
    let gate = Socket::new(Arc::new(FaultSocket(None)), authorization);
    let began = Instant::now();
    let cutoff = gate.drain()?;
    assert!(cutoff >= began);
    assert!(
        cutoff
            <= Instant::now()
                + Duration::from_millis(nestlink_protocol::network_migration::MAX_DRAIN_MS)
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(gate.drain()?, cutoff);
    let mut cx = Context::from_waker(Waker::noop());
    let mut storage = [0; 128];
    let mut buffers = [IoSliceMut::new(&mut storage)];
    let mut metadata = [RecvMeta::default()];
    assert!(
        gate.poll_recv(&mut cx, &mut buffers, &mut metadata)
            .is_pending()
    );
    revocation.revoke();
    assert!(
        matches!(gate.poll_recv(&mut cx, &mut buffers, &mut metadata), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    // The original grant deadline caps even a newly armed physical-loss hold.
    let mut expiring = Fixture::new()?;
    expiring.transit.scope.expires_at_ms = expiring.now + 300;
    let (authorization, _revocation) = expiring.authorization()?;
    let authority_deadline = authorization.deadline();
    let gate = Socket::new(
        Arc::new(FaultSocket(Some(io::ErrorKind::TimedOut))),
        authorization,
    );
    gate.arm()?;
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(gate.held_loss_deadline(), Some(authority_deadline));
    tokio::time::sleep_until(authority_deadline + Duration::from_millis(1)).await;
    assert_eq!(
        send(&gate).err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(
        *gate.subscribe_failure()?.borrow(),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
