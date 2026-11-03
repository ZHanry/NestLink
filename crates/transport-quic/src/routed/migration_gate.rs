//! A bounded hold for an explicitly prepared spare and finite old-path drain.
//! Business/path revocation and the original authority expiry bypass holdoff.
use super::RouteAuthorization;
use nestlink_protocol::network_migration::{MAX_CONTROL_LIFETIME_MS, MAX_DRAIN_MS};
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use std::{fmt, future::Future, io::{self, IoSliceMut}, net::SocketAddr, pin::Pin,
    sync::{Arc, Mutex}, task::{Context, Poll, Waker}, time::Duration};
use tokio::{sync::watch, time::{Instant, Sleep}};

#[derive(Default)]
struct State { armed: bool, hold_until: Option<Instant>, drain_until: Option<Instant>, wake: Option<Waker> }
pub(super) struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    authority: RouteAuthorization,
    state: Mutex<State>,
    timer: Mutex<Pin<Box<Sleep>>>,
    failure: Mutex<watch::Sender<Option<io::ErrorKind>>>,
}
impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("MigrationSocketGate").finish_non_exhaustive() }
}
fn recoverable(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut)
}
impl Socket {
    pub(super) fn new(inner: Arc<dyn AsyncUdpSocket>, authority: RouteAuthorization) -> Arc<Self> {
        let (failure, _) = watch::channel(None);
        Arc::new(Self { inner, authority, state: Mutex::new(State::default()),
            timer: Mutex::new(Box::pin(tokio::time::sleep(Duration::from_secs(60)))), failure: Mutex::new(failure) })
    }
    pub(super) fn subscribe_failure(&self) -> io::Result<watch::Receiver<Option<io::ErrorKind>>> {
        Ok(self.failure.lock().map_err(|_| io::Error::other("migration failure state poisoned"))?.subscribe())
    }
    pub(super) fn failure_sender(&self) -> io::Result<watch::Sender<Option<io::ErrorKind>>> {
        Ok(self.failure.lock().map_err(|_| io::Error::other("migration failure state poisoned"))?.clone())
    }
    pub(super) fn set_failure_sender(&self, sender: watch::Sender<Option<io::ErrorKind>>) -> io::Result<()> {
        *self.failure.lock().map_err(|_| io::Error::other("migration failure state poisoned"))? = sender;
        Ok(())
    }
    fn record(&self, kind: io::ErrorKind) {
        if let Ok(sender) = self.failure.lock() {
            sender.send_if_modified(|current| {
                if current.is_some_and(|old| !recoverable(old) || recoverable(kind)) { return false; }
                *current = Some(kind); true
            });
        }
    }
    pub(super) fn arm(&self) -> io::Result<()> {
        self.authority.check_live()?;
        if self.failure_sender()?.borrow().is_some() { return Err(io::ErrorKind::NotConnected.into()); }
        let mut state = self.state.lock().map_err(|_| io::Error::other("migration gate poisoned"))?;
        if state.hold_until.is_some() || state.drain_until.is_some() { return Err(io::ErrorKind::AlreadyExists.into()); }
        state.armed = true;
        Ok(())
    }
    pub(super) fn held_loss_deadline(&self) -> Option<Instant> {
        self.authority.check_live().ok()?;
        let state = self.state.lock().ok()?;
        state.hold_until.filter(|until| state.drain_until.is_none() && Instant::now() < *until)
    }
    pub(super) fn drain(&self) -> io::Result<Instant> {
        let mut state = self.state.lock().map_err(|_| io::Error::other("migration gate poisoned"))?;
        let until = *state.drain_until.get_or_insert_with(||
            (Instant::now() + Duration::from_millis(MAX_DRAIN_MS)).min(self.authority.deadline()));
        if let Some(wake) = state.wake.take() { wake.wake(); }
        Ok(until)
    }
    fn authorized(&self) -> io::Result<Option<Instant>> {
        // The independent original expiry and terminal revocation are checked
        // before considering any recoverable socket error or hold timer.
        self.authority.check_live().inspect_err(|error| self.record(error.kind()))?;
        let state = self.state.lock().map_err(|_| io::Error::other("migration gate poisoned"))?;
        if state.drain_until.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        Ok(state.drain_until)
    }
    fn hold_error(&self, error: io::Error) -> io::Result<Option<Instant>> {
        self.authority.check_live().inspect_err(|error| self.record(error.kind()))?;
        let mut state = self.state.lock().map_err(|_| io::Error::other("migration gate poisoned"))?;
        if state.armed && state.drain_until.is_none() && recoverable(error.kind()) {
            let until = *state.hold_until.get_or_insert_with(||
                (Instant::now() + Duration::from_millis(MAX_CONTROL_LIFETIME_MS)).min(self.authority.deadline()));
            if Instant::now() < until { return Ok(Some(until)); }
        }
        self.record(error.kind());
        Err(error)
    }
    fn poll_deadline(&self, cx: &mut Context<'_>, until: Instant) -> Poll<io::Result<()>> {
        let Ok(mut timer) = self.timer.lock() else { return Poll::Ready(Err(io::Error::other("migration timer poisoned"))); };
        timer.as_mut().reset(until);
        if timer.as_mut().poll(cx).is_ready() { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}
struct Writable { socket: Arc<Socket>, inner: Pin<Box<dyn UdpPoller>>, timer: Pin<Box<Sleep>> }
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("MigrationGateWritable").finish_non_exhaustive() }
}
impl UdpPoller for Writable {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.socket.authorized() { return Poll::Ready(Err(error)); }
        match self.inner.as_mut().poll_writable(cx) {
            Poll::Ready(Err(error)) => match self.socket.hold_error(error) {
                Ok(Some(_)) => {},
                Ok(None) => return Poll::Ready(Ok(())),
                Err(error) => return Poll::Ready(Err(error)),
            },
            result => return result,
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.timer.as_mut().reset(Instant::now() + Duration::from_millis(5));
            let _ = self.timer.as_mut().poll(cx);
        }
        Poll::Pending
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let inner = self.inner.clone().create_io_poller();
        Box::pin(Writable { socket: self, inner, timer: Box::pin(tokio::time::sleep(Duration::from_millis(5))) })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.authorized()?;
        match self.inner.try_send(transmit) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            Err(error) => match self.hold_error(error)? {
                Some(_) => Err(io::ErrorKind::WouldBlock.into()), None => Ok(()),
            }
        }
    }
    fn poll_recv(&self, cx: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>], metadata: &mut [RecvMeta])
    -> Poll<io::Result<usize>> {
        let drain = match self.authorized() { Ok(deadline) => deadline, Err(error) => return Poll::Ready(Err(error)) };
        if let Ok(mut state) = self.state.lock() { state.wake = Some(cx.waker().clone()); }
        if let Some(until) = drain { let _ = self.poll_deadline(cx, until); }
        match self.inner.poll_recv(cx, buffers, metadata) {
            Poll::Ready(Err(error)) => match self.hold_error(error) {
                Ok(Some(until)) => {
                    let _ = self.poll_deadline(cx, until);
                    Poll::Pending
                },
                Ok(None) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
            result => result,
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }
    fn may_fragment(&self) -> bool { self.inner.may_fragment() }
}
