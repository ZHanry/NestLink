//! Prototype only: adapt the selected mature ICE connection, never bind UDP.
use futures_util::task::AtomicWaker;
use nestlink_transport_stream::owner::TaskOwner;
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use std::{
    fmt, io::{self, IoSliceMut}, net::SocketAddr, pin::Pin,
    sync::{Arc, Mutex, Weak, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}},
    task::{Context, Poll}, time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use webrtc::{ice::agent::Agent, util::Conn};

const PACKET: usize = 1200;
const QUEUE: usize = 32;
const AGE: Duration = Duration::from_millis(250);
struct Packet { bytes: Vec<u8>, born: Instant }
struct State {
    stopped: AtomicBool,
    writable: Mutex<Vec<Weak<AtomicWaker>>>,
    readable: AtomicWaker,
    sent: AtomicU64,
    received: AtomicU64,
    largest_sent: AtomicUsize,
}
impl State {
    fn wake_writers(&self) {
        if let Ok(mut waiters) = self.writable.lock() {
            waiters.retain(|waiter| {
                if let Some(waiter) = waiter.upgrade() { waiter.wake(); true } else { false }
            });
        }
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.readable.wake();
        self.wake_writers();
    }
}
pub(super) struct IceUdp {
    connection: Arc<dyn Conn + Send + Sync>,
    agent: Arc<Agent>,
    local: SocketAddr,
    peer: SocketAddr,
    state: Arc<State>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    outgoing: mpsc::Sender<Packet>,
    reader: TaskOwner,
    writer: TaskOwner,
}
impl fmt::Debug for IceUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceUdpPrototype").field("local", &self.local).field("peer", &self.peer).finish_non_exhaustive()
    }
}
fn stopped() -> io::Error { io::ErrorKind::ConnectionAborted.into() }
fn current(connection: &dyn Conn, local: SocketAddr, peer: SocketAddr) -> bool {
    connection.local_addr().ok() == Some(local) && connection.remote_addr() == Some(peer)
}
impl IceUdp {
    pub(super) fn new(agent: Arc<Agent>, connection: Arc<dyn Conn + Send + Sync>) -> io::Result<Arc<Self>> {
        let local = connection.local_addr().map_err(io::Error::other)?;
        let peer = connection.remote_addr().ok_or_else(stopped)?;
        let state = Arc::new(State { stopped: AtomicBool::new(false), writable: Mutex::new(Vec::new()), readable: AtomicWaker::new(),
            sent: AtomicU64::new(0), received: AtomicU64::new(0), largest_sent: AtomicUsize::new(0) });
        // The prototype freezes its only gathered candidate on each endpoint.
        // A selected-pair notification outside those exact tuples is terminal.
        let observed = state.clone();
        agent.on_selected_candidate_pair_change(Box::new(move |a, b| {
            if a.addr() != local || b.addr() != peer { observed.stop(); }
            Box::pin(async {})
        }));
        let (incoming_tx, incoming) = mpsc::channel(QUEUE);
        let (outgoing, mut outgoing_rx) = mpsc::channel::<Packet>(QUEUE);
        let read_connection = connection.clone();
        let read_state = state.clone();
        let reader = TaskOwner::new(tokio::spawn(async move {
            // Exactly one AgentConn reader. ICE owns the physical socket reader
            // and demultiplexes authenticated STUN before this application API.
            let mut buffer = vec![0; 65_536];
            loop {
                if read_state.stopped.load(Ordering::SeqCst) || !current(read_connection.as_ref(), local, peer) { break; }
                let Ok(length) = read_connection.recv(&mut buffer).await else { break; };
                if !current(read_connection.as_ref(), local, peer) || length == 0 || length > PACKET { break; }
                read_state.received.fetch_add(length as u64, Ordering::Relaxed);
                let packet = Packet { bytes: buffer[..length].to_vec(), born: Instant::now() };
                match incoming_tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {},
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
                tokio::task::yield_now().await;
            }
            read_state.stop();
        }));
        let write_connection = connection.clone();
        let write_state = state.clone();
        let writer = TaskOwner::new(tokio::spawn(async move {
            while let Some(packet) = outgoing_rx.recv().await {
                write_state.wake_writers();
                if write_state.stopped.load(Ordering::SeqCst) || !current(write_connection.as_ref(), local, peer) { break; }
                if packet.born.elapsed() >= AGE { continue; }
                let Ok(length) = write_connection.send(&packet.bytes).await else { break; };
                if length != packet.bytes.len() || !current(write_connection.as_ref(), local, peer) { break; }
                write_state.sent.fetch_add(length as u64, Ordering::Relaxed);
                write_state.largest_sent.fetch_max(length, Ordering::Relaxed);
            }
            write_state.stop();
        }));
        Ok(Arc::new(Self { connection, agent, local, peer, state, incoming: Mutex::new(incoming), outgoing, reader, writer }))
    }
    pub(super) fn peer(&self) -> SocketAddr { self.peer }
    pub(super) fn counters(&self) -> (u64, u64, usize) {
        (self.state.sent.load(Ordering::Relaxed), self.state.received.load(Ordering::Relaxed), self.state.largest_sent.load(Ordering::Relaxed))
    }
    fn live(&self) -> io::Result<()> {
        if self.state.stopped.load(Ordering::SeqCst)
            || !current(self.connection.as_ref(), self.local, self.peer)
            || self.agent.get_selected_candidate_pair().is_none() {
            self.state.stop();
            return Err(stopped());
        }
        Ok(())
    }
    pub(super) async fn close_tasks(&self, deadline: Instant) -> io::Result<()> {
        self.state.stop();
        self.reader.request_close();
        self.writer.request_close();
        self.reader.close_and_wait(deadline).await?;
        self.writer.close_and_wait(deadline).await
    }
}
impl Drop for IceUdp {
    fn drop(&mut self) {
        self.state.stop();
        self.reader.request_close();
        self.writer.request_close();
    }
}
struct Writable { socket: Arc<IceUdp>, waker: Arc<AtomicWaker> }
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("IceWritablePrototype").finish_non_exhaustive() }
}
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.waker.register(cx.waker());
        if let Err(error) = self.socket.live() { return Poll::Ready(Err(error)); }
        if self.socket.outgoing.is_closed() { return Poll::Ready(Err(stopped())); }
        if self.socket.outgoing.capacity() > 0 { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}
impl AsyncUdpSocket for IceUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let waker = Arc::new(AtomicWaker::new());
        if let Ok(mut waiters) = self.state.writable.lock() {
            waiters.retain(|waiter| waiter.strong_count() != 0);
            waiters.push(Arc::downgrade(&waker));
        } else {
            self.state.stopped.store(true, Ordering::SeqCst);
            self.state.readable.wake();
        }
        Box::pin(Writable { socket: self, waker })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.live()?;
        if transmit.destination != self.peer || transmit.src_ip.is_some_and(|ip| ip != self.local.ip())
            || transmit.segment_size.is_some() || transmit.contents.is_empty() || transmit.contents.len() > PACKET {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.outgoing.try_send(Packet { bytes: transmit.contents.to_vec(), born: Instant::now() }).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
            mpsc::error::TrySendError::Closed(_) => stopped(),
        })
    }
    fn poll_recv(&self, cx: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>], metadata: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        self.state.readable.register(cx.waker());
        if let Err(error) = self.live() { return Poll::Ready(Err(error)); }
        if buffers.is_empty() || metadata.is_empty() { return Poll::Ready(Err(io::ErrorKind::InvalidInput.into())); }
        let Ok(mut incoming) = self.incoming.lock() else { return Poll::Ready(Err(stopped())); };
        for _ in 0..QUEUE {
            match incoming.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(stopped())),
                Poll::Ready(Some(packet)) => {
                    if packet.born.elapsed() >= AGE { continue; }
                    if packet.bytes.len() > buffers[0].len() { return Poll::Ready(Err(io::ErrorKind::InvalidInput.into())); }
                    buffers[0][..packet.bytes.len()].copy_from_slice(&packet.bytes);
                    metadata[0] = RecvMeta { addr: self.peer, len: packet.bytes.len(), stride: packet.bytes.len(), dst_ip: Some(self.local.ip()), ecn: None };
                    return Poll::Ready(Ok(1));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { Ok(self.local) }
    fn max_transmit_segments(&self) -> usize { 1 }
    fn max_receive_segments(&self) -> usize { 1 }
}
