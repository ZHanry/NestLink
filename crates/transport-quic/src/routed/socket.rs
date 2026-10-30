//! The existing virtual UDP adaptation with a separate, verified route codec.
use super::{RouteAuthorization, wire};
use crate::fragments::{Fragment, Packet, Reassembly};
use nestlink_transport_stream::owner::TaskOwner;
use quinn::{
    AsyncUdpSocket, Connection, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    time::Sleep,
};

fn connection_fault(error: quinn::ConnectionError) -> io::ErrorKind {
    match error {
        // Routed allocations have no implicit reconnect authority. An
        // authenticated adjacency shutdown ends this exact allocation.
        quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::LocallyClosed => {
            io::ErrorKind::PermissionDenied
        }
        error => crate::virtual_udp::connection_fault(error),
    }
}

fn record_failure(failure: &watch::Sender<Option<io::ErrorKind>>, kind: io::ErrorKind) {
    failure.send_if_modified(|current| {
        if current.is_some() {
            return false;
        }
        *current = Some(kind);
        true
    });
}

#[derive(Default)]
struct Budget {
    sequence: u64,
    bytes: u64,
}
pub(super) struct RoutedSocket {
    authorization: RouteAuthorization,
    connection: Connection,
    local: SocketAddr,
    peer: SocketAddr,
    direction: wire::Direction,
    budget: Arc<Mutex<Budget>>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    receiver: TaskOwner,
    failure: watch::Sender<Option<io::ErrorKind>>,
}
impl fmt::Debug for RoutedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedSocket")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl RoutedSocket {
    pub(super) fn new(
        authorization: RouteAuthorization,
        connection: Connection,
        first: bool,
    ) -> io::Result<(Arc<Self>, TaskOwner)> {
        authorization.live()?;
        if connection
            .max_datagram_size()
            .is_none_or(|n| n < wire::HEADER + wire::FRAGMENT_BYTES)
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let a = SocketAddr::from(([127, 0, 0, 1], 28744));
        let b = SocketAddr::from(([127, 0, 0, 2], 28744));
        let (local, peer, direction) = if first {
            (a, b, wire::Direction::FirstToSecond)
        } else {
            (b, a, wire::Direction::SecondToFirst)
        };
        let (tx, rx) = mpsc::channel(wire::PENDING_PACKETS);
        let budget = Arc::new(Mutex::new(Budget::default()));
        let counted = budget.clone();
        let copy = connection.clone();
        let granted = authorization.retained();
        let (failure, _) = watch::channel(None);
        let failed = failure.clone();
        let receiver = TaskOwner::new(tokio::spawn(async move {
            let mut packets = Reassembly::new(
                wire::FRAGMENT_BYTES,
                wire::PENDING_PACKETS,
                wire::REPLAY_WINDOW,
                Duration::from_millis(wire::PACKET_AGE_MS),
            );
            let receive = async {
                let mut processed = 0u32;
                loop {
                    granted.live()?;
                    let bytes = tokio::select! { biased;
                        _ = granted.wait_stopped() => {
                            granted.live()?;
                            return Err(io::ErrorKind::PermissionDenied.into());
                        },
                        result = copy.accept_bi() => return Err(match result {
                            Ok(_) => io::ErrorKind::InvalidData,
                            Err(error) => connection_fault(error),
                        }.into()),
                        result = copy.accept_uni() => return Err(match result {
                            Ok(_) => io::ErrorKind::InvalidData,
                            Err(error) => connection_fault(error),
                        }.into()),
                        bytes = copy.read_datagram() => bytes.map_err(|error| io::Error::from(connection_fault(error)))?,
                    };
                    granted.live()?;
                    let fragment = wire::decode(&bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    if fragment.binding != granted.binding_digest()
                        || fragment.direction != direction.reverse()
                        || fragment.remaining_hops != 0
                    {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    charge(&counted, bytes.len(), granted.byte_limit())?;
                    if let Some(packet) = packets.insert(
                        Fragment {
                            packet: fragment.packet,
                            length: fragment.length,
                            index: fragment.index,
                            payload: fragment.payload,
                        },
                        Instant::now(),
                    )? {
                        let _ = tx.try_send(packet);
                    }
                    processed = (processed + 1) % 32;
                    if processed == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            };
            let result: io::Result<()> = receive.await;
            record_failure(
                &failed,
                result.err().map_or(io::ErrorKind::PermissionDenied, |error| error.kind()),
            );
            copy.close(1u32.into(), b"routed UDP receive ended");
        }));
        Ok((
            Arc::new(Self {
                authorization,
                connection,
                local,
                peer,
                direction,
                budget,
                incoming: Mutex::new(rx),
                receiver: receiver.clone(),
                failure,
            }),
            receiver,
        ))
    }
    pub(super) fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub(super) fn subscribe_failure(&self) -> watch::Receiver<Option<io::ErrorKind>> {
        self.failure.subscribe()
    }
    fn live(&self) -> io::Result<()> {
        if let Err(error) = self.authorization.live() {
            record_failure(&self.failure, error.kind());
            return Err(error);
        }
        if let Some(error) = self.connection.close_reason() {
            let kind = connection_fault(error);
            record_failure(&self.failure, kind);
            return Err(kind.into());
        }
        if let Some(kind) = *self.failure.borrow() {
            return Err(kind.into());
        }
        Ok(())
    }
    fn writable(&self) -> io::Result<bool> {
        self.live()?;
        Ok(self.connection.datagram_send_buffer_space() >= wire::PACKET_BYTES + 2 * wire::HEADER)
    }
}
impl Drop for RoutedSocket {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"routed UDP owner dropped");
        self.receiver.request_close();
    }
}
fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "routed UDP stopped or refused",
    )
}
fn charge(budget: &Mutex<Budget>, bytes: usize, limit: u64) -> io::Result<()> {
    let mut budget = budget.lock().map_err(|_| stopped())?;
    let used = budget
        .bytes
        .checked_add(bytes as u64)
        .filter(|used| *used <= limit)
        .ok_or(io::ErrorKind::PermissionDenied)?;
    budget.bytes = used;
    Ok(())
}
struct Writable {
    socket: Arc<RoutedSocket>,
    timer: Pin<Box<Sleep>>,
}
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedWritable").finish_non_exhaustive()
    }
}
impl UdpPoller for Writable {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        match self.socket.writable() {
            Ok(true) => return Poll::Ready(Ok(())),
            Err(error) => return Poll::Ready(Err(error)),
            Ok(false) => {}
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(5));
            let _ = self.timer.as_mut().poll(cx);
        }
        Poll::Pending
    }
}
impl AsyncUdpSocket for RoutedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            socket: self,
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(5))),
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.live()?;
        if transmit.destination != self.peer
            || transmit.src_ip.is_some_and(|ip| ip != self.local.ip())
            || transmit
                .segment_size
                .is_some_and(|size| size != transmit.contents.len())
            || transmit.contents.is_empty()
            || transmit.contents.len() > wire::PACKET_BYTES
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if !self.writable()? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut budget = self.budget.lock().map_err(|_| stopped())?;
        let sequence = budget.sequence.checked_add(1).ok_or_else(stopped)?;
        let fragments = wire::encode(
            self.authorization.binding_digest(),
            self.direction,
            sequence,
            transmit.contents,
        )
        .map_err(io::Error::other)?;
        let bytes = fragments.iter().map(Vec::len).sum::<usize>();
        let used = budget
            .bytes
            .checked_add(bytes as u64)
            .filter(|used| *used <= self.authorization.byte_limit())
            .ok_or_else(stopped)?;
        budget.sequence = sequence;
        budget.bytes = used;
        for fragment in fragments {
            self.authorization.live()?;
            self.connection
                .send_datagram(fragment.into())
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.live() {
            return Poll::Ready(Err(error));
        }
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(stopped()));
        };
        for _ in 0..wire::PENDING_PACKETS {
            match incoming.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(stopped())),
                Poll::Ready(Some(packet)) => {
                    if Instant::now().saturating_duration_since(packet.born)
                        >= Duration::from_millis(wire::PACKET_AGE_MS)
                    {
                        continue;
                    }
                    let bytes = packet.bytes;
                    if bytes.len() > bufs[0].len() {
                        return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
                    }
                    bufs[0][..bytes.len()].copy_from_slice(&bytes);
                    meta[0] = RecvMeta {
                        addr: self.peer,
                        len: bytes.len(),
                        stride: bytes.len(),
                        dst_ip: Some(self.local.ip()),
                        ecn: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn may_fragment(&self) -> bool {
        false
    }
}
