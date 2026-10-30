//! One synthetic UDP path over outer unreliable QUIC datagrams. No real peer UDP
//! socket is opened and packets can never select another network destination.
use crate::fragments::{Fragment, Packet, Reassembly as BoundedReassembly};
use nestlink_protocol::{
    RELAY_UDP_AGE_MS, RELAY_UDP_FRAGMENT_BYTES, RELAY_UDP_PACKET_BYTES, RELAY_UDP_PENDING_PACKETS,
    relay_datagram::{self, HEADER},
};
use nestlink_transport_stream::owner::TaskOwner;
use quinn::{
    AsyncUdpSocket, UdpPoller,
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
use tokio::{sync::mpsc, time::Sleep};

const WINDOW: u64 = 64;
struct Reassembly {
    bounded: BoundedReassembly,
}
impl Default for Reassembly {
    fn default() -> Self {
        Self {
            bounded: BoundedReassembly::new(
                RELAY_UDP_FRAGMENT_BYTES as usize,
                RELAY_UDP_PENDING_PACKETS as usize,
                WINDOW,
                Duration::from_millis(RELAY_UDP_AGE_MS),
            ),
        }
    }
}
impl Reassembly {
    fn insert(&mut self, bytes: &[u8], now: Instant) -> io::Result<Option<Packet>> {
        let f = relay_datagram::decode(bytes).map_err(io::Error::other)?;
        self.bounded.insert(
            Fragment {
                packet: f.packet,
                length: f.length,
                index: f.index,
                payload: f.payload,
            },
            now,
        )
    }
}
fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "relay UDP carrier closed")
}
pub(crate) fn connection_fault(error: quinn::ConnectionError) -> io::ErrorKind {
    match error {
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        quinn::ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        quinn::ConnectionError::ApplicationClosed(_) => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::InvalidData,
    }
}
pub(crate) struct RelaySocket {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    local: SocketAddr,
    peer: SocketAddr,
    sequence: Mutex<u64>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    receiver: TaskOwner,
    failure: tokio::sync::watch::Sender<Option<io::ErrorKind>>,
}
impl fmt::Debug for RelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySocket")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl Drop for RelaySocket {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"virtual UDP owner dropped");
        self.receiver.request_close();
    }
}
impl RelaySocket {
    pub(crate) fn new(
        connection: quinn::Connection,
        endpoint: quinn::Endpoint,
        controller: bool,
        mut read: quinn::RecvStream,
        _write: quinn::SendStream,
    ) -> io::Result<Arc<Self>> {
        if connection
            .max_datagram_size()
            .is_none_or(|n| n < HEADER + RELAY_UDP_FRAGMENT_BYTES as usize)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "outer QUIC datagram MTU too small",
            ));
        }
        let first = SocketAddr::from(([127, 0, 0, 1], 28743));
        let second = SocketAddr::from(([127, 0, 0, 2], 28743));
        let (local, peer) = if controller {
            (first, second)
        } else {
            (second, first)
        };
        let (tx, rx) = mpsc::channel(RELAY_UDP_PENDING_PACKETS as usize);
        let copy = connection.clone();
        let (failure, _) = tokio::sync::watch::channel(None);
        let failed = failure.clone();
        let receiver = tokio::spawn(async move {
            let _control_write = _write;
            let mut packets = Reassembly::default();
            let mut extra = [0u8; 1];
            let mut processed = 0u32;
            let reason = loop {
                tokio::select! { biased;
                    result = read.read(&mut extra) => break match result {
                        Ok(Some(_)) => io::ErrorKind::InvalidData,
                        Ok(None) => io::ErrorKind::UnexpectedEof,
                        Err(quinn::ReadError::ConnectionLost(error)) => connection_fault(error),
                        Err(error) => io::Error::from(error).kind(),
                    },
                    result = copy.accept_bi() => break match result { Ok(_) => io::ErrorKind::InvalidData, Err(error) => connection_fault(error) },
                    result = copy.accept_uni() => break match result { Ok(_) => io::ErrorKind::InvalidData, Err(error) => connection_fault(error) },
                    result = copy.read_datagram() => {
                        let bytes = match result { Ok(bytes) => bytes, Err(error) => break connection_fault(error) };
                        match packets.insert(&bytes, Instant::now()) {
                            Ok(Some(packet)) => { let _ = tx.try_send(packet); },
                            Ok(None) => {},
                            Err(_) => break io::ErrorKind::InvalidData,
                        }
                    }
                }
                processed = (processed + 1) % 32;
                if processed == 0 {
                    tokio::task::yield_now().await;
                }
            };
            failed.send_replace(Some(reason));
            copy.close(1u32.into(), b"relay UDP receive stopped");
        });
        Ok(Arc::new(Self {
            connection,
            _endpoint: endpoint,
            local,
            peer,
            sequence: Mutex::new(0),
            incoming: Mutex::new(rx),
            receiver: TaskOwner::new(receiver),
            failure,
        }))
    }
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub(crate) fn close_owner(&self) -> TaskOwner {
        self.receiver.clone()
    }
    pub(crate) fn subscribe_failure(&self) -> tokio::sync::watch::Receiver<Option<io::ErrorKind>> {
        self.failure.subscribe()
    }
    fn writable(&self) -> io::Result<bool> {
        if self.connection.close_reason().is_some() {
            return Err(failed());
        }
        Ok(self.connection.datagram_send_buffer_space()
            >= RELAY_UDP_PACKET_BYTES as usize + 2 * HEADER)
    }
}
struct Writable {
    socket: Arc<RelaySocket>,
    timer: Pin<Box<Sleep>>,
}
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayWritable").finish_non_exhaustive()
    }
}
impl UdpPoller for Writable {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        match self.socket.writable() {
            Ok(true) => return Poll::Ready(Ok(())),
            Err(e) => return Poll::Ready(Err(e)),
            Ok(false) => {}
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(5));
            // Register the next wake after resetting, even if the first poll was ready.
            let _ = self.timer.as_mut().poll(cx);
        }
        Poll::Pending
    }
}
impl AsyncUdpSocket for RelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            socket: self,
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(5))),
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.peer
            || transmit.src_ip.is_some_and(|ip| ip != self.local.ip())
            || transmit
                .segment_size
                .is_some_and(|n| n != transmit.contents.len())
            || transmit.contents.is_empty()
            || transmit.contents.len() > RELAY_UDP_PACKET_BYTES as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtual UDP destination/MTU rejected",
            ));
        }
        let mut sequence = self.sequence.lock().map_err(|_| failed())?;
        if !self.writable()? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let next = sequence.checked_add(1).ok_or_else(failed)?;
        let fragments =
            relay_datagram::encode(next, transmit.contents).map_err(io::Error::other)?;
        *sequence = next;
        for fragment in fragments {
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
        if self.connection.close_reason().is_some() {
            return Poll::Ready(Err(failed()));
        }
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let Ok(mut rx) = self.incoming.lock() else {
            return Poll::Ready(Err(failed()));
        };
        for _ in 0..RELAY_UDP_PENDING_PACKETS {
            match rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(failed())),
                Poll::Ready(Some(packet)) => {
                    if Instant::now().saturating_duration_since(packet.born)
                        >= Duration::from_millis(RELAY_UDP_AGE_MS)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unreliable_reordering_duplicates_expiry_and_late_fragments_do_not_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![91; 1200];
        let f = relay_datagram::encode(1, &bytes)?;
        let now = Instant::now();
        let mut r = Reassembly::default();
        assert!(r.insert(&f[1], now)?.is_none());
        assert!(r.insert(&f[1], now)?.is_none());
        assert_eq!(r.insert(&f[0], now)?, Some(Packet { born: now, bytes }));
        assert!(r.insert(&f[0], now)?.is_none());
        let f = relay_datagram::encode(2, &[7; 1200])?;
        assert!(r.insert(&f[0], now)?.is_none());
        let late = now + Duration::from_millis(RELAY_UDP_AGE_MS);
        assert!(r.insert(&f[1], late)?.is_none());
        assert!(r.insert(&f[0], late)?.is_none());
        Ok(())
    }
    #[test]
    fn fragment_flood_stays_bounded_and_conflicting_packets_fail()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut r = Reassembly::default();
        for id in 1..=5000 {
            r.insert(&relay_datagram::encode(id, &[6; 1200])?[0], now)?;
            assert!(r.bounded.pending_len() <= RELAY_UDP_PENDING_PACKETS as usize);
            assert!(r.bounded.finished_len() <= WINDOW as usize + 1);
        }
        let mut r = Reassembly::default();
        r.insert(&relay_datagram::encode(1, &[6; 1200])?[0], now)?;
        assert!(
            r.insert(&relay_datagram::encode(1, &[7; 1200])?[0], now)
                .is_err()
        );
        assert!(relay_datagram::encode(0, &[1]).is_err());
        assert!(relay_datagram::encode(1, &[1; 1201]).is_err());
        let mut malformed = relay_datagram::encode(1, &[1])?.remove(0);
        malformed[1] = 255;
        assert!(r.insert(&malformed, now).is_err());
        Ok(())
    }
}
