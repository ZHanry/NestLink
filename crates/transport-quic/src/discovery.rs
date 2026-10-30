//! Demultiplexes bounded STUN replies before QUIC decoding, preserving GRO batches.
use nestlink_traversal::stun;
use nestlink_platform_network::path::{NetworkInterface, NetworkPathManager, RoutePolicy};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::HashMap,
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub struct Observation {
    pub server: SocketAddr,
    pub local: SocketAddr,
    pub reflexive: SocketAddr,
    pub network_generation: u64,
    pub observed_at: Instant,
    pub expires_at: Instant,
}
pub const OBSERVATION_TTL: Duration = Duration::from_secs(5);
impl Observation {
    pub fn check_current(&self, socket: &DiscoverySocket) -> io::Result<()> {
        socket.check_path()?;
        if self.network_generation != socket.generation() || !socket.trusted.contains(&self.server)
            || socket.inner.local_addr()? != self.local || Instant::now() >= self.expires_at
        { return Err(failure()); }
        Ok(())
    }
}
struct Pending {
    server: SocketAddr,
    generation: u64,
    sender: oneshot::Sender<io::Result<(SocketAddr, Instant)>>,
}
pub struct DiscoverySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    trusted: Vec<SocketAddr>,
    generation: AtomicU64,
    pending: Mutex<HashMap<[u8; 12], Pending>>,
    released: Mutex<Option<oneshot::Receiver<()>>>,
    path: Option<NetworkPathManager>,
    observations: Mutex<HashMap<SocketAddr, Observation>>,
}
impl fmt::Debug for DiscoverySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoverySocket")
            .field("generation", &self.generation.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
fn failure() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "STUN discovery rejected")
}
struct Cleanup {
    socket: Arc<DiscoverySocket>,
    transaction: [u8; 12],
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.socket.pending.lock() {
            pending.remove(&self.transaction);
        }
    }
}
impl DiscoverySocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, trusted: Vec<SocketAddr>) -> io::Result<Self> {
        if trusted.len() > 4
            || trusted
                .iter()
                .any(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
        {
            return Err(failure());
        }
        let (inner, released) = crate::service::socket::tracked(inner);
        Ok(Self {
            inner,
            trusted,
            generation: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            released: Mutex::new(Some(released)),
            path: None,
            observations: Mutex::new(HashMap::new()),
        })
    }
    pub(crate) fn on_path(inner: Arc<dyn AsyncUdpSocket>, trusted: Vec<SocketAddr>, path: NetworkPathManager) -> io::Result<Self> {
        let mut socket = Self::new(inner, trusted)?;
        socket.path = Some(path);
        socket.check_path()?;
        Ok(socket)
    }
    pub fn check_path(&self) -> io::Result<()> {
        if let Some(path) = &self.path { path.validate_bound(self.inner.local_addr()?)?; }
        Ok(())
    }
    pub fn candidate_interfaces(&self) -> io::Result<Vec<NetworkInterface>> {
        match &self.path {
            Some(path) => path.candidate_interfaces(self.inner.local_addr()?),
            None => NetworkPathManager::new(RoutePolicy::System)?.candidate_interfaces(self.inner.local_addr()?),
        }
    }
    /// Only the endpoint's unique close owner takes the physical release
    /// receipt; socket and writable-poller clones must all drop before it fires.
    pub fn take_release_receipt(&self) -> io::Result<oneshot::Receiver<()>> {
        self.released
            .lock()
            .map_err(|_| failure())?
            .take()
            .ok_or_else(|| io::Error::other("UDP release receipt already owned"))
    }
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    /// Network adapters call this before re-probing; old replies can never win a new race.
    pub fn invalidate_network(&self, next: u64) -> io::Result<()> {
        let mut pending = self.pending.lock().map_err(|_| failure())?;
        if next <= self.generation() || next > i64::MAX as u64 {
            return Err(failure());
        }
        self.generation.store(next, Ordering::Release);
        self.observations.lock().map_err(|_| failure())?.clear();
        for (_, request) in pending.drain() {
            let _ = request.sender.send(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network generation changed",
            )));
        }
        Ok(())
    }
    pub async fn probe(
        self: &Arc<Self>,
        server: SocketAddr,
        budget: Duration,
    ) -> io::Result<Observation> {
        self.check_path()?;
        let local = self.inner.local_addr()?;
        if !self.trusted.contains(&server) || budget.is_zero() || budget > Duration::from_secs(3)
            || server.is_ipv4() != local.is_ipv4()
        {
            return Err(failure());
        }
        let transaction = stun::transaction();
        let generation = self.generation();
        let (sender, mut receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock().map_err(|_| failure())?;
            let mut observations = self.observations.lock().map_err(|_| failure())?;
            observations.retain(|_, observation| observation.network_generation == generation
                && observation.local == local && Instant::now() < observation.expires_at);
            if self.generation() == generation && let Some(observation) = observations.get(&server) {
                return Ok(observation.clone());
            }
            if pending.len() >= 4 || self.generation() != generation {
                return Err(failure());
            }
            pending.insert(
                transaction,
                Pending {
                    server,
                    generation,
                    sender,
                },
            );
        }
        let _cleanup = Cleanup {
            socket: self.clone(),
            transaction,
        };
        let bytes = stun::request(&transaction);
        let deadline = Instant::now() + budget;
        let mut poller = self.inner.clone().create_io_poller();
        for attempt in 0..3 {
            let transmit = Transmit {
                destination: server,
                ecn: None,
                contents: &bytes,
                segment_size: None,
                src_ip: None,
            };
            loop {
                // Serialize the generation check and nonblocking kernel send
                // with invalidation. No retry can send an old transaction after
                // invalidate_network has finished draining that generation.
                let sent = {
                    let _pending = self.pending.lock().map_err(|_| failure())?;
                    if self.generation() != generation {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "network generation changed"));
                    }
                    self.check_path()?;
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "STUN binding budget exhausted"));
                    }
                    self.inner.try_send(&transmit)
                };
                match sent {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        tokio::select! { biased;
                            result = &mut receiver => {
                                let (reflexive,observed_at) = result.map_err(io::Error::other)??;
                                return self.finish_observation(server,local,generation,reflexive,observed_at);
                            },
                            result = tokio::time::timeout_at(deadline.into(), std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))) => { result.map_err(io::Error::other)??; },
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            let wait = if attempt == 2 {
                deadline
            } else {
                (Instant::now() + Duration::from_millis(250_u64 << attempt)).min(deadline)
            };
            tokio::select! {
                result=&mut receiver=>{
                    let (reflexive, observed_at)=result.map_err(io::Error::other)??;
                    return self.finish_observation(server,local,generation,reflexive,observed_at);
                }
                _=tokio::time::sleep_until(wait.into())=>{}
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "STUN binding budget exhausted",
        ))
    }
    fn finish_observation(&self, server: SocketAddr, local: SocketAddr, generation: u64,
        reflexive: SocketAddr, observed_at: Instant) -> io::Result<Observation>
    {
        let observation = Observation {server,local,reflexive,network_generation:generation,observed_at,expires_at:observed_at+OBSERVATION_TTL};
        if reflexive.is_ipv4() != local.is_ipv4() { return Err(failure()); }
        observation.check_current(self)?;
        let _pending = self.pending.lock().map_err(|_| failure())?;
        if self.generation()!=generation{return Err(io::Error::new(io::ErrorKind::Interrupted,"network generation changed"));}
        self.observations.lock().map_err(|_| failure())?.insert(server,observation.clone());
        Ok(observation)
    }
    fn consume(&self, bytes: &[u8], source: SocketAddr) {
        if !stun::is_stun(bytes) {
            return;
        }
        let Ok(transaction) = <[u8; 12]>::try_from(&bytes[8..20]) else {
            return;
        };
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let Some(request) = pending.get(&transaction) else {
            return;
        };
        if request.server != source || request.generation != self.generation() {
            return;
        }
        let Ok(address) = stun::mapped_address(bytes, &transaction) else {
            return;
        };
        if let Some(request) = pending.remove(&transaction) {
            let _ = request.sender.send(Ok((address, Instant::now())));
        }
    }
}
impl AsyncUdpSocket for DiscoverySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Bound work under a STUN flood and yield so timers/authorization remain responsive.
        for _ in 0..8 {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                result => return result,
            };
            let mut output = 0;
            for index in 0..count {
                let mut item = meta[index];
                if item.len > bufs[index].len() || item.stride == 0 {
                    return Poll::Ready(Err(failure()));
                }
                let mut kept = 0;
                let buffer = &mut bufs[index];
                for offset in (0..item.len).step_by(item.stride) {
                    let end = (offset + item.stride).min(item.len);
                    if stun::is_stun(&buffer[offset..end]) {
                        self.consume(&buffer[offset..end], item.addr);
                    } else {
                        buffer.copy_within(offset..end, kept);
                        kept += end - offset;
                    }
                }
                if kept == 0 {
                    continue;
                }
                item.len = kept;
                if output < index {
                    let (before, after) = bufs.split_at_mut(index);
                    if before[output].len() < kept {
                        return Poll::Ready(Err(failure()));
                    }
                    before[output][..kept].copy_from_slice(&after[0][..kept]);
                }
                meta[output] = item;
                output += 1;
            }
            if output != 0 {
                return Poll::Ready(Ok(output));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, task::Waker};
    #[derive(Debug)]
    struct Packet {
        bytes: Vec<u8>,
        stride: usize,
    }
    #[derive(Debug)]
    struct Fake(Mutex<VecDeque<Vec<Packet>>>);
    #[derive(Debug)]
    struct Writable;
    impl UdpPoller for Writable {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncUdpSocket for Fake {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(Writable)
        }
        fn try_send(&self, _: &Transmit) -> io::Result<()> {
            Ok(())
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let Ok(mut packets) = self.0.lock() else {
                return Poll::Ready(Err(failure()));
            };
            let Some(batch) = packets.pop_front() else {
                return Poll::Pending;
            };
            if batch.len() > bufs.len() {
                return Poll::Ready(Err(failure()));
            }
            let count = batch.len();
            for (index, packet) in batch.into_iter().enumerate() {
                if packet.bytes.len() > bufs[index].len() {
                    return Poll::Ready(Err(failure()));
                }
                bufs[index][..packet.bytes.len()].copy_from_slice(&packet.bytes);
                meta[index] = RecvMeta {
                    len: packet.bytes.len(),
                    stride: packet.stride,
                    addr: SocketAddr::from(([127, 0, 0, 1], 1)),
                    ..RecvMeta::default()
                };
            }
            Poll::Ready(Ok(count))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 1)))
        }
    }
    #[test]
    fn mixed_gro_and_batch_compaction_preserve_quic_datagram_boundaries() -> io::Result<()> {
        let request = stun::request(&[1; 12]);
        let bytes = [vec![0x40; 20], request.to_vec(), vec![0x41; 20]].concat();
        let fake = Arc::new(Fake(Mutex::new(VecDeque::from([vec![
            Packet {
                bytes: request.to_vec(),
                stride: 20,
            },
            Packet { bytes, stride: 20 },
        ]]))));
        let socket = DiscoverySocket::new(fake, vec![])?;
        let mut first = [0; 128];
        let mut second = [0; 128];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [RecvMeta::default(); 2];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&bufs[0][..40], &[vec![0x40; 20], vec![0x41; 20]].concat());
        assert_eq!(meta[0].len, 40);
        assert_eq!(meta[0].stride, 20);
        Ok(())
    }
    #[test]
    fn stun_flood_yields_between_bounded_batches() -> io::Result<()> {
        let mut queue = VecDeque::new();
        for _ in 0..16 {
            queue.push_back(vec![Packet {
                bytes: stun::request(&[1; 12]).to_vec(),
                stride: 20,
            }]);
        }
        queue.push_back(vec![Packet {
            bytes: vec![0x40; 20],
            stride: 20,
        }]);
        let socket = DiscoverySocket::new(Arc::new(Fake(Mutex::new(queue))), vec![])?;
        let mut storage = [0; 128];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
        assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&bufs[0][..20], &[0x40; 20]);
        Ok(())
    }

    #[derive(Debug, Default)]
    struct Blocked {
        attempts: std::sync::atomic::AtomicUsize,
        started: tokio::sync::Notify,
    }
    #[derive(Debug)]
    struct NeverWritable;
    impl UdpPoller for NeverWritable {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncUdpSocket for Blocked {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(NeverWritable)
        }
        fn try_send(&self, _: &Transmit) -> io::Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn poll_recv(&self, _: &mut Context<'_>, _: &mut [IoSliceMut<'_>], _: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 1)))
        }
    }

    #[tokio::test]
    async fn network_change_interrupts_a_blocked_send_without_waiting_for_writable_or_retry() -> io::Result<()> {
        let inner = Arc::new(Blocked::default());
        let server = SocketAddr::from(([127, 0, 0, 1], 2));
        let socket = Arc::new(DiscoverySocket::new(inner.clone(), vec![server])?);
        let pending_socket = socket.clone();
        let probe = tokio::spawn(async move { pending_socket.probe(server, Duration::from_secs(3)).await });
        tokio::time::timeout(Duration::from_secs(1), inner.started.notified()).await.map_err(io::Error::other)?;
        socket.invalidate_network(2)?;
        let result = tokio::time::timeout(Duration::from_secs(1), probe).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
        assert_eq!(result.err().map(|error| error.kind()), Some(io::ErrorKind::Interrupted));
        assert_eq!(inner.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(socket.generation(), 2);
        Ok(())
    }
}
