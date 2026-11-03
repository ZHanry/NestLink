//! Single raw receiver and independent bounded control/business endpoint views.
//! Unknown business CIDs are never offered to the control Quinn endpoint.
use super::{socket::RoutedSocket, wire};
use crate::fragments::Packet;
use nestlink_protocol::network_migration::packet::{self, Mode};
use nestlink_transport_stream::owner::TaskOwner;
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use std::{collections::VecDeque, fmt, future::poll_fn, io::{self, IoSliceMut}, net::SocketAddr,
    pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll, Waker}, time::{Duration, Instant}};

struct Queued { mode: Mode, packet: Packet }
struct Queues {
    control: VecDeque<Queued>,
    business: VecDeque<Queued>,
    control_waker: Option<Waker>,
    business_waker: Option<Waker>,
    failure: Option<io::ErrorKind>,
}
impl Queues {
    fn pop(&mut self, mode: Mode, now: Instant) -> Option<Packet> {
        let queue = match mode { Mode::Control => &mut self.control, Mode::Business(_) => &mut self.business };
        for _ in 0..wire::PENDING_PACKETS {
            let queued = queue.pop_front()?;
            if queued.mode == mode && now.saturating_duration_since(queued.packet.born)
                < Duration::from_millis(wire::PACKET_AGE_MS) { return Some(queued.packet); }
        }
        None
    }
}
struct Shared(Mutex<Queues>);
impl Shared {
    fn push(&self, mode: Mode, packet: Packet) -> io::Result<()> {
        let mut queues = self.0.lock().map_err(|_| io::Error::other("migration queue poisoned"))?;
        // One original aggregate capacity; choosing tags cannot multiply it.
        if queues.control.len() + queues.business.len() >= wire::PENDING_PACKETS { return Ok(()); }
        let queued = Queued { mode, packet };
        let waker = match mode {
            Mode::Control => { queues.control.push_back(queued); queues.control_waker.take() },
            Mode::Business(_) => { queues.business.push_back(queued); queues.business_waker.take() },
        };
        if let Some(waker) = waker { waker.wake(); }
        Ok(())
    }
    fn fail(&self, kind: io::ErrorKind) {
        if let Ok(mut queues) = self.0.lock() {
            queues.failure = Some(kind);
            if let Some(waker) = queues.control_waker.take() { waker.wake(); }
            if let Some(waker) = queues.business_waker.take() { waker.wake(); }
        }
    }
}

pub(super) struct Hub {
    raw: Arc<RoutedSocket>,
    shared: Arc<Shared>,
    receiver: TaskOwner,
}
impl Hub {
    pub(super) fn new(raw: Arc<RoutedSocket>) -> Arc<Self> {
        let shared = Arc::new(Shared(Mutex::new(Queues { control: VecDeque::new(),
            business: VecDeque::new(), control_waker: None, business_waker: None, failure: None })));
        let incoming = raw.clone();
        let queued = shared.clone();
        let receiver = TaskOwner::new(tokio::spawn(async move {
            let receive: io::Result<()> = async {
                let mut count = 0u8;
                loop {
                    let original = poll_fn(|cx| incoming.poll_packet(cx)).await?;
                    let (mode, payload) = packet::decode(&original.bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    queued.push(mode, Packet { born: original.born, bytes: payload.to_vec() })?;
                    count = (count + 1) % 32;
                    if count == 0 { tokio::task::yield_now().await; }
                }
            }.await;
            if let Err(error) = receive { queued.fail(error.kind()); }
        }));
        Arc::new(Self { raw, shared, receiver })
    }
    pub(super) fn view(self: &Arc<Self>, mode: Mode) -> Arc<Socket> {
        Arc::new(Socket { hub: self.clone(), mode })
    }
    pub(super) fn request_close(&self) { self.receiver.request_close(); }
    pub(super) async fn close_and_wait(&self, deadline: tokio::time::Instant) -> io::Result<()> {
        self.receiver.close_and_wait(deadline).await
    }
}
impl Drop for Hub {
    fn drop(&mut self) { self.request_close(); }
}

pub(super) struct Socket { hub: Arc<Hub>, mode: Mode }
impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationPacketView").field("mode", &self.mode).finish_non_exhaustive()
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.hub.raw.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let bytes = packet::encode(self.mode, transmit.contents).map_err(io::Error::other)?;
        if transmit.segment_size.is_some_and(|size| size != transmit.contents.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.hub.raw.try_send(&Transmit { destination: transmit.destination, ecn: transmit.ecn,
            contents: &bytes, segment_size: None, src_ip: transmit.src_ip })
    }
    fn poll_recv(&self, cx: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>], metadata: &mut [RecvMeta])
    -> Poll<io::Result<usize>> {
        if let Err(error) = self.hub.raw.authorization().check_live() { return Poll::Ready(Err(error)); }
        if buffers.is_empty() || metadata.is_empty() { return Poll::Ready(Err(io::ErrorKind::InvalidInput.into())); }
        let Ok(mut queues) = self.hub.shared.0.lock() else { return Poll::Ready(Err(io::Error::other("migration queue poisoned"))); };
        if let Some(kind) = queues.failure { return Poll::Ready(Err(kind.into())); }
        if let Some(queued) = queues.pop(self.mode, Instant::now()) {
            let bytes = queued.bytes;
            if bytes.len() > buffers[0].len() { return Poll::Ready(Err(io::ErrorKind::InvalidInput.into())); }
            buffers[0][..bytes.len()].copy_from_slice(&bytes);
            metadata[0] = RecvMeta { addr: self.hub.raw.peer_addr(), len: bytes.len(), stride: bytes.len(),
                dst_ip: self.hub.raw.local_addr().ok().map(|address| address.ip()), ecn: None };
            return Poll::Ready(Ok(1));
        }
        match self.mode { Mode::Control => queues.control_waker = Some(cx.waker().clone()),
            Mode::Business(_) => queues.business_waker = Some(cx.waker().clone()) }
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.hub.raw.local_addr() }
    fn may_fragment(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shared() -> Shared {
        Shared(Mutex::new(Queues { control: VecDeque::new(), business: VecDeque::new(),
            control_waker: None, business_waker: None, failure: None }))
    }
    #[test]
    fn early_business_cids_cannot_reach_control_and_only_the_exact_epoch_can_receive() -> io::Result<()> {
        let shared = shared();
        let born = Instant::now();
        shared.push(Mode::Business(2), Packet { born, bytes: b"original business CID".to_vec() })?;
        shared.push(Mode::Control, Packet { born, bytes: b"candidate control CID".to_vec() })?;
        let mut queues = shared.0.lock().map_err(|_| io::Error::other("queue poisoned"))?;
        assert_eq!(queues.pop(Mode::Control, born).map(|packet| packet.bytes), Some(b"candidate control CID".to_vec()));
        assert!(queues.pop(Mode::Control, born).is_none());
        let business = queues.pop(Mode::Business(2), born).ok_or_else(|| io::Error::other("business CID lost"))?;
        assert_eq!(business.bytes, b"original business CID");
        assert_eq!(business.born, born);
        drop(queues);
        shared.push(Mode::Business(1), Packet { born, bytes: vec![1] })?;
        shared.push(Mode::Business(2), Packet { born, bytes: vec![2] })?;
        let mut queues = shared.0.lock().map_err(|_| io::Error::other("queue poisoned"))?;
        assert_eq!(queues.pop(Mode::Business(2), born).map(|packet| packet.bytes), Some(vec![2]));
        assert!(queues.pop(Mode::Business(1), born).is_none());
        Ok(())
    }
    #[test]
    fn aggregate_capacity_and_original_packet_age_are_not_multiplied_or_refreshed() -> io::Result<()> {
        let shared = shared();
        let born = Instant::now();
        for index in 0..wire::PENDING_PACKETS + 5 {
            shared.push(if index % 2 == 0 { Mode::Control } else { Mode::Business(2) },
                Packet { born, bytes: vec![index as u8] })?;
        }
        let mut queues = shared.0.lock().map_err(|_| io::Error::other("queue poisoned"))?;
        assert_eq!(queues.control.len() + queues.business.len(), wire::PENDING_PACKETS);
        let expired = born + Duration::from_millis(wire::PACKET_AGE_MS);
        assert!(queues.pop(Mode::Control, expired).is_none());
        assert!(queues.pop(Mode::Business(2), expired).is_none());
        assert!(queues.control.is_empty() && queues.business.is_empty());
        drop(queues);
        shared.fail(io::ErrorKind::PermissionDenied);
        assert_eq!(shared.0.lock().map_err(|_| io::Error::other("queue poisoned"))?.failure, Some(io::ErrorKind::PermissionDenied));
        Ok(())
    }
}
