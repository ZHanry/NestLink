use super::{Adjacency, RouteAuthorization, wire};
use std::{
    collections::BTreeMap,
    io,
    time::{Duration, Instant},
};

struct Seen {
    born: Instant,
    length: usize,
    mask: u8,
}
#[derive(Default)]
struct Replay {
    high: u64,
    seen: BTreeMap<u64, Seen>,
}
impl Replay {
    fn accept(&mut self, fragment: &wire::Fragment<'_>, now: Instant) -> io::Result<bool> {
        self.high = self.high.max(fragment.packet);
        let floor = self.high.saturating_sub(wire::REPLAY_WINDOW);
        self.seen.retain(|id, _| *id >= floor);
        if fragment.packet < floor {
            return Ok(false);
        }
        let seen = self.seen.entry(fragment.packet).or_insert(Seen {
            born: now,
            length: fragment.length,
            mask: 0,
        });
        if seen.length != fragment.length {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let bit = 1u8 << fragment.index;
        if now.saturating_duration_since(seen.born) >= Duration::from_millis(wire::PACKET_AGE_MS)
            || seen.mask & bit != 0
        {
            return Ok(false);
        }
        seen.mask |= bit;
        Ok(true)
    }
}

/// The node production adapter uses the same bounded fragment/replay checks as
/// the standalone forwarding owner. One instance belongs to each direction.
#[derive(Default)]
pub struct FragmentReplayWindow(Replay);
impl FragmentReplayWindow {
    pub fn accept(&mut self, fragment: &wire::Fragment<'_>) -> io::Result<bool> {
        self.0.accept(fragment, Instant::now())
    }
}

/// Own both fixed, pinned neighbors. This forwarding loop never parses inner
/// QUIC or business frames, opens sockets from packet fields, or adds a reliable
/// replay queue. Its one cumulative quota covers both directions and all headers.
pub struct RelayForwarder {
    authorization: RouteAuthorization,
    first: Adjacency,
    second: Adjacency,
    replay: [Replay; 2],
    used: u64,
    forwarded: u64,
    close_deadline: Option<tokio::time::Instant>,
    #[cfg(test)]
    pub(super) initial_packets: u64,
    #[cfg(test)]
    pub(super) captured: Vec<Vec<u8>>,
}
impl RelayForwarder {
    pub fn new(
        authorization: RouteAuthorization,
        first: Adjacency,
        second: Adjacency,
    ) -> io::Result<Self> {
        authorization.live()?;
        if first.local() != authorization.relay()
            || second.local() != authorization.relay()
            || first.remote() != authorization.peers().first
            || second.remote() != authorization.peers().second
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        for adjacency in [&first, &second] {
            if adjacency
                .connection()?
                .max_datagram_size()
                .is_none_or(|size| size < wire::HEADER + wire::FRAGMENT_BYTES)
            {
                return Err(io::ErrorKind::Unsupported.into());
            }
        }
        Ok(Self {
            authorization,
            first,
            second,
            replay: [Replay::default(), Replay::default()],
            used: 0,
            forwarded: 0,
            close_deadline: None,
            #[cfg(test)]
            initial_packets: 0,
            #[cfg(test)]
            captured: Vec::new(),
        })
    }
    pub fn forwarded_fragments(&self) -> u64 {
        self.forwarded
    }
    pub fn charged_bytes(&self) -> u64 {
        self.used
    }
    pub async fn run(&mut self) -> io::Result<()> {
        // Cancelling this borrowed run future stops its original adjacencies
        // even if the caller retains the owner to collect physical receipts.
        let _close = CloseOnDrop([
            self.first.connection()?.clone(),
            self.second.connection()?.clone(),
        ]);
        let result = self.run_inner().await;
        self.request_close();
        result
    }
    async fn run_inner(&mut self) -> io::Result<()> {
        let mut processed = 0u32;
        loop {
            self.authorization.live()?;
            let first = self.first.connection()?;
            let second = self.second.connection()?;
            let (direction, packet) = tokio::select! {
                _ = self.authorization.wait_stopped() => return self.authorization.live(),
                _ = first.accept_bi() => return Err(io::ErrorKind::InvalidData.into()),
                _ = first.accept_uni() => return Err(io::ErrorKind::InvalidData.into()),
                _ = second.accept_bi() => return Err(io::ErrorKind::InvalidData.into()),
                _ = second.accept_uni() => return Err(io::ErrorKind::InvalidData.into()),
                packet = first.read_datagram() => (wire::Direction::FirstToSecond, packet.map_err(io::Error::other)?),
                packet = second.read_datagram() => (wire::Direction::SecondToFirst, packet.map_err(io::Error::other)?),
            };
            self.authorization.live()?;
            let mut bytes = packet.to_vec();
            let fragment = wire::decode(&bytes).map_err(io::Error::other)?;
            if fragment.binding != self.authorization.binding_digest()
                || fragment.direction != direction
                || fragment.remaining_hops != 1
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let index = usize::from(direction == wire::Direction::SecondToFirst);
            if !self.replay[index].accept(&fragment, Instant::now())? {
                continue;
            }
            #[cfg(test)]
            {
                if fragment.index == 0
                    && fragment.length >= 1200
                    && fragment.payload.len() >= 5
                    && fragment.payload[0] & 0xf0 == 0xc0
                    && fragment.payload[1..5] == [0, 0, 0, 1]
                {
                    self.initial_packets += 1;
                }
                if self.captured.len() < 32 {
                    self.captured.push(fragment.payload.to_vec());
                }
            }
            let next = self
                .used
                .checked_add(bytes.len() as u64)
                .filter(|used| *used <= self.authorization.byte_limit())
                .ok_or(io::ErrorKind::PermissionDenied)?;
            self.used = next;
            wire::forward(&mut bytes, self.authorization.binding_digest(), direction)
                .map_err(io::Error::other)?;
            let peer = if index == 0 {
                self.second.connection()?
            } else {
                self.first.connection()?
            };
            // Congestion drops the new datagram rather than evicting previously
            // admitted bytes or creating an application reliable buffer.
            if peer.datagram_send_buffer_space() >= bytes.len() {
                self.authorization.live()?;
                peer.send_datagram(bytes.into()).map_err(io::Error::other)?;
                self.forwarded = self.forwarded.saturating_add(1);
            }
            processed = (processed + 1) % 32;
            if processed == 0 {
                tokio::task::yield_now().await;
            }
        }
    }
    pub fn request_close(&self) {
        self.first.request_close();
        self.second.request_close();
    }
    pub async fn close_and_wait(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        self.first.close_and_wait(deadline).await?;
        self.second.close_and_wait(deadline).await
    }
}
impl Drop for RelayForwarder {
    fn drop(&mut self) {
        self.request_close();
    }
}
struct CloseOnDrop([quinn::Connection; 2]);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        for connection in &self.0 {
            connection.close(0u32.into(), b"routed forwarding ended");
        }
    }
}
