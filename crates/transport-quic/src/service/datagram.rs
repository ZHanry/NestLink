//! Native QUIC DATAGRAM only. Unknown, oversized or congested packets are
//! dropped without introducing a stream fallback or an unbounded reliable queue.
use super::*;
use nestlink_protocol::service_plane::SERVICE_DATAGRAM_BYTES;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::mpsc;

const MAX_MAPPINGS: usize = 128;
const ROUTE_QUEUE: usize = 16;
struct Entry {
    token: u64,
    packets: mpsc::Sender<Vec<u8>>,
}
struct State {
    next: u64,
    entries: HashMap<[u8; 16], Entry>,
    closed: bool,
}
struct Shared {
    state: Mutex<State>,
    driven: AtomicBool,
}
#[derive(Clone)]
pub struct DatagramRouter {
    shared: Arc<Shared>,
}
pub struct DatagramRoute {
    shared: Arc<Shared>,
    key: [u8; 16],
    token: u64,
    packets: mpsc::Receiver<Vec<u8>>,
}
impl Default for DatagramRouter {
    fn default() -> Self {
        Self::new()
    }
}
impl DatagramRouter {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    next: 0,
                    entries: HashMap::new(),
                    closed: false,
                }),
                driven: AtomicBool::new(false),
            }),
        }
    }
    pub fn register(&self, key: [u8; 16]) -> io::Result<DatagramRoute> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| io::ErrorKind::ConnectionAborted)?;
        if state.closed
            || key == [0; 16]
            || state.entries.len() >= MAX_MAPPINGS
            || state.entries.contains_key(&key)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let token = state
            .next
            .checked_add(1)
            .ok_or(io::ErrorKind::ConnectionAborted)?;
        state.next = token;
        let (packets, receiver) = mpsc::channel(ROUTE_QUEUE);
        state.entries.insert(key, Entry { token, packets });
        Ok(DatagramRoute {
            shared: self.shared.clone(),
            key,
            token,
            packets: receiver,
        })
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.closed = true;
            state.entries.clear();
        }
    }
    /// The caller retains and joins this one driver for the connection. A
    /// second drive call is refused and cannot steal another mapping's packet.
    pub async fn drive(&self, connection: &Connection, reply: bool) -> io::Result<()> {
        if self.shared.driven.swap(true, Ordering::AcqRel) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let result = loop {
            let packet = match connection.read_datagram().await {
                Ok(packet) => packet,
                Err(error) => break Err(io::Error::other(error)),
            };
            if !(31..=SERVICE_DATAGRAM_BYTES).contains(&packet.len())
                || &packet[..4] != b"NSD1"
                || packet[4] != u8::from(reply)
            {
                continue;
            }
            let key: [u8; 16] = packet[5..21].try_into().map_err(io::Error::other)?;
            let receiver = {
                let state = self
                    .shared
                    .state
                    .lock()
                    .map_err(|_| io::ErrorKind::ConnectionAborted)?;
                if state.closed {
                    break Ok(());
                }
                state.entries.get(&key).map(|entry| entry.packets.clone())
            };
            if let Some(receiver) = receiver {
                let _ = receiver.try_send(packet.to_vec());
            }
        };
        self.close();
        result
    }
}
impl DatagramRoute {
    pub async fn receive(&mut self) -> Option<Vec<u8>> {
        self.packets.recv().await
    }
}
impl Drop for DatagramRoute {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock()
            && state
                .entries
                .get(&self.key)
                .is_some_and(|entry| entry.token == self.token)
        {
            state.entries.remove(&self.key);
        }
    }
}
pub fn supports_native(connection: &Connection) -> bool {
    connection
        .max_datagram_size()
        .is_some_and(|n| n >= SERVICE_DATAGRAM_BYTES)
}
pub fn send(connection: &Connection, packet: Vec<u8>) -> io::Result<()> {
    if !(31..=SERVICE_DATAGRAM_BYTES).contains(&packet.len())
        || connection
            .max_datagram_size()
            .is_none_or(|n| n < packet.len())
    {
        return Err(io::ErrorKind::Unsupported.into());
    }
    connection
        .send_datagram(packet.into())
        .map_err(io::Error::other)
}
#[cfg(test)]
mod tests;
