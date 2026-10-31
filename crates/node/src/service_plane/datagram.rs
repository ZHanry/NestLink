use super::{Error, PreparedLocalTunnel, ServiceFlowPermit, gate::rejected};
use nestlink_protocol::{ErrorCode, service_plane::SERVICE_DATAGRAM_BYTES};
use std::{net::SocketAddr, sync::Mutex};
use tokio::net::UdpSocket;

const HEADER: usize = 31;
const MAX_PAYLOAD: usize = SERVICE_DATAGRAM_BYTES - HEADER;
/// Each packet is one native carrier datagram. This codec performs no framing
/// over TCP, queuing, fragmentation, or reassembly.
#[derive(Debug, Clone)]
pub struct DatagramPacket {
    pub mapping_id: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct DatagramReply {
    pub mapping_id: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
fn encode(packet: &DatagramPacket, reply: bool) -> Result<Vec<u8>, Error> {
    let id = uuid::Uuid::parse_str(&packet.mapping_id).map_err(|_| Error::Datagram)?;
    if id.is_nil()
        || id.to_string() != packet.mapping_id
        || packet.sequence == 0
        || packet.sequence > i64::MAX as u64
        || packet.payload.len() > MAX_PAYLOAD
    {
        return Err(Error::Datagram);
    }
    let mut bytes = Vec::with_capacity(HEADER + packet.payload.len());
    bytes.extend_from_slice(b"NSD1");
    bytes.push(u8::from(reply));
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&packet.sequence.to_be_bytes());
    bytes.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&packet.payload);
    Ok(bytes)
}
fn decode(bytes: &[u8], reply: bool) -> Result<DatagramPacket, Error> {
    if !(HEADER..=SERVICE_DATAGRAM_BYTES).contains(&bytes.len())
        || &bytes[..4] != b"NSD1"
        || bytes[4] != u8::from(reply)
    {
        return Err(Error::Datagram);
    }
    let id = uuid::Uuid::from_slice(&bytes[5..21]).map_err(|_| Error::Datagram)?;
    let sequence = u64::from_be_bytes(bytes[21..29].try_into().map_err(|_| Error::Datagram)?);
    let length = usize::from(u16::from_be_bytes(
        bytes[29..31].try_into().map_err(|_| Error::Datagram)?,
    ));
    if id.is_nil() || sequence == 0 || sequence > i64::MAX as u64 || length != bytes.len() - HEADER
    {
        return Err(Error::Datagram);
    }
    Ok(DatagramPacket {
        mapping_id: id.to_string(),
        sequence,
        payload: bytes[HEADER..].to_vec(),
    })
}
impl DatagramPacket {
    pub const MAX_PAYLOAD: usize = MAX_PAYLOAD;
    pub fn mapping_key(mapping_id: &str) -> Result<[u8; 16], Error> {
        let id = uuid::Uuid::parse_str(mapping_id).map_err(|_| Error::Datagram)?;
        if id.is_nil() || id.to_string() != mapping_id {
            return Err(Error::Datagram);
        }
        Ok(*id.as_bytes())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        encode(self, false)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        decode(bytes, false)
    }
}
impl DatagramReply {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        encode(
            &DatagramPacket {
                mapping_id: self.mapping_id.clone(),
                sequence: self.sequence,
                payload: self.payload.clone(),
            },
            true,
        )
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let packet = decode(bytes, true)?;
        Ok(Self {
            mapping_id: packet.mapping_id,
            sequence: packet.sequence,
            payload: packet.payload,
        })
    }
}
#[derive(Default, Clone, Copy)]
pub struct ReplayWindow {
    high: u64,
    bits: u64,
}
impl ReplayWindow {
    pub fn accept(&mut self, sequence: u64) -> Result<(), Error> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(Error::Datagram);
        }
        if sequence > self.high {
            let shift = sequence - self.high;
            self.bits = self
                .bits
                .checked_shl(u32::try_from(shift).unwrap_or(u32::MAX))
                .unwrap_or(0)
                | 1;
            self.high = sequence;
            return Ok(());
        }
        let behind = self.high - sequence;
        if behind >= 64 || self.bits & (1u64 << behind) != 0 {
            return Err(Error::Datagram);
        }
        self.bits |= 1u64 << behind;
        Ok(())
    }
}
pub struct DatagramMapping {
    socket: UdpSocket,
    flow: ServiceFlowPermit,
    mapping_id: String,
    received: Mutex<ReplayWindow>,
    sent: Mutex<u64>,
}
impl DatagramMapping {
    pub async fn new(prepared: PreparedLocalTunnel) -> Result<Self, Error> {
        Self::from_target(prepared.flow, prepared.address, prepared.protocol,
            prepared.stream_id, prepared.challenge_deadline).await
    }
    pub async fn new_private(prepared: super::PreparedPrivateLocalTunnel) -> Result<Self, Error> {
        Self::from_target(prepared.flow, prepared.address, prepared.protocol,
            prepared.stream_id, prepared.challenge_deadline).await
    }
    async fn from_target(flow: ServiceFlowPermit, address: SocketAddr, protocol: String,
        stream_id: String, challenge_deadline: std::time::Instant) -> Result<Self, Error> {
        if protocol != "udp" {
            return Err(Error::Target);
        }
        flow.check_live()?;
        if std::time::Instant::now() >= challenge_deadline { return Err(rejected(ErrorCode::LeaseExpired).into()); }
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .map_err(|_| Error::Target)?;
        let socket = UdpSocket::bind(bind).await?;
        tokio::select! { biased;
            _=flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            _=tokio::time::sleep_until(challenge_deadline.into())=>return Err(rejected(ErrorCode::LeaseExpired).into()),
            connected=socket.connect(address)=>connected?,
        }
        flow.check_live()?;
        if std::time::Instant::now() >= challenge_deadline { return Err(rejected(ErrorCode::LeaseExpired).into()); }
        Ok(Self {
            socket,
            flow,
            mapping_id: stream_id,
            received: Mutex::new(ReplayWindow::default()),
            sent: Mutex::new(0),
        })
    }
    pub fn mapping_id(&self) -> &str {
        &self.mapping_id
    }
    pub async fn wait_stopped(&self) {
        self.flow.wait_stopped().await;
    }
    pub async fn send_packet(&self, packet: &DatagramPacket) -> Result<(), Error> {
        if packet.mapping_id != self.mapping_id || packet.payload.len() > MAX_PAYLOAD {
            return Err(Error::Datagram);
        }
        self.flow.check_live()?;
        {
            let mut window = self.received.lock().map_err(|_| Error::Datagram)?;
            let mut next = *window;
            next.accept(packet.sequence)?;
            // Native UDP drops on rate refusal; it never waits in a reliable queue.
            self.flow.try_charge(packet.payload.len())?;
            *window = next;
        }
        let sent = tokio::select! { biased;
            _=self.flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            sent=self.socket.send(&packet.payload)=>sent?,
        };
        if sent != packet.payload.len() {
            return Err(Error::Datagram);
        }
        self.flow.activity()?;
        Ok(())
    }
    pub async fn receive_reply(&self) -> Result<DatagramReply, Error> {
        self.flow.check_live()?;
        // One extra byte detects truncation at the allowed payload boundary.
        let mut buffer = [0; MAX_PAYLOAD + 1];
        let length = tokio::select! { biased;
            _=self.flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            length=self.socket.recv(&mut buffer)=>length?,
        };
        if length > MAX_PAYLOAD {
            return Err(Error::Datagram);
        }
        self.flow.try_charge(length)?;
        let mut sequence = self.sent.lock().map_err(|_| Error::Datagram)?;
        *sequence = sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Datagram)?;
        self.flow.activity()?;
        Ok(DatagramReply {
            mapping_id: self.mapping_id.clone(),
            sequence: *sequence,
            payload: buffer[..length].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_codec_checks_direction_exact_length_and_entire_packet_budget() -> Result<(), Error> {
        let mut packet = DatagramPacket {
            mapping_id: uuid::Uuid::new_v4().to_string(),
            sequence: 1,
            payload: vec![7; MAX_PAYLOAD],
        };
        let bytes = packet.encode()?;
        assert_eq!(bytes.len(), SERVICE_DATAGRAM_BYTES);
        assert_eq!(DatagramPacket::decode(&bytes)?.payload, packet.payload);
        assert!(DatagramReply::decode(&bytes).is_err());
        assert!(DatagramPacket::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(DatagramPacket::decode(&extra).is_err());
        packet.payload.push(0);
        assert!(packet.encode().is_err());
        packet.payload.clear();
        packet.sequence = 0;
        assert!(packet.encode().is_err());
        assert!(DatagramPacket::decode(&[0; 30]).is_err());
        Ok(())
    }
    #[test]
    fn replay_window_accepts_bounded_reordering_and_rejects_duplicates_and_overflow()
    -> Result<(), Error> {
        let mut window = ReplayWindow::default();
        window.accept(64)?;
        window.accept(1)?;
        window.accept(63)?;
        assert!(window.accept(64).is_err());
        assert!(window.accept(1).is_err());
        window.accept(65)?;
        assert!(window.accept(1).is_err());
        window.accept(i64::MAX as u64)?;
        assert!(window.accept(65).is_err());
        assert!(window.accept(0).is_err());
        assert!(window.accept(i64::MAX as u64 + 1).is_err());
        Ok(())
    }
}
