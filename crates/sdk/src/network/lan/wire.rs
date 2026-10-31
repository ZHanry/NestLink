//! Product discovery framing uses the existing Prost and etherparse codecs.
//! It is always carried as ordinary unicast IP through the original admission.
use super::{denied, wall_ms};
use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use prost::Message;
use std::{io, net::Ipv4Addr};

pub(super) const UDP_MAX: usize = nestlink_protocol::network_datagram::PACKET_BYTES;
pub(super) const MAX_RECORDS: usize = 32;

#[derive(Clone, PartialEq, Message)]
pub(super) struct Envelope {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(string, tag = "2")]
    pub space: String,
    #[prost(bytes = "vec", tag = "3")]
    pub business: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub sequence: u64,
    #[prost(uint64, tag = "5")]
    pub sent_ms: u64,
    #[prost(uint32, tag = "6")]
    pub hops: u32,
    #[prost(oneof = "Body", tags = "7,8,9,10")]
    pub body: Option<Body>,
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub(super) enum Body {
    #[prost(message, tag = "7")]
    Request(UdpRequest),
    #[prost(message, tag = "8")]
    Reply(UdpRequest),
    #[prost(message, tag = "9")]
    Service(Service),
    #[prost(message, tag = "10")]
    Withdraw(Service),
}
#[derive(Clone, PartialEq, Message)]
pub(super) struct UdpRequest {
    #[prost(string, tag = "1")]
    pub rule: String,
    #[prost(uint64, tag = "2")]
    pub flow: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    #[prost(bool, tag = "4")]
    pub discovery: bool,
}
#[derive(Clone, PartialEq, Message)]
pub(super) struct Service {
    #[prost(string, tag = "1")]
    pub service_type: String,
    #[prost(string, tag = "2")]
    pub instance: String,
    #[prost(uint32, tag = "3")]
    pub port: u32,
    #[prost(message, repeated, tag = "4")]
    pub properties: Vec<Txt>,
}
#[derive(Clone, PartialEq, Message)]
pub(super) struct Txt {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub value: Option<Vec<u8>>,
}
/// Bind the reused opaque fragment owner to the exact application flow and
/// forwarding mode as well as the original business digest. Fragments from
/// different clients, rules, replies or discovery probes cannot be combined.
pub(super) fn flow_binding(
    business: [u8; 32],
    rule: &str,
    flow: u64,
    reply: bool,
    discovery: bool,
) -> [u8; 32] {
    let mut input = b"NestLink/LAN-UDP-flow/v1\0".to_vec();
    input.extend_from_slice(&business);
    input.extend_from_slice(&flow.to_be_bytes());
    input.extend_from_slice(&[u8::from(reply), u8::from(discovery)]);
    input.extend_from_slice(rule.as_bytes());
    nestlink_identity::digest(&input)
}
pub(super) fn packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
    envelope: &Envelope,
) -> io::Result<Vec<u8>> {
    let body = envelope.encode_to_vec();
    let builder = PacketBuilder::ipv4(source.octets(), destination.octets(), 16).udp(port, port);
    if builder.size(body.len()) > super::super::packet_access::PACKET_MTU {
        return Err(denied("discovery envelope exceeds the original packet MTU"));
    }
    let mut packet = Vec::with_capacity(builder.size(body.len()));
    builder.write(&mut packet, &body).map_err(denied)?;
    Ok(packet)
}
pub(super) fn parse(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
) -> io::Result<Envelope> {
    let sliced = SlicedPacket::from_ip(packet).map_err(denied)?;
    let Some(NetSlice::Ipv4(ip)) = sliced.net else {
        return Err(denied("LAN envelopes require exact IPv4 hosts"));
    };
    let header = ip.header();
    let Some(TransportSlice::Udp(udp)) = sliced.transport else {
        return Err(denied("LAN envelope is not UDP"));
    };
    if header.source_addr() != source
        || header.destination_addr() != destination
        || usize::from(header.total_len()) != packet.len()
        || packet.len() > 1280
        || header.is_fragmenting_payload()
        || !header.options().is_empty()
        || ip.extensions().auth.is_some()
        || header.ttl() == 0
        || header.header_checksum() != header.to_header().calc_header_checksum()
        || udp.source_port() != port
        || udp.destination_port() != port
        || usize::from(udp.length()) != ip.payload().payload.len()
        || udp.checksum() == 0
        || udp.checksum()
            != udp
                .to_header()
                .calc_checksum_ipv4_raw(source.octets(), destination.octets(), udp.payload())
                .map_err(denied)?
    {
        return Err(denied(
            "LAN envelope packet endpoint, fragment or checksum mismatch",
        ));
    }
    let envelope = Envelope::decode(udp.payload()).map_err(denied)?;
    if envelope.encode_to_vec() != udp.payload() {
        return Err(denied("noncanonical or unknown LAN envelope fields"));
    }
    Ok(envelope)
}
/// Select only the reserved virtual-host tuple. Malformed envelopes on this
/// tuple still go to the strict parser and can never fall through to a TUN.
pub(super) fn transport_matches(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
) -> bool {
    let Ok(sliced) = SlicedPacket::from_ip(packet) else {
        return false;
    };
    matches!((sliced.net, sliced.transport),
        (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp)))
        if ip.header().source_addr() == source
            && ip.header().destination_addr() == destination
            && udp.source_port() == port && udp.destination_port() == port)
}
#[derive(Default)]
pub(super) struct Replay {
    highest: u64,
    seen: u64,
}
impl Replay {
    pub(super) fn admit(
        &mut self,
        envelope: &Envelope,
        space: &str,
        business: &[u8; 32],
    ) -> io::Result<()> {
        let now = wall_ms()?;
        if envelope.version != 1
            || envelope.space != space
            || envelope.business.as_slice() != business.as_slice()
            || envelope.sequence == 0
            || envelope.hops != 1
            || envelope.body.is_none()
            || envelope.sent_ms > now
            || now - envelope.sent_ms >= 2000
        {
            return Err(denied("cross-space, stale, looped or unbound LAN envelope"));
        }
        let sequence = envelope.sequence;
        if sequence > self.highest {
            let advance = sequence - self.highest;
            self.seen = if advance >= 64 {
                1
            } else {
                (self.seen << advance) | 1
            };
            self.highest = sequence;
        } else {
            let behind = self.highest - sequence;
            if behind >= 64 || self.seen & (1 << behind) != 0 {
                return Err(denied("LAN replay or stale sequence"));
            }
            self.seen |= 1 << behind;
        }
        Ok(())
    }
}
