//! The maintained strict etherparse codec owns wire parsing and checksums.
//! NestLink's policy rejects semantics that could change an OS destination.
use super::{FlowKey, PACKET_MTU, denied};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use nestlink_protocol::network::IpProtocol;
use std::{io, net::IpAddr};

pub(super) struct Packet {
    pub(super) key: FlowKey,
    pub(super) protocol: IpProtocol,
    pub(super) tcp: bool,
    pub(super) syn: bool,
    pub(super) ack: bool,
    pub(super) rst: bool,
    pub(super) fin: bool,
    pub(super) echo_request: bool,
    pub(super) echo_reply: bool,
}
pub(super) fn packet(bytes: &[u8]) -> io::Result<Packet> {
    if bytes.is_empty() || bytes.len() > PACKET_MTU {
        return Err(denied("raw IP packet exceeds the managed MTU"));
    }
    let sliced = SlicedPacket::from_ip(bytes).map_err(denied)?;
    let (source, destination, protocol, payload_length) = match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let header = ip.header();
            if usize::from(header.total_len()) != bytes.len()
                || header.is_fragmenting_payload()
                || !header.options().is_empty()
                || ip.extensions().auth.is_some()
                || header.ttl() == 0
                || header.header_checksum() != header.to_header().calc_header_checksum()
            {
                return Err(denied(
                    "fragmented, source-routed, truncated or corrupt IPv4 is denied",
                ));
            }
            (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
                ip.payload().ip_number.0,
                ip.payload().payload.len(),
            )
        }
        Some(NetSlice::Ipv6(ip)) => {
            let header = ip.header();
            // Reject every fragment (including atomic), routing, AH, opaque
            // option and extension chain before looking at transport ports.
            // There is no unbounded IP fragment cache or lax parser fallback.
            if 40 + usize::from(header.payload_length()) != bytes.len()
                || header.payload_length() == 0
                || header.hop_limit() == 0
                || !ip.extensions().is_empty()
                || ip.payload().fragmented
            {
                return Err(denied(
                    "IPv6 fragments, extensions, jumbograms or truncation are denied",
                ));
            }
            (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
                ip.payload().ip_number.0,
                ip.payload().payload.len(),
            )
        }
        _ => return Err(denied("a complete IPv4 or IPv6 packet is required")),
    };
    if [source, destination].iter().any(|ip| {
        ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
    }) {
        return Err(denied(
            "raw IP endpoints must be non-loopback unicast addresses",
        ));
    }
    let mut packet = Packet {
        key: FlowKey {
            source,
            destination,
            protocol,
            source_port: 0,
            destination_port: 0,
        },
        protocol: IpProtocol::Udp,
        tcp: false,
        syn: false,
        ack: false,
        rst: false,
        fin: false,
        echo_request: false,
        echo_reply: false,
    };
    match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let checksum = match (source, destination) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    tcp.calc_checksum_ipv4(source.octets(), destination.octets())
                }
                (IpAddr::V6(source), IpAddr::V6(destination)) => {
                    tcp.calc_checksum_ipv6(source.octets(), destination.octets())
                }
                _ => return Err(denied("mixed raw IP address families")),
            }
            .map_err(denied)?;
            if protocol != 6 || tcp.slice().len() != payload_length || tcp.checksum() != checksum {
                return Err(denied("invalid raw TCP checksum or length"));
            }
            packet.protocol = IpProtocol::Tcp;
            packet.key.source_port = tcp.source_port();
            packet.key.destination_port = tcp.destination_port();
            packet.tcp = true;
            packet.syn = tcp.syn();
            packet.ack = tcp.ack();
            packet.rst = tcp.rst();
            packet.fin = tcp.fin();
        }
        Some(TransportSlice::Udp(udp)) => {
            let checksum = match (source, destination) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => udp
                    .to_header()
                    .calc_checksum_ipv4_raw(source.octets(), destination.octets(), udp.payload()),
                (IpAddr::V6(source), IpAddr::V6(destination)) => udp
                    .to_header()
                    .calc_checksum_ipv6_raw(source.octets(), destination.octets(), udp.payload()),
                _ => return Err(denied("mixed raw IP address families")),
            }
            .map_err(denied)?;
            if protocol != 17
                || usize::from(udp.length()) != payload_length
                || (udp.checksum() == 0 && source.is_ipv6())
                || (udp.checksum() != 0 && udp.checksum() != checksum)
            {
                return Err(denied("invalid raw UDP checksum or length"));
            }
            packet.key.source_port = udp.source_port();
            packet.key.destination_port = udp.destination_port();
        }
        Some(TransportSlice::Icmpv4(icmp)) if source.is_ipv4() && protocol == 1 => {
            if icmp.slice().len() != payload_length
                || icmp.checksum() != icmp.icmp_type().calc_checksum(icmp.payload())
            {
                return Err(denied("invalid raw ICMPv4 checksum or length"));
            }
            packet.protocol = IpProtocol::IcmpV4;
            match icmp.icmp_type() {
                etherparse::Icmpv4Type::EchoRequest(echo) => {
                    packet.echo_request = true;
                    packet.key.source_port = echo.id;
                    packet.key.destination_port = echo.seq;
                }
                etherparse::Icmpv4Type::EchoReply(echo) => {
                    packet.echo_reply = true;
                    packet.key.source_port = echo.seq;
                    packet.key.destination_port = echo.id;
                }
                _ => {
                    return Err(denied(
                        "raw ICMPv4 requires an explicitly authorized echo exchange",
                    ));
                }
            }
        }
        Some(TransportSlice::Icmpv6(icmp)) if source.is_ipv6() && protocol == 58 => {
            let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) else {
                return Err(denied("mixed raw ICMPv6 address families"));
            };
            if icmp.slice().len() != payload_length
                || icmp.checksum()
                    != icmp
                        .icmp_type()
                        .calc_checksum(source.octets(), destination.octets(), icmp.payload())
                        .map_err(denied)?
            {
                return Err(denied("invalid raw ICMPv6 checksum or length"));
            }
            packet.protocol = IpProtocol::IcmpV6;
            match icmp.icmp_type() {
                etherparse::Icmpv6Type::EchoRequest(echo) => {
                    packet.echo_request = true;
                    packet.key.source_port = echo.id;
                    packet.key.destination_port = echo.seq;
                }
                etherparse::Icmpv6Type::EchoReply(echo) => {
                    packet.echo_reply = true;
                    packet.key.source_port = echo.seq;
                    packet.key.destination_port = echo.id;
                }
                _ => {
                    return Err(denied(
                        "raw ICMPv6 control and neighbor discovery never enter the managed tunnel",
                    ));
                }
            }
        }
        _ => return Err(denied("unknown or opaque raw transport protocol is denied")),
    }
    if matches!(packet.protocol, IpProtocol::Tcp | IpProtocol::Udp)
        && (packet.key.source_port == 0 || packet.key.destination_port == 0)
    {
        return Err(denied("raw TCP/UDP endpoints require nonzero ports"));
    }
    Ok(packet)
}
