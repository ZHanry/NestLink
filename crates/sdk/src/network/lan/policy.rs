use super::denied;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io, net::{Ipv4Addr, SocketAddrV4}};

/// A locally reviewed, owner-private opt-in, independent from the signed
/// NetworkAccess grant. No policy is synthesized from space membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanPolicy {
    pub schema_version: u16,
    pub space_id: String,
    /// Exact physical LAN interface, checked again before every local action.
    pub interface_index: u32,
    pub interface_address: Ipv4Addr,
    pub local_prefix: String,
    /// Separately granted unicast UDP port between the original virtual hosts.
    pub transport_port: u16,
    pub packets_per_second: u16,
    pub bytes_per_second: u32,
    pub udp: Vec<UdpRule>,
    pub mdns: Vec<MdnsRule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpRule {
    /// The same explicit rule ID identifies the two approved LAN adapters.
    pub id: String,
    pub port: u16,
    /// Only this actual LAN server may answer a forwarded request.
    pub local_target: SocketAddrV4,
    pub allow_local_to_peer: bool,
    pub allow_peer_to_local: bool,
    pub allow_broadcast_discovery: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdnsRule {
    pub service_type: String,
    pub port: u16,
    /// Export only a service running on this adapter host. Imported records
    /// refer to the other authenticated virtual host, never an advertised LAN IP.
    pub allow_export: bool,
    pub allow_import: bool,
}
impl LanPolicy {
    pub fn validate(&self) -> io::Result<()> {
        let prefix = self.prefix()?;
        let mut ports = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut services = BTreeSet::new();
        if self.schema_version != 1 || !nestlink_protocol::valid_id(&self.space_id)
            || self.interface_index == 0 || !self.interface_address.is_private()
            || !(16..=30).contains(&prefix.prefix_len())
            || !prefix.contains(&self.interface_address)
            || [prefix.network(), prefix.broadcast()].contains(&self.interface_address)
            || self.transport_port < 1024 || self.transport_port == 5353
            || !(1..=100).contains(&self.packets_per_second)
            || !(1024..=131_072).contains(&self.bytes_per_second)
            || self.udp.len() > 8 || self.mdns.len() > 8
            || self.udp.is_empty() && self.mdns.is_empty()
        { return Err(denied("invalid bounded explicit LAN policy")); }
        for rule in &self.udp {
            if !name(&rule.id, 32) || !ids.insert(&rule.id)
                || rule.port < 1024 || [self.transport_port,5353].contains(&rule.port)
                || !ports.insert(rule.port) || rule.local_target.port() != rule.port
                || !prefix.contains(rule.local_target.ip())
                || [prefix.network(),prefix.broadcast(),self.interface_address].contains(rule.local_target.ip())
                || !rule.allow_local_to_peer && !rule.allow_peer_to_local
            { return Err(denied("UDP discovery requires unique ports and one exact other LAN server")); }
        }
        for rule in &self.mdns {
            let labels:Vec<_> = rule.service_type.split('.').collect();
            if labels.len()!=4 || !labels[0].starts_with('_')
                || !name(&labels[0][1..],15) || !["_tcp","_udp"].contains(&labels[1])
                || labels[2]!="local" || !labels[3].is_empty()
            {return Err(denied("only explicit DNS-SD service types under .local. are allowed"));}
            if rule.port==0 || !services.insert((&rule.service_type,rule.port))
                || !rule.allow_export && !rule.allow_import
            {return Err(denied("invalid explicit DNS-SD port or direction"));}
        }
        Ok(())
    }
    pub(super) fn prefix(&self) -> io::Result<ipnet::Ipv4Net> {
        let value:ipnet::Ipv4Net=self.local_prefix.parse().map_err(denied)?;
        if value.to_string()!=self.local_prefix || value.network()!=value.addr() {
            return Err(denied("canonical LAN prefix required"));
        }
        Ok(value)
    }
    /// Read-only interface observation. A changed address/index permanently
    /// terminates the resident command; it cannot silently choose another LAN.
    pub fn check_interface(&self) -> io::Result<()> {
        let matches = nestlink_platform_network::path::NetworkPathManager::interfaces()?.into_iter().filter(|item| {
            item.up && item.index==self.interface_index && item.addresses.contains(&std::net::IpAddr::V4(self.interface_address))
        }).count();
        if matches!=1 {return Err(denied("original selected LAN interface changed or disappeared"));}
        Ok(())
    }
}
pub(super) fn name(value:&str, maximum:usize)->bool {
    !value.is_empty() && value.len()<=maximum && value.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'-' || b==b'_')
}
