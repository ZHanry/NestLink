//! Thin product resource adapter over the supported Windows IP Helper API.
//! Wintun/tun-rs retain all driver, session, ring and packet implementation.
#![allow(unsafe_code)]
use super::{super::security, ProviderIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut,
};
use windows_sys::{
    Win32::{
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
    },
    core::GUID,
};

const MAX_ROWS: usize = 65_536;
const METRIC: u32 = 42420;
fn checked(result: u32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}
struct Allocation(*mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0) }
        }
    }
}
fn bounded(count: u32) -> io::Result<usize> {
    let count = count as usize;
    if count > MAX_ROWS {
        Err(io::Error::other(
            "native TUN observation table exceeded its bound",
        ))
    } else {
        Ok(count)
    }
}
pub fn guid_value(value: &str) -> io::Result<u128> {
    if !nestlink_protocol::valid_id(value) {
        return Err(security::denied());
    }
    u128::from_str_radix(&value.replace('-', ""), 16).map_err(|_| security::denied())
}
fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}
fn alias(row: &MIB_IF_ROW2) -> io::Result<String> {
    let length = row
        .Alias
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(security::denied)?;
    String::from_utf16(&row.Alias[..length]).map_err(|_| security::denied())
}
fn interfaces() -> io::Result<Vec<MIB_IF_ROW2>> {
    let mut table = null_mut();
    checked(unsafe { GetIfTable2(&mut table) })?;
    let _allocation = Allocation(table.cast());
    if table.is_null() {
        return Err(security::denied());
    }
    Ok(unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), bounded((*table).NumEntries)?)
    }
    .to_vec())
}
fn address(value: &SOCKADDR_INET) -> io::Result<IpAddr> {
    unsafe {
        match value.si_family {
            AF_INET => Ok(Ipv4Addr::from(value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()),
            AF_INET6 => Ok(Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte).into()),
            _ => Err(security::denied()),
        }
    }
}
fn sockaddr(value: IpAddr) -> SOCKADDR_INET {
    match value {
        IpAddr::V4(ip) => {
            let mut v = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            v.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            SOCKADDR_INET { Ipv4: v }
        }
        IpAddr::V6(ip) => {
            let mut v = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            v.sin6_addr.u.Byte = ip.octets();
            SOCKADDR_INET { Ipv6: v }
        }
    }
}
fn addresses() -> io::Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table = null_mut();
    checked(unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) })?;
    let _allocation = Allocation(table.cast());
    if table.is_null() {
        return Err(security::denied());
    }
    Ok(unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), bounded((*table).NumEntries)?)
    }
    .to_vec())
}
fn routes() -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table = null_mut();
    checked(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })?;
    let _allocation = Allocation(table.cast());
    if table.is_null() {
        return Err(security::denied());
    }
    Ok(unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), bounded((*table).NumEntries)?)
    }
    .to_vec())
}
fn host_bits(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
fn contains(network: IpAddr, prefix: u8, host: IpAddr) -> io::Result<bool> {
    let (network, host, bits) = match (network, host) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u128::from(u32::from(a)), u128::from(u32::from(b)), 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return Ok(false),
    };
    if prefix > bits {
        return Err(security::denied());
    }
    let shift = u32::from(bits - prefix);
    Ok(shift == 128 || (network >> shift) == (host >> shift))
}
/// Reject existing names/GUIDs, address collisions and nondefault routes which
/// would already capture any signed remote host. No preexisting link is used.
pub fn preflight(
    guid: &str,
    name: &str,
    local: &[IpAddr; 2],
    remote: &[IpAddr; 2],
) -> io::Result<()> {
    let guid = GUID::from_u128(guid_value(guid)?);
    for row in interfaces()? {
        if same_guid(&row.InterfaceGuid, &guid) || alias(&row)? == name {
            return Err(io::Error::other(
                "fresh TUN adapter identity already exists",
            ));
        }
    }
    for row in addresses()? {
        let ip = address(&row.Address)?;
        if local.contains(&ip) || remote.contains(&ip) {
            return Err(io::Error::other("signed TUN address is already configured"));
        }
    }
    for row in routes()? {
        if row.DestinationPrefix.PrefixLength == 0 {
            continue;
        }
        let network = address(&row.DestinationPrefix.Prefix)?;
        for host in remote {
            if contains(network, row.DestinationPrefix.PrefixLength, *host)? {
                return Err(io::Error::other(
                    "an existing specific route already captures a signed remote TUN host",
                ));
            }
        }
    }
    Ok(())
}
pub fn capture(
    guid: &str,
    name: &str,
    provider_sha256: [u8; 32],
) -> io::Result<Option<ProviderIdentity>> {
    let target = GUID::from_u128(guid_value(guid)?);
    let mut found = None;
    for row in interfaces()? {
        let same = same_guid(&row.InterfaceGuid, &target);
        if same || alias(&row)? == name {
            if !same || alias(&row)? != name || found.is_some() {
                return Err(io::Error::other(
                    "original TUN adapter GUID/name was replaced",
                ));
            }
            found = Some(ProviderIdentity {
                adapter_guid: guid.into(),
                name: name.into(),
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                mtu: 1280,
                provider_sha256,
                configuration_sha256: [0; 32],
            });
        }
    }
    Ok(found)
}
fn original(identity: &ProviderIdentity) -> io::Result<Option<MIB_IF_ROW2>> {
    let Some(current) = capture(
        &identity.adapter_guid,
        &identity.name,
        identity.provider_sha256,
    )?
    else {
        return Ok(None);
    };
    if current.index != identity.index || current.luid != identity.luid {
        return Err(io::Error::other(
            "original TUN adapter kernel identity was replaced",
        ));
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: identity.index,
        ..Default::default()
    };
    checked(unsafe { GetIfEntry2(&mut row) })?;
    if unsafe { row.InterfaceLuid.Value } != identity.luid
        || !same_guid(
            &row.InterfaceGuid,
            &GUID::from_u128(guid_value(&identity.adapter_guid)?),
        )
    {
        return Err(security::denied());
    }
    Ok(Some(row))
}
fn family(identity: &ProviderIdentity, family: u16) -> io::Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: NET_LUID_LH {
            Value: identity.luid,
        },
        InterfaceIndex: identity.index,
        ..Default::default()
    };
    checked(unsafe { GetIpInterfaceEntry(&mut row) })?;
    Ok(row)
}
/// This API is limited to the helper's already captured fresh original link.
pub fn isolate(identity: &ProviderIdentity) -> io::Result<()> {
    super::super::require_administrator_process()?;
    original(identity)?.ok_or_else(security::denied)?;
    for af in [AF_INET, AF_INET6] {
        let mut row = family(identity, af)?;
        row.AdvertisingEnabled = false;
        row.ForwardingEnabled = false;
        row.WeakHostSend = false;
        row.WeakHostReceive = false;
        row.UseAutomaticMetric = false;
        row.Metric = METRIC;
        row.NlMtu = 1280;
        row.ManagedAddressConfigurationSupported = false;
        row.OtherStatefulConfigurationSupported = false;
        row.AdvertiseDefaultRoute = false;
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.LinkLocalAddressBehavior = LinkLocalAlwaysOff;
        row.DadTransmits = 0;
        row.DisableDefaultRoutes = true;
        // IP Helper requires this ignored IPv4 member to be zero when setting.
        row.SitePrefixLength = 0;
        checked(unsafe { SetIpInterfaceEntry(&mut row) })?;
    }
    Ok(())
}
fn on_original(identity: &ProviderIdentity, luid: NET_LUID_LH, index: u32) -> bool {
    unsafe { luid.Value == identity.luid && index == identity.index }
}
/// Remove automatic routes only from this fresh link. Retain its exact local
/// /32 and /128 kernel host routes, then install only signed remote hosts.
pub fn install_routes(
    identity: &ProviderIdentity,
    local: &[IpAddr; 2],
    remote: &[IpAddr; 2],
) -> io::Result<()> {
    super::super::require_administrator_process()?;
    original(identity)?.ok_or_else(security::denied)?;
    for row in routes()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) {
            let destination = address(&row.DestinationPrefix.Prefix)?;
            if row.DestinationPrefix.PrefixLength == host_bits(destination)
                && local.contains(&destination)
            {
                continue;
            }
            checked(unsafe { DeleteIpForwardEntry2(&row) })?;
        }
    }
    for host in remote {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH {
            Value: identity.luid,
        };
        row.InterfaceIndex = identity.index;
        row.DestinationPrefix.Prefix = sockaddr(*host);
        row.DestinationPrefix.PrefixLength = host_bits(*host);
        row.NextHop = sockaddr(if host.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        });
        row.SitePrefixLength = 0;
        row.Metric = METRIC;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row.Origin = NlroManual;
        checked(unsafe { CreateIpForwardEntry2(&row) })?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyState {
    family: u16,
    mtu: u32,
    metric: u32,
    automatic_metric: bool,
    forwarding: bool,
    weak_send: bool,
    weak_receive: bool,
    advertising: bool,
    default_advertising: bool,
    router_discovery: i32,
    link_local: i32,
    dad: u32,
    managed: bool,
    other_stateful: bool,
    disable_default_routes: bool,
}
impl FamilyState {
    fn from(row: MIB_IPINTERFACE_ROW) -> Self {
        Self {
            family: row.Family,
            mtu: row.NlMtu,
            metric: row.Metric,
            automatic_metric: row.UseAutomaticMetric,
            forwarding: row.ForwardingEnabled,
            weak_send: row.WeakHostSend,
            weak_receive: row.WeakHostReceive,
            advertising: row.AdvertisingEnabled,
            default_advertising: row.AdvertiseDefaultRoute,
            router_discovery: row.RouterDiscoveryBehavior,
            link_local: row.LinkLocalAddressBehavior,
            dad: row.DadTransmits,
            managed: row.ManagedAddressConfigurationSupported,
            other_stateful: row.OtherStatefulConfigurationSupported,
            disable_default_routes: row.DisableDefaultRoutes,
        }
    }
    fn isolated(&self) -> bool {
        self.mtu == 1280
            && self.metric == METRIC
            && !self.automatic_metric
            && !self.forwarding
            && !self.weak_send
            && !self.weak_receive
            && !self.advertising
            && !self.default_advertising
            && self.router_discovery == RouterDiscoveryDisabled
            && self.link_local == LinkLocalAlwaysOff
            && self.dad == 0
            && !self.managed
            && !self.other_stateful
            && self.disable_default_routes
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressState {
    ip: IpAddr,
    prefix: u8,
    prefix_origin: i32,
    suffix_origin: i32,
    dad: i32,
    skip: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteState {
    destination: IpAddr,
    prefix: u8,
    next_hop: IpAddr,
    metric: u32,
    protocol: i32,
    origin: i32,
    loopback: bool,
    autoconfigure: bool,
    publish: bool,
    immortal: bool,
    site_prefix: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    mtu: u32,
    interface_type: u32,
    tunnel_type: i32,
    admin_status: i32,
    families: Vec<FamilyState>,
    addresses: Vec<AddressState>,
    routes: Vec<RouteState>,
}
impl Snapshot {
    pub fn digest(&self) -> io::Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }
    pub fn verify(&self, local: &[IpAddr; 2], remote: &[IpAddr; 2]) -> io::Result<()> {
        if self.mtu != 1280
            || self.families.len() != 2
            || self.families.iter().map(|row| row.family).collect::<Vec<_>>() != [AF_INET, AF_INET6]
            || !self.families.iter().all(FamilyState::isolated)
            || self.addresses.len() != 2
            || self.routes.is_empty()
            || self.routes.len() > 4
        {
            return Err(security::denied());
        }
        for host in local {
            if self.addresses.iter().filter(|row| row.ip == *host).count() != 1 {
                return Err(security::denied());
            }
        }
        for row in &self.addresses {
            if !local.contains(&row.ip)
                || row.prefix != host_bits(row.ip)
                || row.prefix_origin != IpPrefixOriginManual
                || row.suffix_origin != IpSuffixOriginManual
                || row.dad != IpDadStatePreferred
                || row.skip
            {
                return Err(security::denied());
            }
        }
        for row in &self.routes {
            if row.prefix != host_bits(row.destination)
                || (!local.contains(&row.destination) && !remote.contains(&row.destination))
                || !row.next_hop.is_unspecified()
                || row.autoconfigure
                || row.publish
            {
                return Err(security::denied());
            }
            if remote.contains(&row.destination)
                && (row.metric != METRIC
                    || row.protocol != MIB_IPPROTO_NETMGMT
                    || row.origin != NlroManual)
            {
                return Err(security::denied());
            }
        }
        for host in remote {
            if !self.routes.iter().any(|row| row.destination == *host) {
                return Err(security::denied());
            }
        }
        Ok(())
    }
}
pub fn inspect(identity: &ProviderIdentity) -> io::Result<Option<Snapshot>> {
    let Some(row) = original(identity)? else {
        return Ok(None);
    };
    let families = [AF_INET, AF_INET6]
        .into_iter()
        .map(|af| family(identity, af).map(FamilyState::from))
        .collect::<io::Result<Vec<_>>>()?;
    let mut hosts = Vec::new();
    for row in addresses()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) {
            hosts.push(AddressState {
                ip: address(&row.Address)?,
                prefix: row.OnLinkPrefixLength,
                prefix_origin: row.PrefixOrigin,
                suffix_origin: row.SuffixOrigin,
                dad: row.DadState,
                skip: row.SkipAsSource,
            });
        }
    }
    hosts.sort();
    let mut paths = Vec::new();
    for row in routes()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) {
            paths.push(RouteState {
                destination: address(&row.DestinationPrefix.Prefix)?,
                prefix: row.DestinationPrefix.PrefixLength,
                next_hop: address(&row.NextHop)?,
                metric: row.Metric,
                protocol: row.Protocol,
                origin: row.Origin,
                loopback: row.Loopback,
                autoconfigure: row.AutoconfigureAddress,
                publish: row.Publish,
                immortal: row.Immortal,
                site_prefix: row.SitePrefixLength,
            });
        }
    }
    paths.sort();
    // Re-read the exact identity after table snapshots; replacement is terminal.
    original(identity)?.ok_or_else(security::denied)?;
    Ok(Some(Snapshot {
        mtu: row.Mtu,
        interface_type: row.Type,
        tunnel_type: row.TunnelType,
        admin_status: row.AdminStatus,
        families,
        addresses: hosts,
        routes: paths,
    }))
}

/// Interface disappearance alone cannot clear a durable address/route record.
/// Observe all original kernel identifiers, and never mutate a surviving row.
pub fn absent(identity: &ProviderIdentity) -> io::Result<bool> {
    if original(identity)?.is_some() {
        return Ok(false);
    }
    if addresses()?.iter().any(|row| on_original(identity,row.InterfaceLuid,row.InterfaceIndex))
        || routes()?.iter().any(|row| on_original(identity,row.InterfaceLuid,row.InterfaceIndex))
    {
        return Ok(false);
    }
    // A name/GUID replacement during those two table reads is also terminal.
    Ok(original(identity)?.is_none())
}
