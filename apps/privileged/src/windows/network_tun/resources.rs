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
// The pinned Wintun 0.14.1 driver reports its fixed NDIS packet capacity here;
// the separately writable per-family IP MTU must still be exactly 1280.
const WINTUN_LINK_MTU: u32 = 65_535;
const WINTUN_INTERFACE_TYPE: u32 = 53; // IF_TYPE_PROP_VIRTUAL
const LOCAL_HOST_ROUTE_METRIC: u32 = 256;
fn checked(result: u32, operation: &str) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::from_raw_os_error(result as i32);
        Err(io::Error::new(
            error.kind(),
            format!("{operation}: {error} (Win32 {result})"),
        ))
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
    checked(unsafe { GetIfTable2(&mut table) }, "GetIfTable2")?;
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
    checked(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) },
        "GetUnicastIpAddressTable",
    )?;
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
    checked(
        unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) },
        "GetIpForwardTable2",
    )?;
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
pub(super) fn original(identity: &ProviderIdentity) -> io::Result<Option<MIB_IF_ROW2>> {
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
    checked(unsafe { GetIfEntry2(&mut row) }, "GetIfEntry2")?;
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
    optional_family(identity, family)?.ok_or_else(|| io::Error::other(format!(
        "original TUN IP interface family {family} is absent"
    )))
}
fn optional_family(identity: &ProviderIdentity, family: u16) -> io::Result<Option<MIB_IPINTERFACE_ROW>> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: NET_LUID_LH {
            Value: identity.luid,
        },
        InterfaceIndex: identity.index,
        ..Default::default()
    };
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result == 1168 { return Ok(None); } // ERROR_NOT_FOUND: the IP layer was withdrawn.
    checked(result, &format!("GetIpInterfaceEntry family {family}"))?;
    Ok(Some(row))
}

/// Independent IPv4 autoconfiguration observation. AdapterName is the OS
/// adapter GUID; both it and Index must match the already captured fresh link.
/// Own aligned storage for the complete bounded pointer list and validate each
/// next pointer before reading it. No OS pointer or buffer escapes this call.
fn ipv4_dhcp(identity: &ProviderIdentity) -> io::Result<bool> {
    optional_ipv4_dhcp(identity)?.ok_or_else(|| io::Error::other("original IPv4 TUN adapter DHCP observation missing"))
}
fn optional_ipv4_dhcp(identity: &ProviderIdentity) -> io::Result<Option<bool>> {
    const MAX_BYTES: usize = 4 * 1024 * 1024;
    const BUFFER_OVERFLOW: u32 = 111;
    let mut size = 0_u32;
    let result = unsafe { GetAdaptersInfo(null_mut(), &mut size) };
    if result != BUFFER_OVERFLOW {
        checked(result, "GetAdaptersInfo size")?;
        return Err(security::denied());
    }
    for _ in 0..3 {
        let requested = size as usize;
        let row_size = std::mem::size_of::<IP_ADAPTER_INFO>();
        if requested < row_size || requested > MAX_BYTES {
            return Err(io::Error::other(
                "IPv4 adapter observation exceeded its bound",
            ));
        }
        let mut storage = vec![IP_ADAPTER_INFO::default(); requested.div_ceil(row_size)];
        let capacity = storage.len() * row_size;
        size = u32::try_from(capacity).map_err(|_| security::denied())?;
        let result = unsafe { GetAdaptersInfo(storage.as_mut_ptr(), &mut size) };
        if result == BUFFER_OVERFLOW {
            continue;
        }
        checked(result, "GetAdaptersInfo original TUN DHCP state")?;
        let start = storage.as_ptr().addr();
        let returned = size as usize;
        if returned < row_size || returned > capacity {
            return Err(security::denied());
        }
        let end = start.checked_add(returned).ok_or_else(security::denied)?;
        let mut current = storage.as_ptr();
        let mut visited = std::collections::BTreeSet::new();
        let mut found = None;
        while !current.is_null() {
            let address = current.addr();
            if address < start
                || address.checked_add(row_size).is_none_or(|next| next > end)
                || !address.is_multiple_of(std::mem::align_of::<IP_ADAPTER_INFO>())
                || visited.len() >= MAX_ROWS
                || !visited.insert(address)
            {
                return Err(security::denied());
            }
            // SAFETY: the pointer is aligned and checked to cover one fully
            // initialized ABI row inside this still-owned allocation.
            let row = unsafe { &*current };
            let length = row
                .AdapterName
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(security::denied)?;
            let name = String::from_utf8(
                row.AdapterName[..length]
                    .iter()
                    .map(|byte| byte.to_ne_bytes()[0])
                    .collect(),
            )
            .map_err(|_| security::denied())?;
            let name = name
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
                .unwrap_or(&name);
            let same = name.eq_ignore_ascii_case(&identity.adapter_guid);
            if same || row.Index == identity.index {
                if !same || row.Index != identity.index || found.is_some() {
                    return Err(security::denied());
                }
                found = Some(row.DhcpEnabled != 0);
            }
            current = row.Next;
        }
        return Ok(found);
    }
    Err(io::Error::other(
        "IPv4 adapter inventory changed beyond its bounded retry budget",
    ))
}

/// This API is limited to the helper's already captured fresh original link.
pub fn isolate(identity: &ProviderIdentity) -> io::Result<()> {
    super::super::require_administrator_process()?;
    original(identity)?.ok_or_else(security::denied)?;
    for af in [AF_INET, AF_INET6] {
        let mut row = family(identity, af)?;
        // A family can reject a specific member with the otherwise opaque
        // ERROR_INVALID_PARAMETER. Keep each required change attributable;
        // partial application still closes only our new original adapter.
        type Update = fn(&mut MIB_IPINTERFACE_ROW);
        let changes: [(&str, Update); 13] = [
            ("AdvertisingEnabled", |row| row.AdvertisingEnabled = false),
            ("ForwardingEnabled", |row| row.ForwardingEnabled = false),
            ("WeakHostSend", |row| row.WeakHostSend = false),
            ("WeakHostReceive", |row| row.WeakHostReceive = false),
            ("UseAutomaticMetric", |row| row.UseAutomaticMetric = false),
            ("Metric", |row| row.Metric = METRIC),
            ("NlMtu", |row| row.NlMtu = 1280),
            ("ManagedAddressConfigurationSupported", |row| {
                row.ManagedAddressConfigurationSupported = false
            }),
            ("OtherStatefulConfigurationSupported", |row| {
                row.OtherStatefulConfigurationSupported = false
            }),
            ("AdvertiseDefaultRoute", |row| {
                row.AdvertiseDefaultRoute = false
            }),
            ("RouterDiscoveryBehavior", |row| {
                row.RouterDiscoveryBehavior = RouterDiscoveryDisabled
            }),
            ("DadTransmits", |row| row.DadTransmits = 0),
            ("DisableDefaultRoutes", |row| {
                row.DisableDefaultRoutes = true
            }),
        ];
        for (field, update) in changes {
            update(&mut row);
            // Wintun rejects LinkLocalAlwaysOff in both address families. Use
            // the documented unchanged setter sentinel; effective isolation
            // still requires the complete exact manual-host/route inventory.
            // Any extra generated address fails before packet handoff and on
            // every later observation; no link-local packet is authorized.
            row.LinkLocalAddressBehavior = LinkLocalUnchanged;
            if af == AF_INET {
                // IP Helper requires this ignored IPv4 member to be zero.
                row.SitePrefixLength = 0;
            }
            checked(
                unsafe { SetIpInterfaceEntry(&mut row) },
                &format!("SetIpInterfaceEntry family {af} member {field}"),
            )?;
        }
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
            checked(
                unsafe { DeleteIpForwardEntry2(&row) },
                "DeleteIpForwardEntry2 on fresh original adapter",
            )?;
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
        // InitializeIpForwardEntry deliberately defaults these to TRUE. A
        // signed remote host is neither a local loopback nor an advertised or
        // address-producing prefix; make every such property explicit.
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row.Origin = NlroManual;
        checked(
            unsafe { CreateIpForwardEntry2(&row) },
            &format!("CreateIpForwardEntry2 signed host {host}"),
        )?;
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
            && [LinkLocalAlwaysOff, LinkLocalDelayed, LinkLocalAlwaysOn].contains(&self.link_local)
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
impl AddressState {
    fn from(row: MIB_UNICASTIPADDRESS_ROW) -> io::Result<Self> {
        Ok(Self {
            ip: address(&row.Address)?, prefix: row.OnLinkPrefixLength,
            prefix_origin: row.PrefixOrigin, suffix_origin: row.SuffixOrigin,
            dad: row.DadState, skip: row.SkipAsSource,
        })
    }
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
impl RouteState {
    fn from(row: MIB_IPFORWARD_ROW2) -> io::Result<Self> {
        Ok(Self {
            destination: address(&row.DestinationPrefix.Prefix)?,
            prefix: row.DestinationPrefix.PrefixLength, next_hop: address(&row.NextHop)?,
            metric: row.Metric, protocol: row.Protocol, origin: row.Origin,
            loopback: row.Loopback, autoconfigure: row.AutoconfigureAddress,
            publish: row.Publish, immortal: row.Immortal, site_prefix: row.SitePrefixLength,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    link_mtu: u32,
    interface_type: u32,
    tunnel_type: i32,
    admin_status: i32,
    ipv4_dhcp_enabled: bool,
    families: Vec<FamilyState>,
    addresses: Vec<AddressState>,
    routes: Vec<RouteState>,
}
impl Snapshot {
    pub fn digest(&self) -> io::Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }
    fn permits_recovery_remainder(&self, families: &[FamilyState], hosts: &[AddressState], paths: &[RouteState], dhcp: Option<bool>) -> bool {
        fn subset<T: PartialEq>(remaining: &[T], original: &[T]) -> bool {
            remaining.len() <= original.len() && remaining.iter().all(|row| original.contains(row)
                && remaining.iter().filter(|v| *v == row).count() <= original.iter().filter(|v| *v == row).count())
        }
        subset(families, &self.families) && subset(hosts, &self.addresses) && subset(paths, &self.routes)
            && match dhcp {
                Some(enabled) => enabled == self.ipv4_dhcp_enabled,
                None => !families.iter().any(|row| row.family == AF_INET),
            }
    }
    pub fn verify(&self, local: &[IpAddr; 2], remote: &[IpAddr; 2]) -> io::Result<()> {
        if self.link_mtu != WINTUN_LINK_MTU
            || self.interface_type != WINTUN_INTERFACE_TYPE
            || self.tunnel_type != 0
            || self.admin_status != 1
            || self.ipv4_dhcp_enabled
            || self.families.len() != 2
            || self
                .families
                .iter()
                .map(|row| row.family)
                .collect::<Vec<_>>()
                != [AF_INET, AF_INET6]
            || !self.families.iter().all(FamilyState::isolated)
            || self.addresses.len() != 2
            || self.routes.len() != 4
        {
            return Err(io::Error::other(format!(
                "original TUN isolation snapshot differs from the exact required state: {self:?}"
            )));
        }
        for host in local {
            if self.addresses.iter().filter(|row| row.ip == *host).count() != 1 {
                return Err(io::Error::other(format!(
                    "original TUN does not have exactly one approved local host {host}"
                )));
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
                return Err(io::Error::other(format!(
                    "original TUN address differs from the exact manual host state: {row:?}"
                )));
            }
        }
        for row in &self.routes {
            if row.prefix != host_bits(row.destination)
                || (!local.contains(&row.destination) && !remote.contains(&row.destination))
                || !row.next_hop.is_unspecified()
                || row.publish
                || row.immortal
                || row.site_prefix != 0
            {
                return Err(io::Error::other(format!(
                    "original TUN route exceeds the approved host inventory: {row:?}"
                )));
            }
            if remote.contains(&row.destination)
                && (row.metric != METRIC
                    || row.protocol != MIB_IPPROTO_NETMGMT
                    || row.origin != NlroManual
                    || row.loopback
                    || row.autoconfigure)
            {
                return Err(io::Error::other(format!(
                    "original TUN remote route differs from the exact manual state: {row:?}"
                )));
            }
            // Windows creates each exact local /32 or /128 host route while
            // assigning the approved address. Its autoconfigure flag describes
            // that local address; it is not an extra remotely routed prefix.
            if local.contains(&row.destination)
                && (row.metric != LOCAL_HOST_ROUTE_METRIC
                    || row.protocol != MIB_IPPROTO_LOCAL
                    || row.origin != NlroManual
                    || !row.loopback
                    || !row.autoconfigure)
            {
                return Err(io::Error::other(format!(
                    "original TUN local route differs from the exact kernel host state: {row:?}"
                )));
            }
        }
        for host in local.iter().chain(remote) {
            if self
                .routes
                .iter()
                .filter(|row| row.destination == *host)
                .count()
                != 1
            {
                return Err(io::Error::other(format!(
                    "original TUN does not have exactly one approved host route {host}"
                )));
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
    let ipv4_dhcp_enabled = ipv4_dhcp(identity)?;
    let mut hosts = Vec::new();
    for row in addresses()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) {
            hosts.push(AddressState::from(row)?);
        }
    }
    hosts.sort();
    let mut paths = Vec::new();
    for row in routes()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) {
            paths.push(RouteState::from(row)?);
        }
    }
    paths.sort();
    // Re-read the exact identity after table snapshots; replacement is terminal.
    original(identity)?.ok_or_else(security::denied)?;
    Ok(Some(Snapshot {
        link_mtu: row.Mtu,
        interface_type: row.Type,
        tunnel_type: row.TunnelType,
        admin_status: row.AdminStatus,
        ipv4_dhcp_enabled,
        families,
        addresses: hosts,
        routes: paths,
    }))
}

/// Only after both original process incarnations are dead: the kernel may
/// already have withdrawn IP interfaces while retaining the PnP miniport.
/// Every still-observable resource must be an unchanged member of the original
/// attested inventory. Missing rows never authorize a new business session.
pub fn verify_recovery_remainder(identity: &ProviderIdentity, expected: &Snapshot) -> io::Result<()> {
    let row = original(identity)?.ok_or_else(security::denied)?;
    if row.Mtu != expected.link_mtu || row.Type != expected.interface_type
        || row.TunnelType != expected.tunnel_type || row.AdminStatus != expected.admin_status {
        return Err(io::Error::other("original recovery miniport properties changed"));
    }
    let mut families = Vec::new();
    for af in [AF_INET, AF_INET6] {
        if let Some(row) = optional_family(identity, af)? { families.push(FamilyState::from(row)); }
    }
    let dhcp = optional_ipv4_dhcp(identity)?;
    let mut hosts = Vec::new();
    for row in addresses()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) { hosts.push(AddressState::from(row)?); }
    }
    let mut paths = Vec::new();
    for row in routes()? {
        if on_original(identity, row.InterfaceLuid, row.InterfaceIndex) { paths.push(RouteState::from(row)?); }
    }
    if !expected.permits_recovery_remainder(&families, &hosts, &paths, dhcp) {
        return Err(io::Error::other(format!("original recovery resources changed beyond kernel withdrawal: families={families:?}, addresses={hosts:?}, routes={paths:?}, ipv4_dhcp={dhcp:?}")));
    }
    original(identity)?.ok_or_else(security::denied)?;
    Ok(())
}

/// Interface disappearance alone cannot clear a durable address/route record.
/// Observe all original kernel identifiers, and never mutate a surviving row.
pub fn absent(identity: &ProviderIdentity) -> io::Result<bool> {
    if original(identity)?.is_some() {
        return Ok(false);
    }
    if addresses()?
        .iter()
        .any(|row| on_original(identity, row.InterfaceLuid, row.InterfaceIndex))
        || routes()?
            .iter()
            .any(|row| on_original(identity, row.InterfaceLuid, row.InterfaceIndex))
    {
        return Ok(false);
    }
    // A name/GUID replacement during those two table reads is also terminal.
    Ok(original(identity)?.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stable fields from the actual 0.14.1 hosted NetIO inventory. This fixture
    // does not replace the dedicated native kernel packet/cleanup experiment.
    fn fixture() -> ([IpAddr; 2], [IpAddr; 2], Snapshot) {
        let local: [IpAddr; 2] = [
            Ipv4Addr::new(10, 81, 0, 2).into(),
            Ipv6Addr::new(0xfd81, 0, 0, 0, 0, 0, 0, 2).into(),
        ];
        let remote: [IpAddr; 2] = [
            Ipv4Addr::new(10, 81, 0, 3).into(),
            Ipv6Addr::new(0xfd81, 0, 0, 0, 0, 0, 0, 3).into(),
        ];
        let snapshot = Snapshot {
            link_mtu: WINTUN_LINK_MTU,
            interface_type: WINTUN_INTERFACE_TYPE,
            tunnel_type: 0,
            admin_status: 1,
            ipv4_dhcp_enabled: false,
            families: [AF_INET, AF_INET6]
                .into_iter()
                .map(|family| FamilyState {
                    family,
                    mtu: 1280,
                    metric: METRIC,
                    automatic_metric: false,
                    forwarding: false,
                    weak_send: false,
                    weak_receive: false,
                    advertising: false,
                    default_advertising: false,
                    router_discovery: RouterDiscoveryDisabled,
                    link_local: if family == AF_INET {
                        LinkLocalDelayed
                    } else {
                        LinkLocalAlwaysOn
                    },
                    dad: 0,
                    managed: false,
                    other_stateful: false,
                    disable_default_routes: true,
                })
                .collect(),
            addresses: local
                .into_iter()
                .map(|ip| AddressState {
                    ip,
                    prefix: host_bits(ip),
                    prefix_origin: IpPrefixOriginManual,
                    suffix_origin: IpSuffixOriginManual,
                    dad: IpDadStatePreferred,
                    skip: false,
                })
                .collect(),
            routes: local
                .into_iter()
                .chain(remote)
                .map(|destination| {
                    let is_local = local.contains(&destination);
                    RouteState {
                        destination,
                        prefix: host_bits(destination),
                        next_hop: if destination.is_ipv4() {
                            Ipv4Addr::UNSPECIFIED.into()
                        } else {
                            Ipv6Addr::UNSPECIFIED.into()
                        },
                        metric: if is_local {
                            LOCAL_HOST_ROUTE_METRIC
                        } else {
                            METRIC
                        },
                        protocol: if is_local {
                            MIB_IPPROTO_LOCAL
                        } else {
                            MIB_IPPROTO_NETMGMT
                        },
                        origin: NlroManual,
                        loopback: is_local,
                        autoconfigure: is_local,
                        publish: false,
                        immortal: false,
                        site_prefix: 0,
                    }
                })
                .collect(),
        };
        (local, remote, snapshot)
    }

    #[test]
    fn driver_capacity_never_substitutes_for_each_effective_ip_mtu() -> io::Result<()> {
        let (local, remote, snapshot) = fixture();
        snapshot.verify(&local, &remote)?;
        for family in 0..2 {
            let mut changed = snapshot.clone();
            changed.families[family].mtu = WINTUN_LINK_MTU;
            assert!(changed.verify(&local, &remote).is_err());
        }
        let mut changed = snapshot;
        changed.link_mtu = 1280;
        assert!(changed.verify(&local, &remote).is_err());
        Ok(())
    }

    #[test]
    fn kernel_local_host_flags_never_authorize_a_remote_autoconfigured_prefix() {
        let (local, remote, snapshot) = fixture();
        for index in 2..4 {
            let mut changed = snapshot.clone();
            changed.routes[index].autoconfigure = true;
            assert!(changed.verify(&local, &remote).is_err());
            let mut changed = snapshot.clone();
            changed.routes[index].loopback = true;
            assert!(changed.verify(&local, &remote).is_err());
        }
        let mut changed = snapshot;
        changed.routes[3] = changed.routes[2].clone();
        assert!(changed.verify(&local, &remote).is_err());
    }

    #[test]
    fn link_local_and_broader_resources_remain_outside_the_signed_inventory() {
        let (local, remote, snapshot) = fixture();
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        let mut changed = snapshot.clone();
        changed.addresses[1].ip = link_local;
        assert!(changed.verify(&local, &remote).is_err());
        let mut changed = snapshot.clone();
        changed.addresses.push(AddressState {
            ip: link_local,
            ..changed.addresses[1].clone()
        });
        assert!(changed.verify(&local, &remote).is_err());
        let mut changed = snapshot.clone();
        changed.routes[3].destination = link_local;
        assert!(changed.verify(&local, &remote).is_err());
        let mut changed = snapshot;
        changed.routes[3].prefix = 64;
        assert!(changed.verify(&local, &remote).is_err());
    }

    #[test]
    fn recovery_allows_only_withdrawal_and_never_substitutes_for_online_readiness() {
        let (local, remote, snapshot) = fixture();
        assert!(snapshot.permits_recovery_remainder(&[], &[], &[], None));
        assert!(snapshot.permits_recovery_remainder(&snapshot.families[1..],
            &snapshot.addresses[..1], &snapshot.routes[2..], Some(false)));
        assert!(!snapshot.permits_recovery_remainder(&snapshot.families, &snapshot.addresses,
            &snapshot.routes, None));
        assert!(!snapshot.permits_recovery_remainder(&[], &[], &[], Some(true)));
        let mut changed = snapshot.clone();
        changed.routes[2].autoconfigure = true;
        assert!(!snapshot.permits_recovery_remainder(&[], &[], &changed.routes[2..], None));
        changed = snapshot.clone();
        changed.families[1].mtu = WINTUN_LINK_MTU;
        assert!(!snapshot.permits_recovery_remainder(&changed.families[1..], &[], &[], None));
        changed = snapshot;
        changed.families.clear();
        changed.addresses.clear();
        changed.routes.clear();
        assert!(changed.verify(&local, &remote).is_err());
    }
}
