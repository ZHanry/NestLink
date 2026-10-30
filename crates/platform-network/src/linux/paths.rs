//! Reuse if-addrs and socket2; the kernel owns interface discovery and pinning.
use crate::path::NetworkInterface;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    net::IpAddr,
    num::NonZeroU32,
    path::Path,
};

const FACT_BYTES: u64 = 4 * 1024 * 1024;

fn read_fact(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(FACT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > FACT_BYTES {
        return Err(io::Error::other("kernel network fact exceeds its byte budget"));
    }
    Ok(text)
}

fn route_metric(defaults: &mut BTreeMap<String, u32>, name: &str, metric: u32) {
    defaults
        .entry(name.into())
        .and_modify(|old| *old = (*old).min(metric))
        .or_insert(metric);
}

fn default_routes() -> io::Result<BTreeMap<String, u32>> {
    let mut defaults = BTreeMap::new();
    // These kernel-owned proc files expose configured defaults, not Internet
    // reachability or a replacement for policy routing / kernel route lookup.
    for (file, ipv6) in [("/proc/net/route", false), ("/proc/net/ipv6_route", true)] {
        let text = match read_fact(Path::new(file)) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in text.lines() {
            let row: Vec<_> = line.split_whitespace().collect();
            let parsed = if ipv6
                && row.len() == 10
                && row[0] == "00000000000000000000000000000000"
                && row[1] == "00"
            {
                u32::from_str_radix(row[8], 16)
                    .ok()
                    .zip(u32::from_str_radix(row[5], 16).ok())
                    .map(|(flags, metric)| (row[9], flags, metric))
            } else if !ipv6
                && row.len() == 11
                && row[1] == "00000000"
                && row[7] == "00000000"
            {
                u32::from_str_radix(row[3], 16)
                    .ok()
                    .zip(row[6].parse::<u32>().ok())
                    .map(|(flags, metric)| (row[0], flags, metric))
            } else {
                None
            };
            if let Some((name, flags, metric)) = parsed
                && flags & libc::RTF_UP as u32 != 0
                && flags & libc::RTF_REJECT as u32 == 0
            {
                route_metric(&mut defaults, name, metric);
            }
        }
    }
    Ok(defaults)
}

pub(crate) fn path_interfaces() -> io::Result<Vec<NetworkInterface>> {
    let defaults = default_routes()?;
    let control = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let mut interfaces = BTreeMap::new();
    for address in if_addrs::get_if_addrs()? {
        let Some(index) = address.index.filter(|index| *index != 0) else {
            continue;
        };
        let ip = address.ip();
        // Match the Windows media candidate scope. Link-local IPv6 requires
        // scope-aware discovery, rather than choosing an implicit interface.
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || address.is_link_local() {
            continue;
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = interfaces.entry(index) {
            entry.insert(NetworkInterface {
                // Linux has no Windows LUID. A sysfs mount can belong to a
                // different netns, so it must not classify a same-named host
                // device as this namespace's physical adapter.
                index,
                luid: 0,
                name: address.name.clone(),
                physical: false,
                // if-addrs exposes IFF_RUNNING as oper_status but discards
                // IFF_UP. Require both current kernel flags explicitly.
                up: super::interface_is_up(&control, &address.name, index)?,
                metric: defaults.get(&address.name).copied().unwrap_or(u32::MAX),
                default_route: defaults.contains_key(&address.name),
                addresses: Vec::new(),
            });
        }
        if let Some(interface) = interfaces.get_mut(&index) {
            if interface.name != address.name {
                return Err(unavailable());
            }
            if !interface.addresses.contains(&ip) {
                interface.addresses.push(ip);
            }
        }
    }
    for interface in interfaces.values_mut() {
        interface.addresses.sort();
    }
    Ok(interfaces.into_values().collect())
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "selected Linux interface or source address is no longer available",
    )
}

pub(crate) fn validate_media_interface(selected: &NetworkInterface, source: IpAddr) -> io::Result<()> {
    let current = path_interfaces()?
        .into_iter()
        .find(|interface| interface.index == selected.index)
        .ok_or_else(unavailable)?;
    if !current.up || current.name != selected.name || !current.addresses.contains(&source) {
        return Err(unavailable());
    }
    Ok(())
}

pub(crate) fn bind_media_interface(socket: &socket2::Socket, index: u32, ipv6: bool) -> io::Result<()> {
    let index = NonZeroU32::new(index).ok_or_else(unavailable)?;
    // socket2 owns Linux SO_BINDTOIFINDEX, including ABI handling. Do not fall
    // back to an address-only bind or a mutable interface name on any failure.
    let actual = if ipv6 {
        socket.bind_device_by_index_v6(Some(index))?;
        socket.device_index_v6()?
    } else {
        socket.bind_device_by_index_v4(Some(index))?;
        socket.device_index_v4()?
    };
    if actual != Some(index) {
        return Err(io::Error::other(
            "Linux interface binding did not persist",
        ));
    }
    Ok(())
}
