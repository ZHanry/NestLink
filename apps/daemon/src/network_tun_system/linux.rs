//! The kernel TUN driver and reviewed tun-rs own framing/descriptor operations.
//! This adapter owns only exact product configuration and recovery readback.
use super::*;
use ipnet::IpNet;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

const ROUTE_METRIC: u64 = 42420;
fn tool() -> Result<PathBuf> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        if let Ok(path) = Path::new(directory).join("ip").canonicalize() {
            let metadata = path.metadata()?;
            if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 {
                return Ok(path);
            }
        }
    }
    Err(io::Error::other("root-owned iproute2 is required for managed TUN configuration").into())
}
async fn ip(args: &[&str]) -> Result<Vec<u8>> {
    crate::space_dns_system::native_command(
        &tool()?,
        &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
        None,
    )
    .await
}
async fn json_ip(args: &[&str]) -> Result<Value> {
    Ok(serde_json::from_slice(&ip(args).await?)?)
}
fn rows(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::other("iproute2 returned a non-array kernel observation").into())
}
pub(super) fn validate_owner(plan: &TunPlan) -> Result {
    let facts =
        nestlink_platform_security::local_port_gate::ProcessIdentity::read(plan.process.pid())?;
    let helper =
        nestlink_platform_security::local_port_gate::ProcessIdentity::read(std::process::id())?;
    if facts.uid != plan.uid
        || facts.uid == 0
        || helper.uid != 0
        || facts.image_device != helper.image_device
        || facts.image_inode != helper.image_inode
    {
        return Err(io::Error::other("managed TUN helper and normal owner must use the exact original executable inode and ordinary UID").into());
    }
    let ordinary_namespace = std::fs::metadata(format!("/proc/{}/ns/net", plan.process.pid()))?;
    let helper_namespace = std::fs::metadata("/proc/self/ns/net")?;
    if ordinary_namespace.dev() != helper_namespace.dev()
        || ordinary_namespace.ino() != helper_namespace.ino()
    {
        return Err(io::Error::other(
            "managed TUN helper must run in the original ordinary owner's network namespace",
        )
        .into());
    }
    Ok(())
}
fn scalar(path: &Path, name: &str) -> Result<String> {
    let bytes = std::fs::read(path.join(name))?;
    if bytes.len() > 128 {
        return Err(io::Error::other("TUN sysfs field exceeded bound").into());
    }
    Ok(std::str::from_utf8(&bytes)?.trim().to_owned())
}
fn flag_value(value: &str) -> Result<u32> {
    Ok(if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    })
}
pub(super) async fn inspect(plan: &TunPlan) -> Result<Option<TunState>> {
    tokio::time::timeout(Duration::from_secs(2),inspect_inner(plan)).await
        .map_err(|_|io::Error::other("bounded exact TUN readback timed out; stop and retain the original recovery journal"))?
}
async fn inspect_inner(plan: &TunPlan) -> Result<Option<TunState>> {
    let links = json_ip(&["-j", "-d", "link", "show"]).await?;
    let mut selected = rows(&links)?
        .iter()
        .filter(|row| row["ifname"].as_str() == Some(plan.link().as_str()));
    let Some(link) = selected.next() else {
        return Ok(None);
    };
    if selected.next().is_some()
        || link["linkinfo"]["info_kind"] != "tun"
        || link["linkinfo"]["info_data"]["type"] != "tun"
    {
        return Err(io::Error::other(
            "managed TUN name is occupied by a different kernel interface",
        )
        .into());
    }
    let index = u32::try_from(
        link["ifindex"]
            .as_u64()
            .ok_or_else(|| io::Error::other("kernel interface index missing"))?,
    )?;
    let marker = link["ifalias"].as_str().unwrap_or("").to_owned();
    let name = plan.link();
    let sysfs = PathBuf::from("/sys/class/net").join(&name);
    // The creating root descriptor briefly has the kernel's unassigned -1
    // owner before user() completes. It can never pass complete admission.
    let owner: i64 = scalar(&sysfs, "owner")?.parse()?;
    let owner = u32::try_from(owner).unwrap_or(u32::MAX);
    let framing = flag_value(&scalar(&sysfs, "tun_flags")?)?;
    // pi/vnet/multiqueue cannot silently change a whole-packet ACL into a
    // byte-prefix ACL. The descriptor reader has a separate 65536-byte bound.
    if framing & 0x1001 != 0x1001
        || framing & (0x0002 | 0x0100 | 0x4000) != 0
        || link["linkinfo"]["info_data"]["pi"] != false
        || link["linkinfo"]["info_data"]["vnet_hdr"] != false
        || link["linkinfo"]["info_data"]["multi_queue"] != false
    {
        return Err(io::Error::other(
            "managed TUN requires exclusive L3 NO_PI, no offload, no multiqueue framing",
        )
        .into());
    }
    let mut addresses = Vec::new();
    for family in ["-4", "-6"] {
        let observed = json_ip(&["-j", family, "addr", "show", "dev", &name]).await?;
        for row in rows(&observed)? {
            if row["ifindex"].as_u64() != Some(u64::from(index)) {
                return Err(io::Error::other("TUN replaced during address readback").into());
            }
            for address in rows(&row["addr_info"])? {
                addresses.push(json!({"family":address["family"],"local":address["local"],"prefixlen":address["prefixlen"],"scope":address["scope"],"peer":address["peer"],"broadcast":address["broadcast"]}));
            }
        }
    }
    let mut routes = Vec::new();
    for family in ["-4", "-6"] {
        let observed =
            json_ip(&["-j", family, "route", "show", "table", "all", "dev", &name]).await?;
        for route in rows(&observed)? {
            let mut route = route.clone();
            // Carrier state is volatile while the sole ordinary descriptor is
            // detached; no other route flag is ignored in ownership readback.
            if let Some(flags) = route.get_mut("flags").and_then(Value::as_array_mut) {
                flags.retain(|flag| flag != "linkdown");
            }
            routes.push(route);
        }
    }
    addresses.sort_by_key(Value::to_string);
    routes.sort_by_key(Value::to_string);
    Ok(Some(TunState {
        identity: InterfaceIdentity {
            name,
            index,
            marker,
            uid: owner,
        },
        mtu: u16::try_from(
            link["mtu"]
                .as_u64()
                .ok_or_else(|| io::Error::other("TUN MTU missing"))?,
        )?,
        up: rows(&link["flags"])?.iter().any(|flag| flag == "UP"),
        persistent: link["linkinfo"]["info_data"]["persist"]
            .as_bool()
            .ok_or_else(|| io::Error::other("TUN persistence observation missing"))?,
        framing,
        addresses,
        routes,
    }))
}
pub(super) async fn preflight(plan: &TunPlan) -> Result {
    require_kernel_device()?;
    if inspect(plan).await?.is_some() {
        return Err(io::Error::other("managed TUN name already exists; existing interfaces are never adopted by the root helper").into());
    }
    let addresses = json_ip(&["-j", "addr", "show"]).await?;
    let v4 = json_ip(&["-j", "-4", "route", "show", "table", "all"]).await?;
    let v6 = json_ip(&["-j", "-6", "route", "show", "table", "all"]).await?;
    check_conflicts(plan, &addresses, &v4, &v6)
}
fn require_kernel_device() -> Result {
    let metadata = std::fs::symlink_metadata("/dev/net/tun")?;
    // Require the installed kernel driver node; the provider's mknod fallback
    // must never create or replace a system-wide device on this product path.
    if !metadata.file_type().is_char_device() || metadata.uid() != 0 || metadata.rdev() != 0x0ac8 {
        return Err(io::Error::other(
            "the original root-owned Linux /dev/net/tun (10:200) device is required",
        )
        .into());
    }
    Ok(())
}
pub(super) fn check_conflicts(plan: &TunPlan, addresses: &Value, v4: &Value, v6: &Value) -> Result {
    let hosts: Vec<_> = plan
        .local_hosts
        .iter()
        .chain(&plan.remote_hosts)
        .copied()
        .collect();
    for interface in rows(addresses)? {
        for entry in rows(&interface["addr_info"])? {
            let local: IpAddr = entry["local"]
                .as_str()
                .ok_or_else(|| io::Error::other("kernel address is malformed"))?
                .parse()?;
            if hosts.contains(&local) {
                return Err(io::Error::other("a requested virtual host address is already assigned; other VPNs and manual addresses are preserved").into());
            }
        }
    }
    for route in rows(v4)?.iter().chain(rows(v6)?) {
        let prefix = route["dst"]
            .as_str()
            .ok_or_else(|| io::Error::other("kernel route destination missing"))?;
        if matches!(prefix, "default" | "0.0.0.0/0" | "::/0") {
            continue;
        }
        let prefix = parse_prefix(prefix)?;
        if hosts.iter().any(|host| prefix.contains(host)) {
            return Err(io::Error::other("a nondefault OS/VPN route overlaps a requested virtual host; no configuration was replaced").into());
        }
    }
    Ok(())
}
fn parse_prefix(value: &str) -> Result<IpNet> {
    if value.contains('/') {
        return Ok(value.parse()?);
    }
    let host: IpAddr = value.parse()?;
    Ok(IpNet::new(host, if host.is_ipv4() { 32 } else { 128 })?)
}
pub(super) async fn create(plan: &TunPlan) -> Result<tun_rs::SyncDevice> {
    // tun-rs creates an ephemeral descriptor first. It receives no addresses,
    // DNS, default routes or permission to configure another interface.
    // With no requested name the kernel allocates a new tun%d interface. An
    // explicit TUNSETIFF name could otherwise attach a same-named interface
    // raced into existence after preflight. SIOCSIFNAME then fails atomically
    // on an occupied target, and Drop removes only our new ephemeral object.
    let device = tun_rs::DeviceBuilder::new().enable(false).build_sync()?;
    device.set_name(&plan.link())?;
    device.user(i32::try_from(plan.uid)?)?;
    ip(&["link", "set", "dev", &plan.link(), "alias", &plan.marker()]).await?;
    Ok(device)
}
pub(super) async fn created_identity(plan: &TunPlan) -> Result<InterfaceIdentity> {
    let state = inspect(plan)
        .await?
        .ok_or_else(|| io::Error::other("new ephemeral TUN disappeared"))?;
    if state.identity.marker != plan.marker()
        || state.identity.uid != plan.uid
        || state.up
        || state.persistent
        || !state.addresses.is_empty()
        || !state.routes.is_empty()
    {
        return Err(io::Error::other(
            "new ephemeral TUN did not match its unconfigured original identity",
        )
        .into());
    }
    Ok(state.identity)
}
pub(super) async fn configure(plan: &TunPlan) -> Result {
    let name = plan.link();
    ip(&[
        "link",
        "set",
        "dev",
        &name,
        "mtu",
        "1280",
        "multicast",
        "off",
        "addrgenmode",
        "none",
    ])
    .await?;
    for (family, local, remote, prefix) in [
        ("-4", plan.local_hosts[0], plan.remote_hosts[0], 32),
        ("-6", plan.local_hosts[1], plan.remote_hosts[1], 128),
    ] {
        let host = format!("{local}/{prefix}");
        let remote = format!("{remote}/{prefix}");
        let mut address = vec![
            family,
            "addr",
            "add",
            host.as_str(),
            "dev",
            name.as_str(),
            "noprefixroute",
        ];
        if family == "-6" {
            address.push("nodad");
        }
        ip(&address).await?;
        ip(&[
            family,
            "route",
            "add",
            &remote,
            "dev",
            &name,
            "src",
            &local.to_string(),
            "proto",
            "static",
            "metric",
            "42420",
        ])
        .await?;
    }
    ip(&["link", "set", "dev", &name, "up"]).await?;
    Ok(())
}
pub(super) fn verify(plan: &TunPlan, state: &TunState, complete: bool) -> Result {
    if state.identity.name != plan.link()
        || state.identity.marker != plan.marker()
        || state.identity.uid != plan.uid
        || state.identity.index == 0
        || (complete && (state.mtu != 1280 || !state.up || !state.persistent))
    {
        return Err(io::Error::other(
            "TUN identity, MTU or activation differs from its exact plan",
        )
        .into());
    }
    if state.addresses.len() > 2 || state.routes.len() > 5 {
        return Err(io::Error::other("foreign configuration appeared on the managed TUN").into());
    }
    for row in &state.addresses {
        let ip: IpAddr = row["local"]
            .as_str()
            .ok_or_else(|| io::Error::other("TUN address is malformed"))?
            .parse()?;
        if !plan.local_hosts.contains(&ip)
            || row["prefixlen"].as_u64() != Some(if ip.is_ipv4() { 32 } else { 128 })
            || row["family"] != if ip.is_ipv4() { "inet" } else { "inet6" }
            || row["scope"] != "global"
            || !row["peer"].is_null()
            || !row["broadcast"].is_null()
        {
            return Err(io::Error::other(
                "TUN contains an unapproved address/prefix or address scope",
            )
            .into());
        }
    }
    let mut remote_count = 0;
    for route in &state.routes {
        if route["dev"].as_str() != Some(state.identity.name.as_str())
            || !route["gateway"].is_null()
            || !route["nhid"].is_null()
            || !route["nexthops"].is_null()
        {
            return Err(
                io::Error::other("TUN contains an unapproved gateway or multipath route").into(),
            );
        }
        let dst = route["dst"]
            .as_str()
            .ok_or_else(|| io::Error::other("TUN route destination missing"))?;
        let prefix = parse_prefix(dst)?;
        if plan.remote_hosts.iter().any(|host| {
            prefix.addr() == *host && prefix.prefix_len() == if host.is_ipv4() { 32 } else { 128 }
        }) {
            remote_count += 1;
            let index = if prefix.addr().is_ipv4() { 0 } else { 1 };
            if route["protocol"] != "static"
                || route["metric"].as_u64() != Some(ROUTE_METRIC)
                || route["prefsrc"].as_str() != Some(plan.local_hosts[index].to_string().as_str())
                || !(route["table"].is_null() || route["table"] == "main" || route["table"] == 254)
                || (!route["type"].is_null() && route["type"] != "unicast")
            {
                return Err(io::Error::other(
                    "TUN remote host route differs from its signed exact target",
                )
                .into());
            }
        } else {
            let local = plan.local_hosts.iter().any(|host| {
                prefix.addr() == *host
                    && prefix.prefix_len() == if host.is_ipv4() { 32 } else { 128 }
            });
            let multicast = dst == "ff00::/8" && route["type"] == "multicast";
            if (!local && !multicast)
                || route["protocol"] != "kernel"
                || !(route["table"] == "local" || route["table"] == 255)
                || (local && route["type"] != "local")
            {
                return Err(io::Error::other(
                    "managed TUN contains a foreign route; preserving it for operator review",
                )
                .into());
            }
        }
    }
    if complete && (state.addresses.len() != 2 || remote_count != 2) {
        return Err(io::Error::other(
            "TUN exact dual-stack address/host-route readback is incomplete",
        )
        .into());
    }
    Ok(())
}
pub(super) async fn adopt(plan: &TunPlan, expected: &TunState) -> Result<tun_rs::AsyncDevice> {
    require_kernel_device()?;
    verify(plan, expected, true)?;
    if inspect(plan).await?.as_ref() != Some(expected) {
        return Err(io::Error::other("TUN changed before ordinary descriptor admission").into());
    }
    let device = tun_rs::DeviceBuilder::new()
        .name(plan.link())
        .inherit_enable_state()
        .build_async()?;
    if device.name()? != expected.identity.name
        || device.if_index()? != expected.identity.index
        || inspect(plan).await?.as_ref() != Some(expected)
    {
        return Err(io::Error::other(
            "ordinary TUN descriptor does not own the exact root-created interface",
        )
        .into());
    }
    Ok(device)
}
pub(super) async fn remove(journal: &Journal) -> Result {
    let Some(current) = inspect(&journal.plan).await? else {
        return Ok(());
    };
    // No durable identity means the creating descriptor was nonpersistent. A
    // same-named surviving link cannot be assumed to belong to that operation.
    if journal.identity.as_ref() != Some(&current.identity) {
        return Err(io::Error::other("TUN incarnation is not the original durably recorded interface; preserving it and the journal").into());
    }
    verify(&journal.plan, &current, false)?;
    if journal
        .installed
        .as_ref()
        .is_some_and(|expected| expected != &current)
    {
        return Err(io::Error::other(
            "TUN configuration changed externally; preserving changed resources and journal",
        )
        .into());
    }
    if inspect(&journal.plan).await?.as_ref() != Some(&current) {
        return Err(io::Error::other("TUN changed during cleanup; journal retained").into());
    }
    ip(&["link", "delete", "dev", &journal.plan.link()]).await?;
    if inspect(&journal.plan).await?.is_some() {
        return Err(io::Error::other("TUN interface deletion was not confirmed").into());
    }
    // Routes and addresses attached to this exact kernel interface disappear
    // with deletion; independently read the complete tables to confirm that no
    // original interface route remains before acknowledging physical cleanup.
    for family in ["-4", "-6"] {
        let routes = json_ip(&["-j", family, "route", "show", "table", "all"]).await?;
        if rows(&routes)?
            .iter()
            .any(|route| route["dev"].as_str() == Some(journal.plan.link().as_str()))
        {
            return Err(io::Error::other(
                "kernel still reports a route for the removed managed TUN; journal retained",
            )
            .into());
        }
    }
    Ok(())
}
