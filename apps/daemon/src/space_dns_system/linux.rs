#![cfg(target_os = "linux")]
use super::{DnsPlan, Journal, ProcessIdentity, Result, Value, command, io};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(super) async fn identity(pid: u32) -> Result<ProcessIdentity> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = std::fs::read_to_string(root.join("stat"))?;
    let fields = stat
        .get(
            stat.rfind(')')
                .ok_or_else(|| io::Error::other("invalid process stat"))?
                + 1..,
        )
        .ok_or_else(|| io::Error::other("invalid process stat"))?
        .split_whitespace()
        .collect::<Vec<_>>();
    let start = fields
        .get(19)
        .ok_or_else(|| io::Error::other("process start identity missing"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let uid = std::fs::metadata(&root)?.uid();
    Ok(ProcessIdentity {
        pid,
        incarnation: format!("{uid}:{start}:{}", boot.trim()),
        image: std::fs::read_link(root.join("exe"))?
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode resolver image"))?
            .into(),
    })
}

fn tool(name: &str) -> Result<PathBuf> {
    for directory in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        let path = Path::new(directory).join(name);
        if let Ok(path) = path.canonicalize() {
            let metadata = path.metadata()?;
            if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 {
                return Ok(path);
            }
        }
    }
    Err(io::Error::other(format!(
        "required root-owned OS component {name} is unavailable"
    ))
    .into())
}
async fn run(name: &str, args: Vec<String>) -> Result<Vec<u8>> {
    command::run(&tool(name)?, &args, None).await
}
async fn ip(args: &[&str]) -> Result<Value> {
    Ok(serde_json::from_slice(
        &run("ip", args.iter().map(|s| (*s).into()).collect()).await?,
    )?)
}
async fn resolved(args: &[&str]) -> Result {
    run("resolvectl", args.iter().map(|s| (*s).into()).collect()).await?;
    Ok(())
}

async fn property(path: &str, interface: &str, name: &str) -> Result<Value> {
    let output = run(
        "busctl",
        [
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.resolve1",
            path,
            interface,
            name,
        ]
        .iter()
        .map(|s| (*s).into())
        .collect(),
    )
    .await?;
    decode_property(&output, interface, name)
}

fn link_bus_path(index: u64) -> String {
    // systemd's sd_bus_path_encode escapes the first decimal digit as its
    // ASCII byte, then preserves subsequent digits: index 5 is /link/_35.
    let decimal = index.to_string();
    format!(
        "/org/freedesktop/resolve1/link/_{:02x}{}",
        decimal.as_bytes()[0],
        &decimal[1..]
    )
}

fn decode_property(output: &[u8], interface: &str, name: &str) -> Result<Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Property {
        #[serde(rename = "type")]
        signature: String,
        data: Value,
    }
    let property: Property = serde_json::from_slice(output)?;
    let expected = match (interface, name) {
        ("org.freedesktop.resolve1.Manager", "Domains") => "a(isb)",
        ("org.freedesktop.resolve1.Manager", "DNSEx") => "a(iiayqs)",
        ("org.freedesktop.resolve1.Link", "Domains") => "a(sb)",
        ("org.freedesktop.resolve1.Link", "DNSEx") => "a(iayqs)",
        ("org.freedesktop.resolve1.Link", "DefaultRoute") => "b",
        ("org.freedesktop.resolve1.Link", "LLMNR" | "MulticastDNS" | "DNSSEC" | "DNSOverTLS") => {
            "s"
        }
        _ => return Err(io::Error::other("unsupported resolved property").into()),
    };
    if property.signature != expected {
        return Err(
            io::Error::other("unexpected typed systemd-resolved property signature").into(),
        );
    }
    // get-property uses json_transform_variant: data is the property itself.
    // Unlike a method reply, there is no outer one-argument array to unwrap.
    // Validate every row before a missing/foreign index can look like absence.
    match expected {
        "a(isb)" => {
            let _: Vec<(i32, String, bool)> = serde_json::from_value(property.data.clone())?;
        }
        "a(iiayqs)" => {
            let _: Vec<(i32, i32, Vec<u8>, u16, String)> =
                serde_json::from_value(property.data.clone())?;
        }
        "a(sb)" => {
            let _: Vec<(String, bool)> = serde_json::from_value(property.data.clone())?;
        }
        "a(iayqs)" => {
            let _: Vec<(i32, Vec<u8>, u16, String)> =
                serde_json::from_value(property.data.clone())?;
        }
        "b" => {
            let _: bool = serde_json::from_value(property.data.clone())?;
        }
        "s" => {
            let _: String = serde_json::from_value(property.data.clone())?;
        }
        _ => unreachable!(),
    }
    Ok(property.data)
}

pub(super) async fn require_admin() -> Result {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(io::Error::other("split-DNS apply/recover requires a separate root process; the resolver remains a normal user").into());
    }
    Ok(())
}

async fn all_domains() -> Result<Value> {
    property(
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "Domains",
    )
    .await
}

pub(super) async fn preflight(plan: &DnsPlan) -> Result {
    let config = std::fs::read_to_string("/etc/resolv.conf")?;
    if !config.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("nameserver") && words.next() == Some("127.0.0.53")
    }) {
        return Err(io::Error::other("systemd-resolved stub 127.0.0.53 must already be the system resolver; NestLink never rewrites resolv.conf").into());
    }
    let links = ip(&["-j", "-d", "link", "show"]).await?;
    let links = links
        .as_array()
        .ok_or_else(|| io::Error::other("invalid iproute2 link observation"))?;
    if links.len() > 128 || links.iter().any(|link| link["ifname"] == plan.link()) {
        return Err(io::Error::other(
            "managed interface name is occupied; no existing interface will be adopted",
        )
        .into());
    }
    let domains = all_domains().await?;
    for row in domains
        .as_array()
        .ok_or_else(|| io::Error::other("invalid resolved domain list"))?
    {
        let domain = row
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("invalid resolved domain"))?;
        if overlaps(domain, &plan.suffix) {
            return Err(io::Error::other(
                "another system/VPN DNS domain overlaps the selected private suffix",
            )
            .into());
        }
    }
    Ok(())
}

fn overlaps(domain: &str, suffix: &str) -> bool {
    let domain = domain
        .trim_start_matches('~')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    !domain.is_empty()
        && (domain == suffix
            || suffix.ends_with(&format!(".{domain}"))
            || domain.ends_with(&format!(".{suffix}")))
}

fn check_link_owner(plan: &DnsPlan, link: &Value) -> Result {
    if link["ifname"] != plan.link()
        || link["ifalias"] != plan.marker()
        || link["linkinfo"]["info_kind"] != "dummy"
    {
        // These are public owner/configuration fields, not unrelated interface
        // data. Preserve the actual observation when refusing unsafe cleanup.
        let observed = json!({"ifindex":link["ifindex"], "ifname":link["ifname"], "ifalias":link["ifalias"], "info_kind":link["linkinfo"]["info_kind"]});
        return Err(io::Error::other(format!(
            "interface name belongs to another owner; no configuration was deleted; expected marker {}; observed {observed}",
            plan.marker()
        )).into());
    }
    Ok(())
}

pub(super) async fn inspect(plan: &DnsPlan) -> Result<Option<Value>> {
    let links = ip(&["-j", "-d", "link", "show"]).await?;
    let rows = links
        .as_array()
        .ok_or_else(|| io::Error::other("invalid iproute2 observation"))?;
    if rows.len() > 128 {
        return Err(io::Error::other("interface observation limit exceeded").into());
    }
    let Some(link) = rows.iter().find(|link| link["ifname"] == plan.link()) else {
        return Ok(None);
    };
    check_link_owner(plan, link)?;
    let index = link["ifindex"]
        .as_u64()
        .filter(|value| *value <= i32::MAX as u64)
        .ok_or_else(|| io::Error::other("invalid interface index"))?;
    let path = link_bus_path(index);
    let iface = "org.freedesktop.resolve1.Link";
    let (dns, domains, default_route, llmnr, mdns, dnssec, tls) = tokio::try_join!(
        property(&path, iface, "DNSEx"),
        property(&path, iface, "Domains"),
        property(&path, iface, "DefaultRoute"),
        property(&path, iface, "LLMNR"),
        property(&path, iface, "MulticastDNS"),
        property(&path, iface, "DNSSEC"),
        property(&path, iface, "DNSOverTLS")
    )?;
    let link_name = plan.link();
    let address_args = ["-j", "address", "show", "dev", &link_name];
    let route4_args = [
        "-4", "-j", "route", "show", "table", "all", "dev", &link_name,
    ];
    let route6_args = [
        "-6", "-j", "route", "show", "table", "all", "dev", &link_name,
    ];
    let (addresses, routes4, routes6) =
        tokio::try_join!(ip(&address_args), ip(&route4_args), ip(&route6_args))?;
    let addresses = addresses
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row["addr_info"].as_array())
        .ok_or_else(|| io::Error::other("invalid interface address observation"))?;
    // Compare configuration, not counters, carrier/operstate or other runtime
    // facts. MTU/MAC/flags are retained because an external configuration change
    // to our link must not be mistaken for our original resource.
    let flags = link["flags"]
        .as_array()
        .ok_or_else(|| io::Error::other("invalid interface flags"))?
        .iter()
        .filter(|flag| !matches!(flag.as_str(), Some("LOWER_UP" | "DORMANT" | "RUNNING")))
        .cloned()
        .collect::<Vec<_>>();
    let address_generation: u8 = std::fs::read_to_string(format!(
        "/proc/sys/net/ipv6/conf/{link_name}/addr_gen_mode"
    ))?
    .trim()
    .parse()?;
    let configuration = json!({"ifindex":index,"ifname":link["ifname"],"ifalias":link["ifalias"],"linkinfo":{"info_kind":link["linkinfo"]["info_kind"]},"mtu":link["mtu"],"address":link["address"],"broadcast":link["broadcast"],"flags":flags,"ipv6_addr_gen_mode":address_generation});
    // The kernel's automatic IPv6 multicast route is intrinsic to an UP dummy
    // link. Any unicast/export route or configured address is an external use.
    let routes6 = routes6
        .as_array()
        .ok_or_else(|| io::Error::other("invalid IPv6 route observation"))?
        .iter()
        .filter(|route| {
            !(route["dst"] == "ff00::/8"
                && route["type"] == "multicast"
                && route["protocol"] == "kernel")
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(Some(
        json!({"link":configuration, "addresses":addresses, "routes4":routes4, "routes6":routes6, "dns":dns, "domains":domains, "default_route":default_route, "llmnr":llmnr, "mdns":mdns, "dnssec":dnssec, "tls":tls}),
    ))
}

fn dns_value(plan: &DnsPlan) -> Value {
    json!([[2, [127, 0, 0, 1], plan.listen.port(), ""]])
}
fn domains_value(plan: &DnsPlan) -> Value {
    json!([[plan.suffix, true]])
}
fn safe_partial(plan: &DnsPlan, current: &Value) -> bool {
    let link = &current["link"];
    let dns = &current["dns"];
    let domains = &current["domains"];
    let empty = json!([]);
    link["ifname"] == plan.link()
        && link["ifalias"] == plan.marker()
        && link["linkinfo"]["info_kind"] == "dummy"
        && (dns == &empty || dns == &dns_value(plan))
        && (domains == &empty || domains == &domains_value(plan))
        && (dns == &empty || current["default_route"] == false)
        && current["addresses"].as_array().is_some_and(Vec::is_empty)
        && current["routes4"].as_array().is_some_and(Vec::is_empty)
        && current["routes6"].as_array().is_some_and(Vec::is_empty)
}
pub(super) fn verify_installed(plan: &DnsPlan, current: &Value) -> Result {
    if !safe_partial(plan, current)
        || current["dns"] != dns_value(plan)
        || current["domains"] != domains_value(plan)
        || current["default_route"] != false
        || current["llmnr"] != "no"
        || current["mdns"] != "no"
        || current["dnssec"] != "no"
        || current["tls"] != "no"
        || current["link"]["ipv6_addr_gen_mode"] != 1
        || !current["link"]["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"))
    {
        return Err(io::Error::other(format!(
            "resolved did not confirm the exact isolated DNS configuration; expected DNS {} and domains {}; owned configuration observed: {current}",
            dns_value(plan),
            domains_value(plan)
        ))
        .into());
    }
    Ok(())
}

pub(super) async fn install(plan: &DnsPlan) -> Result {
    let link = plan.link();
    // Specify the locally administered unicast address in the create request.
    // rtnl_create_link then sets NET_ADDR_SET before udev observes this device;
    // systemd's default persistent-MAC policy respects this explicit choice.
    // An initially random dummy MAC can otherwise change during the handoff.
    let mut address_bytes: [u8; 32] = Sha256::digest(plan.marker().as_bytes()).into();
    address_bytes[0] = (address_bytes[0] & 0xfc) | 0x02;
    let address = address_bytes[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    run(
        "ip",
        [
            "link",
            "add",
            "name",
            &link,
            "address",
            &address,
            "alias",
            &plan.marker(),
            "type",
            "dummy",
        ]
        .iter()
        .map(|s| (*s).into())
        .collect(),
    )
    .await?;
    // Linux 6.8/6.14 rtnl_create_link does not apply IFLA_IFALIAS, even though
    // iproute2 accepts `link add ... alias ...`. The existing-device set path
    // does apply it. Bind this just-created, still-DOWN dummy before any DNS
    // setting, and retain its index/address while awaiting resolved. This is
    // never used to adopt an interface which preflight/create did not own.
    let created = ip(&["-j", "-d", "link", "show", "dev", &link]).await?;
    let created = created
        .as_array()
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows.first())
        .ok_or_else(|| io::Error::other("exclusive dummy creation readback missing"))?;
    let created_index = created["ifindex"]
        .as_u64()
        .filter(|index| *index > 0 && *index <= i32::MAX as u64)
        .ok_or_else(|| io::Error::other("invalid created interface index"))?;
    let created_address = created["address"]
        .as_str()
        .filter(|address| !address.is_empty())
        .ok_or_else(|| io::Error::other("created dummy address missing"))?
        .to_owned();
    if created["ifname"] != link
        || created_address != address
        || created["linkinfo"]["info_kind"] != "dummy"
        || created["ifalias"]
            .as_str()
            .is_some_and(|alias| !alias.is_empty() && alias != plan.marker())
        || created["flags"]
            .as_array()
            .is_none_or(|flags| flags.iter().any(|flag| flag == "UP"))
    {
        return Err(io::Error::other(
            "exclusive dummy creation changed before owner marker; preserving it and the journal",
        )
        .into());
    }
    run(
        "ip",
        ["link", "set", "dev", &link, "alias", &plan.marker()]
            .iter()
            .map(|argument| (*argument).into())
            .collect(),
    )
    .await?;
    // Commit IPv6's no-generation mode while the new link is still DOWN.
    // A combined addrgenmode/up request opens the device before AF_SPEC is
    // applied and can create a real link-local address and unicast routes.
    run(
        "ip",
        ["link", "set", "dev", &link, "addrgenmode", "none"]
            .iter()
            .map(|argument| (*argument).into())
            .collect(),
    )
    .await?;
    if std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{link}/addr_gen_mode"))?
        .trim()
        != "1"
    {
        return Err(io::Error::other(
            "owned interface did not disable IPv6 address generation before activation; journal retained",
        )
        .into());
    }
    // Wait for resolved's netlink observer to create its Link object. The
    // interface is still DOWN and has no DNS server during this handoff.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let links = ip(&["-j", "-d", "link", "show"]).await?;
            if let Some(observed) = links
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["ifname"] == link))
            {
                // The exclusive create and this owner must still agree before
                // any per-link DNS setting can touch the observed interface.
                check_link_owner(plan, observed)?;
                if observed["ifindex"].as_u64() != Some(created_index)
                    || observed["address"].as_str() != Some(created_address.as_str())
                {
                    return Err(io::Error::other(format!("created interface incarnation changed before DNS setup; expected index {created_index}, address {created_address}; observed index {}, address {}; journal retained",observed["ifindex"],observed["address"])).into());
                }
                let path = link_bus_path(created_index);
                if property(&path, "org.freedesktop.resolve1.Link", "DefaultRoute")
                    .await
                    .is_ok()
                {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::other(
            "resolved did not observe the owned interface; recover the retained journal",
        )
    })??;
    // Set the no-default-routing boundary before introducing any DNS server.
    // The link remains DOWN until every setting is applied.
    resolved(&["default-route", &link, "no"]).await?;
    resolved(&["domain", &link, &format!("~{}", plan.suffix)]).await?;
    for setting in ["llmnr", "mdns", "dnssec", "dnsovertls"] {
        resolved(&[setting, &link, "no"]).await?;
    }
    resolved(&["dns", &link, &plan.listen.to_string()]).await?;
    run(
        "ip",
        ["link", "set", "dev", &link, "up"]
            .iter()
            .map(|s| (*s).into())
            .collect(),
    )
    .await?;
    Ok(())
}

pub(super) async fn remove(journal: &Journal) -> Result {
    let Some(current) = inspect(&journal.plan).await? else {
        if let Some(index) = journal
            .installed
            .as_ref()
            .and_then(|state| state["link"]["ifindex"].as_u64())
        {
            confirm_removed(index).await?;
        }
        return Ok(());
    };
    if !safe_partial(&journal.plan, &current)
        || journal
            .installed
            .as_ref()
            .is_some_and(|expected| expected != &current)
    {
        return Err(io::Error::other(format!("managed interface/DNS changed; preserving it and the recovery journal for explicit operator review; owned configuration observed: {current}")).into());
    }
    // Readback immediately before the narrow deletion detects replacement or
    // an administrator's configuration change. No physical/VPN link is used.
    if inspect(&journal.plan).await? != Some(current.clone()) {
        return Err(io::Error::other("interface changed during cleanup; journal retained").into());
    }
    run(
        "ip",
        ["link", "delete", "dev", &journal.plan.link()]
            .iter()
            .map(|s| (*s).into())
            .collect(),
    )
    .await?;
    if inspect(&journal.plan).await?.is_some() {
        return Err(io::Error::other("interface deletion was not confirmed").into());
    }
    confirm_removed(
        current["link"]["ifindex"]
            .as_u64()
            .ok_or_else(|| io::Error::other("owned interface index missing"))?,
    )
    .await?;
    // systemd-resolved removes per-link configuration with the deleted link.
    Ok(())
}

async fn confirm_removed(index: u64) -> Result {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (domains, dns) = tokio::try_join!(
                all_domains(),
                property(
                    "/org/freedesktop/resolve1",
                    "org.freedesktop.resolve1.Manager",
                    "DNSEx"
                )
            )?;
            let gone = [&domains, &dns].iter().all(|rows| {
                rows.as_array().is_some_and(|rows| {
                    rows.iter()
                        .all(|row| row.get(0).and_then(Value::as_u64) != Some(index))
                })
            });
            if gone {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::other(
            "resolved still reports the removed interface's DNS policy; journal retained",
        )
    })??;
    Ok(())
}

#[cfg(test)]
pub(super) async fn native_unrelated_state() -> Result<Value> {
    let (mut domains, mut dns) = tokio::try_join!(
        all_domains(),
        property(
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "DNSEx"
        )
    )?;
    for value in [&mut domains, &mut dns] {
        if let Some(rows) = value.as_array_mut() {
            rows.sort_by_key(Value::to_string);
        }
    }
    Ok(json!({"domains":domains,"dns":dns}))
}
#[cfg(test)]
pub(super) async fn native_query(plan: &DnsPlan) -> Result<String> {
    Ok(String::from_utf8(
        run(
            "resolvectl",
            vec![
                "--legend=no".into(),
                "--type=A".into(),
                "query".into(),
                format!("os-probe.{}", plan.suffix),
            ],
        )
        .await?,
    )?)
}
#[cfg(test)]
pub(super) async fn native_change_owned(plan: &DnsPlan) -> Result {
    let current = inspect(plan).await?.ok_or("owned link missing")?;
    let mtu = current["link"]["mtu"].as_u64().ok_or("MTU missing")? + 1;
    run(
        "ip",
        vec![
            "link".into(),
            "set".into(),
            "dev".into(),
            plan.link(),
            "mtu".into(),
            mtu.to_string(),
        ],
    )
    .await?;
    Ok(())
}
#[cfg(test)]
pub(super) async fn native_restore_owned(plan: &DnsPlan, expected: &Value) -> Result {
    let mtu = expected["link"]["mtu"]
        .as_u64()
        .ok_or("original MTU missing")?;
    run(
        "ip",
        vec![
            "link".into(),
            "set".into(),
            "dev".into(),
            plan.link(),
            "mtu".into(),
            mtu.to_string(),
        ],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolved_link_paths_escape_the_leading_decimal_digit() {
        for (index, path) in [
            (1, "/org/freedesktop/resolve1/link/_31"),
            (5, "/org/freedesktop/resolve1/link/_35"),
            (12, "/org/freedesktop/resolve1/link/_312"),
            (128, "/org/freedesktop/resolve1/link/_3128"),
            (2147483647, "/org/freedesktop/resolve1/link/_32147483647"),
        ] {
            assert_eq!(link_bus_path(index), path);
        }
    }

    #[test]
    fn busctl_property_data_preserves_full_arrays_empty_arrays_and_scalars() -> Result {
        let manager = "org.freedesktop.resolve1.Manager";
        let link = "org.freedesktop.resolve1.Link";
        for (interface, name, signature, data) in [
            (
                manager,
                "Domains",
                "a(isb)",
                json!([[2, "example.test", false], [7, "private.test", true]]),
            ),
            (
                manager,
                "DNSEx",
                "a(iiayqs)",
                json!([
                    [2, 2, [192, 0, 2, 53], 53, ""],
                    [7, 2, [127, 0, 0, 1], 5300, ""]
                ]),
            ),
            (link, "Domains", "a(sb)", json!([["private.test", true]])),
            (link, "Domains", "a(sb)", json!([])),
            (
                link,
                "DNSEx",
                "a(iayqs)",
                json!([[2, [127, 0, 0, 1], 5300, ""]]),
            ),
            (link, "DefaultRoute", "b", json!(false)),
            (link, "LLMNR", "s", json!("no")),
        ] {
            let bytes = serde_json::to_vec(&json!({"type": signature, "data": data}))?;
            assert_eq!(decode_property(&bytes, interface, name)?, data);
        }
        for value in [
            json!({"type":"a(sb)", "data":[[2, "private.test", true]]}),
            json!({"type":"a(isb)", "data":[["wrong-index", "private.test", true]]}),
            json!({"type":"a(isb)", "data":[[2, "private.test"]]}),
            json!({"type":"a(isb)", "data":[[[2, "private.test", true]]]}),
            json!({"type":"a(isb)"}),
        ] {
            assert!(decode_property(&serde_json::to_vec(&value)?, manager, "Domains").is_err());
        }
        Ok(())
    }

    #[test]
    fn domain_conflicts_are_label_bounded_and_do_not_capture_root_or_local() {
        let suffix = "s-0123456789abcdef0123456789abcdef.nestlink.internal";
        assert!(overlaps(suffix, suffix));
        assert!(overlaps("nestlink.internal", suffix));
        assert!(overlaps(&format!("device.{suffix}"), suffix));
        assert!(!overlaps(".", suffix));
        assert!(!overlaps("local", suffix));
        assert!(!overlaps("notnestlink.internal", suffix));
    }
}
