//! Only mature iproute2, nftables/netfilter, util-linux and iputils perform OS
//! networking. Every mutation is confined to the one recorded namespace.
use super::*;
use serde_json::Value;
use std::os::unix::fs::MetadataExt;

pub(super) fn tool(name:&str)->Result<PathBuf> {
    if !matches!(name,"ip"|"nft"|"unshare"|"arping") {return Err(io::Error::other("unrecognized subnet OS tool").into());}
    for directory in ["/usr/sbin","/usr/bin","/sbin","/bin"] {
        if let Ok(path)=Path::new(directory).join(name).canonicalize() {let metadata=path.metadata()?;if metadata.is_file()&&metadata.uid()==0&&metadata.mode()&0o022==0 {return Ok(path);}}
    }
    Err(io::Error::other(format!("root-owned mature {name} is required for the subnet provider")).into())
}
pub(super) async fn command(name:&str,args:&[&str])->Result<Vec<u8>> {
    crate::space_dns_system::native_command(&tool(name)?,&args.iter().map(|arg|(*arg).to_owned()).collect::<Vec<_>>(),None).await
}
pub(super) async fn ip(args:&[&str])->Result<Value> {Ok(serde_json::from_slice(&command("ip",args).await?)?)}
pub(super) fn one(value:&Value)->Result<&Value> {let rows=value.as_array().ok_or_else(||io::Error::other("bounded iproute2 array required"))?;if rows.len()!=1 {return Err(io::Error::other("exactly one original kernel interface required").into());}Ok(&rows[0])}
pub(super) async fn parent(plan:&Plan)->Result<Value> {
    let value=ip(&["-j","-d","link","show","dev",&plan.lan_name]).await?;
    let row=one(&value)?;
    if row["ifindex"].as_u64()!=Some(u64::from(plan.lan_index))||row["ifname"].as_str()!=Some(plan.lan_name.as_str())||row["link_type"]!="ether"||row["address"].as_str().is_none() {return Err(io::Error::other("selected original Ethernet LAN name/index changed").into());}
    // Retain the original interface's exact identity and configuration. Linux
    // bridge elapsed timers and learned-FDB counts change as time/traffic pass;
    // they cannot identify an interface or invalidate its unchanged ownership.
    let mut linkinfo=row["linkinfo"].clone();
    if linkinfo["info_kind"]=="bridge" && let Some(data)=linkinfo["info_data"].as_object_mut() {
        for field in ["hello_timer","tcn_timer","topology_change_timer","gc_timer","fdb_n_learned"] {data.remove(field);}
    }
    Ok(serde_json::json!({"name":row["ifname"],"index":row["ifindex"],"address":row["address"],"link_type":row["link_type"],"link_index":row["link_index"],"link_netnsid":row["link_netnsid"],"master":row["master"],"linkinfo":linkinfo}))
}
pub(super) fn namespace(path:&Path)->Result<Option<(u64,u64)>> {
    let root=Path::new("/run/netns");
    match std::fs::symlink_metadata(root) {Ok(metadata) if metadata.is_dir()&&metadata.uid()==0&&metadata.mode()&0o022==0=>{},Err(error) if error.kind()==io::ErrorKind::NotFound=>return Ok(None),_=>return Err(io::Error::other("root-owned non-writable native namespace directory required").into())}
    match std::fs::symlink_metadata(path) {Ok(metadata) if !metadata.file_type().is_symlink()&&metadata.uid()==0=>Ok(Some((metadata.dev(),metadata.ino()))),Err(error) if error.kind()==io::ErrorKind::NotFound=>Ok(None),_=>Err(io::Error::other("selected namespace ownership changed").into())}
}
pub(super) fn namespace_path(plan:&Plan)->PathBuf {Path::new("/run/netns").join(plan.namespace())}
pub(super) async fn preflight(plan:&Plan)->Result<Value> {
    plan.checked(true)?;
    let parent=parent(plan).await?;
    if namespace(&namespace_path(plan))?.is_some() {return Err(io::Error::other("subnet namespace name is already occupied").into());}
    let addresses=ip(&["-j","-4","addr","show"]).await?;
    for interface in addresses.as_array().ok_or_else(||io::Error::other("invalid native address observation"))? {
        for address in interface["addr_info"].as_array().ok_or_else(||io::Error::other("invalid native address array"))? {
            if address["local"].as_str()==Some(plan.lan_gateway.to_string().as_str()) {return Err(io::Error::other("extra subnet gateway IP is already assigned on the host").into());}
        }
    }
    for required in ["ip","nft","unshare","arping"] {tool(required)?;}
    Ok(parent)
}
pub(super) async fn attach(plan:&Plan,namespace:&journal::Namespace)->Result {
    let pid=namespace.worker.pid().to_string();
    command("ip",&["netns","attach",&plan.namespace(),&pid]).await?;
    if self::namespace(&namespace_path(plan))?!=Some((namespace.device,namespace.inode)) {return Err(io::Error::other("named namespace does not match the original precommitted kernel inode").into());}
    command("ip",&["link","add","link",&plan.lan_name,"name",&plan.macvlan(),"netns",&plan.namespace(),"type","macvlan","mode","bridge"]).await?;
    Ok(())
}
pub(super) async fn local_link(name:&str)->Result<Value> {Ok(one(&ip(&["-j","-d","link","show","dev",name]).await?)?.clone())}
pub(super) async fn configure(plan:&Plan,journal_dir:&Path,tun:&tun_rs::AsyncDevice,server_secret:Option<&[u8;32]>)->Result<Receipt> {
    let checked=plan.checked(true)?;
    let current=std::fs::metadata("/proc/self/ns/net")?;
    if namespace(&namespace_path(plan))?!=Some((current.dev(),current.ino())) {return Err(io::Error::other("subnet worker is outside its exact owned namespace").into());}
    let macvlan=local_link(&plan.macvlan()).await?;
    if macvlan["linkinfo"]["info_kind"]!="macvlan"||macvlan["linkinfo"]["info_data"]["mode"]!="bridge"||macvlan["link_index"].as_u64()!=Some(u64::from(plan.lan_index)) {return Err(io::Error::other("owned macvlan does not attach to the selected original LAN").into());}
    let rules=rules(plan,&checked)?;
    let path=journal_dir.join("network-subnet-rules.nft");
    if nestlink_platform_security::replace_private_metadata(&path,rules.as_bytes())?!=nestlink_platform_security::MetadataCommit::Durable {return Err(io::Error::other("subnet firewall source durability unknown").into());}
    let path=path.to_str().ok_or_else(||io::Error::other("native nft input path must be UTF-8"))?;
    command("nft",&["--check","--file",path]).await?;
    command("nft",&["--file",path]).await?;
    command("ip",&["link","set","dev",&plan.macvlan(),"alias",&plan.marker(),"multicast","off","addrgenmode","none","up"]).await?;
    // Duplicate-address probing occurs before assigning any LAN address and
    // before enabling forwarding. An uncertain result prevents application.
    command("arping",&["-D","-c","2","-w","2","-I",&plan.macvlan(),&plan.lan_gateway.to_string()]).await?;
    let lan=format!("{}/{}",plan.lan_gateway,plan.lan_prefix_len);
    command("ip",&["-4","addr","add",&lan,"dev",&plan.macvlan()]).await?;
    if let Some(ingress)=&plan.wireguard {ingress.configure(plan,server_secret.ok_or_else(||io::Error::other("WireGuard namespace requires the explicitly approved root private key"))?).await?;}
    command("ip",&["link","set","dev",&plan.tun(),"alias",&plan.marker(),"mtu","1280"]).await?;
    for remote in &checked.remote {let prefix=format!("{}/{}",remote.network,remote.prefix_len);command("ip",&["-4","route","add",&prefix,"dev",&plan.tun(),"metric","42420"]).await?;}
    // These procfs values belong solely to the new worker namespace.
    std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter",b"0")?;
    std::fs::write("/proc/sys/net/ipv4/conf/default/rp_filter",b"0")?;
    for interface in [plan.tun(),plan.macvlan()] {std::fs::write(format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter"),b"0")?;}
    std::fs::write("/proc/sys/net/ipv4/ip_forward",b"1")?;
    command("ip",&["link","set","dev",&plan.tun(),"up"]).await?;
    let _=tun;
    let tun=local_link(&plan.tun()).await?;
    let macvlan=local_link(&plan.macvlan()).await?;
    Ok(Receipt{schema_version:1,plan_digest:plan.digest()?,worker:process_identity(std::process::id()).await?,namespace_device:current.dev(),namespace_inode:current.ino(),
        tun_index:u32::try_from(tun["ifindex"].as_u64().ok_or_else(||io::Error::other("owned TUN index missing"))?)?,macvlan_index:u32::try_from(macvlan["ifindex"].as_u64().ok_or_else(||io::Error::other("owned macvlan index missing"))?)?,socket_device:0,socket_inode:0,socket_parent_device:0,socket_parent_inode:0,
        wireguard_index:if plan.wireguard.is_some(){Some(u32::try_from(local_link(&wireguard::Ingress::interface(plan)).await?["ifindex"].as_u64().ok_or_else(||io::Error::other("owned WireGuard index missing"))?)?)}else{None}})
}

pub(super) fn rules(plan:&Plan,checked:&plan::Checked)->Result<String> {
    if let Some(ingress)=&plan.wireguard {return ingress.rules(plan,checked);}
    use nestlink_protocol::network::{Direction,IpProtocol};
    let name=plan.namespace();let tun=plan.tun();let lan=plan.macvlan();
    let original=plan::net(checked.mapping.original)?.to_string();let alias=plan::net(checked.mapping.alias)?.to_string();
    let remote=checked.remote.iter().map(|prefix|format!("{}/{}",prefix.network,prefix.prefix_len)).collect::<Vec<_>>().join(", ");
    // Reject original fragments before NF_CONNTRACK_DEFRAG (-400) can hide
    // their fragmentation flags from the complete-IP business boundary.
    let mut rules=format!("table inet {name} {{\nquota budget {{ {} bytes }}\nchain raw {{ type filter hook prerouting priority -450; policy accept; meta time >= {} drop; meta nfproto ipv6 drop; ip frag-off & 0x3fff != 0 drop; ip hdrlength != 5 drop; }}\nchain input {{ type filter hook input priority 0; policy drop; }}\nchain output {{ type filter hook output priority 0; policy drop; }}\nchain admitted {{ quota name budget accept; }}\nchain forward {{ type filter hook forward priority 0; policy drop; ct state invalid drop;\n",checked.business.byte_limit,plan.expires_at_ms/1000);
    // Replies use the kernel's exact conntrack tuple and original initiating
    // policy. Forwarding remains limited to the two owned interface directions.
    for (from,to,source,destination) in [(&tun,&lan,format!("{{ {remote} }}"),original.clone()),(&lan,&tun,original.clone(),format!("{{ {remote} }}"))] {
        rules.push_str(&format!("iifname \"{from}\" oifname \"{to}\" ip saddr {source} ip daddr {destination} ct state established jump admitted;\n"));
        let source_to_destination=if from==&lan {checked.local_source} else {!checked.local_source};
        let required=if source_to_destination {Direction::Inbound} else {Direction::Outbound};
        for rule in &checked.business.rules {
            if rule.direction!=required {continue;}
            let protocol=match rule.protocol {IpProtocol::Tcp=>{let [low,high]=rule.ports.ok_or_else(||io::Error::other("TCP subnet rule has no exact port interval"))?;format!("tcp dport {} tcp flags & (syn|ack|fin|rst) == syn",ports(low,high))},IpProtocol::Udp=>{let [low,high]=rule.ports.ok_or_else(||io::Error::other("UDP subnet rule has no exact port interval"))?;format!("udp dport {}",ports(low,high))},IpProtocol::IcmpV4=>"icmp type echo-request".into(),_=>return Err(io::Error::other("IPv4 subnet provider cannot apply this protocol family").into())};
            rules.push_str(&format!("iifname \"{from}\" oifname \"{to}\" ip saddr {source} ip daddr {destination} {protocol} ct state new jump admitted;\n"));
        }
    }
    rules.push_str("}\n");
    if original!=alias {rules.push_str(&format!("chain prerouting {{ type nat hook prerouting priority dstnat; policy accept; iifname \"{tun}\" ip daddr {alias} dnat ip prefix to ip daddr map {{ {alias} : {original} }}; }}\n"));}
    rules.push_str("chain postrouting { type nat hook postrouting priority srcnat; policy accept; ");
    if original!=alias {rules.push_str(&format!("oifname \"{tun}\" ip saddr {original} snat ip prefix to ip saddr map {{ {original} : {alias} }}; "));}
    rules.push_str(&format!("oifname \"{lan}\" ip saddr {{ {remote} }} ip daddr {original} snat ip to {}; }}\n}}\n",plan.lan_gateway));
    Ok(rules)
}
fn ports(low:u16,high:u16)->String {if low==high {low.to_string()} else {format!("{low}-{high}")}}
