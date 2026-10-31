use super::*;
use std::os::unix::fs::MetadataExt;

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lab {pub id:String,pub ordinary:PathBuf,pub root:PathBuf}
#[derive(Serialize,Deserialize)]
struct Owned {bridges:Vec<(String,u64)>,targets:Vec<(String,u64,u64)>}
impl Lab {
    pub fn new()->Result<Self> {let id=nestlink_auth::random_id();let ordinary=Path::new("/tmp").join(format!("nls-{id}"));nestlink_platform_security::new_private_directory(&ordinary)?;let root=Path::new("/tmp").join(format!("nestlink-subnet-native-{id}"));Ok(Self{id,ordinary,root})}
    pub fn config(&self)->PathBuf {self.ordinary.join("lab.json")}
    pub fn plan(&self,index:usize)->PathBuf {self.ordinary.join(format!("site{index}.json"))}
    pub fn journal(&self,index:usize)->PathBuf {self.root.join(format!("gateway{index}"))}
    pub fn bridge(&self,index:usize)->String {format!("nlb{index}{}",&self.id.replace('-',"")[..10])}
    pub fn target(&self,index:usize)->String {format!("nltarget{index}{}",&self.id.replace('-',"")[..10])}
    fn veth(&self,index:usize)->String {format!("nlv{index}{}",&self.id.replace('-',"")[..10])}
    pub fn checked(path:&Path)->Result<Self> {let (bytes,uid)=crate::network_packet_runtime::read_public_plan(path,4096)?;let lab:Self=serde_json::from_slice(&bytes)?;if uid==0||lab.id.len()!=36||!lab.id.bytes().all(|byte|byte.is_ascii_hexdigit()||byte==b'-')||lab.ordinary!=Path::new("/tmp").join(format!("nls-{}",lab.id))||lab.root!=Path::new("/tmp").join(format!("nestlink-subnet-native-{}",lab.id))||lab.config()!=path {return Err(io::Error::other("unexpected source-exact hosted lab paths").into());}Ok(lab)}
    pub fn command(&self,role:&str)->Result<Command> {
        let mut command=Command::new("/usr/bin/sudo");
        command.args(["-n","--preserve-env=NESTLINK_SUBNET_NATIVE_CASE","--","/usr/bin/env","GITHUB_ACTIONS=true","NESTLINK_SUBNET_NATIVE_LAB=1"]).arg(format!("NESTLINK_SUBNET_NATIVE_ROLE={role}")).arg(format!("NESTLINK_SUBNET_NATIVE_CONFIG={}",self.config().display()));
        if let Some(index)=role.strip_prefix("service").or_else(||role.strip_prefix("probe")) {let index:usize=index.parse()?;if index>1{return Err(io::Error::other("invalid owned target site").into());}command.arg(kernel::tool("ip")?).args(["netns","exec",&self.target(index)]);}
        command.arg(std::env::current_exe()?).args(["--exact",ROLE_TEST,"--ignored","--nocapture","--test-threads=1"]).stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).kill_on_drop(true);
        Ok(command)
    }
    pub async fn status(&self,role:&str)->Result<bool> {Ok(tokio::time::timeout(Duration::from_secs(10),self.command(role)?.status()).await??.success())}
    pub async fn setup(&self)->Result {
        nestlink_platform_security::new_private_directory(&self.root)?;
        let mut owned=Owned{bridges:Vec::new(),targets:Vec::new()};
        for index in 0..2 {
            nestlink_platform_security::new_private_directory(&self.journal(index))?;
            kernel::command("ip",&["link","add","name",&self.bridge(index),"type","bridge"]).await?;
            let bridge=kernel::local_link(&self.bridge(index)).await?;owned.bridges.push((self.bridge(index),bridge["ifindex"].as_u64().ok_or_else(||io::Error::other("owned lab bridge index missing"))?));self.save(&owned)?;
            // The isolated lab is IPv4-only. Disable autoconfiguration solely
            // on this journaled lab link before UP so DAD cannot change the
            // host's route snapshot after the setup boundary.
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6",self.bridge(index)),b"1")?;
            kernel::command("ip",&["link","set","dev",&self.bridge(index),"alias",&format!("NestLink:subnet:lab:{}",self.id),"addrgenmode","none","up"]).await?;
            kernel::command("ip",&["netns","add",&self.target(index)]).await?;
            let target=std::fs::metadata(Path::new("/run/netns").join(self.target(index)))?;owned.targets.push((self.target(index),target.dev(),target.ino()));self.save(&owned)?;
            kernel::command("ip",&["link","add","name",&self.veth(index),"type","veth","peer","name","eth0","netns",&self.target(index)]).await?;
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6",self.veth(index)),b"1")?;
            kernel::command("ip",&["link","set","dev",&self.veth(index),"alias",&format!("NestLink:subnet:lab:{}",self.id),"addrgenmode","none","master",&self.bridge(index),"up"]).await?;
            kernel::command("ip",&["-n",&self.target(index),"link","set","dev","lo","up"]).await?;
            kernel::command("ip",&["-n",&self.target(index),"link","set","dev","eth0","mtu","1280","up"]).await?;
            kernel::command("ip",&["-n",&self.target(index),"-4","addr","add",&format!("{}/24",fixture::TARGET),"dev","eth0"]).await?;
            kernel::command("ip",&["-n",&self.target(index),"-4","route","add",&format!("{}/24",fixture::ALIASES[1-index]),"via","192.168.1.254"]).await?;
        }
        nestlink_platform_security::create_private(&self.root.join("host-before.json"),&serde_json::to_vec(&host().await?)?)?;
        Ok(())
    }
    fn save(&self,owned:&Owned)->Result {if nestlink_platform_security::replace_private_metadata(&self.root.join("owned.json"),&serde_json::to_vec(owned)?)?!=nestlink_platform_security::MetadataCommit::Durable {return Err(io::Error::other("native lab setup identity was not durable").into());}Ok(())}
    pub async fn verify_host(&self)->Result {let before:serde_json::Value=serde_json::from_slice(&nestlink_platform_security::read_private(&self.root.join("host-before.json"),65_536)?)?;assert_eq!(before,host().await?,"gateway application changed the host's original IP/default routes/firewall/global forwarding settings");Ok(())}
    pub async fn teardown(&self)->Result {
        self.verify_host().await?;
        for index in 0..2 {let store=journal::Store::open(&self.journal(index))?;helper::recover(&store).await?;assert!(store.read()?.is_none());}
        let owned:Owned=serde_json::from_slice(&nestlink_platform_security::read_private(&self.root.join("owned.json"),4096)?)?;
        for (name,device,inode) in owned.targets {
            let path=Path::new("/run/netns").join(&name);let metadata=std::fs::metadata(path)?;
            if metadata.dev()!=device||metadata.ino()!=inode {return Err(io::Error::other("lab target namespace identity changed; preserve it").into());}
            kernel::command("ip",&["netns","delete",&name]).await?;
        }
        for (name,index) in owned.bridges {let current=kernel::local_link(&name).await?;if current["ifindex"].as_u64()!=Some(index)||current["ifalias"]!=format!("NestLink:subnet:lab:{}",self.id) {return Err(io::Error::other("lab bridge identity changed; preserve it").into());}kernel::command("ip",&["link","delete","dev",&name]).await?;}
        // The whole dedicated root-private lab directory is expendable only
        // after every journal and exact kernel resource has been confirmed gone.
        std::fs::remove_dir_all(&self.root)?;
        Ok(())
    }
    pub async fn apply(&self,index:usize)->Result {
        let plan=Plan::read(&self.plan(index))?;
        nestlink_platform_security::create_private(&self.journal(index).join("lab-helper.json"),&serde_json::to_vec(&process_identity(std::process::id()).await?)?)?;
        use clap::Parser;
        let mut arguments=vec!["nestlink-daemon".into(),"network-subnet-system".into(),"apply".into(),"--plan".into(),plan.path.display().to_string(),"--journal-dir".into(),self.journal(index).display().to_string(),"--authority".into(),URL_SAFE_NO_PAD.encode(plan.authority),"--approve-access-digest".into(),URL_SAFE_NO_PAD.encode(plan.approved_access),"--approve-mapping-digest".into(),URL_SAFE_NO_PAD.encode(plan.approved_mapping),"--lan-interface".into(),plan.lan_index.to_string(),"--lan-gateway".into(),plan.lan_gateway.to_string()];
        if let Some(ingress)=&plan.wireguard {
            arguments.extend(["--approve-wireguard-binding-digest".into(),URL_SAFE_NO_PAD.encode(ingress.approved_binding),"--wireguard-client-endpoint".into(),ingress.client_endpoint.to_string(),"--wireguard-listen-port".into(),ingress.listen_port.to_string(),"--wireguard-server-private-key".into(),self.root.join("wireguard-server.key").display().to_string()]);
            if let Some(next)=ingress.underlay_next_hop {arguments.extend(["--wireguard-underlay-next-hop".into(),next.to_string()]);}
        }
        let arguments=crate::Args::try_parse_from(arguments)?;
        let Some(crate::Command::NetworkSubnetSystem(arguments))=arguments.command else {return Err(io::Error::other("native root helper command parsing differs").into());};
        helper::run(arguments).await
    }
    pub async fn kill(&self,index:usize,service:bool)->Result {
        let path=if service {self.root.join(format!("service{index}.json"))}else{self.journal(index).join("lab-helper.json")};
        let original:crate::space_dns_system::ProcessIdentity=serde_json::from_slice(&nestlink_platform_security::read_private(&path,4096)?)?;
        if process_identity(original.pid()).await?!=original||!crate::space_dns_system::current_image_matches(&original)? {return Err(io::Error::other("original native actor was replaced").into());}
        let pid=rustix::process::Pid::from_raw(i32::try_from(original.pid())?).ok_or_else(||io::Error::other("invalid original actor PID"))?;
        rustix::process::kill_process(pid,if service {rustix::process::Signal::TERM}else{rustix::process::Signal::KILL})?;Ok(())
    }
    pub async fn freeze_ordinary(&self)->Result {
        let plan=Plan::read(&self.plan(0))?;
        if process_identity(plan.process.pid()).await?!=plan.process||!crate::space_dns_system::current_image_matches(&plan.process)? {return Err(io::Error::other("the original ordinary lab owner was replaced").into());}
        let pid=rustix::process::Pid::from_raw(i32::try_from(plan.process.pid())?).ok_or_else(||io::Error::other("invalid original ordinary PID"))?;
        rustix::process::kill_process(pid,rustix::process::Signal::STOP)?;
        tokio::time::sleep(Duration::from_secs(7)).await;
        if process_identity(plan.process.pid()).await?!=plan.process {return Err(io::Error::other("ordinary lab owner changed during the bounded suspension").into());}
        rustix::process::kill_process(pid,rustix::process::Signal::CONT)?;Ok(())
    }
}
// Stateless nft output retains every table, chain, rule and configuration but
// excludes packet/byte counters changed by unrelated hosted-runner traffic.
async fn host()->Result<serde_json::Value> {Ok(serde_json::json!({"routes":kernel::ip(&["-j","-4","route","show","table","all"]).await?,"routes6":kernel::ip(&["-j","-6","route","show","table","all"]).await?,"firewall":serde_json::from_slice::<serde_json::Value>(&kernel::command("nft",&["--stateless","-j","list","ruleset"]).await?)?,"forwarding":std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?,"rp_filter":std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")?}))}
