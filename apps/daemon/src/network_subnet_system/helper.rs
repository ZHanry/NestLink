use super::*;
use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
use std::{os::unix::fs::MetadataExt,process::Stdio};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},process::Command};

#[derive(clap::Args)]
pub(crate) struct SystemSubnetArgs {#[command(subcommand)]action:Action}
#[derive(clap::Subcommand)]
enum Action {
    /// Generate one stable root-private portal key with mature distribution wg.
    GenerateWireguardServerKey {#[arg(long)]private_key:PathBuf,#[arg(long)]public_key:PathBuf},
    InitJournal {#[arg(long)]journal_dir:PathBuf},
    Review {#[arg(long)]plan:PathBuf},
    Apply {
        #[arg(long)]plan:PathBuf,
        /// Preapprove fixed pins before the ordinary owner creates its fresh plan.
        #[arg(long,default_value_t=0,value_parser=clap::value_parser!(u16).range(0..=60))]wait_seconds:u16,
        #[arg(long)]journal_dir:PathBuf,
        #[arg(long)]authority:String,
        #[arg(long)]approve_access_digest:String,
        #[arg(long)]approve_mapping_digest:String,
        #[arg(long)]lan_interface:u32,
        #[arg(long)]lan_gateway:std::net::Ipv4Addr,
        /// Required only for a standard WireGuard ingress plan.
        #[arg(long)]approve_wireguard_binding_digest:Option<String>,
        #[arg(long)]wireguard_client_endpoint:Option<std::net::SocketAddrV4>,
        #[arg(long)]wireguard_listen_port:Option<u16>,
        #[arg(long)]wireguard_underlay_next_hop:Option<std::net::Ipv4Addr>,
        /// Root-private stable portal key; never an ordinary plan/CLI secret.
        #[arg(long)]wireguard_server_private_key:Option<PathBuf>,
    },
    Recover {#[arg(long)]journal_dir:PathBuf},
    Inspect {#[arg(long)]journal_dir:PathBuf},
}
pub(crate) async fn run(args:SystemSubnetArgs)->Result {
    match args.action {
        Action::GenerateWireguardServerKey{private_key,public_key}=>{require_system_admin().await?;crate::wireguard::generate_key(&private_key,&public_key,"portal server").await},
        Action::Review{plan}=>{println!("{}",serde_json::to_string_pretty(&Plan::read(&plan)?)?);Ok(())},
        Action::InitJournal{journal_dir}=>{require_system_admin().await?;if !journal_dir.is_absolute(){return Err(io::Error::other("absolute root-private subnet journal directory required").into());}match nestlink_platform_security::new_private_directory(&journal_dir){Ok(())=>{},Err(error) if error.kind()==io::ErrorKind::AlreadyExists=>nestlink_platform_security::check_private_directory(&journal_dir)?,Err(error)=>return Err(error.into())}Ok(())},
        Action::Recover{journal_dir}=>{require_system_admin().await?;recover(&journal::Store::open(&journal_dir)?).await},
        Action::Inspect{journal_dir}=>{require_system_admin().await?;let store=journal::Store::open(&journal_dir)?;println!("{}",serde_json::to_string_pretty(&store.read()?)?);Ok(())},
        Action::Apply{plan:path,wait_seconds,journal_dir,authority,approve_access_digest,approve_mapping_digest,lan_interface,lan_gateway,approve_wireguard_binding_digest,wireguard_client_endpoint,wireguard_listen_port,wireguard_underlay_next_hop,wireguard_server_private_key}=>{
            require_system_admin().await?;
            // The administrator selects three independent pins and the LAN
            // exposure. A normal process cannot authorize its own root plan.
            let deadline=tokio::time::Instant::now()+Duration::from_secs(u64::from(wait_seconds));
            let plan=loop {match Plan::read(&path) {Ok(plan)=>break plan,Err(error) if tokio::time::Instant::now()<deadline&&error.downcast_ref::<io::Error>().is_some_and(|error|error.kind()==io::ErrorKind::NotFound)=>tokio::time::sleep(Duration::from_millis(50)).await,Err(error)=>return Err(error)}};plan.initial()?;
            if URL_SAFE_NO_PAD.encode(plan.authority)!=authority||URL_SAFE_NO_PAD.encode(plan.approved_access)!=approve_access_digest||URL_SAFE_NO_PAD.encode(plan.approved_mapping)!=approve_mapping_digest||plan.lan_index!=lan_interface||plan.lan_gateway!=lan_gateway {return Err(io::Error::other("subnet plan differs from explicit administrator approval").into());}
            let server_secret=match &plan.wireguard {
                Some(ingress)=>{
                    if approve_wireguard_binding_digest.as_deref()!=Some(URL_SAFE_NO_PAD.encode(ingress.approved_binding).as_str())||wireguard_client_endpoint!=Some(ingress.client_endpoint)||wireguard_listen_port!=Some(ingress.listen_port)||wireguard_underlay_next_hop!=ingress.underlay_next_hop {return Err(io::Error::other("WireGuard ingress differs from independent administrator binding/endpoint/port/next-hop approval").into());}
                    let path=wireguard_server_private_key.as_ref().ok_or_else(||io::Error::other("root-private stable WireGuard portal key path required"))?;
                    if !path.is_absolute(){return Err(io::Error::other("absolute root-private stable portal key path required").into());}
                    let encoded=nestlink_platform_security::read_private(path,128)?;
                    let secret=zeroize::Zeroizing::new(crate::wireguard::key(std::str::from_utf8(&encoded)?.trim_end_matches('\n'))?);
                    if crate::wireguard::public_key_for(&secret).await?!=ingress.server_public_key {return Err(io::Error::other("stable portal private key does not match the explicitly approved WireGuard server public key").into());}
                    Some(secret)
                },
                None if approve_wireguard_binding_digest.is_none()&&wireguard_client_endpoint.is_none()&&wireguard_listen_port.is_none()&&wireguard_underlay_next_hop.is_none()&&wireguard_server_private_key.is_none()=>None,
                None=>return Err(io::Error::other("WireGuard key/approvals cannot be attached to an ordinary subnet plan").into()),
            };
            let owner=nestlink_platform_security::local_port_gate::ProcessIdentity::read(plan.process.pid())?;
            let helper=nestlink_platform_security::local_port_gate::ProcessIdentity::read(std::process::id())?;
            if owner.uid!=plan.uid||owner.uid==0||helper.uid!=0||owner.image_device!=helper.image_device||owner.image_inode!=helper.image_inode||process_identity(plan.process.pid()).await?!=plan.process {return Err(io::Error::other("subnet administrator and original ordinary owner must use the same executable inode").into());}
            let store=journal::Store::open(&journal_dir)?;recover(&store).await?;
            let socket=pipe::SocketDirectory::open(&plan)?;
            if socket.device!=std::fs::metadata(&store.directory)?.dev() {return Err(io::Error::other("root journal and ordinary subnet plan must share a filesystem for crash-safe socket handoff").into());}
            if pipe::socket_metadata(&store.socket_path())?.is_some() {return Err(io::Error::other("unclaimed root-private subnet socket; preserve journal directory").into());}
            drop(socket);
            let parent=kernel::preflight(&plan).await?;
            store.consume(&plan)?;
            let mut journal=journal::Journal{schema_version:1,plan,parent,namespace:None,receipt:None};store.save(&journal)?;
            let result=apply(&store,&mut journal,server_secret.as_deref()).await;
            let cleanup=recover(&store).await;
            cleanup?;result
        }
    }
}
async fn apply(store:&journal::Store,journal:&mut journal::Journal,server_secret:Option<&[u8;32]>)->Result {
    let executable=std::env::current_exe()?;
    let mut command=Command::new(kernel::tool("unshare")?);
    command.args(["--net","--fork","--kill-child=SIGKILL","--"]).arg(&executable)
        .env_clear().env("LANG","C.UTF-8").env("LC_ALL","C.UTF-8").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(not(test))]
    command.arg("network-subnet-worker").arg("--journal").arg(store.path());
    #[cfg(test)]
    {command.args(["--exact",super::native_tests::ROLE_TEST,"--ignored","--nocapture","--test-threads=1"]).env("GITHUB_ACTIONS","true").env("NESTLINK_SUBNET_NATIVE_LAB","1").env("NESTLINK_SUBNET_NATIVE_ROLE","worker").env("NESTLINK_SUBNET_NATIVE_JOURNAL",store.path());}
    let mut child=command.spawn()?;
    let mut input=child.stdin.take().ok_or_else(||io::Error::other("subnet root control pipe missing"))?;
    let mut output=child.stdout.take().ok_or_else(||io::Error::other("subnet root namespace observation pipe missing"))?;
    let stderr=child.stderr.take().ok_or_else(||io::Error::other("subnet root diagnostic pipe missing"))?;
    let diagnostic=tokio::spawn(async move {let mut bytes=Vec::new();stderr.take(4_097).read_to_end(&mut bytes).await?;Ok::<_,io::Error>(bytes)});
    let outcome:Result=async {
        tokio::time::timeout(Duration::from_secs(2),pipe::control_start(&mut output)).await??;
        let namespace:journal::Namespace=serde_json::from_slice(&tokio::time::timeout(Duration::from_secs(2),pipe::message(&mut output)).await??)?;
        let actual=std::fs::metadata(format!("/proc/{}/ns/net",namespace.worker.pid()))?;
        let host=std::fs::metadata("/proc/self/ns/net")?;
        if actual.dev()!=namespace.device||actual.ino()!=namespace.inode||(actual.dev()==host.dev()&&actual.ino()==host.ino())||process_identity(namespace.worker.pid()).await?!=namespace.worker||!crate::space_dns_system::current_image_matches(&namespace.worker)? {return Err(io::Error::other("subnet worker did not prove its exact isolated namespace").into());}
        journal.namespace=Some(namespace);store.save(journal)?;
        kernel::attach(&journal.plan,journal.namespace.as_ref().ok_or_else(||io::Error::other("committed namespace missing"))?).await?;
        if kernel::parent(&journal.plan).await?!=journal.parent {return Err(io::Error::other("physical LAN parent changed during namespace creation").into());}
        input.write_u8(0xa5).await?;
        if let Some(secret)=server_secret {input.write_all(secret).await?;input.flush().await?;}
        let receipt:Receipt=serde_json::from_slice(&tokio::time::timeout(Duration::from_secs(7),pipe::message(&mut output)).await??)?;
        let namespace=journal.namespace.as_ref().ok_or_else(||io::Error::other("committed namespace missing"))?;
        let socket=pipe::socket_metadata(&store.socket_path())?.ok_or_else(||io::Error::other("subnet socket must remain root-private before durable handoff"))?;
        let parent=pipe::SocketDirectory::open(&journal.plan)?;
        if receipt.plan_digest!=journal.plan.digest()?||receipt.worker!=namespace.worker||receipt.namespace_inode!=namespace.inode||receipt.namespace_device!=namespace.device||receipt.tun_index==0||receipt.macvlan_index==0||receipt.socket_device!=socket.dev()||receipt.socket_inode!=socket.ino()||!parent.matches(&receipt)||journal.plan.wireguard.is_some()!=receipt.wireguard_index.is_some()||receipt.wireguard_index==Some(0) {return Err(io::Error::other("subnet worker receipt differs from committed resources").into());}
        journal.receipt=Some(receipt);store.save(journal)?;
        input.write_u8(0x5a).await?;
        let mut tick=tokio::time::interval(Duration::from_millis(250));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let signal=crate::space_dns_system::termination();tokio::pin!(signal);
        let mut observed=tokio::time::Instant::now();
        loop {tokio::select! {biased;
            result=&mut signal=>return result.map_err(Into::into),
            status=child.wait()=>{if status?.success(){return Ok(());}return Err(io::Error::other("original isolated subnet worker stopped; recovering exact namespace").into());},
            _=tick.tick()=>{
                journal.plan.checked(true)?;
                if Plan::read(&journal.plan.path)?.digest()?!=journal.plan.digest()?||process_identity(journal.plan.process.pid()).await?!=journal.plan.process {return Err(io::Error::other("original ordinary subnet owner ended or replaced its plan").into());}
                if observed.elapsed()>=Duration::from_secs(1) {if kernel::parent(&journal.plan).await?!=journal.parent{return Err(io::Error::other("original physical LAN identity changed").into());}observed=tokio::time::Instant::now();}
            },
        }}
    }.await;
    drop(input);
    if tokio::time::timeout(Duration::from_secs(1),child.wait()).await.is_err(){let _=child.kill().await;let _=child.wait().await;}
    let diagnostics=tokio::time::timeout(Duration::from_secs(1),diagnostic).await???;
    if diagnostics.len()>4_096 {return Err(io::Error::other("subnet worker diagnostics exceeded their fixed byte budget").into());}
    match outcome {Ok(())=>Ok(()),Err(error)=>Err(io::Error::other(format!("{error}; isolated worker diagnostic: {}",String::from_utf8_lossy(&diagnostics))).into())}
}
pub(super) async fn recover(store:&journal::Store)->Result {
    let Some(journal)=store.read()? else {return Ok(());};
    if let Some(namespace)=&journal.namespace {
        // The stdin lifetime and util-linux parent-death signal terminate a
        // worker after helper loss. Never signal a possibly reused bare PID.
        match process_identity(namespace.worker.pid()).await {Ok(process) if process==namespace.worker=>return Err(io::Error::other("original subnet worker is still alive; retain journal until its control pipe closes").into()),Ok(_)=>{},Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|error.kind()==io::ErrorKind::NotFound)=>{},Err(error)=>return Err(error)}
        let path=kernel::namespace_path(&journal.plan);
        if let Some(current)=kernel::namespace(&path)? {
            if current!=(namespace.device,namespace.inode) {return Err(io::Error::other("namespace name was replaced; refusing foreign resource cleanup").into());}
            kernel::command("ip",&["netns","delete",&journal.plan.namespace()]).await?;
            if kernel::namespace(&path)?.is_some(){return Err(io::Error::other("original namespace removal was not confirmed").into());}
        }
    }
    // The only socket that can be exposed to an ordinary directory already
    // has its immutable inode in this durable receipt. An uncommitted staging
    // socket can exist only inside this root-private, exclusively locked store.
    pipe::remove_socket(&store.socket_path(),journal.receipt.as_ref())?;
    if let Some(receipt)=&journal.receipt {
        let parent=pipe::SocketDirectory::open(&journal.plan)?;
        if !parent.matches(receipt) {return Err(io::Error::other("original subnet socket directory was replaced; retain recovery journal").into());}
        pipe::remove_socket(&parent.path,Some(receipt))?;
    }
    store.clear()
}
