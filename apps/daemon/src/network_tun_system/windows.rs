//! The administrator owns only one pinned provider, exact OS state and a local
//! packet pipe. The ordinary process owns online authority and all transport.
use super::*;
use nestlink_privileged::windows::network_tun::{
    AdminJournal, PacketReceipt, PacketServer, PinnedProviderImage, ProviderIdentity,
    resources::{self, Snapshot},
};
use std::{net::IpAddr, path::Path};
#[cfg(test)]
mod native_tests;

#[derive(clap::Args)]
pub(crate) struct SystemTunArgs {
    #[command(subcommand)]
    action: Action,
}
#[derive(clap::Subcommand)]
enum Action {
    InitJournal {
        #[arg(long)]
        journal_dir: PathBuf,
    },
    Review {
        #[arg(long)]
        plan: PathBuf,
    },
    Apply {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        journal_dir: PathBuf,
        /// Explicit administrator-selected absolute signed Wintun DLL.
        #[arg(long)]
        driver: PathBuf,
        /// Exact per-architecture DLL SHA256, 64 lowercase hexadecimal digits.
        #[arg(long)]
        driver_sha256: String,
        /// Fresh administrator-owned, original-user-readable receipt file.
        #[arg(long)]
        receipt: PathBuf,
    },
    Inspect {
        #[arg(long)]
        journal_dir: PathBuf,
    },
    Recover {
        #[arg(long)]
        journal_dir: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u16,
    plan: TunPlan,
    guid: String,
    name: String,
    driver_sha256: [u8; 32],
    receipt_path: PathBuf,
    identity: Option<ProviderIdentity>,
    installed: Option<Snapshot>,
    receipt: Option<PacketReceipt>,
}
impl Record {
    fn save(&self, store: &AdminJournal) -> Result {
        store.save(&serde_json::to_vec(self)?)?;
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self> {
        let record: Self = serde_json::from_slice(bytes)?;
        record.plan.validate(false)?;
        if record.schema_version != 1
            || record.name != format!("NestLink-{}", record.guid)
            || record.driver_sha256 == [0; 32]
            || !record.receipt_path.is_absolute()
        {
            return Err(io::Error::other("invalid protected Windows TUN recovery record").into());
        }
        resources::guid_value(&record.guid)?;
        if let Some(identity) = &record.identity
            && (identity.adapter_guid != record.guid
                || identity.name != record.name
                || identity.provider_sha256 != record.driver_sha256)
        {
            return Err(io::Error::other(
                "Windows TUN identity differs from original creation intent",
            )
            .into());
        }
        if let Some(receipt) = &record.receipt
            && (record.identity.as_ref() != Some(&receipt.provider)
                || receipt.binding.owner_id != record.plan.owner_id
                || receipt.binding.plan_sha256 != record.plan.digest()?
                || receipt.binding.expires_at_ms != record.plan.expires_at_ms)
        {
            return Err(io::Error::other(
                "Windows TUN receipt differs from original recovery intent",
            )
            .into());
        }
        Ok(record)
    }
    fn capture(&self) -> Result<Option<ProviderIdentity>> {
        Ok(resources::capture(
            &self.guid,
            &self.name,
            self.driver_sha256,
        )?)
    }
}
fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::other("expected exact lowercase Wintun DLL SHA256").into());
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(out)
}
fn native<T>(operation: &str, result: io::Result<T>) -> Result<T> {
    result.map_err(|error| {
        io::Error::new(error.kind(), format!("Windows TUN {operation}: {error}")).into()
    })
}
pub(crate) async fn run(args: SystemTunArgs) -> Result {
    match args.action {
        Action::Review { plan } => {
            let plan = TunPlan::read(&plan)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            println!(
                "Only signed local /32 and /128 addresses and exact remote host routes. No default route, DNS, forwarding, login or remote listener."
            );
            Ok(())
        }
        Action::InitJournal { journal_dir } => {
            AdminJournal::initialize(&journal_dir)?;
            println!(
                "Private TUN recovery journal ready: {}",
                journal_dir.display()
            );
            Ok(())
        }
        Action::Inspect { journal_dir } => {
            let store = AdminJournal::open(&journal_dir)?;
            let record = store
                .read()?
                .map(|bytes| Record::read(&bytes))
                .transpose()?;
            let current = record.as_ref().map(Record::capture).transpose()?.flatten();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"journal":record,"current":current})
                )?
            );
            Ok(())
        }
        Action::Recover { journal_dir } => recover(&AdminJournal::open(&journal_dir)?).await,
        Action::Apply {
            plan: path,
            journal_dir,
            driver,
            driver_sha256,
            receipt,
        } => apply(path, journal_dir, driver, hash(&driver_sha256)?, receipt).await,
    }
}
async fn apply(
    path: PathBuf,
    journal_dir: PathBuf,
    driver: PathBuf,
    pin: [u8; 32],
    receipt_path: PathBuf,
) -> Result {
    require_system_admin().await?;
    let plan = TunPlan::read(&path)?;
    plan.validate(true)?;
    let binding = plan.windows_binding().await?;
    let helper =
        nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(std::process::id())?;
    if !crate::space_dns_system::current_image_matches(&plan.process)?
        || helper.image_volume != binding.process.image_volume
        || helper.image_index != binding.process.image_index
    {
        return Err(io::Error::other(
            "ordinary TUN owner and administrator must use the same protected original executable",
        )
        .into());
    }
    // Pinning and protected ancestor handles live beyond provider shutdown.
    let image = PinnedProviderImage::open(&driver, pin)?;
    let store = AdminJournal::open(&journal_dir)?;
    recover(&store).await?;
    nestlink_privileged::windows::network_tun::validate_receipt_destination(&receipt_path)?;
    let guid = nestlink_auth::random_id();
    let name = format!("NestLink-{guid}");
    resources::preflight(&guid, &name, &plan.local_hosts, &plan.remote_hosts)?;
    let mut record = Record {
        schema_version: 1,
        plan,
        guid,
        name,
        driver_sha256: pin,
        receipt_path,
        identity: None,
        installed: None,
        receipt: None,
    };
    record.save(&store)?;
    let mut device = None;
    let outcome=async {
        // A fresh random identity is journaled before create. Never open an
        // existing named adapter or delete the shared installed Wintun driver.
        let created=native("create original pinned provider and session",tun_rs::DeviceBuilder::new().name(&record.name).description(record.plan.marker())
            .device_guid(resources::guid_value(&record.guid)?)
            .wintun_file(image.path().to_str().ok_or_else(||io::Error::other("non-Unicode pinned Wintun path"))?.into())
            .delete_driver(false).mtu(1280).build_async())?;
        device=Some(created);
        let original=device.as_ref().ok_or_else(||io::Error::other("provider missing"))?;
        let identity=record.capture()?.ok_or_else(||io::Error::other("created original Wintun adapter missing"))?;
        if identity.index!=original.if_index()?{return Err(io::Error::other("Wintun provider and kernel adapter differ").into());}
        record.identity=Some(identity.clone());record.save(&store)?;
        resources::isolate(&identity)?;
        for address in native("list fresh provider addresses",original.addresses())? {native(&format!("remove fresh automatic address {address}"),original.remove_address(address))?;}
        let [IpAddr::V4(v4),IpAddr::V6(v6)]=record.plan.local_hosts else {return Err(io::Error::other("signed dual-stack hosts missing").into());};
        if record.capture()?.as_ref()!=Some(&identity) {
            return Err(io::Error::other("original TUN adapter changed before static IPv4 configuration").into());
        }
        // NetIO rejects the LinkLocalAddressBehavior mutation. Use the
        // reviewed Windows static-address operation on this fresh original
        // adapter only; an active-only /32 disables DHCP without a gateway.
        // Independent NetIO/GetAdaptersInfo readback below must still prove
        // DHCP is off and that only the two signed manual hosts/routes exist.
        let netsh=nestlink_platform_network::system_tools::windows_netsh()?;
        let system_root=netsh.parent().and_then(Path::parent)
            .ok_or_else(||io::Error::other("trusted Windows system root missing"))?;
        crate::space_dns_system::native_command(&netsh,&[
            "interface".into(),"ipv4".into(),"set".into(),"address".into(),
            format!("name={}",identity.index),"source=static".into(),
            format!("address={v4}"),"mask=255.255.255.255".into(),
            "gateway=none".into(),"store=active".into(),
        ],Some(("SystemRoot",system_root.to_str()
            .ok_or_else(||io::Error::other("Windows system root is not Unicode"))?.into()))).await?;
        if record.capture()?.as_ref()!=Some(&identity) {
            return Err(io::Error::other("original TUN adapter changed during static IPv4 configuration").into());
        }
        native("add signed IPv6 host",original.add_address_v6(v6,128))?;
        native("set IPv4 MTU",original.set_mtu(1280))?;native("set IPv6 MTU",original.set_mtu_v6(1280))?;
        resources::install_routes(&identity,&record.plan.local_hosts,&record.plan.remote_hosts)?;
        let snapshot=resources::inspect(&identity)?.ok_or_else(||io::Error::other("Wintun disappeared during readback"))?;
        snapshot.verify(&record.plan.local_hosts,&record.plan.remote_hosts)?;
        let mut identity=identity;identity.configuration_sha256=snapshot.digest()?;
        record.identity=Some(identity.clone());record.installed=Some(snapshot);record.save(&store)?;
        let mut server=PacketServer::bind(binding,identity)?;
        record.receipt=Some(server.receipt().clone());record.save(&store)?;
        server.publish_receipt(&record.receipt_path)?;
        println!("Original Wintun provider ready; protected receipt {}",record.receipt_path.display());
        let signal=crate::space_dns_system::termination();tokio::pin!(signal);
        let pipe=tokio::select! {biased;result=&mut signal=>{result?;return Ok(());},result=server.accept()=>result?};
        let result=pump(original,&pipe,&server,&record,&path).await;
        let stopped=pipe.shutdown().await;drop(pipe);stopped?;result
    }.await;
    // Dropping the original provider closes its own adapter/session. Native
    // identity absence, not a successful destructor call, completes cleanup.
    drop(device);
    let cleanup = confirm_absence(&record).await;
    if cleanup.is_ok() {
        clear_record(&store, &record)?;
    }
    drop(image);
    cleanup?;
    outcome
}
async fn pump(
    device: &tun_rs::AsyncDevice,
    pipe: &nestlink_privileged::windows::network_tun::PacketPipe,
    server: &PacketServer,
    record: &Record,
    path: &Path,
) -> Result {
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut kernel = [0_u8; 65_536];
    let mut ordinary = [0_u8; 1280];
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Ok(());},
            _=tick.tick()=>{
                server.check_current()?;
                match TunPlan::read(path){Ok(current) if current==record.plan=>{},_=>return Ok(())}
                let identity=record.identity.as_ref().ok_or_else(||io::Error::other("original provider identity missing"))?;
                if resources::inspect(identity)?!=record.installed{return Err(io::Error::other("owned Windows TUN state changed; recovery record retained").into());}
            },
            received=device.recv(&mut kernel)=>{let count=received?;if count==0||count>1280{return Err(io::Error::other("provider returned an oversized or empty complete packet").into());}pipe.send(&kernel[..count]).await?;},
            received=pipe.recv(&mut ordinary)=>{
                let count=match received {Ok(count)=>count,Err(error) if matches!(error.kind(),io::ErrorKind::UnexpectedEof|io::ErrorKind::BrokenPipe|io::ErrorKind::NotConnected)=>return Ok(()),Err(error)=>return Err(error.into())};
                let written=tokio::time::timeout(Duration::from_millis(250),device.send(&ordinary[..count])).await??;if written!=count{return Err(io::Error::other("incomplete Windows provider injection").into());}
            },
        }
    }
}
async fn confirm_absence(record: &Record) -> Result {
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let absent=match &record.identity {Some(identity)=>resources::absent(identity)?,None=>record.capture()?.is_none()};
            if absent{return Ok::<(),Box<dyn std::error::Error+Send+Sync>>(());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.map_err(|_|io::Error::other("original Wintun adapter absence not observed within five seconds; protected recovery record retained"))??;
    Ok(())
}
fn clear_record(store: &AdminJournal, record: &Record) -> Result {
    if let Some(receipt) = &record.receipt {
        nestlink_privileged::windows::network_tun::clear_receipt(
            &record.receipt_path,
            &serde_json::to_vec(receipt)?,
        )?;
    }
    store.clear(&serde_json::to_vec(record)?)?;
    Ok(())
}
async fn recover(store: &AdminJournal) -> Result {
    let Some(bytes) = store.read()? else {
        return Ok(());
    };
    let record = Record::read(&bytes)?;
    if system_wall_ms()? < record.plan.expires_at_ms
        && process_identity(record.plan.process.pid())
            .await
            .ok()
            .as_ref()
            == Some(&record.plan.process)
    {
        return Err(io::Error::other(
            "original ordinary owner is still alive; stop it before Windows TUN recovery",
        )
        .into());
    }
    // A crashed Wintun creator should lose its original software-device handle.
    // Never reopen a surviving GUID just to delete it: that would silently
    // adopt another session. Retain a visible exact recovery failure instead.
    confirm_absence(&record).await?;
    clear_record(store, &record)?;
    println!("Original Wintun adapter absent; exact protected journal recovered.");
    Ok(())
}
