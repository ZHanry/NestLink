//! Ordinary user production entry. Reuses installation admission, login
//! recovery/singleton, exact online start claim and pinned physical mTLS owner.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::network::GrantClaims;
use nestlink_sdk::{
    Sdk,
    network::{
        packet_access::{OnlinePacketAccess, PACKET_MTU},
        routed::PinnedNetworkSpace,
    },
};
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint, PacketAssembler, encode_direct};
use std::{net::SocketAddr, path::Path};
use tokio::time::Instant;

#[derive(clap::Args)]
pub(crate) struct TunArgs {
    /// Existing ordinary installation with protected login recovery enabled.
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    space: String,
    #[arg(long)]
    grant: String,
    /// Operator-pinned 32-byte space authority, URL-safe unpadded base64.
    #[arg(long)]
    authority: String,
    /// Explicit locally approved NetworkAccess digest; issuance alone is not consent.
    #[arg(long)]
    approve_digest: String,
    /// Exact physical underlay interface; never inferred from an overlay route.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    interface: u32,
    /// Concrete address on that original underlay. Port zero is allowed.
    #[arg(long)]
    bind: SocketAddr,
    /// Exact remote physical endpoint; omit on the accepting side.
    #[arg(long)]
    dial: Option<SocketAddr>,
    /// Fresh owner-private public plan for a separately invoked root helper.
    #[arg(long)]
    plan: PathBuf,
    /// Exact administrator-owned receipt selected for the separate Wintun helper.
    #[cfg(windows)]
    #[arg(long)]
    receipt: PathBuf,
}
fn bytes32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 43 {
        return Err(io::Error::other("expected 32-byte URL-safe unpadded base64 value").into());
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)?
        .try_into()
        .map_err(|_| io::Error::other("invalid pinned digest length"))?;
    if URL_SAFE_NO_PAD.encode(bytes) != value || bytes == [0; 32] {
        return Err(io::Error::other("noncanonical or zero pinned digest").into());
    }
    Ok(bytes)
}
pub(crate) async fn run(args: TunArgs) -> Result {
    #[cfg(target_os="linux")]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("network-tun must run as the original ordinary user; use a separate network-tun-system helper for OS configuration").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    #[cfg(windows)]
    let os=OwnerOs::new(args.receipt.clone())?;
    #[cfg(target_os="linux")]
    let os=OwnerOs::new()?;
    if args.bind.ip().is_unspecified()
        || args.bind.ip().is_multicast()
        || args.dial.is_some_and(|address| {
            address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
        })
    {
        return Err(io::Error::other("select concrete original underlay endpoints").into());
    }
    let approved = bytes32(&args.approve_digest)?;
    let pin = PinnedNetworkSpace::new(args.space.clone(), bytes32(&args.authority)?)?;
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    let sdk = crate::session_store::SessionStore::new(directory.clone())
        .restore()
        .await
        .ok_or_else(|| {
            io::Error::other(
                "sign in and enable protected login recovery before starting a managed TUN",
            )
        })?;
    let login = crate::space_dns::session_snapshot(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(
            io::Error::other("TUN requires the original registered installation identity").into(),
        );
    }
    let local = crate::identity(&directory)?;
    let owner_id = nestlink_auth::random_id();
    // The irreversible online claim happens before binding a packet socket,
    // creating a plan, or asking the helper for any OS resource. A lost start
    // response consumes this grant; this command never retries it.
    let mut access =
        OnlinePacketAccess::start(&sdk, &pin, &local, &args.grant, approved, owner_id.clone())
            .await?;
    let underlay = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(args.interface),
    )?;
    let mut endpoint =
        DirectPacketEndpoint::bind(args.bind, &local.identity, access.remote_peer(), underlay)?;
    println!(
        "Original pinned physical packet endpoint: {}",
        endpoint.local_addr()
    );
    let result = async {
        let view = tokio::time::timeout(Duration::from_secs(2),sdk.network_access(&args.space,&args.grant)).await??;
        let signed = nestlink_sdk::network_management::decode_network_grant(&view.access)?;
        let claims = GrantClaims::decode_canonical(&signed.claims)?;
        let scope = claims.scope();
        let now = system_wall_ms()?;
        let remaining = u64::try_from(access.remaining_lifetime().as_millis())?;
        let plan = TunPlan { schema_version:2, owner_id, space_id:args.space.clone(),
            process: process_identity(std::process::id()).await?, principal:plan::HostPrincipal::current()?,
            created_at_ms:now, expires_at_ms:scope.expires_at_ms.min(now.checked_add(remaining).ok_or_else(|| io::Error::other("TUN deadline overflow"))?),
            deployment_id:scope.deployment_id.clone(), authority_key:*pin.authority_key(),
            local_peer:nestlink_protocol::network::PeerId(local.identity.fingerprint()),remote_peer:access.remote_peer(),
            local_hosts:access.local_hosts(),remote_hosts:access.remote_hosts(),approved_digest:approved,policy_epoch:scope.policy_epoch,
            signed_claims:view.access.claims,signature:view.access.signature };
        if plan.remote_hosts.contains(&endpoint.local_addr().ip()) || args.dial.is_some_and(|address| plan.remote_hosts.contains(&address.ip())) {
            return Err(io::Error::other("managed overlay host routes must not capture the original physical peer endpoint").into());
        }
        plan.save_new(&args.plan)?;
        drop(installation);
        println!("Public TUN plan: {}",args.plan.display());
        #[cfg(target_os="linux")]
        println!("Review the exact plan, then separately run this same executable as root: network-tun-system apply --plan <above-path> --journal-dir <root-private-directory>");
        #[cfg(windows)]
        println!("Review the exact plan, then separately run this protected executable as administrator: network-tun-system apply --plan <above-path> --journal-dir <admin-private-directory> --driver <absolute-pinned-wintun.dll> --driver-sha256 <exact-architecture-hash> --receipt {}",args.receipt.display());
        let outcome = async {
            let state = wait_ready(&os,&plan,&sdk,&mut access,&directory,login).await?;
            let mut device = adopt_ready(&os,&plan,&state,&sdk,&mut access,&directory,login).await?;
            access.refresh(&sdk).await?;
            // Physical binding precedes every overlay route. While a peer is
            // connecting, keep the original online authority and local login
            // observed; no packet is consumed until mTLS and digest proof pass.
            establish(&os,&mut endpoint,args.dial,&sdk,&mut access,&directory,login,&plan,&state).await?;
            let result = packet_loop(&os,&device,&mut endpoint,&sdk,&mut access,&directory,login,&plan,&state).await;
            let stopped=device.shutdown().await;
            drop(device);
            stopped?;
            result
        }.await;
        access.stop();
        let cleanup = release_plan_with_os(&os,&plan,&args.plan).await;
        cleanup?;
        outcome
    }.await;
    access.stop();
    let released = endpoint
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await;
    // Always attempt and report physical carrier cleanup even on OS failure.
    released?;
    result
}

fn local_current(directory: &Path, login: [u8; 32]) -> Result {
    if nestlink_local_ipc::maintenance::requested(directory)? {
        return Err(io::Error::other(
            "installation maintenance requested; the original TUN is stopping",
        )
        .into());
    }
    if crate::space_dns::session_snapshot(directory).ok() != Some(login) {
        return Err(io::Error::other("original protected login changed; a TUN grant cannot survive logout or account replacement").into());
    }
    Ok(())
}
async fn wait_ready(
    os:&OwnerOs,
    plan: &TunPlan,
    sdk: &Sdk,
    access: &mut OnlinePacketAccess,
    directory: &Path,
    login: [u8; 32],
) -> Result<TunState> {
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut refreshed = Instant::now();
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Err(io::Error::other("original TUN stopped before administrator admission").into());},
            _=tick.tick()=>{
                local_current(directory,login)?;
                plan.validate(true)?;
                if refreshed.elapsed()>=Duration::from_secs(1) {access.refresh(sdk).await?;refreshed=Instant::now();}
                if let Some(state)=os.inspect(plan).await? {
                    // An incomplete original root installation is still DOWN;
                    // its UID/alias are set before persistence. Never open a
                    // descriptor until complete readback independently passes.
                    if os.ready(&state) {
                        os.verify(plan,&state)?;
                        return Ok(state);
                    }
                }
            },
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn adopt_ready(
    os:&OwnerOs,
    plan: &TunPlan,
    state: &TunState,
    sdk: &Sdk,
    access: &mut OnlinePacketAccess,
    directory: &Path,
    login: [u8; 32],
) -> Result<PacketDevice> {
    // UP becomes observable before the helper durably commits its readback and
    // closes its one creating queue. That original EBUSY is a handoff wait,
    // never permission to attach a changed interface or restart the business.
    let deadline = Instant::now() + access.remaining_lifetime().min(Duration::from_secs(2));
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let wait = async {
        let mut refreshed = Instant::now();
        loop {
            local_current(directory, login)?;
            plan.validate(true)?;
            if refreshed.elapsed() >= Duration::from_secs(1) {
                access.refresh(sdk).await?;
                refreshed = Instant::now();
            }
            match os.adopt(plan, state).await {
                Ok(device) => return Ok(device),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| cfg!(target_os="linux") && error.raw_os_error() == Some(16)) =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(error) => return Err(error),
            }
        }
    };
    tokio::select! {biased;
        result=&mut signal=>{result?;Err(io::Error::other("original TUN stopped before the exact privileged descriptor handoff").into())},
        result=tokio::time::timeout_at(deadline,wait)=>result.map_err(|_|io::Error::other("the original privileged TUN descriptor was not handed off within its finite bound"))?,
    }
}
#[allow(clippy::too_many_arguments)]
async fn establish(
    os:&OwnerOs,
    endpoint: &mut DirectPacketEndpoint,
    dial: Option<SocketAddr>,
    sdk: &Sdk,
    access: &mut OnlinePacketAccess,
    directory: &Path,
    login: [u8; 32],
    plan: &TunPlan,
    state: &TunState,
) -> Result {
    let binding = access.business_digest();
    let group = access.transport_group();
    let deadline = Instant::now() + access.remaining_lifetime().min(Duration::from_secs(10));
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let connection = endpoint.establish(dial, binding, group, deadline);
    tokio::pin!(connection);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Err(io::Error::other("original TUN stopped during physical peer proof").into());},
            _=tick.tick()=>{
                local_current(directory,login)?;
                access.refresh(sdk).await?;
                if os.inspect(plan).await?.as_ref()!=Some(state){return Err(io::Error::other("original managed TUN changed during peer proof").into());}
            },
            result=&mut connection=>return result,
        }
    }
}
#[derive(Default, Serialize)]
struct Counters {
    sent_packets: u64,
    received_packets: u64,
    rejected_packets: u64,
    spent_bytes: u64,
}
#[allow(clippy::too_many_arguments)]
async fn packet_loop(
    os:&OwnerOs,
    device: &PacketDevice,
    endpoint: &mut DirectPacketEndpoint,
    sdk: &Sdk,
    access: &mut OnlinePacketAccess,
    directory: &Path,
    login: [u8; 32],
    plan: &TunPlan,
    state: &TunState,
) -> Result {
    // A 65536-byte read prevents a provider truncating an oversized packet to
    // an apparently valid approved prefix. IPv6's 1280-byte complete packet is
    // split only by the already authenticated bounded carrier codec.
    let mut buffer = vec![0_u8; 65_536];
    let mut assembler = PacketAssembler::new(
        access.business_digest(),
        access.wire_direction().reverse(),
        PACKET_MTU,
    )?;
    let connection = endpoint.connection()?.clone();
    let mut sequence = 0_u64;
    let mut counters = Counters::default();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut refreshed = Instant::now();
    let outcome = loop {
        tokio::select! {biased;
            result=&mut signal=>break result.map_err(Into::into),
            _=tick.tick()=>{
                if let Err(error)=local_current(directory,login){break Err(error);}
                if refreshed.elapsed()>=Duration::from_secs(1){
                    if let Err(error)=access.refresh(sdk).await{break Err(error.into());}
                    if let Err(error)=endpoint.validate_underlay(){break Err(error.into());}
                    match os.inspect(plan).await {Ok(Some(current)) if current==*state=>{},Ok(_)=>break Err(io::Error::other("managed TUN configuration changed").into()),Err(error)=>break Err(error)}
                    refreshed=Instant::now();
                }
            },
            result=connection.read_datagram()=>{
                let bytes=match result{Ok(bytes)=>bytes,Err(error)=>break Err(error.into())};
                let packet=match assembler.insert(&bytes,std::time::Instant::now()){Ok(Some(packet))=>packet,Ok(None)=>continue,Err(error)=>break Err(error.into())};
                if access.admit_remote(&packet).is_err(){counters.rejected_packets=counters.rejected_packets.saturating_add(1);continue;}
                match tokio::time::timeout(Duration::from_millis(250),device.send(&packet)).await {
                    Ok(Ok(written)) if written==packet.len()=>counters.received_packets=counters.received_packets.saturating_add(1),
                    Ok(Err(error))=>break Err(error.into()),
                    _=>break Err(io::Error::other("complete TUN injection did not finish within its bound").into()),
                }
            },
            result=device.recv(&mut buffer)=>{
                let count=match result{Ok(count) if count>0=>count,Ok(_)=>break Err(io::Error::other("owned TUN descriptor ended").into()),Err(error)=>break Err(error.into())};
                if count>PACKET_MTU || access.admit_local(&buffer[..count]).is_err(){counters.rejected_packets=counters.rejected_packets.saturating_add(1);continue;}
                sequence=match sequence.checked_add(1){Some(value)=>value,None=>break Err(io::Error::other("raw packet sequence exhausted").into())};
                let fragments=match encode_direct(access.business_digest(),access.wire_direction(),sequence,&buffer[..count]){Ok(fragments)=>fragments,Err(error)=>break Err(error.into())};
                let mut failed=None;
                for fragment in fragments {if let Err(error)=connection.send_datagram(fragment.into()){failed=Some(error);break;}}
                if let Some(error)=failed{break Err(error.into());}
                counters.sent_packets=counters.sent_packets.saturating_add(1);
            },
        }
    };
    counters.spent_bytes = access.spent_bytes();
    // Only bounded aggregate counters are printed. No packet, address, signed
    // credential, application content or private key enters diagnostics.
    println!("TUN packet counters: {}", serde_json::to_string(&counters)?);
    outcome
}
#[cfg(all(test,target_os="linux"))]
pub(super) async fn release_plan(plan: &TunPlan, path: &Path) -> Result {
    release_plan_with_os(&OwnerOs::new()?,plan,path).await
}
pub(super) async fn release_plan_with_os(os:&OwnerOs,plan: &TunPlan, path: &Path) -> Result {
    match TunPlan::read(path) {
        Ok(current) if current == *plan => {
            std::fs::remove_file(path)?;
            #[cfg(target_os="linux")]
            std::fs::File::open(
                path.parent()
                    .ok_or_else(|| io::Error::other("TUN plan parent missing"))?,
            )?
            .sync_all()?;
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
        _ => {
            return Err(io::Error::other(
                "TUN plan changed; preserving the input file and awaiting exact root recovery",
            )
            .into());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    tokio::time::timeout_at(deadline,async {
        loop {
            if os.absent(plan).await?{return Ok::<(),Box<dyn std::error::Error+Send+Sync>>(());}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.map_err(|_|io::Error::other("original TUN/host-route cleanup was not confirmed within five seconds; root recovery journal is retained"))??;
    Ok(())
}
