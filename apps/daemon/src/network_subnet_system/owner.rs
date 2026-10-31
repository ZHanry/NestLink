use super::*;
use crate::network_packet_runtime::{GuardFuture, OwnerGuard, PacketAuthority};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_sdk::{
    Sdk,
    network::{
        packet_access::OnlinePacketAccess,
        routed::PinnedNetworkSpace,
        subnet::{SubnetInterface, SubnetInterfaces, SubnetLocalConsent},
    },
};
use nestlink_transport_quic::packet_codec::DirectPacketEndpoint;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(clap::Args)]
pub(crate) struct SubnetArgs {
    #[arg(long)]
    pub(super) state_dir: PathBuf,
    #[arg(long)]
    pub(super) space: String,
    #[arg(long)]
    pub(super) grant: String,
    #[arg(long)]
    pub(super) authority: String,
    #[arg(long)]
    pub(super) approve_access_digest: String,
    #[arg(long)]
    pub(super) approve_mapping_digest: String,
    /// The original physical carrier interface; never an overlay interface.
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..))]
    pub(super) interface: u32,
    #[arg(long)]
    pub(super) bind: SocketAddr,
    #[arg(long)]
    pub(super) dial: Option<SocketAddr>,
    #[arg(long)]
    pub(super) plan: PathBuf,
    /// Exact existing LAN parent selected for the new namespace's macvlan.
    #[arg(long)]
    pub(super) lan_name: String,
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..))]
    pub(super) lan_interface: u32,
    /// A separately approved unused address, never the host's existing address.
    #[arg(long)]
    pub(super) lan_gateway: Ipv4Addr,
    #[arg(long,value_parser=clap::value_parser!(u8).range(1..=30))]
    pub(super) lan_prefix_len: u8,
}
pub(super) fn pin(value: &str) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)?
        .try_into()
        .map_err(|_| io::Error::other("exact 32-byte public subnet pin required"))?;
    if bytes == [0; 32] || URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(io::Error::other("canonical nonzero public subnet pin required").into());
    }
    Ok(bytes)
}
pub(crate) async fn run(args: SubnetArgs) -> Result {
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("network-subnet must run as the original ordinary installation; invoke its OS helper separately as root").into());
    }
    if args.bind.ip().is_unspecified()
        || args.bind.ip().is_multicast()
        || args.dial.is_some_and(|address| {
            address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
        })
    {
        return Err(io::Error::other("exact original physical subnet endpoints required").into());
    }
    let approved_access = pin(&args.approve_access_digest)?;
    let approved_mapping = pin(&args.approve_mapping_digest)?;
    let authority = pin(&args.authority)?;
    let space = PinnedNetworkSpace::new(args.space.clone(), authority)?;
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
                "sign in and enable protected login recovery before starting a subnet gateway",
            )
        })?;
    let login = crate::space_dns::session_snapshot(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(io::Error::other(
            "subnet gateway requires its original explicitly bound registered installation",
        )
        .into());
    }
    let local = crate::identity(&directory)?;
    let owner_id = nestlink_auth::random_id();
    let mut access = OnlinePacketAccess::start(
        &sdk,
        &space,
        &local,
        &args.grant,
        approved_access,
        owner_id.clone(),
    )
    .await?;
    let underlay = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(args.interface),
    )?;
    let endpoint =
        DirectPacketEndpoint::bind(args.bind, &local.identity, access.remote_peer(), underlay)?;
    let now = system_wall_ms()?;
    let credentials = tokio::time::timeout(
        Duration::from_secs(2),
        sdk.network_access(&args.space, &args.grant),
    )
    .await??;
    let business = nestlink_protocol::network::GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&credentials.access)?.claims,
    )?;
    let expires_at_ms = business.scope().expires_at_ms.min(
        now.checked_add(u64::try_from(access.remaining_lifetime().as_millis())?)
            .ok_or_else(|| io::Error::other("original subnet deadline overflow"))?,
    );
    let mut physical_endpoints = vec![endpoint.local_addr().ip()];
    if let Some(remote) = args.dial {
        physical_endpoints.push(remote.ip());
    }
    let plan = Plan {
        schema_version: 1,
        owner_id,
        process: process_identity(std::process::id()).await?,
        uid: rustix::process::geteuid().as_raw(),
        path: args.plan,
        created_at_ms: now,
        expires_at_ms,
        deployment_id: business.scope().deployment_id.clone(),
        space_id: args.space,
        authority,
        local_public: local.identity.public_key(),
        approved_access,
        approved_mapping,
        lan_name: args.lan_name,
        lan_index: args.lan_interface,
        lan_gateway: args.lan_gateway,
        lan_prefix_len: args.lan_prefix_len,
        physical_endpoints,
        credentials,
        wireguard: None,
    };
    operate(
        Session {
            plan: &plan,
            sdk: &sdk,
            directory: &directory,
            login,
            installation,
            endpoint,
            dial: args.dial,
        },
        &mut access,
        |access, receipt| {
            // The privileged receipt supplies actual namespace interface indexes;
            // it cannot replace either original explicit local digest approval.
            access.subnet_plan(
                SubnetLocalConsent::approve(
                    plan.owner_id.clone(),
                    approved_mapping,
                    approved_access,
                )?,
                SubnetInterfaces {
                    tun: SubnetInterface {
                        index: receipt.tun_index,
                        name: plan.tun(),
                    },
                    lan: SubnetInterface {
                        index: receipt.macvlan_index,
                        name: plan.macvlan(),
                    },
                },
                &plan.physical_endpoints,
            )?;
            Ok(())
        },
    )
    .await
}
pub(super) struct Session<'a> {
    pub plan: &'a Plan,
    pub sdk: &'a Sdk,
    pub directory: &'a Path,
    pub login: [u8; 32],
    pub installation: nestlink_local_ipc::maintenance::InstallationStartup,
    pub endpoint: DirectPacketEndpoint,
    pub dial: Option<SocketAddr>,
}
pub(super) async fn operate<A: PacketAuthority + ?Sized, F: FnOnce(&mut A, &Receipt) -> Result>(
    session: Session<'_>,
    access: &mut A,
    prepare: F,
) -> Result {
    let Session {
        plan,
        sdk,
        directory,
        login,
        installation,
        mut endpoint,
        dial,
    } = session;
    let parent = kernel::parent(plan).await?;
    let result=async {
        plan.save_new()?;drop(installation);
        println!("Original packet ingress public plan: {}",plan.path.display());
        println!("Apply this exact plan with the separate root network-subnet-system command and its independent authority, business, mapping and physical exposure approvals.");
        let pipe=wait_ready(plan,sdk,access,directory,login).await?;
        prepare(access,&pipe.receipt)?;
        let guard=Guard{plan,pipe:&pipe,directory,login,parent};
        let outcome=async {
            pipe.during_peer_proof(crate::network_packet_runtime::establish(&mut endpoint,dial,sdk,access,&guard)).await?;
            crate::network_packet_runtime::packet_loop(&pipe,&mut endpoint,sdk,access,&guard).await
        }.await;
        access.stop();pipe.shutdown().await?;drop(pipe);
        outcome
    }.await;
    access.stop();
    let cleanup = release(plan).await;
    let close = endpoint
        .close_and_wait(tokio::time::Instant::now() + Duration::from_secs(5))
        .await;
    cleanup?;
    close?;
    result
}
async fn wait_ready<A: PacketAuthority + ?Sized>(
    plan: &Plan,
    sdk: &Sdk,
    access: &mut A,
    directory: &Path,
    login: [u8; 32],
) -> Result<pipe::PacketPipe> {
    let deadline = tokio::time::Instant::now() + access.remaining_lifetime();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut fetched = tokio::time::Instant::now();
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Err(io::Error::other("original subnet owner stopped before root admission").into());},
            _=tokio::time::sleep_until(deadline)=>return Err(io::Error::other("original subnet grant expired before root admission").into()),
            _=tick.tick()=>{
                local_current(plan,directory,login)?;
                if fetched.elapsed()>=Duration::from_secs(1){access.refresh(sdk).await?;fetched=tokio::time::Instant::now();}
                match pipe::PacketPipe::connect(plan).await {Ok(pipe)=>return Ok(pipe),Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|matches!(error.kind(),io::ErrorKind::NotFound|io::ErrorKind::ConnectionRefused))=>{},Err(error)=>return Err(error)}
            },
        }
    }
}
fn local_current(plan: &Plan, directory: &Path, login: [u8; 32]) -> Result {
    plan.checked(true)?;
    if nestlink_local_ipc::maintenance::requested(directory)?
        || crate::space_dns::session_snapshot(directory).ok() != Some(login)
    {
        return Err(io::Error::other(
            "original subnet installation login or maintenance state changed",
        )
        .into());
    }
    Ok(())
}
struct Guard<'a> {
    plan: &'a Plan,
    pipe: &'a pipe::PacketPipe,
    directory: &'a Path,
    login: [u8; 32],
    parent: serde_json::Value,
}
impl OwnerGuard for Guard<'_> {
    fn check_local(&self) -> Result {
        local_current(self.plan, self.directory, self.login)
    }
    fn check(&self) -> GuardFuture<'_> {
        Box::pin(async move {
            tokio::time::timeout(Duration::from_millis(250), self.pipe.heartbeat()).await??;
            if Plan::read(&self.plan.path)?.digest()? != self.plan.digest()?
                || self.pipe.receipt.plan_digest != self.plan.digest()?
                || kernel::parent(self.plan).await? != self.parent
            {
                return Err(io::Error::other(
                    "original subnet intent, root receipt or physical LAN identity changed",
                )
                .into());
            }
            Ok(())
        })
    }
}
async fn release(plan: &Plan) -> Result {
    match Plan::read(&plan.path) {
        Ok(current) if current.digest()? == plan.digest()? => {
            std::fs::remove_file(&plan.path)?;
            std::fs::File::open(
                plan.path
                    .parent()
                    .ok_or_else(|| io::Error::other("subnet plan parent missing"))?,
            )?
            .sync_all()?;
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
        _ => {
            return Err(
                io::Error::other("subnet intent changed; retain original recovery state").into(),
            );
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while kernel::namespace(&kernel::namespace_path(plan))?.is_some() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| {
        io::Error::other(
            "exact namespace/conntrack cleanup was not confirmed; retain root recovery journal",
        )
    })??;
    Ok(())
}
