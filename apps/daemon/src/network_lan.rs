//! The existing resident packet owner with explicit bounded local LAN adapters.
use crate::network_packet_runtime::{GuardFuture, OwnerGuard, PacketIoFuture, WholePacketDevice};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_sdk::network::{
    lan::{LanBridge, LanPolicy},
    packet_access::OnlinePacketAccess,
    routed::PinnedNetworkSpace,
};
use nestlink_transport_quic::packet_codec::DirectPacketEndpoint;
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) mod attached;

#[derive(clap::Args)]
pub(crate) struct LanArgs {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    space: String,
    #[arg(long)]
    grant: String,
    #[arg(long)]
    authority: String,
    /// Explicit original signed NetworkAccess digest; never implied by a listing.
    #[arg(long)]
    approve_digest: String,
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..))]
    interface: u32,
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long)]
    dial: Option<SocketAddr>,
    /// Owner-private JSON with exact LAN interface, ports, service types and directions.
    #[arg(long)]
    policy: PathBuf,
    /// Exact SHA256 of the policy reviewed by the operator, URL-safe base64.
    #[arg(long)]
    approve_policy: String,
}
pub(super) fn bytes32(value: &str) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)?
        .try_into()
        .map_err(|_| io::Error::other("exact 32-byte unpadded URL-safe base64 required"))?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(io::Error::other("noncanonical local approval").into());
    }
    Ok(bytes)
}
pub(super) fn policy_bytes(path: &Path) -> io::Result<Vec<u8>> {
    if !path.is_absolute() || std::fs::metadata(path)?.len() > 16_384 {
        return Err(io::Error::other(
            "bounded absolute owner-private LAN policy required",
        ));
    }
    let bytes = nestlink_platform_security::read_private(path, 16_384)?.to_vec();
    if bytes.len() > 16_384 {
        return Err(io::Error::other("LAN policy grew past its bound"));
    }
    Ok(bytes)
}
struct Device(LanBridge);
impl WholePacketDevice for Device {
    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketIoFuture<'a> {
        Box::pin(self.0.recv(packet))
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketIoFuture<'a> {
        Box::pin(async move { self.0.receive_admitted(packet) })
    }
}
struct Guard<'a> {
    device: &'a Device,
    directory: &'a Path,
    login: [u8; 32],
    policy: &'a Path,
    approval: [u8; 32],
}
impl OwnerGuard for Guard<'_> {
    fn check_local(&self) -> Result {
        if nestlink_local_ipc::maintenance::requested(self.directory)?
            || crate::space_dns::session_snapshot(self.directory).ok() != Some(self.login)
            || nestlink_identity::digest(&policy_bytes(self.policy)?) != self.approval
        {
            return Err(io::Error::other(
                "original LAN login, local consent or installation owner changed",
            )
            .into());
        }
        self.device.0.check_current()?;
        Ok(())
    }
    fn check(&self) -> GuardFuture<'_> {
        Box::pin(async move { self.check_local() })
    }
}
pub(crate) async fn run(args: LanArgs) -> Result {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(
            io::Error::other("LAN discovery runs as the ordinary installation owner").into(),
        );
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    let approved = bytes32(&args.approve_digest)?;
    let policy_approval = bytes32(&args.approve_policy)?;
    let bytes = policy_bytes(&args.policy)?;
    if nestlink_identity::digest(&bytes) != policy_approval {
        return Err(
            io::Error::other("LAN policy differs from the explicitly reviewed digest").into(),
        );
    }
    let policy: LanPolicy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    policy.check_interface()?;
    if policy.space_id != args.space
        || args.bind.ip().is_unspecified()
        || args.bind.ip().is_multicast()
        || args.dial.is_some_and(|address| {
            address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
        })
    {
        return Err(io::Error::other(
            "exact pinned space and concrete underlay endpoints required",
        )
        .into());
    }
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
            io::Error::other("sign in and enable protected login recovery before LAN discovery")
        })?;
    let login = crate::space_dns::session_snapshot(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(io::Error::other("original registered installation identity required").into());
    }
    let local = crate::identity(&directory)?;
    let mut access = OnlinePacketAccess::start(
        &sdk,
        &pin,
        &local,
        &args.grant,
        approved,
        nestlink_auth::random_id(),
    )
    .await?;
    let path = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(args.interface),
    )?;
    let mut endpoint =
        DirectPacketEndpoint::bind(args.bind, &local.identity, access.remote_peer(), path)?;
    println!("Original LAN packet endpoint: {}", endpoint.local_addr());
    drop(installation);
    let outcome = async {
        let device = Device(LanBridge::bind(policy, &args.space, &access)?);
        let guard = Guard {
            device: &device,
            directory: &directory,
            login,
            policy: &args.policy,
            approval: policy_approval,
        };
        let outcome = async {
            crate::network_packet_runtime::establish(
                &mut endpoint,
                args.dial,
                &sdk,
                &mut access,
                &guard,
            )
            .await?;
            crate::network_packet_runtime::packet_loop(
                &device,
                &mut endpoint,
                &sdk,
                &mut access,
                &guard,
            )
            .await
        }
        .await;
        access.stop();
        device
            .0
            .shutdown(std::time::Instant::now() + Duration::from_secs(5))?;
        outcome
    }
    .await;
    access.stop();
    endpoint
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    outcome
}
