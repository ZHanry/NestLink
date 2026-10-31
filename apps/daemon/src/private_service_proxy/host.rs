//! An explicit local target choice around the existing private-service host.
//! No consumer ACL, wire protocol, scheduler or second login owner is created.
use super::Result;
use crate::space_dns::session_snapshot;
use nestlink_protocol::{
    api::ServiceView,
    services::private::{ServiceAccessMode, ServiceExposureUpdate},
};
use nestlink_sdk::{
    DeviceIdentity, Sdk, SdkError,
    services::{
        HttpsBackendTls, LocalServiceTargetConsent, PrivateServiceHost, PrivateServiceHostConfig,
        PrivateServiceRelayPolicy,
    },
};
use std::{
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, clap::ValueEnum)]
enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
}
impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum AccessMode {
    Private,
    Both,
}
impl AccessMode {
    fn mode(self) -> ServiceAccessMode {
        match self {
            Self::Private => ServiceAccessMode::Private,
            Self::Both => ServiceAccessMode::Both,
        }
    }
}
#[derive(clap::Args)]
pub(super) struct HostArgs {
    #[arg(long)]
    service: String,
    #[arg(long)]
    space: String,
    /// Already fixed numeric local backend address. Never resolved from DNS.
    #[arg(long)]
    target: SocketAddr,
    #[arg(long, value_enum)]
    protocol: Protocol,
    /// Local QUIC UDP listener. Port zero chooses a free port.
    #[arg(long)]
    listen: SocketAddr,
    /// Numeric address consumers can reach; must match --listen's IP family.
    #[arg(long)]
    advertised_ip: IpAddr,
    /// Explicit canonical private-network prefix containing an allowed relay
    /// node address; repeat for each locally trusted prefix. Default is public
    /// unicast relay nodes only. This never authorizes a backend target.
    #[arg(long = "relay-private-prefix")]
    relay_private_prefixes: Vec<String>,
    /// Explicitly allow local loopback relay node addresses for this runtime.
    #[arg(long)]
    allow_loopback_relay: bool,
    /// Both also reserves public budget, but this command runs the private host.
    /// Public ingress is started separately through the existing publication UI.
    #[arg(long, value_enum)]
    access_mode: AccessMode,
    /// Positive finite share of the original service's cumulative byte limit.
    #[arg(long)]
    private_maximum_bytes: u64,
    /// Explicitly zero in private mode; positive in both mode. The two shares
    /// together may not exceed the original service's cumulative byte limit.
    #[arg(long)]
    public_maximum_bytes: u64,
    /// Finite approval and command lifetime, also capped by this login's expiry.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    approval_seconds: u64,
    /// Confirm the displayed service definition, fixed local target and exposure
    /// update. Every invocation invalidates previous consumer ACLs/leases and
    /// stops previous publications; grant consumers again in the Web ACL panel.
    #[arg(long, required = true)]
    approve_target: bool,
    /// HTTPS backend's verified TLS server name. Required only for HTTPS.
    #[arg(long)]
    backend_server_name: Option<String>,
    /// Local trusted CA in DER X.509 format, one file per certificate (max 8,
    /// 16384 bytes each). HTTPS requires this and --backend-server-name.
    #[arg(long = "backend-ca-der")]
    backend_ca_der: Vec<PathBuf>,
}
impl HostArgs {
    fn validate(&self) -> io::Result<()> {
        if !self.approve_target
            || !nestlink_protocol::valid_id(&self.service)
            || !nestlink_protocol::valid_id(&self.space)
            || self.advertised_ip.is_unspecified()
            || self.advertised_ip.is_multicast()
            || matches!(self.advertised_ip, IpAddr::V4(ip) if ip.is_broadcast())
            || self.listen.is_ipv4() != self.advertised_ip.is_ipv4()
            || self.private_maximum_bytes == 0
            || self
                .private_maximum_bytes
                .checked_add(self.public_maximum_bytes)
                .is_none()
            || self.access_mode.mode().public_enabled() != (self.public_maximum_bytes > 0)
            || !(1..=3600).contains(&self.approval_seconds)
        {
            return Err(io::Error::other(
                "choose valid IDs, a reachable numeric advertised IP matching the listener, finite mode budgets and --approve-target",
            ));
        }
        let https = matches!(self.protocol, Protocol::Https);
        if https != self.backend_server_name.is_some()
            || https == self.backend_ca_der.is_empty()
            || self.backend_ca_der.len() > 8
        {
            return Err(io::Error::other(
                "HTTPS requires a local server name and 1..8 DER CA files; other protocols must not supply TLS options",
            ));
        }
        Ok(())
    }
    fn validate_service(&self, view: &ServiceView, host: &DeviceIdentity) -> io::Result<()> {
        if view.definition.host_device_id != host.device_id
            || self
                .private_maximum_bytes
                .checked_add(self.public_maximum_bytes)
                .is_none_or(|total| total > view.definition.limits.maximum_bytes)
            || self.access_mode.mode().public_enabled() && view.definition.edge_node_id.is_empty()
        {
            return Err(io::Error::other(
                "the service must belong to this installation; mode shares must fit its original cumulative budget, and both mode requires its registered public edge",
            ));
        }
        Ok(())
    }
    fn backend_tls(&self) -> Result<Option<HttpsBackendTls>> {
        let Some(name) = &self.backend_server_name else {
            return Ok(None);
        };
        let mut roots = Vec::new();
        for path in &self.backend_ca_der {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(io::Error::other(
                    "backend CA must be a local regular DER certificate file",
                )
                .into());
            }
            let file = std::fs::File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::other("backend CA changed file type").into());
            }
            let mut bytes = Vec::new();
            file.take(16385).read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() > 16384 {
                return Err(
                    io::Error::other("backend DER certificate exceeds its bounded size").into(),
                );
            }
            roots.push(bytes);
        }
        Ok(Some(HttpsBackendTls::new(name.clone(), roots)?))
    }
}
fn wall_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
struct SessionGuard {
    directory: PathBuf,
    original_login: [u8; 32],
    until: AtomicU64,
    last_wall: AtomicU64,
    deadline: tokio::time::Instant,
    cancelled: AtomicBool,
}
impl SessionGuard {
    fn new(directory: PathBuf, original_login: [u8; 32], sdk: &Sdk, seconds: u64) -> Result<Self> {
        let now = wall_ms()?;
        let login_end = sdk
            .principal()
            .ok_or(SdkError::SignIn)?
            .access_expires
            .checked_mul(1000)
            .ok_or(SdkError::Invalid)?;
        let until = now
            .checked_add(seconds.checked_mul(1000).ok_or(SdkError::Invalid)?)
            .ok_or(SdkError::Invalid)?
            .min(login_end);
        if until <= now {
            return Err(SdkError::SignIn.into());
        }
        Ok(Self {
            directory,
            original_login,
            until: AtomicU64::new(until),
            last_wall: AtomicU64::new(now),
            deadline: tokio::time::Instant::now() + Duration::from_millis(until - now),
            cancelled: AtomicBool::new(false),
        })
    }
    fn running(&self) -> io::Result<bool> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let now = wall_ms()?;
        if now < self.last_wall.fetch_max(now, Ordering::SeqCst) {
            return Err(io::Error::other(
                "wall clock regressed; private service host stopped",
            ));
        }
        if now >= self.until.load(Ordering::SeqCst) || tokio::time::Instant::now() >= self.deadline
        {
            return Ok(false);
        }
        if nestlink_local_ipc::maintenance::requested(&self.directory).map_err(io::Error::other)? {
            return Ok(false);
        }
        if session_snapshot(&self.directory)? != self.original_login {
            return Err(io::Error::other(
                "protected management session changed; private service host stopped",
            ));
        }
        Ok(true)
    }
}

async fn start(
    args: &HostArgs,
    sdk: &Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    guard: &SessionGuard,
) -> Result<Option<PrivateServiceHost>> {
    if !guard.running()? {
        return Ok(None);
    }
    let relay_policy = PrivateServiceRelayPolicy::from_local_choice(
        &args.relay_private_prefixes,
        args.allow_loopback_relay,
    )?;
    let view = sdk.service(&args.service).await?;
    args.validate_service(&view, &host)?;
    let tls = args.backend_tls()?;
    let mut consent =
        LocalServiceTargetConsent::from_local_choice(&view, args.protocol.name(), args.target)?;
    if let Some(tls) = tls {
        consent = consent.with_https_backend_tls(tls)?;
    }
    let previous = sdk.service_exposure(&args.service).await?;
    if !guard.running()? {
        return Ok(None);
    }
    println!(
        "Approving service {} revision {} definition: {}",
        view.id,
        view.revision,
        serde_json::to_string(&view.definition)?
    );
    println!(
        "Explicit local target: {} {}; space {}; mode {:?}; private/public byte shares {}/{}.",
        args.protocol.name(),
        args.target,
        args.space,
        args.access_mode.mode(),
        args.private_maximum_bytes,
        args.public_maximum_bytes
    );
    println!(
        "This target/exposure update invalidates old consumer ACLs and leases and stops previous publications. No consumer is automatically authorized."
    );
    let lifetime = guard
        .until
        .load(Ordering::SeqCst)
        .saturating_sub(wall_ms()?);
    if lifetime == 0 {
        return Ok(None);
    }
    let approved = sdk
        .approve_service_target(&host, &consent, lifetime)
        .await?;
    println!(
        "Local target approval revision {} is saved. The exposure update follows only while this protected session remains current.",
        approved.revision
    );
    let end = approved
        .approval_expires_at_unix_ms
        .ok_or(SdkError::Trust)?;
    guard.until.fetch_min(end, Ordering::SeqCst);
    if !guard.running()? {
        return Ok(None);
    }
    let exposure = sdk
        .set_service_exposure(
            &args.service,
            ServiceExposureUpdate {
                expected_revision: previous.as_ref().map_or(0, |view| view.revision),
                expected_service_revision: approved.revision,
                space_id: args.space.clone(),
                mode: args.access_mode.mode(),
                private_maximum_bytes: args.private_maximum_bytes,
                public_maximum_bytes: args.public_maximum_bytes,
            },
        )
        .await?;
    println!(
        "Target approval and exposure revision {} are saved. Grant explicit consumers in the Web private-service ACL panel while this host runs. Re-running this command requires new ACL grants.",
        exposure.revision
    );
    if !guard.running()? {
        return Ok(None);
    }
    // One stable installation-private ledger across invocations; no temporary
    // runtime/service-specific allowance that would reset cumulative accounting.
    let owner = sdk
        .start_private_service_host_with_relay_policy(
            host,
            consent,
            PrivateServiceHostConfig {
                listen: args.listen,
                advertised_ip: args.advertised_ip,
                usage_directory: guard.directory.join("private-service-usage"),
            },
            relay_policy,
        )
        .await?;
    Ok(Some(owner))
}

pub(super) async fn run(
    args: HostArgs,
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    directory: PathBuf,
    original_login: [u8; 32],
) -> Result<()> {
    args.validate()?;
    let guard = SessionGuard::new(directory, original_login, &sdk, args.approval_seconds)?;
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let setup = start(&args, &sdk, host, &guard);
    tokio::pin!(setup);
    let mut operation: Option<io::Result<()>> = None;
    let started = loop {
        tokio::select! { biased;
            result = &mut signal, if operation.is_none() => {
                guard.cancelled.store(true, Ordering::SeqCst); operation = Some(result);
            },
            _ = tick.tick(), if operation.is_none() => match guard.running() {
                Ok(true) => {},
                result => { guard.cancelled.store(true, Ordering::SeqCst); operation = Some(result.map(|_| ())); },
            },
            result = &mut setup => break result?,
        }
    };
    // Never drop an in-progress host start. Stop/expiry marks its checkpoints;
    // if the original start already owns a listener, retain its returned owner.
    let Some(mut owner) = started else {
        return Ok(operation.unwrap_or(Ok(()))?);
    };
    if operation.is_none() {
        println!(
            "Private service {} in space {}: authenticated QUIC {}. Target {} {}; approval expires at {} ms UTC. Press Ctrl-C to stop.",
            args.service,
            args.space,
            owner.address(),
            args.protocol.name(),
            args.target,
            guard.until.load(Ordering::SeqCst)
        );
        operation = Some(loop {
            tokio::select! { biased;
                result = &mut signal => break result,
                _ = tick.tick() => {
                    if owner.is_finished() { break Ok(()); }
                    match guard.running() { Ok(true) => {}, result => break result.map(|_| ()) }
                },
            }
        });
    }
    owner.stop();
    let mut reported_pending = false;
    loop {
        match owner.wait_stopped().await {
            Ok(()) => {
                println!(
                    "Private service host stopped; its original connections and UDP listener are physically closed. The cumulative usage ledger is retained."
                );
                return Ok(operation.unwrap_or(Ok(()))?);
            }
            Err(SdkError::Timeout) => {
                if !reported_pending {
                    eprintln!(
                        "Private service host cleanup is pending; retaining the original owner and join handle."
                    );
                    reported_pending = true;
                }
                // The SDK retains its first absolute cleanup deadline. Later
                // pending polls may return immediately; never spin or reset it.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                let detail = match operation {
                    Some(Err(operation)) => format!("{operation}; cleanup: {error}"),
                    _ => format!("private service host cleanup failed: {error}"),
                };
                return Err(io::Error::other(detail).into());
            }
        }
    }
}

#[cfg(test)]
mod tests;
