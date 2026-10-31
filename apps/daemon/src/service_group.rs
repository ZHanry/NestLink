//! Explicit local target and complete edge allocation around the existing
//! service runtime. A downloaded group never creates a target owner by itself.
use crate::{session_store::SessionStore, space_dns::session_snapshot};
use nestlink_protocol::service_plane::group::{
    ServiceEdgeGroupUpdate, ServiceGroupPublicationRequest,
};
use nestlink_sdk::services::{
    HttpsBackendTls, LocalServiceGroupChoice, LocalServiceTargetConsent, ServiceGroupHostWait,
};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

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

#[derive(clap::Args)]
pub(crate) struct GroupArgs {
    /// Existing ordinary installation with protected login recovery enabled.
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    service: String,
    /// Numeric fixed local backend. No remote JSON or DNS chooses this address.
    #[arg(long)]
    target: SocketAddr,
    #[arg(long, value_enum)]
    protocol: Protocol,
    /// Owner-private exact ServiceEdgeGroupUpdate, including every approved
    /// recipient, namespace revision, fixed-entry IP and finite allocation.
    /// expected_service_revision must be the current revision plus one because
    /// this invocation explicitly approves a fresh target before configuring.
    #[arg(long)]
    allocation: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    approval_seconds: u64,
    /// Approve both the fixed target and the complete allocation in the file.
    /// This replaces prior target approval and stops its old publications.
    #[arg(long, required = true)]
    approve_target_and_group: bool,
    #[arg(long)]
    backend_server_name: Option<String>,
    /// Explicit local HTTPS CA DER files, at most eight of at most16KiB each.
    #[arg(long = "backend-ca")]
    backend_ca: Vec<PathBuf>,
}

pub(crate) async fn run(args: GroupArgs) -> Result {
    if !args.approve_target_and_group
        || !args.allocation.is_absolute()
        || args.target.port() == 0
        || args.target.ip().is_unspecified()
        || args.target.ip().is_multicast()
        || !nestlink_protocol::valid_id(&args.service)
    {
        return Err(io::Error::other(
            "explicit fixed target, service and absolute private allocation are required",
        )
        .into());
    }
    let allocation: ServiceEdgeGroupUpdate = serde_json::from_slice(
        &nestlink_platform_security::read_private(&args.allocation, 16_384)?,
    )?;
    let tls = if matches!(args.protocol, Protocol::Https) {
        if args.backend_ca.is_empty() || args.backend_ca.len() > 8 {
            return Err(io::Error::other(
                "HTTPS requires one to eight locally trusted CA DER files",
            )
            .into());
        }
        let name = args
            .backend_server_name
            .clone()
            .ok_or_else(|| io::Error::other("HTTPS requires the exact backend TLS server name"))?;
        let roots = args
            .backend_ca
            .iter()
            .map(|path| {
                nestlink_platform_security::read_private(path, 16_384).map(|bytes| bytes.to_vec())
            })
            .collect::<io::Result<Vec<_>>>()?;
        Some(HttpsBackendTls::new(name, roots)?)
    } else {
        if args.backend_server_name.is_some() || !args.backend_ca.is_empty() {
            return Err(io::Error::other("backend TLS options require protocol https").into());
        }
        None
    };
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(io::Error::other(
            "enroll this host installation before approving public service recipients",
        )
        .into());
    }
    let sdk = SessionStore::new(directory.clone())
        .restore()
        .await
        .ok_or_else(|| {
            io::Error::other(
                "sign in and enable protected login recovery for this host installation first",
            )
        })?;
    let original_login = session_snapshot(&directory)?;
    let host = Arc::new(crate::identity(&directory)?);
    let service = sdk.service(&args.service).await?;
    allocation.validate(&service.definition)?;
    if service.revision.checked_add(1) != Some(allocation.expected_service_revision)
        || service.definition.host_device_id != host.device_id
    {
        return Err(io::Error::other("service or approved allocation revision changed; review the current target and complete edge allocation again").into());
    }
    let remaining = sdk
        .principal()
        .ok_or(nestlink_sdk::SdkError::SignIn)?
        .access_expires
        .saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    let lifetime = args.approval_seconds.min(remaining);
    if lifetime == 0 {
        return Err(nestlink_sdk::SdkError::SignIn.into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(lifetime);
    let mut consent =
        LocalServiceTargetConsent::from_local_choice(&service, args.protocol.name(), args.target)?;
    if let Some(tls) = tls {
        consent = consent.with_https_backend_tls(tls)?;
    }
    sdk.approve_service_target(&host, &consent, lifetime * 1000)
        .await?;
    if session_snapshot(&directory).ok() != Some(original_login) {
        return Err(io::Error::other("original login changed before group publication").into());
    }
    let group = sdk
        .set_service_edge_group(&args.service, &allocation)
        .await?;
    let choice = LocalServiceGroupChoice::from_local_choice(&group, &consent)?;
    let request = ServiceGroupPublicationRequest {
        group_version: group.group_version,
        group_id: group.group_id.clone(),
        expected_group_revision: group.revision,
        expected_service_revision: group.service_revision,
        aggregate_sha256: nestlink_identity::service_plane::group::service_edge_group_digest(
            &group,
        )?,
    };
    let (cancel, cancelled) = tokio::sync::watch::channel(false);
    let stop = wait_stop(&directory, original_login, deadline);
    tokio::pin!(stop);
    let start = sdk.start_service_group_host_cancellable(host, consent, choice, cancelled);
    tokio::pin!(start);
    let mut owner = tokio::select! {
        result = &mut start => result?,
        reason = &mut stop => {
            cancel.send_replace(true);
            let cleanup = start.await;
            let _ = tokio::time::timeout(Duration::from_secs(2), sdk.stop_service_group_publication(&args.service, &request)).await;
            if let Ok(mut owner) = cleanup {
                while matches!(owner.wait_stopped(Duration::from_secs(5)).await, ServiceGroupHostWait::CleanupPending) {
                    eprintln!("service_group_cleanup_pending=true");
                }
            }
            reason?;
            return Err(io::Error::other("local service group startup stopped by its original owner").into());
        }
    };
    drop(installation);
    println!(
        "service_group={} revision={} local_attachments={} external_fixed_entry_validation=required",
        group.group_id,
        group.revision,
        owner.ready_members().len()
    );
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut last_count = owner.ready_members().len();
    let stopped = loop {
        tokio::select! {
            reason = &mut stop => break reason,
            _ = tick.tick() => {
                let count = owner.ready_members().len();
                if count != last_count { println!("service_group_local_attachments={count}"); last_count = count; }
                if count == 0 { break Ok("all_original_members_stopped"); }
            }
        }
    };
    owner.stop();
    let withdrawn = tokio::time::timeout(
        Duration::from_secs(2),
        sdk.stop_service_group_publication(&args.service, &request),
    )
    .await;
    let mut failed = !matches!(withdrawn, Ok(Ok(())));
    loop {
        match owner.wait_stopped(Duration::from_secs(5)).await {
            ServiceGroupHostWait::CleanupPending => eprintln!("service_group_cleanup_pending=true"),
            ServiceGroupHostWait::Stopped { members } => {
                failed |= members.iter().any(|(_, report)| report.failed);
                break;
            }
        }
    }
    let reason = stopped?;
    println!("service_group_stopped=true cause={reason} cleanup_failed={failed}");
    if failed {
        return Err(io::Error::other(
            "local group stopped; one or more original edge cleanup or withdrawal receipts failed",
        )
        .into());
    }
    Ok(())
}

async fn wait_stop(
    directory: &Path,
    login: [u8; 32],
    deadline: tokio::time::Instant,
) -> io::Result<&'static str> {
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            result = &mut signal => { result?; return Ok("local_signal"); },
            _ = tokio::time::sleep_until(deadline) => return Ok("original_deadline"),
            _ = tick.tick() => {
                if session_snapshot(directory).ok() != Some(login) { return Ok("original_login_changed"); }
                if nestlink_local_ipc::maintenance::requested(directory).map_err(io::Error::other)? { return Ok("installation_maintenance"); }
            }
        }
    }
}
