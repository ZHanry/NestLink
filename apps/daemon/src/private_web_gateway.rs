//! Explicit per-user private Web entry. The existing protected login and
//! installation key remain with the original normal-user runtime owner.
use crate::{session_store::SessionStore, space_dns::session_snapshot};
use nestlink_sdk::{
    Sdk,
    services::{
        LocalProxyServiceChoice,
        web_gateway::{PrivateWebGatewayConfig, PrivateWebGatewayWait},
        web_launch::{PrivateWebLaunchRequest, PRIVATE_WEB_REQUEST_BYTES},
    },
};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(clap::Args)]
pub(crate) struct GatewayArgs {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, required_unless_present = "request", conflicts_with = "request")]
    service: Option<String>,
    #[arg(long, required_unless_present = "request", conflicts_with = "request")]
    space: Option<String>,
    /// Exact HTTPS origin: https://<service-UUID>.<private-domain>. The private
    /// domain must be separate from the management site's last two DNS labels.
    #[arg(long, required_unless_present = "request", conflicts_with = "request")]
    origin: Option<String>,
    /// Finite original private service allowance for each HTTP/WS connection.
    #[arg(long, required_unless_present = "request", conflicts_with = "request")]
    maximum_bytes: Option<u64>,
    #[arg(long, conflicts_with = "request", value_parser=clap::value_parser!(u64).range(1..=3600))]
    lifetime_seconds: Option<u64>,
    /// Bounded management selection; grants no access and must match this owner.
    #[arg(long)]
    request: Option<PathBuf>,
    /// Private upstream for the operator-managed strict-SNI Caddy HTTPS server.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Fresh owner-private Caddy route JSON. Never paste it into a browser.
    #[arg(long)]
    bootstrap: PathBuf,
    /// Fresh owner-private JSON, created after HTTPS reaches this exact owner.
    #[arg(long)]
    launch_output: PathBuf,
}

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) async fn run(args: GatewayArgs) -> Result {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("private Web gateway must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    if !args.bootstrap.is_absolute()
        || !args.launch_output.is_absolute()
        || args.bootstrap == args.launch_output
        || args.request.as_ref().is_some_and(|path| !path.is_absolute())
        || !args.listen.ip().is_loopback()
    {
        return Err(io::Error::other("choose a loopback upstream and separate new absolute private bootstrap/launch paths").into());
    }
    let parent = args
        .bootstrap
        .parent()
        .ok_or_else(|| io::Error::other("bootstrap parent missing"))?;
    nestlink_platform_security::check_private_directory(parent)?;
    nestlink_platform_security::check_private_directory(args.launch_output.parent().ok_or_else(|| io::Error::other("launch parent missing"))?)?;
    if args.bootstrap.try_exists()? || args.launch_output.try_exists()? {
        return Err(io::Error::other("bootstrap and launch output must both be fresh paths").into());
    }
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(io::Error::other("enroll this gateway installation and explicitly join/authorize it in the chosen space first").into());
    }
    let store = SessionStore::new(directory.clone());
    let sdk = store.restore().await.ok_or_else(|| {
        io::Error::other(
            "sign in and enable protected login recovery for this gateway installation first",
        )
    })?;
    let original_login = session_snapshot(&directory)?;
    let consumer = Arc::new(crate::identity(&directory)?);
    let selection = selection(&args, &sdk, &consumer.device_id).await?;
    let entry = selected_service(&sdk, &consumer.device_id, &selection.service_id, &selection.space_id).await?;
    if !selection.checks_entry(&consumer.device_id, &entry) {
        return Err(io::Error::other("private Web selection changed, is offline, or exceeds current authority; refresh the directory and choose again").into());
    }
    if !matches!(
        &entry.service.definition.requested_ingress,
        nestlink_protocol::api::ServiceIngress::Http { .. }
            | nestlink_protocol::api::ServiceIngress::Https { .. }
    ) {
        return Err(io::Error::other(
            "this browser gateway accepts HTTP/HTTPS only; use private-service-proxy for TCP/UDP",
        )
        .into());
    }
    let remaining = sdk
        .principal()
        .ok_or(nestlink_sdk::SdkError::SignIn)?
        .access_expires
        .saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    let lifetime = Duration::from_secs(selection.lifetime_seconds.min(remaining));
    let choice = LocalProxyServiceChoice::from_local_choice(
        &entry,
        "private-web.nestlink.internal",
        443,
        selection.maximum_bytes,
        lifetime,
    )?;
    let mut gateway = Arc::new(sdk)
        .start_private_web_gateway(
            consumer,
            choice,
            PrivateWebGatewayConfig {
                listen: args.listen,
                origin: selection.origin.clone(),
            },
        )
        .await?;
    #[derive(serde::Serialize)]
    struct Bootstrap<'a> {
        schema_version: u32,
        service_id: &'a str,
        space_id: &'a str,
        origin: &'a str,
        gateway_owner_id: &'a str,
        caddy_https_route: serde_json::Value,
    }
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&Bootstrap {
        schema_version: 2,
        service_id: &selection.service_id,
        space_id: &selection.space_id,
        origin: gateway.origin(),
        gateway_owner_id: gateway.owner_id(),
        caddy_https_route: gateway.caddy_route(),
    })?);
    let created =
        nestlink_platform_security::create_private(&args.bootstrap, &bytes).and_then(|()| {
            let actual = nestlink_platform_security::read_private(&args.bootstrap, 65536)?;
            if *actual != *bytes {
                return Err(io::Error::other("private Web bootstrap readback differs"));
            }
            Ok(())
        });
    if let Err(error) = created {
        gateway.request_shutdown();
        let cleanup = loop {
            match gateway.wait_stopped(Duration::from_secs(5)).await {
                PrivateWebGatewayWait::CleanupPending => continue,
                receipt => break receipt,
            }
        };
        return Err(io::Error::other(format!("private Web bootstrap could not be confirmed; inspect the exact owner path {}: {error}; cleanup={cleanup:?}",args.bootstrap.display())).into());
    }
    drop(installation);
    println!(
        "Private Web upstream {} for {}. Install the private route from {} in the dedicated strict-SNI HTTPS Caddy server. Waiting stays within the original {}-second lifetime; after HTTPS readiness, a fresh 60-second single-use URL is saved to {}. Press Ctrl-C to stop.",
        gateway.address(),
        gateway.origin(),
        args.bootstrap.display(),
        lifetime.as_secs(),
        args.launch_output.display()
    );
    let probe = match gateway.public_route_probe() {
        Ok(probe) => probe,
        Err(error) => {
            gateway.request_shutdown();
            let cleanup = loop {
                match gateway.wait_stopped(Duration::from_secs(5)).await {
                    PrivateWebGatewayWait::CleanupPending => continue,
                    receipt => break receipt,
                }
            };
            return Err(io::Error::other(format!("public route probe could not start: {error}; cleanup={cleanup:?}; retain bootstrap {} for review",args.bootstrap.display())).into());
        }
    };
    let readiness = async {
        loop {
            if probe.check().await.is_ok_and(|ready| ready) { return; }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::pin!(readiness);
    let mut launch_bytes = None;
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let operation = loop {
        tokio::select! {
            result=&mut signal=>break result,
            _=&mut readiness,if launch_bytes.is_none()=>{
                let result = publish_launch(&mut gateway, &selection, &args.launch_output);
                match result {
                    Ok(bytes)=>{launch_bytes=Some(bytes);println!("Private HTTPS reaches gateway owner {}. Open only launch_url from {} within 60 seconds. Never paste the route bootstrap into the browser.",gateway.owner_id(),args.launch_output.display());},
                    Err(error)=>break Err(io::Error::other(format!("launch output could not be confirmed; inspect {}: {error}",args.launch_output.display()))),
                }
            },
            _=tick.tick()=>{
                if gateway.is_finished(){
                    break if launch_bytes.is_none(){Err(io::Error::other("private HTTPS did not confirm this gateway owner before its fixed lifetime ended; no launch URL was issued; check the dedicated Caddy route, public certificate and DNS"))}else{Ok(())};
                }
                match nestlink_local_ipc::maintenance::requested(&directory){Ok(true)=>break Ok(()),Err(error)=>break Err(io::Error::other(error)),Ok(false)=>{}}
                if session_snapshot(&directory).ok()!=Some(original_login){break Err(io::Error::other("protected management session changed; private Web gateway stopped"));}
            }
        }
    };
    gateway.request_shutdown();
    loop {
        match gateway.wait_stopped(Duration::from_secs(5)).await {
            PrivateWebGatewayWait::CleanupPending => continue,
            PrivateWebGatewayWait::CleanupFailed(report) => return Err(io::Error::other(format!(
                "private Web cleanup receipt failed: {report:?}; retain bootstrap for owner review"
            ))
            .into()),
            PrivateWebGatewayWait::Stopped(report) => {
                remove_bootstrap(&args.bootstrap, &bytes)?;
                if let Some(bytes) = launch_bytes { remove_bootstrap(&args.launch_output, &bytes)?; }
                println!("Private Web gateway stopped: {report:?}");
                operation?;
                return Ok(());
            }
        }
    }
}
fn publish_launch(gateway: &mut nestlink_sdk::services::web_gateway::PrivateWebGateway, selection: &PrivateWebLaunchRequest, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let launch_url = gateway.renew_launch_url()?;
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"service_id":selection.service_id,"space_id":selection.space_id,"gateway_owner_id":gateway.owner_id(),"origin":gateway.origin(),"launch_url":launch_url,"launch_ticket_lifetime_seconds":60}))?);
    nestlink_platform_security::create_private(path, &bytes)?;
    let actual = nestlink_platform_security::read_private(path, 65536)?;
    if *actual != *bytes { return Err(io::Error::other("private launch file readback differs").into()); }
    Ok(bytes)
}
async fn selection(args: &GatewayArgs, sdk: &Sdk, installation: &str) -> Result<PrivateWebLaunchRequest> {
    let selection = if let Some(path) = &args.request {
        let bytes = nestlink_platform_security::read_private(path, PRIVATE_WEB_REQUEST_BYTES as u64)?;
        PrivateWebLaunchRequest::from_json(&bytes)?
    } else {
        let service = args.service.as_deref().ok_or_else(|| io::Error::other("service missing"))?;
        let space = args.space.as_deref().ok_or_else(|| io::Error::other("space missing"))?;
        let entry = selected_service(sdk, installation, service, space).await?;
        PrivateWebLaunchRequest { schema_version: 1, management_origin: sdk.management_origin().into(), gateway_installation_id: installation.into(), service_id: service.into(), space_id: space.into(), expected_service_revision: entry.service.revision, expected_exposure_revision: entry.exposure.revision, target_sha256: entry.exposure.target_sha256, origin: args.origin.clone().ok_or_else(|| io::Error::other("origin missing"))?, maximum_bytes: args.maximum_bytes.ok_or_else(|| io::Error::other("maximum bytes missing"))?, lifetime_seconds: args.lifetime_seconds.unwrap_or(300) }
    };
    selection.validate(sdk.management_origin())?;
    if selection.gateway_installation_id != installation { return Err(io::Error::other("launch request belongs to another gateway installation").into()); }
    Ok(selection)
}
fn remove_bootstrap(path: &Path, original: &[u8]) -> io::Result<()> {
    let current = nestlink_platform_security::read_private(path, 65536)?;
    if current.as_slice() != original {
        return Err(io::Error::other(
            "private Web bootstrap changed; exact owner file retained",
        ));
    }
    std::fs::remove_file(path)
}
async fn selected_service(
    sdk: &Sdk,
    consumer: &str,
    service: &str,
    space: &str,
) -> Result<nestlink_protocol::services::private::PrivateServiceEntry> {
    let mut after = None;
    for _ in 0..64 {
        let page = sdk
            .private_services(consumer, after.as_deref(), 100)
            .await?;
        if let Some(entry) = page
            .entries
            .into_iter()
            .find(|entry| entry.service.id == service && entry.exposure.space_id == space)
        {
            return Ok(entry);
        }
        if !page.more {
            break;
        }
        after = page.next_id;
    }
    Err(io::Error::other(
        "the chosen HTTP service is not in this gateway installation's current private directory",
    )
    .into())
}
