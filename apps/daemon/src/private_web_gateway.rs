//! Explicit per-user private Web entry. The existing protected login and
//! installation key remain with the original normal-user runtime owner.
use crate::{session_store::SessionStore, space_dns::session_snapshot};
use nestlink_sdk::{
    Sdk,
    services::{
        LocalProxyServiceChoice,
        web_gateway::{PrivateWebGatewayConfig, PrivateWebGatewayWait},
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
    #[arg(long)]
    service: String,
    #[arg(long)]
    space: String,
    /// Exact HTTPS origin: https://<service-UUID>.<private-domain>. The private
    /// domain must be separate from the management site's last two DNS labels.
    #[arg(long)]
    origin: String,
    /// Finite original private service allowance for each HTTP/WS connection.
    #[arg(long)]
    maximum_bytes: u64,
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=3600))]
    lifetime_seconds: u64,
    /// Private upstream for the operator-managed strict-SNI Caddy HTTPS server.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Fresh absolute owner-private JSON file containing the one-use launch URL
    /// and Caddy route secret. Never publish this file or include it in logs.
    #[arg(long)]
    bootstrap: PathBuf,
}

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) async fn run(args: GatewayArgs) -> Result {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("private Web gateway must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    if !nestlink_protocol::valid_id(&args.service)
        || !nestlink_protocol::valid_id(&args.space)
        || !args.bootstrap.is_absolute()
        || !args.listen.ip().is_loopback()
    {
        return Err(io::Error::other("choose exact service/space IDs, a loopback upstream and a new absolute private bootstrap path").into());
    }
    let parent = args
        .bootstrap
        .parent()
        .ok_or_else(|| io::Error::other("bootstrap parent missing"))?;
    nestlink_platform_security::check_private_directory(parent)?;
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    if !directory.join("installation.json").try_exists()? {
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
    let entry = selected_service(&sdk, &consumer.device_id, &args.service, &args.space).await?;
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
    let lifetime = Duration::from_secs(args.lifetime_seconds.min(remaining));
    let choice = LocalProxyServiceChoice::from_local_choice(
        &entry,
        "private-web.nestlink.internal",
        443,
        args.maximum_bytes,
        lifetime,
    )?;
    let mut gateway = Arc::new(sdk)
        .start_private_web_gateway(
            consumer,
            choice,
            PrivateWebGatewayConfig {
                listen: args.listen,
                origin: args.origin,
            },
        )
        .await?;
    #[derive(serde::Serialize)]
    struct Bootstrap<'a> {
        schema_version: u32,
        service_id: &'a str,
        space_id: &'a str,
        origin: &'a str,
        launch_url: String,
        launch_ticket_lifetime_seconds: u32,
        caddy_https_route: serde_json::Value,
    }
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&Bootstrap {
        schema_version: 1,
        service_id: &args.service,
        space_id: &args.space,
        origin: gateway.origin(),
        launch_url: gateway.launch_url(),
        launch_ticket_lifetime_seconds: 60,
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
        "Private Web upstream {} for {}. The owner-private bootstrap is {}. Configure its route only in a dedicated HTTPS Caddy server with strict_sni_host=true, then open the one-use launch URL within 60 seconds. Press Ctrl-C to stop.",
        gateway.address(),
        gateway.origin(),
        args.bootstrap.display()
    );
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let operation = loop {
        tokio::select! {
            result=&mut signal=>break result,
            _=tick.tick()=>{
                if gateway.is_finished(){break Ok(());}
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
                println!("Private Web gateway stopped: {report:?}");
                operation?;
                return Ok(());
            }
        }
    }
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
