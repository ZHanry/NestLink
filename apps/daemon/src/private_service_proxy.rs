//! Explicit normal-user entry to one authorized private service.
use crate::{session_store::SessionStore, space_dns::session_snapshot};
use nestlink_protocol::services::private::PrivateServiceEntry;
use nestlink_sdk::{Sdk, services::{LocalProxyServiceChoice, LocalProxyWait}};
use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

#[derive(clap::Args)]
pub(crate) struct ProxyArgs {
    /// Existing installation with protected login recovery enabled.
    #[arg(long)]
    state_dir: PathBuf,
    #[command(subcommand)]
    action: ProxyAction,
}

#[derive(clap::Subcommand)]
enum ProxyAction {
    /// List currently authorized private services without creating listeners.
    List,
    /// Serve one chosen TCP/HTTP/HTTPS service until stopped or its deadline.
    Serve {
        #[arg(long)]
        service: String,
        #[arg(long)]
        space: String,
        /// Exact local SOCKS destination, e.g. docs.nestlink.internal.
        #[arg(long)]
        alias: String,
        /// Exact destination port accepted from local SOCKS clients.
        #[arg(long)]
        port: u16,
        /// Finite reservation for each independently authorized connection.
        #[arg(long)]
        maximum_bytes: u64,
        /// Owner lifetime, capped at 3600 seconds and the current login expiry.
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=3600))]
        lifetime_seconds: u64,
        /// Loopback only. Port zero chooses a free local port.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Existing private directory for the create-new local credentials file.
        /// Defaults to this installation's state directory.
        #[arg(long)]
        credentials_dir: Option<PathBuf>,
    },
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) async fn run(args: ProxyArgs) -> Result<()> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("private service proxy must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    let installation = nestlink_local_ipc::maintenance::InstallationStartup::acquire(
        &std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    // The refresh session and local device identity retain their existing single
    // runtime owner. The desktop/daemon cannot race a second refresh here.
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    let sdk = SessionStore::new(directory.clone()).restore().await.ok_or_else(||
        io::Error::other("sign in and enable protected login recovery before starting a private service proxy"))?;
    let original_login = session_snapshot(&directory)?;
    // This command consumes an installed identity; it cannot create or register
    // a new device implicitly while presenting another installation's services.
    if !directory.join("installation-device.json").try_exists()? {
        return Err(io::Error::other("the installation has no registered local device identity").into());
    }
    let consumer = Arc::new(crate::identity(&directory)?);
    match args.action {
        ProxyAction::List => {
            let mut after = None;
            for _ in 0..64 {
                let page = sdk.private_services(&consumer.device_id, after.as_deref(), 100).await?;
                for entry in &page.entries {
                    #[derive(serde::Serialize)]
                    struct View<'a> {
                        service_id: &'a str, space_id: &'a str,
                        availability: &'a nestlink_protocol::services::private::PrivateServiceAvailability,
                        maximum_bytes_per_connection: u64,
                    }
                    println!("{}", serde_json::to_string(&View {
                        service_id: &entry.service.id, space_id: &entry.exposure.space_id,
                        availability: &entry.availability,
                        maximum_bytes_per_connection: entry.exposure.private_maximum_bytes.min(
                            entry.service.definition.limits.maximum_bytes),
                    })?);
                }
                if !page.more { return Ok(()); }
                after = page.next_id;
            }
            Err(io::Error::other("private service directory exceeds this command's bounded page budget").into())
        }
        ProxyAction::Serve {service, space, alias, port, maximum_bytes, lifetime_seconds, listen, credentials_dir} => {
            if !nestlink_protocol::valid_id(&service) || !nestlink_protocol::valid_id(&space)
                || !listen.ip().is_loopback() {
                return Err(io::Error::other("choose valid service and space IDs and a loopback listener").into());
            }
            let entry = selected_service(&sdk, &consumer.device_id, &service, &space).await?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let remaining = sdk.principal().ok_or(nestlink_sdk::SdkError::SignIn)?
                .access_expires.saturating_sub(now);
            let lifetime = Duration::from_secs(lifetime_seconds.min(remaining));
            let choice = LocalProxyServiceChoice::from_local_choice(
                &entry, &alias, port, maximum_bytes, lifetime)?;
            let sdk = Arc::new(sdk);
            let credential_directory = credentials_dir.unwrap_or_else(|| directory.clone());
            let deadline = tokio::time::Instant::now() + lifetime;
            let mut proxy = sdk.start_private_service_socks(
                consumer, choice, listen, &credential_directory).await?;
            drop(installation);
            println!("Private service {service} in space {space}: SOCKS5 {}", proxy.address());
            println!("Destination: {alias}:{port}; maximum {maximum_bytes} bytes per connection; owner lifetime {} seconds.", lifetime.as_secs());
            println!("Local credentials file: {}", proxy.credentials_path().display());
            println!("Configure your client from that private file. Press Ctrl-C to stop.");
            let signal = crate::space_dns_system::termination();
            tokio::pin!(signal);
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            let operation: io::Result<()> = loop {
                tokio::select! {
                    result = &mut signal => break result,
                    _ = tokio::time::sleep_until(deadline) => break Ok(()),
                    _ = tick.tick() => {
                        if proxy.is_finished() { break Ok(()); }
                        match nestlink_local_ipc::maintenance::requested(&directory) {
                            Ok(true) => break Ok(()),
                            Err(error) => break Err(error),
                            Ok(false) => {},
                        }
                        if session_snapshot(&directory).ok() != Some(original_login) {
                            break Err(io::Error::other("protected management session changed; private proxy stopped"));
                        }
                    }
                }
            };
            proxy.request_shutdown();
            // Keep the same owner and join handle until its actual flow drains
            // and exact credential cleanup have completed. A wait timeout never
            // cancels the owner or permits a second runtime to replace it.
            let mut reported_pending = false;
            loop {
                match proxy.wait_stopped(Duration::from_secs(5)).await {
                    LocalProxyWait::CleanupPending => {
                        if !reported_pending {
                            eprintln!("Private proxy is joining its original connections; cleanup receipt is pending.");
                            reported_pending = true;
                        }
                    }
                    LocalProxyWait::CleanupFailed(report) => {
                        return Err(io::Error::other(format!("private proxy cleanup failed: {report:?}")).into());
                    }
                    LocalProxyWait::Stopped(report) => {
                        println!("Private proxy stopped: {report:?}");
                        operation?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn selected_service(sdk: &Sdk, consumer: &str, service: &str, space: &str) -> Result<PrivateServiceEntry> {
    let mut after = None;
    for _ in 0..64 {
        let page = sdk.private_services(consumer, after.as_deref(), 100).await?;
        if let Some(entry) = page.entries.into_iter().find(|entry|
            entry.service.id == service && entry.exposure.space_id == space) {
            return Ok(entry);
        }
        if !page.more { break; }
        after = page.next_id;
    }
    Err(io::Error::other("the chosen service is not in this device's current private service directory").into())
}
