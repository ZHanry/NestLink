//! Explicit normal-user entry to one authorized private service.
use crate::{session_store::SessionStore, space_dns::session_snapshot};
use nestlink_protocol::services::private::PrivateServiceEntry;
use nestlink_sdk::{
    Sdk,
    services::{LocalProxyServiceChoice, LocalProxyWait, LocalServiceProxy,
        LocalNativeServiceProxy, NativeStreamWait},
};
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    /// Relay redirected stdin/stdout to an existing same-user native endpoint.
    /// Suitable for SSH ProxyCommand and clients with their own message framing.
    /// Windows requires redirected pipes and has no independent write-half EOF.
    Connect {
        #[arg(long)]
        endpoint: PathBuf,
    },
    /// Serve one chosen TCP/HTTP/HTTPS/UDP service until stopped or its deadline.
    /// UDP clients must bind their local UDP socket first, authenticate the TCP
    /// control connection, and declare that exact loopback IP and nonzero UDP
    /// port in UDP ASSOCIATE. Unspecified sources such as [::]:0 are rejected.
    /// Each UDP packet must target the selected alias/port; fragments and
    /// payloads over 1169 bytes are discarded. Empty datagrams are preserved.
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
        /// Existing private directory for credentials or the native Unix socket.
        /// Defaults to this installation's state directory.
        #[arg(long)]
        credentials_dir: Option<PathBuf>,
        /// Use an OS-authenticated Unix socket / Windows byte pipe instead of
        /// SOCKS. TCP/HTTP/HTTPS only; --listen applies to SOCKS mode only.
        #[arg(long)]
        native_stream: bool,
    },
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

enum RunningProxy { Socks(LocalServiceProxy), Native(LocalNativeServiceProxy) }
enum ProxyWait { Pending, Stopped(String), Failed(String) }
impl RunningProxy {
    fn is_finished(&self) -> bool { match self { Self::Socks(owner) => owner.is_finished(), Self::Native(owner) => owner.is_finished() } }
    fn request_shutdown(&self) { match self { Self::Socks(owner) => owner.request_shutdown(), Self::Native(owner) => owner.request_shutdown() } }
    async fn wait_stopped(&mut self) -> ProxyWait {
        match self {
            Self::Socks(owner) => match owner.wait_stopped(Duration::from_secs(5)).await {
                LocalProxyWait::CleanupPending => ProxyWait::Pending,
                LocalProxyWait::Stopped(report) => ProxyWait::Stopped(format!("{report:?}")),
                LocalProxyWait::CleanupFailed(report) => ProxyWait::Failed(format!("{report:?}")),
            },
            Self::Native(owner) => match owner.wait_stopped(Duration::from_secs(5)).await {
                NativeStreamWait::CleanupPending => ProxyWait::Pending,
                NativeStreamWait::Stopped(report) => ProxyWait::Stopped(format!("{report:?}")),
                NativeStreamWait::CleanupFailed(report) => ProxyWait::Failed(format!("{report:?}")),
            },
        }
    }
}

pub(crate) async fn run(args: ProxyArgs) -> Result<()> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("private service proxy must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    if let ProxyAction::Connect { endpoint } = &args.action {
        nestlink_platform_security::check_private_directory(&args.state_dir)?;
        let stream = tokio::time::timeout(Duration::from_secs(3),
            nestlink_platform_security::local_stream::connect(endpoint)).await??;
        return Ok(nestlink_platform_security::local_stream::relay_stdio(stream,
            crate::space_dns_system::termination()).await?);
    }
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
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
        return Err(
            io::Error::other("the installation has no registered local device identity").into(),
        );
    }
    let consumer = Arc::new(crate::identity(&directory)?);
    match args.action {
        ProxyAction::List => {
            let mut after = None;
            for _ in 0..64 {
                let page = sdk
                    .private_services(&consumer.device_id, after.as_deref(), 100)
                    .await?;
                for entry in &page.entries {
                    #[derive(serde::Serialize)]
                    struct View<'a> {
                        service_id: &'a str,
                        space_id: &'a str,
                        availability:
                            &'a nestlink_protocol::services::private::PrivateServiceAvailability,
                        maximum_bytes_per_connection: u64,
                    }
                    println!(
                        "{}",
                        serde_json::to_string(&View {
                            service_id: &entry.service.id,
                            space_id: &entry.exposure.space_id,
                            availability: &entry.availability,
                            maximum_bytes_per_connection: entry
                                .exposure
                                .private_maximum_bytes
                                .min(entry.service.definition.limits.maximum_bytes),
                        })?
                    );
                }
                if !page.more {
                    return Ok(());
                }
                after = page.next_id;
            }
            Err(io::Error::other(
                "private service directory exceeds this command's bounded page budget",
            )
            .into())
        }
        ProxyAction::Serve {
            service,
            space,
            alias,
            port,
            maximum_bytes,
            lifetime_seconds,
            listen,
            credentials_dir,
            native_stream,
        } => {
            if !nestlink_protocol::valid_id(&service)
                || !nestlink_protocol::valid_id(&space)
                || !listen.ip().is_loopback()
            {
                return Err(io::Error::other(
                    "choose valid service and space IDs and a loopback listener",
                )
                .into());
            }
            let entry = selected_service(&sdk, &consumer.device_id, &service, &space).await?;
            let datagram = matches!(&entry.service.definition.requested_ingress,
                nestlink_protocol::api::ServiceIngress::Udp { .. });
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let remaining = sdk
                .principal()
                .ok_or(nestlink_sdk::SdkError::SignIn)?
                .access_expires
                .saturating_sub(now);
            let lifetime = Duration::from_secs(lifetime_seconds.min(remaining));
            let choice = LocalProxyServiceChoice::from_local_choice(
                &entry,
                &alias,
                port,
                maximum_bytes,
                lifetime,
            )?;
            let sdk = Arc::new(sdk);
            let credential_directory = credentials_dir.unwrap_or_else(|| directory.clone());
            let deadline = tokio::time::Instant::now() + lifetime;
            let mut proxy = if native_stream {
                RunningProxy::Native(sdk.start_private_service_native_stream(consumer, choice, &credential_directory).await?)
            } else {
                RunningProxy::Socks(sdk.start_private_service_socks(consumer, choice, listen, &credential_directory).await?)
            };
            drop(installation);
            match &proxy {
                RunningProxy::Socks(owner) => {
                    println!("Private service {service} in space {space}: SOCKS5 {}", owner.address());
                    println!("Local credentials file: {}", owner.credentials_path().display());
                }
                RunningProxy::Native(owner) => {
                    println!("Private service {service} in space {space}: native endpoint {}", owner.endpoint().display());
                    println!("Connect with this command's connect --endpoint subcommand and the same --state-dir; standard native socket/pipe clients may use the endpoint directly.");
                    #[cfg(windows)]
                    println!("Windows byte pipes have no independent write-half EOF; use SOCKS TCP for applications that require FIN before a reverse response.");
                }
            }
            println!(
                "Destination: {alias}:{port}; maximum {maximum_bytes} bytes per connection; owner lifetime {} seconds.",
                lifetime.as_secs()
            );
            println!("Press Ctrl-C to stop.");
            if datagram {
                println!("UDP requires password authentication on a live TCP control connection and UDP ASSOCIATE with your already-bound loopback UDP IP and nonzero port. Wildcard sources are rejected.");
                println!("Send SOCKS UDP packets to the returned relay, targeting {alias}:{port}. Empty datagrams are preserved; FRAG and payloads over 1169 bytes are discarded.");
                println!("fast-socks5 Socks5Datagram convenience constructors request [::]:0 and cannot be used here; use Socks5Stream::request with the exact bound UDP endpoint and the library UDP codec.");
            }
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
                            Err(error) => break Err(io::Error::other(error)),
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
                match proxy.wait_stopped().await {
                    ProxyWait::Pending => {
                        if !reported_pending {
                            eprintln!(
                                "Private proxy is joining its original connections; cleanup receipt is pending."
                            );
                            reported_pending = true;
                        }
                    }
                    ProxyWait::Failed(report) => {
                        return Err(io::Error::other(format!(
                            "private proxy cleanup failed: {report:?}"
                        ))
                        .into());
                    }
                    ProxyWait::Stopped(report) => {
                        println!("Private proxy stopped: {report:?}");
                        operation?;
                        return Ok(());
                    }
                }
            }
        }
        ProxyAction::Connect { .. } => Err(io::Error::other("native connect dispatch failed").into()),
    }
}

async fn selected_service(
    sdk: &Sdk,
    consumer: &str,
    service: &str,
    space: &str,
) -> Result<PrivateServiceEntry> {
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
        "the chosen service is not in this device's current private service directory",
    )
    .into())
}
