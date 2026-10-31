//! Explicit resolver owner using the existing OS-protected management session.
use crate::session_store::SessionStore;
use nestlink_platform_security::{check_private_directory, read_private};
use nestlink_sdk::SpaceDns;
use sha2::{Digest, Sha256};
use std::{io, net::SocketAddr, path::{Path, PathBuf}, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[derive(clap::Args)]
pub(crate) struct SpaceDnsArgs {
    #[arg(long)]
    state_dir: PathBuf,
    /// Exact space ID. A different space requires stopping this owner first.
    #[arg(long)]
    space: String,
    /// Loopback only; both UDP and TCP bind the selected port.
    #[arg(long, default_value = "127.0.0.1:5354")]
    listen: SocketAddr,
    /// Opt in by exporting a public plan for a separate administrator helper.
    /// Windows requires --listen 127.0.0.1:53. Does not itself elevate or install.
    #[arg(long)]
    system_dns_plan: Option<PathBuf>,
}

pub(crate) async fn run(args: SpaceDnsArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("space DNS must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    let installation = nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    check_private_directory(&directory)?;
    // The protected refresh session has exactly one runtime owner. Acquire the
    // existing daemon singleton before restore can rotate its credentials.
    let _runtime = nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    let store = SessionStore::new(directory.clone());
    let sdk = store.restore().await.ok_or_else(|| io::Error::other("sign in and enable protected login recovery before starting space DNS"))?;
    // restore() rotates the stored login. Capture the protected snapshot only
    // afterwards, and close on logout/account change/refresh from another owner.
    let original = session_snapshot(&directory)?;
    let source = Arc::new(RwLock::new(sdk));
    let mut dns = SpaceDns::start(source.clone(), &args.space, args.listen).await?;
    if let Some(path) = &args.system_dns_plan {
        let expires = source.read().await.principal().ok_or_else(|| io::Error::other("DNS session ended"))?.access_expires.saturating_mul(1000);
        let plan = crate::space_dns_system::DnsPlan::current(&args.space, dns.local_addr(), expires).await?;
        plan.save_new(path)?;
        println!("Public split-DNS plan: {}. Review with space-dns-system review; apply separately as administrator/root with a private --journal-dir. The helper reads no login data.", path.display());
    }
    drop(installation);
    println!("Space DNS: {} (UDP/TCP), suffix {}", dns.local_addr(), dns.suffix());
    println!("Names identify current devices in this account; IP access requires separate authorization. Press Ctrl-C to stop.");
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let result = loop {
        tokio::select! {
            result = dns.wait() => break result,
            result = &mut signal => {
                result?;
                break Ok(());
            }
            _ = tick.tick() => {
                if nestlink_local_ipc::maintenance::requested(&directory)? {
                    break Ok(());
                }
                if session_snapshot(&directory).ok() != Some(original) {
                    source.write().await.forget_login();
                    break Err(nestlink_sdk::SpaceDnsError::SessionChanged);
                }
            }
        }
    };
    let cleanup = dns.shutdown().await;
    result?;
    cleanup?;
    Ok(())
}

fn session_snapshot(directory: &Path) -> io::Result<[u8; 32]> {
    check_private_directory(directory)?;
    let enabled = read_private(&directory.join("remember-login.json"), 16)?;
    if enabled.as_slice() != b"true" {
        return Err(io::Error::other("protected login recovery was disabled"));
    }
    let cipher = read_private(&directory.join("management-login.enc"), 16424)?;
    Ok(Sha256::digest(cipher).into())
}
