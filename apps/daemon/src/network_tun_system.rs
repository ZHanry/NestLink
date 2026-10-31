//! Host-only managed Linux TUN. The ordinary owner holds all packet policy,
//! login and carrier state; the separate root command only owns one OS plan.
//! This module never turns space membership into permission to inject IP.
mod linux;
mod owner;
mod plan;
mod store;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod native_tests;

pub(crate) use owner::{TunArgs, run as run_owner};
use crate::space_dns_system::{process_identity, require_system_admin, system_wall_ms};
use plan::TunPlan;
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf, time::Duration};
use store::JournalStore;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(clap::Args)]
pub(crate) struct SystemTunArgs {
    #[command(subcommand)]
    action: SystemTunAction,
}
#[derive(clap::Subcommand)]
enum SystemTunAction {
    /// Create one root-private recovery directory; no network configuration.
    InitJournal { #[arg(long)] journal_dir: PathBuf },
    /// Display a bounded signed public plan; reads no installation or login.
    Review { #[arg(long)] plan: PathBuf },
    /// Apply exactly this normal user's host-only TUN plan until it stops.
    Apply { #[arg(long)] plan: PathBuf, #[arg(long)] journal_dir: PathBuf },
    /// Recover only a recorded dead owner's interface and host routes.
    Recover { #[arg(long)] journal_dir: PathBuf },
    /// Read the protected journal and its exact current kernel interface.
    Inspect { #[arg(long)] journal_dir: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceIdentity {
    name: String,
    index: u32,
    marker: String,
    uid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunState {
    identity: InterfaceIdentity,
    mtu: u16,
    up: bool,
    persistent: bool,
    framing: u32,
    addresses: Vec<serde_json::Value>,
    routes: Vec<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    plan: TunPlan,
    /// Written durably before persistence can outlive the creating descriptor.
    identity: Option<InterfaceIdentity>,
    installed: Option<TunState>,
}

pub(crate) async fn run(args: SystemTunArgs) -> Result {
    match args.action {
        SystemTunAction::InitJournal { journal_dir } => {
            require_system_admin().await?;
            if !journal_dir.is_absolute() { return Err(io::Error::other("absolute root-private TUN journal directory required").into()); }
            match nestlink_platform_security::new_private_directory(&journal_dir) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => nestlink_platform_security::check_private_directory(&journal_dir)?,
                Err(error) => return Err(error.into()),
            }
            println!("TUN recovery directory ready: {}", journal_dir.display());
            Ok(())
        }
        SystemTunAction::Review { plan } => {
            let plan = TunPlan::read(&plan)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            println!("Only the two signed local host addresses and two remote host routes are requested. No default route, forwarding, DNS, login or arbitrary command is accepted.");
            Ok(())
        }
        SystemTunAction::Inspect { journal_dir } => {
            require_system_admin().await?;
            let store = JournalStore::open(&journal_dir)?;
            let journal = store.read()?;
            let current = match &journal { Some(journal) => linux::inspect(&journal.plan).await?, None => None };
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"journal":journal,"current":current}))?);
            Ok(())
        }
        SystemTunAction::Recover { journal_dir } => {
            require_system_admin().await?;
            recover(&JournalStore::open(&journal_dir)?).await
        }
        SystemTunAction::Apply { plan: path, journal_dir } => {
            require_system_admin().await?;
            let plan = TunPlan::read(&path)?;
            plan.validate(true)?;
            if process_identity(plan.process.pid()).await? != plan.process
                || !crate::space_dns_system::current_image_matches(&plan.process)?
            { return Err(io::Error::other("TUN plan must identify the original live ordinary owner of this executable").into()); }
            linux::validate_owner(&plan)?;
            let store = JournalStore::open(&journal_dir)?;
            recover(&store).await?;
            linux::preflight(&plan).await?;
            let mut journal = Journal { schema_version: 1, plan, identity: None, installed: None };
            store.save(&journal)?;
            let outcome = async {
                // The initially nonpersistent descriptor guarantees that a
                // crash before its identity is durable removes the new link.
                let device = linux::create(&journal.plan).await?;
                journal.identity = Some(linux::created_identity(&journal.plan).await?);
                store.save(&journal)?;
                device.persist()?;
                linux::configure(&journal.plan).await?;
                journal.installed = Some(linux::inspect(&journal.plan).await?.ok_or_else(|| io::Error::other("new TUN interface disappeared"))?);
                linux::verify(&journal.plan, journal.installed.as_ref().ok_or_else(|| io::Error::other("missing TUN readback"))?, true)?;
                if journal.installed.as_ref().map(|state| &state.identity) != journal.identity.as_ref() {
                    return Err(io::Error::other("TUN interface changed while applying its plan").into());
                }
                store.save(&journal)?;
                // A single-queue TUN can only be attached by the original
                // ordinary process after this privileged descriptor is gone.
                drop(device);
                println!("Managed TUN {} installed for PID {}; holding exact root journal {}", journal.plan.link(), journal.plan.process.pid(), journal_dir.display());
                monitor(&journal, &path).await
            }.await;
            let cleanup = linux::remove(&journal).await;
            if cleanup.is_ok() { store.clear()?; }
            cleanup?;
            outcome
        }
    }
}

async fn monitor(journal: &Journal, path: &std::path::Path) -> Result {
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {biased;
            result = &mut signal => { result?; return Ok(()); },
            _ = tick.tick() => {
                if system_wall_ms()? >= journal.plan.expires_at_ms
                    || process_identity(journal.plan.process.pid()).await.ok().as_ref() != Some(&journal.plan.process)
                { return Ok(()); }
                // This is the explicit public plan file selected on the root
                // command line, never a path supplied by a network message.
                // Removing it is the ordinary owner's one-way stop signal.
                match TunPlan::read(path) {
                    Ok(current) if current == journal.plan => {},
                    _ => return Ok(()),
                }
                if linux::inspect(&journal.plan).await? != journal.installed {
                    return Err(io::Error::other("managed TUN changed externally; preserving changed configuration and its recovery journal").into());
                }
            },
        }
    }
}

async fn recover(store: &JournalStore) -> Result {
    let Some(journal) = store.read()? else { return Ok(()); };
    if system_wall_ms()? < journal.plan.expires_at_ms
        && process_identity(journal.plan.process.pid()).await.ok().as_ref() == Some(&journal.plan.process)
    { return Err(io::Error::other("the original ordinary TUN owner is still alive; stop it before recovery or upgrade").into()); }
    linux::remove(&journal).await?;
    store.clear()?;
    println!("Recorded TUN, addresses and host routes are absent; recovery completed.");
    Ok(())
}
