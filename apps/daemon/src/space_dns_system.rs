//! Narrow administrative owner for one private DNS suffix. No management login.
mod command;
mod linux;
#[cfg(test)]
mod tests;
mod windows;

use nestlink_platform_security::{
    MetadataCommit, check_private_directory, create_private, read_private, replace_private_metadata,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const JOURNAL: &str = "split-dns-owner.json";
const MAX_JOURNAL: u64 = 65_536;

#[derive(clap::Args)]
pub(crate) struct SystemDnsArgs {
    #[command(subcommand)]
    action: SystemDnsAction,
}
#[derive(clap::Subcommand)]
enum SystemDnsAction {
    /// Create only one new private administrator-owned journal leaf directory.
    InitJournal {
        #[arg(long)]
        journal_dir: PathBuf,
    },
    /// Print the public plan; does not change system configuration.
    Review {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Run separately as administrator/root. Holds ownership until the resolver exits.
    Apply {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        journal_dir: PathBuf,
    },
    /// Recover a previous crashed owner after its resolver process has exited.
    Recover {
        #[arg(long)]
        journal_dir: PathBuf,
    },
    /// Inspect the protected journal and current OS resource without modifying either.
    Inspect {
        #[arg(long)]
        journal_dir: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pid: u32,
    incarnation: String,
    image: String,
}

/// Contains public identifiers only. Never references a session store or token.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsPlan {
    schema_version: u16,
    owner_id: String,
    space_id: String,
    suffix: String,
    listen: SocketAddr,
    process: ProcessIdentity,
    created_at_ms: u64,
    expires_at_ms: u64,
}

impl DnsPlan {
    pub(crate) async fn current(
        space: &str,
        listen: SocketAddr,
        expires_at_ms: u64,
    ) -> Result<Self> {
        let plan = Self {
            schema_version: 1,
            owner_id: nestlink_auth::random_id(),
            space_id: space.into(),
            suffix: format!("s-{space}.nestlink.internal"),
            listen,
            process: identity(std::process::id()).await?,
            created_at_ms: wall_ms()?,
            expires_at_ms,
        };
        plan.validate(true)?;
        Ok(plan)
    }
    fn validate(&self, fresh: bool) -> Result {
        let now = wall_ms()?;
        if self.schema_version != 1
            || !nestlink_protocol::valid_id(&self.owner_id)
            || !nestlink_protocol::valid_id(&self.space_id)
            || self.suffix != format!("s-{}.nestlink.internal", self.space_id)
            || self.listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
            || self.listen.port() == 0
            || self.process.pid == 0
            || self.process.incarnation.is_empty()
            || self.process.incarnation.len() > 128
            || self.process.image.is_empty()
            || self.process.image.len() > 32768
            || self.expires_at_ms <= self.created_at_ms
            || self.expires_at_ms - self.created_at_ms > 86_400_000
            || (fresh
                && (self.created_at_ms > now.saturating_add(1000)
                    || now.saturating_sub(self.created_at_ms) > 300_000
                    || self.expires_at_ms <= now))
        {
            return Err(io::Error::other("invalid or expired public split-DNS plan; generate a fresh plan from the active resolver").into());
        }
        #[cfg(windows)]
        if self.listen.port() != 53 {
            return Err(io::Error::other(
                "Windows NRPT requires an explicit 127.0.0.1:53 resolver",
            )
            .into());
        }
        Ok(())
    }
    fn marker(&self) -> String {
        format!("NestLink:split-dns:v1:{}", self.owner_id)
    }
    #[cfg(any(target_os = "linux", test))]
    fn link(&self) -> String {
        format!("nl-dns-{}", &self.owner_id[..8])
    }
    pub(crate) fn save_new(&self, path: &Path) -> Result {
        self.validate(true)?;
        if !path.is_absolute() {
            return Err(io::Error::other("an absolute public-plan output path is required").into());
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("plan parent missing"))?;
        check_private_directory(parent)?;
        create_private(path, &serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    plan: DnsPlan,
    /// None means a crash or failure occurred during installation. Recovery
    /// accepts only the exact marker and a safe subset of the planned settings.
    installed: Option<Value>,
}

struct JournalStore {
    directory: PathBuf,
    _lock: File,
}
impl JournalStore {
    fn open(directory: &Path) -> Result<Self> {
        if !directory.is_absolute() {
            return Err(io::Error::other(
                "an absolute administrator-owned journal directory is required",
            )
            .into());
        }
        check_private_directory(directory)?;
        let directory = directory.canonicalize()?;
        let lock_path = directory.join("split-dns-owner.lock");
        match create_private(&lock_path, &[]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = read_private(&lock_path, 1)?;
            }
            Err(error) => return Err(error.into()),
        }
        let lock = OpenOptions::new().read(true).write(true).open(lock_path)?;
        if !lock.metadata()?.is_file() || lock.metadata()?.len() != 0 {
            return Err(io::Error::other("invalid split-DNS lock").into());
        }
        lock.try_lock()
            .map_err(|_| io::Error::other("another split-DNS owner holds this journal"))?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    fn read(&self) -> Result<Option<Journal>> {
        let bytes = match read_private(&self.directory.join(JOURNAL), MAX_JOURNAL) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if journal.schema_version != 1 {
            return Err(io::Error::other("unsupported split-DNS recovery journal").into());
        }
        journal.plan.validate(false)?;
        Ok(Some(journal))
    }
    fn save(&self, journal: &Journal) -> Result {
        if replace_private_metadata(&self.directory.join(JOURNAL), &serde_json::to_vec(journal)?)?
            != MetadataCommit::Durable
        {
            return Err(io::Error::other("split-DNS journal is visible but durable persistence could not be confirmed; recovery is required").into());
        }
        Ok(())
    }
    fn clear(&self) -> Result {
        // This fixed file is removed only after OS absence was confirmed.
        let _ = self
            .read()?
            .ok_or_else(|| io::Error::other("split-DNS journal disappeared"))?;
        std::fs::remove_file(self.directory.join(JOURNAL))?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

pub(crate) async fn run(args: SystemDnsArgs) -> Result {
    match args.action {
        SystemDnsAction::InitJournal { journal_dir } => {
            require_admin().await?;
            if !journal_dir.is_absolute() {
                return Err(io::Error::other("an absolute journal directory is required").into());
            }
            match nestlink_platform_security::new_private_directory(&journal_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    check_private_directory(&journal_dir)?
                }
                Err(error) => return Err(error.into()),
            }
            println!(
                "Private split-DNS journal directory ready: {}",
                journal_dir.display()
            );
            Ok(())
        }
        SystemDnsAction::Review { plan } => {
            let plan = read_plan(&plan)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            println!(
                "Installs only this private suffix. Requires a separate administrator/root process. No management credentials are read."
            );
            Ok(())
        }
        SystemDnsAction::Inspect { journal_dir } => {
            let store = JournalStore::open(&journal_dir)?;
            let journal = store.read()?;
            let current = match &journal {
                Some(journal) => inspect(&journal.plan).await?,
                None => None,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"journal":journal,"current":current})
                )?
            );
            Ok(())
        }
        SystemDnsAction::Recover { journal_dir } => {
            require_admin().await?;
            let store = JournalStore::open(&journal_dir)?;
            recover(&store).await
        }
        SystemDnsAction::Apply { plan, journal_dir } => {
            require_admin().await?;
            let plan = read_plan(&plan)?;
            plan.validate(true)?;
            if identity(plan.process.pid).await? != plan.process
                || !same_image(&plan.process.image)?
            {
                return Err(io::Error::other(
                    "split-DNS plan does not identify the live resolver from this executable",
                )
                .into());
            }
            probe_socket(&plan).await?;
            let store = JournalStore::open(&journal_dir)?;
            // A crashed journal is recovered before any new resource is added.
            recover(&store).await?;
            preflight(&plan).await?;
            let mut journal = Journal {
                schema_version: 1,
                plan,
                installed: None,
            };
            store.save(&journal)?;
            let outcome = async {
                install(&journal.plan).await?;
                journal.installed = Some(inspect(&journal.plan).await?.ok_or_else(|| io::Error::other("installed split-DNS resource was not observed"))?);
                verify_installed(&journal.plan, journal.installed.as_ref().ok_or_else(|| io::Error::other("missing installed observation"))?)?;
                store.save(&journal)?;
                println!("Managed split DNS installed for {}; monitoring resolver process {}. Journal: {}", journal.plan.suffix, journal.plan.process.pid, store.directory.display());
                monitor(&journal).await
            }.await;
            let cleanup = remove(&journal).await;
            if cleanup.is_ok() {
                store.clear()?;
            }
            cleanup?;
            outcome
        }
    }
}

async fn monitor(journal: &Journal) -> Result {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let signal = termination();
    tokio::pin!(signal);
    loop {
        tokio::select! {
            result = &mut signal => { result?; return Ok(()); }
            _ = tick.tick() => {
                if wall_ms()? >= journal.plan.expires_at_ms { return Ok(()); }
                match identity(journal.plan.process.pid).await {
                    Ok(current) if current == journal.plan.process => {},
                    _ => return Ok(()),
                }
                if probe_socket(&journal.plan).await.is_err() { return Ok(()); }
                if inspect(&journal.plan).await? != journal.installed {
                    return Err(io::Error::other("managed split-DNS state changed externally; cleanup must preserve the changed resource and journal").into());
                }
            }
        }
    }
}

async fn recover(store: &JournalStore) -> Result {
    let Some(journal) = store.read()? else {
        return Ok(());
    };
    if wall_ms()? < journal.plan.expires_at_ms
        && identity(journal.plan.process.pid)
            .await
            .is_ok_and(|current| current == journal.plan.process)
        && probe_socket(&journal.plan).await.is_ok()
    {
        return Err(io::Error::other("the recorded resolver is still running; stop it before recovering or upgrading its split-DNS owner").into());
    }
    remove(&journal).await?;
    store.clear()?;
    println!("Previous managed split-DNS resource is absent; recovery completed.");
    Ok(())
}

async fn probe_socket(plan: &DnsPlan) -> Result {
    tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(plan.listen),
    )
    .await??;
    Ok(())
}
fn read_plan(path: &Path) -> Result<DnsPlan> {
    // Administrator explicitly selects this public input file. None of its
    // fields become filesystem paths or arbitrary executable arguments.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_JOURNAL {
        return Err(io::Error::other("plan must be a bounded regular JSON file").into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_JOURNAL + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL as usize {
        return Err(io::Error::other("plan exceeds limit").into());
    }
    let plan: DnsPlan = serde_json::from_slice(&bytes)?;
    plan.validate(false)?;
    Ok(plan)
}
fn wall_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
pub(crate) async fn termination() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tokio::signal::ctrl_c().await
    }
}
fn same_image(image: &str) -> Result<bool> {
    let current = std::env::current_exe()?.canonicalize()?;
    #[cfg(windows)]
    return Ok(current
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(image.trim_start_matches(r"\\?\")));
    #[cfg(not(windows))]
    Ok(current == Path::new(image))
}

#[cfg(target_os = "linux")]
use linux::{identity, inspect, install, preflight, remove, require_admin, verify_installed};
#[cfg(windows)]
use windows::{identity, inspect, install, preflight, remove, require_admin, verify_installed};
