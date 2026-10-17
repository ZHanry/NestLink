//! Normal-user installation owner. No PID lookup, process-name kill or shell.
use nestlink_app_ipc::{
    Client,
    wire::{Command, ExitResult, Reply},
};
use nestlink_local_ipc::maintenance::MaintenanceGuard;
use nestlink_platform_security::{create_private, new_private_directory, read_private};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(clap::Args)]
pub(crate) struct ShutdownArgs {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
    timeout_seconds: u64,
}

#[derive(clap::Args)]
pub(crate) struct MaintenanceArgs {
    #[arg(long)]
    state_dir: PathBuf,
    /// A NEW direct child named maintenance-<UUID> under state-dir.
    #[arg(long)]
    control_dir: PathBuf,
    /// Optional isolated per-user installation root (Windows installer owner).
    #[arg(long)]
    installation_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
    timeout_seconds: u64,
    /// Absolute bounded ownership even if an installer crashes before release.
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..=1800))]
    hold_seconds: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Status<'a> {
    schema_version: u16,
    control_id: &'a str,
    state: &'a str,
    stopped_runtime_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_recovery: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    schema_version: u16,
    control_id: String,
    action: String,
}

fn validate_user_directory(directory: &Path) -> Result {
    if !directory.is_absolute() {
        return Err(io::Error::other("maintenance state directory must be absolute").into());
    }
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("user maintenance must run as the installation user").into());
    }
    Ok(())
}

/// The gate is acquired before connecting. A partially starting daemon is
/// allowed to finish publishing, but no replacement runtime can start. After
/// connecting, Exit is sent once on that authenticated connection only.
async fn quiesce(guard: &mut MaintenanceGuard, directory: &Path) -> Result<Option<String>> {
    let mut stopped_runtime = None;
    if !guard.daemon_stopped()? {
        let mut client = loop {
            match Client::connect(directory).await {
                Ok(client) => break Some(client),
                Err(error) if error.is_transient_connect() => {
                    if guard.daemon_stopped()? {
                        break None;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        if let Some(client) = client.as_mut() {
            let runtime = client.runtime_id().to_owned();
            let snapshot = client.request(0, Command::Snapshot).await?;
            let response = client
                .request(snapshot.snapshot.generation, Command::Exit)
                .await?;
            if !matches!(
                response.result,
                Reply::Exited {
                    result: ExitResult::Complete
                }
            ) {
                return Err(
                    io::Error::other("original daemon did not confirm complete cleanup").into(),
                );
            }
            stopped_runtime = Some(runtime);
        }
        drop(client);
    }
    // A complete IPC acknowledgement precedes the final transport/capture
    // owner drop. Retain admission and wait for the real singleton release and
    // every UI/selector lifetime lease before any package operation is allowed.
    while !guard.quiescent()? {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(stopped_runtime)
}

pub(crate) async fn shutdown(args: ShutdownArgs) -> Result {
    validate_user_directory(&args.state_dir)?;
    let mut guard = MaintenanceGuard::acquire(&args.state_dir)?;
    let runtime = tokio::time::timeout(
        Duration::from_secs(args.timeout_seconds),
        quiesce(&mut guard, &args.state_dir),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "graceful shutdown exceeded its budget; no process was killed",
        )
    })??;
    guard.release()?;
    println!(
        "{}",
        serde_json::to_string(&Status {
            schema_version: 1,
            control_id: "shutdown",
            state: "stopped",
            stopped_runtime_id: runtime.as_deref(),
            installation_recovery: None,
        })?
    );
    Ok(())
}

fn create_control_directory(state: &Path, requested: &Path) -> Result<(PathBuf, String)> {
    nestlink_local_ipc::initialize_directory(state)?;
    let state = state.canonicalize()?;
    let name = requested
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::other("invalid maintenance control directory"))?;
    let control_id = name
        .strip_prefix("maintenance-")
        .filter(|id| nestlink_protocol::valid_id(id))
        .ok_or_else(|| io::Error::other("maintenance control directory needs a fresh UUID"))?;
    if !requested.is_absolute()
        || requested
            .parent()
            .map(Path::canonicalize)
            .transpose()?
            .as_deref()
            != Some(state.as_path())
    {
        return Err(io::Error::other(
            "maintenance control directory must be a direct child of state-dir",
        )
        .into());
    }
    let control = state.join(name);
    new_private_directory(&control)?;
    Ok((control, control_id.to_owned()))
}

fn status_file(
    control: &Path,
    id: &str,
    name: &str,
    state: &str,
    runtime: Option<&str>,
    installation_recovery: Option<bool>,
) -> Result {
    create_private(
        &control.join(name),
        &serde_json::to_vec(&Status {
            schema_version: 1,
            control_id: id,
            state,
            stopped_runtime_id: runtime,
            installation_recovery,
        })?,
    )?;
    Ok(())
}

pub(crate) async fn run(args: MaintenanceArgs) -> Result {
    validate_user_directory(&args.state_dir)?;
    let (control, id) = create_control_directory(&args.state_dir, &args.control_dir)?;
    let result = hold(&args, &control, &id).await;
    if result.is_err() {
        // Small diagnostics contain no identity keys, paths, user payloads or
        // detailed remote error. Keep this evidence for a failed installation.
        let _ = status_file(&control, &id, "failed.json", "failed", None, None);
    }
    result
}

async fn hold(args: &MaintenanceArgs, control: &Path, id: &str) -> Result {
    let installation = args
        .installation_dir
        .as_ref()
        .map(|directory| {
            if !directory.is_absolute() {
                return Err(nestlink_local_ipc::Error::Protocol);
            }
            nestlink_local_ipc::maintenance::InstallationMaintenance::acquire(directory)
        })
        .transpose()?;
    let mut guard = MaintenanceGuard::acquire(&args.state_dir)?;
    let runtime = tokio::time::timeout(
        Duration::from_secs(args.timeout_seconds),
        quiesce(&mut guard, &args.state_dir),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "maintenance cleanup exceeded its budget; no process was killed",
        )
    })??;
    let installation_recovery = installation.as_ref().map(|owner| owner.recovering());
    status_file(
        control,
        id,
        "ready.json",
        "ready",
        runtime.as_deref(),
        installation_recovery,
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.hold_seconds);
    let completed = loop {
        match read_private(&control.join("release.json"), 512) {
            Ok(bytes) => {
                let release: Release = serde_json::from_slice(&bytes)?;
                if release.schema_version != 1
                    || release.control_id != id
                    || !matches!(release.action.as_str(), "release" | "abandon")
                {
                    return Err(
                        io::Error::other("maintenance release does not match its owner").into(),
                    );
                }
                break release.action == "release";
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "maintenance owner expired without release",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    if completed {
        guard.release()?;
        if let Some(installation) = installation {
            installation.release()?;
        }
        status_file(
            control,
            id,
            "released.json",
            "released",
            runtime.as_deref(),
            None,
        )?;
    } else {
        // An incomplete installer must release OS ownership for recovery while
        // leaving both durable startup fences closed. Drop never clears them.
        drop(guard);
        drop(installation);
        status_file(
            control,
            id,
            "abandoned.json",
            "abandoned",
            runtime.as_deref(),
            None,
        )?;
    }
    Ok(())
}
