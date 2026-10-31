//! Per-user owner of product operations. It is never a privileged service agent.
mod browser_data;
mod capture;
mod diagnostics;
mod maintenance;
mod native_audio;
mod native_clipboard;
mod native_files;
#[cfg(windows)]
mod native_gpu_diagnostics;
mod native_video;
mod private_service_proxy;
mod privileged_input;
mod session_store;
mod space_dns;
mod space_dns_system;

use clap::{Parser, Subcommand};
use nestlink_app_core::{AppCore, Limits, ShutdownState};
use nestlink_app_core::{NativeNetworkFileStore, NativeNetworkSettingsStore};
use nestlink_app_ipc::{ExitRequest, wire::ExitResult};
use nestlink_local_ipc::LocalServer;
#[cfg(any(unix, test))]
use std::fs;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet};

#[derive(Parser)]
#[command(name = "nestlink-daemon", version, about = "NestLink user daemon")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Bind address for native peer transport sockets.
    #[arg(long, default_value = "0.0.0.0:0")]
    native_bind: SocketAddr,
    /// Explicitly trusted STUN endpoints used for direct candidate discovery.
    #[arg(long = "stun-server")]
    stun_servers: Vec<SocketAddr>,
    /// Administrator-approved private network prefixes for LAN candidates.
    #[arg(long = "private-network-prefix")]
    private_network_prefixes: Vec<String>,
    /// Private JSON NativeRouteSetSettings: explicit pinned space and two relays.
    /// Applies to future sessions and persists with the other local consent.
    #[arg(long, conflicts_with_all = ["disable_native_route_set", "native_space_path"])]
    native_route_set: Option<PathBuf>,
    /// Private JSON NativeSpacePathSettings: admit the original direct owner
    /// through current signed membership/connectivity/path grants.
    #[arg(long, conflicts_with_all = ["disable_native_space_path", "native_route_set"])]
    native_space_path: Option<PathBuf>,
    /// Clear the persisted direct-only space admission.
    #[arg(long)]
    disable_native_space_path: bool,
    /// Explicitly clear the persisted signed original-group opt-in.
    #[arg(long)]
    disable_native_route_set: bool,
    /// Exact finite CPU media target, e.g. 1920x1080@30:4000. No implied presets.
    #[arg(long, value_parser=parse_native_media_target)]
    native_media_target: Option<nestlink_media_codec::VideoConfig>,
    /// Private JSON policy for one internal software candidate; absent keeps rollout closed.
    #[arg(long, requires = "native_media_target")]
    internal_software_media_candidate: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// List approved private services or serve one through authenticated local SOCKS5.
    PrivateServiceProxy(private_service_proxy::ProxyArgs),
    /// Serve one space's current same-account private names on loopback UDP/TCP.
    SpaceDns(space_dns::SpaceDnsArgs),
    /// Review/apply/recover only an explicit managed split-DNS plan; no login data.
    SpaceDnsSystem(space_dns_system::SystemDnsArgs),
    #[command(
        name = "file-quota",
        about = "Offline native FileWrite quota metadata maintenance"
    )]
    FileQuota(FileQuotaArgs),
    /// Stop the exact authenticated user runtime and retain installation admission.
    Maintenance(maintenance::MaintenanceArgs),
    /// Gracefully stop the user runtime and all registered UIs; never force kill.
    Shutdown(maintenance::ShutdownArgs),
    /// Review retained public device IDs for explicit account-side unbinding.
    /// Reads no private key or authorization and never imports old identity.
    RetainedInstances {
        #[arg(long)]
        state_root: PathBuf,
    },
}

#[derive(clap::Args)]
struct FileQuotaArgs {
    #[command(subcommand)]
    action: FileQuotaAction,
}

#[derive(Subcommand)]
enum FileQuotaAction {
    /// Print lengths, validity, usage, and hashes; never print raw metadata bytes.
    Inspect {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Export an exact raw snapshot to one fixed private, create-new file in state_dir.
    Export {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Explicitly repair quota metadata. Export first if you need a saved raw copy.
    Recover {
        #[arg(long)]
        state_dir: PathBuf,
    },
}

#[derive(serde::Serialize)]
struct MetadataFileSummary {
    present: bool,
    bytes: usize,
    sha256: String,
    record_valid: bool,
    stored_maximum_bytes: Option<u64>,
    stored_maximum_artifacts: Option<u64>,
    charged_bytes: Option<u64>,
    charged_artifacts: Option<u64>,
}

#[derive(serde::Serialize)]
struct QuotaInspectionSummary {
    lock_marker_valid: bool,
    lock_marker_bytes: usize,
    lock_marker_sha256: String,
    ledger: Option<MetadataFileSummary>,
    pending: Option<MetadataFileSummary>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    schema_version: u16,
    device_id: String,
    public_key_sha256: [u8; 32],
}
const QUOTA_EXPORT_MAGIC: &[u8; 8] = b"NLWQEXP1";

fn run_file_quota(command: FileQuotaArgs) -> io::Result<()> {
    match command.action {
        FileQuotaAction::Inspect { state_dir } => {
            let snapshot =
                nestlink_platform_files::upload::WriteQuota::inspect_private_ledger(&state_dir)?;
            print_inspection(&snapshot)
        }
        FileQuotaAction::Export { state_dir } => {
            let snapshot =
                nestlink_platform_files::upload::WriteQuota::inspect_private_ledger(&state_dir)?;
            let (bytes, digest) = write_quota_export(&state_dir, &snapshot)?;
            println!(
                "export_file={QUOTA_EXPORT_NAME} export_bytes={bytes} export_sha256={}",
                lower_hex(&digest)
            );
            Ok(())
        }
        FileQuotaAction::Recover { state_dir } => {
            let recovered = nestlink_platform_files::upload::WriteQuota::recover_private_ledger(
                &state_dir,
                nestlink_protocol::FILE_SIZE_BYTES,
                nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64,
            )?;
            println!(
                "charged_bytes={} charged_artifacts={} unknown_usage_saturated_limits={}",
                recovered.charged_bytes,
                recovered.charged_artifacts,
                recovered.unknown_usage_saturated_limits
            );
            Ok(())
        }
    }
}

fn inspection_summary(
    snapshot: &nestlink_platform_files::upload::QuotaLedgerSnapshot,
) -> QuotaInspectionSummary {
    QuotaInspectionSummary {
        lock_marker_valid: snapshot.lock_marker_valid,
        lock_marker_bytes: snapshot.lock_marker.len(),
        lock_marker_sha256: lower_hex(&snapshot.lock_marker_sha256),
        ledger: snapshot.ledger.as_ref().map(summarize_metadata_file),
        pending: snapshot.pending.as_ref().map(summarize_metadata_file),
    }
}

fn summarize_metadata_file(
    file: &nestlink_platform_files::upload::QuotaLedgerFileSnapshot,
) -> MetadataFileSummary {
    let decoded = decode_ledger_summary(&file.raw);
    MetadataFileSummary {
        present: true,
        bytes: file.raw.len(),
        sha256: lower_hex(&file.sha256),
        record_valid: decoded.is_some(),
        stored_maximum_bytes: decoded.map(|fields| fields.0),
        stored_maximum_artifacts: decoded.map(|fields| fields.1),
        charged_bytes: decoded.map(|fields| fields.2),
        charged_artifacts: decoded.map(|fields| fields.3),
    }
}

fn decode_ledger_summary(bytes: &[u8]) -> Option<(u64, u64, u64, u64)> {
    if bytes.len() != 80
        || &bytes[..8] != b"NLWQLED1"
        || u32::from_le_bytes(bytes[8..12].try_into().ok()?) != 1
        || bytes[12..16] != [0; 4]
    {
        return None;
    }
    if sha256(&bytes[..48]).as_slice() != &bytes[48..80] {
        return None;
    }
    let maximum_bytes = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    let maximum_artifacts = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
    let charged_bytes = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let charged_artifacts = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
    (charged_bytes <= maximum_bytes && charged_artifacts <= maximum_artifacts).then_some((
        maximum_bytes,
        maximum_artifacts,
        charged_bytes,
        charged_artifacts,
    ))
}

fn print_inspection(
    snapshot: &nestlink_platform_files::upload::QuotaLedgerSnapshot,
) -> io::Result<()> {
    let output = serde_json::to_string(&inspection_summary(snapshot))
        .map_err(|_| io::Error::other("quota inspection summary encoding failed"))?;
    println!("{output}");
    Ok(())
}

const QUOTA_EXPORT_NAME: &str = "native-file-write-quota.snapshot";

fn write_quota_export(
    state_dir: &Path,
    snapshot: &nestlink_platform_files::upload::QuotaLedgerSnapshot,
) -> io::Result<(usize, [u8; 32])> {
    nestlink_platform_security::check_private_directory(state_dir)?;
    let state_directory = state_dir.canonicalize()?;
    let export_path = state_directory.join(QUOTA_EXPORT_NAME);
    let contents = encode_quota_export(snapshot)?;
    let digest = sha256(&contents);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // The checked state directory supplies the protected inherited DACL.
        options.share_mode(0x0000_0003);
    }
    let mut file = options.open(&export_path)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(&state_directory)?.sync_all()?;
    Ok((contents.len(), digest))
}

fn encode_quota_export(
    snapshot: &nestlink_platform_files::upload::QuotaLedgerSnapshot,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(QUOTA_EXPORT_MAGIC);
    output.push(3);
    append_export_entry(
        &mut output,
        0,
        Some(snapshot.lock_marker.as_slice()),
        &snapshot.lock_marker_sha256,
    )?;
    append_export_entry(
        &mut output,
        1,
        snapshot.ledger.as_ref().map(|file| file.raw.as_slice()),
        snapshot
            .ledger
            .as_ref()
            .map(|file| &file.sha256)
            .unwrap_or(&EMPTY_SHA256),
    )?;
    append_export_entry(
        &mut output,
        2,
        snapshot.pending.as_ref().map(|file| file.raw.as_slice()),
        snapshot
            .pending
            .as_ref()
            .map(|file| &file.sha256)
            .unwrap_or(&EMPTY_SHA256),
    )?;
    let envelope_hash = sha256(&output);
    output.extend_from_slice(&envelope_hash);
    Ok(output)
}

const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

fn append_export_entry(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<&[u8]>,
    expected_sha256: &[u8; 32],
) -> io::Result<()> {
    let raw = value.unwrap_or(&[]);
    if &sha256(raw) != expected_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quota snapshot hash mismatch",
        ));
    }
    let length = u32::try_from(raw.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "quota snapshot is too large"))?;
    output.push(tag);
    output.push(u8::from(value.is_some()));
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(raw);
    output.extend_from_slice(expected_sha256);
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn identity(
    directory: &Path,
) -> Result<nestlink_sdk::DeviceIdentity, Box<dyn std::error::Error + Send + Sync>> {
    use nestlink_platform_security::{create_key, create_private, load_key, read_private};
    let manifest = directory.join("installation-device.json");
    let key_path = directory.join("installation-device.key");
    if manifest.try_exists()? {
        let data = read_private(&manifest, 1024)?;
        let saved: Installation = serde_json::from_slice(&data)?;
        let mut seed = load_key(&key_path)?;
        let identity = nestlink_identity::InstallationIdentity::from_seed_zeroizing(&mut seed);
        if saved.schema_version != 1
            || !nestlink_protocol::valid_id(&saved.device_id)
            || saved.public_key_sha256 != identity.fingerprint()
        {
            return Err(io::Error::other("installation identity record invalid").into());
        }
        return Ok(nestlink_sdk::DeviceIdentity {
            device_id: saved.device_id,
            identity,
        });
    }
    let mut seed = match load_key(&key_path) {
        Ok(seed) => seed,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let seed = zeroize::Zeroizing::new(nestlink_auth::random_bytes::<32>());
            create_key(&key_path, &seed)?;
            seed
        }
        Err(error) => return Err(error.into()),
    };
    let identity = nestlink_identity::InstallationIdentity::from_seed_zeroizing(&mut seed);
    let device_id = nestlink_auth::random_id();
    create_private(
        &manifest,
        &serde_json::to_vec(&Installation {
            schema_version: 1,
            device_id: device_id.clone(),
            public_key_sha256: identity.fingerprint(),
        })?,
    )?;
    Ok(nestlink_sdk::DeviceIdentity {
        device_id,
        identity,
    })
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        // No command/action/HTTP response or key bytes are logged.
        eprintln!("NestLink user daemon stopped: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    match args.command {
        Some(Command::SpaceDns(command)) => return space_dns::run(command).await,
        Some(Command::PrivateServiceProxy(command)) => {
            return private_service_proxy::run(command).await;
        }
        Some(Command::SpaceDnsSystem(command)) => return space_dns_system::run(command).await,
        Some(Command::FileQuota(command)) => return Ok(run_file_quota(command)?),
        Some(Command::Maintenance(command)) => return maintenance::run(command).await,
        Some(Command::Shutdown(command)) => return maintenance::shutdown(command).await,
        Some(Command::RetainedInstances { state_root }) => {
            let startup = nestlink_local_ipc::maintenance::InstallationStartup::acquire(
                &std::env::current_exe()?,
            )?;
            let active = startup.active_instance_id()?;
            let retained =
                nestlink_local_ipc::instance::retained_instances(&state_root, active.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&retained)?);
            return Ok(());
        }
        None => {}
    }
    let state_dir = args
        .state_dir
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--state-dir is required"))?;
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("the user daemon must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    let install_start =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let state_dir = install_start.state_directory(&state_dir)?;
    let server = LocalServer::bind(&state_dir).await?;
    drop(install_start);
    // Open durable quota before accepting product operations. The IPC state
    // owner already proved this is our private directory and holds singleton
    // admission; the quota keeps its own stable OS lock across ledger replaces.
    let quota_directory = state_dir.canonicalize()?;
    let write_quota = Arc::new(
        tokio::task::spawn_blocking(move || {
            nestlink_platform_files::upload::WriteQuota::open_private_ledger(
                &quota_directory,
                nestlink_protocol::FILE_SIZE_BYTES,
                nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64,
            )
        })
        .await??,
    );
    let recovery_directory = state_dir.canonicalize()?;
    let download_recovery = tokio::task::spawn_blocking(move || {
        nestlink_platform_files::download::recovery::DownloadRecoveryStore::open(
            &recovery_directory,
            nestlink_protocol::FILE_SIZE_BYTES,
            nestlink_protocol::file_recovery::DOWNLOAD_RECOVERY_TASKS,
        )
    })
    .await??;
    let file_roots = Arc::new(native_files::RootBudget::new(
        nestlink_protocol::FILE_READ_ROOTS,
        nestlink_protocol::FILE_WRITE_ROOTS,
    ));
    let network = Arc::new(nestlink_sdk::NetworkMonitor::start()?);
    let browser_data_registry = Arc::new(browser_data::BrowserHostDataRegistry::default());
    let mut native = nestlink_app_core::NativeSessionConfig::new(network);
    if let Some(target) = args.native_media_target {
        native = native.with_cpu_media_target(target)?;
    }
    if let Some(path) = args.internal_software_media_candidate {
        let bytes = nestlink_platform_security::read_private(&path, 16 * 1024)?;
        let policy = serde_json::from_slice(&bytes)?;
        native = native.with_internal_software_media_candidate(policy)?;
    }
    native.listen_for_native_requests = true;
    native.bind_address = args.native_bind;
    native.stun_servers = args.stun_servers;
    let network_store = Arc::new(NativeNetworkFileStore::open(&state_dir)?);
    // An explicit operator argument can add consent, while ordinary UI startup
    // must preserve saved settings instead of replacing them with an empty list.
    if !args.private_network_prefixes.is_empty()
        || args.native_route_set.is_some()
        || args.disable_native_route_set
        || args.native_space_path.is_some()
        || args.disable_native_space_path
    {
        let mut settings = network_store.load()?;
        if args.disable_native_route_set {
            settings.route_set = None;
        }
        if args.disable_native_space_path { settings.space_path = None; }
        if let Some(path) = args.native_space_path {
            let bytes = nestlink_platform_security::read_private(&path, 8192)?;
            let scope: nestlink_app_core::NativeSpacePathSettings = serde_json::from_slice(&bytes)?;
            scope.validate()?;
            settings.route_set = None;
            settings.space_path = Some(scope);
        }
        if let Some(path) = args.native_route_set {
            let bytes = nestlink_platform_security::read_private(&path, 8192)?;
            let route: nestlink_app_core::NativeRouteSetSettings = serde_json::from_slice(&bytes)?;
            route.validate()?;
            settings.space_path = None;
            settings.route_set = Some(route);
        }
        for prefix in args.private_network_prefixes {
            if !settings.private_network_prefixes.contains(&prefix) {
                settings.private_network_prefixes.push(prefix);
            }
        }
        settings.validate()?;
        network_store.save(&settings)?;
    }
    native = native.with_network_settings_store(network_store)?;
    let privileged_input = privileged_input::PrivilegedInput::new();
    native = native.with_browser_host(
        capture::browser_host_config(browser_data_registry.clone(), privileged_input.clone())
            .with_diagnostics(diagnostics::browser_host_sink(state_dir.clone())),
    );
    let login_store = Arc::new(session_store::SessionStore::new(state_dir.clone()));
    let recovered = login_store.restore().await;
    native.management_login_store = Some(login_store);
    if recovered.is_some() {
        native.listen_for_native_requests = false;
    }
    let mut core = AppCore::with_restored_identity_and_native_session(
        Limits::default(),
        identity(&state_dir)?,
        native,
        recovered,
    )?;
    let _native_clipboard = native_clipboard::install(&core.handle())?;
    let native_files = Arc::new(native_files::LocalFiles::new(
        core.handle(),
        file_roots.clone(),
        write_quota.clone(),
        download_recovery,
    ));
    let browser_data = Arc::new(browser_data::LocalBrowserHostData::new(
        core.handle(),
        browser_data_registry,
        file_roots,
        write_quota,
    ));
    let mut privileged_task = privileged_input.spawn_monitor(core.handle());
    #[cfg(windows)]
    let mut native_gpu_diagnostics = native_gpu_diagnostics::Recorder::new(state_dir.clone());
    #[cfg(windows)]
    let mut native_gpu_tick = tokio::time::interval(Duration::from_secs(1));
    let mut native_capture = native_video::spawn_native_video_capture(
        core.handle(),
        _native_clipboard.clone(),
        privileged_input.clone(),
    );
    let mut native_audio = native_audio::spawn_native_audio(core.handle());
    let (exit, mut requests) = mpsc::channel::<ExitRequest>(1);
    let mut clients = JoinSet::new();
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let mut cleanup_confirmed = false;
    let mut service_error = None;
    let mut capture_stop_requested = false;
    loop {
        // Completed TLS/client tasks count against the task set until reaped.
        // Reap before biased accept so an invalid-handshake flood cannot retain
        // an unbounded list of already finished tasks.
        while clients.try_join_next().is_some() {}
        tokio::select! {
            biased;
            _ = &mut signal => {
                native_capture.request_stop();
                native_audio.request_stop();
                core.handle().clear_native_video_stream();
                break;
            },
            Some(request) = requests.recv() => {
                capture_stop_requested = true;
                native_capture.request_stop();
                native_audio.request_stop();
                privileged_task.request_stop();
                core.handle().clear_native_video_stream();
                let mut result = match core.shutdown(Duration::from_secs(18)).await {
                    ShutdownState::Complete => ExitResult::Complete,
                    ShutdownState::Pending => ExitResult::Pending,
                    ShutdownState::Failed => ExitResult::Failed,
                };
                if result == ExitResult::Complete {
                    result = match tokio::time::timeout(Duration::from_secs(3), privileged_task.join()).await {
                        Ok(Ok(())) => ExitResult::Complete,
                        Ok(Err(_)) => ExitResult::Failed,
                        Err(_) => ExitResult::Pending,
                    };
                }
                cleanup_confirmed = result == ExitResult::Complete;
                let _ = request.reply.send(result);
                let _ = tokio::time::timeout(Duration::from_secs(1), request.delivered).await;
                if cleanup_confirmed { break; }
            },
            result = native_capture.wait(), if !capture_stop_requested => {
                service_error = Some(result.err().unwrap_or_else(|| {
                    io::Error::other("native capture actor exited before daemon shutdown")
                }));
                native_capture.request_stop();
                native_audio.request_stop();
                core.handle().clear_native_video_stream();
                break;
            },
            result = native_audio.wait(), if !capture_stop_requested => {
                service_error = Some(result.err().unwrap_or_else(|| {
                    io::Error::other("native audio actor exited before daemon shutdown")
                }));
                native_capture.request_stop();
                native_audio.request_stop();
                core.handle().clear_native_video_stream();
                break;
            },
            _ = async {
                #[cfg(windows)] { native_gpu_tick.tick().await; }
                #[cfg(not(windows))] std::future::pending::<()>().await;
            } => {
                #[cfg(windows)] native_gpu_diagnostics.flush(false).await;
            },
            accepted = server.accept() => {
                match accepted {
                    Ok(pending) => {
                        let core = core.handle();
                        let exit = exit.clone();
                        let files = native_files.clone();
                        let browser_data = browser_data.clone();
                        let privileged_input = privileged_input.clone();
                        clients.spawn(async move {
                            if let Ok(connection) = pending.authenticate().await {
                                let _ = nestlink_app_ipc::serve_with_local_handlers(connection, core, exit, Some(files), Some(browser_data), Some(privileged_input)).await;
                            }
                        });
                    }
                    Err(nestlink_local_ipc::Error::Protocol | nestlink_local_ipc::Error::Authentication) => {},
                    Err(error) => {
                        native_capture.request_stop();
                        native_audio.request_stop();
                        core.handle().clear_native_video_stream();
                        service_error = Some(io::Error::other(error));
                        break;
                    },
                }
            },
            Some(_) = clients.join_next(), if !clients.is_empty() => {},
        }
    }
    native_capture.request_stop();
    native_audio.request_stop();
    privileged_task.request_stop();
    core.handle().clear_native_video_stream();
    if !cleanup_confirmed {
        cleanup_confirmed = core.shutdown(Duration::from_secs(18)).await == ShutdownState::Complete;
    }
    server.stop();
    let drained = async { while clients.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(2), drained)
        .await
        .is_err()
    {
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    }
    // Do not detach a blocking screen capture worker. AppCore first closes its
    // lease (which performs bounded platform cleanup), then the actor joins its
    // worker and returns only after the capture controller has been dropped.
    if let Err(error) = native_capture.join().await {
        cleanup_confirmed = false;
        service_error.get_or_insert(error);
    }
    #[cfg(windows)]
    native_gpu_diagnostics.flush(true).await;
    #[cfg(windows)]
    if native_gpu_diagnostics.write_failed() {
        eprintln!("native_gpu_diagnostics_write_failed=true durability=unknown");
    }
    if let Err(error) = native_audio.join().await {
        cleanup_confirmed = false;
        service_error.get_or_insert(error);
    }
    if let Err(error) = privileged_task.join().await {
        cleanup_confirmed = false;
        service_error.get_or_insert(error);
    }
    if let Some(error) = service_error {
        return Err(error.into());
    }
    if cleanup_confirmed {
        Ok(())
    } else {
        Err(
            io::Error::other("user daemon cleanup did not confirm completion within its budget")
                .into(),
        )
    }
}

fn parse_native_media_target(value: &str) -> Result<nestlink_media_codec::VideoConfig, String> {
    let (size, rate) = value
        .split_once('@')
        .ok_or("expected WIDTHxHEIGHT@FPS:KBPS")?;
    let (width, height) = size.split_once('x').ok_or("expected WIDTHxHEIGHT")?;
    let (fps, kbps) = rate.split_once(':').ok_or("expected FPS:KBPS")?;
    let parse = |part: &str| {
        part.parse::<u32>()
            .map_err(|_| "target values must be unsigned integers".to_owned())
    };
    let target = nestlink_media_codec::VideoConfig {
        width: parse(width)?,
        height: parse(height)?,
        fps: parse(fps)?,
        bitrate_kbps: parse(kbps)?,
    };
    nestlink_app_core::NativeMediaProvider::cpu_software(target).map_err(|e| e.to_string())?;
    Ok(target)
}

#[cfg(test)]
mod quota_cli_tests {
    use super::*;
    use nestlink_platform_files::upload::{QuotaLedgerFileSnapshot, QuotaLedgerSnapshot};

    fn private_state() -> io::Result<(tempfile::TempDir, PathBuf)> {
        let owner = tempfile::tempdir()?;
        let state = owner.path().join("private-state");
        nestlink_platform_security::new_private_directory(&state)?;
        Ok((owner, state))
    }

    #[test]
    fn export_is_private_create_new_and_contains_raw_hashes() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let marker = b"NLWQLOCK".to_vec();
        let raw = b"ledger metadata only".to_vec();
        let snapshot = QuotaLedgerSnapshot {
            lock_marker_sha256: sha256(&marker),
            lock_marker: marker,
            lock_marker_valid: true,
            ledger: Some(QuotaLedgerFileSnapshot {
                sha256: sha256(&raw),
                raw: raw.clone(),
            }),
            pending: None,
        };
        let (written, archive_hash) = write_quota_export(&state, &snapshot)?;
        let exported = fs::read(state.join(QUOTA_EXPORT_NAME))?;
        assert_eq!(written, exported.len());
        assert_eq!(archive_hash, sha256(&exported));
        assert!(exported.starts_with(QUOTA_EXPORT_MAGIC));
        assert!(
            exported
                .windows(raw.len())
                .any(|window| window == raw.as_slice())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(state.join(QUOTA_EXPORT_NAME))?
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        assert_eq!(
            write_quota_export(&state, &snapshot)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(state.join(QUOTA_EXPORT_NAME))?, exported);
        Ok(())
    }

    #[test]
    fn inspection_summary_omits_raw_metadata() -> io::Result<()> {
        let raw = b"private raw ledger marker".to_vec();
        let snapshot = QuotaLedgerSnapshot {
            lock_marker_sha256: sha256(&raw),
            lock_marker: raw.clone(),
            lock_marker_valid: false,
            ledger: Some(QuotaLedgerFileSnapshot {
                sha256: sha256(&raw),
                raw: raw.clone(),
            }),
            pending: None,
        };
        let output = serde_json::to_string(&inspection_summary(&snapshot))
            .map_err(|_| io::Error::other("summary serialization failed"))?;
        assert!(!output.contains("private raw ledger marker"));
        assert!(output.contains(&lower_hex(&sha256(&raw))));
        Ok(())
    }

    #[test]
    fn export_uses_one_fixed_name_inside_the_explicit_state_directory() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let snapshot = QuotaLedgerSnapshot {
            lock_marker: Vec::new(),
            lock_marker_valid: true,
            lock_marker_sha256: sha256(&[]),
            ledger: None,
            pending: None,
        };
        let first = write_quota_export(&state, &snapshot)?;
        assert_eq!(
            write_quota_export(&state, &snapshot)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert!(state.join(QUOTA_EXPORT_NAME).is_file());
        assert_eq!(
            first.0,
            fs::metadata(state.join(QUOTA_EXPORT_NAME))?.len() as usize
        );
        Ok(())
    }
}
