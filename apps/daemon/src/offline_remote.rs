//! Resident online review/consume and independent offline native data owner.
//! Authority stays in this process; the desktop uses the existing local IPC.
use crate::offline_resident::{LocalGuard, Result, emit, input};
use nestlink_app_core::{
    Limits, NativeOfflineRemote, NativeOfflineSession, NativeOfflineTransport, NativeSessionStatus,
    ShutdownState,
};
use nestlink_identity::{VerifiedPermit, offline::OfflineProcess};
use nestlink_protocol::{
    Permission,
    offline::{OfflineBusiness, management::*},
};
use nestlink_sdk::{DeviceIdentity, Sdk};
use nestlink_session::{EndpointRole, SessionBinding};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Copy, PartialEq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Controller,
    Host,
}
impl Role {
    fn endpoint(self) -> u8 {
        if self == Self::Controller { 0 } else { 1 }
    }
    fn role(self) -> EndpointRole {
        if self == Self::Controller {
            EndpointRole::Controller
        } else {
            EndpointRole::Host
        }
    }
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum Transport {
    Quic,
    Tls,
}
impl Transport {
    fn native(self) -> NativeOfflineTransport {
        match self {
            Self::Quic => NativeOfflineTransport::Quic,
            Self::Tls => NativeOfflineTransport::Tls,
        }
    }
}
#[derive(clap::Args)]
pub(crate) struct OfflineRemoteArgs {
    /// Existing registered installation with protected login recovery enabled.
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    space: String,
    /// Existing trusted direct remote session; this command cannot approve it.
    #[arg(long)]
    session: String,
    #[arg(long, value_enum)]
    role: Role,
    /// Explicit signed direct carrier; there is no fallback to another carrier.
    #[arg(long, value_enum)]
    transport: Transport,
    #[arg(long, required_if_eq("role", "controller"))]
    peer: Option<SocketAddr>,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Help,
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Policy,
    Enable {
        expected_revision: u64,
        enabled: bool,
    },
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Begin,
    Draft {
        request: OfflineRemoteDraftRequest,
    },
    Review {
        bundle_id: String,
    },
    Approve {
        draft_digest: [u8; 32],
    },
    Activate {
        draft_digest: [u8; 32],
    },
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Start,
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Rebuild,
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Status,
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Recover,
    Revoke {
        bundle_id: String,
    },
    #[serde(deserialize_with = "crate::offline_resident::empty_command")]
    Stop,
}
impl Command {
    fn synchronizes_management(&self) -> bool {
        matches!(
            self,
            Self::Policy | Self::Enable { .. } | Self::Recover | Self::Revoke { .. }
        )
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

struct Resident {
    args: OfflineRemoteArgs,
    sdk: Arc<Sdk>,
    identity: Arc<DeviceIdentity>,
    directory: PathBuf,
    guard: LocalGuard,
    authority: [u8; 32],
    original: VerifiedPermit,
    process: Option<OfflineProcess>,
    reviewed: Option<OfflineBundleView>,
    activation_attempted: bool,
    owner: Option<NativeOfflineRemote>,
    establishing: Option<
        JoinHandle<
            std::result::Result<NativeOfflineSession, nestlink_app_core::NativeOfflineError>,
        >,
    >,
    session: Option<NativeOfflineSession>,
    products: Option<LocalProducts>,
    retired: bool,
    file_stores: Option<Arc<LocalFileStores>>,
}
impl Resident {
    fn process(&self) -> Result<&OfflineProcess> {
        self.process.as_ref().ok_or_else(|| {
            invalid("begin this original resident before exchanging its process nonce").into()
        })
    }
    fn available(&self) -> Result<()> {
        if self.activation_attempted {
            Err(
                invalid("one-use activation was already attempted in this original resident")
                    .into(),
            )
        } else {
            Ok(())
        }
    }
    fn check_review(&self, view: &OfflineBundleView) -> Result<()> {
        let claims = self.original.claims();
        let member = &view.claims.members[usize::from(self.args.role.endpoint())];
        let exact_business = matches!(&view.claims.business,
            OfflineBusiness::RemoteControl { resource_id, capability_digest, .. }
            if resource_id == &claims.resource_id && capability_digest.as_slice() == claims.capability_sha256);
        if !exact_business
            || !view.live
            || view.claims.space_id != self.args.space
            || view.authority_public_key != self.authority
            || view.claims.deployment_id != claims.deployment_id
            || view.claims.security_epoch != claims.security_epoch
            || view.claims.members[0].installation_id != claims.controller_device_id
            || view.claims.members[1].installation_id != claims.host_device_id
            || nestlink_identity::digest(&view.claims.members[0].public_key).as_slice()
                != claims.controller_key_sha256
            || nestlink_identity::digest(&view.claims.members[1].public_key).as_slice()
                != claims.host_key_sha256
            || member.installation_id != self.identity.device_id
            || member.public_key != self.identity.identity.public_key()
            || member.process_nonce != self.process()?.nonce()
            || nestlink_identity::offline::offline_draft_digest(&self.authority, &view.claims)?
                != view.draft_digest
        {
            return Err(invalid("bundle differs from this original remote scope, device, process or pinned authority").into());
        }
        Ok(())
    }
    fn selected(&self, hash: [u8; 32]) -> Result<OfflineBundleView> {
        let view = self
            .reviewed
            .as_ref()
            .ok_or_else(|| invalid("review the complete current bundle first"))?;
        if view.draft_digest != hash {
            return Err(invalid("explicit digest differs from the complete local review").into());
        }
        self.check_review(view)?;
        Ok(view.clone())
    }
    fn binding(&self) -> Result<SessionBinding> {
        let c = self.original.claims();
        if nestlink_protocol::media_authority::permit_formats(c)?.is_some() {
            return Err(invalid("this resident requires the ordinary VP8/H264 remote scope; exact media scopes require their original live execution binding").into());
        }
        Ok(SessionBinding {
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            session_id: c.session_id.clone(),
            account_id: c.account_id.clone(),
            controller_device_id: c.controller_device_id.clone(),
            host_device_id: c.host_device_id.clone(),
            controller_key_sha256: c.controller_key_sha256.as_slice().try_into()?,
            host_key_sha256: c.host_key_sha256.as_slice().try_into()?,
            resource_id: c.resource_id.clone(),
            policy_revision: c.policy_revision,
            connection_generation: c.connection_generation,
            capability_sha256: c.capability_sha256.as_slice().try_into()?,
            granted_permissions: c
                .permissions
                .iter()
                .copied()
                .map(Permission::try_from)
                .collect::<std::result::Result<_, _>>()?,
            supported_capabilities: c.required_capabilities.clone(),
            local_paths: nestlink_policy::PathSet::DIRECT,
            media: None,
        })
    }
    async fn command(&mut self, command: Command) -> Result<bool> {
        self.guard.check()?;
        if command.synchronizes_management()
            && let Some(owner) = &self.owner
        {
            // Fence the original authority before even starting the HTTP
            // request. Failed or unrelated management reads never rearm it.
            owner.stop();
        }
        match command {
            Command::Help => emit(
                "help",
                serde_json::json!({"commands":["policy","enable","begin","draft","review","approve","activate","start","rebuild","status","recover","revoke","stop"],"guide":"docs/network-rewrite/offline-remote-cli.md","label":"离线仅直连","maximum_command_bytes":65536}),
            )?,
            Command::Policy => emit("policy", self.sdk.offline_policy(&self.args.space).await?)?,
            Command::Enable {
                expected_revision,
                enabled,
            } => emit(
                "policy",
                self.sdk
                    .set_offline_enabled(
                        &self.args.space,
                        &OfflineEnableUpdate {
                            expected_revision,
                            enabled,
                        },
                    )
                    .await?,
            )?,
            Command::Begin => {
                self.available()?;
                if self.process.is_some() {
                    return Err(invalid(
                        "this resident already retains its original process nonce",
                    )
                    .into());
                }
                let policy = self.sdk.offline_policy(&self.args.space).await?;
                if !policy.enabled {
                    return Err(invalid(
                        "the space administrator must enable finite offline authority",
                    )
                    .into());
                }
                let process = OfflineProcess::new(
                    self.identity.device_id.clone(),
                    self.identity.identity.public_key(),
                    now()?,
                    policy.highest_revocation_epoch,
                )?;
                self.guard.attach(&process)?;
                emit(
                    "process",
                    serde_json::json!({"device_id":self.identity.device_id,"endpoint":self.args.role.endpoint(),"process_nonce":process.nonce(),"highest_revocation_epoch":policy.highest_revocation_epoch,"restore_supported":false}),
                )?;
                self.process = Some(process);
            }
            Command::Draft { request } => {
                self.available()?;
                if self.args.role != Role::Controller
                    || request.session_id != self.args.session
                    || request.process_nonces[0] != self.process()?.nonce()
                {
                    return Err(invalid(
                        "only the original controller can draft this exact session and process",
                    )
                    .into());
                }
                emit(
                    "draft",
                    self.sdk
                        .create_offline_remote_draft(&self.args.space, &request)
                        .await?,
                )?;
            }
            Command::Review { bundle_id } => {
                self.available()?;
                let view = self
                    .sdk
                    .offline_bundle(&self.args.space, &bundle_id)
                    .await?;
                self.check_review(&view)?;
                emit(
                    "complete_bundle_review",
                    serde_json::json!({"bundle":view,"label":"离线仅直连","revocation_delay_until_ms":view.claims.expires_at_ms,"notice":"中心失联时不能即时收到中心撤销。原期限、额度和本机停止始终有效；恢复联网先停止离线传输再同步。"}),
                )?;
                self.reviewed = Some(view);
            }
            Command::Approve { draft_digest } => {
                self.available()?;
                let view = self.selected(draft_digest)?;
                emit(
                    "approval",
                    self.sdk
                        .approve_offline_bundle(
                            &self.identity,
                            self.process()?,
                            &view,
                            &self.authority,
                            self.args.role.endpoint(),
                            draft_digest,
                        )
                        .await?,
                )?;
            }
            Command::Activate { draft_digest } => {
                self.available()?;
                let original = self.selected(draft_digest)?;
                let view = self
                    .sdk
                    .offline_bundle(&self.args.space, &original.claims.bundle_id)
                    .await?;
                self.check_review(&view)?;
                if view.claims != original.claims || view.draft_digest != draft_digest {
                    return Err(invalid("authority changed after local review").into());
                }
                let binding = self.binding()?;
                self.activation_attempted = true;
                let consumed = self
                    .sdk
                    .activate_offline_bundle(
                        &self.identity,
                        self.process
                            .as_mut()
                            .ok_or_else(|| invalid("original process missing"))?,
                        &view,
                        &self.authority,
                        self.args.role.endpoint(),
                        draft_digest,
                    )
                    .await?;
                self.guard.check()?;
                let owner = self.sdk.prepare_offline_remote(
                    self.identity.clone(),
                    consumed,
                    self.original.clone(),
                    binding,
                    self.args.role.role(),
                )?;
                self.owner = Some(NativeOfflineRemote::new(owner, Limits::default())?);
                self.status()?;
            }
            Command::Start => {
                if self.establishing.is_some() || self.session.is_some() {
                    return Err(
                        invalid("this resident already owns establishment or a session").into(),
                    );
                }
                let owner = self
                    .owner
                    .as_ref()
                    .ok_or_else(|| invalid("activate the original owner online first"))?
                    .clone();
                let transport = self.args.transport.native();
                self.retired = false;
                self.establishing = Some(if self.args.role == Role::Host {
                    let listener = owner.listen(transport, self.args.listen).await?;
                    emit(
                        "listening",
                        serde_json::json!({"address":listener.address()?,"transport":transport,"label":"离线仅直连"}),
                    )?;
                    tokio::spawn(listener.accept())
                } else {
                    let peer = self
                        .args
                        .peer
                        .ok_or_else(|| invalid("controller needs an explicit --peer endpoint"))?;
                    tokio::spawn(async move { owner.connect(transport, peer).await })
                });
            }
            Command::Rebuild => {
                self.session
                    .as_ref()
                    .ok_or_else(|| invalid("no connected original offline carrier"))?
                    .request_carrier_rebuild()?;
                emit(
                    "carrier_retiring",
                    serde_json::json!({"label":"离线仅直连","notice":"仅重建当前直连载体。等待connection_stopped后再次显式start；沿用原绝对期限和累计额度，不重新消费授权。"}),
                )?;
            }
            Command::Status => self.status()?,
            Command::Recover => {
                let owner = self
                    .owner
                    .as_ref()
                    .ok_or_else(|| invalid("activate an original owner first"))?;
                emit("online_state", owner.synchronize_online().await?)?;
            }
            Command::Revoke { bundle_id } => {
                emit(
                    "revoked",
                    self.sdk
                        .revoke_offline_bundle(&self.args.space, &bundle_id)
                        .await?,
                )?;
            }
            Command::Stop => return Ok(true),
        }
        self.guard.check()?;
        Ok(false)
    }
    fn status(&self) -> Result<()> {
        if let Some(session) = &self.session {
            emit("status", session.view())
        } else if let Some(owner) = &self.owner {
            emit(
                "status",
                serde_json::json!({"label":"离线仅直连","activated":true,"establishing":self.establishing.is_some(),"budget":owner.budget()?}),
            )
        } else {
            emit(
                "status",
                serde_json::json!({"label":"离线仅直连","activated":false,"process_started":self.process.is_some(),"activation_attempted":self.activation_attempted}),
            )
        }
    }
    async fn poll_establishment(&mut self) -> Result<()> {
        if !self
            .establishing
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            return Ok(());
        }
        let result = self
            .establishing
            .take()
            .ok_or_else(|| invalid("establishment missing"))?
            .await?;
        match result {
            Ok(session) => {
                if let Err(error) = self.guard.check() {
                    session.request_stop();
                    self.session = Some(session);
                    return Err(error);
                }
                let owner = self
                    .owner
                    .as_ref()
                    .ok_or_else(|| invalid("original owner missing"))?
                    .clone();
                let products = async {
                    let stores = match &self.file_stores {
                        Some(stores) => stores.clone(),
                        None => {
                            let stores = Arc::new(LocalFileStores::open(&self.directory).await?);
                            self.file_stores = Some(stores.clone());
                            stores
                        }
                    };
                    LocalProducts::attach(session.handle(), stores, owner)
                }
                .await;
                let products = match products {
                    Ok(products) => products,
                    Err(error) => {
                        self.session = Some(session);
                        return Err(error);
                    }
                };
                self.products = Some(products);
                let view = session.view();
                self.session = Some(session);
                emit("connected", view)?;
            }
            Err(error) => emit("connection_failed", error.to_string())?,
        }
        Ok(())
    }
    async fn retire_session(&mut self) -> Result<()> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        let report = session.wait_stopped().await;
        let products = if let Some(products) = self.products.as_mut() {
            products.shutdown().await
        } else {
            Ok(())
        };
        let report = report?;
        products?;
        self.retired = true;
        emit("connection_stopped", &report)?;
        if report.cleanup != nestlink_app_core::NativeSessionCleanup::Succeeded
            || report.failure.is_some()
        {
            if let Some(owner) = &self.owner {
                owner.stop();
            }
            return Err(
                invalid("offline lifecycle ended without successful product cleanup").into(),
            );
        }
        if !self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.budget().map_or(true, |budget| budget.stopped))
        {
            self.session.take();
            self.products.take();
        }
        // A terminal local stop keeps its completed IPC snapshot available.
        // Only the transport ended. The original process, absolute deadline,
        // cumulative byte reservations and attempt counter remain unchanged.
        self.status()
    }
    async fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        self.guard.stop();
        if let Some(owner) = &self.owner {
            owner.stop();
        }
        if let Some(task) = self.establishing.take() {
            // Keep the original bounded establishment owner through its stop,
            // rather than detach an endpoint or start a competing carrier.
            match task.await {
                Ok(Ok(session)) => {
                    self.session = Some(session);
                }
                Ok(Err(error)) => {
                    if let Err(error) = emit("connection_stopped", error.to_string()) {
                        failures.push(error.to_string());
                    }
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        if let Some(session) = self.session.as_mut() {
            loop {
                match session.shutdown(Duration::from_secs(5)).await {
                    ShutdownState::Pending => {
                        if let Err(error) = emit("cleanup_pending", session.view()) {
                            failures.push(error.to_string());
                        }
                    }
                    ShutdownState::Complete => {
                        match session.wait_stopped().await {
                            Ok(report) => {
                                if let Err(error) = emit("stopped", report) {
                                    failures.push(error.to_string());
                                }
                            }
                            Err(error) => failures.push(error.to_string()),
                        }
                        break;
                    }
                    ShutdownState::Failed => {
                        failures.push("original offline product cleanup failed".into());
                        if let Err(error) = emit("cleanup_failed", session.view()) {
                            failures.push(error.to_string());
                        }
                        break;
                    }
                }
            }
        }
        if let Some(mut products) = self.products.take()
            && let Err(error) = products.shutdown().await
        {
            failures.push(error.to_string());
        }
        self.session.take();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")).into())
        }
    }
}

struct LocalProducts {
    files: Arc<crate::native_files::LocalFiles>,
    privileged: Arc<crate::privileged_input::PrivilegedInput>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<()>>>,
}
struct LocalFileStores {
    roots: Arc<crate::native_files::RootBudget>,
    quota: Arc<nestlink_platform_files::upload::WriteQuota>,
    recovery: Arc<nestlink_platform_files::download::recovery::DownloadRecoveryStore>,
}
impl LocalFileStores {
    async fn open(directory: &std::path::Path) -> Result<Self> {
        let area = directory.canonicalize()?;
        let quota = Arc::new(
            tokio::task::spawn_blocking(move || {
                nestlink_platform_files::upload::WriteQuota::open_private_ledger(
                    &area,
                    nestlink_protocol::FILE_SIZE_BYTES,
                    nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64,
                )
            })
            .await??,
        );
        let area = directory.canonicalize()?;
        let recovery = tokio::task::spawn_blocking(move || {
            nestlink_platform_files::download::recovery::DownloadRecoveryStore::open(
                &area,
                nestlink_protocol::FILE_SIZE_BYTES,
                nestlink_protocol::file_recovery::DOWNLOAD_RECOVERY_TASKS,
            )
        })
        .await??;
        let roots = Arc::new(crate::native_files::RootBudget::new(
            nestlink_protocol::FILE_READ_ROOTS,
            nestlink_protocol::FILE_WRITE_ROOTS,
        ));
        Ok(Self {
            roots,
            quota,
            recovery,
        })
    }
}
impl LocalProducts {
    fn attach(
        core: nestlink_app_core::CoreHandle,
        stores: Arc<LocalFileStores>,
        owner: NativeOfflineRemote,
    ) -> Result<Self> {
        let files = Arc::new(crate::native_files::LocalFiles::new(
            core.clone(),
            stores.roots.clone(),
            stores.quota.clone(),
            stores.recovery.clone(),
        ));
        let clipboard = crate::native_clipboard::install(&core)?;
        let privileged = crate::privileged_input::PrivilegedInput::new();
        let mut broker = privileged.spawn_monitor(core.clone());
        let mut capture = crate::native_video::spawn_native_video_capture(
            core.clone(),
            clipboard,
            privileged.clone(),
        );
        let mut audio = crate::native_audio::spawn_native_audio(core.clone());
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let first = tokio::select! { biased;
                _ = stopping.changed() => Ok(()),
                result = capture.wait() => result,
                result = audio.wait() => result,
            };
            if first.is_err()
                || (!*stopping.borrow()
                    && core.snapshot().lifecycle == nestlink_app_core::Lifecycle::Running)
            {
                owner.stop();
            }
            capture.request_stop();
            audio.request_stop();
            broker.request_stop();
            let capture = capture.join().await;
            let audio = audio.join().await;
            let broker = broker.join().await;
            first?;
            capture?;
            audio?;
            broker?;
            Ok(())
        });
        Ok(Self {
            files,
            privileged,
            stop,
            task: Some(task),
        })
    }
    async fn shutdown(&mut self) -> Result<()> {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for LocalProducts {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

pub(crate) async fn run(args: OfflineRemoteArgs) -> Result<()> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(invalid("offline remote must run as a normal user").into());
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    if !nestlink_protocol::valid_id(&args.space)
        || !nestlink_protocol::valid_id(&args.session)
        || args.role == Role::Controller && args.peer.is_none()
    {
        return Err(
            invalid("choose valid space/session and an explicit controller peer endpoint").into(),
        );
    }
    let installation =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = installation.state_directory(&args.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let server = nestlink_local_ipc::LocalServer::bind(&directory).await?;
    if !directory.join("installation-device.json").try_exists()? {
        return Err(invalid("enroll this installation before offline preparation").into());
    }
    let sdk = Arc::new(
        crate::session_store::SessionStore::new(directory.clone())
            .restore()
            .await
            .ok_or_else(|| {
                invalid("sign in with protected login recovery before offline preparation")
            })?,
    );
    let login = crate::space_dns::session_snapshot(&directory)?;
    let identity = Arc::new(crate::identity(&directory)?);
    let original = if args.role == Role::Host {
        sdk.host_permit(&identity, &args.session).await?
    } else {
        sdk.permit(&args.session).await?
    };
    let authority = crate::offline_resident::authority(&sdk, &args.space).await?;
    let guard = LocalGuard::new(directory.clone(), login)?;
    drop(installation);
    let mut resident = Resident {
        args,
        sdk,
        identity,
        directory,
        guard,
        authority,
        original,
        process: None,
        reviewed: None,
        activation_attempted: false,
        owner: None,
        establishing: None,
        session: None,
        products: None,
        retired: false,
        file_stores: None,
    };
    emit(
        "ready",
        serde_json::json!({"role":resident.args.role,"device_id":resident.identity.device_id,"space_id":resident.args.space,"session_id":resident.args.session,"label":"离线仅直连","guide":"docs/network-rewrite/offline-remote-cli.md","notice":"Keep both original residents alive. Use help and review complete scope before approval. After activation, use start for the explicit direct carrier. The desktop can attach to this same installation IPC after connection."}),
    )?;
    let mut commands = input();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let (exit, mut exits) = mpsc::channel::<nestlink_app_ipc::ExitRequest>(1);
    let mut clients = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut operation = Ok(());
    loop {
        while clients.try_join_next().is_some() {}
        tokio::select! { biased;
            result = &mut signal => { operation = result.map_err(Into::into); break; },
            Some(request) = exits.recv() => {
                let result = resident.cleanup().await;
                let _ = request.reply.send(if result.is_ok() { nestlink_app_ipc::wire::ExitResult::Complete } else { nestlink_app_ipc::wire::ExitResult::Failed });
                let _ = tokio::time::timeout(Duration::from_secs(1), request.delivered).await;
                operation = result; break;
            },
            _ = tick.tick() => {
                if let Err(error) = resident.guard.check() { operation = Err(error); break; }
                if let Err(error) = resident.poll_establishment().await { operation = Err(error); break; }
                if !resident.retired && resident.session.as_ref().is_some_and(|session| matches!(session.view().status, NativeSessionStatus::Stopped | NativeSessionStatus::Failed)) {
                    if let Err(error) = resident.retire_session().await { operation = Err(error); break; }
                    if resident.session.is_none() {
                        // Every old stream is bound to its original CoreHandle.
                        // Platform/input cleanup is already confirmed above;
                        // disconnect these streams so a desktop can reconnect
                        // to the rebuilt lifecycle's newer local generation.
                        clients.abort_all();
                        while clients.join_next().await.is_some() {}
                    }
                }
            },
            accepted = server.accept() => match accepted {
                Ok(pending) => {
                    if let (Some(session), Some(products)) = (&resident.session, &resident.products) {
                        let core = session.handle(); let exit = exit.clone();
                        let files = products.files.clone(); let privileged = products.privileged.clone();
                        clients.spawn(async move { if let Ok(connection) = pending.authenticate().await { let _ = nestlink_app_ipc::serve_with_local_handlers(connection, core, exit, Some(files), None, Some(privileged)).await; } });
                    }
                }
                Err(nestlink_local_ipc::Error::Protocol | nestlink_local_ipc::Error::Authentication) => {}
                Err(error) => { operation = Err(error.into()); break; }
            },
            line = commands.recv() => {
                let Some(line) = line else { break; };
                match line {
                    Ok(line) => match serde_json::from_slice::<Command>(&line) {
                        Ok(command) => match resident.command(command).await { Ok(true) => break, Ok(false) => {}, Err(error) => emit("command_failed", error.to_string())? },
                        Err(error) => emit("command_failed", error.to_string())?,
                    }
                    Err(error) => { operation = Err(error.into()); break; }
                }
            },
        }
    }
    let cleanup = resident.cleanup().await;
    server.stop();
    if tokio::time::timeout(Duration::from_secs(2), async {
        while clients.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    }
    cleanup?;
    operation
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn original_resident_entry_requires_an_explicit_direct_carrier_and_controller_peer()
    -> Result<()> {
        let arguments = [
            "nestlink-daemon",
            "offline-remote",
            "--state-dir",
            "private",
            "--space",
            "00000000-0000-4000-8000-000000000001",
            "--session",
            "00000000-0000-4000-8000-000000000002",
            "--role",
            "controller",
        ];
        assert!(crate::Args::try_parse_from(arguments).is_err());
        let explicit = arguments.into_iter().chain(["--transport", "quic"]);
        assert!(crate::Args::try_parse_from(explicit.clone()).is_err());
        let parsed = crate::Args::try_parse_from(explicit.chain(["--peer", "127.0.0.1:24123"]))?;
        assert!(matches!(
            parsed.command,
            Some(crate::Command::OfflineRemote(OfflineRemoteArgs {
                role: Role::Controller,
                transport: Transport::Quic,
                ..
            }))
        ));
        for carrier in ["relay", "wss", "auto"] {
            assert!(
                crate::Args::try_parse_from(arguments.into_iter().chain([
                    "--transport",
                    carrier,
                    "--peer",
                    "127.0.0.1:24123"
                ]))
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn original_resident_json_cannot_import_authority_or_enable_carrier_fallback() -> Result<()> {
        let mut approved = serde_json::json!({"command":"activate", "draft_digest":vec![7u8;32]});
        assert!(matches!(
            serde_json::from_value::<Command>(approved.clone())?,
            Command::Activate { .. }
        ));
        approved["online_permit"] = serde_json::json!("untrusted saved permit");
        assert!(serde_json::from_value::<Command>(approved).is_err());
        for command in [
            "help", "policy", "begin", "start", "rebuild", "status", "recover", "stop",
        ] {
            assert!(
                serde_json::from_value::<Command>(serde_json::json!({"command":command})).is_ok()
            );
            assert!(
                serde_json::from_value::<Command>(
                    serde_json::json!({"command":command,"authority":"saved transferable owner"})
                )
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<Command>(
                serde_json::json!({"command":"start", "transport":"tls"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<Command>(
                serde_json::json!({"command":"resume", "bundle":"saved authority"})
            )
            .is_err()
        );
        Ok(())
    }
}
