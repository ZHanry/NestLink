//! One resident local chooser, process nonce and original offline carrier owner.
//! JSON is an interaction format; signed authority and target consent are never
//! restored from a file, command line, IPC caller or another process.
use super::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::offline::{OfflineProcess, OfflineProcessStop};
use nestlink_protocol::{offline::management::*, services::private::*};
use nestlink_sdk::{
    DeviceIdentity, Sdk,
    services::{
        LocalServiceTargetConsent,
        offline::{OfflinePrivateRuntime, OfflinePrivateWait},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod target;
#[cfg(test)]
mod tests;
use target::{PendingTarget, TargetReview};

#[derive(Clone, Copy, PartialEq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Source,
    Host,
}
impl Role {
    fn endpoint(self) -> u8 {
        if self == Self::Source { 0 } else { 1 }
    }
}
#[derive(clap::Args)]
pub(super) struct OfflineArgs {
    #[arg(long)]
    space: String,
    #[arg(long, value_enum)]
    role: Role,
    /// Direct host QUIC UDP endpoint; required for the source role.
    #[arg(long)]
    peer: Option<SocketAddr>,
    /// Host's direct QUIC UDP listener; port zero chooses a free port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Existing owner-private directory for the source native endpoint. Unix
    /// socket path limits may require a shorter directory than --state-dir.
    #[arg(long)]
    endpoint_dir: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Help,
    Policy,
    Enable {
        expected_revision: u64,
        enabled: bool,
    },
    Service {
        service_id: String,
    },
    TargetReview(TargetReview),
    TargetApprove {
        target_digest: String,
    },
    Grant {
        service_id: String,
        request: PrivateServiceAclUpdate,
    },
    Begin,
    Draft {
        request: OfflinePrivateDraftRequest,
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
    Status,
    Recover,
    Revoke {
        bundle_id: String,
    },
    Stop,
}
fn emit(event: &str, value: impl Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(
        &mut output,
        &serde_json::json!({"event":event,"data":value}),
    )?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn identity_snapshot(directory: &std::path::Path) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(nestlink_platform_security::read_private(
        &directory.join("installation-device.json"),
        16384,
    )?)
    .into())
}
struct LocalGuard {
    stopped: Arc<AtomicBool>,
    process: Arc<Mutex<Option<OfflineProcessStop>>>,
    task: tokio::task::JoinHandle<()>,
}
impl LocalGuard {
    fn new(directory: PathBuf, login: [u8; 32]) -> Result<Self> {
        let identity = identity_snapshot(&directory)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let process: Arc<Mutex<Option<OfflineProcessStop>>> = Arc::new(Mutex::new(None));
        let (cancelled, stopper) = (stopped.clone(), process.clone());
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tick.tick().await;
                if crate::space_dns::session_snapshot(&directory).ok() != Some(login)
                    || identity_snapshot(&directory).ok() != Some(identity)
                    || nestlink_local_ipc::maintenance::requested(&directory).ok() != Some(false)
                {
                    cancelled.store(true, Ordering::Release);
                    if let Ok(process) = stopper.lock() && let Some(stop) = process.as_ref() {
                        stop.stop();
                    }
                    break;
                }
            }
        });
        Ok(Self {
            stopped,
            process,
            task,
        })
    }
    fn check(&self) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            Err(invalid("local logout, identity change, maintenance or inspection failure stopped this original process").into())
        } else {
            Ok(())
        }
    }
    fn attach(&self, process: &OfflineProcess) -> Result<()> {
        *self
            .process
            .lock()
            .map_err(|_| invalid("offline lifecycle lock failed"))? = Some(process.stop_handle());
        if self.check().is_err() {
            process.stop_handle().stop();
        }
        self.check()
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Ok(process) = self.process.lock() && let Some(stop) = process.as_ref() {
            stop.stop();
        }
    }
}
impl Drop for LocalGuard {
    fn drop(&mut self) {
        self.stop();
        self.task.abort();
    }
}
fn input() -> tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>> {
    let (send, receive) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        let mut reader = io::BufReader::new(io::stdin());
        loop {
            let mut line = Vec::new();
            let result = reader.by_ref().take(65537).read_until(b'\n', &mut line);
            match result {
                Ok(0) => break,
                Ok(_) if line.len() > 65536 => {
                    let _ = send.blocking_send(Err(invalid("offline command exceeds 65536 bytes")));
                    break;
                }
                Ok(_) => {
                    if send.blocking_send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = send.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    receive
}
struct Resident {
    args: OfflineArgs,
    sdk: Arc<Sdk>,
    identity: Arc<DeviceIdentity>,
    directory: PathBuf,
    guard: LocalGuard,
    authority: [u8; 32],
    process: Option<OfflineProcess>,
    pending_target: Option<PendingTarget>,
    target: Option<LocalServiceTargetConsent>,
    reviewed: Option<OfflineBundleView>,
    activation_attempted: bool,
    owner: Option<OfflinePrivateRuntime>,
}
impl Resident {
    fn process(&self) -> Result<&OfflineProcess> {
        self.process.as_ref().ok_or_else(||invalid("begin this original process after target/ACL preparation, then exchange its fresh nonce").into())
    }
    fn available(&self) -> Result<()> {
        if self.activation_attempted {
            Err(invalid("this resident has already attempted one-use activation; stop it and prepare a new bundle in a new resident").into())
        } else {
            Ok(())
        }
    }
    fn selected(&self, hash: [u8; 32]) -> Result<OfflineBundleView> {
        let view = self
            .reviewed
            .as_ref()
            .ok_or_else(|| invalid("review the complete bundle before approval or activation"))?;
        if hash != view.draft_digest {
            return Err(invalid(
                "explicit approved digest differs from this resident's complete reviewed draft",
            )
            .into());
        }
        Ok(view.clone())
    }
    fn check_review(&self, view: &OfflineBundleView) -> Result<()> {
        let member = &view.claims.members[usize::from(self.args.role.endpoint())];
        if view.claims.space_id != self.args.space
            || view.authority_public_key != self.authority
            || member.installation_id != self.identity.device_id
            || member.public_key != self.identity.identity.public_key()
            || member.process_nonce != self.process()?.nonce()
            || nestlink_identity::offline::offline_draft_digest(&self.authority, &view.claims)?
                != view.draft_digest
        {
            return Err(invalid(
                "bundle differs from this exact space, device, process or authority",
            )
            .into());
        }
        Ok(())
    }
    async fn command(&mut self, command: Command) -> Result<bool> {
        self.guard.check()?;
        match command {
            Command::Help => emit(
                "help",
                serde_json::json!({"commands":["policy","enable","service","target_review","target_approve","grant","begin","draft","review","approve","activate","status","recover","revoke","stop"],"guide":"docs/network-rewrite/offline-private-cli.md","label":"离线仅直连","maximum_command_bytes":65536}),
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
            Command::Service { service_id } => emit(
                "service",
                serde_json::json!({"service":self.sdk.service(&service_id).await?,"exposure":self.sdk.service_exposure(&service_id).await?}),
            )?,
            Command::TargetReview(request) => {
                self.available()?;
                if self.args.role != Role::Host {
                    return Err(invalid("only the original host can choose a local target").into());
                }
                self.pending_target = Some(
                    PendingTarget::review(&self.sdk, &self.identity, &self.args.space, request)
                        .await?,
                );
                emit(
                    "target_review",
                    self.pending_target
                        .as_ref()
                        .ok_or_else(|| invalid("target review missing"))?
                        .view(),
                )?;
            }
            Command::TargetApprove { target_digest } => {
                self.available()?;
                let pending = self
                    .pending_target
                    .take()
                    .ok_or_else(|| invalid("review the fixed local target first"))?;
                if pending.digest() != target_digest {
                    self.pending_target = Some(pending);
                    return Err(invalid(
                        "explicit target digest differs from the complete local review",
                    )
                    .into());
                }
                self.target = Some(
                    pending
                        .approve(&self.sdk, &self.identity, &self.args.space, &self.guard)
                        .await?,
                );
            }
            Command::Grant {
                service_id,
                request,
            } => {
                self.available()?;
                emit(
                    "consumer_acl",
                    self.sdk.grant_private_service(&service_id, request).await?,
                )?;
            }
            Command::Begin => {
                self.available()?;
                if self.process.is_some() {
                    return Err(
                        invalid("this resident already has its original process nonce").into(),
                    );
                }
                let policy = self.sdk.offline_policy(&self.args.space).await?;
                if !policy.enabled {
                    return Err(invalid(
                        "the space administrator must explicitly enable finite offline authority",
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
                    serde_json::json!({"device_id":self.identity.device_id,"endpoint":self.args.role.endpoint(),"process_nonce":process.nonce(),"highest_revocation_epoch":policy.highest_revocation_epoch,"label":"离线仅直连","restore_supported":false}),
                )?;
                self.process = Some(process);
            }
            Command::Draft { request } => {
                self.available()?;
                if request.process_nonces[usize::from(self.args.role.endpoint())]
                    != self.process()?.nonce()
                {
                    return Err(invalid("draft must bind this original process nonce").into());
                }
                emit(
                    "draft",
                    self.sdk
                        .create_offline_private_draft(&self.args.space, &request)
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
                    serde_json::json!({"bundle":view,"label":"离线仅直连","revocation_delay_until_ms":view.claims.expires_at_ms,"notice":"中心失联时，中心撤销最迟在原定期限结束时生效；恢复连接后必须同步最新状态。额度在双方批准时永久预留，不根据客户端报告退款。"}),
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
                if self.args.role == Role::Host && self.target.is_none() {
                    return Err(invalid("host must retain its explicitly reviewed and approved local target in this same resident").into());
                }
                let view = self
                    .sdk
                    .offline_bundle(&self.args.space, &original.claims.bundle_id)
                    .await?;
                self.check_review(&view)?;
                if view.claims != original.claims || view.draft_digest != draft_digest {
                    return Err(invalid("authority changed after local review").into());
                }
                self.activation_attempted = true;
                let consumed = self
                    .sdk
                    .activate_offline_bundle(
                        &self.identity,
                        self.process
                            .as_mut()
                            .ok_or_else(|| invalid("process missing"))?,
                        &view,
                        &self.authority,
                        self.args.role.endpoint(),
                        draft_digest,
                    )
                    .await?;
                self.guard.check()?;
                self.owner = Some(if self.args.role == Role::Host {
                    self.sdk
                        .start_offline_private_service_host(
                            self.identity.clone(),
                            consumed,
                            self.target
                                .take()
                                .ok_or_else(|| invalid("local target missing"))?,
                            self.args.listen,
                        )
                        .await?
                } else {
                    self.sdk
                        .start_offline_private_service_proxy(
                            self.identity.clone(),
                            consumed,
                            self.args
                                .peer
                                .ok_or_else(|| invalid("source needs a direct --peer endpoint"))?,
                            self.args.endpoint_dir.as_deref().unwrap_or(&self.directory),
                        )
                        .await?
                });
                self.status()?;
            }
            Command::Status => self.status()?,
            Command::Recover => {
                let owner = self
                    .owner
                    .as_ref()
                    .ok_or_else(|| invalid("activate the original owner first"))?;
                owner.synchronize_online(&self.sdk).await?;
                self.status()?;
            }
            Command::Revoke { bundle_id } => {
                emit(
                    "revoked",
                    self.sdk
                        .revoke_offline_bundle(&self.args.space, &bundle_id)
                        .await?,
                )?;
                if let Some(owner) = &self.owner && owner.status().is_ok_and(|status| status.bundle_id == bundle_id) {
                    owner.stop();
                }
            }
            Command::Stop => return Ok(true),
        }
        self.guard.check()?;
        Ok(false)
    }
    fn status(&self) -> Result<()> {
        match &self.owner {
            Some(owner) => emit(
                "status",
                serde_json::json!({"label":"离线仅直连","status":owner.status()?,"direct_address":owner.address(),"native_endpoint":owner.endpoint()}),
            ),
            None => emit(
                "status",
                serde_json::json!({"label":"离线仅直连","active":false,"role":self.args.role,"process_started":self.process.is_some(),"activation_attempted":self.activation_attempted}),
            ),
        }
    }
    async fn cleanup(&mut self) -> Result<()> {
        self.guard.stop();
        if let Some(owner) = self.owner.as_mut() {
            loop {
                match owner.wait_stopped(Duration::from_secs(5)).await {
                    OfflinePrivateWait::CleanupPending => emit("cleanup_pending", owner.status()?)?,
                    OfflinePrivateWait::Stopped(report) => {
                        emit("stopped", report)?;
                        break;
                    }
                    OfflinePrivateWait::CleanupFailed(report) => {
                        emit("cleanup_failed", report)?;
                        return Err(invalid(
                            "original offline carrier cleanup failed; inspect its exact receipt",
                        )
                        .into());
                    }
                }
            }
        }
        Ok(())
    }
}
pub(super) async fn run(
    args: OfflineArgs,
    sdk: Arc<Sdk>,
    identity: Arc<DeviceIdentity>,
    directory: PathBuf,
    original_login: [u8; 32],
) -> Result<()> {
    if !nestlink_protocol::valid_id(&args.space) || args.role == Role::Source && args.peer.is_none()
    {
        return Err(invalid(
            "choose a valid space and, for the source, its explicit direct --peer endpoint",
        )
        .into());
    }
    let policy = sdk.network_policy(&args.space).await?;
    let authority = URL_SAFE_NO_PAD
        .decode(policy.authority_public_key)?
        .try_into()
        .map_err(|_| invalid("network authority key length"))?;
    let guard = LocalGuard::new(directory.clone(), original_login)?;
    let mut resident = Resident {
        args,
        sdk,
        identity,
        directory,
        guard,
        authority,
        process: None,
        pending_target: None,
        target: None,
        reviewed: None,
        activation_attempted: false,
        owner: None,
    };
    emit(
        "ready",
        serde_json::json!({"label":"离线仅直连","role":resident.args.role,"device_id":resident.identity.device_id,"space_id":resident.args.space,"guide":"docs/network-rewrite/offline-private-cli.md","notice":"Use help. Prepare the fixed host target and explicit ACL before begin. Keep both original residents alive; no authority can be restored after exit."}),
    )?;
    let mut commands = input();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut operation = Ok(());
    loop {
        tokio::select! {biased;
            result=&mut signal=>{operation=result.map_err(Into::into);break;},
            _=tick.tick()=>{
                if let Err(error)=resident.guard.check() {operation=Err(error);break;}
                if let Some(owner)=&resident.owner && owner.is_finished() {resident.status()?;break;}
            },
            line=commands.recv()=>{
                let Some(line)=line else {break;};
                let line=match line {Ok(line)=>line,Err(error)=>{operation=Err(error.into());break;}};
                match serde_json::from_slice::<Command>(&line) {
                    Ok(command)=>match resident.command(command).await {Ok(true)=>break,Ok(false)=>{},Err(error)=>emit("command_failed",error.to_string())?},
                    Err(error)=>emit("command_failed",error.to_string())?,
                }
            },
        }
    }
    resident.cleanup().await?;
    operation
}
