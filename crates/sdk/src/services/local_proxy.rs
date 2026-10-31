//! Authenticated local SOCKS entry for one explicit private service choice.
//! The component owns every SOCKS byte. This adapter never resolves a requested
//! name or dials a requested address; only the private-service SDK can connect.
use super::*;
use fast_socks5::{ReplyError, Socks5Command, server::Socks5ServerProtocol, util::target_addr::TargetAddr};
use nestlink_auth::{token, token_hash};
use nestlink_identity::services::private::VerifiedPrivateServiceLease;
use nestlink_protocol::services::private::{PrivateServiceAccessRequest, PrivateServiceAvailability, PrivateServiceEntry};
use std::{io, path::{Path, PathBuf}, sync::{Arc, OnceLock}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{net::{TcpListener, TcpStream}, sync::{Semaphore, watch}, task::{JoinHandle, JoinSet}, time::Instant};
use zeroize::Zeroizing;

const SETUP_BUDGET: Duration = Duration::from_secs(3);
const MAX_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_OWNERS: usize = 16;
const MAX_FLOWS: usize = 32;
const OWNER_FLOWS: usize = 8;
const CREDENTIAL_BYTES: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum LocalProxyError {
    #[error("invalid local private service proxy choice")]
    Invalid,
    #[error("local proxy owner limit reached")]
    Busy,
    #[error("local proxy I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("private service admission failed: {0}")]
    Admission(#[from] SdkError),
    #[error("local proxy startup retained credentials for owner recovery at {path}: {source}")]
    CredentialsRetained { path: PathBuf, source: io::Error },
}

/// A local user chooses one already approved service, alias, port, sub-reservation
/// and lifetime. This owner cannot be deserialized from a remote response or IPC.
pub struct LocalProxyServiceChoice {
    entry: PrivateServiceEntry,
    alias: String,
    port: u16,
    maximum_bytes: u64,
    lifetime: Duration,
}
impl LocalProxyServiceChoice {
    pub fn from_local_choice(entry: &PrivateServiceEntry, alias: &str, port: u16,
        maximum_bytes: u64, lifetime: Duration) -> Result<Self, LocalProxyError> {
        let service = &entry.service;
        let exposure = &entry.exposure;
        let alias = canonical_alias(alias).ok_or(LocalProxyError::Invalid)?;
        service.definition.validate().map_err(SdkError::from)?;
        let definition = nestlink_identity::services::definition_digest(&service.definition).map_err(SdkError::from)?;
        let declared = nestlink_identity::services::decode_digest(&service.definition_sha256).map_err(SdkError::from)?;
        let target = service.target_sha256.as_deref()
            .map(nestlink_identity::services::decode_digest).transpose().map_err(SdkError::from)?;
        if entry.availability != PrivateServiceAvailability::Ready
            || service.approval != ServiceApprovalState::ApprovedTarget
            || [&service.id, &service.account_id, &exposure.space_id].iter().any(|id| !valid_id(id))
            || service.target_id.as_deref().is_none_or(|id| !valid_id(id))
            || !nestlink_protocol::services::revision_valid(service.revision)
            || !nestlink_protocol::services::revision_valid(exposure.revision)
            || exposure.service_id != service.id || exposure.service_revision != service.revision
            || !exposure.mode.private_enabled() || definition != declared
            || target != Some(exposure.target_sha256) || exposure.target_sha256 == [0; 32]
            || matches!(service.definition.requested_ingress, ServiceIngress::Udp { .. })
            || maximum_bytes == 0 || maximum_bytes > service.definition.limits.maximum_bytes
            || maximum_bytes > exposure.private_maximum_bytes || port == 0
            || lifetime.is_zero() || lifetime > MAX_LIFETIME {
            return Err(LocalProxyError::Invalid);
        }
        Ok(Self { entry: entry.clone(), alias, port, maximum_bytes, lifetime })
    }

    fn accepts(&self, target: &TargetAddr) -> bool {
        matches!(target, TargetAddr::Domain(alias, port)
            if *port == self.port && canonical_alias(alias).as_deref() == Some(self.alias.as_str()))
    }

    fn checks_lease(&self, lease: &VerifiedPrivateServiceLease) -> bool {
        let base = lease.lease().claims();
        let service = &self.entry.service;
        base.service_id == service.id && base.service_revision == service.revision
            && base.account_id == service.account_id && base.definition == service.definition
            && base.target_id.as_str() == service.target_id.as_deref().unwrap_or("")
            && base.target_sha256 == self.entry.exposure.target_sha256
            && lease.claims().space_id == self.entry.exposure.space_id
            && lease.claims().exposure_revision == self.entry.exposure.revision
    }
}

fn canonical_alias(alias: &str) -> Option<String> {
    if !alias.is_ascii() || alias.len() > 253 || alias.len() <= ".nestlink.internal".len() {
        return None;
    }
    let alias = alias.to_ascii_lowercase();
    if !alias.ends_with(".nestlink.internal") || !alias.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) { return None; }
    Some(alias)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalProxyStopReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub cleanup_failures: u64,
    pub credentials_removed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProxyWait {
    /// The original owner is still joining physical resources. Waiting again
    /// observes the same task; cancellation never aborts or replaces it.
    CleanupPending,
    Stopped(LocalProxyStopReport),
    CleanupFailed(LocalProxyStopReport),
}

pub struct LocalServiceProxy {
    address: SocketAddr,
    credentials_path: PathBuf,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<LocalProxyStopReport>>,
    report: Option<LocalProxyStopReport>,
    runtime: tokio::runtime::Handle,
}
impl LocalServiceProxy {
    pub fn address(&self) -> SocketAddr { self.address }
    /// Contains credentials readable only by the selected local OS owner.
    /// Do not copy its contents into logs, URLs, diagnostics, or management IPC.
    pub fn credentials_path(&self) -> &Path { &self.credentials_path }
    /// Observe expiry/failure without requesting shutdown or replacing its task.
    pub fn is_finished(&self) -> bool { self.report.is_some() || self.task.as_ref().is_none_or(JoinHandle::is_finished) }
    pub fn request_shutdown(&self) { self.stop.send_replace(true); }
    pub async fn wait_stopped(&mut self, budget: Duration) -> LocalProxyWait {
        self.request_shutdown();
        if let Some(task) = self.task.as_mut() {
            let result = match tokio::time::timeout(budget, &mut *task).await {
                Err(_) => return LocalProxyWait::CleanupPending,
                Ok(result) => result,
            };
            self.task.take();
            self.report = Some(result.unwrap_or_else(|_| LocalProxyStopReport {
                cleanup_failures: 1, ..LocalProxyStopReport::default()
            }));
        }
        let report = self.report.clone().unwrap_or_else(|| LocalProxyStopReport {
            cleanup_failures: 1, ..LocalProxyStopReport::default()
        });
        if report.cleanup_failures == 0 && report.credentials_removed {
            LocalProxyWait::Stopped(report)
        } else { LocalProxyWait::CleanupFailed(report) }
    }
}
impl Drop for LocalServiceProxy {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() {
            self.runtime.spawn(async move { let _ = task.await; });
        }
    }
}

struct Credentials { username: Secret, password: Secret }
impl Credentials {
    fn new() -> Self { Self { username: token(), password: token() } }
    fn accepts(&self, username: String, password: String) -> bool {
        let username = Secret::from_text(username);
        let password = Secret::from_text(password);
        // Domain-separated fixed-size digests avoid comparisons of a partially
        // matching plaintext password. Both fields are always evaluated.
        (token_hash("local-proxy-username", username.expose())
            == token_hash("local-proxy-username", self.username.expose()))
            & (token_hash("local-proxy-password", password.expose())
                == token_hash("local-proxy-password", self.password.expose()))
    }
}
struct CredentialFile { path: PathBuf, original: Zeroizing<Vec<u8>> }
impl CredentialFile {
    fn remove(&self) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| io::Error::other("credential owner missing"))?;
        nestlink_platform_security::check_private_directory(parent)?;
        let current = nestlink_platform_security::read_private(&self.path, CREDENTIAL_BYTES)?;
        if *current != *self.original {
            return Err(io::Error::other("credential file changed; preserve for owner recovery"));
        }
        std::fs::remove_file(&self.path)
    }
}
fn owners() -> &'static Arc<Semaphore> {
    static OWNERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    OWNERS.get_or_init(|| Arc::new(Semaphore::new(MAX_OWNERS)))
}
fn flows() -> &'static Arc<Semaphore> {
    static FLOWS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    FLOWS.get_or_init(|| Arc::new(Semaphore::new(MAX_FLOWS)))
}

impl Sdk {
    /// Start a standard password-authenticated SOCKS5 TCP CONNECT entry for one
    /// fixed service. The caller supplies an existing protected local directory
    /// (platform-security::new_private_directory creates one) and owns shutdown.
    /// A desktop/daemon owner must request shutdown when its local session ends.
    pub async fn start_private_service_socks(self: &Arc<Self>, consumer: Arc<DeviceIdentity>,
        choice: LocalProxyServiceChoice, bind: SocketAddr, credential_directory: &Path)
        -> Result<LocalServiceProxy, LocalProxyError> {
        if !bind.ip().is_loopback() || !valid_id(&consumer.device_id) {
            return Err(LocalProxyError::Invalid);
        }
        self.principal().ok_or(SdkError::SignIn)?;
        let owner = owners().clone().try_acquire_owned().map_err(|_| LocalProxyError::Busy)?;
        nestlink_platform_security::check_private_directory(credential_directory)?;
        let deadline = Instant::now() + choice.lifetime;
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let credentials = Arc::new(Credentials::new());
        // Serialize directly into a zeroizing buffer; serde_json::Value would
        // retain additional, non-zeroizing plaintext credential Strings.
        #[derive(Serialize)]
        struct File<'a> { schema_version: u32, proxy_address: SocketAddr,
            target_alias: &'a str, target_port: u16, username: &'a str, password: &'a str }
        let original = Zeroizing::new(serde_json::to_vec(&File { schema_version: 1,
            proxy_address: address, target_alias: &choice.alias, target_port: choice.port,
            username: credentials.username.expose(), password: credentials.password.expose(),
        }).map_err(SdkError::from)?);
        let file = CredentialFile { path: credential_directory.join(format!("proxy-{}.json", random_id())), original };
        // create_new prevents replacement of another owner's credentials.
        if let Err(error) = nestlink_platform_security::create_private(&file.path, &file.original) {
            if error.kind() == io::ErrorKind::AlreadyExists { return Err(LocalProxyError::Io(error)); }
            return Err(LocalProxyError::CredentialsRetained { path: file.path.clone(), source: error });
        }
        let readback = nestlink_platform_security::read_private(&file.path, CREDENTIAL_BYTES)
            .and_then(|bytes| if *bytes == *file.original { Ok(()) }
                else { Err(io::Error::other("credential startup readback differs")) });
        if let Err(error) = readback {
            // Do not delete an unreadable/replaced file or claim cleanup.
            return Err(LocalProxyError::CredentialsRetained { path: file.path.clone(), source: error });
        }
        let credentials_path = file.path.clone();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_owner(self.clone(), consumer, Arc::new(choice), listener,
            credentials, file, stopped, deadline, owner));
        Ok(LocalServiceProxy { address, credentials_path, stop, task: Some(task), report: None,
            runtime: tokio::runtime::Handle::current() })
    }
}

async fn stopping(stop: &mut watch::Receiver<bool>) {
    loop { if *stop.borrow() || stop.changed().await.is_err() { return; } }
}
#[derive(Default)]
struct FlowOutcome { rejected: bool, failed: bool, cleanup_failed: bool }

#[allow(clippy::too_many_arguments)]
async fn run_owner(sdk: Arc<Sdk>, consumer: Arc<DeviceIdentity>, choice: Arc<LocalProxyServiceChoice>,
    listener: TcpListener, credentials: Arc<Credentials>, file: CredentialFile,
    mut stop: watch::Receiver<bool>, deadline: Instant, _owner: tokio::sync::OwnedSemaphorePermit)
    -> LocalProxyStopReport {
    let mut report = LocalProxyStopReport::default();
    let mut workers = JoinSet::new();
    let (worker_stop, stopped) = watch::channel(false);
    loop {
        tokio::select! { biased;
            _ = stopping(&mut stop) => break,
            _ = tokio::time::sleep_until(deadline) => break,
            outcome = workers.join_next(), if !workers.is_empty() => {
                record_outcome(&mut report, outcome);
            }
            incoming = listener.accept() => {
                let Ok((socket, peer)) = incoming else { report.cleanup_failures += 1; break; };
                report.accepted_connections += 1;
                if !peer.ip().is_loopback() || workers.len() >= OWNER_FLOWS {
                    report.rejected_connections += 1; drop(socket); continue;
                }
                let Ok(permit) = flows().clone().try_acquire_owned() else {
                    report.rejected_connections += 1; drop(socket); continue;
                };
                let (sdk, consumer, choice, credentials, stopped) =
                    (sdk.clone(), consumer.clone(), choice.clone(), credentials.clone(), stopped.clone());
                let address = listener.local_addr().unwrap_or(peer);
                workers.spawn(async move {
                    let _permit = permit;
                    run_flow(sdk, consumer, choice, credentials, socket, address, stopped, deadline).await
                });
            }
        }
    }
    drop(listener);
    worker_stop.send_replace(true);
    while !workers.is_empty() { record_outcome(&mut report, workers.join_next().await); }
    report.credentials_removed = file.remove().is_ok();
    if !report.credentials_removed { report.cleanup_failures += 1; }
    report
}
fn record_outcome(report: &mut LocalProxyStopReport,
    outcome: Option<Result<FlowOutcome, tokio::task::JoinError>>) {
    report.completed_connections += 1;
    match outcome {
        Some(Ok(outcome)) => {
            report.rejected_connections += u64::from(outcome.rejected);
            report.failed_connections += u64::from(outcome.failed);
            report.cleanup_failures += u64::from(outcome.cleanup_failed);
        }
        _ => report.cleanup_failures += 1,
    }
}
type Command = Socks5ServerProtocol<TcpStream, fast_socks5::server::states::CommandRead>;
async fn authenticate_target(socket: TcpStream, credentials: &Credentials,
    choice: &LocalProxyServiceChoice) -> Result<Command, ()> {
    let (authenticated, _) = Socks5ServerProtocol::accept_password_auth(socket,
        |username, password| credentials.accepts(username, password)).await.map_err(|_| ())?;
    let (protocol, command, target) = authenticated.read_command().await.map_err(|_| ())?;
    if command != Socks5Command::TCPConnect {
        let _ = protocol.reply_error(&ReplyError::CommandNotSupported).await;
        return Err(());
    }
    if !choice.accepts(&target) {
        let _ = protocol.reply_error(&ReplyError::ConnectionNotAllowed).await;
        return Err(());
    }
    Ok(protocol)
}

#[allow(clippy::too_many_arguments)]
async fn run_flow(sdk: Arc<Sdk>, consumer: Arc<DeviceIdentity>, choice: Arc<LocalProxyServiceChoice>,
    credentials: Arc<Credentials>, socket: TcpStream, address: SocketAddr,
    mut stop: watch::Receiver<bool>, owner_deadline: Instant) -> FlowOutcome {
    let setup_deadline = (Instant::now() + SETUP_BUDGET).min(owner_deadline);
    let setup = async {
        let protocol = authenticate_target(socket, &credentials, &choice).await?;
        let request = PrivateServiceAccessRequest { request_id: random_id(),
            consumer_device_id: consumer.device_id.clone(),
            expected_service_revision: choice.entry.service.revision,
            expected_exposure_revision: choice.entry.exposure.revision,
            maximum_bytes: choice.maximum_bytes };
        let lease = match sdk.request_private_service(&choice.entry.service.id, request).await {
            Ok(lease) if choice.checks_lease(&lease) => lease,
            _ => { let _ = protocol.reply_error(&ReplyError::ConnectionNotAllowed).await; return Err(()); }
        };
        Ok((protocol, lease))
    };
    let (protocol, lease) = tokio::select! { biased;
        _ = stopping(&mut stop) => return FlowOutcome::default(),
        result = tokio::time::timeout_at(setup_deadline, setup) => match result {
            Ok(Ok(value)) => value,
            _ => return FlowOutcome { rejected: true, ..FlowOutcome::default() },
        }
    };
    // A connect future owns native sockets before it returns a Connection. Keep
    // that exact future on stop/deadline, then await its physical close receipt.
    let connecting = sdk.connect_private_service(&consumer, lease);
    tokio::pin!(connecting);
    let connected = tokio::select! { biased;
        _ = stopping(&mut stop) => None,
        _ = tokio::time::sleep_until(setup_deadline) => None,
        result = &mut connecting => Some(result),
    };
    let mut connection = match connected {
        Some(Ok(connection)) => connection,
        Some(Err(_)) => {
            let _ = tokio::time::timeout_at(setup_deadline, protocol.reply_error(&ReplyError::GeneralFailure)).await;
            // SDK failure may itself represent an unconfirmed carrier cleanup.
            // Conservatively retain that distinction in the final owner report.
            return FlowOutcome { failed: true, cleanup_failed: true, ..FlowOutcome::default() }; }
        None => {
            drop(protocol);
            let cleanup_failed = match connecting.await { Ok(mut connection) => connection.close().await.is_err(), Err(_) => true };
            return FlowOutcome { cleanup_failed, ..FlowOutcome::default() };
        }
    };
    let ready = tokio::select! { biased;
        _ = stopping(&mut stop) => None,
        result = tokio::time::timeout_at(setup_deadline, protocol.reply_success(address)) => result.ok().and_then(Result::ok),
    };
    let mut failed = false;
    if let Some(mut local) = ready {
        let lease = connection.lease().clone();
        let transfer = async {
            tokio::io::copy_bidirectional(&mut local, connection.stream().map_err(|_| ())?).await.map_err(|_| ())
        };
        tokio::select! { biased;
            _ = stopping(&mut stop) => {},
            _ = tokio::time::sleep_until(owner_deadline) => {},
            _ = authority_expired(&lease) => {},
            result = transfer => { failed = result.is_err(); },
        }
        drop(local);
    }
    let cleanup_failed = connection.close().await.is_err();
    FlowOutcome { failed, cleanup_failed, ..FlowOutcome::default() }
}
fn wall_ms() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis().try_into().ok()
}
async fn authority_expired(lease: &VerifiedPrivateServiceLease) {
    let Some(mut previous) = wall_ms() else { return; };
    let remaining = lease.lease().claims().expires_at_unix_ms.saturating_sub(previous);
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! { biased;
            _ = tokio::time::sleep_until(deadline) => return,
            _ = tick.tick() => {
                let Some(now) = wall_ms() else { return; };
                if now < previous || lease.check_time(now).is_err() { return; }
                previous = now;
            }
        }
    }
}

#[cfg(test)]
mod tests;
