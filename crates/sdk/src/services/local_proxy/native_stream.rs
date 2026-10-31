//! One fixed private service behind an OS-authenticated local byte stream.
//! Unix sockets preserve half-close; Windows byte pipes have no write-half EOF.
use super::*;
use nestlink_platform_security::local_stream::{Listener, LocalStream};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeStreamStopReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub cleanup_failures: u64,
    pub endpoint_removed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeStreamWait { CleanupPending, Stopped(NativeStreamStopReport), CleanupFailed(NativeStreamStopReport) }
pub struct LocalNativeServiceProxy {
    endpoint: PathBuf,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<NativeStreamStopReport>>,
    report: Option<NativeStreamStopReport>,
    runtime: tokio::runtime::Handle,
}
impl LocalNativeServiceProxy {
    pub fn endpoint(&self) -> &Path { &self.endpoint }
    pub fn is_finished(&self) -> bool { self.report.is_some() || self.task.as_ref().is_none_or(JoinHandle::is_finished) }
    pub fn request_shutdown(&self) { self.stop.send_replace(true); }
    pub async fn wait_stopped(&mut self, budget: Duration) -> NativeStreamWait {
        self.request_shutdown();
        if let Some(task) = self.task.as_mut() {
            let result = match tokio::time::timeout(budget, &mut *task).await {
                Err(_) => return NativeStreamWait::CleanupPending, Ok(result) => result,
            };
            self.task.take();
            self.report = Some(result.unwrap_or_else(|_| NativeStreamStopReport {
                cleanup_failures: 1, ..NativeStreamStopReport::default()
            }));
        }
        let report = self.report.clone().unwrap_or_else(|| NativeStreamStopReport {
            cleanup_failures: 1, ..NativeStreamStopReport::default()
        });
        if report.cleanup_failures == 0 && report.endpoint_removed { NativeStreamWait::Stopped(report) }
        else { NativeStreamWait::CleanupFailed(report) }
    }
}
impl Drop for LocalNativeServiceProxy {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() { self.runtime.spawn(async move { let _ = task.await; }); }
    }
}
impl Sdk {
    /// Create an owner-private Unix socket or Windows byte-mode named pipe for
    /// one selected TCP/HTTP/HTTPS service. The OS authenticates each local peer.
    /// This method creates no unauthenticated loopback TCP/UDP listener.
    pub async fn start_private_service_native_stream(self: &Arc<Self>, consumer: Arc<DeviceIdentity>,
        choice: LocalProxyServiceChoice, private_directory: &Path) -> Result<LocalNativeServiceProxy, LocalProxyError> {
        if !valid_id(&consumer.device_id)
            || matches!(choice.entry.service.definition.requested_ingress, ServiceIngress::Udp { .. }) {
            return Err(LocalProxyError::Invalid);
        }
        self.principal().ok_or(SdkError::SignIn)?;
        let owner = owners().clone().try_acquire_owned().map_err(|_| LocalProxyError::Busy)?;
        let deadline = Instant::now() + choice.lifetime;
        let listener = Listener::bind(private_directory, &random_id())?;
        let endpoint = listener.endpoint().to_path_buf();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_owner(self.clone(), consumer, Arc::new(choice), listener, stopped, deadline, owner));
        Ok(LocalNativeServiceProxy { endpoint, stop, task: Some(task), report: None,
            runtime: tokio::runtime::Handle::current() })
    }
}
fn record(report: &mut NativeStreamStopReport, outcome: Option<Result<FlowOutcome, tokio::task::JoinError>>) {
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
async fn run_owner(sdk: Arc<Sdk>, consumer: Arc<DeviceIdentity>, choice: Arc<LocalProxyServiceChoice>,
    mut listener: Listener, mut stop: watch::Receiver<bool>, deadline: Instant,
    _owner: tokio::sync::OwnedSemaphorePermit) -> NativeStreamStopReport {
    let mut report = NativeStreamStopReport::default();
    let mut workers = JoinSet::new();
    let (worker_stop, stopped) = watch::channel(false);
    loop { tokio::select! { biased;
        _ = stopping(&mut stop) => break,
        _ = tokio::time::sleep_until(deadline) => break,
        outcome = workers.join_next(), if !workers.is_empty() => record(&mut report, outcome),
        incoming = listener.accept() => {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => { report.rejected_connections += 1; continue; }
                Err(_) => { report.cleanup_failures += 1; break; }
            };
            report.accepted_connections += 1;
            if workers.len() >= OWNER_FLOWS { report.rejected_connections += 1; drop(stream); continue; }
            let Ok(permit) = flows().clone().try_acquire_owned() else {
                report.rejected_connections += 1; drop(stream); continue;
            };
            let (sdk, consumer, choice, stopped) = (sdk.clone(), consumer.clone(), choice.clone(), stopped.clone());
            workers.spawn(async move {
                let _permit = permit;
                forward(sdk, consumer, choice, stream, stopped, deadline).await
            });
        }
    }}
    listener.stop_accepting();
    worker_stop.send_replace(true);
    while !workers.is_empty() { record(&mut report, workers.join_next().await); }
    report.endpoint_removed = listener.cleanup().is_ok();
    if !report.endpoint_removed { report.cleanup_failures += 1; }
    report
}
async fn forward(sdk: Arc<Sdk>, consumer: Arc<DeviceIdentity>, choice: Arc<LocalProxyServiceChoice>,
    mut local: LocalStream, mut stop: watch::Receiver<bool>, owner_deadline: Instant) -> FlowOutcome {
    let setup_deadline = (Instant::now() + SETUP_BUDGET).min(owner_deadline);
    let request = PrivateServiceAccessRequest { request_id: random_id(), consumer_device_id: consumer.device_id.clone(),
        expected_service_revision: choice.entry.service.revision,
        expected_exposure_revision: choice.entry.exposure.revision, maximum_bytes: choice.maximum_bytes };
    let lease = tokio::select! { biased;
        _ = stopping(&mut stop) => return FlowOutcome::default(),
        result = tokio::time::timeout_at(setup_deadline, sdk.request_private_service(&choice.entry.service.id, request)) => match result {
            Ok(Ok(lease)) if choice.checks_lease(&lease) => lease,
            _ => return FlowOutcome { rejected: true, ..FlowOutcome::default() },
        }
    };
    let connecting = sdk.connect_private_service(&consumer, lease);
    tokio::pin!(connecting);
    let connected = tokio::select! { biased;
        _ = stopping(&mut stop) => None,
        _ = tokio::time::sleep_until(setup_deadline) => None,
        result = &mut connecting => Some(result),
    };
    let mut connection = match connected {
        Some(Ok(connection)) => connection,
        Some(Err(_)) => return FlowOutcome { failed: true, cleanup_failed: true, ..FlowOutcome::default() },
        None => {
            drop(local);
            let cleanup_failed = match connecting.await { Ok(mut connection) => connection.close().await.is_err(), Err(_) => true };
            return FlowOutcome { cleanup_failed, ..FlowOutcome::default() };
        }
    };
    let lease = connection.lease().clone();
    let mut outcome = FlowOutcome::default();
    {
        let transfer = async {
            tokio::io::copy_bidirectional(&mut local, connection.stream().map_err(|_| ())?).await.map_err(|_| ())
        };
        tokio::select! { biased;
            _ = stopping(&mut stop) => {},
            _ = tokio::time::sleep_until(owner_deadline) => {},
            _ = authority_expired(&lease) => {},
            result = transfer => { outcome.failed = result.is_err(); },
        }
    }
    drop(local);
    outcome.cleanup_failed = connection.close().await.is_err();
    outcome
}
