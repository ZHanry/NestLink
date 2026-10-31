//! Independent finite private-service authority on the original QUIC carrier,
//! fixed local target and OS-authenticated native local stream. No online lease
//! is fabricated, renewed or converted, and no signed file can start this owner.
use super::*;
use crate::network_management::ConsumedOfflineBundle;
use nestlink_protocol::offline::{OfflineBusiness, OfflineDirectTransport};
use nestlink_transport_quic::service::{
    self as carrier, BiStream, PrivateListener,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};
mod guard;
mod runtime;
use guard::Shared;

fn wall() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

#[derive(Clone, Debug, Serialize)]
pub struct OfflinePrivateStatus {
    pub bundle_id: String,
    pub direct_only: bool,
    pub expires_at_ms: u64,
    pub remaining_ms: u64,
    pub remaining_bytes: u64,
    pub cumulative_connections: u32,
    pub connected: u32,
    pub stopped: bool,
    pub recovering: bool,
    pub cleanup_pending: bool,
    pub central_revocation_may_be_delayed_until_ms: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct OfflinePrivateReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub released_quic_sockets: u64,
    pub cleanup_failures: u64,
    pub local_endpoint_removed: bool,
}
#[derive(Clone, Debug)]
pub enum OfflinePrivateWait {
    CleanupPending,
    Stopped(OfflinePrivateReport),
    CleanupFailed(OfflinePrivateReport),
}
pub struct OfflinePrivateRuntime {
    shared: Arc<Shared>,
    address: Option<SocketAddr>,
    endpoint: Option<PathBuf>,
    task: Option<JoinHandle<OfflinePrivateReport>>,
    report: Option<OfflinePrivateReport>,
    runtime: tokio::runtime::Handle,
}
impl OfflinePrivateRuntime {
    pub fn address(&self) -> Option<SocketAddr> {
        self.address
    }
    pub fn endpoint(&self) -> Option<&Path> {
        self.endpoint.as_deref()
    }
    pub fn stop(&self) {
        self.shared.stop();
    }
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn status(&self) -> Result<OfflinePrivateStatus, SdkError> {
        self.shared.status(!self.is_finished())
    }
    /// The caller invokes this on management recovery before more business I/O.
    /// Every flow pauses while the original owner applies latest current state.
    pub async fn synchronize_online(&self, sdk: &Sdk) -> Result<(), SdkError> {
        self.shared.synchronize(sdk).await
    }
    /// Cancellation and timeout retain the original cleanup task and receipt.
    pub async fn wait_stopped(&mut self, budget: Duration) -> OfflinePrivateWait {
        self.stop();
        if let Some(task) = self.task.as_mut() {
            let result = match tokio::time::timeout(budget, &mut *task).await {
                Err(_) => return OfflinePrivateWait::CleanupPending,
                Ok(r) => r,
            };
            self.task.take();
            self.report = Some(result.unwrap_or_else(|_| OfflinePrivateReport {
                cleanup_failures: 1,
                ..Default::default()
            }));
        }
        let report = self.report.clone().unwrap_or_else(|| OfflinePrivateReport {
            cleanup_failures: 1,
            ..Default::default()
        });
        if report.cleanup_failures == 0 && report.local_endpoint_removed {
            OfflinePrivateWait::Stopped(report)
        } else {
            OfflinePrivateWait::CleanupFailed(report)
        }
    }
}
impl Drop for OfflinePrivateRuntime {
    fn drop(&mut self) {
        self.stop();
        if let Some(task) = self.task.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}
impl Sdk {
    pub async fn start_offline_private_service_host(
        self: &Arc<Self>,
        host: Arc<DeviceIdentity>,
        consumed: ConsumedOfflineBundle,
        consent: LocalServiceTargetConsent,
        listen: SocketAddr,
    ) -> Result<OfflinePrivateRuntime, SdkError> {
        runtime::host(self, host, consumed, consent, listen).await
    }
    pub async fn start_offline_private_service_proxy(
        self: &Arc<Self>,
        consumer: Arc<DeviceIdentity>,
        consumed: ConsumedOfflineBundle,
        peer: SocketAddr,
        private_directory: &Path,
    ) -> Result<OfflinePrivateRuntime, SdkError> {
        runtime::proxy(self, consumer, consumed, peer, private_directory).await
    }
}
