use super::{ServiceHostStopReport, ServiceHostWait};
use std::{future::Future, io, time::Duration};
use tokio::task::JoinHandle;

pub(super) struct ServiceCleanupMonitor {
    task: Option<JoinHandle<ServiceHostStopReport>>,
    endpoint: Option<quinn::Endpoint>,
    release: Option<std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    releasing: Option<JoinHandle<io::Result<()>>>,
    runtime: tokio::runtime::Handle,
    report: Option<ServiceHostStopReport>,
    worker_report: Option<ServiceHostStopReport>,
    failed: bool,
}
impl ServiceCleanupMonitor {
    pub(super) fn new(
        task: JoinHandle<ServiceHostStopReport>, endpoint: quinn::Endpoint,
        release: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> Self {
        Self {
            task: Some(task),
            endpoint: Some(endpoint),
            release: Some(Box::pin(release)),
            releasing: None,
            runtime: tokio::runtime::Handle::current(),
            report: None,
            worker_report: None,
            failed: false,
        }
    }
    pub(super) fn pending(&self) -> bool {
        self.report.is_none()
    }
    pub(super) async fn wait(&mut self, budget: Duration) -> ServiceHostWait {
        if let Some(report) = self.report {
            return ServiceHostWait::Stopped(report);
        }
        if self.failed {
            return ServiceHostWait::CleanupPending { failed: true };
        }
        match tokio::time::timeout(budget, self.finish()).await {
            Err(_) => ServiceHostWait::CleanupPending { failed: self.failed },
            Ok(Ok(report)) => ServiceHostWait::Stopped(report),
            Ok(Err(())) => { self.failed = true; ServiceHostWait::CleanupPending { failed: true } }
        }
    }
    async fn finish(&mut self) -> Result<ServiceHostStopReport, ()> {
        if let Some(task) = self.task.as_mut() {
            let result = (&mut *task).await;
            self.task.take();
            match result {
                Ok(report) => self.worker_report = Some(report),
                Err(_) => {
                    // A panicked worker cannot certify that its children joined.
                    if let Some(endpoint) = &self.endpoint {
                        endpoint.close(1u32.into(), b"service cleanup coordinator failed");
                    }
                    return Err(());
                }
            }
        }
        if self.releasing.is_none() {
            let endpoint = self.endpoint.take().ok_or(())?;
            let release = self.release.take().ok_or(())?;
            // Store the release task before awaiting. Cancelling this wait must
            // retain the endpoint, original receipt and the same physical work.
            self.releasing = Some(self.runtime.spawn(async move {
                endpoint.close(0u32.into(), b"service worker joined");
                endpoint.wait_idle().await;
                drop(endpoint);
                release.await
            }));
        }
        let releasing = self.releasing.as_mut().ok_or(())?;
        (&mut *releasing).await.map_err(|_| ())?.map_err(|_| ())?;
        self.releasing.take();
        let report = self.worker_report.take().ok_or(())?;
        self.report = Some(report);
        Ok(report)
    }
}
impl Drop for ServiceCleanupMonitor {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"service cleanup owner dropped");
        }
        if let Some(releasing) = self.releasing.take() {
            self.runtime.spawn(async move { let _ = releasing.await; });
        }
        let endpoint = self.endpoint.take();
        let release = self.release.take();
        if let Some(task) = self.task.take() {
            // The reaper retains the original worker handle and endpoint; it
            // never labels abort() or a closed socket as completed cleanup.
            self.runtime.spawn(async move {
                let _ = task.await;
                if let Some(endpoint) = endpoint { endpoint.wait_idle().await; drop(endpoint); }
                if let Some(release) = release { let _ = release.await; }
            });
        } else if endpoint.is_some() || release.is_some() {
            self.runtime.spawn(async move {
                if let Some(endpoint) = endpoint { endpoint.wait_idle().await; drop(endpoint); }
                if let Some(release) = release { let _ = release.await; }
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn endpoint_owner() -> io::Result<(quinn::Endpoint, impl Future<Output = io::Result<()>> + Send)> {
        let listener = nestlink_transport_quic::service::PrivateListener::bind(
            "127.0.0.1:0".parse().map_err(io::Error::other)?,
            &nestlink_identity::InstallationIdentity::generate(),
        ).map_err(io::Error::other)?;
        Ok((listener.endpoint.clone(), listener.close_and_wait()))
    }
    #[tokio::test]
    async fn drop_on_an_ordinary_thread_retains_endpoint_until_original_worker_ends() -> Result {
        let (endpoint, socket_release) = endpoint_owner()?;
        let address = endpoint.local_addr()?;
        let (release, waiting) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            let _ = completed.send(());
            ServiceHostStopReport { failed: false }
        });
        let monitor = ServiceCleanupMonitor::new(task, endpoint, socket_release);
        std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            drop(monitor);
        })
        .join()
        .map_err(|_| "cleanup drop thread panicked")?;
        // Let the endpoint driver react to close/drop while the worker remains
        // blocked. The reaper must still own the socket during that interval.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::net::UdpSocket::bind(address)
                .err()
                .ok_or("endpoint released before worker cleanup")?
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        let _ = release.send(());
        tokio::time::timeout(Duration::from_secs(1), completion).await??;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match std::net::UdpSocket::bind(address) {
                    Ok(socket) => return Ok::<_, std::io::Error>(socket),
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        Ok(())
    }
    #[tokio::test]
    async fn slow_cleanup_does_not_report_physical_stop_or_drop_original_handle() -> Result {
        let (endpoint, socket_release) = endpoint_owner()?;
        let (release, waiting) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            ServiceHostStopReport { failed: false }
        });
        let mut monitor = ServiceCleanupMonitor::new(task, endpoint, socket_release);
        assert_eq!(
            monitor.wait(Duration::from_millis(10)).await,
            ServiceHostWait::CleanupPending { failed: false }
        );
        assert!(monitor.task.is_some());
        assert!(monitor.pending());
        assert!(monitor.endpoint.as_ref().is_some_and(|endpoint| endpoint.local_addr().is_ok()));
        let _ = release.send(());
        assert_eq!(
            monitor.wait(Duration::from_secs(1)).await,
            ServiceHostWait::Stopped(ServiceHostStopReport { failed: false })
        );
        assert!(!monitor.pending());
        Ok(())
    }
    #[tokio::test]
    async fn abandoning_a_wait_preserves_the_same_cleanup_worker_and_endpoint() -> Result {
        let (endpoint, socket_release) = endpoint_owner()?;
        let (release, waiting) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            ServiceHostStopReport { failed: true }
        });
        let mut monitor = ServiceCleanupMonitor::new(task, endpoint, socket_release);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                monitor.wait(Duration::from_secs(60))
            )
            .await
            .is_err()
        );
        assert!(monitor.task.is_some());
        assert!(monitor.pending());
        assert!(monitor.endpoint.as_ref().is_some_and(|endpoint| endpoint.local_addr().is_ok()));
        let _ = release.send(());
        assert_eq!(
            monitor.wait(Duration::from_secs(1)).await,
            ServiceHostWait::Stopped(ServiceHostStopReport { failed: true })
        );
        Ok(())
    }
    #[tokio::test]
    async fn joined_worker_cannot_certify_socket_stop_while_an_endpoint_holder_remains() -> Result {
        let (endpoint, socket_release) = endpoint_owner()?;
        let address = endpoint.local_addr()?;
        let holder = endpoint.clone();
        let task = tokio::spawn(async { ServiceHostStopReport { failed: false } });
        let mut monitor = ServiceCleanupMonitor::new(task, endpoint, socket_release);
        assert_eq!(monitor.wait(Duration::from_millis(25)).await,
            ServiceHostWait::CleanupPending { failed: false });
        assert!(monitor.task.is_none());
        assert!(monitor.releasing.is_some());
        assert!(monitor.pending());
        assert!(matches!(std::net::UdpSocket::bind(address), Err(error)
            if error.kind() == io::ErrorKind::AddrInUse));
        // Abandoning another wait must leave the same physical release task.
        assert!(tokio::time::timeout(Duration::from_millis(10),
            monitor.wait(Duration::from_secs(60))).await.is_err());
        drop(holder);
        assert_eq!(monitor.wait(Duration::from_secs(1)).await,
            ServiceHostWait::Stopped(ServiceHostStopReport { failed: false }));
        let rebound = std::net::UdpSocket::bind(address)?;
        drop(rebound);
        Ok(())
    }
}
