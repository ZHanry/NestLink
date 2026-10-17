use super::{ServiceHostStopReport, ServiceHostWait};
use std::time::Duration;
use tokio::task::JoinHandle;

pub(super) struct ServiceCleanupMonitor {
    task: Option<JoinHandle<ServiceHostStopReport>>,
    endpoint: quinn::Endpoint,
    runtime: tokio::runtime::Handle,
    report: Option<ServiceHostStopReport>,
    failed: bool,
}
impl ServiceCleanupMonitor {
    pub(super) fn new(task: JoinHandle<ServiceHostStopReport>, endpoint: quinn::Endpoint) -> Self {
        Self {
            task: Some(task),
            endpoint,
            runtime: tokio::runtime::Handle::current(),
            report: None,
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
        let Some(task) = self.task.as_mut() else {
            return ServiceHostWait::CleanupPending { failed: true };
        };
        match tokio::time::timeout(budget, &mut *task).await {
            Err(_) => ServiceHostWait::CleanupPending {
                failed: self.failed,
            },
            Ok(Ok(report)) => {
                self.task.take();
                self.report = Some(report);
                ServiceHostWait::Stopped(report)
            }
            Ok(Err(_)) => {
                // A panicked/canceled coordinator cannot certify child joins.
                // Keep the endpoint owner and expose pending failed cleanup.
                self.task.take();
                self.failed = true;
                self.endpoint
                    .close(1u32.into(), b"service cleanup coordinator failed");
                ServiceHostWait::CleanupPending { failed: true }
            }
        }
    }
}
impl Drop for ServiceCleanupMonitor {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"service cleanup owner dropped");
        if let Some(task) = self.task.take() {
            // The reaper retains the original worker handle and endpoint; it
            // never labels abort() or a closed socket as completed cleanup.
            let endpoint = self.endpoint.clone();
            self.runtime.spawn(async move {
                let _ = task.await;
                endpoint.wait_idle().await;
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    #[tokio::test]
    async fn drop_on_an_ordinary_thread_retains_endpoint_until_original_worker_ends() -> Result {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let address = endpoint.local_addr()?;
        let (release, waiting) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            let _ = completed.send(());
            ServiceHostStopReport { failed: false }
        });
        let monitor = ServiceCleanupMonitor::new(task, endpoint);
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
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let (release, waiting) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            ServiceHostStopReport { failed: false }
        });
        let mut monitor = ServiceCleanupMonitor::new(task, endpoint);
        assert_eq!(
            monitor.wait(Duration::from_millis(10)).await,
            ServiceHostWait::CleanupPending { failed: false }
        );
        assert!(monitor.task.is_some());
        assert!(monitor.pending());
        assert!(monitor.endpoint.local_addr().is_ok());
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
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let (release, waiting) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
            ServiceHostStopReport { failed: true }
        });
        let mut monitor = ServiceCleanupMonitor::new(task, endpoint);
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
        assert!(monitor.endpoint.local_addr().is_ok());
        let _ = release.send(());
        assert_eq!(
            monitor.wait(Duration::from_secs(1)).await,
            ServiceHostWait::Stopped(ServiceHostStopReport { failed: true })
        );
        Ok(())
    }
}
