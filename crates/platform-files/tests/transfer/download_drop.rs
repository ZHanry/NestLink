use super::*;
use nestlink_platform_files::download::LocalDownloadSelection;
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadSnapshot,
    FileDownloadWorker,
};

#[derive(Clone, Copy)]
enum ProviderFault {
    Drop,
    Status,
}

struct FaultFactory(LocalDownloadSelection, ProviderFault);

impl FileDestinationFactory for FaultFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.0.consent()
    }

    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        let destination = Box::new(self.0).build(source)?;
        Ok(Box::new(FaultDestination(destination, self.1)))
    }
}

struct FaultDestination(Box<dyn FileDestination>, ProviderFault);

impl Drop for FaultDestination {
    fn drop(&mut self) {
        if matches!(self.1, ProviderFault::Drop) {
            panic!("injected provider destructor panic");
        }
    }
}

impl FileDestination for FaultDestination {
    fn status(&self) -> FileDestinationStatus {
        if matches!(self.1, ProviderFault::Status) {
            panic!("injected provider status panic");
        }
        self.0.status()
    }

    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.0.prepare(authorized)
    }

    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.0.write(source, chunk, authorized)
    }

    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.0.resume(source, authorized)
    }

    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.0.finish(source, authorized)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        self.0.cleanup()
    }
}

async fn wait_finished(monitor: &nestlink_remote::files::FileDownloadMonitor) -> Result {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut state = monitor.subscribe();
        while !state.borrow_and_update().finished {
            state.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn provider_drop_panic_still_publishes_finished_after_verified_completion() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("empty"), b"")?;
    let (root, provider, _keep) = roots(source.path())?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut sessions.c, 9)?;
    let mut download = client.open(&random_id(), &root, "empty", 0, None).await?;
    let (selection, _consent) =
        LocalDownloadSelection::new(&output.path().join("area"), "done", FILE_SIZE_BYTES)?;
    let mut worker = FileDownloadWorker::start(
        &client,
        &download,
        FaultFactory(selection, ProviderFault::Drop),
    )?;
    let monitor = worker.monitor();
    worker.ready().await?;
    assert!(client.next(&mut download).await?.is_none());
    assert!(worker.finish(&download).await?.published);

    wait_finished(&monitor).await?;
    let status = monitor.status();
    assert!(status.finished);
    assert_eq!(
        status.phase,
        nestlink_remote::files::FileDownloadPhase::Completed
    );
    assert_eq!(status.cleanup_error, Some(io::ErrorKind::Other));
    assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn provider_status_panic_still_publishes_final_finished_fact() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("empty"), b"")?;
    let (root, provider, _keep) = roots(source.path())?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut sessions.c, 9)?;
    let download = client.open(&random_id(), &root, "empty", 0, None).await?;
    let (selection, _consent) =
        LocalDownloadSelection::new(&output.path().join("area"), "done", FILE_SIZE_BYTES)?;
    let mut worker = FileDownloadWorker::start(
        &client,
        &download,
        FaultFactory(selection, ProviderFault::Status),
    )?;
    let monitor = worker.monitor();

    assert!(worker.ready().await.is_err());
    wait_finished(&monitor).await?;
    let status = monitor.status();
    assert!(status.finished);
    assert_eq!(
        status.phase,
        nestlink_remote::files::FileDownloadPhase::Stopped
    );
    assert_eq!(status.error, Some(io::ErrorKind::Other));
    assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
