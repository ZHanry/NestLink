//! The mature SyncIoBridge owns bounded byte bridging; native cancellation owns
//! the two synchronous inherited pipe operations and their original thread joins.
#![allow(unsafe_code)]
use super::*;
use std::{
    io::{Read, Write},
    os::windows::io::AsRawHandle,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio_util::io::SyncIoBridge;
use windows_sys::Win32::{
    Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType},
    System::IO::CancelSynchronousIo,
};

struct CancelIo<T> {
    inner: T,
    stop: Arc<AtomicBool>,
}
impl<T: Read> Read for CancelIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let result = self.inner.read(bytes);
        if self.stop.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        result
    }
}
impl<T: Write> Write for CancelIo<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let result = self
            .inner
            .write(bytes)
            .and_then(|length| self.inner.flush().map(|_| length));
        if self.stop.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
async fn join(workers: Vec<JoinHandle<()>>, output_stopped: Arc<AtomicBool>) -> io::Result<()> {
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut output_cancelled = false;
    while workers.iter().any(|worker| !worker.is_finished()) {
        // Cancellation may race the start of ReadFile/WriteFile. Repeat while
        // retaining the exact handles until both original threads finish.
        for (index, worker) in workers.iter().enumerate() {
            if worker.is_finished() {
                continue;
            }
            if index == 1 {
                // Duplex flush is not a synchronous stdout delivery receipt.
                // Let the original writer drain all queued bytes before stop.
                if tokio::time::Instant::now() < drain_deadline {
                    continue;
                }
                output_stopped.store(true, Ordering::SeqCst);
                output_cancelled = true;
            }
            unsafe {
                CancelSynchronousIo(worker.as_raw_handle().cast());
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("stdio worker panicked"))?;
    }
    if output_cancelled {
        return Err(io::Error::other(
            "stdio output did not drain before its original deadline",
        ));
    }
    Ok(())
}
struct Workers {
    threads: Vec<JoinHandle<()>>,
    closing: Option<tokio::task::JoinHandle<io::Result<()>>>,
    stopped: Arc<AtomicBool>,
    output_stopped: Arc<AtomicBool>,
    runtime: tokio::runtime::Handle,
}
impl Workers {
    fn begin_close(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if self.closing.is_none() && !self.threads.is_empty() {
            self.closing = Some(self.runtime.spawn(join(
                std::mem::take(&mut self.threads),
                self.output_stopped.clone(),
            )));
        }
    }
    async fn close(&mut self) -> io::Result<()> {
        self.begin_close();
        if let Some(task) = self.closing.as_mut() {
            let result = tokio::time::timeout(Duration::from_secs(2), &mut *task).await
                .map_err(|_| io::Error::other("stdio worker cleanup is pending; original cancellation/join owner retained"))?;
            self.closing.take();
            result.map_err(|_| io::Error::other("stdio cleanup task panicked"))??;
        }
        Ok(())
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        self.begin_close();
        if let Some(task) = self.closing.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}
pub(super) async fn relay(
    stream: LocalStream,
    stop_signal: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    if unsafe { GetFileType(std::io::stdin().as_raw_handle().cast()) } != FILE_TYPE_PIPE
        || unsafe { GetFileType(std::io::stdout().as_raw_handle().cast()) } != FILE_TYPE_PIPE
    {
        return Err(io::Error::other(
            "native stream stdio requires redirected stdin/stdout pipes (for example SSH ProxyCommand)",
        ));
    }
    let (input, input_bridge) = tokio::io::duplex(16_384);
    let (output, output_bridge) = tokio::io::duplex(16_384);
    let stopped = Arc::new(AtomicBool::new(false));
    let output_stopped = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(Mutex::new(None));
    let (cancel, failure, runtime) = (
        stopped.clone(),
        failed.clone(),
        tokio::runtime::Handle::current(),
    );
    let errors = failures.clone();
    let input_worker = thread::Builder::new()
        .name("nestlink-stdio-input".into())
        .spawn(move || {
            let mut source = CancelIo {
                inner: std::io::stdin(),
                stop: cancel.clone(),
            };
            let mut target = SyncIoBridge::new_with_handle(input_bridge, runtime);
            if let Err(error) = std::io::copy(&mut source, &mut target)
                && !cancel.load(Ordering::SeqCst)
            {
                if let Ok(mut errors) = errors.lock()
                    && errors.is_none()
                {
                    *errors = Some(error);
                }
                failure.store(true, Ordering::SeqCst);
            }
        })?;
    let mut workers = Workers {
        threads: vec![input_worker],
        closing: None,
        stopped: stopped.clone(),
        output_stopped: output_stopped.clone(),
        runtime: tokio::runtime::Handle::current(),
    };
    let (cancel, failure, runtime) = (
        output_stopped,
        failed.clone(),
        tokio::runtime::Handle::current(),
    );
    let errors = failures.clone();
    let output_worker = match thread::Builder::new()
        .name("nestlink-stdio-output".into())
        .spawn(move || {
            let mut source = SyncIoBridge::new_with_handle(output_bridge, runtime);
            let mut target = CancelIo {
                inner: std::io::stdout(),
                stop: cancel.clone(),
            };
            if let Err(error) = std::io::copy(&mut source, &mut target)
                && !cancel.load(Ordering::SeqCst)
            {
                if let Ok(mut errors) = errors.lock()
                    && errors.is_none()
                {
                    *errors = Some(error);
                }
                failure.store(true, Ordering::SeqCst);
            }
        }) {
        Ok(worker) => worker,
        Err(error) => {
            drop(input);
            drop(output);
            workers.close().await?;
            return Err(error);
        }
    };
    workers.threads.push(output_worker);
    let operation = {
        let transfer = relay_io(input, output, stream, stop_signal);
        tokio::pin!(transfer);
        tokio::select! { biased;
            result = &mut transfer => result,
            _ = async { while !failed.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(10)).await; } } =>
                Err(io::Error::other("native stream stdio worker failed")),
        }
    };
    let cleanup = workers.close().await;
    let worker_error = failures.lock().ok().and_then(|mut errors| errors.take());
    if let Some(error) = worker_error.or_else(|| operation.err()) {
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => io::Error::new(error.kind(), format!("{error}; cleanup: {cleanup}")),
        });
    }
    cleanup
}
