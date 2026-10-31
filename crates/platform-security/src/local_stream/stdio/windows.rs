//! The mature SyncIoBridge owns bounded byte bridging; native cancellation owns
//! the two synchronous inherited pipe operations and their original thread joins.
#![allow(unsafe_code)]
use super::*;
use std::{io::{Read, Write}, os::windows::io::AsRawHandle,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, thread::{self, JoinHandle}, time::Duration};
use tokio_util::io::SyncIoBridge;
use windows_sys::Win32::{Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType}, System::IO::CancelSynchronousIo};

struct CancelIo<T> { inner: T, stop: Arc<AtomicBool> }
impl<T: Read> Read for CancelIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        let result = self.inner.read(bytes);
        if self.stop.load(Ordering::SeqCst) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        result
    }
}
impl<T: Write> Write for CancelIo<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        let result = self.inner.write(bytes).and_then(|length| self.inner.flush().map(|_| length));
        if self.stop.load(Ordering::SeqCst) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        result
    }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}
async fn join(workers: Vec<JoinHandle<()>>) -> io::Result<()> {
    while workers.iter().any(|worker| !worker.is_finished()) {
        // Cancellation may race the start of ReadFile/WriteFile. Repeat while
        // retaining the exact handles until both original threads finish.
        for worker in &workers {
            if !worker.is_finished() { unsafe { CancelSynchronousIo(worker.as_raw_handle().cast()); } }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for worker in workers { worker.join().map_err(|_| io::Error::other("stdio worker panicked"))?; }
    Ok(())
}
struct Workers {
    threads: Vec<JoinHandle<()>>,
    closing: Option<tokio::task::JoinHandle<io::Result<()>>>,
    stopped: Arc<AtomicBool>,
    runtime: tokio::runtime::Handle,
}
impl Workers {
    fn begin_close(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if self.closing.is_none() && !self.threads.is_empty() {
            self.closing = Some(self.runtime.spawn(join(std::mem::take(&mut self.threads))));
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
        if let Some(task) = self.closing.take() { self.runtime.spawn(async move { let _ = task.await; }); }
    }
}
pub(super) async fn relay(stream: LocalStream, stop_signal: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    if unsafe { GetFileType(std::io::stdin().as_raw_handle().cast()) } != FILE_TYPE_PIPE
        || unsafe { GetFileType(std::io::stdout().as_raw_handle().cast()) } != FILE_TYPE_PIPE {
        return Err(io::Error::other("native stream stdio requires redirected stdin/stdout pipes (for example SSH ProxyCommand)"));
    }
    let (input, input_bridge) = tokio::io::duplex(16_384);
    let (output, output_bridge) = tokio::io::duplex(16_384);
    let stopped = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let (cancel, failure, runtime) = (stopped.clone(), failed.clone(), tokio::runtime::Handle::current());
    let input_worker = thread::Builder::new().name("nestlink-stdio-input".into()).spawn(move || {
        let mut source = CancelIo { inner: std::io::stdin(), stop: cancel.clone() };
        let mut target = SyncIoBridge::new_with_handle(input_bridge, runtime);
        if std::io::copy(&mut source, &mut target).is_err() && !cancel.load(Ordering::SeqCst) { failure.store(true, Ordering::SeqCst); }
    })?;
    let mut workers = Workers { threads: vec![input_worker], closing: None,
        stopped: stopped.clone(), runtime: tokio::runtime::Handle::current() };
    let (cancel, failure, runtime) = (stopped.clone(), failed.clone(), tokio::runtime::Handle::current());
    let output_worker = match thread::Builder::new().name("nestlink-stdio-output".into()).spawn(move || {
        let mut source = SyncIoBridge::new_with_handle(output_bridge, runtime);
        let mut target = CancelIo { inner: std::io::stdout(), stop: cancel.clone() };
        if std::io::copy(&mut source, &mut target).is_err() && !cancel.load(Ordering::SeqCst) { failure.store(true, Ordering::SeqCst); }
    }) {
        Ok(worker) => worker,
        Err(error) => {
            drop(input); drop(output);
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
    workers.close().await?;
    operation
}
