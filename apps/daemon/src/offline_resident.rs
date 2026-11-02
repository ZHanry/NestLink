//! Shared original-process input and local logout/identity/maintenance fence.
use nestlink_identity::offline::{OfflineProcess, OfflineProcessStop};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(crate) fn emit(event: &str, value: impl Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(
        &mut output,
        &serde_json::json!({"event":event,"data":value}),
    )?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn identity_snapshot(directory: &std::path::Path) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(nestlink_platform_security::read_private(
        &directory.join("installation-device.json"),
        16384,
    )?)
    .into())
}
pub(crate) struct LocalGuard {
    stopped: Arc<AtomicBool>,
    process: Arc<Mutex<Option<OfflineProcessStop>>>,
    task: tokio::task::JoinHandle<()>,
}
impl LocalGuard {
    pub(crate) fn new(directory: PathBuf, login: [u8; 32]) -> Result<Self> {
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
                    if let Ok(process) = stopper.lock()
                        && let Some(stop) = process.as_ref()
                    {
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
    pub(crate) fn check(&self) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            Err(invalid("local logout, identity change, maintenance or inspection failure stopped this original process").into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn attach(&self, process: &OfflineProcess) -> Result<()> {
        *self
            .process
            .lock()
            .map_err(|_| invalid("offline lifecycle lock failed"))? = Some(process.stop_handle());
        if self.check().is_err() {
            process.stop_handle().stop();
        }
        self.check()
    }
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Ok(process) = self.process.lock()
            && let Some(stop) = process.as_ref()
        {
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
pub(crate) fn input() -> tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>> {
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
