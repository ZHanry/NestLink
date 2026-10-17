use nestlink_protocol::ErrorCode;
use nestlink_remote::{CleanupStatus, LeaseControl, RemoteError};
use nestlink_session::StopReason;
use std::{
    io,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const JOIN_BUDGET: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Default)]
pub struct WorkerStatus {
    pub finished: bool,
    /// Sticky even if the detached worker eventually finishes.
    pub cleanup_timed_out: bool,
    pub error: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReport {
    Joined,
    /// The worker missed the join budget. Owners that promise cleanup receipts
    /// must retain the Worker until its monitor reports completion.
    TimedOutDetached,
}
struct Completion {
    status: Mutex<WorkerStatus>,
    changed: Condvar,
}
#[derive(Clone)]
pub struct WorkerMonitor(Arc<Completion>);
impl WorkerMonitor {
    pub fn status(&self) -> WorkerStatus {
        self.0
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
pub(crate) struct Worker {
    pub(crate) lease: LeaseControl,
    pub(crate) stop: watch::Sender<bool>,
    monitor: WorkerMonitor,
    thread: Option<JoinHandle<()>>,
    shutdown: Option<ShutdownReport>,
}
impl Worker {
    pub(crate) fn spawn(
        name: &str,
        lease: LeaseControl,
        task: impl FnOnce(watch::Receiver<bool>) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let monitor = WorkerMonitor(Arc::new(Completion {
            status: Mutex::new(WorkerStatus::default()),
            changed: Condvar::new(),
        }));
        let completion = monitor.clone();
        let worker_lease = lease.clone();
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let mut result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| task(stopped)))
                        .unwrap_or_else(|_| Err(io::Error::other("media worker panicked")));
                if result
                    .as_ref()
                    .is_err_and(|error| completed_lease_authorization(error, &worker_lease))
                {
                    result = Ok(());
                }
                let _ = if result.is_ok() {
                    worker_lease.stop_if_running(StopReason::ExplicitExit)
                } else {
                    worker_lease.stop(StopReason::PlatformChanged).map(|_| ())
                };
                let mut state = completion
                    .0
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.finished = true;
                state.error = result.err().map(|error| error.to_string());
                completion.0.changed.notify_all();
            })?;
        Ok(Self {
            lease,
            stop,
            monitor,
            thread: Some(thread),
            shutdown: None,
        })
    }
    pub(crate) fn monitor(&self) -> WorkerMonitor {
        self.monitor.clone()
    }
    pub(crate) fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        self.shutdown_inner(reason, false)
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<ShutdownReport> {
        self.shutdown_inner(StopReason::ExplicitExit, true)
    }

    fn shutdown_inner(&mut self, reason: StopReason, cleanup: bool) -> io::Result<ShutdownReport> {
        if let Some(report) = self.shutdown {
            if report == ShutdownReport::TimedOutDetached {
                // A caller may retry after the original bounded wait. Reap
                // the actual thread if it has since exited, but keep the
                // original timeout receipt sticky.
                self.reap_finished()?;
            }
            return Ok(report);
        }
        // No join or codec-state lock is taken by a lease stop handler. A codec
        // still running after this request can never enqueue another packet.
        self.stop.send_replace(true);
        if cleanup {
            self.lease
                .stop_if_running(reason)
                .map_err(io::Error::other)?;
        } else {
            self.lease.stop(reason).map_err(io::Error::other)?;
        }
        let deadline = Instant::now() + JOIN_BUDGET;
        let status = self
            .monitor
            .0
            .status
            .lock()
            .map_err(|_| io::Error::other("media completion poisoned"))?;
        let (status, _) = self
            .monitor
            .0
            .changed
            .wait_timeout_while(status, JOIN_BUDGET, |status| !status.finished)
            .map_err(|_| io::Error::other("media completion poisoned"))?;
        drop(status);
        while self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(1));
        }
        let report = if self.thread.as_ref().is_none_or(JoinHandle::is_finished) {
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("media worker join failed"))?;
            }
            ShutdownReport::Joined
        } else {
            self.monitor
                .0
                .status
                .lock()
                .map_err(|_| io::Error::other("media completion poisoned"))?
                .cleanup_timed_out = true;
            // Keep the join handle. Most callers will drop their Worker after
            // reporting failure, but a session owner can retain it and keep
            // tracking the actual worker cleanup.
            ShutdownReport::TimedOutDetached
        };
        self.shutdown = Some(report);
        Ok(report)
    }

    /// Join the owned thread after it exits following a timed-out shutdown.
    /// This does not change the original shutdown report.
    pub(crate) fn reap_finished(&mut self) -> io::Result<bool> {
        let Some(thread) = self.thread.as_ref() else {
            return Ok(true);
        };
        if !thread.is_finished() {
            return Ok(false);
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("media worker join failed"))?;
        }
        Ok(true)
    }
}

/// A media operation can lose the race to the lease's terminal stop before
/// its worker-specific cancellation signal arrives. Only typed authorization
/// failures backed by an actual successful stop receipt are normal completion.
/// Codec, device, transport and cleanup errors retain their failure semantics.
fn completed_lease_authorization(error: &io::Error, lease: &LeaseControl) -> bool {
    let terminal_authorization = match error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<RemoteError>())
    {
        Some(RemoteError::Stopped) => true,
        Some(RemoteError::Authorization(error)) => matches!(
            error.code,
            ErrorCode::LeaseExpired | ErrorCode::PolicyRevoked
        ),
        _ => false,
    };
    terminal_authorization
        && lease.subscribe_stopped().borrow().is_some_and(|report| {
            matches!(
                report.cleanup,
                CleanupStatus::NotAttached | CleanupStatus::Succeeded
            )
        })
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(crate) fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
pub(crate) fn stopped(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

#[cfg(test)]
mod tests;
