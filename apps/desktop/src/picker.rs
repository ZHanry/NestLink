//! A single owned chooser process. Paths return on a private bounded pipe and
//! are never command arguments. Dropping it closes any old session's OS dialog.
use nestlink_platform_files::selection::{self, MAX_SELECTION_PATH, SelectionKind};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

static MAINTENANCE_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

/// Bind chooser children to the parent's exact isolated state namespace.
pub fn configure_maintenance_directory(directory: &Path) -> io::Result<()> {
    if MAINTENANCE_DIRECTORY
        .get()
        .is_some_and(|current| current == directory)
    {
        return Ok(());
    }
    MAINTENANCE_DIRECTORY
        .set(directory.to_owned())
        .map_err(|_| io::Error::other("chooser maintenance namespace was already configured"))
}

const SELECTOR_BUDGET: Duration = Duration::from_secs(360);
// Includes a cancelled selector until the reaper confirms its physical exit.
// Session changes cannot accumulate native dialogs or cleanup threads.
static SELECTOR_BUSY: AtomicBool = AtomicBool::new(false);
// If the OS cannot create a reaper thread, keep the killed Child here instead
// of moving it into a closure that `thread::spawn` would discard on failure.
// SELECTOR_BUSY bounds this slot to one child.
static PENDING_REAPER: Mutex<Option<Child>> = Mutex::new(None);
static REAPER_RUNNING: AtomicBool = AtomicBool::new(false);

fn lock_pending_reaper() -> std::sync::MutexGuard<'static, Option<Child>> {
    PENDING_REAPER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn start_reaper_if_pending() {
    if lock_pending_reaper().is_none()
        || REAPER_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    // Check again after claiming the worker slot. The closure intentionally
    // owns no Child, so a failed OS thread creation leaves ownership intact.
    if lock_pending_reaper().is_none() {
        REAPER_RUNNING.store(false, Ordering::Release);
        return;
    }
    if std::thread::Builder::new()
        .name("nestlink-file-selector-reaper".into())
        .spawn(reap_pending_child)
        .is_err()
    {
        REAPER_RUNNING.store(false, Ordering::Release);
    }
}

fn reap_child(mut child: Child) {
    loop {
        if child.wait().is_ok() {
            return;
        }
        let _ = child.kill();
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn reap_pending_child() {
    let Some(child) = lock_pending_reaper().take() else {
        REAPER_RUNNING.store(false, Ordering::Release);
        return;
    };
    reap_child(child);
    // Mark the worker idle before releasing the selector slot. A new selector
    // can then never be mistaken for the child this worker just reaped.
    REAPER_RUNNING.store(false, Ordering::Release);
    SELECTOR_BUSY.store(false, Ordering::Release);
}

pub(crate) struct Selector {
    child: Option<Child>,
    deadline: Instant,
}
impl Selector {
    pub(crate) fn start(kind: SelectionKind) -> io::Result<Self> {
        let directory = MAINTENANCE_DIRECTORY
            .get()
            .ok_or_else(|| io::Error::other("chooser maintenance namespace was not configured"))?;
        let _startup = nestlink_local_ipc::maintenance::StartupPermit::acquire(directory)
            .map_err(io::Error::other)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--state-dir")
            .arg(directory)
            .arg("--native-file-selector")
            .arg(match kind {
                SelectionKind::File => "file",
                SelectionKind::Folder => "folder",
            })
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // No console is created. The native selector remains visible.
            command.creation_flags(0x0800_0000);
        }
        if SELECTOR_BUSY.load(Ordering::Acquire) {
            start_reaper_if_pending();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the previous selector is still closing",
            ));
        }
        if SELECTOR_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            start_reaper_if_pending();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the previous selector is still closing",
            ));
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                SELECTOR_BUSY.store(false, Ordering::Release);
                return Err(error);
            }
        };
        Ok(Self {
            child: Some(child),
            deadline: Instant::now() + SELECTOR_BUDGET,
        })
    }

    pub(crate) fn poll(&mut self) -> Option<io::Result<Option<PathBuf>>> {
        let child = self.child.as_mut()?;
        let status = match child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) if Instant::now() < self.deadline => return None,
            Ok(None) => {
                self.close();
                return Some(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local file selection expired",
                )));
            }
            Err(_) => {
                self.close();
                return Some(Err(io::Error::other(
                    "local selector status is unavailable",
                )));
            }
        };
        let child = self.child.take()?;
        let result = match status.code() {
            Some(0) => Self::read_selection(child).map(Some),
            Some(2) => Ok(None),
            _ => Err(io::Error::other("local file selection was unavailable")),
        };
        SELECTOR_BUSY.store(false, Ordering::Release);
        Some(result)
    }
    /// Stop showing a selection dialog while retaining its Child owner until
    /// `poll` observes the actual exit. A replacement selector stays blocked
    /// by SELECTOR_BUSY during this interval.
    pub(crate) fn cancel(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
        }
    }
    fn read_selection(mut child: Child) -> io::Result<PathBuf> {
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("local selector response is unavailable"))?;
        let mut bytes = Vec::new();
        output
            .take(MAX_SELECTION_PATH as u64 + 1)
            .read_to_end(&mut bytes)?;
        let path = std::str::from_utf8(&bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid local selector response",
            )
        })?;
        selection::validate(path)
    }
    fn close(&mut self) {
        // kill/wait target only the Child returned by our own spawn. There is
        // no PID lookup, shell, daemon or another user's dialog to terminate.
        let Some(mut child) = self.child.take() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            SELECTOR_BUSY.store(false, Ordering::Release);
            return;
        }
        let _ = child.kill();
        let mut pending = lock_pending_reaper();
        if pending.is_some() {
            // The single-slot invariant means this is unreachable. Preserve
            // ownership even if that invariant is ever broken, then retry the
            // already-pending child without clearing its busy slot here.
            drop(pending);
            reap_child(child);
            start_reaper_if_pending();
            return;
        }
        *pending = Some(child);
        drop(pending);
        start_reaper_if_pending();
    }
}
impl Drop for Selector {
    fn drop(&mut self) {
        self.close();
    }
}

/// Called before state-directory, daemon or ordinary desktop initialization.
/// Exit 2 means explicit cancellation; exit 1 carries no path/error details.
pub fn run_selector(kind: &str) -> i32 {
    let kind = match kind {
        "file" => SelectionKind::File,
        "folder" => SelectionKind::Folder,
        _ => return 1,
    };
    match selection::choose(kind) {
        Ok(Some(path)) => {
            let Some(path) = path.to_str() else { return 1 };
            // At most 3072 bytes fit the anonymous pipe without requiring the
            // parent to read before observing process exit (Windows: 4096 B).
            if selection::validate(path).is_err() {
                return 1;
            }
            let mut output = io::stdout().lock();
            if output
                .write_all(path.as_bytes())
                .and_then(|()| output.flush())
                .is_ok()
            {
                0
            } else {
                1
            }
        }
        Ok(None) => 2,
        Err(_) => 1,
    }
}
