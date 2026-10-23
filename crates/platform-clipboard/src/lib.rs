//! Local OS clipboard facts, never a source of application authorization.
//! No adapter reads at startup, subscribes to plaintext changes, or saves the
//! user's previous clipboard. Read and write are independently approved.
use std::{
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::WindowsClipboard;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(target_os = "linux")]
mod x11_transport;
#[cfg(target_os = "linux")]
pub use x11::X11Clipboard;
#[cfg(target_os = "linux")]
pub mod portal;

pub const CLIPBOARD_TEXT_BYTES: usize = 64 * 1024;
pub const CLIPBOARD_OPERATION_BUDGET: Duration = Duration::from_millis(250);
/// Maximum actual clipboard worker owners, including blocked startup and Drop
/// owners. A slot is released only after the original thread has been joined.
pub const CLIPBOARD_WORKER_LIMIT: usize = 32;
const TICK: Duration = Duration::from_millis(20);
const STARTUP: Duration = Duration::from_secs(2);
const JOIN_POLL: Duration = Duration::from_millis(1);

static WORKER_SLOTS: AtomicUsize = AtomicUsize::new(0);
static RETAINED_WORKERS: Mutex<Vec<Arc<Shared>>> = Mutex::new(Vec::new());

struct WorkerSlot;
impl WorkerSlot {
    fn reserve() -> io::Result<Self> {
        reap_retained_workers();
        WORKER_SLOTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(1)
                    .filter(|next| *next <= CLIPBOARD_WORKER_LIMIT)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "clipboard actual worker ownership budget exhausted",
                )
            })?;
        Ok(Self)
    }
}
impl Drop for WorkerSlot {
    fn drop(&mut self) {
        WORKER_SLOTS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct OwnedWorker {
    handle: thread::JoinHandle<()>,
    slot: WorkerSlot,
}
enum WorkerState {
    NotStarted,
    Running(OwnedWorker),
    Joining,
    Joined,
}

/// Drop cannot return an error. Keep the same real owner when its original
/// cleanup budget expires; do not detach it or create a second reaper thread.
fn retain_worker(shared: Arc<Shared>) {
    reap_retained_workers();
    let mut retained = RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retained.retain(|owner| !owner.worker_joined());
    if !shared.worker_joined() && !retained.iter().any(|owner| Arc::ptr_eq(owner, &shared)) {
        // Every unfinished owner still holds its pre-spawn WorkerSlot, so
        // this table cannot exceed CLIPBOARD_WORKER_LIMIT distinct workers.
        retained.push(shared);
    }
}

fn reap_retained_workers() {
    let owners = RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for owner in owners {
        owner.try_join();
    }
    RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|owner| !owner.worker_joined());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardDirection {
    Read,
    Write,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardBinding {
    pub session_id: String,
    pub connection_generation: u64,
}
impl ClipboardBinding {
    pub fn validate(&self) -> io::Result<()> {
        if !nestlink_protocol::valid_id(&self.session_id) || self.connection_generation == 0 {
            return Err(invalid(
                "clipboard requires an original session and connection generation",
            ));
        }
        Ok(())
    }
}
/// Implement with the current shared business lease, exact session and
/// connection generation. This check may only observe authority; it must not
/// refresh it or hold a business lock while an OS operation runs.
pub trait ClipboardAuthority: Send + Sync {
    fn check(&self, binding: &ClipboardBinding, direction: ClipboardDirection) -> io::Result<()>;
}
struct ApprovalState {
    binding: ClipboardBinding,
    read: AtomicBool,
    write: AtomicBool,
    live: AtomicBool,
}
/// Move this token into exactly one platform adapter. It is not serializable
/// and cannot be reconstructed from a network message or device ID.
pub struct LocalClipboardApproval(Arc<ApprovalState>);
/// Keep this owner in the local GUI or authenticated local IPC owner. Dropping
/// it ends consent. Revoked directions cannot be enabled again on this token.
pub struct LocalClipboardApprovalControl(Arc<ApprovalState>);
impl LocalClipboardApproval {
    /// Only call after an explicit local user decision naming this session and
    /// the requested directions. Business permission is checked separately.
    pub fn approve_from_local_user(
        binding: ClipboardBinding,
        read: bool,
        write: bool,
    ) -> io::Result<(Self, LocalClipboardApprovalControl)> {
        binding.validate()?;
        if !read && !write {
            return Err(denied("no clipboard direction was locally approved"));
        }
        let state = Arc::new(ApprovalState {
            binding,
            read: AtomicBool::new(read),
            write: AtomicBool::new(write),
            live: AtomicBool::new(true),
        });
        Ok((Self(state.clone()), LocalClipboardApprovalControl(state)))
    }
}
impl LocalClipboardApprovalControl {
    pub fn revoke_read(&self) {
        self.0.read.store(false, Ordering::SeqCst);
    }
    pub fn revoke_write(&self) {
        self.0.write.store(false, Ordering::SeqCst);
    }
    pub fn revoke_all(&self) {
        self.0.live.store(false, Ordering::SeqCst);
        self.revoke_read();
        self.revoke_write();
    }
}
impl Drop for LocalClipboardApprovalControl {
    fn drop(&mut self) {
        self.revoke_all();
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardFailure {
    pub kind: io::ErrorKind,
    pub reason: String,
}
impl ClipboardFailure {
    fn from_error(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            reason: error.to_string(),
        }
    }
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.reason.clone())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardCleanup {
    Pending,
    /// The backend has dropped and its original worker JoinHandle has joined
    /// within the original cleanup deadline, with a successful cleanup proof.
    Complete,
    Failed(ClipboardFailure),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardStatus {
    pub active: bool,
    pub failure: Option<ClipboardFailure>,
    pub cleanup: ClipboardCleanup,
}
struct Facts {
    failure: Option<ClipboardFailure>,
    cleanup: ClipboardCleanup,
    backend_cleanup: Option<Result<(), ClipboardFailure>>,
    cleanup_until: Option<Instant>,
    heartbeat: Instant,
}
struct Shared {
    active: AtomicBool,
    facts: Mutex<Facts>,
    wake: Condvar,
    worker: Mutex<WorkerState>,
}
impl Shared {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
            facts: Mutex::new(Facts {
                failure: None,
                cleanup: ClipboardCleanup::Pending,
                backend_cleanup: None,
                cleanup_until: None,
                heartbeat: Instant::now(),
            }),
            wake: Condvar::new(),
            worker: Mutex::new(WorkerState::NotStarted),
        }
    }
    fn stop(&self, error: Option<&io::Error>) {
        self.active.store(false, Ordering::SeqCst);
        if let Ok(mut facts) = self.facts.lock() {
            if let Some(error) = error {
                facts
                    .failure
                    .get_or_insert_with(|| ClipboardFailure::from_error(error));
            }
            facts
                .cleanup_until
                .get_or_insert_with(|| Instant::now() + CLIPBOARD_OPERATION_BUDGET);
        }
        self.wake.notify_all();
    }
    fn heartbeat(&self) -> io::Result<()> {
        self.facts
            .lock()
            .map_err(|_| io::Error::other("clipboard state poisoned"))?
            .heartbeat = Instant::now();
        Ok(())
    }
    fn backend_closed(&self, outcome: io::Result<()>) {
        self.stop(None);
        if let Ok(mut facts) = self.facts.lock() {
            let outcome = outcome.map_err(|error| ClipboardFailure::from_error(&error));
            if facts.backend_cleanup.is_none() || outcome.is_err() {
                facts.backend_cleanup = Some(outcome);
            }
        }
        self.wake.notify_all();
    }
    fn worker_joined(&self) -> bool {
        matches!(
            *self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            WorkerState::Joined
        )
    }
    fn try_join(&self) {
        let worker = {
            let mut current = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !matches!(&*current, WorkerState::Running(worker) if worker.handle.is_finished()) {
                return;
            }
            match std::mem::replace(&mut *current, WorkerState::Joining) {
                WorkerState::Running(worker) => worker,
                previous => {
                    *current = previous;
                    return;
                }
            }
        };
        let OwnedWorker { handle, slot } = worker;
        let result = handle.join();
        let joined_at = Instant::now();
        // The actual original JoinHandle has returned. No backend, queued
        // command, captured callback, or worker closure can remain alive.
        *self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = WorkerState::Joined;
        self.stop(None);
        match self.facts.lock() {
            Ok(mut facts) => {
                if matches!(facts.cleanup, ClipboardCleanup::Pending) {
                    let outcome = if result.is_err() {
                        Err(ClipboardFailure::from_error(&io::Error::other(
                            "clipboard worker join after panic could not prove cleanup",
                        )))
                    } else {
                        facts.backend_cleanup.clone().unwrap_or_else(|| {
                            Err(ClipboardFailure::from_error(&io::Error::other(
                                "clipboard backend cleanup result is unavailable",
                            )))
                        })
                    };
                    let outcome = if outcome.is_ok()
                        && facts.cleanup_until.is_some_and(|until| joined_at > until)
                    {
                        Err(ClipboardFailure::from_error(&timed_out(
                            "clipboard actual worker join exceeded its original cleanup deadline",
                        )))
                    } else {
                        outcome
                    };
                    facts.cleanup = match outcome {
                        Ok(()) => ClipboardCleanup::Complete,
                        Err(failure) => ClipboardCleanup::Failed(failure),
                    };
                }
            }
            Err(poisoned) => {
                let mut facts = poisoned.into_inner();
                if matches!(facts.cleanup, ClipboardCleanup::Pending) {
                    facts.cleanup = ClipboardCleanup::Failed(ClipboardFailure::from_error(
                        &io::Error::other("clipboard cleanup state unavailable after join"),
                    ));
                }
            }
        }
        drop(slot);
        self.wake.notify_all();
    }
    fn fail_cleanup(&self, error: &io::Error, until: Instant) {
        self.active.store(false, Ordering::SeqCst);
        let mut facts = self
            .facts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        facts
            .failure
            .get_or_insert_with(|| ClipboardFailure::from_error(error));
        facts.cleanup_until.get_or_insert(until);
        if matches!(facts.cleanup, ClipboardCleanup::Pending) {
            facts.cleanup = ClipboardCleanup::Failed(ClipboardFailure::from_error(error));
        }
        self.wake.notify_all();
    }
    fn wait_join_until(&self, until: Instant) -> io::Result<()> {
        loop {
            reap_retained_workers();
            self.try_join();
            let joined = self.worker_joined();
            let facts = self
                .facts
                .lock()
                .map_err(|_| io::Error::other("clipboard cleanup state poisoned"))?;
            if joined {
                match &facts.cleanup {
                    ClipboardCleanup::Complete => return Ok(()),
                    ClipboardCleanup::Failed(failure) => return Err(failure.error()),
                    ClipboardCleanup::Pending => {}
                }
            }
            let deadline = facts
                .cleanup_until
                .map_or(until, |original| original.min(until));
            if Instant::now() >= deadline {
                drop(facts);
                let error = timed_out(
                    "clipboard actual worker has not joined within its original cleanup budget",
                );
                self.fail_cleanup(&error, deadline);
                return Err(error);
            }
            let poll = JOIN_POLL.min(deadline.saturating_duration_since(Instant::now()));
            drop(
                self.wake
                    .wait_timeout(facts, poll)
                    .map_err(|_| io::Error::other("clipboard cleanup state poisoned"))?,
            );
        }
    }
    fn cleanup_deadline(&self) -> Instant {
        self.facts
            .lock()
            .ok()
            .and_then(|facts| facts.cleanup_until)
            .unwrap_or_else(|| Instant::now() + CLIPBOARD_OPERATION_BUDGET)
    }
}
/// Terminal worker facts and cleanup observation. invalidate can only stop;
/// neither this monitor nor local approval can renew business authorization.
#[derive(Clone)]
pub struct ClipboardMonitor(Arc<Shared>);
impl ClipboardMonitor {
    pub fn status(&self) -> ClipboardStatus {
        reap_retained_workers();
        self.0.try_join();
        match self.0.facts.lock() {
            Ok(facts) => {
                let active = self.0.active.load(Ordering::SeqCst)
                    && facts.heartbeat.elapsed() < CLIPBOARD_OPERATION_BUDGET + TICK * 2;
                if !active && self.0.active.load(Ordering::SeqCst) {
                    drop(facts);
                    self.0
                        .stop(Some(&timed_out("clipboard worker heartbeat expired")));
                    return self.status();
                }
                ClipboardStatus {
                    active,
                    failure: facts.failure.clone(),
                    cleanup: facts.cleanup.clone(),
                }
            }
            Err(_) => ClipboardStatus {
                active: false,
                failure: Some(ClipboardFailure::from_error(&io::Error::other(
                    "clipboard state poisoned",
                ))),
                cleanup: ClipboardCleanup::Failed(ClipboardFailure::from_error(&io::Error::other(
                    "clipboard cleanup state unavailable",
                ))),
            },
        }
    }
    pub fn invalidate(&self) {
        self.0.stop(Some(&denied("clipboard session invalidated")));
    }
    pub fn wait_cleanup_until(&self, until: Instant) -> io::Result<()> {
        self.0.wait_join_until(until)
    }
}
#[derive(Clone)]
pub(crate) struct Context {
    binding: ClipboardBinding,
    approval: Arc<ApprovalState>,
    authority: Arc<dyn ClipboardAuthority>,
    shared: Arc<Shared>,
}
impl Context {
    fn approved(&self, direction: ClipboardDirection) -> bool {
        match direction {
            ClipboardDirection::Read => self.approval.read.load(Ordering::SeqCst),
            ClipboardDirection::Write => self.approval.write.load(Ordering::SeqCst),
        }
    }
    pub(crate) fn live(&self, until: Instant) -> io::Result<()> {
        if Instant::now() >= until {
            return Err(timed_out("clipboard operation deadline exhausted"));
        }
        if !self.shared.active.load(Ordering::SeqCst) || !self.approval.live.load(Ordering::SeqCst)
        {
            return Err(denied("clipboard consent or worker is terminal"));
        }
        Ok(())
    }
    pub(crate) fn check(&self, direction: ClipboardDirection, until: Instant) -> io::Result<()> {
        self.live(until)?;
        if self.binding != self.approval.binding {
            return Err(denied(
                "clipboard local approval belongs to a different session",
            ));
        }
        if !self.approved(direction) {
            return Err(denied("clipboard direction has no current local approval"));
        }
        self.authority.check(&self.binding, direction)?;
        self.live(until)?;
        if !self.approved(direction) {
            return Err(denied(
                "clipboard direction was revoked during authority observation",
            ));
        }
        Ok(())
    }
    fn check_all(&self, until: Instant) -> io::Result<()> {
        self.live(until)?;
        let mut approved = false;
        for direction in [ClipboardDirection::Read, ClipboardDirection::Write] {
            if self.approved(direction) {
                match self.check(direction, until) {
                    Ok(()) => approved = true,
                    // A direction can be revoked between observing its bit
                    // and querying the business lease. Preserve the separately
                    // approved direction instead of treating that race as OS loss.
                    Err(_) if !self.approved(direction) && self.live(until).is_ok() => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.live(until)?;
        if !approved
            || (!self.approved(ClipboardDirection::Read)
                && !self.approved(ClipboardDirection::Write))
        {
            return Err(denied("all clipboard directions were revoked"));
        }
        Ok(())
    }
}
pub(crate) trait Backend {
    fn check(&mut self, until: Instant) -> io::Result<()>;
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>>;
    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()>;
    fn service(&mut self, context: &Context, until: Instant) -> io::Result<()>;
    fn close(&mut self, until: Instant) -> io::Result<()>;
}
enum Operation {
    Check,
    Read,
    Write(Zeroizing<String>),
}
enum Reply {
    Done,
    Text(Option<Zeroizing<String>>),
}
struct Command {
    operation: Operation,
    until: Instant,
    reply: mpsc::SyncSender<io::Result<Reply>>,
}
/// Transferable adapter owner. OS resources and selection servicing stay on
/// the owned worker, with one queued operation and one bounded text value.
/// Factory open may return an inactive failed owner when a started worker
/// cannot prove timely cleanup. Always check before installing the adapter;
/// a startup failure remains the check result even after the worker joins.
pub struct ClipboardDevice {
    context: Context,
    commands: mpsc::SyncSender<Command>,
    startup_failure: Option<ClipboardFailure>,
}
/// Retain with pending text and check immediately before remote disclosure or
/// a later OS write. This observes the original direction, local consent,
/// business lease and worker; it cannot extend any of their lifetimes.
#[derive(Clone)]
pub struct ClipboardDirectionGuard {
    context: Context,
    direction: ClipboardDirection,
}
impl ClipboardDirectionGuard {
    pub fn binding(&self) -> &ClipboardBinding {
        &self.context.binding
    }
    pub fn direction(&self) -> ClipboardDirection {
        self.direction
    }
    pub fn check(&self) -> io::Result<()> {
        self.check_until(Instant::now() + CLIPBOARD_OPERATION_BUDGET)
    }
    /// The caller supplies the pending operation's original deadline. A
    /// successful check never renews that deadline or authorizes a new session.
    pub fn check_until(&self, until: Instant) -> io::Result<()> {
        if !ClipboardMonitor(self.context.shared.clone())
            .status()
            .active
        {
            return Err(denied(
                "clipboard worker ended before pending text delivery",
            ));
        }
        self.context.check(self.direction, until)
    }
}
pub trait NativeClipboard: Send {
    fn binding(&self) -> &ClipboardBinding;
    fn monitor(&self) -> ClipboardMonitor;
    fn direction_guard(&self, direction: ClipboardDirection) -> ClipboardDirectionGuard;
    /// Required after factory open, before declaring the owner ready. An
    /// inactive failed owner preserves the original startup error and worker.
    fn check(&mut self) -> io::Result<()>;
    fn read_text(&mut self) -> io::Result<Option<String>>;
    fn write_text(&mut self, text: &str) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}
impl ClipboardDevice {
    /// An Ok owner is not a readiness proof: call check before installing it.
    /// Failed startup returns Err only after cleanup and the original worker
    /// join are proved. Otherwise the inactive owner preserves that same
    /// thread, and check returns the original startup failure.
    pub(crate) fn open<F>(
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
        open: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(Instant) -> io::Result<Box<dyn Backend>> + Send + 'static,
    {
        Self::open_with_budget(binding, approval, authority, STARTUP, open)
    }
    fn open_with_budget<F>(
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
        startup_budget: Duration,
        open: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(Instant) -> io::Result<Box<dyn Backend>> + Send + 'static,
    {
        binding.validate()?;
        if binding != approval.0.binding {
            return Err(denied("clipboard local consent binding mismatch"));
        }
        let shared = Arc::new(Shared::new());
        let context = Context {
            binding,
            approval: approval.0,
            authority,
            shared: shared.clone(),
        };
        let until = Instant::now() + startup_budget;
        context.check_all(until)?;
        let slot = WorkerSlot::reserve()?;
        let (commands, receive) = mpsc::sync_channel(1);
        let (ready, result) = mpsc::sync_channel(1);
        let owned = context.clone();
        let worker = thread::Builder::new()
            .name("nestlink-native-clipboard".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(owned.clone(), receive, ready.clone(), until, open)
                }));
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ =
                            ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                        owned.shared.stop(Some(&error));
                        if owned
                            .shared
                            .facts
                            .lock()
                            .is_ok_and(|facts| facts.backend_cleanup.is_none())
                        {
                            // run returned before taking a backend. The open
                            // callback and all of its captures have also dropped.
                            // This private fact still requires the real join.
                            owned.shared.backend_closed(Ok(()));
                        }
                    }
                    Err(_) => {
                        let error = io::Error::other("clipboard worker panicked");
                        let _ =
                            ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                        owned.shared.stop(Some(&error));
                        owned.shared.backend_closed(Err(io::Error::other(
                            "clipboard cleanup after panic could not be proven",
                        )));
                    }
                }
            })?;
        *shared
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            WorkerState::Running(OwnedWorker {
                handle: worker,
                slot,
            });
        match result.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => Ok(Self {
                context,
                commands,
                startup_failure: None,
            }),
            result => {
                let error = match result {
                    Ok(Err(error)) => error,
                    _ => timed_out(
                        "clipboard worker startup did not complete within its original budget",
                    ),
                };
                shared.stop(Some(&error));
                // Startup may already have failed while backend destruction
                // blocks the ready reply. Preserve that earlier failure.
                let failure = shared
                    .facts
                    .lock()
                    .ok()
                    .and_then(|facts| facts.failure.clone())
                    .unwrap_or_else(|| ClipboardFailure::from_error(&error));
                let error = failure.error();
                let mut device = Self {
                    context,
                    commands,
                    startup_failure: Some(failure),
                };
                let _ = device.close();
                if shared.worker_joined()
                    && matches!(
                        device.monitor().status().cleanup,
                        ClipboardCleanup::Complete
                    )
                {
                    Err(error)
                } else {
                    Ok(device)
                }
            }
        }
    }
    fn execute(&self, operation: Operation) -> io::Result<Reply> {
        let until = Instant::now() + CLIPBOARD_OPERATION_BUDGET;
        let direction = match &operation {
            Operation::Read => Some(ClipboardDirection::Read),
            Operation::Write(_) => Some(ClipboardDirection::Write),
            Operation::Check => None,
        };
        self.context.live(until)?;
        if let Some(direction) = direction {
            self.context.check(direction, until)?;
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command {
                operation,
                until,
                reply,
            })
            .map_err(|_| denied("clipboard worker operation queue unavailable"))?;
        match response.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(result) => {
                let value = result?;
                if let Some(direction) = direction {
                    self.context.check(direction, until)?;
                }
                self.context.live(until)?;
                Ok(value)
            }
            Err(_) => {
                let error =
                    timed_out("clipboard operation did not complete within its original budget");
                self.context.shared.stop(Some(&error));
                Err(error)
            }
        }
    }
}
impl NativeClipboard for ClipboardDevice {
    fn binding(&self) -> &ClipboardBinding {
        &self.context.binding
    }
    fn monitor(&self) -> ClipboardMonitor {
        ClipboardMonitor(self.context.shared.clone())
    }
    fn direction_guard(&self, direction: ClipboardDirection) -> ClipboardDirectionGuard {
        ClipboardDirectionGuard {
            context: self.context.clone(),
            direction,
        }
    }
    fn check(&mut self) -> io::Result<()> {
        if let Some(failure) = &self.startup_failure {
            return Err(failure.error());
        }
        self.execute(Operation::Check).map(|_| ())
    }
    fn read_text(&mut self) -> io::Result<Option<String>> {
        match self.execute(Operation::Read)? {
            Reply::Text(text) => Ok(text.map(|value| value.to_string())),
            Reply::Done => Err(io::Error::other(
                "clipboard worker returned a mismatched read reply",
            )),
        }
    }
    fn write_text(&mut self, text: &str) -> io::Result<()> {
        validate_text(text)?;
        self.execute(Operation::Write(Zeroizing::new(text.to_owned())))
            .map(|_| ())
    }
    fn close(&mut self) -> io::Result<()> {
        self.context.shared.stop(None);
        self.context
            .shared
            .wait_join_until(self.context.shared.cleanup_deadline())
    }
}
impl Drop for ClipboardDevice {
    fn drop(&mut self) {
        let _ = self.close();
        if !self.context.shared.worker_joined() {
            retain_worker(self.context.shared.clone());
        }
    }
}
fn run<F>(
    context: Context,
    receive: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<io::Result<()>>,
    until: Instant,
    open: F,
) -> io::Result<()>
where
    F: FnOnce(Instant) -> io::Result<Box<dyn Backend>>,
{
    context.check_all(until)?;
    let mut backend = open(until)?;
    let outcome = (|| {
        backend.check(until)?;
        context.check_all(until)?;
        context.shared.heartbeat()?;
        ready
            .try_send(Ok(()))
            .map_err(|_| denied("clipboard caller ended before startup"))?;
        while context.shared.active.load(Ordering::SeqCst) {
            let until = Instant::now() + CLIPBOARD_OPERATION_BUDGET;
            context.check_all(until)?;
            backend.check(until)?;
            backend.service(&context, until)?;
            context.shared.heartbeat()?;
            match receive.recv_timeout(TICK) {
                Ok(command) => {
                    let result: io::Result<Reply> = (|| {
                        context.live(command.until)?;
                        backend.check(command.until)?;
                        match command.operation {
                            Operation::Check => {
                                context.check_all(command.until)?;
                                Ok(Reply::Done)
                            }
                            Operation::Read => {
                                context.check(ClipboardDirection::Read, command.until)?;
                                let text = backend.read(&context, command.until)?;
                                if let Some(text) = &text {
                                    validate_text(text)?;
                                }
                                context.check(ClipboardDirection::Read, command.until)?;
                                Ok(Reply::Text(text))
                            }
                            Operation::Write(text) => {
                                context.check(ClipboardDirection::Write, command.until)?;
                                backend.write(&text, &context, command.until)?;
                                context.check(ClipboardDirection::Write, command.until)?;
                                Ok(Reply::Done)
                            }
                        }
                    })();
                    if let Err(error) = &result
                        && !matches!(
                            error.kind(),
                            io::ErrorKind::InvalidInput
                                | io::ErrorKind::InvalidData
                                | io::ErrorKind::NotFound
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::Unsupported
                        )
                    {
                        context.shared.stop(Some(error));
                    }
                    let _ = command.reply.try_send(result);
                    context.shared.heartbeat()?;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(())
    })();
    if let Err(error) = &outcome {
        context.shared.stop(Some(error));
    }
    context.shared.stop(None);
    let cleanup = backend.close(context.shared.cleanup_deadline());
    drop(backend);
    context.shared.backend_closed(cleanup);
    outcome
}
pub(crate) fn validate_text(text: &str) -> io::Result<()> {
    if text.len() > CLIPBOARD_TEXT_BYTES || text.contains('\0') {
        return Err(invalid(
            "clipboard text exceeds its UTF-8 budget or contains NUL",
        ));
    }
    Ok(())
}
pub(crate) fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
pub(crate) fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
pub(crate) fn timed_out(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, reason)
}

#[cfg(test)]
mod tests;
