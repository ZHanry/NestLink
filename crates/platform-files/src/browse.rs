//! Consent-scoped, bounded directory metadata. Disk operations belong to the
//! owned worker or an explicitly blocking caller, never an async executor.
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use nestlink_protocol::{FILE_ROOT_DISPLAY_NAME_BYTES, files::validate_relative_path, valid_id};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};
pub mod network;

pub const DIRECTORY_MAX_ENTRIES: usize = 4096;
pub const DIRECTORY_MAX_NAME_BYTES: usize = 1024 * 1024;
pub const DIRECTORY_PAGE_ENTRIES: usize = 128;
pub const DIRECTORY_OPERATION_BUDGET: Duration = Duration::from_secs(30);
pub const DIRECTORY_CURSOR_LIFETIME: Duration = Duration::from_secs(300);
pub const DIRECTORY_CLEANUP_BUDGET: Duration = Duration::from_millis(250);

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
fn changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "directory metadata changed; start a fresh browse",
    )
}
fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "directory operation budget expired",
    )
}
fn cursor_expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "directory cursor expired; start a fresh browse",
    )
}

/// These local limits may be lowered, but cannot exceed the hard bounds.
#[derive(Clone, Copy, Debug)]
pub struct BrowseLimits {
    maximum_entries: usize,
    maximum_name_bytes: usize,
    operation_budget: Duration,
    cursor_lifetime: Duration,
}
impl BrowseLimits {
    pub fn new(
        maximum_entries: usize,
        maximum_name_bytes: usize,
        operation_budget: Duration,
        cursor_lifetime: Duration,
    ) -> io::Result<Self> {
        if maximum_entries == 0
            || maximum_entries > DIRECTORY_MAX_ENTRIES
            || maximum_name_bytes == 0
            || maximum_name_bytes > DIRECTORY_MAX_NAME_BYTES
            || operation_budget.is_zero()
            || operation_budget > DIRECTORY_OPERATION_BUDGET
            || cursor_lifetime.is_zero()
            || cursor_lifetime > DIRECTORY_CURSOR_LIFETIME
        {
            return Err(invalid("directory limits exceed the fixed bounds"));
        }
        Ok(Self {
            maximum_entries,
            maximum_name_bytes,
            operation_budget,
            cursor_lifetime,
        })
    }
}
impl Default for BrowseLimits {
    fn default() -> Self {
        Self {
            maximum_entries: DIRECTORY_MAX_ENTRIES,
            maximum_name_bytes: DIRECTORY_MAX_NAME_BYTES,
            operation_budget: DIRECTORY_OPERATION_BUDGET,
            cursor_lifetime: DIRECTORY_CURSOR_LIFETIME,
        }
    }
}

struct ConsentState {
    active: AtomicBool,
    revoked_at: Mutex<Option<Instant>>,
}
impl ConsentState {
    fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    fn revoke(&self) {
        self.revoked_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get_or_insert_with(Instant::now);
        self.active.store(false, Ordering::Release);
    }
    fn revoked_at(&self) -> Option<Instant> {
        *self
            .revoked_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}
impl nestlink_remote::files::FileReadConsent for ConsentState {
    fn check(&self) -> io::Result<()> {
        if self.active() {
            Ok(())
        } else {
            Err(denied("local directory consent revoked"))
        }
    }
}
/// One owner for the separate local decision to disclose directory metadata.
/// Revoke or drop it to invalidate idle cursors and pending worker replies.
pub struct BrowseConsent(Arc<ConsentState>);
impl BrowseConsent {
    pub fn revoke(&self) {
        self.0.revoke();
    }
}
impl Drop for BrowseConsent {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Only the local application supplies this native path and root identity.
/// Selection itself performs no filesystem I/O.
pub struct BrowseSelection {
    id: String,
    display_name: String,
    local_path: PathBuf,
    limits: BrowseLimits,
    consent: Arc<ConsentState>,
}
impl BrowseSelection {
    pub fn new(
        id: &str,
        local_absolute_directory: &Path,
        limits: BrowseLimits,
    ) -> io::Result<(Self, BrowseConsent)> {
        let display_name = local_absolute_directory
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Selected folder".into());
        Self::new_with_display_name(id, &display_name, local_absolute_directory, limits)
    }

    /// Construct from a local chooser's explicit display label. The label is
    /// the only root metadata sent to a peer; `local_absolute_directory` never
    /// enters the protocol or product-visible status.
    pub fn new_with_display_name(
        id: &str,
        display_name: &str,
        local_absolute_directory: &Path,
        limits: BrowseLimits,
    ) -> io::Result<(Self, BrowseConsent)> {
        if !valid_id(id) || !local_absolute_directory.is_absolute() {
            return Err(invalid(
                "invalid local directory identity or absolute selection",
            ));
        }
        if display_name.is_empty()
            || display_name.len() as u64 > FILE_ROOT_DISPLAY_NAME_BYTES
            || display_name.trim() != display_name
            || display_name
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
        {
            return Err(invalid("invalid selected directory display name"));
        }
        let consent = Arc::new(ConsentState {
            active: AtomicBool::new(true),
            revoked_at: Mutex::new(None),
        });
        Ok((
            Self {
                id: id.into(),
                display_name: display_name.into(),
                local_path: local_absolute_directory.into(),
                limits,
                consent: consent.clone(),
            },
            BrowseConsent(consent),
        ))
    }
    /// Blocking. Prefer `DirectoryWorker::start` for product use. No disk I/O
    /// is performed inside the authorization callback.
    pub fn open(
        self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<ApprovedBrowseRoot> {
        let started = Instant::now();
        let mut check = || {
            authorized()?;
            if !self.consent.active() {
                return Err(denied("local directory consent revoked"));
            }
            if started.elapsed() >= self.limits.operation_budget {
                return Err(expired());
            }
            Ok(())
        };
        check()?;
        // Only this local selection is ambient. Its final component must not
        // be a link; every peer-provided lookup below is handle-relative.
        let directory = match (self.local_path.parent(), self.local_path.file_name()) {
            (Some(parent), Some(name)) => {
                let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
                check()?;
                parent.open_dir_nofollow(name)?
            }
            _ => Dir::open_ambient_dir(&self.local_path, cap_std::ambient_authority())?,
        };
        check()?;
        let metadata = directory.dir_metadata()?;
        safe_directory(&metadata, metadata.dev())?;
        check()?;
        Ok(ApprovedBrowseRoot {
            id: self.id,
            directory,
            device: metadata.dev(),
            limits: self.limits,
            consent: self.consent,
            owner: Arc::new(()),
            snapshot: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowseEntryKind {
    File,
    Directory,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowseEntry {
    pub name: String,
    pub kind: BrowseEntryKind,
    /// Directories have no claimed content length.
    pub size: Option<u64>,
    pub modified: SystemTime,
}

/// A local, non-serializable capability, not a remote token or a root grant.
/// It is bound to one root handle, one snapshot and one expected next offset.
#[derive(Debug)]
pub struct BrowseCursor {
    owner: Arc<()>,
    snapshot: Arc<()>,
    offset: usize,
}
#[derive(Debug)]
pub struct BrowsePage {
    pub root_id: String,
    pub directory: Option<String>,
    pub total_entries: usize,
    pub entries: Vec<BrowseEntry>,
    pub next: Option<BrowseCursor>,
    snapshot_started: Instant,
    cursor_lifetime: Duration,
}
impl BrowsePage {
    fn check_lifetime(&self) -> io::Result<()> {
        if self.snapshot_started.elapsed() >= self.cursor_lifetime {
            return Err(cursor_expired());
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    links: u64,
    size: u64,
    modified: SystemTime,
}
impl Stamp {
    fn new(metadata: &Metadata) -> io::Result<Self> {
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            size: metadata.len(),
            modified: metadata.modified()?.into_std(),
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
struct ScannedEntry {
    entry: BrowseEntry,
    stamp: Stamp,
}
struct Snapshot {
    directory: Dir,
    path: Option<String>,
    stamp: Stamp,
    entries: Vec<ScannedEntry>,
    identity: Arc<()>,
    next: usize,
    started: Instant,
}

fn no_reparse(metadata: &Metadata) -> io::Result<()> {
    #[cfg(windows)]
    {
        use cap_fs_ext::OsMetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(denied("directory metadata cannot disclose a reparse point"));
        }
    }
    #[cfg(not(windows))]
    let _ = metadata;
    Ok(())
}
fn safe_directory(metadata: &Metadata, device: u64) -> io::Result<()> {
    no_reparse(metadata)?;
    if !metadata.is_dir() || metadata.dev() != device {
        return Err(denied("directory must remain on the approved filesystem"));
    }
    Ok(())
}

/// A pinned selected root and at most one active directory snapshot.
pub struct ApprovedBrowseRoot {
    id: String,
    directory: Dir,
    device: u64,
    limits: BrowseLimits,
    consent: Arc<ConsentState>,
    owner: Arc<()>,
    snapshot: Option<Snapshot>,
}
impl ApprovedBrowseRoot {
    pub fn id(&self) -> &str {
        &self.id
    }
    fn checked<'a>(
        &'a self,
        authorized: &'a mut dyn FnMut() -> io::Result<()>,
        started: Instant,
    ) -> impl FnMut() -> io::Result<()> + 'a {
        move || {
            authorized()?;
            if !self.consent.active() {
                return Err(denied("local directory consent revoked"));
            }
            if started.elapsed() >= self.limits.operation_budget {
                return Err(expired());
            }
            Ok(())
        }
    }
    fn target(
        &self,
        relative_path: Option<&str>,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Dir> {
        let mut directory = self.directory.try_clone()?;
        check()?;
        if let Some(path) = relative_path {
            validate_relative_path(path).map_err(|_| invalid("invalid portable directory path"))?;
            for component in path.split('/') {
                check()?;
                directory = directory.open_dir_nofollow(component)?;
                check()?;
                safe_directory(&directory.dir_metadata()?, self.device)?;
            }
        }
        check()?;
        Ok(directory)
    }
    fn scan(
        &self,
        directory: &Dir,
        relative_path: Option<&str>,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(Stamp, Vec<ScannedEntry>)> {
        check()?;
        let before = directory.dir_metadata()?;
        safe_directory(&before, self.device)?;
        let before = Stamp::new(&before)?;
        check()?;
        let mut entries = Vec::new();
        let mut name_bytes: usize = 0;
        let mut iterator = directory.entries()?;
        loop {
            check()?;
            let Some(item) = iterator.next() else { break };
            check()?;
            let item = item?;
            if entries.len() >= self.limits.maximum_entries {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "directory exceeds the locally approved entry limit",
                ));
            }
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| denied("directory entry is not portable UTF-8"))?;
            validate_relative_path(&name)
                .map_err(|_| denied("directory entry name is not portable"))?;
            if name.contains('/') {
                return Err(denied("directory entry must be one portable component"));
            }
            if let Some(path) = relative_path {
                validate_relative_path(&format!("{path}/{name}"))
                    .map_err(|_| denied("directory entry exceeds the portable path bounds"))?;
            }
            name_bytes = name_bytes
                .checked_add(name.len())
                .ok_or_else(|| invalid("directory name byte budget overflow"))?;
            if name_bytes > self.limits.maximum_name_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "directory exceeds the locally approved name byte limit",
                ));
            }
            check()?;
            let kind = item.file_type()?;
            check()?;
            let (kind, metadata) = if kind.is_dir() {
                let child = directory.open_dir_nofollow(&name)?;
                check()?;
                let metadata = child.dir_metadata()?;
                safe_directory(&metadata, self.device)?;
                (BrowseEntryKind::Directory, metadata)
            } else if kind.is_file() {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                #[cfg(unix)]
                {
                    use cap_std::fs::OpenOptionsExt;
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    // O_PATH metadata opens do not invoke device/FIFO open
                    // behavior. Do not add NONBLOCK: openat2 rejects that
                    // unused flag in combination with O_PATH.
                    let flags = rustix::fs::OFlags::PATH;
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    let flags = rustix::fs::OFlags::NONBLOCK;
                    options.custom_flags(flags.bits() as i32);
                }
                #[cfg(windows)]
                {
                    use cap_std::fs::OpenOptionsExt;
                    // FILE_READ_ATTRIBUTES, with read sharing only. Browsing
                    // does not acquire FILE_READ_DATA authority.
                    options.access_mode(0x80).share_mode(1);
                }
                let child = directory.open_with(&name, &options)?;
                check()?;
                let metadata = child.metadata()?;
                no_reparse(&metadata)?;
                if !metadata.is_file() || metadata.dev() != self.device || metadata.nlink() != 1 {
                    return Err(denied(
                        "directory entry must be a regular single-link file on the approved filesystem",
                    ));
                }
                (BrowseEntryKind::File, metadata)
            } else {
                return Err(denied("directory entry cannot be a link or special file"));
            };
            check()?;
            let stamp = Stamp::new(&metadata)?;
            entries.push(ScannedEntry {
                entry: BrowseEntry {
                    name,
                    kind,
                    size: (kind == BrowseEntryKind::File).then_some(metadata.len()),
                    modified: stamp.modified,
                },
                stamp,
            });
        }
        check()?;
        let after = directory.dir_metadata()?;
        safe_directory(&after, self.device)?;
        if Stamp::new(&after)? != before {
            return Err(changed());
        }
        entries.sort_unstable_by(|left, right| left.entry.name.cmp(&right.entry.name));
        if entries
            .windows(2)
            .any(|pair| pair[0].entry.name == pair[1].entry.name)
        {
            return Err(changed());
        }
        check()?;
        Ok((before, entries))
    }
    fn page(
        &self,
        snapshot: &mut Snapshot,
        maximum: usize,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<BrowsePage> {
        let snapshot_started = snapshot.started;
        let mut in_snapshot = || {
            check()?;
            if snapshot_started.elapsed() >= self.limits.cursor_lifetime {
                return Err(cursor_expired());
            }
            Ok(())
        };
        in_snapshot()?;
        let (stamp, entries) = self.scan(
            &snapshot.directory,
            snapshot.path.as_deref(),
            &mut in_snapshot,
        )?;
        if stamp != snapshot.stamp || entries != snapshot.entries {
            return Err(changed());
        }
        let end = snapshot
            .next
            .saturating_add(maximum)
            .min(snapshot.entries.len());
        let entries = snapshot.entries[snapshot.next..end]
            .iter()
            .map(|entry| entry.entry.clone())
            .collect();
        in_snapshot()?;
        snapshot.next = end;
        Ok(BrowsePage {
            root_id: self.id.clone(),
            directory: snapshot.path.clone(),
            total_entries: snapshot.entries.len(),
            entries,
            next: (end < snapshot.entries.len()).then(|| BrowseCursor {
                owner: self.owner.clone(),
                snapshot: snapshot.identity.clone(),
                offset: end,
            }),
            snapshot_started: snapshot.started,
            cursor_lifetime: self.limits.cursor_lifetime,
        })
    }
    /// `None` lists the selected root. A nonempty portable relative path lists
    /// one descendant. This replaces any previous snapshot, even on failure.
    pub fn begin(
        &mut self,
        relative_path: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<BrowsePage> {
        self.snapshot = None;
        if maximum == 0 || maximum > DIRECTORY_PAGE_ENTRIES {
            return Err(invalid("invalid bounded directory page size"));
        }
        let started = Instant::now();
        let (page, snapshot) = {
            let mut operation = self.checked(authorized, started);
            let mut check = || {
                operation()?;
                if started.elapsed() >= self.limits.cursor_lifetime {
                    return Err(cursor_expired());
                }
                Ok(())
            };
            check()?;
            let directory = self.target(relative_path, &mut check)?;
            let (stamp, entries) = self.scan(&directory, relative_path, &mut check)?;
            let mut snapshot = Snapshot {
                directory,
                path: relative_path.map(str::to_owned),
                stamp,
                entries,
                identity: Arc::new(()),
                next: 0,
                started,
            };
            let page = self.page(&mut snapshot, maximum, &mut check)?;
            (page, snapshot)
        };
        if page.next.is_some() {
            self.snapshot = Some(snapshot);
        }
        Ok(page)
    }
    /// Revalidate the complete bounded metadata snapshot before returning the
    /// next page. Failed or stale requests retire it; callers must refresh.
    pub fn next(
        &mut self,
        cursor: &BrowseCursor,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<BrowsePage> {
        let mut snapshot = self
            .snapshot
            .take()
            .ok_or_else(|| invalid("directory snapshot is not active"))?;
        if maximum == 0
            || maximum > DIRECTORY_PAGE_ENTRIES
            || !Arc::ptr_eq(&cursor.owner, &self.owner)
            || !Arc::ptr_eq(&cursor.snapshot, &snapshot.identity)
            || cursor.offset != snapshot.next
        {
            return Err(invalid(
                "directory cursor does not match the expected snapshot page",
            ));
        }
        let page = {
            let mut check = self.checked(authorized, Instant::now());
            self.page(&mut snapshot, maximum, &mut check)?
        };
        if page.next.is_some() {
            self.snapshot = Some(snapshot);
        }
        Ok(page)
    }
    pub fn retire(&mut self) {
        self.snapshot = None;
    }
}

type CurrentAuthorization = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;
#[derive(Clone)]
struct Checkpoint {
    consent: Arc<ConsentState>,
    stopping: Arc<AtomicBool>,
    operation_cancelled: Arc<AtomicBool>,
    authorization: CurrentAuthorization,
    started: Instant,
    budget: Duration,
    monitor: DirectoryMonitor,
}
impl Checkpoint {
    fn check(&self) -> io::Result<()> {
        if let Err(error) = (self.authorization)() {
            self.stopping.store(true, Ordering::Release);
            self.monitor.stop();
            return Err(error);
        }
        if !self.consent.active() {
            self.stopping.store(true, Ordering::Release);
            self.monitor.stop();
            return Err(denied("local directory consent revoked"));
        }
        if self.stopping.load(Ordering::Acquire) || self.operation_cancelled.load(Ordering::Acquire)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "directory operation cancelled",
            ));
        }
        if self.started.elapsed() >= self.budget {
            return Err(expired());
        }
        Ok(())
    }
}
/// Poll with `try_result` from async code; it never waits for disk or joins a
/// thread. Dropping a pending ticket cancels only this operation.
pub struct BrowseTicket<T> {
    receiver: Option<Receiver<io::Result<T>>>,
    checkpoint: Checkpoint,
    slot: Arc<WorkSlot>,
    validate: fn(&T) -> io::Result<()>,
    consumed: bool,
}
impl<T> BrowseTicket<T> {
    pub fn try_result(&mut self) -> io::Result<Option<T>> {
        if self.consumed {
            return Err(invalid("directory reply was already consumed or cancelled"));
        }
        if let Err(error) = self.checkpoint.check() {
            self.consumed = true;
            self.checkpoint
                .operation_cancelled
                .store(true, Ordering::Release);
            self.receiver.take();
            self.slot.retire();
            return Err(error);
        }
        let receiver = self
            .receiver
            .as_ref()
            .ok_or_else(|| invalid("directory reply receiver was already retired"))?;
        match receiver.try_recv() {
            Ok(result) => {
                self.consumed = true;
                self.receiver.take();
                self.slot.retire();
                self.checkpoint.check()?;
                let result = result?;
                (self.validate)(&result)?;
                Ok(Some(result))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.consumed = true;
                self.receiver.take();
                self.slot.retire();
                Err(io::Error::other("directory worker stopped without a reply"))
            }
        }
    }
}
impl<T> Drop for BrowseTicket<T> {
    fn drop(&mut self) {
        if !self.consumed {
            self.checkpoint
                .operation_cancelled
                .store(true, Ordering::Release);
            self.slot.retire();
        }
    }
}

struct WorkSlot {
    state: AtomicU8,
    busy: Arc<AtomicBool>,
}
impl WorkSlot {
    fn new(busy: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(0),
            busy,
        })
    }
    fn complete(&self) {
        if self.state.fetch_or(1, Ordering::AcqRel) & 2 != 0 {
            self.busy.store(false, Ordering::Release);
        }
    }
    fn retire(&self) {
        if self.state.fetch_or(2, Ordering::AcqRel) & 1 != 0 {
            self.busy.store(false, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryWorkerStatus {
    pub active: bool,
    pub root_opened: bool,
    pub handles_closed: bool,
    /// Owned root/snapshot/iterator handles have been destroyed. Native thread
    /// exit is certified separately by `poll_shutdown() == Finished`.
    pub finished: bool,
    pub cleanup_timed_out: bool,
    pub failed_operations: u64,
    pub completed_operations: u64,
}
#[derive(Clone)]
pub struct DirectoryMonitor(Arc<Mutex<MonitorState>>);
struct MonitorState {
    status: DirectoryWorkerStatus,
    stopped_at: Option<Instant>,
    consent: Arc<ConsentState>,
}
impl MonitorState {
    fn observe_timeout(&mut self) {
        if let Some(revoked) = self.consent.revoked_at() {
            self.stopped_at = Some(
                self.stopped_at
                    .map_or(revoked, |previous| previous.min(revoked)),
            );
        }
        if self
            .stopped_at
            .is_some_and(|started| started.elapsed() >= DIRECTORY_CLEANUP_BUDGET)
        {
            self.status.cleanup_timed_out = true;
        }
    }
}
impl DirectoryMonitor {
    pub fn status(&self) -> DirectoryWorkerStatus {
        let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        if !state.status.finished {
            state.observe_timeout();
        }
        state.status
    }
    fn update(&self, change: impl FnOnce(&mut DirectoryWorkerStatus)) {
        let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        change(&mut state.status);
    }
    fn stop(&self) {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .stopped_at
            .get_or_insert_with(Instant::now);
    }
    fn finished(&self) {
        let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        if !state.status.finished {
            state.observe_timeout();
            state.status.active = false;
            state.status.handles_closed = true;
            state.status.finished = true;
            if thread::panicking() {
                state.status.failed_operations = state.status.failed_operations.saturating_add(1);
            }
        }
    }
}
struct Teardown(DirectoryMonitor, Arc<AtomicBool>);
impl Drop for Teardown {
    fn drop(&mut self) {
        self.1.store(true, Ordering::Release);
        self.0.finished();
    }
}
enum Command {
    Begin(
        Option<String>,
        usize,
        Checkpoint,
        Arc<WorkSlot>,
        SyncSender<io::Result<BrowsePage>>,
    ),
    Next(
        BrowseCursor,
        usize,
        Checkpoint,
        Arc<WorkSlot>,
        SyncSender<io::Result<BrowsePage>>,
    ),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryShutdown {
    Waiting,
    TimedOut,
    Finished,
}

/// One owned std thread, one active work slot and one fixed snapshot. The
/// authorization closure must be a short thread-safe current FileRead/session
/// generation check. It must never perform disk I/O or wait on platform work.
pub struct DirectoryWorker {
    sender: SyncSender<Command>,
    thread: Option<JoinHandle<()>>,
    consent: Arc<ConsentState>,
    stopping: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
    authorization: CurrentAuthorization,
    budget: Duration,
    monitor: DirectoryMonitor,
}
impl DirectoryWorker {
    pub fn start(
        selection: BrowseSelection,
        current_authorization: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<(Self, BrowseTicket<()>)> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let busy = Arc::new(AtomicBool::new(true));
        let authorization: CurrentAuthorization = Arc::new(current_authorization);
        let monitor = DirectoryMonitor(Arc::new(Mutex::new(MonitorState {
            status: DirectoryWorkerStatus {
                active: true,
                ..DirectoryWorkerStatus::default()
            },
            stopped_at: None,
            consent: selection.consent.clone(),
        })));
        let checkpoint = Checkpoint {
            consent: selection.consent.clone(),
            stopping: stopping.clone(),
            operation_cancelled: Arc::new(AtomicBool::new(false)),
            authorization: authorization.clone(),
            started: Instant::now(),
            budget: selection.limits.operation_budget,
            monitor: monitor.clone(),
        };
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let owned_checkpoint = checkpoint.clone();
        let slot = WorkSlot::new(busy.clone());
        let owned_slot = slot.clone();
        let owned_monitor = monitor.clone();
        let thread = thread::Builder::new()
            .name("nestlink-directory".into())
            .spawn(move || {
                // Declared before root so this reports closed only after root and
                // any iterator/entry handles have actually been dropped.
                let _teardown = Teardown(owned_monitor.clone(), owned_checkpoint.stopping.clone());
                let mut root = match selection.open(&mut || owned_checkpoint.check()) {
                    Ok(root) => root,
                    Err(error) => {
                        owned_slot.complete();
                        let _ = ready_sender.try_send(Err(error));
                        owned_monitor.update(|status| {
                            status.active = false;
                            status.failed_operations = 1;
                        });
                        return;
                    }
                };
                owned_monitor.update(|status| {
                    status.root_opened = true;
                    status.handles_closed = false;
                    status.active = false;
                });
                owned_slot.complete();
                let _ = ready_sender.try_send(Ok(()));
                loop {
                    // Check local/session consent while idle as well. OS handles
                    // cannot be destroyed until any blocking operation returns.
                    if !root.consent.active()
                        || owned_checkpoint.stopping.load(Ordering::Acquire)
                        || (owned_checkpoint.authorization)().is_err()
                    {
                        owned_checkpoint.stopping.store(true, Ordering::Release);
                        owned_monitor.stop();
                        break;
                    }
                    let command = match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    owned_monitor.update(|status| status.active = true);
                    let (result, slot, reply) = match command {
                        Command::Begin(path, maximum, checkpoint, slot, reply) => (
                            root.begin(path.as_deref(), maximum, &mut || checkpoint.check()),
                            slot,
                            reply,
                        ),
                        Command::Next(cursor, maximum, checkpoint, slot, reply) => (
                            root.next(&cursor, maximum, &mut || checkpoint.check()),
                            slot,
                            reply,
                        ),
                    };
                    let failed = result.is_err();
                    owned_monitor.update(|status| {
                        status.active = false;
                        if failed {
                            status.failed_operations = status.failed_operations.saturating_add(1);
                        } else {
                            status.completed_operations =
                                status.completed_operations.saturating_add(1);
                        }
                    });
                    slot.complete();
                    let _ = reply.try_send(result);
                }
                drop(root);
            })?;
        Ok((
            Self {
                sender,
                thread: Some(thread),
                consent: checkpoint.consent.clone(),
                stopping,
                busy,
                authorization,
                budget: checkpoint.budget,
                monitor,
            },
            BrowseTicket {
                receiver: Some(ready_receiver),
                checkpoint,
                slot,
                validate: |_| Ok(()),
                consumed: false,
            },
        ))
    }
    pub fn monitor(&self) -> DirectoryMonitor {
        self.monitor.clone()
    }
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            consent: self.consent.clone(),
            stopping: self.stopping.clone(),
            operation_cancelled: Arc::new(AtomicBool::new(false)),
            authorization: self.authorization.clone(),
            started: Instant::now(),
            budget: self.budget,
            monitor: self.monitor.clone(),
        }
    }
    fn submit(
        &self,
        command: impl FnOnce(Checkpoint, Arc<WorkSlot>, SyncSender<io::Result<BrowsePage>>) -> Command,
    ) -> io::Result<BrowseTicket<BrowsePage>> {
        let checkpoint = self.checkpoint();
        checkpoint.check()?;
        if self.monitor.status().finished {
            return Err(io::Error::other("directory worker already finished"));
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "directory work slot is occupied",
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let slot = WorkSlot::new(self.busy.clone());
        if let Err(error) = self
            .sender
            .try_send(command(checkpoint.clone(), slot.clone(), sender))
        {
            self.busy.store(false, Ordering::Release);
            return Err(match error {
                TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "directory work slot is occupied")
                }
                TrySendError::Disconnected(_) => {
                    io::Error::other("directory worker already finished")
                }
            });
        }
        Ok(BrowseTicket {
            receiver: Some(receiver),
            checkpoint,
            slot,
            validate: BrowsePage::check_lifetime,
            consumed: false,
        })
    }
    pub fn begin(
        &self,
        relative_path: Option<&str>,
        maximum: usize,
    ) -> io::Result<BrowseTicket<BrowsePage>> {
        if maximum == 0 || maximum > DIRECTORY_PAGE_ENTRIES {
            return Err(invalid("invalid bounded directory page size"));
        }
        if let Some(path) = relative_path {
            validate_relative_path(path).map_err(|_| invalid("invalid portable directory path"))?;
        }
        self.submit(|checkpoint, slot, reply| {
            Command::Begin(
                relative_path.map(str::to_owned),
                maximum,
                checkpoint,
                slot,
                reply,
            )
        })
    }
    pub fn next(
        &self,
        cursor: BrowseCursor,
        maximum: usize,
    ) -> io::Result<BrowseTicket<BrowsePage>> {
        if maximum == 0 || maximum > DIRECTORY_PAGE_ENTRIES {
            return Err(invalid("invalid bounded directory page size"));
        }
        self.submit(|checkpoint, slot, reply| {
            Command::Next(cursor, maximum, checkpoint, slot, reply)
        })
    }
    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.monitor.stop();
    }
    /// Never blocks on disk or a running thread. Timeout remains in the
    /// monitor even if a later poll observes real handle destruction.
    pub fn poll_shutdown(&mut self) -> DirectoryShutdown {
        self.stop();
        if self.thread.as_ref().is_none_or(JoinHandle::is_finished) {
            if let Some(thread) = self.thread.take()
                && thread.join().is_err()
            {
                self.monitor.update(|status| {
                    if !status.finished {
                        status.active = false;
                        status.handles_closed = true;
                        status.finished = true;
                        status.failed_operations = status.failed_operations.saturating_add(1);
                    }
                });
            }
            return DirectoryShutdown::Finished;
        }
        if self.monitor.status().cleanup_timed_out {
            DirectoryShutdown::TimedOut
        } else {
            DirectoryShutdown::Waiting
        }
    }
}
impl Drop for DirectoryWorker {
    fn drop(&mut self) {
        self.stop();
        // Detach if still in an OS call. The monitor reports actual teardown
        // when it happens; Drop never reports handles closed in advance.
    }
}
