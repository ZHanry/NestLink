//! Explicit local file selections for one proved app-core session. Disk work is
//! delegated to the Core-owned file workers; the IPC task only updates consent.
use nestlink_app_core::{
    CoreHandle, NativeBrowsePage, NativeFileTaskKind, NativeFileTaskPhase, NativeFileTaskStatus,
    NativeSessionBinding, NativeSessionStatus, Snapshot,
};
use nestlink_app_ipc::files::*;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent,
    browse::{BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots},
    download::{
        LocalDownloadConsent,
        recovery::{DownloadRecoveryStore, PersistentDownloadSelection},
    },
    upload::{
        LocalUploadConsent, LocalUploadSelection, WriteQuota, WriteRootConsent, WriteRootSelection,
        WriteRoots,
    },
};
use nestlink_protocol::{
    DirectoryBrowsePage, DirectoryEntryKind, FILE_READ_ROOTS, FILE_SIZE_BYTES, FILE_WRITE_ROOTS,
    FileReadChunk, FileReadManifest, FileWriteChunk, FileWriteOpen, FileWriteState,
};
use nestlink_remote::{
    files::{
        DirectoryBrowseSource, FileDestination, FileDestinationFactory, FileDestinationStatus,
        FileDownloadSnapshot, FileReadConsent, FileReadDevice, FileReadRootListing, FileReadSource,
    },
    upload::{
        FileUploadSourceFactory, FileWriteConsent, FileWriteDestination, FileWriteDevice,
        FileWriteRootListing,
    },
};
use nestlink_sdk::{
    browse::NativeBrowseRequest, files::NativeDownloadRequest, upload::NativeUploadRequest,
};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::sync::Mutex as AsyncMutex;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local file selection is no longer approved",
    )
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid local file selection")
}
fn absolute(value: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty() || value.contains('\0') || !path.is_absolute() {
        return Err(invalid());
    }
    Ok(path)
}
fn label(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.len() as u64 > nestlink_protocol::FILE_ROOT_DISPLAY_NAME_BYTES
        || value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Registry removal does not release a slot while a file or browse owner still
/// holds the selected root. One budget spans every session of this daemon.
pub(super) struct RootBudget {
    used: Mutex<[u64; 2]>,
    maximum: [u64; 2],
}
impl RootBudget {
    pub(super) fn new(read: u64, write: u64) -> Self {
        Self {
            used: Mutex::new([0, 0]),
            maximum: [read, write],
        }
    }
    pub(super) fn reserve(self: &Arc<Self>, direction: FileDirection) -> io::Result<RootPermit> {
        let index = match direction {
            FileDirection::Read => 0,
            FileDirection::Write => 1,
        };
        let mut used = lock(&self.used);
        if used[index] >= self.maximum[index] {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "folder selection capacity exhausted; wait for old folder owners to close",
            ));
        }
        used[index] += 1;
        Ok(RootPermit {
            budget: self.clone(),
            index,
        })
    }
}
pub(super) struct RootPermit {
    budget: Arc<RootBudget>,
    index: usize,
}
impl Drop for RootPermit {
    fn drop(&mut self) {
        let mut used = lock(&self.budget.used);
        if let Some(remaining) = used[self.index].checked_sub(1) {
            used[self.index] = remaining;
        }
    }
}

struct Approval(Vec<Arc<AtomicBool>>);
impl Approval {
    fn check(&self) -> io::Result<()> {
        if self.0.iter().all(|flag| flag.load(Ordering::Acquire)) {
            Ok(())
        } else {
            Err(denied())
        }
    }
}
impl FileReadConsent for Approval {
    fn check(&self) -> io::Result<()> {
        self.check()
    }
}
impl FileWriteConsent for Approval {
    fn check(&self) -> io::Result<()> {
        self.check()
    }
}
struct ReadApproval(Arc<dyn FileReadConsent>, Arc<Approval>);
impl FileReadConsent for ReadApproval {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}
struct WriteApproval(Arc<dyn FileWriteConsent>, Arc<Approval>);
impl FileWriteConsent for WriteApproval {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}

struct ReadProvider {
    path: Option<PathBuf>,
    browse: Option<BrowseSelection>,
    device: Option<BrowseRoots<FileRoots>>,
    _read_consent: Option<ReadRootConsent>,
    _browse_consent: Option<BrowseConsent>,
}
impl ReadProvider {
    fn device(&mut self, id: &str, approval: &Approval) -> io::Result<&mut BrowseRoots<FileRoots>> {
        approval.check()?;
        if self.device.is_none() {
            let path = self.path.take().ok_or_else(denied)?;
            let (root, consent) = ApprovedReadRoot::open(id, &path, FILE_SIZE_BYTES)?;
            approval.check()?;
            self._read_consent = Some(consent);
            self.device = Some(BrowseRoots::new(
                FileRoots::new(vec![root])?,
                self.browse.take().into_iter().collect(),
            )?);
        }
        self.device.as_mut().ok_or_else(denied)
    }
}
struct ReadEntry {
    id: String,
    name: String,
    active: Arc<AtomicBool>,
    approval: Arc<Approval>,
    provider: Mutex<ReadProvider>,
    // Declared last so the pinned platform provider closes before its slot.
    _slot: Option<RootPermit>,
}
struct WriteEntry {
    id: String,
    name: String,
    active: Arc<AtomicBool>,
    approval: Arc<Approval>,
    provider: Mutex<WriteRoots>,
    _consent: WriteRootConsent,
    _slot: Option<RootPermit>,
}
type ReadRegistry = Arc<Mutex<BTreeMap<String, Arc<ReadEntry>>>>;
type WriteRegistry = Arc<Mutex<BTreeMap<String, Arc<WriteEntry>>>>;

fn insert_read_entry(registry: &mut BTreeMap<String, Arc<ReadEntry>>, entry: Arc<ReadEntry>) {
    if let Some(previous) = registry.insert(entry.id.clone(), entry) {
        // A stable root ID can be selected again. Old sources and directory
        // snapshots retain their entry; replacing its row must revoke its
        // independent consent before that old owner becomes unreachable here.
        previous.active.store(false, Ordering::Release);
    }
}

struct DynamicRead {
    registry: ReadRegistry,
    active: Arc<AtomicBool>,
}
impl FileReadDevice for DynamicRead {
    fn retire_revoked(&mut self) {
        lock(&self.registry).retain(|_, entry| entry.approval.check().is_ok());
    }
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        self.retire_revoked();
        let entries: Vec<_> = lock(&self.registry).values().cloned().collect();
        let mut flags = vec![self.active.clone()];
        let roots = entries
            .iter()
            .map(|entry| {
                flags.push(entry.active.clone());
                nestlink_protocol::FileRoot {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                }
            })
            .collect();
        let approval = Arc::new(Approval(flags));
        approval.check()?;
        authorized()?;
        Ok(FileReadRootListing {
            roots,
            consent: approval,
        })
    }
    fn open(&mut self, id: &str, path: &str) -> io::Result<Box<dyn FileReadSource>> {
        self.retire_revoked();
        let entry = lock(&self.registry).get(id).cloned().ok_or_else(denied)?;
        entry.approval.check()?;
        let source = lock(&entry.provider)
            .device(id, &entry.approval)?
            .open(id, path)?;
        entry.approval.check()?;
        Ok(Box::new(OwnedSource {
            source,
            approval: entry.approval.clone(),
            _owner: Some(Box::new(entry)),
        }))
    }
    fn browse(
        &mut self,
        id: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn DirectoryBrowseSource>> {
        self.retire_revoked();
        let entry = lock(&self.registry).get(id).cloned().ok_or_else(denied)?;
        entry.approval.check()?;
        authorized()?;
        let source = lock(&entry.provider)
            .device(id, &entry.approval)?
            .browse(id, &mut || {
                entry.approval.check()?;
                authorized()
            })?;
        entry.approval.check()?;
        Ok(Box::new(OwnedBrowse {
            source,
            approval: entry.approval.clone(),
            _owner: entry,
        }))
    }
}
struct DynamicWrite {
    registry: WriteRegistry,
    active: Arc<AtomicBool>,
}
impl FileWriteDevice for DynamicWrite {
    fn retire_revoked(&mut self) {
        lock(&self.registry).retain(|_, entry| entry.approval.check().is_ok());
    }
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        self.retire_revoked();
        let entries: Vec<_> = lock(&self.registry).values().cloned().collect();
        let mut flags = vec![self.active.clone()];
        let roots = entries
            .iter()
            .map(|entry| {
                flags.push(entry.active.clone());
                nestlink_protocol::FileRoot {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                }
            })
            .collect();
        let approval = Arc::new(Approval(flags));
        approval.check()?;
        Ok(FileWriteRootListing {
            roots,
            consent: approval,
        })
    }
    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>> {
        self.retire_revoked();
        let entry = lock(&self.registry)
            .get(&open.root_id)
            .cloned()
            .ok_or_else(denied)?;
        entry.approval.check()?;
        let destination = lock(&entry.provider).build(open, &mut || {
            entry.approval.check()?;
            authorized()
        })?;
        entry.approval.check()?;
        Ok(Box::new(OwnedWrite {
            destination,
            approval: entry.approval.clone(),
            _owner: entry,
        }))
    }
}

struct OwnedSource {
    source: Box<dyn FileReadSource>,
    approval: Arc<Approval>,
    _owner: Option<Box<dyn Send>>,
}
impl FileReadSource for OwnedSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(self.source.consent(), self.approval.clone()))
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        self.source.describe(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        self.source.read_chunk(offset, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.source.verify(original, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
}
struct OwnedBrowse {
    source: Box<dyn DirectoryBrowseSource>,
    approval: Arc<Approval>,
    _owner: Arc<ReadEntry>,
}
impl DirectoryBrowseSource for OwnedBrowse {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(self.source.consent(), self.approval.clone()))
    }
    fn begin(
        &mut self,
        directory: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        self.source.begin(directory, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn next(
        &mut self,
        cursor: &[u8],
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        self.source.next(cursor, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn snapshot_deadline(&self) -> io::Result<Instant> {
        self.source.snapshot_deadline()
    }
    fn reply_deadline(&self) -> io::Result<Instant> {
        self.source.reply_deadline()
    }
}
struct OwnedWrite {
    destination: Box<dyn FileWriteDestination>,
    approval: Arc<Approval>,
    _owner: Arc<WriteEntry>,
}
impl FileWriteDestination for OwnedWrite {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        Arc::new(WriteApproval(
            self.destination.consent(),
            self.approval.clone(),
        ))
    }
    fn status(&self) -> FileWriteState {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.write(chunk, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.finish(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}

struct DownloadSelection {
    selection: PersistentDownloadSelection,
    owner: LocalDownloadConsent,
    approval: Arc<Approval>,
}
impl FileDestinationFactory for DownloadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(
            self.selection.consent(),
            self.approval.clone(),
        ))
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        self.approval.check()?;
        Ok(Box::new(OwnedDownload {
            destination: Box::new(self.selection).build(source)?,
            _owner: self.owner,
            approval: self.approval,
        }))
    }
}
struct OwnedDownload {
    destination: Box<dyn FileDestination>,
    _owner: LocalDownloadConsent,
    approval: Arc<Approval>,
}
impl FileDestination for OwnedDownload {
    fn status(&self) -> FileDestinationStatus {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.write(source, chunk, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.resume(source, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.finish(source, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}
struct UploadSelection {
    selection: LocalUploadSelection,
    owner: LocalUploadConsent,
    approval: Arc<Approval>,
}
impl FileUploadSourceFactory for UploadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(
            self.selection.consent(),
            self.approval.clone(),
        ))
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        self.approval.check()?;
        let source = Box::new(self.selection).open(&mut || {
            self.approval.check()?;
            authorized()
        })?;
        Ok(Box::new(OwnedSource {
            source,
            approval: self.approval,
            _owner: Some(Box::new(self.owner)),
        }))
    }
}

struct SessionFiles {
    binding: NativeSessionBinding,
    generation: u64,
    active: Arc<AtomicBool>,
    reads: ReadRegistry,
    writes: WriteRegistry,
    read_started: AsyncMutex<bool>,
    write_started: AsyncMutex<bool>,
}
impl SessionFiles {
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }
    fn matches(&self, snapshot: &Snapshot) -> bool {
        snapshot.generation == self.generation
            && snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Connected
                        && session.request_id == self.binding.request_id
                        && session.connection_generation == self.binding.connection_generation
                })
    }
    fn approval(&self) -> Arc<Approval> {
        Arc::new(Approval(vec![self.active.clone()]))
    }
    fn roots(&self, direction: FileDirection) -> Vec<FileRootView> {
        match direction {
            FileDirection::Read => lock(&self.reads)
                .values()
                .filter(|entry| entry.approval.check().is_ok())
                .map(|entry| FileRootView {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                })
                .collect(),
            FileDirection::Write => lock(&self.writes)
                .values()
                .filter(|entry| entry.approval.check().is_ok())
                .map(|entry| FileRootView {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                })
                .collect(),
        }
    }
}
impl Drop for SessionFiles {
    fn drop(&mut self) {
        self.retire();
    }
}

pub struct LocalFiles {
    state: Arc<Mutex<Option<Arc<SessionFiles>>>>,
    roots: Arc<RootBudget>,
    write_quota: Arc<WriteQuota>,
    recovery: Arc<DownloadRecoveryStore>,
}
impl LocalFiles {
    pub(super) fn new(
        core: CoreHandle,
        roots: Arc<RootBudget>,
        write_quota: Arc<WriteQuota>,
        recovery: Arc<DownloadRecoveryStore>,
    ) -> Self {
        let state: Arc<Mutex<Option<Arc<SessionFiles>>>> = Arc::new(Mutex::new(None));
        let observer_roots = roots.clone();
        let observer_write_quota = write_quota.clone();
        let observer_recovery = recovery.clone();
        let weak = Arc::downgrade(&state);
        let mut view = core.observe();
        tokio::spawn(async move {
            loop {
                let snapshot = view.borrow_and_update().clone();
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let local = LocalFiles {
                    state,
                    roots: observer_roots.clone(),
                    write_quota: observer_write_quota.clone(),
                    recovery: observer_recovery.clone(),
                };
                {
                    let mut current = lock(&local.state);
                    if current
                        .as_ref()
                        .is_some_and(|session| !session.matches(&snapshot))
                        && let Some(session) = current.take()
                    {
                        session.retire();
                    }
                }
                if snapshot
                    .native_session
                    .data
                    .as_ref()
                    .is_some_and(|session| {
                        session.status == NativeSessionStatus::Connected
                            && session.host_view_authorized
                    })
                    && let Some(binding) = core.native_file_session_binding()
                    && let Ok(session) = local.session(&core, &binding, snapshot.generation)
                {
                    // Start both approved directions with an empty registry.
                    // Requests before folder approval receive an empty list or
                    // a consent rejection, preserving the proved file claim.
                    if local.start_host_services(&core, &session).await.is_err() {
                        session.retire();
                    }
                }
                drop(local);
                if view.changed().await.is_err() {
                    return;
                }
            }
        });
        Self {
            state,
            roots,
            write_quota,
            recovery,
        }
    }
    async fn start_host_services(
        &self,
        core: &CoreHandle,
        session: &SessionFiles,
    ) -> Result<(), String> {
        let access = core
            .native_file_access(&session.binding, session.generation)
            .map_err(core_error)?;
        if !access.is_host {
            return Ok(());
        }
        if access.read {
            let mut started = session.read_started.lock().await;
            if !*started {
                core.native_host_start_file_read(
                    &session.binding,
                    session.generation,
                    DynamicRead {
                        registry: session.reads.clone(),
                        active: session.active.clone(),
                    },
                )
                .await
                .map_err(core_error)?;
                *started = true;
            }
        }
        if access.write {
            let mut started = session.write_started.lock().await;
            if !*started {
                core.native_host_start_file_write(
                    &session.binding,
                    session.generation,
                    DynamicWrite {
                        registry: session.writes.clone(),
                        active: session.active.clone(),
                    },
                )
                .await
                .map_err(core_error)?;
                *started = true;
            }
        }
        Ok(())
    }
    fn session(
        &self,
        core: &CoreHandle,
        binding: &NativeSessionBinding,
        generation: u64,
    ) -> io::Result<Arc<SessionFiles>> {
        if core.snapshot().generation != generation
            || core.native_file_session_binding().as_ref() != Some(binding)
        {
            return Err(denied());
        }
        let mut state = lock(&self.state);
        if state
            .as_ref()
            .is_some_and(|session| session.binding != *binding || session.generation != generation)
            && let Some(old) = state.take()
        {
            old.retire();
        }
        let session = state
            .get_or_insert_with(|| {
                Arc::new(SessionFiles {
                    binding: binding.clone(),
                    generation,
                    active: Arc::new(AtomicBool::new(true)),
                    reads: Arc::new(Mutex::new(BTreeMap::new())),
                    writes: Arc::new(Mutex::new(BTreeMap::new())),
                    read_started: AsyncMutex::new(false),
                    write_started: AsyncMutex::new(false),
                })
            })
            .clone();
        session.approval().check()?;
        Ok(session)
    }
    async fn execute_recovery(
        &self,
        core: &CoreHandle,
        generation: u64,
        command: DownloadRecoveryCommand,
    ) -> Result<DownloadRecoveryReply, String> {
        if core.snapshot().generation != generation {
            return Err("The product generation changed; refresh recovery tasks".into());
        }
        match command {
            DownloadRecoveryCommand::List => {}
            DownloadRecoveryCommand::Cancel { task_id } => {
                let store = self.recovery.clone();
                tokio::task::spawn_blocking(move || store.cancel(&task_id))
                    .await
                    .map_err(|_| "Recovery cleanup worker failed".to_owned())?
                    .map_err(local_error)?;
            }
            DownloadRecoveryCommand::ExportPartial {
                task_id,
                fresh_directory,
                local_name,
                acknowledge_partial,
            } => {
                if !acknowledge_partial {
                    return Err(
                        "Explicit approval to export an incomplete partial is required".into(),
                    );
                }
                let area = absolute(&fresh_directory).map_err(local_error)?;
                let store = self.recovery.clone();
                tokio::task::spawn_blocking(move || {
                    store.export_partial(&task_id, &area, &local_name)
                })
                .await
                .map_err(|_| "Partial export worker failed".to_owned())?
                .map_err(local_error)?;
            }
            DownloadRecoveryCommand::Resume {
                task_id,
                request_id,
                connection_generation,
                approve_local_resume,
            } => {
                if !approve_local_resume {
                    return Err("Approve this exact interrupted task again before resuming".into());
                }
                let binding = NativeSessionBinding {
                    request_id,
                    connection_generation,
                };
                let session = self
                    .session(core, &binding, generation)
                    .map_err(local_error)?;
                let access = core
                    .native_file_access(&binding, generation)
                    .map_err(core_error)?;
                if access.is_host || !access.read {
                    return Err("A newly approved controller FileRead session is required".into());
                }
                let facts = self.recovery.resume_facts(&task_id).map_err(local_error)?;
                let (selection, owner) =
                    PersistentDownloadSelection::recover(self.recovery.clone(), &task_id)
                        .map_err(local_error)?;
                let task = core
                    .native_download_recover(
                        &binding,
                        generation,
                        facts,
                        DownloadSelection {
                            selection,
                            owner,
                            approval: session.approval(),
                        },
                    )
                    .map_err(core_error)?;
                return Ok(DownloadRecoveryReply::Resumed {
                    recovery_id: task_id,
                    task_id: task.task_id().to_owned(),
                });
            }
        }
        let (tasks, reserved_bytes) = self.recovery.list().map_err(local_error)?;
        Ok(DownloadRecoveryReply::Tasks {
            tasks,
            reserved_bytes,
        })
    }

    async fn execute(
        &self,
        core: &CoreHandle,
        binding: &NativeSessionBinding,
        generation: u64,
        command: NativeFileCommand,
    ) -> Result<NativeFileReply, String> {
        let session = self
            .session(core, binding, generation)
            .map_err(local_error)?;
        let access = core
            .native_file_access(binding, generation)
            .map_err(core_error)?;
        let result = match command {
            NativeFileCommand::SelectHostReadRoots { roots } => {
                if !access.read {
                    return Err("File reading is not approved in this session".into());
                }
                if core.native_host_session_binding().as_ref() != Some(binding) {
                    return Err("Only the hosting device can select shared folders".into());
                }
                if roots.is_empty() || roots.len() as u64 > FILE_READ_ROOTS {
                    return Err("Folder selection capacity exceeded".into());
                }
                lock(&session.reads).retain(|_, entry| entry.approval.check().is_ok());
                let mut pending = Vec::with_capacity(roots.len());
                for root in roots {
                    let slot = self
                        .roots
                        .reserve(FileDirection::Read)
                        .map_err(local_error)?;
                    label(&root.display_name).map_err(local_error)?;
                    let path = absolute(&root.directory).map_err(local_error)?;
                    let root_path = path.clone();
                    let recovery = self.recovery.clone();
                    let id = tokio::task::spawn_blocking(move || {
                        recovery.approved_read_root_id(&root_path, &nestlink_auth::random_id())
                    })
                    .await
                    .map_err(|_| "Read-root identity worker failed".to_owned())?
                    .map_err(local_error)?;
                    session.approval().check().map_err(local_error)?;
                    let (browse, consent) = if root.disclose_directory {
                        let (selection, consent) = BrowseSelection::new_with_display_name(
                            &id,
                            &root.display_name,
                            &path,
                            BrowseLimits::default(),
                        )
                        .map_err(local_error)?;
                        (Some(selection), Some(consent))
                    } else {
                        (None, None)
                    };
                    let active = Arc::new(AtomicBool::new(true));
                    pending.push(Arc::new(ReadEntry {
                        id,
                        name: root.display_name,
                        active: active.clone(),
                        approval: Arc::new(Approval(vec![session.active.clone(), active])),
                        provider: Mutex::new(ReadProvider {
                            path: Some(path),
                            browse,
                            device: None,
                            _read_consent: None,
                            _browse_consent: consent,
                        }),
                        _slot: Some(slot),
                    }));
                }
                let mut started = session.read_started.lock().await;
                if !*started {
                    core.native_host_start_file_read(
                        binding,
                        generation,
                        DynamicRead {
                            registry: session.reads.clone(),
                            active: session.active.clone(),
                        },
                    )
                    .await
                    .map_err(core_error)?;
                    *started = true;
                }
                session.approval().check().map_err(local_error)?;
                {
                    let mut registry = lock(&session.reads);
                    if registry.len() + pending.len() > FILE_READ_ROOTS as usize {
                        return Err(
                            "Folder selection capacity exceeded; wait for revoked folders to close"
                                .into(),
                        );
                    }
                    for entry in pending {
                        insert_read_entry(&mut registry, entry);
                    }
                }
                NativeFileReply::HostRootsSelected {
                    direction: FileDirection::Read,
                    roots: session.roots(FileDirection::Read),
                }
            }
            NativeFileCommand::SelectHostWriteRoots { roots } => {
                if !access.write {
                    return Err("File writing is not approved in this session".into());
                }
                if core.native_host_session_binding().as_ref() != Some(binding) {
                    return Err("Only the hosting device can select receiving folders".into());
                }
                if roots.is_empty() || roots.len() as u64 > FILE_WRITE_ROOTS {
                    return Err("Folder selection capacity exceeded".into());
                }
                lock(&session.writes).retain(|_, entry| entry.approval.check().is_ok());
                let mut pending = Vec::with_capacity(roots.len());
                for root in roots {
                    let slot = self
                        .roots
                        .reserve(FileDirection::Write)
                        .map_err(local_error)?;
                    let path = absolute(&root.fresh_directory).map_err(local_error)?;
                    let id = nestlink_auth::random_id();
                    let (selection, consent) = WriteRootSelection::new_with_display_name_and_quota(
                        &id,
                        &root.display_name,
                        &path,
                        FILE_SIZE_BYTES,
                        self.write_quota.clone(),
                    )
                    .map_err(local_error)?;
                    let active = Arc::new(AtomicBool::new(true));
                    pending.push(Arc::new(WriteEntry {
                        id,
                        name: root.display_name,
                        active: active.clone(),
                        approval: Arc::new(Approval(vec![session.active.clone(), active])),
                        provider: Mutex::new(
                            WriteRoots::new(vec![selection]).map_err(local_error)?,
                        ),
                        _consent: consent,
                        _slot: Some(slot),
                    }));
                }
                let mut started = session.write_started.lock().await;
                if !*started {
                    core.native_host_start_file_write(
                        binding,
                        generation,
                        DynamicWrite {
                            registry: session.writes.clone(),
                            active: session.active.clone(),
                        },
                    )
                    .await
                    .map_err(core_error)?;
                    *started = true;
                }
                session.approval().check().map_err(local_error)?;
                {
                    let mut registry = lock(&session.writes);
                    if registry.len() + pending.len() > FILE_WRITE_ROOTS as usize {
                        return Err(
                            "Folder selection capacity exceeded; wait for revoked folders to close"
                                .into(),
                        );
                    }
                    for entry in pending {
                        registry.insert(entry.id.clone(), entry);
                    }
                }
                NativeFileReply::HostRootsSelected {
                    direction: FileDirection::Write,
                    roots: session.roots(FileDirection::Write),
                }
            }
            NativeFileCommand::RevokeHostRoot { direction, root_id } => {
                if core.native_host_session_binding().as_ref() != Some(binding) {
                    return Err("Only the hosting device can revoke local folders".into());
                }
                let active = match direction {
                    FileDirection::Read => lock(&session.reads)
                        .get(&root_id)
                        .map(|entry| entry.active.clone()),
                    FileDirection::Write => lock(&session.writes)
                        .get(&root_id)
                        .map(|entry| entry.active.clone()),
                }
                .ok_or_else(|| "The selected folder is unavailable".to_owned())?;
                active.store(false, Ordering::Release);
                NativeFileReply::HostRootRevoked { direction, root_id }
            }
            NativeFileCommand::ListRoots { direction } => {
                if (direction == FileDirection::Read && !access.read)
                    || (direction == FileDirection::Write && !access.write)
                {
                    return Err("This file direction is not approved in the session".into());
                }
                let roots = if core.native_host_session_binding().as_ref() == Some(binding) {
                    session.roots(direction)
                } else {
                    match direction {
                        FileDirection::Read => {
                            core.native_file_read_roots(binding, generation).await
                        }
                        FileDirection::Write => {
                            core.native_file_write_roots(binding, generation).await
                        }
                    }
                    .map_err(core_error)?
                    .into_iter()
                    .map(|root| FileRootView {
                        root_id: root.root_id,
                        display_name: root.display_name,
                    })
                    .collect()
                };
                NativeFileReply::Roots { direction, roots }
            }
            NativeFileCommand::BrowseBegin { root_id, directory } => {
                let request = NativeBrowseRequest::new(
                    &root_id,
                    directory.as_deref(),
                    nestlink_protocol::DIRECTORY_PAGE_ENTRIES as u32,
                )
                .map_err(|_| "Invalid remote directory selection".to_owned())?;
                directory_reply(
                    core.native_browse_begin(binding, generation, request)
                        .await
                        .map_err(core_error)?,
                )
            }
            NativeFileCommand::BrowseNext { browse_id } => {
                match core
                    .native_browse_next(
                        binding,
                        generation,
                        &browse_id,
                        nestlink_protocol::DIRECTORY_PAGE_ENTRIES as u32,
                    )
                    .await
                    .map_err(core_error)?
                {
                    Some(page) => directory_reply(page),
                    None => NativeFileReply::BrowseCancelled,
                }
            }
            NativeFileCommand::BrowseCancel { browse_id } => {
                core.native_browse_cancel(binding, generation, &browse_id)
                    .await
                    .map_err(core_error)?;
                NativeFileReply::BrowseCancelled
            }
            NativeFileCommand::Download {
                root_id,
                relative_path,
                local_directory,
                local_name,
            } => {
                let path = absolute(&local_directory).map_err(local_error)?;
                let request = NativeDownloadRequest::new(&root_id, &relative_path)
                    .map_err(|_| "Invalid remote file selection".to_owned())?;
                let (selection, owner) = PersistentDownloadSelection::new(
                    self.recovery.clone(),
                    &nestlink_auth::random_id(),
                    &path,
                    &local_name,
                )
                .map_err(local_error)?;
                let task = core
                    .native_download(
                        binding,
                        generation,
                        request,
                        DownloadSelection {
                            selection,
                            owner,
                            approval: session.approval(),
                        },
                    )
                    .map_err(core_error)?;
                NativeFileReply::Task {
                    task: task_view(task.status()),
                }
            }
            NativeFileCommand::Upload {
                root_id,
                relative_path,
                local_file,
            } => {
                let path = absolute(&local_file).map_err(local_error)?;
                let request = NativeUploadRequest::new(&root_id, &relative_path)
                    .map_err(|_| "Invalid remote upload selection".to_owned())?;
                let (selection, owner) =
                    LocalUploadSelection::new(&path, FILE_SIZE_BYTES).map_err(local_error)?;
                let task = core
                    .native_upload(
                        binding,
                        generation,
                        request,
                        UploadSelection {
                            selection,
                            owner,
                            approval: session.approval(),
                        },
                    )
                    .map_err(core_error)?;
                NativeFileReply::Task {
                    task: task_view(task.status()),
                }
            }
            NativeFileCommand::Task { task_id } => NativeFileReply::Task {
                task: task_view(
                    core.native_file_task_status(binding, generation, &task_id)
                        .map_err(core_error)?,
                ),
            },
            NativeFileCommand::Control { task_id, action } => {
                let action = match action {
                    NativeFileTaskAction::Pause => nestlink_app_core::NativeFileTaskAction::Pause,
                    NativeFileTaskAction::Resume => nestlink_app_core::NativeFileTaskAction::Resume,
                    NativeFileTaskAction::Cancel => nestlink_app_core::NativeFileTaskAction::Cancel,
                };
                core.native_file_task_control(binding, generation, &task_id, action)
                    .map_err(core_error)?;
                NativeFileReply::ControlAccepted
            }
        };
        if !session.matches(&core.snapshot()) {
            session.retire();
            return Err("The file session changed; refresh before retrying".into());
        }
        Ok(result)
    }
}
impl LocalFileHandler for LocalFiles {
    fn recovery(
        &self,
        core: CoreHandle,
        generation: u64,
        command: DownloadRecoveryCommand,
    ) -> RecoveryReplyFuture<'_> {
        Box::pin(async move {
            self.execute_recovery(&core, generation, command)
                .await
                .unwrap_or_else(|reason| DownloadRecoveryReply::Refused { reason })
        })
    }

    fn handle(
        &self,
        core: CoreHandle,
        binding: NativeSessionBinding,
        generation: u64,
        command: NativeFileCommand,
    ) -> FileReplyFuture<'_> {
        Box::pin(async move {
            self.execute(&core, &binding, generation, command)
                .await
                .unwrap_or_else(|reason| NativeFileReply::Refused { reason })
        })
    }
}
fn local_error(error: io::Error) -> String {
    format!("Local file selection failed: {:?}", error.kind())
}
fn core_error(error: nestlink_app_core::NativeFilesError) -> String {
    error.to_string()
}
fn directory_reply(page: NativeBrowsePage) -> NativeFileReply {
    let directory = page.page.directory;
    let entries = page
        .page
        .entries
        .into_iter()
        .map(|entry| FileEntryView {
            relative_path: if directory.is_empty() {
                entry.name
            } else {
                format!("{directory}/{}", entry.name)
            },
            directory: entry.kind == DirectoryEntryKind::DirectoryEntryDirectory as i32,
            size: entry.size,
        })
        .collect();
    NativeFileReply::Directory {
        root_id: page.page.root_id,
        directory,
        browse_id: page.browse_id,
        entries,
        complete: !page.page.has_more,
    }
}
fn task_view(task: NativeFileTaskStatus) -> FileTaskView {
    let phase = match task.phase {
        NativeFileTaskPhase::Queued => "queued",
        NativeFileTaskPhase::Active => "running",
        NativeFileTaskPhase::Paused => "paused",
        NativeFileTaskPhase::Settling => "cancelling",
        NativeFileTaskPhase::Completed => "completed",
        NativeFileTaskPhase::Cancelled => "cancelled",
        NativeFileTaskPhase::Failed => "failed",
    };
    FileTaskView {
        task_id: task.task_id,
        upload: task.kind == NativeFileTaskKind::Upload,
        phase: phase.into(),
        confirmed_bytes: task.confirmed_bytes,
        total_bytes: task.total_bytes,
        finished: task.finished,
        error: task.error.map(core_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn read_entry(
        path: &Path,
        session: Arc<AtomicBool>,
        metadata: bool,
    ) -> io::Result<Arc<ReadEntry>> {
        read_entry_with_id(path, session, metadata, nestlink_auth::random_id())
    }

    fn read_entry_with_id(
        path: &Path,
        session: Arc<AtomicBool>,
        metadata: bool,
        id: String,
    ) -> io::Result<Arc<ReadEntry>> {
        let active = Arc::new(AtomicBool::new(true));
        let (browse, consent) = if metadata {
            let (selection, consent) = BrowseSelection::new_with_display_name(
                &id,
                "Shared documents",
                path,
                BrowseLimits::default(),
            )?;
            (Some(selection), Some(consent))
        } else {
            (None, None)
        };
        Ok(Arc::new(ReadEntry {
            id,
            name: "Shared documents".into(),
            active: active.clone(),
            approval: Arc::new(Approval(vec![session, active])),
            provider: Mutex::new(ReadProvider {
                path: Some(path.into()),
                browse,
                device: None,
                _read_consent: None,
                _browse_consent: consent,
            }),
            _slot: None,
        }))
    }

    #[test]
    fn empty_registry_can_add_roots_and_revoke_open_sources_without_ending_other_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("selected.txt"),
            b"explicit file selection",
        )?;
        let active = Arc::new(AtomicBool::new(true));
        let registry = Arc::new(Mutex::new(BTreeMap::new()));
        let mut device = DynamicRead {
            registry: registry.clone(),
            active: active.clone(),
        };
        assert!(device.list_roots(&mut || Ok(()))?.roots.is_empty());
        let first = read_entry(directory.path(), active.clone(), false)?;
        let second = read_entry(directory.path(), active.clone(), false)?;
        lock(&registry).insert(first.id.clone(), first.clone());
        lock(&registry).insert(second.id.clone(), second.clone());
        let listing = device.list_roots(&mut || Ok(()))?;
        assert_eq!(listing.roots.len(), 2);
        assert!(
            listing
                .roots
                .iter()
                .all(|root| root.display_name == "Shared documents")
        );
        let mut old = device.open(&first.id, "selected.txt")?;
        assert_eq!(old.describe(&mut || Ok(()))?.size, 23);
        assert!(device.browse(&first.id, &mut || Ok(())).is_err());
        first.active.store(false, Ordering::Release);
        assert!(listing.consent.check().is_err());
        assert!(old.describe(&mut || Ok(())).is_err());
        assert!(device.open(&first.id, "selected.txt").is_err());
        assert_eq!(device.list_roots(&mut || Ok(()))?.roots.len(), 1);
        let mut surviving = device.open(&second.id, "selected.txt")?;
        assert!(surviving.describe(&mut || Ok(())).is_ok());
        active.store(false, Ordering::Release);
        assert!(surviving.describe(&mut || Ok(())).is_err());
        drop(old);
        drop(surviving);
        drop(device);
        drop(first);
        drop(second);
        drop(registry);
        directory.close()?;
        Ok(())
    }

    #[test]
    fn approved_directory_page_is_invalidated_when_its_local_root_is_revoked()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("visible.txt"), b"visible")?;
        let active = Arc::new(AtomicBool::new(true));
        let entry = read_entry(directory.path(), active.clone(), true)?;
        let registry = Arc::new(Mutex::new(BTreeMap::from([(
            entry.id.clone(),
            entry.clone(),
        )])));
        let mut device = DynamicRead { registry, active };
        let mut browse = device.browse(&entry.id, &mut || Ok(()))?;
        let page = browse.begin(None, 1, &mut || Ok(()))?;
        assert_eq!(page.entries[0].name, "visible.txt");
        entry.active.store(false, Ordering::Release);
        assert!(browse.consent().check().is_err());
        assert!(device.browse(&entry.id, &mut || Ok(())).is_err());
        drop(browse);
        drop(device);
        drop(entry);
        directory.close()?;
        Ok(())
    }

    #[test]
    fn write_revocation_prevents_prepare_but_still_allows_actual_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receiving = directory.path().join("new-receiving-area");
        let id = nestlink_auth::random_id();
        let session = Arc::new(AtomicBool::new(true));
        let active = Arc::new(AtomicBool::new(true));
        let (selection, consent) = WriteRootSelection::new_with_display_name(
            &id,
            "Receiving",
            &receiving,
            FILE_SIZE_BYTES,
            FILE_SIZE_BYTES,
        )?;
        let entry = Arc::new(WriteEntry {
            id: id.clone(),
            name: "Receiving".into(),
            active: active.clone(),
            approval: Arc::new(Approval(vec![session.clone(), active.clone()])),
            provider: Mutex::new(WriteRoots::new(vec![selection])?),
            _consent: consent,
            _slot: None,
        });
        let registry = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), entry.clone())])));
        let mut device = DynamicWrite {
            registry,
            active: session,
        };
        let open = FileWriteOpen {
            root_id: id.clone(),
            path: "safe.txt".into(),
            size: 0,
            sha256: vec![
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ],
        };
        let mut destination = device.build(&open, &mut || Ok(()))?;
        destination.prepare(&mut || Ok(()))?;
        assert!(receiving.exists());
        active.store(false, Ordering::Release);
        assert!(destination.consent().check().is_err());
        assert!(destination.finish(&mut || Ok(())).is_err());
        destination.cleanup()?;
        assert!(destination.status().file_closed);
        assert!(!receiving.join("safe.txt").exists());
        assert!(device.list_roots()?.roots.is_empty());
        drop(destination);
        drop(device);
        drop(entry);
        directory.close()?;
        Ok(())
    }

    #[test]
    fn revoked_root_keeps_its_global_slot_until_actual_file_and_browse_owners_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("selected.txt"), b"selected")?;
        let budget = Arc::new(RootBudget::new(1, 1));
        for browse_last in [false, true] {
            let active = Arc::new(AtomicBool::new(true));
            let mut entry = read_entry(directory.path(), active.clone(), true)?;
            Arc::get_mut(&mut entry)
                .ok_or("fixture root unexpectedly shared")?
                ._slot = Some(budget.reserve(FileDirection::Read)?);
            let id = entry.id.clone();
            let registry = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), entry)])));
            let mut device = DynamicRead {
                registry: registry.clone(),
                active: active.clone(),
            };
            let mut source = device.open(&id, "selected.txt")?;
            assert_eq!(source.describe(&mut || Ok(()))?.size, 8);
            let mut browse = device.browse(&id, &mut || Ok(()))?;
            assert_eq!(browse.begin(None, 1, &mut || Ok(()))?.entries.len(), 1);
            active.store(false, Ordering::Release);
            device.retire_revoked();
            assert!(lock(&registry).is_empty());
            drop(device);
            drop(registry);
            assert!(source.describe(&mut || Ok(())).is_err());
            assert!(browse.consent().check().is_err());
            assert!(budget.reserve(FileDirection::Read).is_err());
            // The independently approved write direction retains its own cap.
            drop(budget.reserve(FileDirection::Write)?);
            if browse_last {
                drop(source);
                assert!(budget.reserve(FileDirection::Read).is_err());
                drop(browse);
            } else {
                drop(browse);
                assert!(budget.reserve(FileDirection::Read).is_err());
                drop(source);
            }
            drop(budget.reserve(FileDirection::Read)?);
        }
        directory.close()?;
        Ok(())
    }

    #[test]
    fn removed_write_root_keeps_its_slot_through_real_staging_cleanup_until_owner_drops()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receiving = directory.path().join("receiving");
        let id = nestlink_auth::random_id();
        let active = Arc::new(AtomicBool::new(true));
        let session = Arc::new(AtomicBool::new(true));
        let budget = Arc::new(RootBudget::new(1, 1));
        let (selection, consent) = WriteRootSelection::new_with_quota(
            &id,
            &receiving,
            0,
            Arc::new(WriteQuota::new(0, 1)),
        )?;
        let entry = Arc::new(WriteEntry {
            id: id.clone(),
            name: "Receiving".into(),
            active: active.clone(),
            approval: Arc::new(Approval(vec![session.clone(), active.clone()])),
            provider: Mutex::new(WriteRoots::new(vec![selection])?),
            _consent: consent,
            _slot: Some(budget.reserve(FileDirection::Write)?),
        });
        let registry = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), entry)])));
        let mut device = DynamicWrite {
            registry: registry.clone(),
            active: session,
        };
        let open = FileWriteOpen {
            root_id: id,
            path: "empty.txt".into(),
            size: 0,
            sha256: vec![
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ],
        };
        let mut destination = device.build(&open, &mut || Ok(()))?;
        destination.prepare(&mut || Ok(()))?;
        assert_eq!(std::fs::read_dir(&receiving)?.count(), 1);
        active.store(false, Ordering::Release);
        device.retire_revoked();
        assert!(lock(&registry).is_empty());
        drop(device);
        drop(registry);
        assert!(destination.consent().check().is_err());
        assert!(budget.reserve(FileDirection::Write).is_err());
        destination.cleanup()?;
        assert!(destination.status().file_closed && destination.status().temporary_removed);
        assert_eq!(std::fs::read_dir(&receiving)?.count(), 0);
        assert!(budget.reserve(FileDirection::Write).is_err());
        drop(destination);
        drop(budget.reserve(FileDirection::Write)?);
        directory.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn offline_recovery_lists_facts_but_missing_explicit_approval_never_touches_disk()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let private = directory.path().join("state");
        nestlink_platform_security::new_private_directory(&private)?;
        let recovery = DownloadRecoveryStore::open(&private, FILE_SIZE_BYTES, 4)?;
        let mut core = nestlink_app_core::AppCore::start(nestlink_app_core::Limits::default())?;
        let handle = core.handle();
        // No native session/permit/client exists. These commands exercise the
        // actual daemon handler rather than merely inspecting a schema field.
        let files = LocalFiles {
            state: Arc::new(Mutex::new(None)),
            roots: Arc::new(RootBudget::new(1, 1)),
            write_quota: Arc::new(WriteQuota::new(FILE_SIZE_BYTES, 1)),
            recovery,
        };
        let generation = handle.snapshot().generation;
        let before = std::fs::read(private.join("native-download-recovery.json"))?;
        assert!(matches!(
            files
                .execute_recovery(&handle, generation, DownloadRecoveryCommand::List)
                .await,
            Ok(DownloadRecoveryReply::Tasks {
                reserved_bytes: 0,
                ..
            })
        ));
        let refused = files
            .execute_recovery(
                &handle,
                generation,
                DownloadRecoveryCommand::Resume {
                    task_id: nestlink_auth::random_id(),
                    request_id: nestlink_auth::random_id(),
                    connection_generation: 9,
                    approve_local_resume: false,
                },
            )
            .await;
        assert_eq!(
            refused.err().as_deref(),
            Some("Approve this exact interrupted task again before resuming")
        );
        let target = directory.path().join("export");
        let refused = files
            .execute_recovery(
                &handle,
                generation,
                DownloadRecoveryCommand::ExportPartial {
                    task_id: nestlink_auth::random_id(),
                    fresh_directory: target.to_string_lossy().into_owned(),
                    local_name: "saved.partial".into(),
                    acknowledge_partial: false,
                },
            )
            .await;
        assert_eq!(
            refused.err().as_deref(),
            Some("Explicit approval to export an incomplete partial is required")
        );
        assert!(!target.exists());
        assert_eq!(
            std::fs::read(private.join("native-download-recovery.json"))?,
            before
        );
        assert!(
            files
                .execute_recovery(
                    &handle,
                    generation.saturating_add(1),
                    DownloadRecoveryCommand::List
                )
                .await
                .is_err()
        );
        let _ = core.shutdown(std::time::Duration::from_secs(2)).await;
        Ok(())
    }

    #[test]
    fn reselecting_a_stable_read_root_revokes_old_real_owners_and_keeps_slots_until_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let shared = directory.path().join("shared");
        std::fs::create_dir(&shared)?;
        std::fs::write(shared.join("selected.txt"), b"explicit file selection")?;
        let private = directory.path().join("state");
        nestlink_platform_security::new_private_directory(&private)?;
        let store = DownloadRecoveryStore::open(&private, FILE_SIZE_BYTES, 4)?;
        let first_id = store.approved_read_root_id(&shared, &nestlink_auth::random_id())?;
        let replacement_id = store.approved_read_root_id(&shared, &nestlink_auth::random_id())?;
        assert_eq!(first_id, replacement_id);

        let budget = Arc::new(RootBudget::new(2, 1));
        let session = Arc::new(AtomicBool::new(true));
        let registry = Arc::new(Mutex::new(BTreeMap::new()));
        let mut device = DynamicRead {
            registry: registry.clone(),
            active: session.clone(),
        };
        let mut first = read_entry_with_id(&shared, session.clone(), true, first_id.clone())?;
        Arc::get_mut(&mut first)
            .ok_or("fixture first entry unexpectedly shared")?
            ._slot = Some(budget.reserve(FileDirection::Read)?);
        insert_read_entry(&mut lock(&registry), first.clone());
        let old_listing = device.list_roots(&mut || Ok(()))?;
        let mut old_source = device.open(&first_id, "selected.txt")?;
        let mut old_browse = device.browse(&first_id, &mut || Ok(()))?;
        let old_page = old_browse.begin(None, 1, &mut || Ok(()))?;
        assert_eq!(
            old_source.read_chunk(0, 23, &mut || Ok(()))?,
            b"explicit file selection"
        );
        assert_eq!(old_page.entries.len(), 1);
        assert!(old_listing.consent.check().is_ok());
        assert!(old_browse.consent().check().is_ok());

        let mut replacement =
            read_entry_with_id(&shared, session.clone(), true, replacement_id.clone())?;
        Arc::get_mut(&mut replacement)
            .ok_or("fixture replacement unexpectedly shared")?
            ._slot = Some(budget.reserve(FileDirection::Read)?);
        // This is the exact insertion helper used by SelectHostReadRoots, with
        // actual platform source/browse handles retaining the old Arc entry.
        insert_read_entry(&mut lock(&registry), replacement.clone());
        drop(first);
        assert!(old_listing.consent.check().is_err());
        assert!(old_source.describe(&mut || Ok(())).is_err());
        assert!(old_source.read_chunk(0, 23, &mut || Ok(())).is_err());
        assert!(old_browse.consent().check().is_err());
        assert!(old_browse.begin(None, 1, &mut || Ok(())).is_err());
        assert!(budget.reserve(FileDirection::Read).is_err());

        let current_listing = device.list_roots(&mut || Ok(()))?;
        assert_eq!(current_listing.roots.len(), 1);
        assert_eq!(current_listing.roots[0].root_id, replacement_id);
        assert!(current_listing.consent.check().is_ok());
        let mut current_source = device.open(&replacement_id, "selected.txt")?;
        let mut current_browse = device.browse(&replacement_id, &mut || Ok(()))?;
        assert_eq!(current_source.describe(&mut || Ok(()))?.size, 23);
        assert_eq!(
            current_source.read_chunk(0, 23, &mut || Ok(()))?,
            b"explicit file selection"
        );
        assert_eq!(
            current_browse.begin(None, 1, &mut || Ok(()))?.entries.len(),
            1
        );

        // RevokeHostRoot resolves this current registry entry and flips this
        // exact flag. Neither the old owners nor current owners may survive it.
        let current = lock(&registry)
            .get(&replacement_id)
            .cloned()
            .ok_or("current entry missing")?;
        current.active.store(false, Ordering::Release);
        assert!(current_listing.consent.check().is_err());
        assert!(current_source.describe(&mut || Ok(())).is_err());
        assert!(current_browse.consent().check().is_err());
        assert!(old_source.describe(&mut || Ok(())).is_err());
        assert!(device.list_roots(&mut || Ok(()))?.roots.is_empty());
        assert!(budget.reserve(FileDirection::Read).is_err());
        drop(old_source);
        assert!(budget.reserve(FileDirection::Read).is_err());
        drop(old_browse);
        drop(budget.reserve(FileDirection::Read)?);
        assert!(session.load(Ordering::Acquire));
        drop(current_source);
        drop(current_browse);
        drop(current);
        drop(replacement);
        drop(device);
        drop(registry);
        drop(store);
        directory.close()?;
        Ok(())
    }
}
