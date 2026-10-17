//! Explicit, session-scoped Android host files. SAF URIs never cross JNI.
//! Real snapshot, storage, service and export owners survive cancellation.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]
use crate::file_transfer::{
    AndroidExportIdentity, AndroidExportSession, AndroidExportStatus, AndroidFileIdentity,
    ExportFailure, clear_saf_destination, export_json, export_start_error, export_verified_file,
};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use nestlink_app_core::{
    BrowserHostBinding, BrowserHostFileRootView, BrowserHostStatus, CoreHandle,
};
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent,
    browse::{BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots},
    upload::{WriteRootConsent, WriteRootSelection, WriteRoots},
};
use nestlink_protocol::{
    FileReadManifest, FileRoot, FileWriteChunk, FileWriteOpen, FileWriteState,
};
use nestlink_remote::{
    LeaseControl, RemoteError,
    files::{
        ClaimedFileRead, DirectoryBrowseSource, FileReadConsent, FileReadDevice,
        FileReadRootListing, FileReadServer, FileReadSource, FileShutdown, FileWorkerMonitor,
    },
    upload::{
        ClaimedFileWrite, FileWriteConsent, FileWriteDestination, FileWriteDevice,
        FileWriteMonitor, FileWriteRootListing, FileWriteServer,
    },
};
use nestlink_sdk::webrtc_host::{HostDataOwner, WebRtcHostError};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use std::{future::Future, pin::Pin};
use tokio::runtime::Runtime;

const MAX_ARTIFACTS: usize = 8;
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const SNAPSHOT_BUDGET: Duration = Duration::from_secs(300);

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Android host file approval ended",
    )
}

fn consume_saf_grant(consumed: &Mutex<BTreeSet<String>>, grant_id: &str) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(grant_id).map_err(|_| "invalid local SAF grant".to_owned())?;
    if id.hyphenated().to_string() != grant_id {
        return Err("non-canonical local SAF grant".into());
    }
    let mut consumed = lock(consumed);
    if consumed.len() >= 256 || !consumed.insert(grant_id.to_owned()) {
        return Err("SAF grant was consumed or local grant capacity is full".into());
    }
    Ok(())
}
fn label(name: &str) -> io::Result<()> {
    nestlink_protocol::files::validate_relative_path(name).map_err(|_| denied())?;
    if name.contains('/')
        || name.len() > 255
        || name.len() as u64 > nestlink_protocol::FILE_ROOT_DISPLAY_NAME_BYTES
        || name.trim() != name
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported selected document name",
        ));
    }
    Ok(())
}

#[derive(Clone)]
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

#[derive(Default)]
struct ArtifactState {
    phase: String,
    size: Option<u64>,
    sha256: Vec<u8>,
    published: bool,
    verified: bool,
    error: Option<String>,
    cleanup_error: Option<String>,
    write: FileWriteState,
}
struct Artifact {
    id: String,
    identity: HostFileIdentity,
    name: String,
    area_name: String,
    receive: bool,
    write_root: Option<String>,
    active: Arc<AtomicBool>,
    owners: AtomicUsize,
    discard: AtomicBool,
    state: Mutex<ArtifactState>,
}
// Also covers unwind before a destination wrapper can be returned. Dropping
// the actual storage stack precedes this guard; capacity stays in the Book.
struct ArtifactOwner(Arc<Artifact>);
impl Drop for ArtifactOwner {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        if !state.published {
            self.0.discard.store(true, Ordering::Release);
            state.phase = "failed".into();
        }
        drop(state);
        self.0.owners.fetch_sub(1, Ordering::Release);
    }
}
#[derive(Default)]
struct Book {
    entries: BTreeMap<String, (u64, Arc<Artifact>)>,
}
impl Book {
    fn remaining(&self) -> u64 {
        MAX_BYTES.saturating_sub(self.entries.values().map(|(bytes, _)| *bytes).sum::<u64>())
    }
    fn reserve(&mut self, bytes: u64, artifact: Arc<Artifact>) -> io::Result<()> {
        if artifact.receive
            && self.entries.values().any(|(_, existing)| {
                existing.receive
                    && existing.write_root == artifact.write_root
                    && existing.name == artifact.name
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the approved receiving root already owns this name; it cannot be overwritten or reused before confirmed cleanup",
            ));
        }
        if self.entries.len() >= MAX_ARTIFACTS
            || bytes > self.remaining()
            || self.entries.contains_key(&artifact.id)
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "Android host files use the shared 8-file / 4-GiB capacity",
            ));
        }
        self.entries.insert(artifact.id.clone(), (bytes, artifact));
        Ok(())
    }
}
type SharedBook = Arc<Mutex<Book>>;
struct ReadEntry {
    artifact: Arc<Artifact>,
    approval: Approval,
    provider: Mutex<BrowseRoots<FileRoots>>,
    _read: ReadRootConsent,
    _browse: BrowseConsent,
}
type ReadRegistry = Arc<Mutex<BTreeMap<String, Arc<ReadEntry>>>>;

struct DynamicRead {
    roots: ReadRegistry,
    active: Arc<AtomicBool>,
}
impl FileReadDevice for DynamicRead {
    fn retire_revoked(&mut self) {
        lock(&self.roots).retain(|_, root| root.approval.check().is_ok());
    }
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        self.retire_revoked();
        let entries: Vec<_> = lock(&self.roots).values().cloned().collect();
        let mut flags = vec![self.active.clone()];
        let roots = entries
            .iter()
            .map(|entry| {
                flags.push(entry.artifact.active.clone());
                FileRoot {
                    root_id: entry.artifact.id.clone(),
                    display_name: entry.artifact.name.clone(),
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
        let entry = lock(&self.roots).get(id).cloned().ok_or_else(denied)?;
        entry.approval.check()?;
        // A selected file never confers authority over its original parent.
        if path != entry.artifact.name {
            return Err(denied());
        }
        let source = lock(&entry.provider).open(id, path)?;
        entry.approval.check()?;
        Ok(Box::new(OwnedRead { source, entry }))
    }
    fn browse(
        &mut self,
        id: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn DirectoryBrowseSource>> {
        let entry = lock(&self.roots).get(id).cloned().ok_or_else(denied)?;
        let source = lock(&entry.provider).browse(id, &mut || {
            entry.approval.check()?;
            authorized()
        })?;
        Ok(Box::new(OwnedBrowse { source, entry }))
    }
}
struct ReadConsent(Arc<dyn FileReadConsent>, Approval);
impl FileReadConsent for ReadConsent {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}
struct OwnedRead {
    source: Box<dyn FileReadSource>,
    entry: Arc<ReadEntry>,
}
impl FileReadSource for OwnedRead {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadConsent(
            self.source.consent(),
            self.entry.approval.clone(),
        ))
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        self.source.describe(&mut || {
            self.entry.approval.check()?;
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
            self.entry.approval.check()?;
            authorized()
        })
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.source.verify(original, &mut || {
            self.entry.approval.check()?;
            authorized()
        })
    }
}
struct OwnedBrowse {
    source: Box<dyn DirectoryBrowseSource>,
    entry: Arc<ReadEntry>,
}
impl DirectoryBrowseSource for OwnedBrowse {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadConsent(
            self.source.consent(),
            self.entry.approval.clone(),
        ))
    }
    fn begin(
        &mut self,
        directory: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<nestlink_protocol::DirectoryBrowsePage> {
        self.source.begin(directory, maximum, &mut || {
            self.entry.approval.check()?;
            authorized()
        })
    }
    fn next(
        &mut self,
        cursor: &[u8],
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<nestlink_protocol::DirectoryBrowsePage> {
        self.source.next(cursor, maximum, &mut || {
            self.entry.approval.check()?;
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

struct ReceiveGrant {
    id: String,
    active: Arc<AtomicBool>,
}
type ReceiveRegistry = Arc<Mutex<Option<ReceiveGrant>>>;
struct DynamicWrite {
    grant: ReceiveRegistry,
    session_active: Arc<AtomicBool>,
    identity: HostFileIdentity,
    book: SharedBook,
    area: PathBuf,
}
impl FileWriteDevice for DynamicWrite {
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        let grant = lock(&self.grant);
        let flags = grant
            .as_ref()
            .map(|grant| vec![self.session_active.clone(), grant.active.clone()])
            .unwrap_or_else(|| vec![self.session_active.clone()]);
        let approval = Arc::new(Approval(flags));
        approval.check()?;
        let roots = grant
            .as_ref()
            .map(|grant| {
                vec![FileRoot {
                    root_id: grant.id.clone(),
                    display_name: "Android 私有接收区".to_owned(),
                }]
            })
            .unwrap_or_default();
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
        label(&open.path)?;
        let approval = {
            let grant = lock(&self.grant);
            let grant = grant
                .as_ref()
                .filter(|grant| grant.id == open.root_id)
                .ok_or_else(denied)?;
            Approval(vec![self.session_active.clone(), grant.active.clone()])
        };
        approval.check()?;
        authorized()?;
        let id = uuid::Uuid::new_v4().to_string();
        let artifact = Arc::new(Artifact {
            id: id.clone(),
            identity: self.identity.clone(),
            name: open.path.clone(),
            area_name: uuid::Uuid::new_v4().to_string(),
            receive: true,
            write_root: Some(open.root_id.clone()),
            active: Arc::new(AtomicBool::new(true)),
            owners: AtomicUsize::new(1),
            discard: AtomicBool::new(false),
            state: Mutex::new(ArtifactState {
                phase: "receiving".into(),
                size: Some(open.size),
                sha256: open.sha256.clone(),
                ..ArtifactState::default()
            }),
        });
        let owner = ArtifactOwner(artifact.clone());
        let mut flags = approval.0.clone();
        flags.push(artifact.active.clone());
        let approval = Approval(flags);
        // Reserve declared bytes and a slot BEFORE any staging directory I/O.
        lock(&self.book).reserve(open.size, artifact.clone())?;
        let built = (|| {
            let (selection, consent) = WriteRootSelection::new_with_display_name(
                &open.root_id,
                "Android 私有接收区",
                &self.area.join(&artifact.area_name),
                open.size,
                open.size,
            )?;
            let destination = WriteRoots::new(vec![selection])?.build(open, &mut || {
                approval.check()?;
                authorized()
            })?;
            Ok::<_, io::Error>((destination, consent))
        })();
        match built {
            Ok((inner, consent)) => Ok(Box::new(OwnedWrite {
                inner: Some(inner),
                artifact,
                approval,
                _consent: consent,
                owner: Some(owner),
            })),
            Err(error) => {
                let mut state = lock(&artifact.state);
                state.phase = "failed".into();
                state.error = Some(format!(
                    "receiving storage could not open ({:?})",
                    error.kind()
                ));
                drop(state);
                artifact.discard.store(true, Ordering::Release);
                // Even a failed build may have created storage. Cleanup, not
                // an optimistic error path, releases its reservation.
                Err(error)
            }
        }
    }
}
struct WriteConsent(Arc<dyn FileWriteConsent>, Approval);
impl FileWriteConsent for WriteConsent {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}
struct OwnedWrite {
    inner: Option<Box<dyn FileWriteDestination>>,
    artifact: Arc<Artifact>,
    approval: Approval,
    _consent: WriteRootConsent,
    owner: Option<ArtifactOwner>,
}
impl OwnedWrite {
    fn inner(&mut self) -> io::Result<&mut Box<dyn FileWriteDestination>> {
        self.inner.as_mut().ok_or_else(denied)
    }
    fn record(&self) {
        if let Some(inner) = self.inner.as_ref() {
            let actual = inner.status();
            let mut state = lock(&self.artifact.state);
            state.write = actual;
            state.published |= actual.published;
            // Publication only follows the platform adapter's actual full
            // re-read/hash/sync. Record it even if the final permit check failed.
            let fully_verified =
                actual.published && !actual.poisoned && state.size == Some(actual.confirmed_bytes);
            state.verified |= fully_verified;
        }
    }
}
impl FileWriteDestination for OwnedWrite {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        let underlying = self
            .inner
            .as_ref()
            .map(|inner| inner.consent())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        Arc::new(WriteConsent(underlying, self.approval.clone()))
    }
    fn status(&self) -> FileWriteState {
        self.inner
            .as_ref()
            .map(|inner| inner.status())
            .unwrap_or_else(|| lock(&self.artifact.state).write)
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let approval = self.approval.clone();
        let result = self.inner()?.prepare(&mut || {
            approval.check()?;
            authorized()
        });
        self.record();
        result
    }
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let approval = self.approval.clone();
        let result = self.inner()?.write(chunk, &mut || {
            approval.check()?;
            authorized()
        });
        self.record();
        result
    }
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let approval = self.approval.clone();
        let result = self.inner()?.finish(&mut || {
            approval.check()?;
            authorized()
        });
        self.record();
        if let Err(error) = &result {
            lock(&self.artifact.state).error = Some(format!(
                "remote completion was not confirmed ({:?}); publication facts are retained",
                error.kind()
            ));
        }
        result
    }
    fn cleanup(&mut self) -> io::Result<()> {
        let result = self.inner()?.cleanup();
        self.record();
        if let Err(error) = &result {
            lock(&self.artifact.state).cleanup_error = Some(format!(
                "remote staging cleanup failed ({:?})",
                error.kind()
            ));
        }
        result
    }
}
impl Drop for OwnedWrite {
    fn drop(&mut self) {
        self.record();
        // The actual destination destructor closes handles before publishing
        // the local owner receipt. Unknown publication is never rolled back.
        self.inner.take();
        let mut state = lock(&self.artifact.state);
        state.phase = if state.published {
            "received"
        } else {
            "failed"
        }
        .into();
        if !state.published {
            self.artifact.discard.store(true, Ordering::Release);
        }
        drop(state);
        self.owner.take();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
enum HostFileIdentity {
    Native(AndroidFileIdentity),
    Browser { browser_binding: BrowserHostBinding },
}
impl From<AndroidFileIdentity> for HostFileIdentity {
    fn from(value: AndroidFileIdentity) -> Self {
        Self::Native(value)
    }
}
impl HostFileIdentity {
    fn current(&self, core: &CoreHandle) -> bool {
        match self {
            Self::Native(identity) => identity.current(core),
            Self::Browser { browser_binding } => {
                core.browser_host_data_binding().as_ref() == Some(browser_binding)
            }
        }
    }
}

/// Local copies also observe the actual proved business lease before and
/// after each I/O, independently of a later Core snapshot publication.
struct HostFileGuard {
    identity: HostFileIdentity,
    browser_proof: Option<LeaseControl>,
    channel: Channel,
}
impl AndroidExportIdentity for HostFileGuard {
    fn current(&self, core: &CoreHandle) -> bool {
        if !self.identity.current(core) {
            return false;
        }
        match &self.identity {
            HostFileIdentity::Native(_) => true,
            HostFileIdentity::Browser { browser_binding } => {
                self.browser_proof.as_ref().is_some_and(|proof| {
                    proof
                        .check_channel_binding(self.channel, browser_binding.connection_generation)
                        .is_ok()
                })
            }
        }
    }
}
impl Session {
    fn owner_current(&self, core: &CoreHandle) -> bool {
        let HostFileIdentity::Browser { browser_binding } = &self.identity else {
            return self.identity.current(core);
        };
        let Some(proof) = &self.browser_proof else {
            return false;
        };
        if (self.read.is_some()
            && proof
                .check_channel_binding(Channel::FileRead, browser_binding.connection_generation)
                .is_err())
            || (self.write.is_some()
                && proof
                    .check_channel_binding(
                        Channel::FileWrite,
                        browser_binding.connection_generation,
                    )
                    .is_err())
        {
            return false;
        }
        if self.identity.current(core) {
            return true;
        }
        // The factory is consumed after proof, before Core publishes Connected.
        // This is retention only: every local selection still requires current().
        core.snapshot()
            .browser_host
            .data
            .as_ref()
            .is_some_and(|host| {
                host.status == BrowserHostStatus::Establishing
                    && host.request_id == browser_binding.request_id
                    && host.connection_generation == browser_binding.connection_generation
            })
    }
}

struct Session {
    identity: HostFileIdentity,
    active: Arc<AtomicBool>,
    roots: ReadRegistry,
    receive: ReceiveRegistry,
    read: Option<FileWorkerMonitor>,
    write: Option<FileWriteMonitor>,
    browser_proof: Option<LeaseControl>,
    browser_retained: Arc<AtomicBool>,
    saf_consumed: Mutex<BTreeSet<String>>,
}
impl Session {
    fn revoke(&self) {
        self.active.store(false, Ordering::Release);
        for entry in lock(&self.roots).values() {
            entry.artifact.active.store(false, Ordering::Release);
        }
        lock(&self.roots).clear();
        if let Some(grant) = lock(&self.receive).take() {
            grant.active.store(false, Ordering::Release);
        }
    }
    fn stopped(&self) -> bool {
        !self.browser_retained.load(Ordering::Acquire)
            && self
                .read
                .as_ref()
                .is_none_or(|monitor| monitor.status().finished)
            && self
                .write
                .as_ref()
                .is_none_or(|monitor| monitor.status().finished)
    }
}
struct SnapshotJob {
    artifact: Arc<Artifact>,
    thread: Option<JoinHandle<io::Result<Arc<ReadEntry>>>>,
    entry: Option<Arc<ReadEntry>>,
}
struct ExportJob {
    artifact_id: String,
    identity: HostFileIdentity,
    saf_grant: Option<String>,
    created: Instant,
    status: Arc<Mutex<AndroidExportStatus>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
#[derive(Default)]
pub(crate) struct AndroidHostFiles {
    area: Option<(PathBuf, Dir)>,
    session: Option<Session>,
    book: SharedBook,
    snapshots: BTreeMap<String, SnapshotJob>,
    cleanups: BTreeMap<String, JoinHandle<io::Result<()>>>,
    exports: BTreeMap<String, ExportJob>,
    closing: bool,
}
impl AndroidHostFiles {
    pub(crate) fn share(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        name: String,
        source: File,
    ) -> Result<String, String> {
        self.share_for(core, &identity.clone().into(), name, source)
    }
    pub(crate) fn approve_receive(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        approved: bool,
    ) -> Result<(), String> {
        self.approve_receive_for(core, &identity.clone().into(), approved)
    }
    pub(crate) fn discard(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        id: &str,
    ) -> Result<(), String> {
        self.discard_for(core, &identity.clone().into(), id)
    }
    pub(crate) fn status(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
    ) -> Result<serde_json::Value, String> {
        self.status_for(core, &identity.clone().into())
    }
    pub(crate) fn start_export(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        id: &str,
        destination: File,
    ) -> Result<AndroidExportStatus, String> {
        self.start_export_for(core, &identity.clone().into(), id, destination)
    }
    pub(crate) fn cancel_export(
        &mut self,
        identity: &AndroidFileIdentity,
        id: &str,
    ) -> Result<(), String> {
        self.cancel_export_for(&identity.clone().into(), id)
    }
    fn consume_browser_saf(
        &self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        grant_id: &str,
        write: bool,
    ) -> Result<HostFileIdentity, String> {
        let identity = HostFileIdentity::Browser {
            browser_binding: binding.clone(),
        };
        let access = Self::check(core, &identity)?;
        if !(if write { access.write } else { access.read }) {
            return Err("SAF direction is not permitted".into());
        }
        let session = self
            .session
            .as_ref()
            .filter(|session| {
                session.identity == identity && session.active.load(Ordering::Acquire)
            })
            .ok_or_else(|| "browser SAF owner ended".to_owned())?;
        let proof = session
            .browser_proof
            .as_ref()
            .ok_or_else(|| "browser SAF proof unavailable".to_owned())?;
        proof
            .check_channel_binding(
                if write {
                    Channel::FileWrite
                } else {
                    Channel::FileRead
                },
                binding.connection_generation,
            )
            .map_err(|error| error.to_string())?;
        consume_saf_grant(&session.saf_consumed, grant_id)?;
        Ok(identity)
    }
    pub(crate) fn browser_status(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
    ) -> Result<serde_json::Value, String> {
        self.status_for(
            core,
            &HostFileIdentity::Browser {
                browser_binding: binding.clone(),
            },
        )
    }
    pub(crate) fn browser_roots(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
    ) -> Result<(Vec<BrowserHostFileRootView>, Vec<BrowserHostFileRootView>), String> {
        let identity = HostFileIdentity::Browser {
            browser_binding: binding.clone(),
        };
        Self::check(core, &identity)?;
        self.refresh(core);
        let Some(session) = self.session.as_ref().filter(|session| {
            session.identity == identity && session.active.load(Ordering::Acquire)
        }) else {
            return Ok((Vec::new(), Vec::new()));
        };
        let reads = lock(&session.roots)
            .values()
            .filter(|entry| entry.approval.check().is_ok())
            .map(|entry| BrowserHostFileRootView {
                root_id: entry.artifact.id.clone(),
                display_name: entry.artifact.name.clone(),
            })
            .collect();
        let writes = lock(&session.receive)
            .as_ref()
            .filter(|grant| grant.active.load(Ordering::Acquire))
            .map(|grant| BrowserHostFileRootView {
                root_id: grant.id.clone(),
                display_name: "Android 私有接收区".to_owned(),
            })
            .into_iter()
            .collect();
        Ok((reads, writes))
    }
    pub(crate) fn browser_share(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        grant_id: &str,
        name: String,
        source: File,
    ) -> Result<String, String> {
        let identity = self.consume_browser_saf(core, binding, grant_id, false)?;
        self.share_for(core, &identity, name, source)
    }
    pub(crate) fn browser_approve_receive(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        approved: bool,
    ) -> Result<(), String> {
        if approved {
            let guard = self.file_guard(
                &HostFileIdentity::Browser {
                    browser_binding: binding.clone(),
                },
                Channel::FileWrite,
            );
            if !guard.current(core) {
                return Err("browser FileWrite proof ended".into());
            }
        }
        self.approve_receive_for(
            core,
            &HostFileIdentity::Browser {
                browser_binding: binding.clone(),
            },
            approved,
        )
    }
    pub(crate) fn browser_discard(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        id: &str,
    ) -> Result<(), String> {
        self.discard_for(
            core,
            &HostFileIdentity::Browser {
                browser_binding: binding.clone(),
            },
            id,
        )
    }
    pub(crate) fn browser_start_export(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        grant_id: &str,
        id: &str,
        destination: File,
    ) -> Result<AndroidExportStatus, String> {
        match self.consume_browser_saf(core, binding, grant_id, true) {
            Ok(identity) => {
                let status = self.start_export_for(core, &identity, id, destination)?;
                if let Some(export) = self.exports.get_mut(&status.export_id) {
                    export.saf_grant = Some(grant_id.to_owned());
                }
                Ok(status)
            }
            Err(error) => Err(export_start_error(
                error,
                clear_saf_destination(&destination),
            )),
        }
    }
    /// Local cleanup observation remains available after the active Core proof
    /// is gone. It grants no file access and is scoped to the exact original
    /// proof and the one-use local picker grant, even if Java missed the reply.
    pub(crate) fn browser_export_status(
        &mut self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
        grant_id: &str,
    ) -> Result<Option<AndroidExportStatus>, String> {
        if !nestlink_protocol::valid_id(grant_id) {
            return Err("Android browser export grant is invalid".into());
        }
        self.refresh(core);
        let identity = HostFileIdentity::Browser {
            browser_binding: binding.clone(),
        };
        Ok(self
            .exports
            .values()
            .find(|export| {
                export.identity == identity && export.saf_grant.as_deref() == Some(grant_id)
            })
            .map(|export| lock(&export.status).clone()))
    }
    pub(crate) fn browser_cancel_export(
        &mut self,
        binding: &BrowserHostBinding,
        id: &str,
    ) -> Result<(), String> {
        self.cancel_export_for(
            &HostFileIdentity::Browser {
                browser_binding: binding.clone(),
            },
            id,
        )
    }
    fn revoke_browser(&mut self, binding: &BrowserHostBinding) {
        let identity = HostFileIdentity::Browser {
            browser_binding: binding.clone(),
        };
        if let Some(session) = self
            .session
            .as_ref()
            .filter(|session| session.identity == identity)
        {
            session.revoke();
        }
        for (_, artifact) in lock(&self.book)
            .entries
            .values()
            .filter(|(_, artifact)| artifact.identity == identity)
        {
            artifact.active.store(false, Ordering::Release);
            artifact.discard.store(true, Ordering::Release);
        }
        for export in self
            .exports
            .values()
            .filter(|export| export.identity == identity)
        {
            export.cancel.store(true, Ordering::Release);
        }
    }
    pub(crate) fn set_area(&mut self, path: PathBuf) -> Result<(), String> {
        if self.closing || !path.is_absolute() {
            return Err("Android host private area is unavailable".into());
        }
        if let Some((current, _)) = &self.area {
            return if current == &path {
                Ok(())
            } else {
                Err("Android host private area cannot be replaced".into())
            };
        }
        nestlink_platform_security::private_directory(&path)
            .map_err(|_| "Android host area is not private".to_owned())?;
        let directory = Dir::open_ambient_dir(&path, cap_std::ambient_authority())
            .map_err(|_| "Android host area cannot be opened".to_owned())?;
        if directory
            .entries()
            .map_err(|_| "Android host area cannot be inspected".to_owned())?
            .next()
            .is_some()
        {
            return Err("Android host private area contains unowned historical data; it cannot be approved or reused".into());
        }
        self.area = Some((path, directory));
        Ok(())
    }
    fn check(
        core: &CoreHandle,
        identity: &HostFileIdentity,
    ) -> Result<nestlink_app_core::NativeFileAccess, String> {
        if !identity.current(core) {
            return Err("Android host files belong to an ended session".into());
        }
        match identity {
            HostFileIdentity::Native(identity) => {
                let access = core
                    .native_file_access(&identity.binding, identity.core_generation)
                    .map_err(|error| error.to_string())?;
                if !access.is_host
                    || core.native_host_session_binding().as_ref() != Some(&identity.binding)
                {
                    return Err("only this proved hosting session can approve local files".into());
                }
                Ok(access)
            }
            HostFileIdentity::Browser { browser_binding } => {
                let snapshot = core.snapshot();
                let host = snapshot
                    .browser_host
                    .data
                    .as_ref()
                    .filter(|host| host.binding.as_ref() == Some(browser_binding))
                    .ok_or_else(|| "browser host proof changed".to_owned())?;
                Ok(nestlink_app_core::NativeFileAccess {
                    is_host: true,
                    read: host.data.permitted_file_read,
                    write: host.data.permitted_file_write,
                })
            }
        }
    }
    fn file_guard(&self, identity: &HostFileIdentity, channel: Channel) -> HostFileGuard {
        HostFileGuard {
            identity: identity.clone(),
            browser_proof: self
                .session
                .as_ref()
                .filter(|session| {
                    session.identity == *identity && session.active.load(Ordering::Acquire)
                })
                .and_then(|session| session.browser_proof.clone()),
            channel,
        }
    }
    pub(crate) fn attach(
        &mut self,
        core: &CoreHandle,
        runtime: &Runtime,
        native: &AndroidFileIdentity,
    ) -> Result<(), String> {
        let identity = &HostFileIdentity::Native(native.clone());
        let access = Self::check(core, identity)?;
        self.refresh(core);
        if self.closing {
            return Err("Android host file owners are closing".into());
        }
        if self.session.as_ref().is_some_and(|session| {
            session.identity != *identity || !session.active.load(Ordering::Acquire)
        }) {
            return Err("previous Android host file owners or cleanup are still retained".into());
        }
        let (path, _) = self
            .area
            .as_ref()
            .ok_or_else(|| "configure the app private host area first".to_owned())?;
        if self.session.is_none() {
            self.session = Some(Session {
                identity: identity.clone(),
                active: Arc::new(AtomicBool::new(true)),
                roots: Arc::new(Mutex::new(BTreeMap::new())),
                receive: Arc::new(Mutex::new(None)),
                read: None,
                write: None,
                browser_proof: None,
                browser_retained: Arc::new(AtomicBool::new(false)),
                saf_consumed: Mutex::new(BTreeSet::new()),
            });
        }
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "Android host session is unavailable".to_owned())?;
        if access.read && session.read.is_none() {
            session.read = Some(
                runtime
                    .block_on(core.native_host_start_file_read(
                        &native.binding,
                        native.core_generation,
                        DynamicRead {
                            roots: session.roots.clone(),
                            active: session.active.clone(),
                        },
                    ))
                    .map_err(|error| error.to_string())?,
            );
        }
        if access.write && session.write.is_none() {
            session.write = Some(
                runtime
                    .block_on(core.native_host_start_file_write(
                        &native.binding,
                        native.core_generation,
                        DynamicWrite {
                            grant: session.receive.clone(),
                            session_active: session.active.clone(),
                            identity: identity.clone(),
                            book: self.book.clone(),
                            area: path.clone(),
                        },
                    ))
                    .map_err(|error| error.to_string())?,
            );
        }
        Ok(())
    }
    fn share_for(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
        name: String,
        source: File,
    ) -> Result<String, String> {
        if !Self::check(core, identity)?.read {
            return Err("FileRead is not approved in this session".into());
        }
        label(&name).map_err(|_| "selected file name cannot be shared".to_owned())?;
        let session = self
            .session
            .as_ref()
            .filter(|session| {
                session.identity == *identity
                    && session.active.load(Ordering::Acquire)
                    && session.read.is_some()
            })
            .ok_or_else(|| "attach Android host FileRead first".to_owned())?;
        let guard = self.file_guard(identity, Channel::FileRead);
        if !guard.current(core) {
            return Err("Android host FileRead proof ended".into());
        }
        let (area, _) = self
            .area
            .as_ref()
            .ok_or_else(|| "Android host private area is unavailable".to_owned())?;
        let id = uuid::Uuid::new_v4().to_string();
        let reservation = lock(&self.book).remaining();
        if reservation == 0 {
            return Err("Android host private file byte capacity is full".into());
        }
        let artifact = Arc::new(Artifact {
            id: id.clone(),
            identity: identity.clone(),
            name,
            area_name: uuid::Uuid::new_v4().to_string(),
            receive: false,
            write_root: None,
            active: Arc::new(AtomicBool::new(true)),
            owners: AtomicUsize::new(1),
            discard: AtomicBool::new(false),
            state: Mutex::new(ArtifactState {
                phase: "preparing".into(),
                ..ArtifactState::default()
            }),
        });
        // A descriptor's stat may block. Reserve the full available maximum
        // before the thread opens, stats, or copies anything.
        lock(&self.book)
            .reserve(reservation, artifact.clone())
            .map_err(|error| error.to_string())?;
        let worker_artifact = artifact.clone();
        let worker_core = core.clone();
        let approval = Approval(vec![session.active.clone(), artifact.active.clone()]);
        let directory = area.join(&artifact.area_name);
        let result = thread::Builder::new()
            .name("nestlink-android-host-snapshot".into())
            .spawn(move || {
                prepare_snapshot(
                    source,
                    &directory,
                    &worker_artifact,
                    &worker_core,
                    approval,
                    reservation,
                    guard,
                )
            });
        match result {
            Ok(thread) => {
                self.snapshots.insert(
                    id.clone(),
                    SnapshotJob {
                        artifact,
                        thread: Some(thread),
                        entry: None,
                    },
                );
                Ok(id)
            }
            Err(_) => {
                artifact.owners.store(0, Ordering::Release);
                artifact.discard.store(true, Ordering::Release);
                let mut state = lock(&artifact.state);
                state.phase = "failed".into();
                state.error = Some("Android snapshot worker could not start".into());
                Err("Android snapshot worker could not start; reserved cleanup is retained".into())
            }
        }
    }
    fn approve_receive_for(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
        approve: bool,
    ) -> Result<(), String> {
        if !Self::check(core, identity)?.write {
            return Err("FileWrite is not approved in this session".into());
        }
        let session = self
            .session
            .as_ref()
            .filter(|session| {
                session.identity == *identity
                    && session.active.load(Ordering::Acquire)
                    && session.write.is_some()
            })
            .ok_or_else(|| "attach Android host FileWrite first".to_owned())?;
        let mut grant = lock(&session.receive);
        if let Some(previous) = grant.take() {
            previous.active.store(false, Ordering::Release);
        }
        if approve {
            *grant = Some(ReceiveGrant {
                id: uuid::Uuid::new_v4().to_string(),
                active: Arc::new(AtomicBool::new(true)),
            });
        }
        Ok(())
    }
    fn discard_for(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
        id: &str,
    ) -> Result<(), String> {
        Self::check(core, identity)?;
        let artifact = lock(&self.book)
            .entries
            .get(id)
            .map(|(_, artifact)| artifact.clone())
            .filter(|artifact| artifact.identity == *identity)
            .ok_or_else(|| "Android host artifact is unavailable".to_owned())?;
        artifact.active.store(false, Ordering::Release);
        artifact.discard.store(true, Ordering::Release);
        if let Some(session) = &self.session {
            lock(&session.roots).remove(id);
        }
        for export in self
            .exports
            .values()
            .filter(|export| export.artifact_id == id)
        {
            export.cancel.store(true, Ordering::Release);
        }
        self.refresh(core);
        Ok(())
    }
    pub(crate) fn begin_shutdown(&mut self) {
        self.closing = true;
        if let Some(session) = &self.session {
            session.revoke();
        }
        for (_, artifact) in lock(&self.book).entries.values() {
            artifact.active.store(false, Ordering::Release);
            artifact.discard.store(true, Ordering::Release);
        }
        for export in self.exports.values() {
            export.cancel.store(true, Ordering::Release);
        }
    }
    pub(crate) fn refresh(&mut self, core: &CoreHandle) {
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.owner_current(core))
        {
            if let Some(session) = &self.session {
                session.revoke();
            }
            for (_, artifact) in lock(&self.book).entries.values() {
                artifact.active.store(false, Ordering::Release);
                artifact.discard.store(true, Ordering::Release);
            }
            for export in self.exports.values() {
                export.cancel.store(true, Ordering::Release);
            }
        }
        let completed: Vec<_> = self
            .snapshots
            .iter()
            .filter(|(_, job)| job.thread.as_ref().is_some_and(JoinHandle::is_finished))
            .map(|(id, _)| id.clone())
            .collect();
        for id in completed {
            if let Some(job) = self.snapshots.get_mut(&id)
                && let Some(thread) = job.thread.take()
            {
                match thread.join() {
                    Ok(Ok(entry))
                        if !self.closing
                            && entry.approval.check().is_ok()
                            && job.artifact.identity.current(core) =>
                    {
                        if let Some(session) = self.session.as_ref().filter(|session| {
                            session.identity == job.artifact.identity
                                && session.active.load(Ordering::Acquire)
                        }) {
                            lock(&session.roots).insert(id.clone(), entry.clone());
                            job.entry = Some(entry);
                            let mut book = lock(&self.book);
                            if let Some((reserved, _)) = book.entries.get_mut(&id) {
                                *reserved = lock(&job.artifact.state).size.unwrap_or(*reserved);
                            }
                            lock(&job.artifact.state).phase = "shared".into();
                        } else {
                            job.artifact.discard.store(true, Ordering::Release);
                        }
                    }
                    result => {
                        let error = match result {
                            Ok(Err(error)) => {
                                format!("selected snapshot failed ({:?})", error.kind())
                            }
                            Err(_) => "selected snapshot worker panicked".to_owned(),
                            _ => "selected snapshot approval ended".to_owned(),
                        };
                        lock(&job.artifact.state).error = Some(error);
                        lock(&job.artifact.state).phase = "failed".into();
                        job.artifact.discard.store(true, Ordering::Release);
                    }
                }
                job.artifact.owners.store(0, Ordering::Release);
            }
        }
        let finished: Vec<_> = self
            .exports
            .iter()
            .filter(|(_, export)| export.thread.as_ref().is_some_and(JoinHandle::is_finished))
            .map(|(id, _)| id.clone())
            .collect();
        for id in finished {
            if let Some(export) = self.exports.get_mut(&id)
                && let Some(thread) = export.thread.take()
            {
                let joined = thread.join().is_ok();
                let mut status = lock(&export.status);
                status.owner_stopped = true;
                if !joined {
                    status.phase = "failed".into();
                    status.error = Some(
                        "Android host export worker panicked; inspect the system target".into(),
                    );
                    status.destination_cleanup_complete = false;
                }
                export.status.clear_poison();
            }
        }
        let finished: Vec<_> = self
            .cleanups
            .iter()
            .filter(|(_, thread)| thread.is_finished())
            .map(|(id, _)| id.clone())
            .collect();
        for id in finished {
            if let Some(thread) = self.cleanups.remove(&id) {
                match thread.join() {
                    Ok(Ok(())) => {
                        lock(&self.book).entries.remove(&id);
                        self.snapshots.remove(&id);
                    }
                    result => {
                        if let Some((_, artifact)) = lock(&self.book).entries.get(&id) {
                            let error = match result {
                                Ok(Err(error)) => format!(
                                    "private cleanup failed ({:?}); capacity and owner retained",
                                    error.kind()
                                ),
                                _ => "private cleanup worker panicked; owner retained".into(),
                            };
                            lock(&artifact.state).cleanup_error = Some(error);
                        }
                    }
                }
            }
        }
        let discarded: Vec<_> = lock(&self.book)
            .entries
            .values()
            .filter(|(_, artifact)| {
                artifact.discard.load(Ordering::Acquire)
                    && artifact.owners.load(Ordering::Acquire) == 0
            })
            .map(|(_, artifact)| artifact.clone())
            .collect();
        for artifact in discarded {
            if self.cleanups.contains_key(&artifact.id)
                || self
                    .exports
                    .values()
                    .any(|export| export.artifact_id == artifact.id && export.thread.is_some())
            {
                continue;
            }
            if let Some(job) = self.snapshots.get_mut(&artifact.id) {
                if job.thread.is_some() {
                    continue;
                }
                if job
                    .entry
                    .as_ref()
                    .is_some_and(|entry| Arc::strong_count(entry) > 1)
                {
                    continue;
                }
                job.entry.take(); // Close the actual provider before deleting.
            }
            // Wait for receive's actual destination destructor and, during
            // session teardown, both actual host server monitors as well.
            if self.session.as_ref().is_some_and(|session| {
                !session.active.load(Ordering::Acquire) && !session.stopped()
            }) {
                continue;
            }
            if let Some((_, area)) = &self.area {
                match area.try_clone() {
                    Ok(directory) => {
                        let area_name = artifact.area_name.clone();
                        match thread::Builder::new()
                            .name("nestlink-android-host-cleanup".into())
                            .spawn(move || match directory.remove_dir_all(&area_name) {
                                Ok(()) => Ok(()),
                                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                                Err(error) => Err(error),
                            }) {
                            Ok(thread) => {
                                self.cleanups.insert(artifact.id.clone(), thread);
                            }
                            Err(_) => {
                                lock(&artifact.state).cleanup_error = Some(
                                    "private cleanup worker could not start; capacity retained"
                                        .into(),
                                );
                            }
                        }
                    }
                    Err(_) => {
                        lock(&artifact.state).cleanup_error = Some(
                            "private cleanup directory is unavailable; capacity retained".into(),
                        );
                    }
                }
            }
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.active.load(Ordering::Acquire) && session.stopped())
            && lock(&self.book).entries.is_empty()
            && self.cleanups.is_empty()
            && self.exports.values().all(|export| export.thread.is_none())
        {
            self.session = None;
        }
    }
    pub(crate) fn cleanup_complete(&mut self, core: &CoreHandle) -> bool {
        self.refresh(core);
        lock(&self.book).entries.is_empty()
            && self.session.as_ref().is_none_or(Session::stopped)
            && self.snapshots.values().all(|job| job.thread.is_none())
            && self.cleanups.is_empty()
            && self.exports.values().all(|export| export.thread.is_none())
    }
    fn status_for(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
    ) -> Result<serde_json::Value, String> {
        Self::check(core, identity)?;
        self.refresh(core);
        let book = lock(&self.book);
        let artifacts: Vec<_> = book.entries.values().filter(|(_, artifact)| artifact.identity == *identity).map(|(reserved, artifact)| {
            let state = lock(&artifact.state);
            let snapshot_stopped = self.snapshots.get(&artifact.id).is_none_or(|job| job.thread.is_none());
            serde_json::json!({ "id": artifact.id, "kind": if artifact.receive { "receive" } else { "share" }, "display_name": artifact.name,
                "phase": state.phase, "size": state.size, "reserved_bytes": reserved, "published": state.published, "verified": state.verified,
                "owner_stopped": snapshot_stopped && artifact.owners.load(Ordering::Acquire) == 0,
                "cleanup_pending": artifact.discard.load(Ordering::Acquire), "error": state.error, "cleanup_error": state.cleanup_error })
        }).collect();
        let receive = self
            .session
            .as_ref()
            .filter(|session| session.identity == *identity)
            .is_some_and(|session| {
                lock(&session.receive)
                    .as_ref()
                    .is_some_and(|grant| grant.active.load(Ordering::Acquire))
            });
        let mut ordered: Vec<_> = self
            .exports
            .values()
            .filter(|export| export.identity == *identity)
            .collect();
        ordered.sort_by_key(|export| export.created);
        let exports: Vec<_> = ordered.into_iter().map(|export| serde_json::json!({ "artifact_id": export.artifact_id, "status": export_json(&lock(&export.status)) })).collect();
        Ok(
            serde_json::json!({ "identity": identity, "receive_approved": receive, "artifacts": artifacts, "exports": exports,
            "reserved_bytes": MAX_BYTES - book.remaining(), "capacity": MAX_ARTIFACTS, "maximum_bytes": MAX_BYTES }),
        )
    }
    fn start_export_for(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
        id: &str,
        destination: File,
    ) -> Result<AndroidExportStatus, String> {
        let result = self.start_export_inner(core, identity, id, &destination);
        result.map_err(|error| export_start_error(error, clear_saf_destination(&destination)))
    }
    fn start_export_inner(
        &mut self,
        core: &CoreHandle,
        identity: &HostFileIdentity,
        id: &str,
        destination: &File,
    ) -> Result<AndroidExportStatus, String> {
        Self::check(core, identity)?;
        self.refresh(core);
        let guard = self.file_guard(identity, Channel::FileWrite);
        if !guard.current(core) {
            return Err("Android host FileWrite proof ended".into());
        }
        if self.closing || self.exports.values().any(|export| export.thread.is_some()) {
            return Err("wait for the previous Android host export owner".into());
        }
        while self.exports.len() >= 32 {
            let expired = self
                .exports
                .iter()
                .filter(|(_, export)| export.thread.is_none())
                .min_by_key(|(_, export)| export.created)
                .map(|(id, _)| id.clone())
                .ok_or_else(|| "Android host export history is full".to_owned())?;
            self.exports.remove(&expired);
        }
        let artifact = lock(&self.book)
            .entries
            .get(id)
            .map(|(_, artifact)| artifact.clone())
            .filter(|artifact| {
                artifact.identity == *identity
                    && artifact.receive
                    && !artifact.discard.load(Ordering::Acquire)
                    && artifact.owners.load(Ordering::Acquire) == 0
            })
            .ok_or_else(|| "verified Android received file is unavailable".to_owned())?;
        let (size, hash) = {
            let state = lock(&artifact.state);
            if !state.published || !state.verified {
                return Err(
                    "only an actually published, fully verified received file can be exported"
                        .into(),
                );
            }
            (
                state
                    .size
                    .ok_or_else(|| "received file size is unknown".to_owned())?,
                state.sha256.clone(),
            )
        };
        let directory = self
            .area
            .as_ref()
            .ok_or_else(|| "Android host private area is unavailable".to_owned())?
            .1
            .open_dir_nofollow(&artifact.area_name)
            .map_err(|_| "verified received file cannot be opened".to_owned())?;
        let target = destination
            .try_clone()
            .map_err(|_| "Android host SAF target could not be retained".to_owned())?;
        let export_id = uuid::Uuid::new_v4().to_string();
        let status = Arc::new(Mutex::new(AndroidExportStatus {
            export_id: export_id.clone(),
            phase: "running".into(),
            total_bytes: size,
            ..AndroidExportStatus::default()
        }));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_status = status.clone();
        let worker_cancel = cancel.clone();
        let worker_core = core.clone();
        let name = artifact.name.clone();
        let thread = thread::Builder::new()
            .name("nestlink-android-host-saf-export".into())
            .spawn(move || {
                let result = export_verified_file(
                    directory,
                    name,
                    target,
                    size,
                    &hash,
                    AndroidExportSession {
                        core: &worker_core,
                        identity: &guard,
                        cancelled: &worker_cancel,
                        status: &worker_status,
                    },
                );
                let mut status = lock(&worker_status);
                match result {
                    Ok(()) => {
                        status.phase = "completed".into();
                        status.destination_cleanup_complete = true;
                    }
                    Err(ExportFailure::Cancelled { cleanup_failed }) => {
                        status.phase = "cancelled".into();
                        status.destination_cleanup_complete = !cleanup_failed;
                        if cleanup_failed {
                            status.destination_cleanup_error =
                                Some("cancelled system target could not be cleared".into());
                        }
                    }
                    Err(ExportFailure::Io {
                        kind,
                        cleanup_failed,
                    }) => {
                        status.phase = "failed".into();
                        status.error = Some(format!("received file export failed ({kind:?})"));
                        status.destination_cleanup_complete = !cleanup_failed;
                        if cleanup_failed {
                            status.destination_cleanup_error = Some(
                                "failed system target could not be cleared; inspect it manually"
                                    .into(),
                            );
                        }
                    }
                }
            })
            .map_err(|_| "Android host SAF export worker could not start".to_owned())?;
        self.exports.insert(
            export_id,
            ExportJob {
                artifact_id: id.into(),
                identity: identity.clone(),
                saf_grant: None,
                created: Instant::now(),
                status: status.clone(),
                cancel,
                thread: Some(thread),
            },
        );
        let receipt = lock(&status).clone();
        Ok(receipt)
    }
    fn cancel_export_for(
        &mut self,
        identity: &HostFileIdentity,
        export_id: &str,
    ) -> Result<(), String> {
        let export = self
            .exports
            .get(export_id)
            .filter(|export| export.identity == *identity)
            .ok_or_else(|| "Android host export is unavailable".to_owned())?;
        export.cancel.store(true, Ordering::Release);
        Ok(())
    }
}

/// File servers are consumed from exact, mutually proved claims. This owner
/// retains the actual servers and the shared SAF storage until join + cleanup.
pub(crate) struct AndroidBrowserFileOwner {
    files: Arc<Mutex<AndroidHostFiles>>,
    core: CoreHandle,
    binding: BrowserHostBinding,
    retained: Arc<AtomicBool>,
    read: Option<FileReadServer>,
    write: Option<FileWriteServer>,
}
impl AndroidBrowserFileOwner {
    pub(crate) fn start(
        files: Arc<Mutex<AndroidHostFiles>>,
        core: CoreHandle,
        binding: BrowserHostBinding,
        expected_read: bool,
        expected_write: bool,
        read: Option<ClaimedFileRead>,
        write: Option<ClaimedFileWrite>,
    ) -> Result<Self, WebRtcHostError> {
        if read.is_some() != expected_read || write.is_some() != expected_write {
            return Err(WebRtcHostError::Permit);
        }
        if let Some(claim) = read.as_ref() {
            if claim.generation() != binding.connection_generation {
                return Err(WebRtcHostError::Permit);
            }
            claim
                .lease_control()
                .check_channel_binding(Channel::FileRead, binding.connection_generation)?;
        }
        if let Some(claim) = write.as_ref() {
            if claim.generation() != binding.connection_generation {
                return Err(WebRtcHostError::Permit);
            }
            claim
                .lease_control()
                .check_channel_binding(Channel::FileWrite, binding.connection_generation)?;
        }
        let retained = Arc::new(AtomicBool::new(expected_read || expected_write));
        let mut owner = Self {
            files: files.clone(),
            core: core.clone(),
            binding: binding.clone(),
            retained: retained.clone(),
            read: None,
            write: None,
        };
        if !expected_read && !expected_write {
            return Ok(owner);
        }
        let proof = read
            .as_ref()
            .map(ClaimedFileRead::lease_control)
            .or_else(|| write.as_ref().map(ClaimedFileWrite::lease_control))
            .ok_or(WebRtcHostError::Permit)?;
        let mut state = lock(&files);
        state.refresh(&core);
        if state.closing || state.session.is_some() || !lock(&state.book).entries.is_empty() {
            return Err(WebRtcHostError::Permit);
        }
        let path = state
            .area
            .as_ref()
            .map(|(path, _)| path.clone())
            .ok_or(WebRtcHostError::Permit)?;
        let identity = HostFileIdentity::Browser {
            browser_binding: binding.clone(),
        };
        let active = Arc::new(AtomicBool::new(true));
        let roots = Arc::new(Mutex::new(BTreeMap::new()));
        let receive = Arc::new(Mutex::new(None));
        state.session = Some(Session {
            identity: identity.clone(),
            active: active.clone(),
            roots: roots.clone(),
            receive: receive.clone(),
            read: None,
            write: None,
            browser_proof: Some(proof.clone()),
            browser_retained: retained,
            saf_consumed: Mutex::new(BTreeSet::new()),
        });
        if let Some(claim) = read {
            match FileReadServer::start_claimed(
                claim,
                DynamicRead {
                    roots,
                    active: active.clone(),
                },
            ) {
                Ok(server) => {
                    if let Some(session) = state.session.as_mut() {
                        session.read = Some(server.monitor());
                    }
                    owner.read = Some(server);
                }
                Err(_) => {
                    active.store(false, Ordering::Release);
                }
            }
        }
        if let Some(claim) = write {
            match FileWriteServer::start_claimed(
                claim,
                DynamicWrite {
                    grant: receive,
                    session_active: active.clone(),
                    identity,
                    book: state.book.clone(),
                    area: path,
                },
            ) {
                Ok(server) => {
                    if let Some(session) = state.session.as_mut() {
                        session.write = Some(server.monitor());
                    }
                    owner.write = Some(server);
                }
                Err(_) => {
                    active.store(false, Ordering::Release);
                }
            }
        }
        drop(state);
        if !active.load(Ordering::Acquire) {
            let _ = proof.stop(StopReason::PlatformChanged);
        }
        // On a partial startup failure, return the stopped owner rather than
        // dropping already-started servers. The SDK observes the stopped lease
        // and retains this owner through its normal cleanup path.
        Ok(owner)
    }
}
impl HostDataOwner for AndroidBrowserFileOwner {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>> {
        Box::pin(async move {
            lock(&self.files).revoke_browser(&self.binding);
            let mut pending = false;
            let mut failure = None;
            if let Some(server) = self.read.as_mut() {
                match server.shutdown(reason).await {
                    Ok(FileShutdown::Finished) => self.read = None,
                    Ok(FileShutdown::TimedOut) => pending = true,
                    Err(error) => failure = Some(error),
                }
            }
            if let Some(server) = self.write.as_mut() {
                match server.shutdown(reason).await {
                    Ok(FileShutdown::Finished) => self.write = None,
                    Ok(FileShutdown::TimedOut) => pending = true,
                    Err(error) => {
                        if failure.is_none() {
                            failure = Some(error);
                        }
                    }
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
            if pending {
                return Err(RemoteError::Cleanup(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Android browser file worker cleanup remains pending",
                )));
            }
            self.retained.store(false, Ordering::Release);
            if !lock(&self.files).cleanup_complete(&self.core) {
                return Err(RemoteError::Cleanup(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Android browser SAF snapshot/export/private cleanup remains pending",
                )));
            }
            Ok(())
        })
    }
}

fn hash_file(
    file: &mut impl Read,
    size: u64,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        check()?;
        let maximum = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..maximum])?;
        check()?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "selected document ended early",
            ));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(hash.finalize().to_vec())
}
fn prepare_snapshot(
    source: File,
    directory: &std::path::Path,
    artifact: &Arc<Artifact>,
    core: &CoreHandle,
    approval: Approval,
    maximum: u64,
    guard: HostFileGuard,
) -> io::Result<Arc<ReadEntry>> {
    prepare_snapshot_storage(source, directory, artifact, approval, maximum, &mut || {
        if guard.current(core) {
            Ok(())
        } else {
            Err(denied())
        }
    })
}
// The storage seam is exercised with real files below. Production always
// supplies the exact Core/session guard above, in addition to local approval.
fn prepare_snapshot_storage(
    mut source: File,
    directory: &std::path::Path,
    artifact: &Arc<Artifact>,
    approval: Approval,
    maximum: u64,
    session_check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Arc<ReadEntry>> {
    let deadline = Instant::now() + SNAPSHOT_BUDGET;
    let mut check = || {
        approval.check()?;
        session_check()?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "selected file snapshot expired",
            ));
        }
        Ok(())
    };
    check()?;
    let original = source.metadata()?;
    check()?;
    if !original.is_file() || original.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SAF selection must be a bounded regular seekable file",
        ));
    }
    source.seek(SeekFrom::Start(0))?;
    check()?;
    nestlink_platform_security::new_private_directory(directory)?;
    check()?;
    let dir = Dir::open_ambient_dir(directory, cap_std::ambient_authority())?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = dir.open_with(&artifact.name, &options)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = original.len();
    while remaining > 0 {
        check()?;
        let maximum = remaining.min(buffer.len() as u64) as usize;
        let count = source.read(&mut buffer[..maximum])?;
        check()?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "selected file ended during snapshot",
            ));
        }
        let mut written = 0;
        while written < count {
            check()?;
            let count = target.write(&buffer[written..count])?;
            check()?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snapshot write stopped",
                ));
            }
            written += count;
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let expected = hash.finalize().to_vec();
    source.seek(SeekFrom::Start(0))?;
    check()?;
    if hash_file(&mut source, original.len(), &mut check)? != expected
        || source.metadata()?.len() != original.len()
        || source.metadata()?.modified().ok() != original.modified().ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selected file changed during snapshot",
        ));
    }
    target.sync_all()?;
    check()?;
    target.seek(SeekFrom::Start(0))?;
    check()?;
    if target.metadata()?.len() != original.len()
        || hash_file(&mut target, original.len(), &mut check)? != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "actual private snapshot differs",
        ));
    }
    check()?;
    drop(target);
    drop(source);
    let (root, read) = ApprovedReadRoot::open(&artifact.id, directory, maximum)?;
    let (browse, metadata) = BrowseSelection::new_with_display_name(
        &artifact.id,
        &artifact.name,
        directory,
        BrowseLimits::default(),
    )?;
    let provider = BrowseRoots::new(FileRoots::new(vec![root])?, vec![browse])?;
    check()?;
    {
        let mut state = lock(&artifact.state);
        state.size = Some(original.len());
        state.sha256 = expected;
        state.verified = true;
        state.phase = "prepared".into();
    }
    Ok(Arc::new(ReadEntry {
        artifact: artifact.clone(),
        approval,
        provider: Mutex::new(provider),
        _read: read,
        _browse: metadata,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_core::NativeSessionBinding;
    use std::sync::mpsc;

    #[test]
    fn saf_grants_are_canonical_one_use_and_bounded_before_storage() -> Result<(), String> {
        let consumed = Mutex::new(BTreeSet::new());
        assert!(consume_saf_grant(&consumed, "arbitrary-provider-uri").is_err());
        assert!(lock(&consumed).is_empty());
        let id = uuid::Uuid::new_v4();
        assert!(consume_saf_grant(&consumed, &id.simple().to_string()).is_err());
        consume_saf_grant(&consumed, &id.to_string())?;
        assert!(consume_saf_grant(&consumed, &id.to_string()).is_err());
        for _ in 1..256 {
            consume_saf_grant(&consumed, &uuid::Uuid::new_v4().to_string())?;
        }
        assert!(consume_saf_grant(&consumed, &uuid::Uuid::new_v4().to_string()).is_err());
        assert_eq!(lock(&consumed).len(), 256);
        Ok(())
    }

    #[test]
    fn browser_artifact_keeps_full_proof_and_does_not_serialize_as_native()
    -> Result<(), serde_json::Error> {
        let native = serde_json::to_value(HostFileIdentity::Native(identity()))?;
        assert!(native.get("binding").is_some());
        assert!(native.get("core_generation").is_some());
        assert!(native.get("browser_binding").is_none());
        let browser = BrowserHostBinding {
            request_id: "outer".into(),
            session_id: "signed-inner".into(),
            controller_device_id: "controller".into(),
            host_device_id: "host".into(),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [3; 32],
            connection_generation: 4,
        };
        let actual = serde_json::to_value(HostFileIdentity::Browser {
            browser_binding: browser.clone(),
        })?;
        assert_eq!(
            actual.get("browser_binding"),
            Some(&serde_json::to_value(browser)?)
        );
        assert!(actual.get("binding").is_none());
        assert!(actual.get("core_generation").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn browser_export_cleanup_receipt_survives_core_stop_and_requires_exact_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let core = nestlink_app_core::AppCore::start(nestlink_app_core::Limits::default())?;
        let handle = core.handle();
        let binding = BrowserHostBinding {
            request_id: uuid::Uuid::new_v4().to_string(),
            session_id: uuid::Uuid::new_v4().to_string(),
            controller_device_id: uuid::Uuid::new_v4().to_string(),
            host_device_id: uuid::Uuid::new_v4().to_string(),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [3; 32],
            connection_generation: 4,
        };
        let grant = uuid::Uuid::new_v4().to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let status = Arc::new(Mutex::new(AndroidExportStatus {
            export_id: id.clone(),
            phase: "running".into(),
            ..AndroidExportStatus::default()
        }));
        let (release, blocked) = mpsc::channel();
        let worker_status = status.clone();
        let worker = thread::spawn(move || {
            let _ = blocked.recv();
            let mut receipt = lock(&worker_status);
            receipt.phase = "cancelled".into();
            receipt.destination_cleanup_complete = false;
            receipt.destination_cleanup_error = Some("provider refused cleanup".into());
        });
        let mut files = AndroidHostFiles::default();
        files.exports.insert(
            id.clone(),
            ExportJob {
                artifact_id: "received".into(),
                identity: HostFileIdentity::Browser {
                    browser_binding: binding.clone(),
                },
                saf_grant: Some(grant.clone()),
                created: Instant::now(),
                status,
                cancel: Arc::new(AtomicBool::new(false)),
                thread: Some(worker),
            },
        );
        assert!(handle.browser_host_data_binding().is_none());
        assert!(
            !files
                .browser_export_status(&handle, &binding, &grant)?
                .ok_or("missing running receipt")?
                .owner_stopped
        );
        let mut replaced = binding.clone();
        replaced.permit_sha256[0] ^= 1;
        assert!(
            files
                .browser_export_status(&handle, &replaced, &grant)?
                .is_none()
        );
        assert!(
            files
                .browser_export_status(&handle, &binding, &uuid::Uuid::new_v4().to_string())?
                .is_none()
        );
        assert!(
            files
                .browser_export_status(&handle, &binding, "not-a-picker-grant")
                .is_err()
        );
        drop(core);
        files.begin_shutdown();
        release.send(())?;
        let until = Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let receipt = files
                .browser_export_status(&handle, &binding, &grant)?
                .ok_or("lost final receipt")?;
            if receipt.owner_stopped {
                assert!(!receipt.destination_cleanup_complete);
                assert_eq!(
                    receipt.destination_cleanup_error.as_deref(),
                    Some("provider refused cleanup")
                );
                break;
            }
            if Instant::now() >= until {
                return Err("actual export worker did not join".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(files.cleanup_complete(&handle));
        assert!(
            !files
                .browser_export_status(&handle, &binding, &grant)?
                .ok_or("cleanup receipt vanished")?
                .destination_cleanup_complete
        );
        Ok(())
    }

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir()
                .join(format!("nestlink-host-files-test-{}", uuid::Uuid::new_v4()));
            nestlink_platform_security::new_private_directory(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn identity() -> AndroidFileIdentity {
        AndroidFileIdentity {
            binding: NativeSessionBinding {
                request_id: "storage-fixture".into(),
                connection_generation: 1,
            },
            core_generation: 1,
        }
    }
    fn artifact(name: &str) -> Arc<Artifact> {
        Arc::new(Artifact {
            id: uuid::Uuid::new_v4().to_string(),
            identity: identity().into(),
            name: name.into(),
            area_name: uuid::Uuid::new_v4().to_string(),
            receive: false,
            write_root: None,
            active: Arc::new(AtomicBool::new(true)),
            owners: AtomicUsize::new(1),
            discard: AtomicBool::new(false),
            state: Mutex::new(ArtifactState::default()),
        })
    }

    #[test]
    fn snapshot_contains_only_the_selected_actual_file_and_revoke_denies_it() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let selected = directory.0.join("selected.txt");
        std::fs::write(&selected, b"selected content")?;
        std::fs::write(
            directory.0.join("unselected-secret.txt"),
            b"never disclosed",
        )?;
        let artifact = artifact("selected.txt");
        let session = Arc::new(AtomicBool::new(true));
        let approval = Approval(vec![session.clone(), artifact.active.clone()]);
        let entry = prepare_snapshot_storage(
            File::open(selected)?,
            &directory.0.join(&artifact.area_name),
            &artifact,
            approval,
            1024,
            &mut || Ok(()),
        )?;
        assert_eq!(
            lock(&artifact.state).sha256,
            Sha256::digest(b"selected content").to_vec()
        );
        assert_eq!(
            std::fs::read(directory.0.join(&artifact.area_name).join("selected.txt"))?,
            b"selected content"
        );
        let roots = Arc::new(Mutex::new(BTreeMap::from([(
            artifact.id.clone(),
            entry.clone(),
        )])));
        let mut device = DynamicRead {
            roots,
            active: session,
        };
        assert_eq!(device.list_roots(&mut || Ok(()))?.roots.len(), 1);
        assert!(device.open(&artifact.id, "unselected-secret.txt").is_err());
        let mut source = device.open(&artifact.id, "selected.txt")?;
        let manifest = source.describe(&mut || Ok(()))?;
        assert_eq!(manifest.size, 16);
        artifact.active.store(false, Ordering::Release);
        assert!(source.read_chunk(0, 16, &mut || Ok(())).is_err());
        assert!(device.open(&artifact.id, "selected.txt").is_err());
        drop(source);
        drop(device);
        drop(entry);
        Ok(())
    }

    #[test]
    fn share_and_receive_reservations_share_bytes_and_zero_length_slots() -> io::Result<()> {
        let mut book = Book::default();
        book.reserve(MAX_BYTES - 3, artifact("snapshot.bin"))?;
        let receive = artifact("received.bin");
        assert!(book.reserve(4, receive.clone()).is_err());
        book.reserve(3, receive)?;
        for _ in 2..MAX_ARTIFACTS {
            book.reserve(0, artifact("empty.bin"))?;
        }
        assert_eq!(book.remaining(), 0);
        assert!(book.reserve(0, artifact("one-too-many.bin")).is_err());
        assert_eq!(book.entries.len(), MAX_ARTIFACTS);
        Ok(())
    }

    #[test]
    fn rejected_receive_cannot_create_staging_before_shared_quota_reservation() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let book = Arc::new(Mutex::new(Book::default()));
        lock(&book).reserve(MAX_BYTES, artifact("snapshot.bin"))?;
        let mut device = DynamicWrite {
            grant: Arc::new(Mutex::new(Some(ReceiveGrant {
                id: "receive-root".into(),
                active: Arc::new(AtomicBool::new(true)),
            }))),
            session_active: Arc::new(AtomicBool::new(true)),
            identity: identity().into(),
            book: book.clone(),
            area: directory.0.clone(),
        };
        let open = FileWriteOpen {
            root_id: "receive-root".into(),
            path: "incoming.txt".into(),
            size: 3,
            sha256: Sha256::digest(b"abc").to_vec(),
        };
        assert!(device.build(&open, &mut || Ok(())).is_err());
        assert_eq!(std::fs::read_dir(&directory.0)?.count(), 0);
        assert_eq!(lock(&book).entries.len(), 1);
        Ok(())
    }

    struct UnknownAfterActualPublish(Box<dyn FileWriteDestination>);
    impl FileWriteDestination for UnknownAfterActualPublish {
        fn consent(&self) -> Arc<dyn FileWriteConsent> {
            self.0.consent()
        }
        fn status(&self) -> FileWriteState {
            self.0.status()
        }
        fn prepare(&mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
            self.0.prepare(check)
        }
        fn write(
            &mut self,
            chunk: &FileWriteChunk,
            check: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<()> {
            self.0.write(chunk, check)
        }
        fn finish(&mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
            self.0.finish(check)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "delivery was revoked after actual publication",
            ))
        }
        fn cleanup(&mut self) -> io::Result<()> {
            self.0.cleanup()
        }
    }
    #[test]
    fn unknown_completion_retains_actual_publication_and_reservation_after_fd_drop()
    -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let book = Arc::new(Mutex::new(Book::default()));
        let root_id = uuid::Uuid::new_v4().to_string();
        let mut device = DynamicWrite {
            grant: Arc::new(Mutex::new(Some(ReceiveGrant {
                id: root_id.clone(),
                active: Arc::new(AtomicBool::new(true)),
            }))),
            session_active: Arc::new(AtomicBool::new(true)),
            identity: identity().into(),
            book: book.clone(),
            area: directory.0.clone(),
        };
        let hash = Sha256::digest(b"abc").to_vec();
        let open = FileWriteOpen {
            root_id,
            path: "incoming.txt".into(),
            size: 3,
            sha256: hash.clone(),
        };
        let inner = device.build(&open, &mut || Ok(()))?;
        let artifact = lock(&book)
            .entries
            .values()
            .next()
            .map(|(_, artifact)| artifact.clone())
            .ok_or_else(denied)?;
        // This outer fixture injects only delivery failure. The publication,
        // hash, sync, target file and status are from the real platform adapter.
        let (unused, consent) = WriteRootSelection::new(
            &uuid::Uuid::new_v4().to_string(),
            &directory.0.join("unused"),
            3,
            3,
        )?;
        drop(unused);
        let mut observed = OwnedWrite {
            inner: Some(Box::new(UnknownAfterActualPublish(inner))),
            artifact: artifact.clone(),
            approval: Approval(vec![Arc::new(AtomicBool::new(true))]),
            _consent: consent,
            owner: None,
        };
        observed.prepare(&mut || Ok(()))?;
        observed.write(
            &FileWriteChunk {
                offset: 0,
                data: b"abc".to_vec(),
                sha256: hash,
            },
            &mut || Ok(()),
        )?;
        assert!(observed.finish(&mut || Ok(())).is_err());
        assert!(lock(&artifact.state).published);
        assert!(lock(&artifact.state).verified);
        observed.cleanup()?;
        drop(observed);
        assert_eq!(artifact.owners.load(Ordering::Acquire), 0);
        assert_eq!(
            std::fs::read(directory.0.join(&artifact.area_name).join("incoming.txt"))?,
            b"abc"
        );
        assert_eq!(lock(&book).remaining(), MAX_BYTES - 3);
        assert_eq!(lock(&book).entries.len(), 1);
        assert!(!artifact.discard.load(Ordering::Acquire));
        let duplicate = device.build(&open, &mut || Ok(()));
        assert!(matches!(duplicate, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
        assert_eq!(lock(&book).entries.len(), 1);
        Ok(())
    }

    struct BlockedFile {
        file: File,
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
    }
    impl Read for BlockedFile {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).map_err(|_| denied())?;
                self.release.recv().map_err(|_| denied())?;
            }
            self.file.read(buffer)
        }
    }
    #[test]
    fn blocked_real_file_owner_survives_revoke_until_the_same_thread_joins() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let path = directory.0.join("held.txt");
        std::fs::write(&path, b"abc")?;
        let file = File::open(path)?;
        let active = Arc::new(AtomicBool::new(true));
        let worker_active = active.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut held = BlockedFile {
                file,
                entered: Some(entered_tx),
                release: release_rx,
            };
            let result = hash_file(&mut held, 3, &mut || {
                Approval(vec![worker_active.clone()]).check()
            });
            drop(held);
            result
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(2));
        active.store(false, Ordering::Release);
        let remained_owned = !worker.is_finished();
        let _ = release_tx.send(());
        let result = worker
            .join()
            .map_err(|_| io::Error::other("fixture worker panicked"))?;
        assert!(entered.is_ok());
        assert!(remained_owned);
        assert!(result.is_err());
        Ok(())
    }
}
