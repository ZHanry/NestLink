//! Explicit local FileWrite selection, pinned capability-relative staging, and
//! no-clobber publication. All I/O is performed by the remote upload owner thread.
mod quota;

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use nestlink_protocol::{
    FILE_PAYLOAD_BYTES, FILE_ROOT_DISPLAY_NAME_BYTES, FILE_SIZE_BYTES, FILE_WRITE_ROOTS,
    FileReadManifest, FileRoot, FileWriteChunk, FileWriteOpen, FileWriteState,
    files::validate_relative_path, valid_id,
};
use nestlink_remote::{
    files::{FileReadConsent, FileReadDevice, FileReadSource},
    upload::{
        FileUploadSourceFactory, FileWriteConsent, FileWriteDestination, FileWriteDevice,
        FileWriteRootListing,
    },
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn check(consent: &AtomicBool, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
    authorized()?;
    if !consent.load(Ordering::Acquire) {
        return Err(denied("local write root consent revoked"));
    }
    Ok(())
}
pub struct WriteRootConsent(Arc<AtomicBool>);
impl WriteRootConsent {
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for WriteRootConsent {
    fn drop(&mut self) {
        self.revoke();
    }
}
/// A freshly created private receiving area in a trusted local parent. It cannot
/// silently select an existing arbitrary directory or inherit a public ACL.
pub struct WriteRootSelection {
    id: String,
    display_name: String,
    area: PathBuf,
    maximum: u64,
    quota: Arc<WriteQuota>,
    consent: Arc<AtomicBool>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct QuotaUsage {
    bytes: u64,
    artifacts: u64,
}

/// Raw, bounded bytes from one regular private quota metadata file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLedgerFileSnapshot {
    pub raw: Vec<u8>,
    pub sha256: [u8; 32],
}

/// A consistent raw metadata snapshot taken while holding the stable quota lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLedgerSnapshot {
    pub lock_marker: Vec<u8>,
    pub lock_marker_valid: bool,
    pub lock_marker_sha256: [u8; 32],
    pub ledger: Option<QuotaLedgerFileSnapshot>,
    pub pending: Option<QuotaLedgerFileSnapshot>,
}

/// Result of an explicit offline metadata recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaLedgerRecovery {
    pub charged_bytes: u64,
    pub charged_artifacts: u64,
    /// True when uncertain on-disk history forced both counters to their limits.
    pub unknown_usage_saturated_limits: bool,
}
struct QuotaFailure {
    kind: io::ErrorKind,
    message: String,
}
impl QuotaFailure {
    fn from_error(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
    fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}
#[derive(Default)]
struct QuotaState {
    usage: QuotaUsage,
    failure: Option<QuotaFailure>,
}
/// An in-process aggregate storage ledger. Pass the same `Arc` to every
/// receiving root whose active and published files must share one limit.
/// Published files and staging areas whose cleanup was not confirmed remain
/// charged for the lifetime of this ledger. Use `open_private_ledger` when the
/// quota must remain charged across process restarts.
pub struct WriteQuota {
    state: Mutex<QuotaState>,
    maximum_bytes: u64,
    maximum_artifacts: u64,
    ledger: Option<quota::PrivateLedger>,
}
impl WriteQuota {
    /// Export a stable-lock-protected snapshot of raw quota metadata.
    ///
    /// This operation never creates the stable lock or changes any metadata.
    /// It fails with `WouldBlock` while a live quota owner holds the lock.
    pub fn inspect_private_ledger(private_state_dir: &Path) -> io::Result<QuotaLedgerSnapshot> {
        quota::inspect_private_ledger(private_state_dir)
    }

    /// Explicitly repair only quota metadata after the daemon has stopped.
    ///
    /// This does not scan destination files, restore upload tasks, or recreate
    /// local consent. If any record cannot be trusted, the result saturates the
    /// aggregate quota so no new reservation can be admitted from unknown history.
    pub fn recover_private_ledger(
        private_state_dir: &Path,
        maximum_bytes: u64,
        maximum_artifacts: u64,
    ) -> io::Result<QuotaLedgerRecovery> {
        let (usage, unknown_usage_saturated_limits) =
            quota::recover_private_ledger(private_state_dir, maximum_bytes, maximum_artifacts)?;
        Ok(QuotaLedgerRecovery {
            charged_bytes: usage.bytes,
            charged_artifacts: usage.artifacts,
            unknown_usage_saturated_limits,
        })
    }

    /// Create an in-memory aggregate quota, primarily for fixtures and callers
    /// that explicitly accept reset-on-restart behavior. A zero artifact limit
    /// disables all uploads; zero-byte uploads still consume one artifact slot.
    pub fn new(maximum_bytes: u64, maximum_artifacts: u64) -> Self {
        Self {
            state: Mutex::new(QuotaState::default()),
            maximum_bytes,
            maximum_artifacts,
            ledger: None,
        }
    }
    /// Open a durable aggregate quota in an existing local private state
    /// directory. The directory must have been created with the platform
    /// private-directory helper and must pass its owner/ACL checks. The
    /// directory contains a fixed-size quota ledger, an independent stable lock
    /// file, and at most one pending metadata replacement; no transfer content,
    /// remote path, or upload identity is persisted. Only one process may hold
    /// this quota at a time.
    ///
    /// A missing ledger is initialized only when the stable lock file has no
    /// initialized marker. A damaged ledger, changed limits, or a second live
    /// owner fails closed. An interrupted pending replacement requires explicit
    /// recovery rather than allocating more metadata names on each restart.
    /// Usage is not reconstructed from destination files, and reopening does
    /// not restore any old business authorization.
    pub fn open_private_ledger(
        private_state_dir: &Path,
        maximum_bytes: u64,
        maximum_artifacts: u64,
    ) -> io::Result<Self> {
        let (ledger, usage) =
            quota::PrivateLedger::open(private_state_dir, maximum_bytes, maximum_artifacts)?;
        Ok(Self {
            state: Mutex::new(QuotaState {
                usage,
                failure: None,
            }),
            maximum_bytes,
            maximum_artifacts,
            ledger: Some(ledger),
        })
    }
    fn reserve(self: &Arc<Self>, bytes: u64) -> io::Result<Reservation> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(failure) = &state.failure {
            return Err(failure.to_error());
        }
        let next_bytes = state
            .usage
            .bytes
            .checked_add(bytes)
            .filter(|used| *used <= self.maximum_bytes);
        let next_artifacts = state
            .usage
            .artifacts
            .checked_add(1)
            .filter(|used| *used <= self.maximum_artifacts);
        let (Some(next_bytes), Some(next_artifacts)) = (next_bytes, next_artifacts) else {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "locally approved receiving byte or artifact quota exhausted",
            ));
        };
        let next_usage = QuotaUsage {
            bytes: next_bytes,
            artifacts: next_artifacts,
        };
        if let Some(ledger) = &self.ledger
            && let Err(error) = ledger.persist(next_usage)
        {
            state.failure = Some(QuotaFailure::from_error(&error));
            return Err(error);
        }
        state.usage = next_usage;
        Ok(Reservation {
            quota: self.clone(),
            bytes,
            staging_started: false,
            released: false,
        })
    }
    fn release(&self, bytes: u64) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(failure) = &state.failure {
            return Err(failure.to_error());
        }
        let Some(next_bytes) = state.usage.bytes.checked_sub(bytes) else {
            let error = invalid("write quota byte accounting underflow");
            state.failure = Some(QuotaFailure::from_error(&error));
            return Err(error);
        };
        let Some(next_artifacts) = state.usage.artifacts.checked_sub(1) else {
            let error = invalid("write quota artifact accounting underflow");
            state.failure = Some(QuotaFailure::from_error(&error));
            return Err(error);
        };
        let next_usage = QuotaUsage {
            bytes: next_bytes,
            artifacts: next_artifacts,
        };
        if let Some(ledger) = &self.ledger
            && let Err(error) = ledger.persist(next_usage)
        {
            state.failure = Some(QuotaFailure::from_error(&error));
            return Err(error);
        }
        state.usage = next_usage;
        Ok(())
    }
}
struct Reservation {
    quota: Arc<WriteQuota>,
    bytes: u64,
    staging_started: bool,
    released: bool,
}
impl Reservation {
    fn new(quota: Arc<WriteQuota>, bytes: u64) -> io::Result<Self> {
        quota.reserve(bytes)
    }
    fn begin_staging(&mut self) {
        self.staging_started = true;
    }
    /// Only a destination that has closed its handle and confirmed removal of
    /// its temporary name may return its reservation to the shared ledger.
    fn release_after_cleanup(
        &mut self,
        state: FileWriteState,
        creation_uncertain: bool,
    ) -> io::Result<()> {
        if creation_uncertain || state.published || !state.file_closed || !state.temporary_removed {
            return Ok(());
        }
        self.release()
    }
    fn release(&mut self) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        self.quota.release(self.bytes)?;
        self.released = true;
        Ok(())
    }
}
fn create_staging_file(
    reservation: &mut Reservation,
    creation_uncertain: &mut bool,
    open: impl FnOnce() -> io::Result<File>,
) -> io::Result<File> {
    reservation.begin_staging();
    match open() {
        Ok(file) => Ok(file),
        Err(error) => {
            // create_new reporting AlreadyExists proves this operation did not
            // create the colliding entry. Other errors retain quota unless a
            // later owner action can prove that no staging object remains.
            if error.kind() != io::ErrorKind::AlreadyExists {
                *creation_uncertain = true;
            }
            Err(error)
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        // Before staging starts, no filesystem object can belong to this
        // reservation. After that point, Drop cannot prove cleanup succeeded.
        if !self.staging_started {
            let _ = self.release();
        }
    }
}
impl WriteRootSelection {
    /// No I/O here; initialization happens on the file worker. The quota counts
    /// declared active bytes plus files actually published by this local owner.
    pub fn new(
        id: &str,
        fresh_area: &Path,
        maximum_file_bytes: u64,
        maximum_total_bytes: u64,
    ) -> io::Result<(Self, WriteRootConsent)> {
        let display_name = fresh_area
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Receiving folder".into());
        Self::new_with_display_name(
            id,
            &display_name,
            fresh_area,
            maximum_file_bytes,
            maximum_total_bytes,
        )
    }

    /// The chosen label is sent as root metadata; the native path stays in the
    /// local storage adapter and never enters a wire message.
    pub fn new_with_display_name(
        id: &str,
        display_name: &str,
        fresh_area: &Path,
        maximum_file_bytes: u64,
        maximum_total_bytes: u64,
    ) -> io::Result<(Self, WriteRootConsent)> {
        if !valid_id(id)
            || maximum_file_bytes > FILE_SIZE_BYTES
            || maximum_total_bytes < maximum_file_bytes
            || maximum_total_bytes > FILE_SIZE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid locally selected write root or quota",
            ));
        }
        if display_name.is_empty()
            || display_name.len() as u64 > FILE_ROOT_DISPLAY_NAME_BYTES
            || display_name.trim() != display_name
            || display_name
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid selected write-root display name",
            ));
        }
        let quota = Arc::new(WriteQuota::new(maximum_total_bytes, u64::MAX));
        Self::new_with_display_name_and_quota(
            id,
            display_name,
            fresh_area,
            maximum_file_bytes,
            quota,
        )
    }

    /// Create a root whose reservations participate in an application-owned
    /// aggregate quota shared with any other roots given the same `Arc`.
    pub fn new_with_quota(
        id: &str,
        fresh_area: &Path,
        maximum_file_bytes: u64,
        quota: Arc<WriteQuota>,
    ) -> io::Result<(Self, WriteRootConsent)> {
        let display_name = fresh_area
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Receiving folder".into());
        Self::new_with_display_name_and_quota(
            id,
            &display_name,
            fresh_area,
            maximum_file_bytes,
            quota,
        )
    }

    /// Display-name form of `new_with_quota` for chooser-selected roots.
    pub fn new_with_display_name_and_quota(
        id: &str,
        display_name: &str,
        fresh_area: &Path,
        maximum_file_bytes: u64,
        quota: Arc<WriteQuota>,
    ) -> io::Result<(Self, WriteRootConsent)> {
        if !valid_id(id) || maximum_file_bytes > FILE_SIZE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid locally selected write root or quota",
            ));
        }
        if display_name.is_empty()
            || display_name.len() as u64 > FILE_ROOT_DISPLAY_NAME_BYTES
            || display_name.trim() != display_name
            || display_name
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid selected write-root display name",
            ));
        }
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                id: id.into(),
                display_name: display_name.into(),
                area: fresh_area.into(),
                maximum: maximum_file_bytes,
                quota,
                consent: consent.clone(),
            },
            WriteRootConsent(consent),
        ))
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
struct WriteRoot {
    selection: WriteRootSelection,
    directory: Option<Dir>,
    initialized: bool,
    device: u64,
}
pub struct WriteRoots(BTreeMap<String, WriteRoot>);
impl WriteRoots {
    pub fn new(selections: Vec<WriteRootSelection>) -> io::Result<Self> {
        if selections.len() as u64 > FILE_WRITE_ROOTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many locally approved write roots",
            ));
        }
        let mut roots = BTreeMap::new();
        for selection in selections {
            let id = selection.id.clone();
            if roots
                .insert(
                    id,
                    WriteRoot {
                        selection,
                        directory: None,
                        initialized: false,
                        device: 0,
                    },
                )
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate write root identity",
                ));
            }
        }
        Ok(Self(roots))
    }
}
impl FileWriteDevice for WriteRoots {
    fn retire_revoked(&mut self) {
        self.0
            .retain(|_, root| root.selection.consent.load(Ordering::Acquire));
    }
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        self.retire_revoked();
        let mut roots = Vec::with_capacity(self.0.len());
        let mut approvals = Vec::with_capacity(self.0.len());
        for (id, root) in &self.0 {
            if !root.selection.consent.load(Ordering::Acquire) {
                return Err(denied("local file write root consent revoked"));
            }
            roots.push(FileRoot {
                root_id: id.clone(),
                display_name: root.selection.display_name.clone(),
            });
            approvals.push(root.selection.consent.clone());
        }
        let consent: Arc<dyn FileWriteConsent> = Arc::new(WriteRootListConsent(approvals));
        consent.check()?;
        Ok(FileWriteRootListing { roots, consent })
    }
    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>> {
        validate_relative_path(&open.path).map_err(|_| denied("invalid portable upload path"))?;
        if open.sha256.len() != 32 || open.size > FILE_SIZE_BYTES {
            return Err(invalid("invalid upload manifest"));
        }
        let root = self
            .0
            .get_mut(&open.root_id)
            .ok_or_else(|| denied("write root was not independently locally approved"))?;
        check(&root.selection.consent, authorized)?;
        if open.size > root.selection.maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "upload exceeds local file limit",
            ));
        }
        let reservation = Reservation::new(root.selection.quota.clone(), open.size)?;
        if root.directory.is_none() {
            if root.initialized {
                return Err(denied("write root initialization was retired"));
            }
            // Owner-selected ambient path used once. Thereafter every operation
            // is relative to retained handles, including after path replacement.
            nestlink_platform_security::new_private_directory(&root.selection.area)?;
            root.initialized = true;
            check(&root.selection.consent, authorized)?;
            root.directory = Some(Dir::open_ambient_dir(
                &root.selection.area,
                cap_std::ambient_authority(),
            )?);
            check(&root.selection.consent, authorized)?;
            root.device = root
                .directory
                .as_ref()
                .ok_or_else(|| invalid("write root closed"))?
                .dir_metadata()?
                .dev();
            check(&root.selection.consent, authorized)?;
        }
        let components: Vec<_> = open.path.split('/').collect();
        let (name, parents) = components
            .split_last()
            .ok_or_else(|| invalid("upload target name missing"))?;
        let mut directory = root
            .directory
            .as_ref()
            .ok_or_else(|| invalid("write root closed"))?
            .try_clone()?;
        for component in parents {
            check(&root.selection.consent, authorized)?;
            directory = directory.open_dir_nofollow(component)?;
            check(&root.selection.consent, authorized)?;
            if directory.dir_metadata()?.dev() != root.device {
                return Err(denied("upload cannot cross the selected filesystem"));
            }
            check(&root.selection.consent, authorized)?;
        }
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let random: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Box::new(LocalUploadDestination {
            directory,
            file: None,
            temporary: format!(".nestlink-upload-{random}.partial"),
            name: (*name).into(),
            temporary_created: false,
            temporary_creation_uncertain: false,
            device: root.device,
            inode: 0,
            manifest: open.clone(),
            consent: root.selection.consent.clone(),
            reservation,
            hash: Sha256::new(),
            state: FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..FileWriteState::default()
            },
        }))
    }
}

struct WriteRootListConsent(Vec<Arc<AtomicBool>>);
impl FileWriteConsent for WriteRootListConsent {
    fn check(&self) -> io::Result<()> {
        if self.0.iter().all(|consent| consent.load(Ordering::Acquire)) {
            Ok(())
        } else {
            Err(denied("local file write root consent revoked"))
        }
    }
}
struct LocalUploadDestination {
    directory: Dir,
    file: Option<File>,
    temporary: String,
    name: String,
    temporary_created: bool,
    temporary_creation_uncertain: bool,
    device: u64,
    inode: u64,
    manifest: FileWriteOpen,
    consent: Arc<AtomicBool>,
    reservation: Reservation,
    hash: Sha256,
    state: FileWriteState,
}
impl LocalUploadDestination {
    fn object(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        let metadata = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("upload staged file closed"))?
            .metadata()?;
        check(&self.consent, authorized)?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.nlink() != 1
            || metadata.len() != self.state.confirmed_bytes
        {
            return Err(invalid("actual staged upload object changed"));
        }
        #[cfg(windows)]
        {
            use cap_fs_ext::OsMetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(denied("staged upload is a reparse point"));
            }
        }
        Ok(())
    }
    fn active(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        if self.state.published || self.state.poisoned || self.file.is_none() {
            return Err(invalid("upload storage is no longer active"));
        }
        self.object(authorized)
    }
    fn hash_actual(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<[u8; 32]> {
        self.object(authorized)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("upload staged file closed"))?;
        check(&self.consent, authorized)?;
        file.seek(SeekFrom::Start(0))?;
        check(&self.consent, authorized)?;
        let mut remaining = self.state.confirmed_bytes;
        let mut hash = Sha256::new();
        let mut data = vec![0; FILE_PAYLOAD_BYTES as usize];
        while remaining != 0 {
            let maximum = remaining.min(FILE_PAYLOAD_BYTES) as usize;
            let mut obtained = 0;
            while obtained < maximum {
                check(&self.consent, authorized)?;
                let count = file.read(&mut data[obtained..maximum])?;
                check(&self.consent, authorized)?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "actual upload ended early",
                    ));
                }
                obtained += count;
            }
            hash.update(&data[..maximum]);
            remaining -= maximum as u64;
        }
        self.object(authorized)?;
        Ok(hash.finalize().into())
    }
}
impl FileWriteDestination for LocalUploadDestination {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        self.consent.clone()
    }
    fn status(&self) -> FileWriteState {
        self.state
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        if self.temporary_created || self.state.poisoned || self.state.published {
            return Err(invalid("upload storage already prepared or retired"));
        }
        // Reject all pre-existing target entry types before creating storage.
        match self.directory.symlink_metadata(&self.name) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "upload target already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        check(&self.consent, authorized)?;
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
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.share_mode(1);
        }
        let directory = &self.directory;
        let temporary = &self.temporary;
        let file = create_staging_file(
            &mut self.reservation,
            &mut self.temporary_creation_uncertain,
            || directory.open_with(temporary, &options),
        )?;
        self.file = Some(file);
        self.temporary_created = true;
        self.state.file_closed = false;
        self.state.temporary_removed = false;
        check(&self.consent, authorized)?;
        let metadata = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("upload file closed"))?
            .metadata()?;
        check(&self.consent, authorized)?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.nlink() != 1
            || metadata.len() != 0
        {
            return Err(invalid("upload must be a fresh regular single-link file"));
        }
        self.inode = metadata.ino();
        self.object(authorized)
    }
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.active(authorized)?;
        if chunk.offset != self.state.confirmed_bytes
            || chunk.data.is_empty()
            || chunk.data.len() as u64 > FILE_PAYLOAD_BYTES
            || chunk
                .offset
                .checked_add(chunk.data.len() as u64)
                .is_none_or(|end| end > self.manifest.size)
            || Sha256::digest(&chunk.data).as_slice() != chunk.sha256
        {
            return Err(invalid(
                "upload chunk differs from the exact staged extent or digest",
            ));
        }
        let mut written = 0;
        let mut disk_failed = false;
        let result = (|| {
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| invalid("upload staged file closed"))?;
            check(&self.consent, authorized)?;
            file.seek(SeekFrom::Start(chunk.offset))
                .inspect_err(|_| disk_failed = true)?;
            check(&self.consent, authorized)?;
            while written < chunk.data.len() {
                check(&self.consent, authorized)?;
                let count = file
                    .write(&chunk.data[written..])
                    .inspect_err(|_| disk_failed = true)?;
                if count == 0 {
                    disk_failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "upload storage made no progress",
                    ));
                }
                written += count;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if written != 0 || disk_failed {
                self.state.poisoned = true;
            }
            return Err(error);
        }
        self.hash.update(&chunk.data);
        self.state.confirmed_bytes += chunk.data.len() as u64;
        check(&self.consent, authorized)
    }
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.active(authorized)?;
        if self.state.confirmed_bytes != self.manifest.size
            || self.hash.clone().finalize().as_slice() != self.manifest.sha256
        {
            self.state.poisoned = true;
            return Err(invalid(
                "upload has incomplete bytes or a different whole digest",
            ));
        }
        if self.hash_actual(authorized)?.as_slice() != self.manifest.sha256 {
            self.state.poisoned = true;
            return Err(invalid("actual complete staged upload checksum differs"));
        }
        check(&self.consent, authorized)?;
        self.file
            .as_ref()
            .ok_or_else(|| invalid("upload staged file closed"))?
            .sync_all()?;
        check(&self.consent, authorized)?;
        self.object(authorized)?;
        check(&self.consent, authorized)?;
        self.directory
            .hard_link(&self.temporary, &self.directory, &self.name)?;
        // Record the actual irreversible publication before rechecking consent.
        self.state.published = true;
        // Staging reservations stay charged after publication.
        check(&self.consent, authorized)?;
        self.file.take();
        self.state.file_closed = true;
        self.directory.remove_file(&self.temporary)?;
        self.state.temporary_removed = true;
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            check(&self.consent, authorized)?;
            let directory = self.directory.open_with(".", &options)?;
            check(&self.consent, authorized)?;
            directory.sync_all()?;
            self.state.directory_synced = true;
            check(&self.consent, authorized)?;
        }
        // Windows directory fsync / power-loss acceptance is not claimed.
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.file.take();
        self.state.file_closed = true;
        if !self.state.published {
            self.state.poisoned = true;
        }
        if self.temporary_created && !self.state.temporary_removed {
            self.directory.remove_file(&self.temporary)?;
            self.state.temporary_removed = true;
        }
        self.reservation
            .release_after_cleanup(self.state, self.temporary_creation_uncertain)
    }
}

pub struct LocalUploadConsent(Arc<AtomicBool>);
impl LocalUploadConsent {
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for LocalUploadConsent {
    fn drop(&mut self) {
        self.revoke();
    }
}
pub struct LocalUploadSelection {
    path: PathBuf,
    maximum: u64,
    consent: Arc<AtomicBool>,
}
impl LocalUploadSelection {
    /// Explicit local chooser path; it is never derived from the remote target.
    pub fn new(
        local_file: &Path,
        maximum_file_bytes: u64,
    ) -> io::Result<(Self, LocalUploadConsent)> {
        if maximum_file_bytes > FILE_SIZE_BYTES || local_file.parent().is_none() {
            return Err(invalid("invalid local upload selection"));
        }
        let name = local_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("upload source needs a UTF-8 portable name"))?;
        validate_relative_path(name).map_err(|_| invalid("invalid selected upload source name"))?;
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                path: local_file.into(),
                maximum: maximum_file_bytes,
                consent: consent.clone(),
            },
            LocalUploadConsent(consent),
        ))
    }
}
struct SelectedSource {
    source: Box<dyn FileReadSource>,
    consent: Arc<AtomicBool>,
    _root_approval: crate::ReadRootConsent,
}
impl FileUploadSourceFactory for LocalUploadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        check(&self.consent, authorized)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("selected upload parent missing"))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("selected upload filename missing"))?;
        // This internal root identity never leaves the source worker.
        let id = "00000001-1111-4111-8111-111111111111";
        let (root, approval) = crate::ApprovedReadRoot::open(id, parent, self.maximum)?;
        check(&self.consent, authorized)?;
        let source = crate::FileRoots::new(vec![root])?.open(id, name)?;
        check(&self.consent, authorized)?;
        Ok(Box::new(SelectedSource {
            source,
            consent: self.consent.clone(),
            _root_approval: approval,
        }))
    }
}
impl FileReadSource for SelectedSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        let consent = self.consent.clone();
        self.source.describe(&mut || check(&consent, authorized))
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let consent = self.consent.clone();
        self.source
            .read_chunk(offset, maximum, &mut || check(&consent, authorized))
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let consent = self.consent.clone();
        self.source
            .verify(original, &mut || check(&consent, authorized))
    }
}
#[cfg(test)]
mod shared_quota_tests {
    use super::*;

    #[test]
    fn ambiguous_staging_open_error_keeps_the_reservation() -> Result<(), Box<dyn std::error::Error>>
    {
        let quota = Arc::new(WriteQuota::new(4, 1));
        let mut reservation = Reservation::new(quota.clone(), 4)?;
        let mut uncertain = false;
        let result = create_staging_file(&mut reservation, &mut uncertain, || {
            Err(io::Error::other("simulated ambiguous create failure"))
        });
        assert!(result.is_err());
        assert!(uncertain);
        let collision = create_staging_file(&mut reservation, &mut uncertain, || {
            Err(io::Error::from(io::ErrorKind::AlreadyExists))
        });
        let error = match collision {
            Err(error) => error,
            Ok(_) => return Err("retry unexpectedly created a staging file".into()),
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(uncertain);
        reservation.release_after_cleanup(
            FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..FileWriteState::default()
            },
            uncertain,
        )?;
        assert_eq!(
            quota.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn existing_create_new_collision_is_preserved_and_releases_proven_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let area = parent.path().join("receiving");
        nestlink_platform_security::new_private_directory(&area)?;
        let directory = Dir::open_ambient_dir(&area, cap_std::ambient_authority())?;
        let device = directory.dir_metadata()?.dev();
        let temporary = ".nestlink-upload-existing.partial";
        std::fs::write(area.join(temporary), b"keep-existing-entry")?;
        let quota = Arc::new(WriteQuota::new(4, 1));
        let consent = Arc::new(AtomicBool::new(true));
        let mut destination = LocalUploadDestination {
            directory,
            file: None,
            temporary: temporary.into(),
            name: "target".into(),
            temporary_created: false,
            temporary_creation_uncertain: false,
            device,
            inode: 0,
            manifest: FileWriteOpen {
                root_id: "00000001-1111-4111-8111-111111111111".into(),
                path: "target".into(),
                size: 4,
                sha256: Sha256::digest(b"data").to_vec(),
            },
            consent,
            reservation: Reservation::new(quota.clone(), 4)?,
            hash: Sha256::new(),
            state: FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..FileWriteState::default()
            },
        };
        let error = match destination.prepare(&mut || Ok(())) {
            Ok(()) => return Err("pre-existing staging name was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        destination.cleanup()?;
        assert_eq!(std::fs::read(area.join(temporary))?, b"keep-existing-entry");
        let admitted = quota.reserve(4)?;
        drop(admitted);
        Ok(())
    }

    fn durable_destination(
        quota: Arc<WriteQuota>,
        area: &Path,
        name: &str,
        contents: &[u8],
    ) -> io::Result<LocalUploadDestination> {
        nestlink_platform_security::new_private_directory(area)?;
        let directory = Dir::open_ambient_dir(area, cap_std::ambient_authority())?;
        let device = directory.dir_metadata()?.dev();
        let mut destination = LocalUploadDestination {
            directory,
            file: None,
            temporary: ".nestlink-upload-quota-fixture.partial".into(),
            name: name.into(),
            temporary_created: false,
            temporary_creation_uncertain: false,
            device,
            inode: 0,
            manifest: FileWriteOpen {
                root_id: "00000001-1111-4111-8111-111111111111".into(),
                path: name.into(),
                size: contents.len() as u64,
                sha256: Sha256::digest(contents).to_vec(),
            },
            consent: Arc::new(AtomicBool::new(true)),
            reservation: Reservation::new(quota, contents.len() as u64)?,
            hash: Sha256::new(),
            state: FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..FileWriteState::default()
            },
        };
        destination.prepare(&mut || Ok(()))?;
        if !contents.is_empty() {
            destination.write(
                &FileWriteChunk {
                    offset: 0,
                    data: contents.to_vec(),
                    sha256: Sha256::digest(contents).to_vec(),
                },
                &mut || Ok(()),
            )?;
        }
        Ok(destination)
    }

    #[test]
    fn durable_quota_releases_only_after_real_staging_removal() -> io::Result<()> {
        let owner = tempfile::tempdir()?;
        let state_dir = owner.path().join("quota-state");
        let area = owner.path().join("receiving");
        nestlink_platform_security::new_private_directory(&state_dir)?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 4, 1)?);
        let mut destination = durable_destination(quota.clone(), &area, "discarded", b"data")?;
        destination.cleanup()?;
        assert!(!area.join(&destination.temporary).exists());
        drop(destination);
        drop(quota);

        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 4, 1)?);
        let reservation = Reservation::new(quota, 4)?;
        drop(reservation);
        Ok(())
    }

    #[test]
    fn durable_quota_keeps_real_published_bytes_across_reopen() -> io::Result<()> {
        let owner = tempfile::tempdir()?;
        let state_dir = owner.path().join("quota-state");
        let area = owner.path().join("receiving");
        nestlink_platform_security::new_private_directory(&state_dir)?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 4, 1)?);
        let mut destination = durable_destination(quota.clone(), &area, "published", b"data")?;
        destination.finish(&mut || Ok(()))?;
        assert_eq!(std::fs::read(area.join("published"))?, b"data");
        assert!(destination.state.published);
        drop(destination);
        drop(quota);

        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 4, 1)?);
        assert_eq!(
            Reservation::new(quota, 0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn durable_quota_keeps_real_staging_when_creation_or_cleanup_is_uncertain() -> io::Result<()> {
        let owner = tempfile::tempdir()?;
        let state_dir = owner.path().join("quota-state");
        let area = owner.path().join("receiving");
        nestlink_platform_security::new_private_directory(&state_dir)?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 0, 1)?);
        let mut destination = durable_destination(quota.clone(), &area, "uncertain", b"")?;
        destination.temporary_creation_uncertain = true;
        destination.cleanup()?;
        assert!(!area.join(&destination.temporary).exists());
        drop(destination);
        drop(quota);

        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 0, 1)?);
        assert_eq!(
            Reservation::new(quota, 0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn durable_zero_byte_artifact_consumes_and_releases_real_quota_slot() -> io::Result<()> {
        let owner = tempfile::tempdir()?;
        let state_dir = owner.path().join("quota-state");
        let area = owner.path().join("receiving");
        nestlink_platform_security::new_private_directory(&state_dir)?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 0, 1)?);
        let mut destination = durable_destination(quota.clone(), &area, "empty", b"")?;
        assert_eq!(
            Reservation::new(quota.clone(), 0)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        destination.cleanup()?;
        drop(destination);
        drop(quota);

        let quota = Arc::new(WriteQuota::open_private_ledger(&state_dir, 0, 1)?);
        let reservation = Reservation::new(quota, 0)?;
        drop(reservation);
        Ok(())
    }
}
