//! Process-restart task facts, never persisted remote or local authority.
//! All public disk methods are blocking: use a file worker or spawn_blocking.
use super::*;
use cap_fs_ext::DirExt;
use nestlink_protocol::file_recovery::{
    DOWNLOAD_RECOVERY_METADATA_BYTES, DOWNLOAD_RECOVERY_TASKS, DownloadRecoveryFacts,
    DownloadRecoveryResume, DownloadRecoveryView,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Component,
    sync::{Mutex, MutexGuard},
};

const LOCK: &str = "native-download-recovery.lock";
const LEDGER: &str = "native-download-recovery.json";
const PENDING: &str = "native-download-recovery.pending";
const MARKER: &[u8] = b"NLDOWN1\n";

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn checked_id(id: &str) -> io::Result<()> {
    if !nestlink_protocol::valid_id(id) {
        return Err(invalid("invalid persisted download ID"));
    }
    Ok(())
}
fn local_name(name: &str) -> io::Result<()> {
    nestlink_protocol::files::validate_relative_path(name)
        .map_err(|_| invalid("invalid local recovery name"))?;
    if name.contains('/') {
        return Err(invalid("one local file name required"));
    }
    Ok(())
}

/// Reopens every absolute path component without following a symlink/reparse
/// point. Windows recovery intentionally requires a local drive path.
fn open_directory(path: &Path) -> io::Result<Dir> {
    if !path.is_absolute() {
        return Err(invalid("absolute recovery directory required"));
    }
    let mut anchor = PathBuf::new();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                if !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) {
                    return Err(invalid("recovery requires a local drive"));
                }
                anchor.push(prefix.as_os_str());
            }
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::Normal(name) => names.push(name),
            _ => return Err(invalid("noncanonical recovery directory")),
        }
    }
    let mut directory = Dir::open_ambient_dir(anchor, cap_std::ambient_authority())?;
    for name in names {
        directory = directory.open_dir_nofollow(name)?;
        no_reparse(&directory.dir_metadata()?)?;
    }
    Ok(directory)
}
fn options(writable: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
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
    options
}
fn lock_options() -> OpenOptions {
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        let mut value = options(true);
        value.share_mode(3);
        value
    }
    #[cfg(not(windows))]
    {
        options(true)
    }
}
fn no_reparse(metadata: &cap_std::fs::Metadata) -> io::Result<()> {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as WindowsMetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(denied("recovery object is a reparse point"));
        }
    }
    if metadata.file_type().is_symlink() {
        return Err(denied("recovery object is a symbolic link"));
    }
    Ok(())
}
fn private_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    no_reparse(&meta)?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(denied(
            "recovery metadata must have one regular private link",
        ));
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as UnixMetadataExt;
        if meta.mode() & 0o077 != 0 || meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(denied("recovery metadata is not private"));
        }
    }
    Ok(())
}
fn sync_directory(directory: &Dir) -> io::Result<bool> {
    #[cfg(unix)]
    {
        directory.open_with(".", &options(false))?.sync_all()?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectId {
    device: u64,
    inode: u64,
}
impl ObjectId {
    fn from(meta: &cap_std::fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }
    fn matches(&self, meta: &cap_std::fs::Metadata) -> bool {
        self.device == meta.dev() && self.inode == meta.ino()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Reserved,
    Staged,
    Publishing,
    Published,
    Cancelled,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialExport {
    area: PathBuf,
    name: String,
    directory: Option<ObjectId>,
    file: Option<ObjectId>,
    checkpoint: u64,
    sha256: [u8; 32],
    published: bool,
    temporary_removed: bool,
    file_synced: bool,
    directory_synced: bool,
    error: Option<String>,
}
impl PartialExport {
    fn summary(&self) -> String {
        format!(
            "{}; {}{}: {}",
            if self.published {
                "published_partial"
            } else {
                "partial_export_attempt"
            },
            if self.temporary_removed {
                "staging_removed"
            } else {
                "cleanup_pending"
            },
            self.error
                .as_ref()
                .map(|error| format!("; {error}"))
                .unwrap_or_default(),
            self.area.join(&self.name).display()
        )
    }
    fn validate(&self, source: &Record) -> io::Result<()> {
        local_name(&self.name)?;
        if !self.name.ends_with(".partial")
            || !self.area.is_absolute()
            || self.area.as_os_str().len() > 4096
            || self.checkpoint > source.facts.size
            || (self.file.is_some() != self.directory.is_some())
            || self.error.as_ref().is_some_and(|value| value.len() > 128)
            || (self.published && (!self.file_synced || self.file.is_none()))
        {
            return Err(invalid("invalid persistent partial export facts"));
        }
        Ok(())
    }
}
const EXPORT_TEMPORARY: &str = ".nestlink-export.partial";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    task_id: String,
    facts: DownloadRecoveryFacts,
    area: PathBuf,
    temporary: String,
    name: String,
    directory: Option<ObjectId>,
    file: Option<ObjectId>,
    checkpoint: u64,
    prefix_sha256: [u8; 32],
    stage: Stage,
    temporary_removed: bool,
    file_synced: bool,
    directory_synced: bool,
    operation_error: Option<String>,
    cleanup_error: Option<String>,
    last_export: Option<PartialExport>,
}
impl Record {
    fn charged(&self) -> bool {
        !self.temporary_removed
    }
    fn view(&self, active: bool) -> DownloadRecoveryView {
        DownloadRecoveryView {
            task_id: self.task_id.clone(),
            local_name: self.name.clone(),
            remote_path: self.facts.relative_path.clone(),
            host_device_id: self.facts.scope.host_device_id.clone(),
            checkpoint_bytes: self.checkpoint,
            total_bytes: self.facts.size,
            phase: if active {
                "active"
            } else {
                match self.stage {
                    Stage::Reserved | Stage::Staged => "waiting_for_approval",
                    Stage::Publishing => "publication_needs_review",
                    Stage::Published => "published",
                    Stage::Cancelled => "cancelled",
                    Stage::Failed if self.temporary_removed => "failed",
                    Stage::Failed => "cleanup_required",
                }
            }
            .into(),
            owner_active: active,
            published: self.stage == Stage::Published,
            temporary_removed: self.temporary_removed,
            file_synced: self.file_synced,
            directory_synced: self.directory_synced,
            error: self.operation_error.clone(),
            cleanup_error: self.cleanup_error.clone(),
            last_export: self.last_export.as_ref().map(PartialExport::summary),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u32,
    sequence: u64,
    maximum_bytes: u64,
    maximum_tasks: usize,
    records: BTreeMap<String, Record>,
    /// Stable directory object facts only; every new session must explicitly
    /// select and approve the root again before it can be opened or disclosed.
    read_root_ids: BTreeMap<String, ObjectId>,
}
impl Ledger {
    fn reserved(&self) -> io::Result<u64> {
        self.records.values().try_fold(0_u64, |used, item| {
            let source = if item.charged() { item.facts.size } else { 0 };
            let export = item
                .last_export
                .as_ref()
                .filter(|export| !export.temporary_removed)
                .map_or(0, |export| export.checkpoint);
            used.checked_add(source)
                .and_then(|value| value.checked_add(export))
                .ok_or_else(|| invalid("recovery quota overflow"))
        })
    }
    fn validate(&self, maximum_bytes: u64, maximum_tasks: usize) -> io::Result<()> {
        if self.schema != 1
            || self.maximum_bytes != maximum_bytes
            || self.maximum_tasks != maximum_tasks
            || maximum_tasks == 0
            || maximum_tasks > DOWNLOAD_RECOVERY_TASKS
            || self.records.len() > maximum_tasks
            || self.read_root_ids.len() > DOWNLOAD_RECOVERY_TASKS
            || self.reserved()? > maximum_bytes
        {
            return Err(invalid("invalid persistent download bounds"));
        }
        for (id, record) in &self.records {
            checked_id(id)?;
            record
                .facts
                .validate()
                .map_err(|_| invalid("invalid persisted source facts"))?;
            local_name(&record.name)?;
            if let Some(export) = &record.last_export {
                export.validate(record)?;
            }
            if &record.task_id != id
                || !record.area.is_absolute()
                || record.area.as_os_str().len() > 4096
                || record.temporary != format!(".nestlink-{}.part", id.replace('-', ""))
                || record.checkpoint > record.facts.size
                || record
                    .cleanup_error
                    .as_ref()
                    .is_some_and(|value| value.len() > 128)
                || record
                    .operation_error
                    .as_ref()
                    .is_some_and(|value| value.len() > 128)
                || (record.file.is_some() != record.directory.is_some())
            {
                return Err(invalid("invalid persisted download task"));
            }
        }
        for id in self.read_root_ids.keys() {
            checked_id(id)?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    ledger: Ledger,
    sha256: [u8; 32],
}
fn encode(ledger: &Ledger) -> io::Result<Vec<u8>> {
    let raw = serde_json::to_vec(ledger).map_err(io::Error::other)?;
    let bytes = serde_json::to_vec(&Envelope {
        ledger: ledger.clone(),
        sha256: Sha256::digest(raw).into(),
    })
    .map_err(io::Error::other)?;
    if bytes.len() > DOWNLOAD_RECOVERY_METADATA_BYTES {
        return Err(invalid("recovery metadata budget exceeded"));
    }
    Ok(bytes)
}
fn decode(bytes: &[u8], maximum_bytes: u64, maximum_tasks: usize) -> io::Result<Ledger> {
    if bytes.len() > DOWNLOAD_RECOVERY_METADATA_BYTES {
        return Err(invalid("recovery metadata budget exceeded"));
    }
    let value: Envelope =
        serde_json::from_slice(bytes).map_err(|_| invalid("malformed recovery metadata"))?;
    let raw = serde_json::to_vec(&value.ledger).map_err(io::Error::other)?;
    if Sha256::digest(raw).as_slice() != value.sha256.as_slice() {
        return Err(invalid("recovery metadata checksum differs"));
    }
    value.ledger.validate(maximum_bytes, maximum_tasks)?;
    Ok(value.ledger)
}
fn read_ledger(
    directory: &Dir,
    name: &str,
    maximum_bytes: u64,
    maximum_tasks: usize,
) -> io::Result<Ledger> {
    let file = directory.open_with(name, &options(false))?;
    private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(DOWNLOAD_RECOVERY_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    decode(&bytes, maximum_bytes, maximum_tasks)
}
struct State {
    ledger: Ledger,
    owners: BTreeSet<String>,
    poisoned: bool,
}
/// Lifetime owns a stable process-exclusive lock. Metadata replacement never
/// replaces that lock. A damaged store is not silently initialized as empty.
pub struct DownloadRecoveryStore {
    directory: Dir,
    _owner: std::fs::File,
    state: Mutex<State>,
}
impl Drop for DownloadRecoveryStore {
    fn drop(&mut self) {
        // A concurrent fork can inherit this open file description before
        // CLOEXEC closes it. Release the lock when the last real owner leaves,
        // without waiting for an unrelated child to exec or exit.
        let _ = self._owner.unlock();
    }
}
impl DownloadRecoveryStore {
    pub fn open(
        private_state_dir: &Path,
        maximum_bytes: u64,
        maximum_tasks: usize,
    ) -> io::Result<Arc<Self>> {
        nestlink_platform_security::check_private_directory(private_state_dir)?;
        let directory = open_directory(private_state_dir)?;
        let mut create = lock_options();
        create.create_new(true);
        let file = match directory.open_with(LOCK, &create) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                directory.open_with(LOCK, &lock_options())?
            }
            Err(error) => return Err(error),
        };
        private_file(&file)?;
        let mut owner = file.into_std();
        owner.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "download journal already has an owner",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        let mut marker = Vec::new();
        Read::by_ref(&mut owner).take(16).read_to_end(&mut marker)?;
        if !marker.is_empty() && marker != MARKER {
            return Err(invalid("invalid download journal lock marker"));
        }
        let mut loaded = match read_ledger(&directory, LEDGER, maximum_bytes, maximum_tasks) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        match read_ledger(&directory, PENDING, maximum_bytes, maximum_tasks) {
            Ok(pending) => {
                if let Some(current) = &loaded {
                    if current.sequence.checked_add(1) != Some(pending.sequence) {
                        return Err(invalid("ambiguous pending download journal"));
                    }
                    // File data is checked against the older committed prefix;
                    // never promote a merely written pending checkpoint.
                    directory.remove_file(PENDING)?;
                    sync_directory(&directory)?;
                } else if marker.is_empty() && pending.sequence == 0 && pending.records.is_empty() {
                    directory.rename(PENDING, &directory, LEDGER)?;
                    sync_directory(&directory)?;
                    loaded = Some(pending);
                } else {
                    return Err(invalid("committed download journal is missing"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if loaded.is_none() && !marker.is_empty() {
            return Err(invalid("established download journal is missing"));
        }
        let fresh = loaded.is_none();
        let ledger = loaded.unwrap_or(Ledger {
            schema: 1,
            sequence: 0,
            maximum_bytes,
            maximum_tasks,
            records: BTreeMap::new(),
            read_root_ids: BTreeMap::new(),
        });
        ledger.validate(maximum_bytes, maximum_tasks)?;
        let store = Arc::new(Self {
            directory,
            _owner: owner,
            state: Mutex::new(State {
                ledger,
                owners: BTreeSet::new(),
                poisoned: false,
            }),
        });
        if fresh {
            store.persist(&lock(&store.state).ledger)?;
        }
        if marker.is_empty() {
            let mut marker_file = store._owner.try_clone()?;
            marker_file.seek(SeekFrom::Start(0))?;
            marker_file.write_all(MARKER)?;
            marker_file.sync_all()?;
            sync_directory(&store.directory)?;
        }
        Ok(store)
    }
    fn persist(&self, ledger: &Ledger) -> io::Result<()> {
        let bytes = encode(ledger)?;
        let mut create = options(true);
        create.create_new(true);
        let mut file = self.directory.open_with(PENDING, &create)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        self.directory.rename(PENDING, &self.directory, LEDGER)?;
        self.directory
            .open_with(LEDGER, &options(true))?
            .sync_all()?;
        sync_directory(&self.directory)?;
        Ok(())
    }
    fn change<T>(&self, change: impl FnOnce(&mut Ledger) -> io::Result<T>) -> io::Result<T> {
        let mut state = lock(&self.state);
        if state.poisoned {
            return Err(invalid(
                "download journal requires restart after failed persistence",
            ));
        }
        let mut next = state.ledger.clone();
        let result = change(&mut next)?;
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("journal sequence exhausted"))?;
        next.validate(next.maximum_bytes, next.maximum_tasks)?;
        if let Err(error) = self.persist(&next) {
            state.poisoned = true;
            return Err(error);
        }
        state.ledger = next;
        Ok(result)
    }
    pub fn list(&self) -> io::Result<(Vec<DownloadRecoveryView>, u64)> {
        let state = lock(&self.state);
        Ok((
            state
                .ledger
                .records
                .values()
                .map(|item| item.view(state.owners.contains(&item.task_id)))
                .collect(),
            state.ledger.reserved()?,
        ))
    }
    /// Called only after this session's explicit host folder selection. Reuses
    /// an opaque ID for the same no-follow directory object, never its consent.
    /// Without this fact a new random per-session root ID could never match a
    /// saved exact-root download after the host process restarted.
    pub fn approved_read_root_id(&self, path: &Path, new_id: &str) -> io::Result<String> {
        checked_id(new_id)?;
        let identity = ObjectId::from(&open_directory(path)?.dir_metadata()?);
        self.change(|ledger| {
            if let Some((id, _)) = ledger
                .read_root_ids
                .iter()
                .find(|(_, value)| value.device == identity.device && value.inode == identity.inode)
            {
                return Ok(id.clone());
            }
            if ledger.read_root_ids.len() >= DOWNLOAD_RECOVERY_TASKS
                || ledger.read_root_ids.contains_key(new_id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "stable local read-root identity capacity reached",
                ));
            }
            ledger.read_root_ids.insert(new_id.into(), identity);
            Ok(new_id.into())
        })
    }
    pub fn resume_facts(&self, id: &str) -> io::Result<DownloadRecoveryResume> {
        let record = self.unowned(id)?;
        if !matches!(record.stage, Stage::Staged) || record.temporary_removed {
            return Err(invalid("download is not an interrupted staged task"));
        }
        Ok(DownloadRecoveryResume {
            facts: record.facts,
            checkpoint_bytes: record.checkpoint,
        })
    }
    fn unowned(&self, id: &str) -> io::Result<Record> {
        checked_id(id)?;
        let state = lock(&self.state);
        if state.owners.contains(id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "download still has a live worker",
            ));
        }
        state
            .ledger
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| invalid("unknown persistent download task"))
    }
    fn claim_record(&self, id: &str) -> io::Result<Record> {
        checked_id(id)?;
        let mut state = lock(&self.state);
        if state.poisoned || state.owners.contains(id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "persistent download owner unavailable",
            ));
        }
        let record = state
            .ledger
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| invalid("unknown persistent download task"))?;
        state.owners.insert(id.into());
        Ok(record)
    }
    fn claim(&self, id: &str) -> io::Result<()> {
        let mut state = lock(&self.state);
        if state.poisoned || !state.owners.insert(id.into()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "persistent download owner unavailable",
            ));
        }
        Ok(())
    }
    fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut Record) -> io::Result<()>,
    ) -> io::Result<()> {
        self.change(|ledger| {
            change(
                ledger
                    .records
                    .get_mut(id)
                    .ok_or_else(|| invalid("unknown persisted download task"))?,
            )
        })
    }
    /// No network/session authority is needed to stop retaining one's exact
    /// local object. A failed delete remains charged and visibly unresolved.
    pub fn cancel(&self, id: &str) -> io::Result<()> {
        let mut record = self.claim_record(id)?;
        let result = (|| {
            if record.temporary_removed {
                return Ok(());
            }
            let (directory, file) = match open_object(
                &record,
                false,
                matches!(record.stage, Stage::Publishing | Stage::Published),
            ) {
                Ok(value) => value,
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && matches!(record.stage, Stage::Publishing | Stage::Published) =>
                {
                    let directory = open_area(&record)?;
                    let mut final_file = directory.open_with(&record.name, &options(false))?;
                    let metadata = final_file.metadata()?;
                    if !metadata.is_file()
                        || metadata.nlink() != 1
                        || metadata.len() != record.facts.size
                        || record.checkpoint != record.facts.size
                        || !record.file.as_ref().is_some_and(|id| id.matches(&metadata))
                    {
                        return Err(invalid("publication gap final object differs"));
                    }
                    let mut hash = Sha256::new();
                    read_prefix(
                        &mut final_file,
                        record.facts.size,
                        &mut hash,
                        None,
                        &mut || Ok(()),
                    )?;
                    if hash.finalize().as_slice() != record.facts.sha256.as_slice() {
                        return Err(invalid("publication gap final digest differs"));
                    }
                    record.stage = Stage::Published;
                    record.temporary_removed = true;
                    record.directory_synced = sync_directory(&directory)?;
                    record.cleanup_error = None;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            if metadata.nlink() == 2 {
                // The final name must be recognized before touching this link.
                verify_published(&directory, &record, &file)?;
                record.stage = Stage::Published;
            }
            drop(file);
            verify_temporary(&directory, &record, record.stage == Stage::Published)?;
            directory.remove_file(&record.temporary)?;
            record.temporary_removed = true;
            record.directory_synced = sync_directory(&directory)?;
            if record.stage != Stage::Published {
                record.stage = Stage::Cancelled;
            }
            record.cleanup_error = None;
            Ok(())
        })();
        if let Err(error) = &result {
            record.cleanup_error = Some(format!("{:?}", error.kind()));
            if !matches!(record.stage, Stage::Publishing | Stage::Published) {
                record.stage = Stage::Failed;
            }
        }
        let export_result = record.last_export.as_mut().map_or(Ok(()), cleanup_export);
        let persisted = self.update(id, |item| {
            *item = record;
            Ok(())
        });
        lock(&self.state).owners.remove(id);
        persisted?;
        result.and(export_result)
    }
    /// Export is visibly a partial copy, never a completed source download.
    /// Its target directory must be fresh and the final entry is no-clobber.
    pub fn export_partial(&self, id: &str, fresh: &Path, name: &str) -> io::Result<()> {
        local_name(name)?;
        if !name.ends_with(".partial") || !fresh.is_absolute() || fresh.as_os_str().len() > 4096 {
            return Err(invalid("bounded absolute partial export path required"));
        }
        let record = self.claim_record(id)?;
        let mut export = PartialExport {
            area: fresh.into(),
            name: name.into(),
            directory: None,
            file: None,
            checkpoint: record.checkpoint,
            sha256: record.prefix_sha256,
            published: false,
            temporary_removed: false,
            file_synced: false,
            directory_synced: false,
            error: None,
        };
        let mut reserved = false;
        let mut created = false;
        let result = (|| {
            if record.last_export.is_some() || record.temporary_removed {
                return Err(invalid(
                    "one bounded export attempt is already recorded, or staging was removed",
                ));
            }
            let (_, mut file) = open_object(&record, false, false)?;
            let mut hash = Sha256::new();
            read_prefix(
                &mut file,
                record.checkpoint,
                &mut hash,
                None,
                &mut || Ok(()),
            )?;
            if hash.finalize().as_slice() != record.prefix_sha256.as_slice() {
                return Err(invalid("partial export prefix differs"));
            }
            // Reserve a second copy's staged bytes before allocating its area.
            // A crash never clears this reservation from absence of consent.
            self.update(id, |item| {
                item.last_export = Some(export.clone());
                Ok(())
            })?;
            reserved = true;
            create_fresh_area(fresh)?;
            let destination = open_directory(fresh)?;
            let mut create = options(true);
            create.create_new(true);
            let mut output = destination.open_with(EXPORT_TEMPORARY, &create)?;
            created = true;
            export.directory = Some(ObjectId::from(&destination.dir_metadata()?));
            export.file = Some(ObjectId::from(&output.metadata()?));
            self.update(id, |item| {
                item.last_export = Some(export.clone());
                Ok(())
            })?;
            file.seek(SeekFrom::Start(0))?;
            let copied = io::copy(&mut file.take(record.checkpoint), &mut output)?;
            if copied != record.checkpoint {
                return Err(invalid("partial export source shortened"));
            }
            output.sync_all()?;
            output.seek(SeekFrom::Start(0))?;
            let mut copied_hash = Sha256::new();
            read_prefix(
                &mut output,
                record.checkpoint,
                &mut copied_hash,
                None,
                &mut || Ok(()),
            )?;
            if copied_hash.finalize().as_slice() != record.prefix_sha256.as_slice() {
                return Err(invalid("partial export copy differs"));
            }
            export.file_synced = true;
            self.update(id, |item| {
                item.last_export = Some(export.clone());
                Ok(())
            })?;
            let actual = destination.symlink_metadata(EXPORT_TEMPORARY)?;
            no_reparse(&actual)?;
            if !export
                .file
                .as_ref()
                .is_some_and(|identity| identity.matches(&actual))
                || !actual.is_file()
                || actual.nlink() != 1
                || actual.len() != export.checkpoint
            {
                return Err(invalid(
                    "partial export temporary changed before publication",
                ));
            }
            destination.hard_link(EXPORT_TEMPORARY, &destination, name)?;
            export.published = true;
            self.update(id, |item| {
                item.last_export = Some(export.clone());
                Ok(())
            })?;
            drop(output);
            Ok(())
        })();
        let cleanup = if reserved {
            if !created {
                export.temporary_removed = true;
                Ok(())
            } else {
                cleanup_export(&mut export)
            }
        } else {
            Ok(())
        };
        if let Err(error) = &result {
            export.error = Some(format!("{:?}", error.kind()));
        }
        if let Err(error) = &cleanup {
            export
                .error
                .get_or_insert_with(|| format!("{:?}", error.kind()));
        }
        let persisted = if reserved {
            self.update(id, |item| {
                item.last_export = Some(export);
                Ok(())
            })
        } else {
            Ok(())
        };
        lock(&self.state).owners.remove(id);
        persisted?;
        result.and(cleanup)
    }
}

fn export_directory(export: &PartialExport) -> io::Result<Dir> {
    nestlink_platform_security::check_private_directory(&export.area)?;
    let directory = open_directory(&export.area)?;
    if !export
        .directory
        .as_ref()
        .is_some_and(|id| directory.dir_metadata().is_ok_and(|meta| id.matches(&meta)))
    {
        return Err(invalid("original partial export directory changed"));
    }
    Ok(directory)
}
fn verify_export_final(directory: &Dir, export: &PartialExport, links: u64) -> io::Result<()> {
    let mut file = directory.open_with(&export.name, &options(false))?;
    let meta = file.metadata()?;
    no_reparse(&meta)?;
    if !meta.is_file()
        || meta.nlink() != links
        || meta.len() != export.checkpoint
        || !export.file.as_ref().is_some_and(|id| id.matches(&meta))
        || !export.file_synced
    {
        return Err(invalid("partial export final object differs"));
    }
    let mut hash = Sha256::new();
    read_prefix(
        &mut file,
        export.checkpoint,
        &mut hash,
        None,
        &mut || Ok(()),
    )?;
    if hash.finalize().as_slice() != export.sha256.as_slice() {
        return Err(invalid("partial export final digest differs"));
    }
    Ok(())
}
fn cleanup_export(export: &mut PartialExport) -> io::Result<()> {
    if export.temporary_removed {
        return Ok(());
    }
    let result = (|| {
        let directory = export_directory(export)?;
        let meta = match directory.symlink_metadata(EXPORT_TEMPORARY) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                verify_export_final(&directory, export, 1)?;
                export.published = true;
                export.temporary_removed = true;
                export.directory_synced = sync_directory(&directory)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        no_reparse(&meta)?;
        if !meta.is_file()
            || !export.file.as_ref().is_some_and(|id| id.matches(&meta))
            || meta.len() > export.checkpoint
            || !(meta.nlink() == 1 || meta.nlink() == 2)
        {
            return Err(invalid("partial export temporary differs"));
        }
        if meta.nlink() == 2 {
            verify_export_final(&directory, export, 2)?;
            export.published = true;
        }
        directory.remove_file(EXPORT_TEMPORARY)?;
        export.temporary_removed = true;
        export.directory_synced = sync_directory(&directory)?;
        Ok(())
    })();
    if let Err(error) = &result {
        export.error = Some(format!("{:?}", error.kind()));
    }
    result
}

/// Cleanup is local owner authority after remote revocation. Capture identities
/// from the retained original handles if initialization failed before journaling
/// them; never turn a pathname lookup into ownership of a replacement object.
fn cleanup_owned_disk(disk: &mut LocalDownload, record: &mut Record) -> io::Result<()> {
    let retained = disk.file.take();
    disk.status.file_closed = true;
    disk.status.poisoned = true;
    if disk.status.temporary_removed {
        return Ok(());
    }
    if !disk.temporary_created {
        disk.status.temporary_removed = true;
        return Ok(());
    }
    let directory = disk
        .directory
        .as_ref()
        .ok_or_else(|| invalid("original cleanup directory closed"))?;
    let directory_meta = directory.dir_metadata()?;
    no_reparse(&directory_meta)?;
    let directory_id = ObjectId::from(&directory_meta);
    if record
        .directory
        .as_ref()
        .is_some_and(|id| !id.matches(&directory_meta))
        || !directory_id.matches(&open_directory(&disk.local_fresh_area)?.dir_metadata()?)
    {
        return Err(invalid("original owned cleanup directory changed"));
    }
    let file = match retained {
        Some(file) => file,
        None if record.file.is_some() => directory.open_with(&record.temporary, &options(false))?,
        None => return Err(invalid("original owned cleanup file identity unavailable")),
    };
    let meta = file.metadata()?;
    no_reparse(&meta)?;
    if !meta.is_file() || record.file.as_ref().is_some_and(|id| !id.matches(&meta)) {
        return Err(invalid("original owned cleanup file changed"));
    }
    record.directory = Some(directory_id);
    record.file = Some(ObjectId::from(&meta));
    let published =
        disk.status.published || matches!(record.stage, Stage::Publishing | Stage::Published);
    verify_temporary(directory, record, published)?;
    if meta.nlink() == 2 {
        verify_published(directory, record, &file)?;
        disk.status.published = true;
    } else if meta.nlink() != 1 {
        return Err(invalid("owned cleanup object has unexpected links"));
    }
    drop(file);
    verify_temporary(directory, record, published)?;
    directory.remove_file(&record.temporary)?;
    disk.status.temporary_removed = true;
    disk.status.directory_synced = sync_directory(directory)?;
    Ok(())
}

fn create_fresh_area(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing selected directory parent"))?;
    let parent_cap = open_directory(parent)?;
    let before = ObjectId::from(&parent_cap.dir_metadata()?);
    // The native ACL helper creates the final component privately. Check the
    // retained parent again and never accept a link at the new final component.
    nestlink_platform_security::new_private_directory(path)?;
    if !before.matches(&open_directory(parent)?.dir_metadata()?) {
        return Err(invalid("selected directory parent changed"));
    }
    let leaf = path
        .file_name()
        .ok_or_else(|| invalid("missing selected area name"))?;
    let directory = parent_cap.open_dir_nofollow(leaf)?;
    let actual = open_directory(path)?;
    if !ObjectId::from(&directory.dir_metadata()?).matches(&actual.dir_metadata()?) {
        return Err(invalid("selected directory changed"));
    }
    Ok(())
}
fn open_area(record: &Record) -> io::Result<Dir> {
    nestlink_platform_security::check_private_directory(&record.area)?;
    let directory = open_directory(&record.area)?;
    if !record
        .directory
        .as_ref()
        .is_some_and(|id| directory.dir_metadata().is_ok_and(|meta| id.matches(&meta)))
    {
        return Err(invalid("original download directory changed"));
    }
    Ok(directory)
}
fn verify_temporary(directory: &Dir, record: &Record, allow_published: bool) -> io::Result<()> {
    let meta = directory.symlink_metadata(&record.temporary)?;
    no_reparse(&meta)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || !record.file.as_ref().is_some_and(|id| id.matches(&meta))
        || !(meta.nlink() == 1 || (allow_published && meta.nlink() == 2))
    {
        return Err(invalid("original partial entry changed"));
    }
    Ok(())
}
fn open_object(record: &Record, writable: bool, allow_published: bool) -> io::Result<(Dir, File)> {
    let directory = open_area(record)?;
    verify_temporary(&directory, record, allow_published)?;
    let file = directory.open_with(&record.temporary, &options(writable))?;
    let meta = file.metadata()?;
    no_reparse(&meta)?;
    if !meta.is_file()
        || !record.file.as_ref().is_some_and(|id| id.matches(&meta))
        || meta.len() < record.checkpoint
        || meta.len() > record.facts.size
        || !(meta.nlink() == 1 || (allow_published && meta.nlink() == 2))
    {
        return Err(invalid("original partial handle changed"));
    }
    verify_temporary(&directory, record, allow_published)?;
    Ok((directory, file))
}
fn read_prefix(
    file: &mut File,
    length: u64,
    hash: &mut Sha256,
    mut verifier: Option<&mut FileReadVerifier>,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    file.seek(SeekFrom::Start(0))?;
    check()?;
    let mut remaining = length;
    let mut buffer = vec![0; FILE_PAYLOAD_BYTES as usize];
    while remaining != 0 {
        let amount = remaining.min(FILE_PAYLOAD_BYTES) as usize;
        let mut obtained = 0;
        while obtained != amount {
            check()?;
            let count = file.read(&mut buffer[obtained..amount])?;
            check()?;
            if count == 0 {
                return Err(invalid("durable partial prefix shortened"));
            }
            obtained += count;
        }
        hash.update(&buffer[..amount]);
        if let Some(verifier) = verifier.as_mut() {
            verifier.seed_prefix(&buffer[..amount])?;
        }
        remaining -= amount as u64;
    }
    check()
}
fn verify_published(directory: &Dir, record: &Record, file: &File) -> io::Result<()> {
    if record.checkpoint != record.facts.size || file.metadata()?.len() != record.facts.size {
        return Err(invalid("publication has no complete checkpoint"));
    }
    let meta = directory.symlink_metadata(&record.name)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 2
        || !record.file.as_ref().is_some_and(|id| id.matches(&meta))
    {
        return Err(invalid(
            "published entry differs from original staged object",
        ));
    }
    let mut opened = file.try_clone()?;
    let mut hash = Sha256::new();
    read_prefix(&mut opened, record.facts.size, &mut hash, None, &mut || {
        Ok(())
    })?;
    if hash.finalize().as_slice() != record.facts.sha256.as_slice() {
        return Err(invalid("published object digest differs"));
    }
    Ok(())
}

/// Each construction is a new, explicit local save/recovery approval. It owns
/// no old authority; the source snapshot is sealed by the fresh FileRead client.
pub struct PersistentDownloadSelection {
    store: Arc<DownloadRecoveryStore>,
    id: String,
    area: Option<PathBuf>,
    name: Option<String>,
    consent: Arc<AtomicBool>,
}
impl PersistentDownloadSelection {
    pub fn new(
        store: Arc<DownloadRecoveryStore>,
        id: &str,
        area: &Path,
        name: &str,
    ) -> io::Result<(Self, LocalDownloadConsent)> {
        checked_id(id)?;
        local_name(name)?;
        if !area.is_absolute() {
            return Err(invalid("absolute selected download area required"));
        }
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                store,
                id: id.into(),
                area: Some(area.into()),
                name: Some(name.into()),
                consent: consent.clone(),
            },
            LocalDownloadConsent(consent),
        ))
    }
    pub fn recover(
        store: Arc<DownloadRecoveryStore>,
        id: &str,
    ) -> io::Result<(Self, LocalDownloadConsent)> {
        checked_id(id)?;
        // A pure selection: disk checks happen only on the worker in prepare.
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                store,
                id: id.into(),
                area: None,
                name: None,
                consent: consent.clone(),
            },
            LocalDownloadConsent(consent),
        ))
    }
}
impl FileDestinationFactory for PersistentDownloadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(PersistentDestination {
            selection: *self,
            source: source.clone(),
            disk: None,
            claimed: false,
            registered: false,
        }))
    }
}
struct PersistentDestination {
    selection: PersistentDownloadSelection,
    source: FileDownloadSnapshot,
    disk: Option<LocalDownload>,
    claimed: bool,
    registered: bool,
}
impl PersistentDestination {
    fn disk(&mut self) -> io::Result<&mut LocalDownload> {
        self.disk
            .as_mut()
            .ok_or_else(|| invalid("persistent destination was not opened"))
    }
    fn record_error(&self, result: &io::Result<()>) {
        if self.registered
            && let Err(error) = result
        {
            // Retain the exact callback error object for the worker's pause
            // boundary. A secondary metadata error must never replace it.
            let _ = self.selection.store.update(&self.selection.id, |record| {
                record
                    .operation_error
                    .get_or_insert_with(|| format!("{:?}", error.kind()));
                Ok(())
            });
        }
    }
    fn checkpoint(
        &mut self,
        stage: Stage,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let consent = self.selection.consent.clone();
        let disk = self.disk()?;
        check(&consent, authorized)?;
        disk.file
            .as_ref()
            .ok_or_else(|| invalid("checkpoint file closed"))?
            .sync_all()?;
        check(&consent, authorized)?;
        disk.object(authorized)?;
        let checkpoint = disk.status.confirmed_bytes;
        let prefix: [u8; 32] = disk.prefix.clone().finalize().into();
        self.selection.store.update(&self.selection.id, |record| {
            record.checkpoint = checkpoint;
            record.prefix_sha256 = prefix;
            record.stage = stage;
            record.file_synced = true;
            Ok(())
        })?;
        check(&consent, authorized)
    }
}
impl FileDestination for PersistentDestination {
    fn status(&self) -> LocalDownloadStatus {
        self.disk.as_ref().map_or(
            LocalDownloadStatus {
                file_closed: true,
                ..LocalDownloadStatus::default()
            },
            LocalDownload::status,
        )
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let result = (|| {
            check(&self.selection.consent, authorized)?;
            if self.claimed || self.disk.is_some() {
                return Err(invalid("persistent destination already prepared"));
            }
            self.selection.store.claim(&self.selection.id)?;
            self.claimed = true;
            let facts = self.source.recovery_facts()?;
            facts
                .validate()
                .map_err(|_| invalid("invalid sealed source recovery facts"))?;
            if let (Some(area), Some(name)) =
                (self.selection.area.clone(), self.selection.name.clone())
            {
                let mut disk = LocalDownload::selected(
                    &area,
                    &name,
                    FILE_SIZE_BYTES,
                    &self.source,
                    self.selection.consent.clone(),
                )?;
                disk.temporary = format!(".nestlink-{}.part", self.selection.id.replace('-', ""));
                let record = Record {
                    task_id: self.selection.id.clone(),
                    facts,
                    area: area.clone(),
                    temporary: disk.temporary.clone(),
                    name: name.clone(),
                    directory: None,
                    file: None,
                    checkpoint: 0,
                    prefix_sha256: Sha256::digest([]).into(),
                    stage: Stage::Reserved,
                    temporary_removed: false,
                    file_synced: false,
                    directory_synced: false,
                    operation_error: None,
                    cleanup_error: None,
                    last_export: None,
                };
                self.selection.store.change(|ledger| {
                    if ledger.records.contains_key(&record.task_id)
                        || ledger.records.len() >= ledger.maximum_tasks
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::StorageFull,
                            "persistent download task capacity reached",
                        ));
                    }
                    ledger.records.insert(record.task_id.clone(), record);
                    Ok(())
                })?;
                self.registered = true;
                // The ledger's full size reservation is durable before creation.
                // LocalDownload's creation already enforces a fresh private area.
                open_directory(
                    area.parent()
                        .ok_or_else(|| invalid("missing local area parent"))?,
                )?;
                self.disk = Some(disk);
                self.disk()?.prepare(authorized)?;
                let disk = self.disk()?;
                let directory_id = ObjectId::from(
                    &disk
                        .directory
                        .as_ref()
                        .ok_or_else(|| invalid("missing prepared directory"))?
                        .dir_metadata()?,
                );
                let file_id = ObjectId::from(
                    &disk
                        .file
                        .as_ref()
                        .ok_or_else(|| invalid("missing prepared file"))?
                        .metadata()?,
                );
                let area_actual = open_directory(&area)?;
                if !directory_id.matches(&area_actual.dir_metadata()?) {
                    return Err(invalid("prepared directory pathname changed"));
                }
                self.selection.store.update(&self.selection.id, |item| {
                    item.directory = Some(directory_id);
                    item.file = Some(file_id);
                    item.stage = Stage::Staged;
                    Ok(())
                })?;
                self.checkpoint(Stage::Staged, authorized)
            } else {
                let record = {
                    let state = lock(&self.selection.store.state);
                    state
                        .ledger
                        .records
                        .get(&self.selection.id)
                        .cloned()
                        .ok_or_else(|| invalid("unknown recovery task"))?
                };
                if record.stage != Stage::Staged
                    || record.temporary_removed
                    || record.facts != facts
                    || self.source.manifest().offset != record.checkpoint
                    || self.source.offset() != record.checkpoint
                {
                    return Err(denied(
                        "fresh source differs from saved recovery scope or checkpoint",
                    ));
                }
                self.registered = true;
                check(&self.selection.consent, authorized)?;
                let (directory, file, verifier, prefix) =
                    reopen_checkpoint(&record, self.source.manifest(), &mut || {
                        check(&self.selection.consent, authorized)
                    })?;
                self.disk = Some(LocalDownload {
                    local_fresh_area: record.area,
                    directory: Some(directory),
                    file: Some(file),
                    temporary_created: true,
                    temporary: record.temporary,
                    name: record.name,
                    device: record
                        .file
                        .as_ref()
                        .ok_or_else(|| invalid("missing recovery file ID"))?
                        .device,
                    inode: record
                        .file
                        .as_ref()
                        .ok_or_else(|| invalid("missing recovery file ID"))?
                        .inode,
                    manifest: self.source.manifest().clone(),
                    binding: self.source.binding(),
                    verifier: Some(verifier),
                    prefix,
                    consent: self.selection.consent.clone(),
                    status: LocalDownloadStatus {
                        confirmed_bytes: record.checkpoint,
                        ..LocalDownloadStatus::default()
                    },
                });
                self.disk()?.object(authorized)?;
                check(&self.selection.consent, authorized)
            }
        })();
        self.record_error(&result);
        result
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let result = (|| {
            self.disk()?.write_chunk(source, chunk, authorized)?;
            self.checkpoint(Stage::Staged, authorized)
        })();
        self.record_error(&result);
        result
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let result = (|| {
            if source.recovery_facts()? != self.source.recovery_facts()? {
                return Err(denied("resume source facts changed"));
            }
            self.disk()?.resume(source, authorized)?;
            self.checkpoint(Stage::Staged, authorized)
        })();
        self.record_error(&result);
        result
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let result = (|| {
            self.checkpoint(Stage::Publishing, authorized)?;
            let record = {
                let state = lock(&self.selection.store.state);
                state
                    .ledger
                    .records
                    .get(&self.selection.id)
                    .cloned()
                    .ok_or_else(|| invalid("publication record disappeared"))?
            };
            let directory = open_area(&record)?;
            verify_temporary(&directory, &record, false)?;
            self.disk()?.finish(source, authorized).map(|_| ())
        })();
        let status = self.status();
        // Record actual publication even if authorization changed after the OS
        // link call. Never falsely erase the completed local object.
        let persisted = self.selection.store.update(&self.selection.id, |record| {
            if status.published {
                record.stage = Stage::Published;
            }
            record.temporary_removed = status.temporary_removed;
            record.directory_synced = status.directory_synced;
            if let Err(error) = &result {
                record
                    .operation_error
                    .get_or_insert_with(|| format!("{:?}", error.kind()));
            }
            Ok(())
        });
        persisted?;
        result
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if !self.registered {
            return Ok(());
        }
        let mut record = {
            let state = lock(&self.selection.store.state);
            state
                .ledger
                .records
                .get(&self.selection.id)
                .cloned()
                .ok_or_else(|| invalid("persistent cleanup record disappeared"))?
        };
        let result = self
            .disk
            .as_mut()
            .map_or(Ok(()), |disk| cleanup_owned_disk(disk, &mut record));
        let status = self.status();
        if status.published {
            record.stage = Stage::Published;
        } else {
            record.stage =
                if result.is_ok() && status.temporary_removed && record.operation_error.is_none() {
                    Stage::Cancelled
                } else if !status.temporary_removed && record.stage == Stage::Publishing {
                    Stage::Publishing
                } else {
                    Stage::Failed
                };
        }
        record.temporary_removed = status.temporary_removed;
        record.directory_synced |= status.directory_synced;
        if let Err(error) = &result {
            record.cleanup_error = Some(format!("{:?}", error.kind()));
        }
        let persisted = self.selection.store.update(&self.selection.id, |item| {
            *item = record;
            Ok(())
        });
        persisted?;
        result
    }
}
impl Drop for PersistentDestination {
    fn drop(&mut self) {
        if self.claimed {
            lock(&self.selection.store.state)
                .owners
                .remove(&self.selection.id);
        }
    }
}

fn reopen_checkpoint(
    record: &Record,
    manifest: &FileReadManifest,
    authorized: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<(Dir, File, FileReadVerifier, Sha256)> {
    authorized()?;
    if manifest.offset != record.checkpoint
        || manifest.size != record.facts.size
        || manifest.sha256 != record.facts.sha256
    {
        return Err(invalid(
            "recovery manifest does not bind the original durable checkpoint",
        ));
    }
    let (directory, mut file) = open_object(record, true, false)?;
    let mut verifier = FileReadVerifier::new(manifest.clone())?;
    let mut prefix = Sha256::new();
    read_prefix(
        &mut file,
        record.checkpoint,
        &mut prefix,
        Some(&mut verifier),
        authorized,
    )?;
    if prefix.clone().finalize().as_slice() != record.prefix_sha256.as_slice() {
        return Err(invalid("actual durable recovery prefix differs"));
    }
    if file.metadata()?.len() != record.checkpoint {
        // Only the original handle, after full prefix proof and new approval.
        // Extra bytes are never treated as confirmed checkpoint data.
        authorized()?;
        file.set_len(record.checkpoint)?;
        file.sync_all()?;
        authorized()?;
    }
    verify_temporary(&directory, record, false)?;
    authorized()?;
    Ok((directory, file, verifier, prefix))
}

#[cfg(test)]
mod tests;
