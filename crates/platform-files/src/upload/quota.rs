//! Durable metadata for the local aggregate FileWrite quota.
use super::{QuotaLedgerFileSnapshot, QuotaLedgerSnapshot, QuotaUsage};
use cap_fs_ext::{MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const LOCK_NAME: &str = "native-file-write-quota.lock";
const LEDGER_NAME: &str = "native-file-write-quota.ledger";
const LEDGER_TEMP_NAME: &str = "native-file-write-quota.pending";
const LEDGER_MAGIC: &[u8; 8] = b"NLWQLED1";
const LOCK_MARKER: &[u8; 8] = b"NLWQLOCK";
const LEDGER_VERSION: u32 = 1;
const LEDGER_BODY_BYTES: usize = 48;
const LEDGER_BYTES: usize = LEDGER_BODY_BYTES + 32;
const MAX_SNAPSHOT_BYTES: u64 = 4096;
const LOCK_EMPTY: u8 = 0;
const LOCK_INITIALIZED: u8 = 1;

/// A process-wide exclusive owner for one stable lock file and one atomic
/// metadata ledger. The lock file is intentionally never replaced.
pub(super) struct PrivateLedger {
    directory: Dir,
    _lock: File,
    maximum_bytes: u64,
    maximum_artifacts: u64,
    #[cfg(test)]
    fail_next_before_replace: std::sync::atomic::AtomicBool,
}

impl Drop for PrivateLedger {
    fn drop(&mut self) {
        // flock belongs to the open file description. A concurrent fork can
        // briefly inherit it even with CLOEXEC; closing our descriptor alone
        // then leaves a departed owner locked until the child execs/exits.
        let _ = self._lock.unlock();
    }
}

impl PrivateLedger {
    pub(super) fn open(
        private_state_dir: &Path,
        maximum_bytes: u64,
        maximum_artifacts: u64,
    ) -> io::Result<(Self, QuotaUsage)> {
        nestlink_platform_security::check_private_directory(private_state_dir)?;
        let directory = Dir::open_ambient_dir(private_state_dir, cap_std::ambient_authority())?;
        let mut lock = open_lock_file(&directory)?;
        check_private_file(&lock)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native file write quota already has an active owner",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }

        let marker = read_lock_marker(&mut lock)?;
        let ledger = Self {
            directory,
            _lock: lock,
            maximum_bytes,
            maximum_artifacts,
            #[cfg(test)]
            fail_next_before_replace: std::sync::atomic::AtomicBool::new(false),
        };

        // A single fixed pending name bounds metadata left by a crash or an
        // unconfirmed cleanup. Do not allocate more names or discard it on
        // reopening: its original write may have reached the filesystem.
        match ledger.directory.symlink_metadata(LEDGER_TEMP_NAME) {
            Ok(_) => return Err(invalid_data("durable quota metadata recovery is required")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let (usage, ledger_exists) = match ledger.read_usage() {
            Ok(usage) => (usage, true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if marker == LOCK_INITIALIZED {
                    return Err(invalid_data("durable quota ledger is missing"));
                }
                (QuotaUsage::default(), false)
            }
            Err(error) => return Err(error),
        };
        if marker != LOCK_EMPTY && marker != LOCK_INITIALIZED {
            return Err(invalid_data("durable quota lock marker is damaged"));
        }

        if !ledger_exists {
            ledger.persist(usage)?;
        }
        if marker == LOCK_EMPTY {
            ledger.write_lock_marker()?;
        }
        Ok((ledger, usage))
    }

    pub(super) fn persist(&self, usage: QuotaUsage) -> io::Result<()> {
        if usage.bytes > self.maximum_bytes || usage.artifacts > self.maximum_artifacts {
            return Err(invalid_data(
                "durable quota usage exceeds configured limits",
            ));
        }
        let contents = encode_ledger(self.maximum_bytes, self.maximum_artifacts, usage);
        let (temporary, mut file) = self.create_temporary()?;
        let write_result = file.write_all(&contents).and_then(|()| file.sync_all());
        if let Err(error) = write_result {
            drop(file);
            let _ = self.directory.remove_file(&temporary);
            return Err(error);
        }
        #[cfg(test)]
        if self
            .fail_next_before_replace
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            drop(file);
            let _ = self.directory.remove_file(&temporary);
            return Err(io::Error::other(
                "injected durable quota ledger replacement failure",
            ));
        }
        drop(file);
        if let Err(error) = self
            .directory
            .rename(&temporary, &self.directory, LEDGER_NAME)
        {
            let _ = self.directory.remove_file(&temporary);
            return Err(error);
        }

        // Sync the new file after replacement as well as syncing the complete
        // temporary contents before rename. Unix additionally syncs the parent
        // directory so the name replacement itself is durable.
        self.open_ledger_file(true)?.sync_all()?;
        #[cfg(unix)]
        self.sync_directory()?;
        Ok(())
    }

    fn read_usage(&self) -> io::Result<QuotaUsage> {
        let file = self.open_ledger_file(false)?;
        let mut contents = Vec::with_capacity(LEDGER_BYTES + 1);
        file.take((LEDGER_BYTES + 1) as u64)
            .read_to_end(&mut contents)?;
        decode_ledger(&contents, self.maximum_bytes, self.maximum_artifacts)
    }

    fn open_ledger_file(&self, writable: bool) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(writable)
            .follow(cap_fs_ext::FollowSymlinks::No);
        into_private_file(self.directory.open_with(LEDGER_NAME, &options)?)
    }

    fn create_temporary(&self) -> io::Result<(String, File)> {
        let mut options = private_file_options();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(cap_fs_ext::FollowSymlinks::No);
        let file = self.directory.open_with(LEDGER_TEMP_NAME, &options)?;
        Ok((LEDGER_TEMP_NAME.to_owned(), into_private_file(file)?))
    }

    fn write_lock_marker(&self) -> io::Result<()> {
        let mut lock = self._lock.try_clone().and_then(|mut cloned| {
            cloned.seek(SeekFrom::Start(0))?;
            cloned.set_len(0)?;
            cloned.write_all(LOCK_MARKER)?;
            cloned.sync_all()?;
            Ok(cloned)
        })?;
        lock.seek(SeekFrom::Start(0))?;
        let mut actual = [0_u8; LOCK_MARKER.len()];
        lock.read_exact(&mut actual)?;
        if &actual != LOCK_MARKER {
            return Err(invalid_data("durable quota lock marker did not persist"));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn sync_directory(&self) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.read(true).follow(cap_fs_ext::FollowSymlinks::No);
        self.directory.open_with(".", &options)?.sync_all()
    }

    #[cfg(test)]
    fn fail_next_persist_for_test(&self) {
        self.fail_next_before_replace
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

struct MaintenanceOwner {
    directory: Dir,
    _lock: File,
    lock_marker: Vec<u8>,
}

impl Drop for MaintenanceOwner {
    fn drop(&mut self) {
        let _ = self._lock.unlock();
    }
}

struct OpenedMetadata {
    snapshot: QuotaLedgerFileSnapshot,
    file: File,
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryDecodeError {
    InvalidContents,
    LimitsMismatch,
}

impl MaintenanceOwner {
    fn open_existing(private_state_dir: &Path) -> io::Result<Self> {
        nestlink_platform_security::check_private_directory(private_state_dir)?;
        let directory = Dir::open_ambient_dir(private_state_dir, cap_std::ambient_authority())?;
        let mut lock = open_existing_lock_file(&directory)?;
        check_private_file(&lock)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native file write quota already has an active owner",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        let lock_marker = read_bounded_file(&mut lock)?;
        Ok(Self {
            directory,
            _lock: lock,
            lock_marker,
        })
    }

    fn marker_state(&self) -> Option<u8> {
        if self.lock_marker.is_empty() {
            Some(LOCK_EMPTY)
        } else if self.lock_marker == LOCK_MARKER {
            Some(LOCK_INITIALIZED)
        } else {
            None
        }
    }
}

/// Read raw quota metadata while holding the pre-existing stable lock.
pub(super) fn inspect_private_ledger(private_state_dir: &Path) -> io::Result<QuotaLedgerSnapshot> {
    let owner = MaintenanceOwner::open_existing(private_state_dir)?;
    let ledger = open_optional_metadata(&owner.directory, LEDGER_NAME, false)?;
    let pending = open_optional_metadata(&owner.directory, LEDGER_TEMP_NAME, false)?;
    let lock_marker_valid = owner.marker_state().is_some();
    let lock_marker_sha256 = sha256(&owner.lock_marker);
    Ok(QuotaLedgerSnapshot {
        lock_marker: owner.lock_marker.clone(),
        lock_marker_valid,
        lock_marker_sha256,
        ledger: ledger.map(|entry| entry.snapshot),
        pending: pending.map(|entry| entry.snapshot),
    })
}

/// Repair only metadata. Unknown usage is represented as a fully charged ledger.
pub(super) fn recover_private_ledger(
    private_state_dir: &Path,
    maximum_bytes: u64,
    maximum_artifacts: u64,
) -> io::Result<(QuotaUsage, bool)> {
    let owner = MaintenanceOwner::open_existing(private_state_dir)?;
    let marker = owner
        .marker_state()
        .ok_or_else(|| invalid_data("durable quota lock marker is damaged"))?;
    let ledger = open_optional_metadata(&owner.directory, LEDGER_NAME, false)?;
    let pending = open_optional_metadata(&owner.directory, LEDGER_TEMP_NAME, true)?;
    if ledger.is_none() && pending.is_none() && marker == LOCK_EMPTY {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "durable quota ledger has not been initialized",
        ));
    }

    let ledger_usage = decode_recovery_entry(ledger.as_ref(), maximum_bytes, maximum_artifacts)?;
    let pending_usage = decode_recovery_entry(pending.as_ref(), maximum_bytes, maximum_artifacts)?;

    let maximum_usage = QuotaUsage {
        bytes: maximum_bytes,
        artifacts: maximum_artifacts,
    };
    let (usage, unknown_usage_saturated_limits, needs_replace) = if marker == LOCK_EMPTY {
        match (
            ledger_usage,
            pending_usage,
            ledger.is_some(),
            pending.is_some(),
        ) {
            (Some(current), None, true, false) if current == QuotaUsage::default() => {
                (current, false, false)
            }
            (Some(_), None, true, false) => (maximum_usage, true, true),
            _ => (maximum_usage, true, true),
        }
    } else {
        match (
            ledger_usage,
            pending_usage,
            ledger.is_some(),
            pending.is_some(),
        ) {
            (Some(current), None, true, false) => (current, false, false),
            (Some(current), Some(next), true, true) => (
                QuotaUsage {
                    bytes: current.bytes.max(next.bytes),
                    artifacts: current.artifacts.max(next.artifacts),
                },
                false,
                true,
            ),
            _ => (maximum_usage, true, true),
        }
    };

    if needs_replace {
        let bytes = encode_ledger(maximum_bytes, maximum_artifacts, usage);
        // Windows replacement requires the old ledger handle to be closed.
        drop(ledger);
        replace_recovered_ledger(&owner.directory, pending, &bytes)?;
    }
    Ok((usage, unknown_usage_saturated_limits))
}

fn decode_recovery_entry(
    entry: Option<&OpenedMetadata>,
    maximum_bytes: u64,
    maximum_artifacts: u64,
) -> io::Result<Option<QuotaUsage>> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    match decode_recovery_ledger(&entry.snapshot.raw, maximum_bytes, maximum_artifacts) {
        Ok(usage) => Ok(Some(usage)),
        Err(RecoveryDecodeError::LimitsMismatch) => Err(invalid_data(
            "durable quota limits differ from the configured quota",
        )),
        Err(RecoveryDecodeError::InvalidContents) => Ok(None),
    }
}

fn decode_recovery_ledger(
    bytes: &[u8],
    maximum_bytes: u64,
    maximum_artifacts: u64,
) -> Result<QuotaUsage, RecoveryDecodeError> {
    if bytes.len() != LEDGER_BYTES
        || &bytes[..8] != LEDGER_MAGIC
        || u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| RecoveryDecodeError::InvalidContents)?,
        ) != LEDGER_VERSION
        || bytes[12..16] != [0; 4]
    {
        return Err(RecoveryDecodeError::InvalidContents);
    }
    if Sha256::digest(&bytes[..LEDGER_BODY_BYTES]).as_slice() != &bytes[LEDGER_BODY_BYTES..] {
        return Err(RecoveryDecodeError::InvalidContents);
    }
    let stored_maximum_bytes =
        read_u64(&bytes[16..24]).map_err(|_| RecoveryDecodeError::InvalidContents)?;
    let stored_maximum_artifacts =
        read_u64(&bytes[24..32]).map_err(|_| RecoveryDecodeError::InvalidContents)?;
    if stored_maximum_bytes != maximum_bytes || stored_maximum_artifacts != maximum_artifacts {
        return Err(RecoveryDecodeError::LimitsMismatch);
    }
    let usage = QuotaUsage {
        bytes: read_u64(&bytes[32..40]).map_err(|_| RecoveryDecodeError::InvalidContents)?,
        artifacts: read_u64(&bytes[40..48]).map_err(|_| RecoveryDecodeError::InvalidContents)?,
    };
    if usage.bytes > maximum_bytes || usage.artifacts > maximum_artifacts {
        return Err(RecoveryDecodeError::InvalidContents);
    }
    Ok(usage)
}

fn open_existing_lock_file(directory: &Dir) -> io::Result<File> {
    let path_metadata = directory.symlink_metadata(LOCK_NAME)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota lock entry is not a regular file",
        ));
    }
    let mut options = private_file_options();
    options
        .read(true)
        .write(true)
        .follow(cap_fs_ext::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let cap_file = directory.open_with(LOCK_NAME, &options)?;
    let metadata = cap_file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota lock entry changed or has extra links",
        ));
    }
    into_private_file(cap_file)
}

fn open_optional_metadata(
    directory: &Dir,
    name: &str,
    writable: bool,
) -> io::Result<Option<OpenedMetadata>> {
    let path_metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota metadata entry is not a regular file",
        ));
    }

    let mut options = private_file_options();
    options
        .read(true)
        .write(writable)
        .follow(cap_fs_ext::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let cap_file = directory.open_with(name, &options)?;
    let opened_metadata = cap_file.metadata()?;
    if !opened_metadata.is_file()
        || opened_metadata.nlink() != 1
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota metadata entry changed or has extra links",
        ));
    }
    let device = opened_metadata.dev();
    let inode = opened_metadata.ino();
    let length = opened_metadata.len();
    if length > MAX_SNAPSHOT_BYTES {
        return Err(invalid_data(
            "durable quota metadata entry exceeds export bound",
        ));
    }
    let mut file = into_private_file(cap_file)?;
    let mut raw = Vec::with_capacity(length as usize);
    (&mut file)
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 != length || file.metadata()?.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable quota metadata changed during inspection",
        ));
    }
    let snapshot = QuotaLedgerFileSnapshot {
        sha256: sha256(&raw),
        raw,
    };
    Ok(Some(OpenedMetadata {
        snapshot,
        file,
        device,
        inode,
    }))
}

fn read_bounded_file(file: &mut File) -> io::Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > MAX_SNAPSHOT_BYTES {
        return Err(invalid_data(
            "durable quota lock marker exceeds export bound",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(length as usize);
    (&mut *file)
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != length || file.metadata()?.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable quota lock marker changed during inspection",
        ));
    }
    Ok(bytes)
}

fn replace_recovered_ledger(
    directory: &Dir,
    pending: Option<OpenedMetadata>,
    contents: &[u8; LEDGER_BYTES],
) -> io::Result<()> {
    let (mut file, device, inode) = match pending {
        Some(entry) => (entry.file, entry.device, entry.inode),
        None => {
            let mut options = private_file_options();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(cap_fs_ext::FollowSymlinks::No);
            let cap_file = directory.open_with(LEDGER_TEMP_NAME, &options)?;
            let metadata = cap_file.metadata()?;
            let identity = (metadata.dev(), metadata.ino());
            (into_private_file(cap_file)?, identity.0, identity.1)
        }
    };
    verify_path_identity(directory, LEDGER_TEMP_NAME, device, inode)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    verify_path_identity(directory, LEDGER_TEMP_NAME, device, inode)?;
    directory.rename(LEDGER_TEMP_NAME, directory, LEDGER_NAME)?;

    let ledger = open_named_metadata(directory, LEDGER_NAME, true)?;
    ledger.sync_all()?;
    #[cfg(unix)]
    sync_private_directory(directory)?;
    Ok(())
}

fn open_named_metadata(directory: &Dir, name: &str, writable: bool) -> io::Result<File> {
    let mut options = private_file_options();
    options
        .read(true)
        .write(writable)
        .follow(cap_fs_ext::FollowSymlinks::No);
    let cap_file = directory.open_with(name, &options)?;
    into_private_file(cap_file)
}

fn verify_path_identity(directory: &Dir, name: &str, device: u64, inode: u64) -> io::Result<()> {
    let current = directory.symlink_metadata(name)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || current.nlink() != 1
        || current.dev() != device
        || current.ino() != inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota pending entry changed during recovery",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_private_directory(directory: &Dir) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).follow(cap_fs_ext::FollowSymlinks::No);
    directory.open_with(".", &options)?.sync_all()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn open_lock_file(directory: &Dir) -> io::Result<File> {
    let mut create = private_file_options();
    create
        .read(true)
        .write(true)
        .create_new(true)
        .follow(cap_fs_ext::FollowSymlinks::No);
    match directory.open_with(LOCK_NAME, &create) {
        Ok(file) => into_private_file(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = private_file_options();
            existing
                .read(true)
                .write(true)
                .follow(cap_fs_ext::FollowSymlinks::No);
            directory
                .open_with(LOCK_NAME, &existing)
                .and_then(into_private_file)
        }
        Err(error) => Err(error),
    }
}

fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        // Contenders must be able to open the stable lock, while delete/share
        // denial prevents replacing its inode during an active owner.
        options.share_mode(0x0000_0003);
    }
    options
}

fn read_lock_marker(lock: &mut File) -> io::Result<u8> {
    let size = lock.metadata()?.len();
    if size == 0 {
        return Ok(LOCK_EMPTY);
    }
    if size != LOCK_MARKER.len() as u64 {
        return Err(invalid_data("durable quota lock marker has invalid size"));
    }
    lock.seek(SeekFrom::Start(0))?;
    let mut marker = [0_u8; LOCK_MARKER.len()];
    lock.read_exact(&mut marker)?;
    if &marker == LOCK_MARKER {
        Ok(LOCK_INITIALIZED)
    } else {
        Err(invalid_data("durable quota lock marker is damaged"))
    }
}

fn check_private_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid_data("durable quota entry is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || std::os::unix::fs::MetadataExt::nlink(&metadata) != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable quota file is not owner-private",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable quota file is a reparse point or has extra hard links",
            ));
        }
    }
    Ok(())
}

fn into_private_file(file: cap_std::fs::File) -> io::Result<File> {
    // cap-fs-ext supplies handle metadata on both targets, including Windows
    // link count, without unstable std Windows metadata APIs.
    if file.metadata()?.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable quota file has extra hard links",
        ));
    }
    let file = file.into_std();
    check_private_file(&file)?;
    Ok(file)
}

fn encode_ledger(
    maximum_bytes: u64,
    maximum_artifacts: u64,
    usage: QuotaUsage,
) -> [u8; LEDGER_BYTES] {
    let mut bytes = [0_u8; LEDGER_BYTES];
    bytes[..8].copy_from_slice(LEDGER_MAGIC);
    bytes[8..12].copy_from_slice(&LEDGER_VERSION.to_le_bytes());
    bytes[16..24].copy_from_slice(&maximum_bytes.to_le_bytes());
    bytes[24..32].copy_from_slice(&maximum_artifacts.to_le_bytes());
    bytes[32..40].copy_from_slice(&usage.bytes.to_le_bytes());
    bytes[40..48].copy_from_slice(&usage.artifacts.to_le_bytes());
    let digest = Sha256::digest(&bytes[..LEDGER_BODY_BYTES]);
    bytes[LEDGER_BODY_BYTES..].copy_from_slice(&digest);
    bytes
}

fn decode_ledger(
    bytes: &[u8],
    maximum_bytes: u64,
    maximum_artifacts: u64,
) -> io::Result<QuotaUsage> {
    if bytes.len() != LEDGER_BYTES
        || &bytes[..8] != LEDGER_MAGIC
        || u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| invalid_data("quota ledger version is truncated"))?,
        ) != LEDGER_VERSION
        || bytes[12..16] != [0; 4]
    {
        return Err(invalid_data("durable quota ledger has invalid format"));
    }
    let digest = Sha256::digest(&bytes[..LEDGER_BODY_BYTES]);
    if digest.as_slice() != &bytes[LEDGER_BODY_BYTES..] {
        return Err(invalid_data("durable quota ledger checksum is invalid"));
    }
    let stored_maximum_bytes = read_u64(&bytes[16..24])?;
    let stored_maximum_artifacts = read_u64(&bytes[24..32])?;
    let usage = QuotaUsage {
        bytes: read_u64(&bytes[32..40])?,
        artifacts: read_u64(&bytes[40..48])?,
    };
    if stored_maximum_bytes != maximum_bytes
        || stored_maximum_artifacts != maximum_artifacts
        || usage.bytes > maximum_bytes
        || usage.artifacts > maximum_artifacts
    {
        return Err(invalid_data(
            "durable quota limits differ from the configured quota",
        ));
    }
    Ok(usage)
}

fn read_u64(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        invalid_data("durable quota ledger field is truncated")
    })?))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload::WriteQuota;
    use std::{fs, sync::Arc};

    fn private_state() -> io::Result<(tempfile::TempDir, std::path::PathBuf)> {
        let owner = tempfile::tempdir()?;
        let state = owner.path().join("private-state");
        nestlink_platform_security::new_private_directory(&state)?;
        Ok((owner, state))
    }

    fn write_pending(state: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(state.join(LEDGER_TEMP_NAME))?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn independent_record(
        maximum_bytes: u64,
        maximum_artifacts: u64,
        charged_bytes: u64,
        charged_artifacts: u64,
    ) -> [u8; LEDGER_BYTES] {
        let mut bytes = [0_u8; LEDGER_BYTES];
        bytes[..8].copy_from_slice(b"NLWQLED1");
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&maximum_bytes.to_le_bytes());
        bytes[24..32].copy_from_slice(&maximum_artifacts.to_le_bytes());
        bytes[32..40].copy_from_slice(&charged_bytes.to_le_bytes());
        bytes[40..48].copy_from_slice(&charged_artifacts.to_le_bytes());
        let checksum = Sha256::digest(&bytes[..LEDGER_BODY_BYTES]);
        bytes[LEDGER_BODY_BYTES..].copy_from_slice(&checksum);
        bytes
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&digest);
        result
    }

    #[test]
    fn interrupted_metadata_requires_recovery_without_allocating_more_entries() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = WriteQuota::open_private_ledger(&state, 4, 1)?;
        drop(quota);
        fs::write(state.join(LEDGER_TEMP_NAME), b"interrupted write")?;
        let original_ledger = fs::read(state.join(LEDGER_NAME))?;
        let count = fs::read_dir(&state)?.count();
        for _ in 0..3 {
            assert_eq!(
                WriteQuota::open_private_ledger(&state, 4, 1)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert_eq!(fs::read_dir(&state)?.count(), count);
            assert_eq!(fs::read(state.join(LEDGER_NAME))?, original_ledger);
            assert_eq!(
                fs::read(state.join(LEDGER_TEMP_NAME))?,
                b"interrupted write"
            );
        }
        Ok(())
    }

    #[test]
    fn reopen_preserves_reservations_including_zero_byte_artifacts() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 4, 2)?);
        let mut nonempty = super::super::Reservation::new(quota.clone(), 4)?;
        nonempty.begin_staging();
        let mut empty = super::super::Reservation::new(quota.clone(), 0)?;
        empty.begin_staging();
        drop(nonempty);
        drop(empty);
        drop(quota);

        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 4, 2)?);
        assert_eq!(
            reopened.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        assert_eq!(
            reopened.reserve(1).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn only_confirmed_unpublished_cleanup_releases_after_reopen() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        let mut reservation = super::super::Reservation::new(quota.clone(), 4)?;
        reservation.begin_staging();
        reservation.release_after_cleanup(
            nestlink_protocol::FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..Default::default()
            },
            false,
        )?;
        drop(reservation);
        drop(quota);

        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        let mut empty = super::super::Reservation::new(reopened.clone(), 0)?;
        empty.begin_staging();
        empty.release_after_cleanup(
            nestlink_protocol::FileWriteState {
                published: true,
                file_closed: true,
                temporary_removed: true,
                ..Default::default()
            },
            false,
        )?;
        drop(empty);
        drop(reopened);

        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        assert_eq!(
            reopened.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn unknown_cleanup_and_published_usage_remain_charged_after_restart() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        let mut uncertain = super::super::Reservation::new(quota.clone(), 4)?;
        uncertain.begin_staging();
        uncertain.release_after_cleanup(
            nestlink_protocol::FileWriteState {
                file_closed: true,
                temporary_removed: true,
                ..Default::default()
            },
            true,
        )?;
        drop(uncertain);
        drop(quota);

        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        assert_eq!(
            reopened.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn damaged_ledger_and_changed_limits_fail_closed() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 4, 1)?);
        let ledger_path = state.join(LEDGER_NAME);
        let mut bytes = fs::read(&ledger_path)?;
        bytes[32] ^= 0x80;
        fs::write(&ledger_path, bytes)?;
        assert_eq!(
            WriteQuota::open_private_ledger(&state, 4, 1)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );

        let (_missing_owner, missing_state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&missing_state, 4, 1)?);
        fs::remove_file(missing_state.join(LEDGER_NAME))?;
        assert_eq!(
            WriteQuota::open_private_ledger(&missing_state, 4, 1)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );

        let (_other_owner, other_state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&other_state, 4, 1)?);
        assert_eq!(
            WriteQuota::open_private_ledger(&other_state, 8, 1)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[test]
    fn a_live_owner_exclusively_holds_the_stable_lock_file() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let first = WriteQuota::open_private_ledger(&state, 4, 1)?;
        assert_eq!(
            WriteQuota::open_private_ledger(&state, 4, 1)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(first);
        drop(WriteQuota::open_private_ledger(&state, 4, 1)?);
        Ok(())
    }

    #[test]
    fn hard_linked_metadata_is_rejected_without_resetting_the_ledger() -> io::Result<()> {
        for name in [LOCK_NAME, LEDGER_NAME] {
            let (_owner, state) = private_state()?;
            drop(WriteQuota::open_private_ledger(&state, 4, 1)?);
            let original = fs::read(state.join(LEDGER_NAME))?;
            fs::hard_link(state.join(name), state.join("linked-metadata"))?;
            for _ in 0..2 {
                assert_eq!(
                    WriteQuota::open_private_ledger(&state, 4, 1)
                        .err()
                        .map(|error| error.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert_eq!(fs::read(state.join(LEDGER_NAME))?, original);
            }
        }
        Ok(())
    }

    #[test]
    fn persistence_error_is_returned_and_sticky() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 4, 2)?);
        quota
            .ledger
            .as_ref()
            .ok_or_else(|| io::Error::other("ledger missing"))?
            .fail_next_persist_for_test();

        let first = quota.reserve(1).err().ok_or_else(|| {
            io::Error::other("injected durable quota update unexpectedly succeeded")
        })?;
        assert!(
            first
                .to_string()
                .contains("injected durable quota ledger replacement failure")
        );
        let second = quota.reserve(0).err().ok_or_else(|| {
            io::Error::other("quota accepted another reservation after persistence failure")
        })?;
        assert_eq!(second.kind(), first.kind());
        assert!(
            second
                .to_string()
                .contains("injected durable quota ledger replacement failure")
        );
        Ok(())
    }

    #[test]
    fn release_persistence_error_is_returned_and_keeps_disk_usage_charged() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        let mut reservation = super::super::Reservation::new(quota.clone(), 4)?;
        reservation.begin_staging();
        quota
            .ledger
            .as_ref()
            .ok_or_else(|| io::Error::other("ledger missing"))?
            .fail_next_persist_for_test();

        let first = reservation
            .release_after_cleanup(
                nestlink_protocol::FileWriteState {
                    file_closed: true,
                    temporary_removed: true,
                    ..Default::default()
                },
                false,
            )
            .err()
            .ok_or_else(|| io::Error::other("injected quota release unexpectedly succeeded"))?;
        assert!(
            first
                .to_string()
                .contains("injected durable quota ledger replacement failure")
        );
        let second = quota.reserve(0).err().ok_or_else(|| {
            io::Error::other("quota accepted a reservation after release persistence failure")
        })?;
        assert_eq!(second.kind(), first.kind());
        drop(reservation);
        drop(quota);

        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 4, 1)?);
        assert_eq!(
            reopened.reserve(1).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn inspect_exports_exact_bytes_and_does_not_mutate_pending() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let original_ledger = fs::read(state.join(LEDGER_NAME))?;
        let pending = independent_record(100, 4, 70, 2);
        write_pending(&state, &pending)?;
        let original_marker = fs::read(state.join(LOCK_NAME))?;
        let entry_count = fs::read_dir(&state)?.count();

        let snapshot = WriteQuota::inspect_private_ledger(&state)?;
        assert!(snapshot.lock_marker_valid);
        assert_eq!(snapshot.lock_marker, original_marker);
        assert_eq!(snapshot.lock_marker_sha256, sha256(&original_marker));
        let ledger = snapshot
            .ledger
            .ok_or_else(|| io::Error::other("ledger missing"))?;
        let pending = snapshot
            .pending
            .ok_or_else(|| io::Error::other("pending missing"))?;
        assert_eq!(ledger.raw, original_ledger);
        assert_eq!(ledger.sha256, sha256(&ledger.raw));
        assert_eq!(pending.raw, independent_record(100, 4, 70, 2));
        assert_eq!(pending.sha256, sha256(&pending.raw));
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, original_ledger);
        assert_eq!(fs::read(state.join(LEDGER_TEMP_NAME))?, pending.raw);
        assert_eq!(fs::read(state.join(LOCK_NAME))?, original_marker);
        assert_eq!(fs::read_dir(&state)?.count(), entry_count);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn retired_owner_releases_lock_even_when_its_file_description_is_duplicated() -> io::Result<()>
    {
        let (_owner, state) = private_state()?;
        let (ledger, _) = PrivateLedger::open(&state, 100, 4)?;
        // try_clone shares the same open file description, as an inherited
        // fork descriptor does, without forking the multithreaded test process.
        let inherited = ledger._lock.try_clone()?;
        assert_eq!(
            PrivateLedger::open(&state, 100, 4).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(ledger);
        let maintenance = MaintenanceOwner::open_existing(&state)?;
        let inherited_maintenance = maintenance._lock.try_clone()?;
        assert_eq!(
            PrivateLedger::open(&state, 100, 4).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(maintenance);
        let reopened = PrivateLedger::open(&state, 100, 4)?;
        drop(reopened);
        drop(inherited_maintenance);
        drop(inherited);
        Ok(())
    }

    #[test]
    fn live_owner_blocks_inspection_and_recovery_without_mutation() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        let marker = fs::read(state.join(LOCK_NAME))?;
        let active = WriteQuota::open_private_ledger(&state, 100, 4)?;
        assert_eq!(
            WriteQuota::inspect_private_ledger(&state)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        drop(active);
        assert_eq!(fs::read(state.join(LOCK_NAME))?, marker);
        assert_eq!(fs::read_dir(&state)?.count(), 2);
        Ok(())
    }

    #[test]
    fn recovery_takes_per_field_max_of_two_valid_records() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        let quota = Arc::new(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let mut reservation = super::super::Reservation::new(quota.clone(), 80)?;
        reservation.begin_staging();
        drop(reservation);
        drop(quota);
        write_pending(&state, &independent_record(100, 4, 70, 2))?;

        let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
        assert_eq!(
            (recovery.charged_bytes, recovery.charged_artifacts),
            (80, 2)
        );
        assert!(!recovery.unknown_usage_saturated_limits);
        assert!(!state.join(LEDGER_TEMP_NAME).exists());
        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 100, 4)?);
        assert_eq!(
            reopened.reserve(21).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn valid_ledger_without_pending_is_a_noop() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        let marker = fs::read(state.join(LOCK_NAME))?;
        let entry_count = fs::read_dir(&state)?.count();

        let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
        assert_eq!((recovery.charged_bytes, recovery.charged_artifacts), (0, 0));
        assert!(!recovery.unknown_usage_saturated_limits);
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        assert_eq!(fs::read(state.join(LOCK_NAME))?, marker);
        assert_eq!(fs::read_dir(&state)?.count(), entry_count);
        Ok(())
    }

    #[test]
    fn invalid_pending_saturates_quota_and_is_recoverable() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        write_pending(&state, b"partial ledger")?;
        let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
        assert_eq!(
            (recovery.charged_bytes, recovery.charged_artifacts),
            (100, 4)
        );
        assert!(recovery.unknown_usage_saturated_limits);
        assert!(!state.join(LEDGER_TEMP_NAME).exists());
        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 100, 4)?);
        assert_eq!(
            reopened.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn malformed_current_ledger_saturates_without_pending() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        fs::write(state.join(LEDGER_NAME), b"truncated ledger")?;

        let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
        assert_eq!(
            (recovery.charged_bytes, recovery.charged_artifacts),
            (100, 4)
        );
        assert!(recovery.unknown_usage_saturated_limits);
        assert!(!state.join(LEDGER_TEMP_NAME).exists());
        let reopened = Arc::new(WriteQuota::open_private_ledger(&state, 100, 4)?);
        assert_eq!(
            reopened.reserve(0).err().map(|error| error.kind()),
            Some(io::ErrorKind::StorageFull)
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_hard_linked_pending_without_mutation() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        write_pending(&state, b"partial ledger")?;
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        let pending = fs::read(state.join(LEDGER_TEMP_NAME))?;
        fs::hard_link(
            state.join(LEDGER_TEMP_NAME),
            state.join("linked-pending-ledger"),
        )?;

        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        assert_eq!(fs::read(state.join(LEDGER_TEMP_NAME))?, pending);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_symlink_pending_without_following_or_mutation() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        symlink(LEDGER_NAME, state.join(LEDGER_TEMP_NAME))?;

        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        assert!(
            fs::symlink_metadata(state.join(LEDGER_TEMP_NAME))?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    #[test]
    fn pending_without_current_ledger_saturates_even_when_pending_is_valid() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        fs::remove_file(state.join(LEDGER_NAME))?;
        write_pending(&state, &independent_record(100, 4, 70, 2))?;

        let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
        assert_eq!(
            (recovery.charged_bytes, recovery.charged_artifacts),
            (100, 4)
        );
        assert!(recovery.unknown_usage_saturated_limits);
        Ok(())
    }

    #[test]
    fn empty_marker_with_charged_ledger_or_pending_saturates() -> io::Result<()> {
        for (charged_bytes, charged_artifacts, include_pending) in [(25, 1, false), (0, 0, true)] {
            let (_owner, state) = private_state()?;
            drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
            fs::write(
                state.join(LEDGER_NAME),
                independent_record(100, 4, charged_bytes, charged_artifacts),
            )?;
            if include_pending {
                write_pending(&state, &independent_record(100, 4, 70, 2))?;
            }
            fs::write(state.join(LOCK_NAME), b"")?;

            let recovery = WriteQuota::recover_private_ledger(&state, 100, 4)?;
            assert_eq!(
                (recovery.charged_bytes, recovery.charged_artifacts),
                (100, 4)
            );
            assert!(recovery.unknown_usage_saturated_limits);
            assert!(fs::read(state.join(LOCK_NAME))?.is_empty());
            assert!(!state.join(LEDGER_TEMP_NAME).exists());
        }
        Ok(())
    }

    #[test]
    fn missing_stable_lock_is_never_recreated_by_maintenance() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        fs::remove_file(state.join(LOCK_NAME))?;
        let entry_count = fs::read_dir(&state)?.count();
        assert_eq!(
            WriteQuota::inspect_private_ledger(&state)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::NotFound)
        );
        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::NotFound)
        );
        assert!(!state.join(LOCK_NAME).exists());
        assert_eq!(fs::read_dir(&state)?.count(), entry_count);
        Ok(())
    }

    #[test]
    fn inspection_exports_damaged_marker_but_recovery_refuses_to_change_it() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        fs::write(state.join(LOCK_NAME), b"bad-marker")?;
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        let marker = fs::read(state.join(LOCK_NAME))?;
        let snapshot = WriteQuota::inspect_private_ledger(&state)?;
        assert!(!snapshot.lock_marker_valid);
        assert_eq!(snapshot.lock_marker, marker);
        assert_eq!(snapshot.lock_marker_sha256, sha256(&marker));
        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        assert_eq!(fs::read(state.join(LOCK_NAME))?, marker);
        Ok(())
    }

    #[test]
    fn hard_linked_metadata_is_rejected_by_inspection_without_mutation() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        fs::hard_link(state.join(LEDGER_NAME), state.join("linked-ledger"))?;
        assert_eq!(
            WriteQuota::inspect_private_ledger(&state)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        Ok(())
    }

    #[test]
    fn configured_limit_mismatch_is_not_rewritten() -> io::Result<()> {
        let (_owner, state) = private_state()?;
        drop(WriteQuota::open_private_ledger(&state, 100, 4)?);
        write_pending(&state, &independent_record(200, 4, 70, 2))?;
        let ledger = fs::read(state.join(LEDGER_NAME))?;
        let pending = fs::read(state.join(LEDGER_TEMP_NAME))?;
        assert_eq!(
            WriteQuota::recover_private_ledger(&state, 100, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(fs::read(state.join(LEDGER_NAME))?, ledger);
        assert_eq!(fs::read(state.join(LEDGER_TEMP_NAME))?, pending);
        Ok(())
    }
}
