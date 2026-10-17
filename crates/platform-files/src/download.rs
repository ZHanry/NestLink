//! Blocking local download storage. Own this on a file worker, never the async
//! executor or authorization mutex. Paths are selected by the local application.
pub mod recovery;

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use nestlink_protocol::{FILE_PAYLOAD_BYTES, FILE_SIZE_BYTES, FileReadChunk, FileReadManifest};
pub use nestlink_remote::files::FileDestinationStatus as LocalDownloadStatus;
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDownloadBinding, FileDownloadSnapshot,
    FileDownloadView, FileReadConsent, FileReadVerifier,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn check(consent: &AtomicBool, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
    authorized()?;
    if !consent.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local download consent revoked",
        ));
    }
    Ok(())
}
pub struct LocalDownloadConsent(Arc<AtomicBool>);
impl LocalDownloadConsent {
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for LocalDownloadConsent {
    fn drop(&mut self) {
        self.revoke();
    }
}
/// One fresh, private local area and one no-clobber final name. The caller must
/// choose a trusted parent for the area; no directory or name comes from a peer.
/// Dropping only closes the handle. It never hides a failed temporary cleanup.
pub struct LocalDownload {
    local_fresh_area: PathBuf,
    directory: Option<Dir>,
    file: Option<File>,
    temporary_created: bool,
    temporary: String,
    name: String,
    device: u64,
    inode: u64,
    manifest: FileReadManifest,
    binding: FileDownloadBinding,
    verifier: Option<FileReadVerifier>,
    prefix: Sha256,
    consent: Arc<AtomicBool>,
    status: LocalDownloadStatus,
}
impl LocalDownload {
    pub fn create(
        local_fresh_area: &Path,
        local_name: &str,
        local_maximum: u64,
        download: &impl FileDownloadView,
    ) -> io::Result<(Self, LocalDownloadConsent)> {
        let consent = Arc::new(AtomicBool::new(true));
        let mut disk = Self::selected(
            local_fresh_area,
            local_name,
            local_maximum,
            download,
            consent.clone(),
        )?;
        if let Err(error) = disk.prepare(&mut || Ok(())) {
            let _ = disk.cancel();
            return Err(error);
        }
        Ok((disk, LocalDownloadConsent(consent)))
    }
    fn selected(
        local_fresh_area: &Path,
        local_name: &str,
        local_maximum: u64,
        download: &impl FileDownloadView,
        consent: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        nestlink_protocol::files::validate_relative_path(local_name)
            .map_err(|_| invalid("invalid local download name"))?;
        if local_name.contains('/')
            || local_maximum > FILE_SIZE_BYTES
            || download.manifest().size > local_maximum
            || download.manifest().offset != 0
            || download.offset() != 0
            || download.finished()
        {
            return Err(invalid("invalid initial download or local size limit"));
        }
        let verifier = FileReadVerifier::new(download.manifest().clone())?;
        let mut random = [0; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| io::Error::other("download name entropy failed"))?;
        let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = format!(".nestlink-{nonce}.part");
        Ok(Self {
            local_fresh_area: local_fresh_area.into(),
            directory: None,
            file: None,
            temporary_created: false,
            temporary,
            name: local_name.into(),
            device: 0,
            inode: 0,
            manifest: download.manifest().clone(),
            binding: download.binding(),
            verifier: Some(verifier),
            prefix: Sha256::new(),
            consent,
            status: LocalDownloadStatus {
                file_closed: true,
                ..LocalDownloadStatus::default()
            },
        })
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        if self.directory.is_some() || self.status.poisoned || self.status.temporary_removed {
            return Err(invalid("download storage was already prepared or retired"));
        }
        // Fresh 0700 / protected Windows owner+SYSTEM DACL. Its parent is an
        // explicitly trusted local application area, not an ambient peer path.
        nestlink_platform_security::new_private_directory(&self.local_fresh_area)?;
        check(&self.consent, authorized)?;
        self.directory = Some(Dir::open_ambient_dir(
            &self.local_fresh_area,
            cap_std::ambient_authority(),
        )?);
        check(&self.consent, authorized)?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| invalid("download area closed"))?;
        self.device = directory.dir_metadata()?.dev();
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
            // A peer cannot modify, rename or delete the staged object while
            // its original read/write handle is retained.
            options.share_mode(1);
        }
        self.file = Some(directory.open_with(&self.temporary, &options)?);
        self.temporary_created = true;
        self.status.file_closed = false;
        check(&self.consent, authorized)?;
        let metadata = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("download file closed"))?
            .metadata()?;
        check(&self.consent, authorized)?;
        if !metadata.is_file() || metadata.dev() != self.device || metadata.nlink() != 1 {
            return Err(invalid(
                "download must be a private regular file on the chosen filesystem",
            ));
        }
        self.inode = metadata.ino();
        check(&self.consent, authorized)
    }
    pub fn status(&self) -> LocalDownloadStatus {
        self.status
    }
    fn active(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        if self.status.published || self.status.poisoned || self.file.is_none() {
            return Err(invalid("download storage is no longer active"));
        }
        Ok(())
    }
    fn object(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        check(&self.consent, authorized)?;
        let metadata = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("download file closed"))?
            .metadata()?;
        check(&self.consent, authorized)?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.nlink() != 1
            || metadata.len() != self.status.confirmed_bytes
        {
            return Err(invalid("staged download object changed"));
        }
        Ok(())
    }
    pub fn write_chunk(
        &mut self,
        download: &impl FileDownloadView,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.active(authorized)?;
        self.object(authorized)?;
        if !self.binding.matches(download)
            || chunk.offset != self.status.confirmed_bytes
            || download.offset() != chunk.offset.saturating_add(chunk.data.len() as u64)
            || download.finished()
        {
            return Err(invalid(
                "chunk does not belong to this exact active download",
            ));
        }
        // Stage the verifier locally. A revoked check before the first write
        // must not advance its offset while the actual file remains unchanged.
        let mut verifier = self
            .verifier
            .as_ref()
            .ok_or_else(|| invalid("download verifier ended"))?
            .clone();
        verifier.accept(chunk)?;
        let mut written = 0;
        let mut disk_failed = false;
        let result = (|| {
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| invalid("download file closed"))?;
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
                        "download disk write made no progress",
                    ));
                }
                written += count;
                // Short writes must recheck before issuing another OS call. A
                // complete chunk commits its actual prefix before the last check.
                if written < chunk.data.len() {
                    check(&self.consent, authorized)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            if disk_failed || written != 0 {
                self.status.poisoned = true;
            }
            return Err(error);
        }
        self.verifier = Some(verifier);
        self.prefix.update(&chunk.data);
        self.status.confirmed_bytes += chunk.data.len() as u64;
        check(&self.consent, authorized)
    }
    /// Explicitly rebind to a newly proven transfer at the actual confirmed
    /// local prefix. Every prefix byte is read from the original handle.
    pub fn resume(
        &mut self,
        download: &impl FileDownloadView,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.active(authorized)?;
        self.object(authorized)?;
        let manifest = download.manifest();
        if manifest.size != self.manifest.size
            || manifest.sha256 != self.manifest.sha256
            || manifest.offset != self.status.confirmed_bytes
            || download.offset() != manifest.offset
            || download.finished()
        {
            return Err(invalid(
                "resumed source differs from the original object or local prefix",
            ));
        }
        let mut verifier = FileReadVerifier::new(manifest.clone())?;
        let hash = self.hash_actual(Some(&mut verifier), authorized)?;
        if hash != self.prefix.clone().finalize().as_slice() {
            self.status.poisoned = true;
            return Err(invalid("actual local resume prefix changed"));
        }
        self.binding = download.binding();
        self.verifier = Some(verifier);
        Ok(())
    }
    fn hash_actual(
        &mut self,
        mut verifier: Option<&mut FileReadVerifier>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<[u8; 32]> {
        self.object(authorized)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("download file closed"))?;
        check(&self.consent, authorized)?;
        file.seek(SeekFrom::Start(0))?;
        check(&self.consent, authorized)?;
        let mut buffer = vec![0; FILE_PAYLOAD_BYTES as usize];
        let mut remaining = self.status.confirmed_bytes;
        let mut hash = Sha256::new();
        while remaining > 0 {
            check(&self.consent, authorized)?;
            let count = remaining.min(FILE_PAYLOAD_BYTES) as usize;
            let mut read = 0;
            while read < count {
                check(&self.consent, authorized)?;
                let obtained = file.read(&mut buffer[read..count])?;
                check(&self.consent, authorized)?;
                if obtained == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "download disk prefix ended early",
                    ));
                }
                read += obtained;
            }
            hash.update(&buffer[..count]);
            if let Some(verifier) = verifier.as_mut() {
                verifier.seed_prefix(&buffer[..count])?;
            }
            remaining -= count as u64;
        }
        self.object(authorized)?;
        check(&self.consent, authorized)?;
        Ok(hash.finalize().into())
    }
    /// Publish one complete verified object by an atomic, same-filesystem,
    /// no-clobber hard link. Existing files, links and directories are untouched.
    /// After any error, inspect status: an issued publication syscall may have
    /// completed before a later consent check or cleanup failure.
    pub fn finish(
        &mut self,
        download: &impl FileDownloadView,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<LocalDownloadStatus> {
        self.active(authorized)?;
        if !self.binding.matches(download)
            || !download.source_verified()
            || self.status.confirmed_bytes != self.manifest.size
            || download.offset() != self.manifest.size
        {
            return Err(invalid(
                "download has no exact complete verified source end",
            ));
        }
        let hash = self.hash_actual(None, authorized)?;
        if hash.as_slice() != self.manifest.sha256 {
            self.status.poisoned = true;
            return Err(invalid("actual complete local file checksum differs"));
        }
        self.verifier
            .as_ref()
            .ok_or_else(|| invalid("download verifier ended"))?
            .clone()
            .finish()?;
        check(&self.consent, authorized)?;
        self.file
            .as_ref()
            .ok_or_else(|| invalid("download file closed"))?
            .sync_all()?;
        check(&self.consent, authorized)?;
        self.object(authorized)?;
        check(&self.consent, authorized)?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| invalid("download area closed"))?;
        directory.hard_link(&self.temporary, directory, &self.name)?;
        self.status.published = true;
        // It is a verified local object once the OS call succeeds. Revocation
        // cannot erase already-published bytes; do not misreport that fact.
        check(&self.consent, authorized)?;
        self.file.take();
        self.status.file_closed = true;
        directory.remove_file(&self.temporary)?;
        self.status.temporary_removed = true;
        #[cfg(unix)]
        {
            // cap-std's directory capability can be O_PATH, which cannot be
            // fsynced. Open the same directory for reading relative to that
            // capability; never reopen the original ambient pathname.
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            check(&self.consent, authorized)?;
            let sync_directory = directory.open_with(".", &options)?;
            check(&self.consent, authorized)?;
            sync_directory.sync_all()?;
            self.status.directory_synced = true;
            check(&self.consent, authorized)?;
        }
        // Windows directory FlushFileBuffers is not claimed here. File data
        // was synced before the atomic publication; power-loss durability still
        // requires the platform/product storage acceptance gate.
        Ok(self.status)
    }
    /// Cleanup is local owner authority, valid after business/root revocation.
    /// Never delete the final entry, including after a partial commit error.
    pub fn cancel(&mut self) -> io::Result<LocalDownloadStatus> {
        self.file.take();
        self.status.file_closed = true;
        self.status.poisoned = true;
        if !self.status.temporary_removed {
            if self.temporary_created {
                self.directory
                    .as_ref()
                    .ok_or_else(|| invalid("download area closed"))?
                    .remove_file(&self.temporary)?;
            }
            self.status.temporary_removed = true;
        }
        Ok(self.status)
    }
}

/// A local application's explicit selection. Construction performs no disk I/O;
/// retain the consent owner while the worker may save or keep a partial file.
pub struct LocalDownloadSelection {
    area: PathBuf,
    name: String,
    maximum: u64,
    consent: Arc<AtomicBool>,
}
impl LocalDownloadSelection {
    pub fn new(area: &Path, name: &str, maximum: u64) -> io::Result<(Self, LocalDownloadConsent)> {
        nestlink_protocol::files::validate_relative_path(name)
            .map_err(|_| invalid("invalid local download name"))?;
        if name.contains('/') || maximum > FILE_SIZE_BYTES {
            return Err(invalid("invalid local name or size limit"));
        }
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                area: area.into(),
                name: name.into(),
                maximum,
                consent: consent.clone(),
            },
            LocalDownloadConsent(consent),
        ))
    }
}
impl FileDestinationFactory for LocalDownloadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(LocalDownload::selected(
            &self.area,
            &self.name,
            self.maximum,
            source,
            self.consent,
        )?))
    }
}
impl FileDestination for LocalDownload {
    fn status(&self) -> LocalDownloadStatus {
        self.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.prepare(authorized)
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.write_chunk(source, chunk, authorized)
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.resume(source, authorized)
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.finish(source, authorized).map(|_| ())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.cancel().map(|_| ())
    }
}
