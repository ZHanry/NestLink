//! Local consent and handle-relative, no-follow reads; locally chosen private
//! download storage. No ambient remote path or directory listing authority.
pub mod browse;
pub mod download;
pub mod selection;
pub mod upload;
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use nestlink_protocol::{
    FILE_PAYLOAD_BYTES, FILE_READ_ROOTS, FILE_SIZE_BYTES, FileReadManifest,
    files::validate_relative_path, valid_id,
};
use nestlink_remote::files::{FileReadConsent, FileReadDevice, FileReadSource};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
/// Keeping this local owner alive preserves its explicit approval. Dropping or
/// revoking it invalidates every open source, independently of session consent.
pub struct ReadRootConsent(Arc<AtomicBool>);
impl ReadRootConsent {
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for ReadRootConsent {
    fn drop(&mut self) {
        self.revoke();
    }
}

pub struct ApprovedReadRoot {
    id: String,
    directory: Dir,
    device: u64,
    maximum: u64,
    consent: Arc<AtomicBool>,
}
impl ApprovedReadRoot {
    /// Call only for a directory explicitly selected in the local product UI or
    /// operator configuration. The returned ID has no independent authority.
    pub fn open(
        id: &str,
        local_path: &Path,
        maximum_file_bytes: u64,
    ) -> io::Result<(Self, ReadRootConsent)> {
        if !valid_id(id) || maximum_file_bytes > FILE_SIZE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file root identity or maximum",
            ));
        }
        let directory = Dir::open_ambient_dir(local_path, cap_std::ambient_authority())?;
        let device = directory.dir_metadata()?.dev();
        let consent = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                id: id.into(),
                directory,
                device,
                maximum: maximum_file_bytes,
                consent: consent.clone(),
            },
            ReadRootConsent(consent),
        ))
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
pub struct FileRoots(BTreeMap<String, ApprovedReadRoot>);
impl FileRoots {
    pub fn new(roots: Vec<ApprovedReadRoot>) -> io::Result<Self> {
        if roots.len() as u64 > FILE_READ_ROOTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many file roots",
            ));
        }
        let mut map = BTreeMap::new();
        for root in roots {
            if map.insert(root.id.clone(), root).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate file root identity",
                ));
            }
        }
        Ok(Self(map))
    }
}
impl FileReadDevice for FileRoots {
    fn retire_revoked(&mut self) {
        self.0
            .retain(|_, root| root.consent.load(Ordering::Acquire));
    }
    fn open(&mut self, id: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        validate_relative_path(relative_path)
            .map_err(|_| denied("invalid portable relative file path"))?;
        let root = self
            .0
            .get(id)
            .ok_or_else(|| denied("file root not approved"))?;
        if !root.consent.load(Ordering::Acquire) {
            return Err(denied("local file root consent revoked"));
        }
        let components: Vec<_> = relative_path.split('/').collect();
        let (name, parents) = components
            .split_last()
            .ok_or_else(|| denied("missing file name"))?;
        let mut parent = root.directory.try_clone()?;
        for component in parents {
            // One single validated component per no-follow operation. The next
            // lookup is relative to the returned handle, never an ambient path.
            parent = parent.open_dir_nofollow(component)?;
            if parent.dir_metadata()?.dev() != root.device {
                return Err(denied("file root cannot traverse a different filesystem"));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            // A FIFO/special file must never block before its type is checked.
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            // FILE_SHARE_READ only: pin against write/rename/delete sharing.
            options.share_mode(1);
        }
        let file = parent.open_with(name, &options)?;
        let original = Stamp::read(&file, root.device, root.maximum)?;
        if !root.consent.load(Ordering::Acquire) {
            return Err(denied("local file root consent revoked"));
        }
        Ok(Box::new(Source {
            file,
            original,
            device: root.device,
            maximum: root.maximum,
            consent: root.consent.clone(),
        }))
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    size: u64,
    inode: u64,
    modified: SystemTime,
}
impl Stamp {
    fn read(file: &File, device: u64, maximum: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.dev() != device || metadata.nlink() != 1 {
            return Err(denied(
                "file handle must be a regular single-link file on the approved filesystem",
            ));
        }
        #[cfg(windows)]
        {
            use cap_fs_ext::OsMetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(denied("file handle must not be a reparse point"));
            }
        }
        if metadata.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "file exceeds the locally approved limit",
            ));
        }
        Ok(Self {
            size: metadata.len(),
            inode: metadata.ino(),
            modified: metadata.modified()?.into_std(),
        })
    }
}
struct Source {
    file: File,
    original: Stamp,
    device: u64,
    maximum: u64,
    consent: Arc<AtomicBool>,
}
impl Source {
    fn check(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        authorized()?;
        if !self.consent.load(Ordering::Acquire) {
            return Err(denied("local file root consent revoked"));
        }
        if Stamp::read(&self.file, self.device, self.maximum)? != self.original {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file changed after opening",
            ));
        }
        Ok(())
    }
    fn hash(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<[u8; 32]> {
        self.check(authorized)?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut buffer = vec![0; FILE_PAYLOAD_BYTES as usize];
        let mut hasher = Sha256::new();
        let mut remaining = self.original.size;
        while remaining > 0 {
            self.check(authorized)?;
            let count = remaining.min(FILE_PAYLOAD_BYTES) as usize;
            self.file.read_exact(&mut buffer[..count])?;
            self.check(authorized)?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
        self.check(authorized)?;
        Ok(hasher.finalize().into())
    }
}
impl FileReadSource for Source {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        Ok(FileReadManifest {
            size: self.original.size,
            sha256: self.hash(authorized)?.to_vec(),
            offset: 0,
        })
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        if maximum == 0
            || maximum as u64 > FILE_PAYLOAD_BYTES
            || offset
                .checked_add(maximum as u64)
                .is_none_or(|end| end > self.original.size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded file read",
            ));
        }
        self.check(authorized)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; maximum];
        self.file.read_exact(&mut bytes)?;
        self.check(authorized)?;
        Ok(bytes)
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if original.size != self.original.size
            || self.hash(authorized)?.as_slice() != original.sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "complete source content changed",
            ));
        }
        Ok(())
    }
}
