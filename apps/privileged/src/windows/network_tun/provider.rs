use super::super::{local_port_gate::store, security};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Retains the existing protected ancestor and no-write/no-delete file handles
/// for the whole provider lifetime. No DLL is loaded by this constructor.
pub struct PinnedProviderImage {
    path: PathBuf,
    sha256: [u8; 32],
    _lock: store::ImageLock,
}
impl PinnedProviderImage {
    pub fn open(path: &Path, expected: [u8; 32]) -> io::Result<Self> {
        if expected == [0; 32]
            || !path.is_absolute()
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("wintun.dll"))
        {
            return Err(security::denied());
        }
        let lock = store::lock_image(path)?;
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        if length == 0 || length > 16 * 1024 * 1024 {
            return Err(security::denied());
        }
        let mut digest = Sha256::new();
        let mut read = 0_u64;
        let mut bytes = [0_u8; 65_536];
        loop {
            let count = file.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(count as u64)
                .ok_or_else(security::denied)?;
            if read > length {
                return Err(security::denied());
            }
            digest.update(&bytes[..count]);
        }
        if read != length || <[u8; 32]>::from(digest.finalize()) != expected {
            return Err(security::denied());
        }
        Ok(Self {
            path: path.to_path_buf(),
            sha256: expected,
            _lock: lock,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}
