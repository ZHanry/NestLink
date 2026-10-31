use super::super::{local_port_gate::store, security};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

// Official Wintun 0.14.1 DLLs inside the frozen archive
// 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51.
// A command-line digest is an explicit operator selection, not permission to
// load another provider. Updating these pins requires a reviewed new binary,
// license and hosted native qualification for the selected architecture.
fn frozen_architecture_pin(expected: &[u8; 32]) -> bool {
    let approved = match std::env::consts::ARCH {
        "x86_64" => "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        "x86" => "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
        "aarch64" => "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
        "arm" => "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
        _ => return false,
    };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut actual = [0_u8; 64];
    for (index, byte) in expected.iter().enumerate() {
        actual[index * 2] = HEX[usize::from(byte >> 4)];
        actual[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    actual.as_slice() == approved.as_bytes()
}

/// Retains the existing protected ancestor and no-write/no-delete file handles
/// for the whole provider lifetime. No DLL is loaded by this constructor.
pub struct PinnedProviderImage {
    path: PathBuf,
    sha256: [u8; 32],
    _lock: store::ImageLock,
}
impl PinnedProviderImage {
    pub fn open(path: &Path, expected: [u8; 32]) -> io::Result<Self> {
        if !frozen_architecture_pin(&expected)
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
