use crate::{Error, IdentityPair, Result};
use nestlink_auth::random_bytes;
use nestlink_identity::InstallationIdentity;
use nestlink_platform_security::{
    check_private_directory, create_key, create_private, load_key, new_private_directory,
    read_private,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const ENDPOINT_FILE: &str = "daemon-endpoint.json";
const MASTER_FILE: &str = "local-ipc.key";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    pub version: u16,
    pub runtime_id: String,
    pub address: SocketAddr,
}
impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        if self.version != crate::VERSION
            || !crate::valid_runtime_id(&self.runtime_id)
            || self.address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || self.address.port() == 0
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
}

fn check_directory(path: &Path) -> io::Result<()> {
    check_private_directory(path)
}

/// Creates only the requested leaf under a caller-approved existing parent.
/// An existing path is checked, never silently chmodded or followed as a link.
pub fn initialize_directory(path: &Path) -> Result<()> {
    match new_private_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(check_directory(path)?),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn identities(path: &Path, create: bool) -> Result<IdentityPair> {
    check_directory(path)?;
    let file = path.join(MASTER_FILE);
    let seed = match load_key(&file) {
        Ok(seed) => seed,
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            let generated = Zeroizing::new(random_bytes::<32>());
            match create_key(&file, &generated) {
                Ok(()) => generated,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => load_key(&file)?,
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };
    let derive = |purpose: &[u8]| -> Result<InstallationIdentity> {
        let mut result = Zeroizing::new([0_u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"NestLink/v15/local-ipc/keys/v1\0"), seed.as_ref())
            .expand(purpose, result.as_mut())
            .map_err(|_| Error::Protocol)?;
        Ok(InstallationIdentity::from_seed_zeroizing(&mut result))
    };
    Ok(IdentityPair {
        server: derive(b"daemon")?,
        client: derive(b"desktop-ui")?,
    })
}

pub(crate) fn endpoint(path: &Path) -> Result<Endpoint> {
    check_directory(path)?;
    let bytes = read_private(&path.join(ENDPOINT_FILE), 1024)?;
    let endpoint: Endpoint = serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)?;
    endpoint.validate()?;
    Ok(endpoint)
}

pub(crate) struct StateLease {
    root: PathBuf,
    runtime_id: String,
    // An OS file lock owns singleton admission. The file is retained across
    // crashes; deletion or a stale endpoint is not the lock mechanism.
    _lock: File,
}
impl StateLease {
    pub fn acquire(root: &Path, runtime_id: &str) -> Result<Self> {
        initialize_directory(root)?;
        // Keep startup admission until the daemon singleton is actually held.
        let _startup = crate::maintenance::StartupPermit::acquire(root)?;
        let lock_path = root.join("daemon.lock");
        match create_private(&lock_path, &[]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Never read the existing lock's bytes: Windows rejects reads
                // while another owner holds the range lock, including an empty
                // file. Open without following links and inspect the actual
                // handle below, then let try_lock classify singleton admission.
            }
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000);
        }
        let lock = options.open(lock_path)?;
        let metadata = lock.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(Error::Protocol);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0
            {
                return Err(Error::Protocol);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::Protocol);
            }
        }
        lock.try_lock().map_err(|_| Error::AlreadyRunning)?;
        Ok(Self {
            root: root.to_owned(),
            runtime_id: runtime_id.to_owned(),
            _lock: lock,
        })
    }
    pub fn publish(&self, address: SocketAddr) -> Result<()> {
        let value = Endpoint {
            version: crate::VERSION,
            runtime_id: self.runtime_id.clone(),
            address,
        };
        value.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|_| Error::Protocol)?);
        let destination = self.root.join(ENDPOINT_FILE);
        // Only a valid old private endpoint may be replaced while we hold the
        // singleton lock. Arbitrary content, links and unowned files fail shut.
        if destination.try_exists()? {
            let _ = endpoint(&self.root)?;
            fs::remove_file(&destination)?;
        }
        create_private(&destination, &bytes)?;
        Ok(())
    }
}
impl Drop for StateLease {
    fn drop(&mut self) {
        if endpoint(&self.root).is_ok_and(|endpoint| endpoint.runtime_id == self.runtime_id) {
            // This is the owner's own small endpoint file, not a recursive
            // cleanup. Other state, user data and the key/lock are retained.
            let _ = fs::remove_file(self.root.join(ENDPOINT_FILE));
        }
    }
}
