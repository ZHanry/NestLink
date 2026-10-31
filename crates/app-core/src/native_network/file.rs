//! One bounded metadata record under an OS-protected local directory.
use super::{
    NativeNetworkCommit, NativeNetworkError, NativeNetworkSettings, NativeNetworkSettingsStore,
};
use nestlink_platform_security::{
    check_private_directory, create_private, read_private, replace_private_metadata,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

const SETTINGS_FILE: &str = "native-network.json";
const SETTINGS_BYTES: u64 = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSettings {
    schema_version: u16,
    settings: NativeNetworkSettings,
}

pub struct NativeNetworkFileStore {
    path: PathBuf,
    // Stable admission survives atomic replacement of the metadata file.
    _lock: File,
}

impl NativeNetworkFileStore {
    /// The caller creates/approves this local directory. No arbitrary filename,
    /// URL, peer data or management-provided path is accepted by the store.
    pub fn open(directory: &Path) -> Result<Self, NativeNetworkError> {
        Self::open_checked(directory).map_err(|_| NativeNetworkError::Persistence)
    }

    fn open_checked(directory: &Path) -> io::Result<Self> {
        if !directory.is_absolute() {
            return Err(io::Error::other(
                "local settings directory must be absolute",
            ));
        }
        check_private_directory(directory)?;
        let directory = directory.canonicalize()?;
        let lock_path = directory.join("native-network.lock");
        match create_private(&lock_path, &[]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        // Verify the exact regular, private file before opening the lock. The
        // protected parent and no-follow open prevent a peer-supplied link.
        if !read_private(&lock_path, 0)?.is_empty() {
            return Err(io::Error::other("local settings lock is invalid"));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW is 0x20000 on Linux/Android, the supported Unix hosts.
            options.custom_flags(0x20000);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000);
        }
        let lock = options.open(&lock_path)?;
        let metadata = lock.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(io::Error::other("local settings lock is invalid"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(io::Error::other(
                    "local settings lock cannot be a reparse point",
                ));
            }
        }
        lock.try_lock().map_err(io::Error::other)?;
        Ok(Self {
            path: directory.join(SETTINGS_FILE),
            _lock: lock,
        })
    }
}

impl NativeNetworkSettingsStore for NativeNetworkFileStore {
    fn load(&self) -> Result<NativeNetworkSettings, NativeNetworkError> {
        let bytes = match read_private(&self.path, SETTINGS_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeNetworkSettings::default());
            }
            Err(_) => return Err(NativeNetworkError::Persistence),
        };
        let saved: SavedSettings =
            serde_json::from_slice(&bytes).map_err(|_| NativeNetworkError::Invalid)?;
        if saved.schema_version != 1 {
            return Err(NativeNetworkError::Invalid);
        }
        saved.settings.validate()?;
        Ok(saved.settings)
    }

    fn save(
        &self,
        settings: &NativeNetworkSettings,
    ) -> Result<NativeNetworkCommit, NativeNetworkError> {
        settings.validate()?;
        let bytes = serde_json::to_vec(&SavedSettings {
            schema_version: 1,
            settings: settings.clone(),
        })
        .map_err(|_| NativeNetworkError::Persistence)?;
        if bytes.len() as u64 > SETTINGS_BYTES {
            return Err(NativeNetworkError::Invalid);
        }
        replace_private_metadata(&self.path, &bytes).map_err(|_| NativeNetworkError::Persistence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn private_store_is_exclusive_and_survives_restart_without_expanding_consent() -> TestResult {
        let directory =
            std::env::temp_dir().join(format!("nestlink-network-{}", nestlink_auth::random_id()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let store = NativeNetworkFileStore::open(&directory)?;
        assert_eq!(store.load()?, NativeNetworkSettings::default());
        assert!(NativeNetworkFileStore::open(&directory).is_err());
        let chosen = NativeNetworkSettings {
            space_path: None,
            route_set: None,
            media_route: Default::default(),
            media_interface_index: None,
            use_deployment_stun: false,
            pcp_gateway: Some("192.168.20.1".parse()?),
            private_network_prefixes: vec!["192.168.20.0/24".into()],
        };
        store.save(&chosen)?;
        let invalid = NativeNetworkSettings {
            private_network_prefixes: vec!["0.0.0.0/0".into()],
            ..chosen.clone()
        };
        assert_eq!(store.save(&invalid), Err(NativeNetworkError::Invalid));
        assert_eq!(store.load()?, chosen);
        drop(store);
        let reopened = NativeNetworkFileStore::open(&directory)?;
        assert_eq!(reopened.load()?, chosen);
        drop(reopened);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn malformed_persisted_policy_never_becomes_default_or_authority() -> TestResult {
        let directory =
            std::env::temp_dir().join(format!("nestlink-network-{}", nestlink_auth::random_id()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let store = NativeNetworkFileStore::open(&directory)?;
        replace_private_metadata(&directory.join(SETTINGS_FILE), b"{\"schema_version\":2}")?;
        assert_eq!(store.load(), Err(NativeNetworkError::Invalid));
        drop(store);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
