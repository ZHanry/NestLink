use super::AndroidManagementSession;
use nestlink_app_core::{NativeNetworkFileStore, NativeNetworkSettings};
use std::{io, path::Path, sync::Arc};

impl AndroidManagementSession {
    pub(crate) fn configure_native_network_area(&self, directory: &str) -> Result<String, String> {
        if directory.len() > 4096 {
            return Err("Local network settings directory is invalid".into());
        }
        let directory = Path::new(directory);
        if !directory.is_absolute() {
            return Err("Local network settings directory is invalid".into());
        }
        match nestlink_platform_security::new_private_directory(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                nestlink_platform_security::check_private_directory(directory)
                    .map_err(|_| "Local network settings directory is unavailable".to_owned())?;
            }
            Err(_) => return Err("Local network settings directory is unavailable".into()),
        }
        let store = Arc::new(NativeNetworkFileStore::open(directory).map_err(|e| e.to_string())?);
        let snapshot = self.handle.snapshot();
        self.runtime
            .block_on(self.handle.install_native_network_settings_store(
                snapshot.generation,
                snapshot.native_network_revision,
                store,
            ))
            .map_err(|e| e.to_string())?;
        self.native_network_settings_json()
    }

    pub(crate) fn native_network_settings_json(&self) -> Result<String, String> {
        let snapshot = self.handle.snapshot();
        serde_json::to_string(&serde_json::json!({
            "generation": snapshot.generation,
            "revision": snapshot.native_network_revision,
            "durable": snapshot.native_network_durable,
            "settings": snapshot.native_network,
        }))
        .map_err(|_| "Local network settings could not be encoded".into())
    }

    pub(crate) fn configure_native_network(
        &self,
        expected_generation: u64,
        expected_revision: u64,
        json: &str,
    ) -> Result<String, String> {
        if json.len() > 4096 {
            return Err("Local network settings exceed their size limit".into());
        }
        let settings: NativeNetworkSettings = serde_json::from_str(json)
            .map_err(|_| "Local network settings are invalid".to_owned())?;
        self.runtime
            .block_on(self.handle.configure_native_network(
                expected_generation,
                expected_revision,
                settings,
            ))
            .map_err(|e| e.to_string())?;
        self.native_network_settings_json()
    }
}
