use super::*;
use crate::{NativeNetworkError, NativeNetworkSettings, NativeNetworkSettingsStore};

fn network_submit_error(error: SubmitError) -> NativeNetworkError {
    match error {
        SubmitError::Stopped => NativeNetworkError::Stopped,
        SubmitError::StaleGeneration => NativeNetworkError::StaleGeneration,
        SubmitError::Capacity => NativeNetworkError::Busy,
        SubmitError::Invalid => NativeNetworkError::Invalid,
    }
}

impl CoreHandle {
    /// Save explicit local dialing consent while no native or browser session
    /// is establishing, connected, stopping, or waiting to recover.
    pub async fn configure_native_network(
        &self,
        expected_generation: u64,
        expected_revision: u64,
        settings: NativeNetworkSettings,
    ) -> Result<NativeNetworkSettings, NativeNetworkError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeNetworkError::Stopped);
        }
        settings.validate()?;
        if expected_generation != self.shared.generation.load(Ordering::Acquire)
            || expected_revision != self.snapshot().native_network_revision
        {
            return Err(NativeNetworkError::StaleGeneration);
        }
        let permit = self.capacity(true).map_err(network_submit_error)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::ConfigureNativeNetwork {
                expected_generation,
                expected_revision,
                settings,
                reply,
                _permit: permit,
            })
            .map_err(|error| network_submit_error(send_error(error)))?;
        receive.await.unwrap_or(Err(NativeNetworkError::Stopped))
    }

    /// Install a platform-owned settings store after a private application
    /// directory becomes available. Loaded policy has the same idle/fence
    /// checks as an explicit local settings change.
    pub async fn install_native_network_settings_store(
        &self,
        expected_generation: u64,
        expected_revision: u64,
        store: Arc<dyn NativeNetworkSettingsStore>,
    ) -> Result<NativeNetworkSettings, NativeNetworkError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeNetworkError::Stopped);
        }
        if expected_generation != self.shared.generation.load(Ordering::Acquire)
            || expected_revision != self.snapshot().native_network_revision
        {
            return Err(NativeNetworkError::StaleGeneration);
        }
        let permit = self.capacity(true).map_err(network_submit_error)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::InstallNativeNetworkSettingsStore {
                expected_generation,
                expected_revision,
                store,
                reply,
                _permit: permit,
            })
            .map_err(|error| network_submit_error(send_error(error)))?;
        receive.await.unwrap_or(Err(NativeNetworkError::Stopped))
    }
}

impl Actor {
    fn native_network_update_ready(
        &self,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<u64, NativeNetworkError> {
        if self.view.lifecycle != Lifecycle::Running || self.shared.closing.load(Ordering::Acquire)
        {
            return Err(NativeNetworkError::Stopped);
        }
        if self.view.generation != expected_generation
            || self.shared.generation.load(Ordering::Acquire) != expected_generation
            || self.view.native_network_revision != expected_revision
        {
            return Err(NativeNetworkError::StaleGeneration);
        }
        if !self.native_network_idle() {
            return Err(NativeNetworkError::Busy);
        }
        if self.native.is_none() {
            return Err(NativeNetworkError::Unavailable);
        }
        expected_revision
            .checked_add(1)
            .ok_or(NativeNetworkError::Unavailable)
    }

    fn publish_native_network_config(
        &mut self,
        config: NativeSessionConfig,
        revision: u64,
        durable: Option<bool>,
    ) -> NativeNetworkSettings {
        // Validation, invalidation and persistence have already succeeded.
        // Publication now has no fallible step that could split disk and view.
        let settings = config.network_settings();
        self.native = Some(config);
        self.view.native_network = settings.clone();
        self.view.native_network_revision = revision;
        self.view.native_network_durable = durable;
        self.publish();
        settings
    }

    pub(super) fn configure_native_network(
        &mut self,
        expected_generation: u64,
        expected_revision: u64,
        settings: NativeNetworkSettings,
    ) -> Result<NativeNetworkSettings, NativeNetworkError> {
        let revision = self.native_network_update_ready(expected_generation, expected_revision)?;
        settings.validate()?;
        let mut candidate = self.native.clone().ok_or(NativeNetworkError::Unavailable)?;
        // Invalidate before saving: if the monitor cannot advance, disk must
        // retain the old policy too. Save failure may only advance this idle
        // candidate generation, leaving the effective settings unchanged.
        candidate
            .network()
            .invalidate_generation()
            .map_err(|_| NativeNetworkError::Unavailable)?;
        let commit = candidate.set_network_settings(settings)?;
        Ok(self.publish_native_network_config(
            candidate,
            revision,
            Some(commit == crate::NativeNetworkCommit::Durable),
        ))
    }

    pub(super) fn install_native_network_settings_store(
        &mut self,
        expected_generation: u64,
        expected_revision: u64,
        store: Arc<dyn NativeNetworkSettingsStore>,
    ) -> Result<NativeNetworkSettings, NativeNetworkError> {
        let revision = self.native_network_update_ready(expected_generation, expected_revision)?;
        let candidate = self
            .native
            .clone()
            .ok_or(NativeNetworkError::Unavailable)?
            .with_network_settings_store(store)?;
        candidate
            .network()
            .invalidate_generation()
            .map_err(|_| NativeNetworkError::Unavailable)?;
        Ok(self.publish_native_network_config(candidate, revision, None))
    }
}
