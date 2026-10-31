#![allow(clippy::unwrap_used)]
use nestlink_app_core::*;
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Default)]
struct Store {
    value: Mutex<NativeNetworkSettings>,
    fail_load: AtomicBool,
    fail_save: AtomicBool,
    uncertain_save: AtomicBool,
    saves: AtomicUsize,
}
impl NativeNetworkSettingsStore for Store {
    fn load(&self) -> std::result::Result<NativeNetworkSettings, NativeNetworkError> {
        if self.fail_load.load(Ordering::Acquire) {
            return Err(NativeNetworkError::Persistence);
        }
        Ok(self
            .value
            .lock()
            .map_err(|_| NativeNetworkError::Persistence)?
            .clone())
    }
    fn save(
        &self,
        settings: &NativeNetworkSettings,
    ) -> std::result::Result<NativeNetworkCommit, NativeNetworkError> {
        self.saves.fetch_add(1, Ordering::AcqRel);
        if self.fail_save.load(Ordering::Acquire) {
            return Err(NativeNetworkError::Persistence);
        }
        *self
            .value
            .lock()
            .map_err(|_| NativeNetworkError::Persistence)? = settings.clone();
        Ok(if self.uncertain_save.load(Ordering::Acquire) {
            NativeNetworkCommit::Visible
        } else {
            NativeNetworkCommit::Durable
        })
    }
}

fn settings() -> NativeNetworkSettings {
    NativeNetworkSettings {
        route_set: None,
        media_route: Default::default(),
        media_interface_index: None,
        use_deployment_stun: false,
        pcp_gateway: None,
        private_network_prefixes: vec!["192.168.12.0/24".into(), "fd12:3456::/32".into()],
    }
}

#[tokio::test]
async fn validated_idle_changes_persist_before_publication_and_advance_candidates() -> Result {
    let network = Arc::new(NetworkMonitor::start()?);
    let store = Arc::new(Store::default());
    let mut core = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        NativeSessionConfig::new(network.clone()).with_network_settings_store(store.clone())?,
    )?;
    let handle = core.handle();
    assert_eq!(
        handle.snapshot().native_network,
        NativeNetworkSettings::default()
    );
    let generation = handle.snapshot().generation;
    let baseline = network.subscribe().borrow().generation;
    assert_eq!(
        handle
            .configure_native_network(generation, 0, settings())
            .await?,
        settings()
    );
    assert_eq!(handle.snapshot().native_network, settings());
    assert_eq!(store.load()?, settings());
    assert_eq!(store.saves.load(Ordering::Acquire), 1);
    assert_eq!(handle.snapshot().native_network_revision, 1);
    assert_eq!(handle.snapshot().native_network_durable, Some(true));
    assert!(network.subscribe().borrow().generation > baseline);
    assert!(network.subscribe().borrow().available);

    let after = network.subscribe().borrow().generation;
    let invalid = NativeNetworkSettings {
        private_network_prefixes: vec!["0.0.0.0/0".into()],
        ..settings()
    };
    assert_eq!(
        handle
            .configure_native_network(generation, 1, invalid)
            .await,
        Err(NativeNetworkError::Invalid)
    );
    store.fail_save.store(true, Ordering::Release);
    assert_eq!(
        handle
            .configure_native_network(generation, 1, NativeNetworkSettings::default())
            .await,
        Err(NativeNetworkError::Persistence)
    );
    assert_eq!(handle.snapshot().native_network, settings());
    assert!(network.subscribe().borrow().generation > after);
    assert_eq!(store.load()?, settings());
    assert_eq!(
        core.shutdown(Duration::from_secs(3)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        handle
            .configure_native_network(handle.snapshot().generation, 1, settings())
            .await,
        Err(NativeNetworkError::Stopped)
    );
    Ok(())
}

#[tokio::test]
async fn store_installation_and_stale_actions_cannot_partially_replace_effective_settings() -> Result
{
    let network = Arc::new(NetworkMonitor::start()?);
    let mut core = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        NativeSessionConfig::new(network.clone()),
    )?;
    let handle = core.handle();
    let generation = handle.snapshot().generation;
    assert_eq!(
        handle
            .configure_native_network(generation, 0, settings())
            .await,
        Err(NativeNetworkError::Persistence)
    );
    let store = Arc::new(Store::default());
    *store.value.lock().unwrap() = settings();
    let baseline = network.subscribe().borrow().generation;
    assert_eq!(
        handle
            .install_native_network_settings_store(generation + 1, 0, store.clone())
            .await,
        Err(NativeNetworkError::StaleGeneration)
    );
    assert_eq!(network.subscribe().borrow().generation, baseline);
    store.fail_load.store(true, Ordering::Release);
    assert_eq!(
        handle
            .install_native_network_settings_store(generation, 0, store.clone())
            .await,
        Err(NativeNetworkError::Persistence)
    );
    assert_eq!(
        handle.snapshot().native_network,
        NativeNetworkSettings::default()
    );
    assert_eq!(network.subscribe().borrow().generation, baseline);
    store.fail_load.store(false, Ordering::Release);
    assert_eq!(
        handle
            .install_native_network_settings_store(generation, 0, store)
            .await?,
        settings()
    );
    assert_eq!(handle.snapshot().native_network, settings());
    assert!(network.subscribe().borrow().generation > baseline);
    let previous = handle.snapshot().native_network.clone();
    let old_generation = handle.snapshot().generation;
    // Logout replaces the account/UI fence but local network consent remains.
    let logout = handle.logout()?;
    let completion = tokio::time::timeout(Duration::from_secs(3), logout.wait()).await??;
    assert_eq!(completion.result.status, OperationStatus::Succeeded);
    assert_ne!(handle.snapshot().generation, old_generation);
    assert_eq!(handle.snapshot().native_network, previous);
    assert_eq!(
        handle
            .configure_native_network(old_generation, 1, NativeNetworkSettings::default())
            .await,
        Err(NativeNetworkError::StaleGeneration)
    );
    assert_eq!(
        core.shutdown(Duration::from_secs(3)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn stale_parallel_and_aba_consent_cannot_restore_revoked_private_networks() -> Result {
    let network = Arc::new(NetworkMonitor::start()?);
    let store = Arc::new(Store::default());
    let mut core = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        NativeSessionConfig::new(network.clone()).with_network_settings_store(store.clone())?,
    )?;
    let handle = core.handle();
    let initial = handle.snapshot();
    // Two local views approved against the same base. Only one can commit.
    let (first, second) = tokio::join!(
        handle.configure_native_network(
            initial.generation,
            initial.native_network_revision,
            settings()
        ),
        handle.configure_native_network(
            initial.generation,
            initial.native_network_revision,
            settings()
        ),
    );
    assert!(matches!(
        (first, second),
        (Ok(_), Err(NativeNetworkError::StaleGeneration))
            | (Err(NativeNetworkError::StaleGeneration), Ok(_))
    ));
    assert_eq!(store.saves.load(Ordering::Acquire), 1);
    assert_eq!(handle.snapshot().native_network_revision, 1);
    handle
        .configure_native_network(initial.generation, 1, NativeNetworkSettings::default())
        .await?;
    assert_eq!(handle.snapshot().native_network, initial.native_network);
    let baseline = network.subscribe().borrow().generation;
    // Same values as before do not make an old approval current again.
    assert_eq!(
        handle
            .configure_native_network(initial.generation, 0, settings())
            .await,
        Err(NativeNetworkError::StaleGeneration)
    );
    let replacement_store = Arc::new(Store::default());
    assert_eq!(
        handle
            .install_native_network_settings_store(initial.generation, 0, replacement_store)
            .await,
        Err(NativeNetworkError::StaleGeneration)
    );
    assert_eq!(network.subscribe().borrow().generation, baseline);
    assert_eq!(store.saves.load(Ordering::Acquire), 2);
    assert_eq!(store.load()?, NativeNetworkSettings::default());
    assert_eq!(
        core.shutdown(Duration::from_secs(3)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn visible_commit_is_published_with_durability_warning_and_can_be_saved_again() -> Result {
    let store = Arc::new(Store::default());
    store.uncertain_save.store(true, Ordering::Release);
    let mut core = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?))
            .with_network_settings_store(store.clone())?,
    )?;
    let handle = core.handle();
    let generation = handle.snapshot().generation;
    handle
        .configure_native_network(generation, 0, settings())
        .await?;
    assert_eq!(handle.snapshot().native_network, store.load()?);
    assert_eq!(handle.snapshot().native_network_durable, Some(false));
    assert_eq!(handle.snapshot().native_network_revision, 1);
    store.uncertain_save.store(false, Ordering::Release);
    handle
        .configure_native_network(generation, 1, settings())
        .await?;
    assert_eq!(handle.snapshot().native_network_durable, Some(true));
    assert_eq!(handle.snapshot().native_network_revision, 2);
    assert_eq!(
        core.shutdown(Duration::from_secs(3)).await,
        ShutdownState::Complete
    );
    Ok(())
}
