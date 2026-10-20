use nestlink_sdk::{NetworkMonitor, native::AddressPolicy};
use std::{net::SocketAddr, sync::Arc};

use crate::{
    BrowserHostConfig, NativeNetworkCommit, NativeNetworkError, NativeNetworkSettings,
    NativeNetworkSettingsStore,
};

/// Trusted local network inputs for app-core-owned native sessions.
/// STUN targets come from local operator configuration and the authenticated
/// deployment. Private networks always require explicit local consent.
#[derive(Clone)]
pub struct NativeSessionConfig {
    /// Continue already approved native offers while the desktop is in the tray.
    /// The authenticated permit remains the sole authority for starting media.
    pub listen_for_native_requests: bool,
    pub bind_address: SocketAddr,
    pub stun_servers: Vec<SocketAddr>,
    pub use_deployment_stun: bool,
    pub media_route: crate::MediaRouteMode,
    pub media_interface_index: Option<u32>,
    pub private_network_prefixes: Vec<String>,
    pub supported_capabilities: Vec<String>,
    pub browser_host: Option<BrowserHostConfig>,
    pub management_login_store: Option<Arc<dyn ManagementLoginStore>>,
    network: Arc<NetworkMonitor>,
    pub(crate) network_settings_store: Option<Arc<dyn NativeNetworkSettingsStore>>,
}

impl NativeSessionConfig {
    /// Resolve once before the initial native connection. Recovery retains this
    /// exact configuration and cannot fetch a wider scope for the old budget.
    pub(crate) async fn resolve_deployment_stun(
        mut self,
        sdk: &nestlink_sdk::Sdk,
    ) -> Result<Self, nestlink_sdk::SdkError> {
        if !self.use_deployment_stun {
            return Ok(self);
        }
        match sdk.native_discovery_config().await {
            Ok(config) => {
                for address in config.stun_servers {
                    if !self.stun_servers.contains(&address) && self.stun_servers.len() < 4 {
                        self.stun_servers.push(address);
                    }
                }
            }
            Err(error) if error.discovery_temporarily_unavailable() => {}
            Err(error) => return Err(error),
        }
        Ok(self)
    }

    pub fn new(network: Arc<NetworkMonitor>) -> Self {
        Self {
            listen_for_native_requests: false,
            bind_address: SocketAddr::from(([0, 0, 0, 0], 0)),
            stun_servers: Vec::new(),
            use_deployment_stun: true,
            media_route: crate::MediaRouteMode::System,
            media_interface_index: None,
            private_network_prefixes: Vec::new(),
            supported_capabilities: {
                let mut capabilities = vec!["vp8".into(), "opus".into()];
                if nestlink_media_codec::h264_hardware_available() {
                    capabilities.push(nestlink_protocol::media::H264_CAPABILITY.into());
                }
                capabilities
            },
            browser_host: None,
            management_login_store: None,
            network,
            network_settings_store: None,
        }
    }

    pub fn with_browser_host(mut self, config: BrowserHostConfig) -> Self {
        self.browser_host = Some(config);
        self
    }

    pub fn network_settings(&self) -> NativeNetworkSettings {
        NativeNetworkSettings {
            media_route: self.media_route,
            media_interface_index: self.media_interface_index,
            use_deployment_stun: self.use_deployment_stun,
            private_network_prefixes: self.private_network_prefixes.clone(),
        }
    }

    pub fn with_network_settings_store(
        mut self,
        store: Arc<dyn NativeNetworkSettingsStore>,
    ) -> Result<Self, NativeNetworkError> {
        let settings = store.load()?;
        settings.validate()?;
        settings.apply_route_policy()?;
        self.media_route = settings.media_route;
        self.media_interface_index = settings.media_interface_index;
        self.use_deployment_stun = settings.use_deployment_stun;
        self.private_network_prefixes = settings.private_network_prefixes;
        self.network_settings_store = Some(store);
        Ok(self)
    }

    pub(crate) fn set_network_settings(
        &mut self,
        settings: NativeNetworkSettings,
    ) -> Result<NativeNetworkCommit, NativeNetworkError> {
        settings.validate()?;
        let store = self
            .network_settings_store
            .as_ref()
            .ok_or(NativeNetworkError::Persistence)?;
        let commit = store.save(&settings)?;
        settings.apply_route_policy()?;
        self.media_route = settings.media_route;
        self.media_interface_index = settings.media_interface_index;
        self.use_deployment_stun = settings.use_deployment_stun;
        self.private_network_prefixes = settings.private_network_prefixes;
        Ok(commit)
    }

    pub(crate) fn validate(&self) -> bool {
        self.stun_servers.len() <= 4
            && self.private_network_prefixes.len() <= 32
            && self.supported_capabilities.len() <= 32
            && self
                .supported_capabilities
                .iter()
                .all(|capability| !capability.is_empty() && capability.len() <= 128)
            && AddressPolicy::new(&self.private_network_prefixes).is_ok()
    }

    pub(crate) fn address_policy(&self) -> Result<AddressPolicy, nestlink_sdk::native::DialError> {
        AddressPolicy::new(&self.private_network_prefixes)
    }

    pub(crate) fn network(&self) -> &NetworkMonitor {
        &self.network
    }
}

/// The implementation must encrypt credentials with an OS-protected key.
/// It is owned by the user daemon and never exposed through Snapshot or IPC.
pub trait ManagementLoginStore: Send + Sync {
    fn enabled(&self) -> bool;
    fn save(&self, bytes: &[u8]) -> std::io::Result<()>;
    fn clear(&self) -> std::io::Result<()>;
}
