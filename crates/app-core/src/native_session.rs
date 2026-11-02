use nestlink_protocol::media_authority::{
    FORMAT_VERSION, FrozenMediaScope, HEVC_FORMAT_VERSION, MediaAnnouncement, MediaDirection,
};
use nestlink_sdk::{NetworkMonitor, native::AddressPolicy};
use std::{io, net::SocketAddr, sync::Arc};

use crate::{
    BrowserHostConfig, NativeNetworkCommit, NativeNetworkError, NativeNetworkSettings,
    NativeNetworkSettingsStore,
};

/// Trusted local network inputs for app-core-owned native sessions.
/// STUN targets come from local operator configuration and the authenticated
/// deployment. Private networks always require explicit local consent.
#[derive(Clone)]
pub struct NativeSessionConfig {
    pub(crate) space_path: Option<crate::NativeSpacePathSettings>,
    pub(crate) route_set: Option<crate::NativeRouteSetSettings>,
    /// Frozen for one local session and its recovery; never a forwarding grant.
    pub(crate) relay_node_id: Option<String>,
    /// Continue already approved native offers while the desktop is in the tray.
    /// The authenticated permit remains the sole authority for starting media.
    pub listen_for_native_requests: bool,
    pub bind_address: SocketAddr,
    pub stun_servers: Vec<SocketAddr>,
    pub use_deployment_stun: bool,
    pub pcp_gateway: Option<std::net::Ipv4Addr>,
    pub media_route: crate::MediaRouteMode,
    pub media_interface_index: Option<u32>,
    pub private_network_prefixes: Vec<String>,
    pub supported_capabilities: Vec<String>,
    pub browser_host: Option<BrowserHostConfig>,
    pub media_provider: Option<crate::NativeMediaProvider>,
    // Explicit local selection intent, never a probe or capture permission.
    gpu_hevc_main8_target: Option<nestlink_media_codec::VideoConfig>,
    gpu_hevc_version: u32,
    gpu_hevc_encoder: nestlink_media_codec::HevcEncoderBackend,
    pub internal_software_media_candidate: Option<
        nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate,
    >,
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
        if self.pcp_gateway.is_some() {
            let policy = sdk.native_pcp_policy().await?;
            if !policy.allowed {
                return Err(nestlink_sdk::SdkError::Api(
                    reqwest::StatusCode::FORBIDDEN,
                    nestlink_protocol::ErrorCode::PermissionRequired,
                ));
            }
        }
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
            space_path: None,
            route_set: None,
            relay_node_id: None,
            listen_for_native_requests: false,
            bind_address: SocketAddr::from(([0, 0, 0, 0], 0)),
            stun_servers: Vec::new(),
            use_deployment_stun: true,
            pcp_gateway: None,
            media_route: crate::MediaRouteMode::default(),
            media_interface_index: None,
            private_network_prefixes: Vec::new(),
            supported_capabilities: {
                let mut capabilities = vec![
                    "vp8".into(),
                    "opus".into(),
                    nestlink_protocol::native_ice::CAPABILITY.into(),
                    nestlink_protocol::native_qos::CAPABILITY.into(),
                ];
                if nestlink_media_codec::h264_hardware_available() {
                    capabilities.push(nestlink_protocol::media::H264_CAPABILITY.into());
                }
                capabilities
            },
            browser_host: None,
            media_provider: None,
            gpu_hevc_main8_target: None,
            gpu_hevc_version: 0,
            gpu_hevc_encoder: nestlink_media_codec::HevcEncoderBackend::SystemMf,
            internal_software_media_candidate: None,
            management_login_store: None,
            network,
            network_settings_store: None,
        }
    }

    /// An explicit product ceiling and at most two lower exact budgets; probes run on the
    /// provider's bounded background worker, never during UI configuration.
    pub fn with_cpu_media_target(
        mut self,
        target: nestlink_media_codec::VideoConfig,
    ) -> std::io::Result<Self> {
        if self.gpu_hevc_main8_target.is_some() {
            return Err(io::Error::other(
                "CPU and GPU media targets are mutually exclusive",
            ));
        }
        self.media_provider = Some(crate::NativeMediaProvider::cpu_software_adaptive(target)?);
        if !self
            .supported_capabilities
            .iter()
            .any(|s| s == nestlink_protocol::media::H264_CAPABILITY)
        {
            self.supported_capabilities
                .push(nestlink_protocol::media::H264_CAPABILITY.into());
        }
        if !self
            .supported_capabilities
            .iter()
            .any(|s| s == nestlink_protocol::media_authority::FORMAT_CAPABILITY)
        {
            self.supported_capabilities
                .push(nestlink_protocol::media_authority::FORMAT_CAPABILITY.into());
        }
        if let Some(policy) = self.internal_software_media_candidate.clone() {
            self = self.with_internal_software_media_candidate(policy)?;
        }
        Ok(self)
    }
    /// Explicit one-target Main8 hardware intent. The existing inbox publishes
    /// its independent Encode probe; a controller request publishes Decode.
    /// Neither configuration nor publication enables production issuance.
    pub fn with_gpu_hevc_main8_target(
        self,
        target: nestlink_media_codec::VideoConfig,
    ) -> io::Result<Self> {
        self.with_gpu_hevc_main8_encoder(target, nestlink_media_codec::HevcEncoderBackend::SystemMf)
    }
    pub fn with_gpu_hevc_main8_encoder(self, target: nestlink_media_codec::VideoConfig, encoder: nestlink_media_codec::HevcEncoderBackend) -> io::Result<Self> {
        self.with_gpu_hevc_target(target, HEVC_FORMAT_VERSION, encoder)
    }
    pub fn with_gpu_hevc_main10_target(
        self,
        target: nestlink_media_codec::VideoConfig,
    ) -> io::Result<Self> {
        self.with_gpu_hevc_main10_encoder(target, nestlink_media_codec::HevcEncoderBackend::SystemMf)
    }
    pub fn with_gpu_hevc_main10_encoder(self, target: nestlink_media_codec::VideoConfig, encoder: nestlink_media_codec::HevcEncoderBackend) -> io::Result<Self> {
        self.with_gpu_hevc_target(
            target,
            nestlink_protocol::media_authority::HEVC_MAIN10_FORMAT_VERSION,
            encoder,
        )
    }
    fn with_gpu_hevc_target(
        mut self,
        target: nestlink_media_codec::VideoConfig,
        version: u32,
        encoder: nestlink_media_codec::HevcEncoderBackend,
    ) -> io::Result<Self> {
        if self.media_provider.is_some() || self.internal_software_media_candidate.is_some() {
            return Err(io::Error::other(
                "GPU media cannot replace a configured CPU target or candidate",
            ));
        }
        self.media_provider = Some(if version == HEVC_FORMAT_VERSION {
            crate::NativeMediaProvider::gpu_hevc_main8_with_encoder(target, encoder)?
        } else {
            crate::NativeMediaProvider::gpu_hevc_main10_with_encoder(target, encoder)?
        });
        self.gpu_hevc_main8_target = Some(target);
        self.gpu_hevc_version = version;
        self.gpu_hevc_encoder = encoder;
        let capability = nestlink_protocol::media_authority::capability_for_version(version)
            .map_err(io::Error::other)?;
        if !self
            .supported_capabilities
            .iter()
            .any(|value| value == capability)
        {
            self.supported_capabilities.push(capability.into());
        }
        Ok(self)
    }
    /// Explicit operator configuration; never exposed by the ordinary remote UI.
    pub fn with_internal_software_media_candidate(
        mut self,
        policy: nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate,
    ) -> std::io::Result<Self> {
        if self.gpu_hevc_main8_target.is_some() {
            return Err(io::Error::other(
                "software candidate cannot authorize GPU media",
            ));
        }
        let format = policy.validate().map_err(std::io::Error::other)?;
        let target = self
            .media_provider
            .as_ref()
            .ok_or_else(|| std::io::Error::other("candidate requires an explicit CPU target"))?
            .target();
        if (target.width, target.height, target.fps, target.bitrate_kbps)
            != (
                format.width,
                format.height,
                format.frame_rate.numerator,
                format.max_kbps,
            )
        {
            return Err(std::io::Error::other(
                "candidate target differs from configured CPU target",
            ));
        }
        // An existing one-format candidate must not begin advertising the
        // convenience adaptive ladder. More formats require explicit policy.
        self.media_provider = Some(
            crate::NativeMediaProvider::cpu_software(target)?
                .with_exact_formats(&policy.format_set().map_err(std::io::Error::other)?)?,
        );
        self.internal_software_media_candidate = Some(policy);
        Ok(self)
    }
    pub(crate) fn media_provider_for_request(
        &self,
        deployment: &str,
        account: &str,
        controller: &str,
        host: &str,
    ) -> io::Result<Option<(&crate::NativeMediaProvider, u32)>> {
        if self.gpu_hevc_main8_target.is_some() {
            validate_media_peers(deployment, account, controller, host)?;
            return Ok(Some((self.gpu_media_provider()?, self.gpu_hevc_version)));
        }
        // A CPU ceiling alone retains legacy routing. An explicit software
        // policy mismatch fails instead of silently creating a legacy request.
        let Some(policy) = self.internal_software_media_candidate.as_ref() else {
            return Ok(None);
        };
        policy
            .authorize_scope(
                deployment,
                account,
                controller,
                host,
                &policy.formats().map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        Ok(Some((
            self.media_provider
                .as_ref()
                .ok_or_else(|| io::Error::other("explicit media provider unavailable"))?,
            FORMAT_VERSION,
        )))
    }
    pub(crate) fn requires_local_media_approval(&self) -> bool {
        self.gpu_hevc_main8_target.is_some()
    }
    fn gpu_media_provider(&self) -> io::Result<&crate::NativeMediaProvider> {
        let target = self
            .gpu_hevc_main8_target
            .ok_or_else(|| io::Error::other("explicit GPU target unavailable"))?;
        self.media_provider
            .as_ref()
            .filter(|provider| {
                self.internal_software_media_candidate.is_none()
                    && provider.hevc_encoder_backend() == self.gpu_hevc_encoder
                    && provider.matches_gpu_hevc_target(target, self.gpu_hevc_version)
            })
            .ok_or_else(|| io::Error::other("configured GPU media provider changed"))
    }
    pub(crate) fn media_provider_for_approval(
        &self,
        deployment: &str,
        account: &str,
        local_host: &str,
        controller: &str,
        host: &str,
        scope: &FrozenMediaScope,
    ) -> io::Result<&crate::NativeMediaProvider> {
        validate_media_peers(deployment, account, controller, host)?;
        if local_host != host {
            return Err(io::Error::other(
                "media approval is not addressed to the local key",
            ));
        }
        let formats = scope.validate().map_err(io::Error::other)?;
        if let Some(target) = self.gpu_hevc_main8_target {
            if scope.version != self.gpu_hevc_version {
                return Err(io::Error::other(
                    "GPU approval version differs from explicit profile",
                ));
            }
            validate_gpu_formats(scope.version, &formats, target)?;
            return self.gpu_media_provider();
        }
        let policy = self
            .internal_software_media_candidate
            .as_ref()
            .ok_or_else(|| io::Error::other("explicit media approval configuration unavailable"))?;
        policy
            .authorize_host_approval(
                deployment,
                account,
                local_host,
                controller,
                host,
                &scope.formats,
            )
            .map_err(io::Error::other)?;
        self.media_provider
            .as_ref()
            .ok_or_else(|| io::Error::other("explicit media provider unavailable"))
    }
    pub(crate) fn validate_media_publication(
        &self,
        publication: &MediaAnnouncement,
        local_device: &str,
        direction: MediaDirection,
        now: u64,
    ) -> io::Result<()> {
        let formats = publication.validate(now).map_err(io::Error::other)?;
        if publication.device_id != local_device || publication.direction != direction {
            return Err(io::Error::other(
                "media publication differs from local direction",
            ));
        }
        if let Some(target) = self.gpu_hevc_main8_target {
            if publication.version != self.gpu_hevc_version {
                return Err(io::Error::other(
                    "GPU publication version differs from explicit profile",
                ));
            }
            self.gpu_media_provider()?;
            validate_gpu_formats(publication.version, &formats, target)
        } else {
            self.internal_software_media_candidate
                .as_ref()
                .ok_or_else(|| io::Error::other("explicit media policy unavailable"))?
                .authorize_announcement(publication, now)
                .map_err(io::Error::other)
        }
    }
    pub fn with_browser_host(mut self, config: BrowserHostConfig) -> Self {
        self.browser_host = Some(config);
        self
    }

    pub fn network_settings(&self) -> NativeNetworkSettings {
        NativeNetworkSettings {
            space_path: self.space_path.clone(),
            route_set: self.route_set.clone(),
            media_route: self.media_route,
            media_interface_index: self.media_interface_index,
            use_deployment_stun: self.use_deployment_stun,
            pcp_gateway: self.pcp_gateway,
            private_network_prefixes: self.private_network_prefixes.clone(),
        }
    }

    pub fn with_route_set(
        mut self,
        route_set: crate::NativeRouteSetSettings,
    ) -> Result<Self, NativeNetworkError> {
        route_set.validate()?;
        if self.space_path.is_some() || self.relay_node_id.is_some() || self.pcp_gateway.is_some() {
            return Err(NativeNetworkError::Invalid);
        }
        self.route_set = Some(route_set);
        Ok(self)
    }
    pub fn with_space_path(
        mut self,
        path: crate::NativeSpacePathSettings,
    ) -> Result<Self, NativeNetworkError> {
        path.validate()?;
        if self.route_set.is_some() || self.relay_node_id.is_some() {
            return Err(NativeNetworkError::Invalid);
        }
        self.space_path = Some(path);
        Ok(self)
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
        self.pcp_gateway = settings.pcp_gateway;
        self.route_set = settings.route_set;
        self.space_path = settings.space_path;
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
        self.pcp_gateway = settings.pcp_gateway;
        self.route_set = settings.route_set;
        self.space_path = settings.space_path;
        self.private_network_prefixes = settings.private_network_prefixes;
        Ok(commit)
    }

    pub(crate) fn validate(&self) -> bool {
        self.network_settings().validate().is_ok()
            && self.gpu_hevc_main8_target.is_none_or(|_| {
                self.gpu_media_provider().is_ok()
                    && self.supported_capabilities.iter().any(|value| {
                        nestlink_protocol::media_authority::capability_for_version(
                            self.gpu_hevc_version,
                        )
                        .is_ok_and(|expected| value == expected)
                    })
            })
            && (self.route_set.is_none() || self.relay_node_id.is_none())
            && (self.space_path.is_none() || self.relay_node_id.is_none())
            && self
                .relay_node_id
                .as_ref()
                .is_none_or(|id| nestlink_protocol::valid_id(id))
            && self.stun_servers.len() <= 4
            && self.pcp_gateway.is_none_or(|gateway| gateway.is_private())
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

fn validate_media_peers(
    deployment: &str,
    account: &str,
    controller: &str,
    host: &str,
) -> io::Result<()> {
    if [deployment, account, controller, host]
        .iter()
        .any(|id| !nestlink_protocol::valid_id(id))
        || controller == host
    {
        return Err(io::Error::other("invalid explicit media peer scope"));
    }
    Ok(())
}
fn validate_gpu_formats(
    version: u32,
    formats: &nestlink_protocol::media_format::FormatSet,
    target: nestlink_media_codec::VideoConfig,
) -> io::Result<()> {
    if !matches!(
        version,
        HEVC_FORMAT_VERSION | nestlink_protocol::media_authority::HEVC_MAIN10_FORMAT_VERSION
    ) || formats.formats().len() != 1
        || u32::from(formats.canonical_version()) != version
    {
        return Err(io::Error::other(
            "GPU media requires one exact v3 Main8 format",
        ));
    }
    let config = nestlink_media_session::hevc_contract(formats.formats()[0])?.config();
    if (config.width, config.height, config.fps, config.bitrate_kbps)
        != (target.width, target.height, target.fps, target.bitrate_kbps)
    {
        return Err(io::Error::other(
            "GPU media format differs from explicit target",
        ));
    }
    Ok(())
}

/// The implementation must encrypt credentials with an OS-protected key.
/// It is owned by the user daemon and never exposed through Snapshot or IPC.
pub trait ManagementLoginStore: Send + Sync {
    fn enabled(&self) -> bool;
    fn save(&self, bytes: &[u8]) -> std::io::Result<()>;
    fn clear(&self) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    struct Running(tokio::task::JoinHandle<()>);
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    fn target() -> nestlink_media_codec::VideoConfig {
        nestlink_media_codec::VideoConfig {
            width: 640,
            height: 480,
            fps: 30,
            bitrate_kbps: 4000,
        }
    }
    fn config() -> Result<NativeSessionConfig> {
        Ok(NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?)))
    }
    fn hevc_format(
        target: nestlink_media_codec::VideoConfig,
    ) -> Result<nestlink_protocol::media_format::VideoFormat> {
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 120;
        Ok(
            nestlink_protocol::media_format::VideoFormat::hevc_main8_observed(
                ptl,
                target.width,
                target.height,
                nestlink_protocol::media_format::FrameRate::new(target.fps, 1)?,
                target.bitrate_kbps,
            )?,
        )
    }
    fn scope(
        formats: Vec<nestlink_protocol::media_format::VideoFormat>,
    ) -> Result<FrozenMediaScope> {
        let set = nestlink_protocol::media_format::FormatSet::new(formats)?;
        Ok(FrozenMediaScope {
            version: u32::from(set.canonical_version()),
            controller_revision: 1,
            host_revision: 2,
            formats: set
                .formats()
                .iter()
                .map(|format| format.encode())
                .collect::<std::result::Result<_, _>>()?,
            sha256: set.digest().to_vec(),
        })
    }
    fn software_policy()
    -> Result<nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate>
    {
        let format = nestlink_protocol::media_format::VideoFormat::legacy_h264(
            31,
            640,
            480,
            nestlink_protocol::media_format::FrameRate::new(30, 1)?,
            4000,
        )?;
        Ok(
            nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate {
                deployment_id: nestlink_auth::random_id(),
                account_id: nestlink_auth::random_id(),
                controller_device_id: nestlink_auth::random_id(),
                host_device_id: nestlink_auth::random_id(),
                format: format.encode()?,
                format_sha256: format.digest()?,
                additional_formats: vec![],
            },
        )
    }

    #[tokio::test]
    async fn gpu_opt_in_routes_v3_only_and_rejects_provider_replacement_and_cpu_policy() -> Result {
        let ids: Vec<_> = (0..4).map(|_| nestlink_auth::random_id()).collect();
        assert!(
            config()?
                .with_cpu_media_target(target())?
                .media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[3])?
                .is_none()
        );
        let gpu = config()?.with_gpu_hevc_main8_target(target())?;
        assert!(gpu.validate());
        let amf = config()?.with_gpu_hevc_main8_encoder(target(), nestlink_media_codec::HevcEncoderBackend::AmdAmf)?;
        assert!(amf.validate());
        assert_eq!(amf.gpu_media_provider()?.hevc_encoder_backend(), nestlink_media_codec::HevcEncoderBackend::AmdAmf);
        let mut replaced = amf;
        replaced.media_provider = Some(crate::NativeMediaProvider::gpu_hevc_main8(target())?);
        assert!(!replaced.validate());
        assert!(gpu.requires_local_media_approval());
        let (provider, version) = gpu
            .media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[3])?
            .ok_or("explicit GPU route missing")?;
        assert_eq!(version, HEVC_FORMAT_VERSION);
        assert!(provider.matches_gpu_hevc_target(target(), 3));
        assert!(
            gpu.media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[2])
                .is_err()
        );
        assert!(
            gpu.media_provider_for_request("invalid", &ids[1], &ids[2], &ids[3])
                .is_err()
        );
        assert!(gpu.clone().with_cpu_media_target(target()).is_err());
        assert!(
            gpu.clone()
                .with_internal_software_media_candidate(software_policy()?)
                .is_err()
        );
        assert!(
            config()?
                .with_cpu_media_target(target())?
                .with_gpu_hevc_main8_target(target())
                .is_err()
        );
        let mut changed = gpu.clone();
        changed.media_provider = Some(crate::NativeMediaProvider::cpu_software(target())?);
        assert!(!changed.validate());
        assert!(
            changed
                .media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[3])
                .is_err()
        );
        changed.media_provider = None;
        assert!(
            changed
                .media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[3])
                .is_err()
        );
        changed = gpu;
        changed
            .supported_capabilities
            .retain(|value| value != nestlink_protocol::media_authority::HEVC_FORMAT_CAPABILITY);
        assert!(!changed.validate());
        Ok(())
    }
    #[tokio::test]
    async fn main10_opt_in_routes_v4_and_cannot_approve_or_publish_a_main8_scope() -> Result {
        use nestlink_protocol::media_authority::{
            HEVC_MAIN10_FORMAT_CAPABILITY, HEVC_MAIN10_FORMAT_VERSION,
        };
        let ids: Vec<_> = (0..4).map(|_| nestlink_auth::random_id()).collect();
        let gpu = config()?.with_gpu_hevc_main10_target(target())?;
        assert!(gpu.validate());
        assert!(gpu.requires_local_media_approval());
        let (provider, version) = gpu
            .media_provider_for_request(&ids[0], &ids[1], &ids[2], &ids[3])?
            .ok_or("Main10 explicit route absent")?;
        assert_eq!(version, HEVC_MAIN10_FORMAT_VERSION);
        assert!(provider.matches_gpu_hevc_target(target(), version));
        assert!(
            gpu.supported_capabilities
                .iter()
                .any(|value| value == HEVC_MAIN10_FORMAT_CAPABILITY)
        );
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 120;
        let main8 = nestlink_protocol::media_format::VideoFormat::hevc_main8_observed(
            ptl,
            640,
            480,
            nestlink_protocol::media_format::FrameRate::new(30, 1)?,
            4000,
        )?;
        assert!(
            gpu.media_provider_for_approval(
                &ids[0],
                &ids[1],
                &ids[3],
                &ids[2],
                &ids[3],
                &scope(vec![main8])?
            )
            .is_err()
        );
        ptl[0] = 2;
        let main10 = nestlink_protocol::media_format::VideoFormat::hevc_main10_observed(
            ptl,
            640,
            480,
            nestlink_protocol::media_format::FrameRate::new(30, 1)?,
            4000,
        )?;
        assert!(
            gpu.media_provider_for_approval(
                &ids[0],
                &ids[1],
                &ids[3],
                &ids[2],
                &ids[3],
                &scope(vec![main10])?
            )
            .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn gpu_approval_requires_local_host_and_one_exact_main8_target() -> Result {
        let ids: Vec<_> = (0..4).map(|_| nestlink_auth::random_id()).collect();
        let gpu = config()?.with_gpu_hevc_main8_target(target())?;
        let exact = scope(vec![hevc_format(target())?])?;
        let approve = |local: &str, scope: &FrozenMediaScope| {
            gpu.media_provider_for_approval(&ids[0], &ids[1], local, &ids[2], &ids[3], scope)
        };
        assert!(approve(&ids[3], &exact).is_ok());
        assert!(approve(&ids[2], &exact).is_err());
        for different in [
            nestlink_media_codec::VideoConfig {
                width: 320,
                ..target()
            },
            nestlink_media_codec::VideoConfig {
                fps: 60,
                ..target()
            },
            nestlink_media_codec::VideoConfig {
                bitrate_kbps: 8000,
                ..target()
            },
        ] {
            assert!(approve(&ids[3], &scope(vec![hevc_format(different)?])?).is_err());
        }
        assert!(
            approve(
                &ids[3],
                &scope(vec![
                    hevc_format(target())?,
                    hevc_format(nestlink_media_codec::VideoConfig {
                        fps: 15,
                        ..target()
                    })?
                ])?
            )
            .is_err()
        );
        let h264 = nestlink_protocol::media_format::VideoFormat::legacy_h264(
            31,
            640,
            480,
            nestlink_protocol::media_format::FrameRate::new(30, 1)?,
            4000,
        )?;
        assert!(approve(&ids[3], &scope(vec![h264])?).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn gpu_publication_data_checks_bind_exact_direction_target_and_reject_withdrawal()
    -> Result {
        // Synthetic announcements exercise data checks only, never native probe success.
        let gpu = config()?.with_gpu_hevc_main8_target(target())?;
        let device = nestlink_auth::random_id();
        let mut publication = MediaAnnouncement {
            version: HEVC_FORMAT_VERSION,
            device_id: device.clone(),
            direction: MediaDirection::Decode,
            revision: 1,
            expires_at_unix_ms: 2000,
            probe: nestlink_protocol::media_authority::ProbeIdentity {
                generation: 1,
                resource_id: nestlink_auth::random_id(),
                backend: "gpu-hevc-decoder".into(),
                adapter_luid: Some(7),
                driver_version: Some(8),
            },
            formats: vec![hevc_format(target())?.encode()?],
        };
        assert!(
            gpu.validate_media_publication(&publication, &device, MediaDirection::Decode, 1000)
                .is_ok()
        );
        assert!(
            gpu.validate_media_publication(&publication, &device, MediaDirection::Encode, 1000)
                .is_err()
        );
        assert!(
            gpu.validate_media_publication(
                &publication,
                &nestlink_auth::random_id(),
                MediaDirection::Decode,
                1000
            )
            .is_err()
        );
        publication.probe.adapter_luid = None;
        assert!(
            gpu.validate_media_publication(&publication, &device, MediaDirection::Decode, 1000)
                .is_err()
        );
        publication.probe.adapter_luid = Some(7);
        publication.formats.clear();
        assert!(publication.validate(1000).is_ok());
        assert!(
            gpu.validate_media_publication(&publication, &device, MediaDirection::Decode, 1000)
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn explicit_software_scope_mismatch_fails_without_legacy_downgrade() -> Result {
        let policy = software_policy()?;
        let cpu = config()?
            .with_cpu_media_target(target())?
            .with_internal_software_media_candidate(policy.clone())?;
        let (_, version) = cpu
            .media_provider_for_request(
                &policy.deployment_id,
                &policy.account_id,
                &policy.controller_device_id,
                &policy.host_device_id,
            )?
            .ok_or("candidate route absent")?;
        assert_eq!(version, FORMAT_VERSION);
        assert!(
            cpu.media_provider_for_request(
                &nestlink_auth::random_id(),
                &policy.account_id,
                &policy.controller_device_id,
                &policy.host_device_id
            )
            .is_err()
        );
        assert!(cpu.with_gpu_hevc_main8_target(target()).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn explicit_pcp_requires_deployment_permission_even_without_deployment_stun() -> Result {
        let deployment = nestlink_auth::random_id();
        let signer = nestlink_identity::PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = nestlink_storage::Store::in_memory(&deployment)?;
        let password = "pcp-policy-core-entry-password";
        store.bootstrap_admin("admin", password)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = nestlink_server::router(nestlink_server::AppState::new(
            store,
            nestlink_auth::VaultKey::from_bytes([21; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let _service = Running(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        let mut sdk = nestlink_sdk::Sdk::connect(
            &origin,
            nestlink_sdk::DeploymentTrust {
                deployment_id: deployment,
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        sdk.login(
            "admin".into(),
            nestlink_auth::Secret::from_text(password.into()),
            None,
        )
        .await?;
        let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?));
        config.use_deployment_stun = false;
        config.pcp_gateway = Some("10.32.0.1".parse()?);
        assert!(matches!(
            config.clone().resolve_deployment_stun(&sdk).await,
            Err(nestlink_sdk::SdkError::Api(
                reqwest::StatusCode::FORBIDDEN,
                nestlink_protocol::ErrorCode::PermissionRequired
            ))
        ));

        sdk.logout().await?;
        config.pcp_gateway = None;
        // An authenticated discovery request would fail after logout. The
        // default-off legacy path returns without making that request.
        assert!(config.resolve_deployment_stun(&sdk).await.is_ok());
        Ok(())
    }
}
