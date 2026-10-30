//! Typed management client used by desktop, Android Rust and browser Rust/WASM.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use nestlink_auth::{Secret, random_bytes, random_id};
use nestlink_identity::{
    InstallationIdentity, VerifiedPermit, digest, verify_permit, verify_server_identity,
};
use nestlink_protocol::{
    ALPN, API_BASE, CONTROL_BYTES, DeviceAction, DeviceActionClaims, ErrorCode, SCHEMA_VERSION,
    api::*,
    service_plane::{ServiceQuotaLimitUpdate, ServiceQuotaUsageQuery, ServiceQuotaUsageView},
    valid_id,
};
use reqwest::{Client, Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
mod http_wasm;
#[cfg(target_arch = "wasm32")]
use http_wasm::request;
use url::Url;
mod diagnostics;
mod media_authority;
pub mod network_management;
mod spaces;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[cfg(not(target_arch = "wasm32"))]
    #[error("service runtime failed: {0}")]
    Service(#[from] nestlink_node::service_plane::Error),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("service carrier failed: {0}")]
    ServiceIo(#[from] std::io::Error),
    #[error("management transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("browser management request failed")]
    BrowserTransport,
    #[error("management request timed out")]
    Timeout,
    #[error("management operation rejected ({0}): {1:?}")]
    Api(StatusCode, ErrorCode),
    #[error("management response invalid")]
    Invalid,
    #[error("deployment or permit issuer does not match the configured trust anchor")]
    Trust,
    #[error("sign in required")]
    SignIn,
    #[error("identity proof failed: {0}")]
    Proof(#[from] nestlink_protocol::ContractError),
    #[error("JSON contract failed: {0}")]
    Json(#[from] serde_json::Error),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("native relay failed: {0}")]
    Relay(#[from] nestlink_transport_wss::Error),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("native reconnection setup failed: {0}")]
    NativeDial(#[from] native::DialError),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("native reconnection cleanup failed: {0}")]
    NativeCleanup(#[from] nestlink_remote::RemoteError),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("node QUIC transport failed: {0}")]
    NodeQuic(#[source] Box<dyn std::error::Error + Send + Sync>),
}
pub struct DeploymentTrust {
    pub deployment_id: String,
    pub permit_issuer: [u8; 32],
}
struct LoginState {
    principal: Principal,
    access: Secret,
    refresh: Secret,
    generation: u64,
    refresh_expires: u64,
}
pub struct DeviceIdentity {
    pub device_id: String,
    pub identity: InstallationIdentity,
}
impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            device_id: random_id(),
            identity: InstallationIdentity::generate(),
        }
    }
}
pub struct Sdk {
    client: Client,
    origin: Url,
    trust: DeploymentTrust,
    health: HealthResponse,
    login: Option<LoginState>,
}
mod native_discovery;
mod node_discovery;
mod reconnection;
mod relay_allocation;
#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_platform_network::{
    NetworkMonitor, PlatformLinkAddress, PlatformNetworkFacts, PlatformRoute,
};
#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_policy::PathSet;
#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_session::StopReason;
pub use node_discovery::{NodeDiscovery, NodeRelayCandidate, NodeRelayCandidates};
#[cfg(not(target_arch = "wasm32"))]
pub use reconnection::NativeReconnectionConfig;
pub use reconnection::{ReconnectedPermit, ReconnectionAttempt};
mod remote_password;
pub mod services;
mod signaling;
mod turn;
pub use signaling::{SignalCursor, verify_peer_signal};
pub use turn::TurnCredentials;
#[cfg(not(target_arch = "wasm32"))]
pub mod browse;
#[cfg(not(target_arch = "wasm32"))]
pub mod clipboard;
#[cfg(not(target_arch = "wasm32"))]
pub mod discovery;
#[cfg(not(target_arch = "wasm32"))]
pub mod download_queue;
#[cfg(not(target_arch = "wasm32"))]
pub mod files;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_recovery;
#[cfg(not(target_arch = "wasm32"))]
mod native_relay;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_renewal;
#[cfg(not(target_arch = "wasm32"))]
pub mod network;
#[cfg(not(target_arch = "wasm32"))]
mod node_relay;
#[cfg(not(target_arch = "wasm32"))]
pub mod upload;
#[cfg(not(target_arch = "wasm32"))]
pub mod webrtc_host;
#[cfg(not(target_arch = "wasm32"))]
pub use native_relay::RelayRoute;
#[cfg(not(target_arch = "wasm32"))]
pub use node_relay::{NativeRelayRoute, NodeQuicRoute, NodeRelayRoute};
#[cfg(all(test, not(target_arch = "wasm32")))]
mod management_login_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod session_refresh_tests;

impl Sdk {
    /// Discover deployment metadata over the origin's authenticated HTTPS
    /// connection, then verify a fresh signed identity challenge. HTTP is
    /// available only for an explicitly allowed loopback development server.
    pub async fn connect_origin(origin: &str, allow_loopback_http: bool) -> Result<Self, SdkError> {
        let parsed = parse_origin(origin, allow_loopback_http)?;
        let client = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let client = client
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        let client = client.build()?;
        let health: HealthResponse = request(&client, &parsed, Method::GET, "/health", None, None)
            .await?
            .ok_or(SdkError::Invalid)?;
        let permit_issuer = URL_SAFE_NO_PAD
            .decode(&health.permit_issuer)
            .map_err(|_| SdkError::Trust)?
            .try_into()
            .map_err(|_| SdkError::Trust)?;
        Self::connect(
            origin,
            DeploymentTrust {
                deployment_id: health.deployment_id,
                permit_issuer,
            },
            allow_loopback_http,
        )
        .await
    }

    /// Caller obtains and approves the deployment trust anchor before installing it.
    pub async fn connect(
        origin: &str,
        trust: DeploymentTrust,
        allow_loopback_http: bool,
    ) -> Result<Self, SdkError> {
        if !valid_id(&trust.deployment_id) {
            return Err(SdkError::Trust);
        }
        let origin = parse_origin(origin, allow_loopback_http)?;
        let client = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let client = client
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        let client = client.build()?;
        let health: HealthResponse = request(&client, &origin, Method::GET, "/health", None, None)
            .await?
            .ok_or(SdkError::Invalid)?;
        let issuer = URL_SAFE_NO_PAD
            .decode(&health.permit_issuer)
            .map_err(|_| SdkError::Invalid)?;
        if health.deployment_id != trust.deployment_id
            || issuer != trust.permit_issuer
            || health.api_base != API_BASE
            || health.alpn != ALPN
            || health.product != "NestLink"
            || health.security_epoch == 0
        {
            return Err(SdkError::Trust);
        }
        let nonce = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let challenge = serde_json::to_value(ServerIdentityChallenge {
            nonce: nonce.clone(),
        })?;
        let proof: ServerIdentityProof = request(
            &client,
            &origin,
            Method::POST,
            "/health/proof",
            Some(challenge),
            None,
        )
        .await?
        .ok_or(SdkError::Invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&proof.signature)
            .map_err(|_| SdkError::Trust)?;
        let claims = &proof.claims;
        if claims.nonce != nonce
            || claims.management_origin != origin.origin().ascii_serialization()
            || claims.product != health.product
            || claims.version != health.version
            || claims.api_base != health.api_base
            || claims.alpn != health.alpn
            || claims.deployment_id != health.deployment_id
            || claims.security_epoch != health.security_epoch
            || claims.permit_issuer != health.permit_issuer
            || claims.node_policy_issuer != health.node_policy_issuer
        {
            return Err(SdkError::Trust);
        }
        verify_server_identity(claims, &signature, &trust.permit_issuer)
            .map_err(|_| SdkError::Trust)?;
        Ok(Self {
            client,
            origin,
            trust,
            health,
            login: None,
        })
    }
    pub fn management_origin(&self) -> &str {
        // Url stores a root path, whereas the management origin contract does
        // not include a trailing slash (including when restored into AppCore).
        self.origin
            .as_str()
            .strip_suffix('/')
            .unwrap_or(self.origin.as_str())
    }
    /// Secret-bearing recovery data for the daemon's OS-protected store only.
    pub fn export_login(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, SdkError> {
        let Some(login) = &self.login else {
            return Ok(None);
        };
        Ok(Some(zeroize::Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({
                "origin": self.management_origin(), "deployment_id": self.trust.deployment_id,
                "permit_issuer": self.trust.permit_issuer,
                "login": LoginResponse { principal: login.principal.clone(), access_token: login.access.expose().into(),
                    refresh_token: login.refresh.expose().into(), generation: login.generation, refresh_expires: login.refresh_expires }
            }),
        )?)))
    }
    pub async fn resume_login(bytes: &[u8]) -> Result<Self, SdkError> {
        #[derive(serde::Deserialize)]
        struct Saved {
            origin: String,
            deployment_id: String,
            permit_issuer: [u8; 32],
            login: LoginResponse,
        }
        let saved: Saved = serde_json::from_slice(bytes)?;
        let origin = saved_management_origin(&saved.origin)?;
        let mut sdk = Self::connect(
            &origin,
            DeploymentTrust {
                deployment_id: saved.deployment_id,
                permit_issuer: saved.permit_issuer,
            },
            false,
        )
        .await?;
        sdk.install_login(saved.login)?;
        sdk.refresh().await?;
        Ok(sdk)
    }
    pub fn forget_login(&mut self) {
        self.login = None;
    }
    pub fn principal(&self) -> Option<&Principal> {
        self.login.as_ref().map(|v| &v.principal)
    }
    pub fn health(&self) -> &HealthResponse {
        &self.health
    }
    pub async fn nodes(&self) -> Result<Vec<NodeView>, SdkError> {
        let result: NodesResponse = self
            .call::<(), _>(Method::GET, "/nodes", None, true)
            .await?
            .ok_or(SdkError::Invalid)?;
        Ok(result.nodes)
    }
    pub async fn register_node(&self, node: NodeRegistration) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(Method::POST, "/nodes", Some(&node), true)
            .await?;
        Ok(())
    }
    pub async fn revoke_node(&self, id: &str) -> Result<(), SdkError> {
        self.call::<(), serde_json::Value>(Method::DELETE, &resource("nodes", id)?, None, true)
            .await?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_relay(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
    ) -> Result<tokio_rustls::TlsStream<nestlink_transport_wss::ByteStream>, SdkError> {
        if !permit
            .claims()
            .paths
            .contains(&(nestlink_protocol::Path::Relay as i32))
        {
            return Err(SdkError::Api(
                StatusCode::FORBIDDEN,
                ErrorCode::RelayDisabled,
            ));
        }
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let login = self.login.as_ref().ok_or(SdkError::SignIn)?;
        let mut url = self
            .origin
            .join(&format!(
                "{API_BASE}{}/relay",
                resource("remote", &permit.claims().session_id)?
            ))
            .map_err(|_| SdkError::Invalid)?;
        url.set_scheme(if self.origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| SdkError::Invalid)?;
        Ok(nestlink_transport_wss::connect(
            url.as_str(),
            login.access.expose(),
            &login.principal.account_id,
            &installation.device_id,
            &installation.identity,
            permit,
        )
        .await?)
    }
    pub async fn login(
        &mut self,
        username: String,
        password: Secret,
        factor: Option<Secret>,
    ) -> Result<(), SdkError> {
        if self.login.is_some() {
            self.logout().await?;
        }
        let body = Login {
            username,
            password: password.expose().into(),
            factor: factor.map(|v| v.expose().into()),
        };
        let response: LoginResponse = self
            .call(Method::POST, "/auth/login", Some(&body), false)
            .await?
            .ok_or(SdkError::Invalid)?;
        self.install_login(response)
    }
    fn install_login(&mut self, response: LoginResponse) -> Result<(), SdkError> {
        if response.access_token.len() != 43
            || response.refresh_token.len() != 43
            || response.generation == 0
            || response.generation > i64::MAX as u64
            || !valid_id(&response.principal.account_id)
            || !valid_id(&response.principal.session_id)
        {
            return Err(SdkError::Invalid);
        }
        self.login = Some(LoginState {
            principal: response.principal,
            access: Secret::from_text(response.access_token),
            refresh: Secret::from_text(response.refresh_token),
            generation: response.generation,
            refresh_expires: response.refresh_expires,
        });
        Ok(())
    }
    /// Select a specific browser session using its HttpOnly cookie. The selector
    /// contains no credential, and must belong to this tab and verified origin.
    pub async fn restore_browser_session(&mut self, session_id: String) -> Result<(), SdkError> {
        if self.login.is_some() || !valid_id(&session_id) {
            return Err(SdkError::Invalid);
        }
        let response: LoginResponse = self
            .call(
                Method::POST,
                "/auth/restore",
                Some(&nestlink_protocol::api::RestoreLogin {
                    session_id: session_id.clone(),
                }),
                false,
            )
            .await?
            .ok_or(SdkError::Invalid)?;
        if response.principal.session_id != session_id {
            return Err(SdkError::Trust);
        }
        self.install_login(response)
    }
    pub async fn refresh(&mut self) -> Result<(), SdkError> {
        let login = self.login.as_ref().ok_or(SdkError::SignIn)?;
        let old_session = login.principal.session_id.clone();
        let old_account = login.principal.account_id.clone();
        let generation = login.generation;
        let body = Refresh {
            refresh_token: Some(login.refresh.expose().into()),
            generation,
        };
        let result = self
            .call::<_, LoginResponse>(Method::POST, "/auth/refresh", Some(&body), false)
            .await;
        let response = match result {
            Ok(Some(response)) => response,
            Err(error @ (SdkError::Timeout | SdkError::BrowserTransport)) => return Err(error),
            #[cfg(not(target_arch = "wasm32"))]
            Err(error @ SdkError::Transport(_)) => return Err(error),
            Err(error @ SdkError::Api(status, _))
                if status.is_server_error() || status.as_u16() == 429 =>
            {
                return Err(error);
            }
            _ => {
                self.login = None;
                return Err(SdkError::SignIn);
            }
        };
        if response.generation != generation + 1
            || response.principal.session_id != old_session
            || response.principal.account_id != old_account
        {
            self.login = None;
            return Err(SdkError::Trust);
        }
        self.install_login(response)
    }
    pub async fn logout(&mut self) -> Result<(), SdkError> {
        if self.login.is_none() {
            return Ok(());
        }
        let result = self
            .call::<(), serde_json::Value>(Method::POST, "/auth/logout", None, true)
            .await;
        self.login = None;
        result.map(|_| ())
    }
    pub async fn me(&self) -> Result<MeResponse, SdkError> {
        self.required(Method::GET, "/auth/me", None::<&()>).await
    }
    pub async fn devices(&self) -> Result<Vec<DeviceView>, SdkError> {
        Ok(self
            .required::<(), DevicesResponse>(Method::GET, "/devices", None)
            .await?
            .devices)
    }
    /// Resolve a peer's registered signing key only when it matches a fresh,
    /// verified permit's expected digest.
    pub async fn peer_device_key(
        &self,
        device_id: &str,
        expected_sha256: &[u8],
    ) -> Result<[u8; 32], SdkError> {
        let devices = self.devices().await?;
        let descriptor = devices
            .iter()
            .find(|device| device.device.id == device_id)
            .ok_or(SdkError::Trust)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(&descriptor.device.public_key)
            .map_err(|_| SdkError::Trust)?;
        let key: [u8; 32] = decoded.try_into().map_err(|_| SdkError::Trust)?;
        if digest(&key).as_slice() != expected_sha256 {
            return Err(SdkError::Trust);
        }
        Ok(key)
    }
    pub async fn accounts(&self) -> Result<Vec<AccountView>, SdkError> {
        Ok(self
            .required::<(), AccountsResponse>(Method::GET, "/accounts", None)
            .await?
            .accounts)
    }

    /// Obtain a peer key through the approved session, including a peer owned
    /// by another account, and bind both returned keys to the signed permit.
    pub async fn remote_peer_key(
        &self,
        permit: &VerifiedPermit,
        installation: &DeviceIdentity,
    ) -> Result<[u8; 32], SdkError> {
        let claims = permit.claims();
        let is_controller = installation.device_id == claims.controller_device_id;
        let is_host = installation.device_id == claims.host_device_id;
        if is_controller == is_host
            || claims.deployment_id != self.trust.deployment_id
            || claims.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let expected_local = if is_controller {
            &claims.controller_key_sha256
        } else {
            &claims.host_key_sha256
        };
        if expected_local.as_slice() != installation.identity.fingerprint() {
            return Err(SdkError::Trust);
        }
        let keys: RemotePeerKeys = self
            .required(
                Method::GET,
                &format!("{}/peer-keys", resource("remote", &claims.session_id)?),
                None::<&()>,
            )
            .await?;
        if keys.session_id != claims.session_id
            || keys.connection_generation != claims.connection_generation
            || keys.lease_sequence != claims.lease_sequence
        {
            return Err(SdkError::Trust);
        }
        let decode_key = |value: &str, fingerprint: &[u8]| -> Result<[u8; 32], SdkError> {
            let key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| SdkError::Trust)?
                .try_into()
                .map_err(|_| SdkError::Trust)?;
            if digest(&key).as_slice() != fingerprint {
                return Err(SdkError::Trust);
            }
            Ok(key)
        };
        let controller = decode_key(&keys.controller_public_key, &claims.controller_key_sha256)?;
        let host = decode_key(&keys.host_public_key, &claims.host_key_sha256)?;
        Ok(if is_controller { host } else { controller })
    }
    pub async fn create_account(
        &self,
        username: String,
        password: Secret,
    ) -> Result<String, SdkError> {
        Ok(self
            .required::<_, IdResponse>(
                Method::POST,
                "/accounts",
                Some(&NewAccount {
                    username,
                    password: password.expose().into(),
                }),
            )
            .await?
            .id)
    }
    pub async fn policy(&self) -> Result<PolicyResponse, SdkError> {
        self.required(Method::GET, "/policy", None::<&()>).await
    }
    pub async fn relay_quota(&self) -> Result<RelayQuota, SdkError> {
        self.required(Method::GET, "/relay/quota", None::<&()>)
            .await
    }
    pub async fn set_relay_quota(&self, update: RelayQuotaUpdate) -> Result<RelayQuota, SdkError> {
        self.required(Method::PUT, "/relay/quota", Some(&update))
            .await
    }
    pub async fn relay_usage(&self) -> Result<RelayUsage, SdkError> {
        self.required(Method::GET, "/relay/usage", None::<&()>)
            .await
    }
    pub async fn service_quota_usage(
        &self,
        query: ServiceQuotaUsageQuery,
    ) -> Result<ServiceQuotaUsageView, SdkError> {
        query.validate()?;
        self.required(
            Method::GET,
            &format!(
                "/service-usage/quota?scope={}&scope_key={}",
                query.scope.as_str(),
                query.scope_key
            ),
            None::<&()>,
        )
        .await
    }
    pub async fn set_service_quota_limit(
        &self,
        update: ServiceQuotaLimitUpdate,
    ) -> Result<ServiceQuotaUsageView, SdkError> {
        update.validate()?;
        self.required(Method::PUT, "/service-usage/quota", Some(&update))
            .await
    }
    pub async fn set_policy(&self, body: PolicyUpdate) -> Result<u64, SdkError> {
        Ok(self
            .required::<_, RevisionResponse>(Method::PUT, "/policy", Some(&body))
            .await?
            .revision)
    }
    pub async fn disable_account(&self, id: &str) -> Result<(), SdkError> {
        self.call::<(), serde_json::Value>(Method::DELETE, &resource("accounts", id)?, None, true)
            .await
            .map(|_| ())
    }
    pub async fn node_usage(
        &self,
        id: &str,
        after_generation: u64,
        limit: u16,
    ) -> Result<NodeUsagePage, SdkError> {
        self.required(
            Method::GET,
            &format!(
                "{}/usage?security_epoch={}&after_generation={after_generation}&limit={limit}",
                resource("nodes", id)?,
                self.health.security_epoch
            ),
            None::<&()>,
        )
        .await
    }
    pub async fn revoke_device(&self, id: &str) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &resource("devices", id)?,
            Some(&RevokeDevice {
                request_id: random_id(),
            }),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn path_limits(&self) -> Result<Vec<PathLimit>, SdkError> {
        Ok(self
            .required::<(), PathLimitsResponse>(Method::GET, "/policy/scopes", None)
            .await?
            .limits)
    }
    pub async fn set_path_limit(
        &self,
        scope: &str,
        id: &str,
        body: PathLimitUpdate,
    ) -> Result<u64, SdkError> {
        if !["account", "device", "resource", "login_session"].contains(&scope) || !valid_id(id) {
            return Err(SdkError::Invalid);
        }
        Ok(self
            .required::<_, RevisionResponse>(
                Method::PUT,
                &format!("/policy/scopes/{scope}/{id}"),
                Some(&body),
            )
            .await?
            .revision)
    }
    pub async fn change_password(
        &mut self,
        current: Secret,
        replacement: Secret,
        factor: Option<Secret>,
    ) -> Result<(), SdkError> {
        let body = PasswordChange {
            current_password: current.expose().into(),
            new_password: replacement.expose().into(),
            factor: factor.map(|v| v.expose().into()),
        };
        self.call::<_, serde_json::Value>(Method::PUT, "/auth/password", Some(&body), true)
            .await?;
        self.login = None;
        Ok(())
    }
    pub async fn pending_remote(&self) -> Result<Vec<RemoteView>, SdkError> {
        let mut requests = Vec::new();
        let mut cursor = None;
        loop {
            let path = cursor
                .as_ref()
                .map_or_else(|| "/remote".to_owned(), |id| format!("/remote?after={id}"));
            let page = self
                .required::<(), RemoteRequestsResponse>(Method::GET, &path, None)
                .await?;
            requests.extend(page.requests);
            let Some(next) = page.next_cursor else {
                return Ok(requests);
            };
            if !nestlink_protocol::valid_id(&next)
                || cursor.as_ref() == Some(&next)
                || requests.len() >= 10000
            {
                return Err(SdkError::Invalid);
            }
            cursor = Some(next);
        }
    }
    pub async fn ready_native_remote(
        &self,
        local: &DeviceIdentity,
    ) -> Result<Vec<RemoteView>, SdkError> {
        if !nestlink_protocol::valid_id(&local.device_id) {
            return Err(SdkError::Invalid);
        }
        Ok(self
            .required::<(), RemoteRequestsResponse>(
                Method::GET,
                &format!("/remote/native-ready/{}", local.device_id),
                None,
            )
            .await?
            .requests)
    }
    pub async fn ready_browser_remote(
        &self,
        local: &DeviceIdentity,
    ) -> Result<Vec<RemoteView>, SdkError> {
        if !nestlink_protocol::valid_id(&local.device_id) {
            return Err(SdkError::Invalid);
        }
        Ok(self
            .required::<(), RemoteRequestsResponse>(
                Method::GET,
                &format!("/remote/browser-ready/{}", local.device_id),
                None,
            )
            .await?
            .requests)
    }
    pub async fn browser_host_readiness(
        &self,
        id: &str,
    ) -> Result<nestlink_protocol::api::BrowserHostReadiness, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/browser-host-ready", resource("remote", id)?),
            None::<&()>,
        )
        .await
    }
    pub async fn mark_browser_host_ready(
        &self,
        local: &DeviceIdentity,
        view: &RemoteView,
    ) -> Result<(), SdkError> {
        if view.host_device_id != local.device_id
            || view.status != "approved"
            || view.lease_sequence != 0
        {
            return Err(SdkError::Trust);
        }
        let version: Vec<u32> = self
            .health
            .version
            .split(['.', '-'])
            .take(2)
            .filter_map(|v| v.parse().ok())
            .collect();
        let protocol_features = if version.as_slice() >= [0, 7].as_slice() {
            vec![
                nestlink_protocol::ice::TRICKLE_CAPABILITY.into(),
                nestlink_protocol::ice::SETUP_CAPABILITY.into(),
            ]
        } else {
            Vec::new()
        };
        let proof = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::PrepareBrowserHost as i32,
            deployment_id: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: local.device_id.clone(),
            resource_id: view.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(&view.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&nestlink_protocol::ice::readiness_payload(
                view.connection_generation,
                &protocol_features,
            )?)
            .to_vec(),
            expires_at_unix_ms: view.expires_at_unix_ms,
        };
        let response: nestlink_protocol::api::BrowserHostReadiness = self
            .required(
                Method::POST,
                &format!("{}/browser-host-ready", resource("remote", &view.id)?),
                Some(&nestlink_protocol::api::BrowserHostReadinessSubmission {
                    protocol_features,
                    signature: URL_SAFE_NO_PAD.encode(local.identity.sign_action(&proof)?),
                }),
            )
            .await?;
        if !response.ready || response.connection_generation != view.connection_generation {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    pub async fn audit_page(&self, after_sequence: u64, limit: u16) -> Result<AuditPage, SdkError> {
        if limit == 0 || limit > 100 || after_sequence > i64::MAX as u64 {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::GET,
            &format!(
                "/audit?security_epoch={}&after_sequence={after_sequence}&limit={limit}",
                self.health.security_epoch
            ),
            None::<&()>,
        )
        .await
    }
    pub async fn audit_retention(&self) -> Result<AuditRetention, SdkError> {
        self.required(Method::GET, "/audit/retention", None::<&()>)
            .await
    }
    pub async fn set_audit_retention(
        &self,
        update: AuditRetentionUpdate,
    ) -> Result<AuditRetention, SdkError> {
        self.required(Method::PUT, "/audit/retention", Some(&update))
            .await
    }
    pub async fn create_remote(&self, body: RemoteRequest) -> Result<RemoteView, SdkError> {
        self.required(Method::POST, "/remote", Some(&body)).await
    }
    pub async fn create_trusted_remote(&self, body: RemoteRequest) -> Result<RemoteView, SdkError> {
        self.required(Method::POST, "/remote/trusted", Some(&body))
            .await
    }
    /// Call only after the local user explicitly chooses to trust the controller.
    pub async fn trust_remote(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        choice: TrustChoice,
    ) -> Result<u64, SdkError> {
        let claims = permit.claims();
        if claims.host_device_id != installation.device_id
            || claims.host_key_sha256 != installation.identity.fingerprint()
            || claims.deployment_id != self.trust.deployment_id
            || claims.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let actor = self.principal().ok_or(SdkError::SignIn)?;
        let transcript = nestlink_identity::trust_transcript(claims, &actor.account_id, &choice)?;
        let body = TrustSubmission {
            choice,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&transcript)?),
        };
        let response: RevisionResponse = self
            .required(
                Method::POST,
                &format!("{}/trust", resource("remote", &claims.session_id)?),
                Some(&body),
            )
            .await?;
        Ok(response.revision)
    }
    pub async fn trusted_devices(&self, host: &str) -> Result<Vec<TrustedDeviceView>, SdkError> {
        let response: TrustedDevicesResponse = self
            .required(
                Method::GET,
                &format!("{}/trust", resource("devices", host)?),
                None::<&()>,
            )
            .await?;
        Ok(response.devices)
    }
    pub async fn revoke_device_trust(
        &self,
        host: &str,
        controller: &str,
        expected_revision: u64,
    ) -> Result<(), SdkError> {
        if !valid_id(controller) {
            return Err(SdkError::Invalid);
        }
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/trust/{controller}", resource("devices", host)?),
            Some(&TrustRevocation { expected_revision }),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn remote(&self, id: &str) -> Result<RemoteView, SdkError> {
        self.required(Method::GET, &resource("remote", id)?, None::<&()>)
            .await
    }
    pub async fn revoke_remote(&self, id: &str) -> Result<(), SdkError> {
        self.call::<(), serde_json::Value>(Method::DELETE, &resource("remote", id)?, None, true)
            .await
            .map(|_| ())
    }
    pub async fn enroll(
        &self,
        installation: &DeviceIdentity,
        name: String,
        platform: String,
        capabilities: Vec<String>,
        path_mode: String,
    ) -> Result<(), SdkError> {
        #[cfg(not(target_arch = "wasm32"))]
        let capabilities = {
            let mut capabilities = capabilities;
            if self.health.native_ice_version == nestlink_protocol::native_ice::VERSION
                && matches!(
                    platform.as_str(),
                    "windows" | "linux-x11" | "linux-wayland" | "android"
                )
                && !capabilities
                    .iter()
                    .any(|value| value == nestlink_protocol::native_ice::CAPABILITY)
            {
                capabilities.push(nestlink_protocol::native_ice::CAPABILITY.into());
            }
            capabilities
        };
        let descriptor = DeviceDescriptor {
            id: installation.device_id.clone(),
            name,
            platform,
            capabilities,
            path_mode,
            public_key: URL_SAFE_NO_PAD.encode(installation.identity.public_key()),
        };
        self.enroll_descriptor(installation, descriptor, "/devices")
            .await
    }

    pub async fn refresh_browser_features(
        &self,
        installation: &DeviceIdentity,
        mut descriptor: DeviceDescriptor,
    ) -> Result<(), SdkError> {
        if descriptor.id != installation.device_id
            || descriptor.platform != "web"
            || descriptor.public_key != URL_SAFE_NO_PAD.encode(installation.identity.public_key())
        {
            return Err(SdkError::Invalid);
        }
        for feature in [
            nestlink_protocol::ice::SETUP_CAPABILITY,
            nestlink_protocol::ice::TRICKLE_CAPABILITY,
        ] {
            if !descriptor.capabilities.iter().any(|value| value == feature) {
                descriptor.capabilities.push(feature.into());
            }
        }
        let path = format!("{}/features", resource("devices", &installation.device_id)?);
        self.enroll_descriptor(installation, descriptor, &path)
            .await
    }

    /// Add only the probed media feature to an existing Windows signing key.
    /// The server verifies the unchanged identity, roles and descriptor fields.
    pub async fn refresh_native_media_features(
        &self,
        installation: &DeviceIdentity,
        mut descriptor: DeviceDescriptor,
    ) -> Result<bool, SdkError> {
        if self
            .health
            .version
            .split(['.', '-'])
            .take(2)
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>()
            .as_slice()
            < [0, 7].as_slice()
        {
            return Ok(false);
        }
        #[cfg(windows)]
        if descriptor.platform == "windows"
            && descriptor.id == installation.device_id
            && !descriptor
                .capabilities
                .iter()
                .any(|value| value == nestlink_protocol::media::H264_CAPABILITY)
            && tokio::task::spawn_blocking(nestlink_media_codec::h264_hardware_available)
                .await
                .unwrap_or(false)
        {
            descriptor
                .capabilities
                .push(nestlink_protocol::media::H264_CAPABILITY.into());
            let path = format!("{}/features", resource("devices", &installation.device_id)?);
            self.enroll_descriptor(installation, descriptor, &path)
                .await?;
            return Ok(true);
        }
        #[cfg(not(windows))]
        let _ = (installation, &mut descriptor);
        Ok(false)
    }

    async fn enroll_descriptor(
        &self,
        installation: &DeviceIdentity,
        descriptor: DeviceDescriptor,
        path: &str,
    ) -> Result<(), SdkError> {
        let challenge: EnrollmentChallenge = self
            .required(Method::POST, "/devices/challenge", None::<&()>)
            .await?;
        if challenge.deployment_id != self.trust.deployment_id
            || challenge.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let claims = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Register as i32,
            deployment_id: challenge.deployment_id,
            security_epoch: challenge.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: descriptor.id.clone(),
            resource_id: challenge.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(challenge.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&serde_json::to_vec(&descriptor)?).to_vec(),
            expires_at_unix_ms: challenge.expires_at_unix_ms,
        };
        let body = DeviceRegistration {
            challenge_id: challenge.id,
            device: descriptor,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&claims)?),
        };
        self.call::<_, serde_json::Value>(Method::POST, path, Some(&body), true)
            .await
            .map(|_| ())
    }
    /// Registers a controller-only browser endpoint with a fixed ten-minute
    /// server lease. The endpoint key is the same key later bound into remote
    /// permits and endpoint-signed signaling; it never becomes a permanent
    /// enrolled installation.
    pub async fn register_browser_endpoint(
        &self,
        installation: &DeviceIdentity,
        name: String,
        path_mode: String,
    ) -> Result<BrowserEndpointLease, SdkError> {
        let challenge: EnrollmentChallenge = self
            .required(Method::POST, "/devices/challenge", None::<&()>)
            .await?;
        if challenge.deployment_id != self.trust.deployment_id
            || challenge.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let descriptor = DeviceDescriptor {
            id: installation.device_id.clone(),
            name,
            platform: "web".into(),
            public_key: URL_SAFE_NO_PAD.encode(installation.identity.public_key()),
            capabilities: vec![
                "controller".into(),
                "vp8".into(),
                nestlink_protocol::ice::TRICKLE_CAPABILITY.into(),
                nestlink_protocol::ice::SETUP_CAPABILITY.into(),
            ],
            path_mode,
        };
        let claims = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::RegisterBrowserEndpoint as i32,
            deployment_id: challenge.deployment_id,
            security_epoch: challenge.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: descriptor.id.clone(),
            resource_id: challenge.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(challenge.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&serde_json::to_vec(&descriptor)?).to_vec(),
            expires_at_unix_ms: challenge.expires_at_unix_ms,
        };
        let body = BrowserEndpointRegistration {
            challenge_id: challenge.id,
            device: descriptor,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&claims)?),
        };
        let lease: BrowserEndpointLease = self
            .required(Method::POST, "/devices/browser", Some(&body))
            .await?;
        if lease.device_id != installation.device_id || lease.expires_at_unix_ms == 0 {
            return Err(SdkError::Invalid);
        }
        Ok(lease)
    }
    pub async fn approve(
        &self,
        installation: &DeviceIdentity,
        view: &RemoteView,
        choice: ApprovalChoice,
    ) -> Result<(), SdkError> {
        if view.host_device_id != installation.device_id {
            return Err(SdkError::Trust);
        }
        let claims = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Approve as i32,
            deployment_id: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: installation.device_id.clone(),
            resource_id: view.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(&view.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&serde_json::to_vec(&choice)?).to_vec(),
            expires_at_unix_ms: view.expires_at_unix_ms,
        };
        let body = ApprovalSubmission {
            choice,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&claims)?),
        };
        self.call::<_, serde_json::Value>(
            Method::POST,
            &format!("{}/approval", resource("remote", &view.id)?),
            Some(&body),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn permit(&self, id: &str) -> Result<VerifiedPermit, SdkError> {
        let response: PermitResponse = self
            .required(
                Method::POST,
                &format!("{}/permit", resource("remote", id)?),
                None::<&()>,
            )
            .await?;
        self.verify_response(id, response)
    }
    /// Read an already-issued live native lease, checking the bound local key.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn current_native_permit(
        &self,
        identity: &DeviceIdentity,
        id: &str,
    ) -> Result<VerifiedPermit, SdkError> {
        let response: PermitResponse = self
            .required(
                Method::GET,
                &format!("{}/permit", resource("remote", id)?),
                None::<&()>,
            )
            .await?;
        let permit = self.verify_response(id, response)?;
        let c = permit.claims();
        let expected = if identity.device_id == c.controller_device_id {
            &c.controller_key_sha256
        } else if identity.device_id == c.host_device_id {
            &c.host_key_sha256
        } else {
            return Err(SdkError::Trust);
        };
        if expected != &identity.identity.fingerprint() {
            return Err(SdkError::Trust);
        }
        Ok(permit)
    }
    /// Confirm the current controller permit after a signed session
    /// reconnection. The initial issuance endpoint is intentionally restricted
    /// to lease sequence 1 and cannot validate a successor permit.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn current_controller_permit(
        &self,
        installation: &DeviceIdentity,
        id: &str,
    ) -> Result<VerifiedPermit, SdkError> {
        let response: PermitResponse = self
            .required(
                Method::GET,
                &format!("{}/permit", resource("remote", id)?),
                None::<&()>,
            )
            .await?;
        let permit = self.verify_response(id, response)?;
        if permit.claims().controller_device_id != installation.device_id
            || permit.claims().controller_key_sha256 != installation.identity.fingerprint()
        {
            return Err(SdkError::Trust);
        }
        Ok(permit)
    }
    pub async fn host_permit(
        &self,
        installation: &DeviceIdentity,
        id: &str,
    ) -> Result<VerifiedPermit, SdkError> {
        let response: PermitResponse = self
            .required(
                Method::GET,
                &format!("{}/permit", resource("remote", id)?),
                None::<&()>,
            )
            .await?;
        let bytes = URL_SAFE_NO_PAD
            .decode(response.permit)
            .map_err(|_| SdkError::Invalid)?;
        let verified = verify_permit(&bytes, &self.trust.permit_issuer)?;
        if verified.claims() != &response.claims
            || verified.claims().deployment_id != self.trust.deployment_id
            || verified.claims().security_epoch != self.health.security_epoch
            || verified.claims().session_id != id
            || verified.claims().host_device_id != installation.device_id
            || verified.claims().host_key_sha256 != installation.identity.fingerprint()
        {
            return Err(SdkError::Trust);
        }
        Ok(verified)
    }
    pub fn renewal_signature(
        &self,
        installation: &DeviceIdentity,
        view: &RemoteView,
        permit: &VerifiedPermit,
    ) -> Result<String, SdkError> {
        let account = self.principal().ok_or(SdkError::SignIn)?.account_id.clone();
        let claims = permit.claims();
        let expected = if installation.device_id == claims.controller_device_id {
            &claims.controller_key_sha256
        } else if installation.device_id == claims.host_device_id {
            &claims.host_key_sha256
        } else {
            return Err(SdkError::Trust);
        };
        if expected != &installation.identity.fingerprint()
            || view.id != claims.session_id
            || view.connection_generation != claims.connection_generation
            || view.lease_sequence != claims.lease_sequence
            || claims.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let sequence = claims
            .lease_sequence
            .checked_add(1)
            .ok_or(SdkError::Invalid)?;
        let proof = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Renew as i32,
            deployment_id: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            account_id: account,
            device_id: installation.device_id.clone(),
            resource_id: view.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(&view.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&sequence.to_be_bytes()).to_vec(),
            expires_at_unix_ms: claims.expires_at_unix_ms,
        };
        Ok(URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&proof)?))
    }
    pub async fn renew_permit(
        &self,
        installation: &DeviceIdentity,
        view: &RemoteView,
        previous: &VerifiedPermit,
        host_signature: String,
    ) -> Result<VerifiedPermit, SdkError> {
        if previous.claims().controller_device_id != installation.device_id {
            return Err(SdkError::Trust);
        }
        let body = RenewalSubmission {
            lease_sequence: previous
                .claims()
                .lease_sequence
                .checked_add(1)
                .ok_or(SdkError::Invalid)?,
            controller_signature: self.renewal_signature(installation, view, previous)?,
            host_signature,
        };
        let response: PermitResponse = self
            .required(
                Method::POST,
                &format!("{}/renew", resource("remote", &view.id)?),
                Some(&body),
            )
            .await?;
        self.verify_response(&view.id, response)
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn submit_native_renewal(
        &self,
        id: &str,
        sequence: u64,
        controller_signature: String,
        host_signature: String,
    ) -> Result<VerifiedPermit, SdkError> {
        let body = RenewalSubmission {
            lease_sequence: sequence,
            controller_signature,
            host_signature,
        };
        let response: PermitResponse = self
            .required(
                Method::POST,
                &format!("{}/renew", resource("remote", id)?),
                Some(&body),
            )
            .await?;
        self.verify_response(id, response)
    }
    fn verify_response(
        &self,
        id: &str,
        response: PermitResponse,
    ) -> Result<VerifiedPermit, SdkError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(response.permit)
            .map_err(|_| SdkError::Invalid)?;
        let verified = verify_permit(&bytes, &self.trust.permit_issuer)?;
        if verified.claims() != &response.claims
            || verified.claims().deployment_id != self.trust.deployment_id
            || verified.claims().security_epoch != self.health.security_epoch
            || verified.claims().session_id != id
            || verified.claims().account_id != self.principal().ok_or(SdkError::SignIn)?.account_id
        {
            return Err(SdkError::Trust);
        }
        Ok(verified)
    }
    async fn required<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R, SdkError> {
        self.call(method, path, body, true)
            .await?
            .ok_or(SdkError::Invalid)
    }
    async fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        authenticated: bool,
    ) -> Result<Option<R>, SdkError> {
        let token = if authenticated {
            Some(self.login.as_ref().ok_or(SdkError::SignIn)?.access.expose())
        } else {
            None
        };
        request(
            &self.client,
            &self.origin,
            method,
            path,
            body.map(serde_json::to_value).transpose()?,
            token,
        )
        .await
    }
}
fn resource(kind: &str, id: &str) -> Result<String, SdkError> {
    if !valid_id(id) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("/{kind}/{id}"))
}
fn saved_management_origin(input: &str) -> Result<String, SdkError> {
    // Older exports used Url::as_str(), which appends a root slash. Accept
    // exactly that legacy spelling while retaining the normal origin checks:
    // paths, queries, userinfo, insecure schemes and further normalization fail.
    let canonical = input.strip_suffix('/').unwrap_or(input);
    parse_origin(canonical, false)?;
    Ok(canonical.to_owned())
}
fn parse_origin(input: &str, allow_loopback: bool) -> Result<Url, SdkError> {
    let origin = Url::parse(input).map_err(|_| SdkError::Invalid)?;
    let local = match origin.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if origin.origin().ascii_serialization() != input
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || (origin.scheme() != "https" && !(allow_loopback && local && origin.scheme() == "http"))
    {
        return Err(SdkError::Invalid);
    }
    Ok(origin)
}
#[cfg(not(target_arch = "wasm32"))]
async fn request<R: DeserializeOwned>(
    client: &Client,
    origin: &Url,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> Result<Option<R>, SdkError> {
    let url = origin
        .join(&format!("{API_BASE}{path}"))
        .map_err(|_| SdkError::Invalid)?;
    let mut request = client
        .request(method, url)
        .header("Origin", origin.origin().ascii_serialization())
        .timeout(Duration::from_secs(15));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status();
    if response.content_length().is_some_and(|v| v > CONTROL_BYTES) {
        return Err(SdkError::Invalid);
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > CONTROL_BYTES as usize {
            return Err(SdkError::Invalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    decode_response(status, &bytes)
}
fn decode_response<R: DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
) -> Result<Option<R>, SdkError> {
    if !status.is_success() {
        let error: ErrorResponse = serde_json::from_slice(bytes).map_err(|_| SdkError::Invalid)?;
        return Err(SdkError::Api(status, error.code));
    }
    if status == StatusCode::NO_CONTENT {
        if !bytes.is_empty() {
            return Err(SdkError::Invalid);
        }
        return Ok(None);
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(bytes)?))
}
