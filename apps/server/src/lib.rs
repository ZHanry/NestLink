mod audit;
pub mod config;
mod connection_diagnostics;
mod database_admission;
mod media_authority;
mod native_discovery;
mod network_policy;
mod node_control;
mod node_discovery;
pub mod node_quic;
pub mod node_relay;
mod node_relay_attributes;
mod node_turn;
mod quotas;
mod reconnection;
mod relay;
pub mod relay_selector;
mod remote_password;
pub mod service_edge;
mod service_publication;
mod service_usage;
mod services;
mod spaces;
mod trusted;
mod turn;
use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, token};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{
    CONTROL_BYTES, ErrorCode,
    api::{
        ApprovalSubmission, BrowserEndpointRegistration, DeviceRegistration, Login, NewAccount,
        PasswordChange, PathLimitUpdate, PolicyUpdate, Refresh, RemotePeerKeys, RemoteRequest,
        RenewalSubmission, RevokeDevice, ServerIdentityChallenge, ServerIdentityClaims,
        ServerIdentityProof, SignalSubmission,
    },
};
use nestlink_storage::{
    StorageError, Store,
    accounts::{LoginGrant, MemberDraft, PasswordVerification, Principal},
};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, broadcast};

type RateBuckets = HashMap<String, HashMap<String, (Instant, u32)>>;

#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    vault: Arc<VaultKey>,
    signer: Arc<PermitSigner>,
    dummy_hash: Arc<String>,
    work: database_admission::DatabaseAdmission,
    passwords: Arc<Semaphore>,
    events: broadcast::Sender<Event>,
    origin: Arc<String>,
    secure_cookies: bool,
    rates: Arc<Mutex<RateBuckets>>,
    relays: Arc<relay::RelayHub>,
    relay_lifecycle: Arc<nestlink_storage::relay_reservations::RelayLifecycle>,
    service_lifecycle: Arc<nestlink_storage::services::publication::ServiceLifecycle>,
    service_signer: Arc<nestlink_identity::service_plane::ServiceLeaseSigner>,
    node_signer: Arc<nestlink_identity::nodes::NodePolicySigner>,
    network_signer: Arc<nestlink_identity::network::NetworkAuthoritySigner>,
    node_connections: Arc<Semaphore>,
    event_connections: Arc<Semaphore>,
    event_accounts: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    stun_servers: Arc<Vec<std::net::SocketAddr>>,
    allow_pcp_mapping: bool,
    connection_diagnostics: Arc<connection_diagnostics::SignalDiagnostics>,
}
#[derive(Clone, Serialize)]
struct Event {
    kind: String,
    resource_id: Option<String>,
    payload: Value,
    #[serde(skip)]
    audience: Option<Vec<String>>,
}
#[derive(Debug)]
pub struct ApiError(StatusCode, ErrorCode);
impl From<StorageError> for ApiError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Unauthorized => Self(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired),
            StorageError::Forbidden => Self(StatusCode::FORBIDDEN, ErrorCode::PermissionRequired),
            StorageError::Conflict => Self(StatusCode::CONFLICT, ErrorCode::ReplayRejected),
            StorageError::RateLimited => {
                Self(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded)
            }
            StorageError::Invalid(_) | StorageError::Json(_) | StorageError::Auth(_) => {
                Self(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage)
            }
            StorageError::Proof(e) => Self(StatusCode::FORBIDDEN, e.code),
            StorageError::Sqlite(rusqlite_error) => {
                if rusqlite_error
                    .sqlite_error_code()
                    .is_some_and(|c| c == rusqlite::ErrorCode::ConstraintViolation)
                {
                    Self(StatusCode::CONFLICT, ErrorCode::InvalidMessage)
                } else {
                    tracing::error!(event = "database_failed", code = ?rusqlite_error.sqlite_error_code(), "database operation failed");
                    Self(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
                }
            }
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"code":self.1}))).into_response()
    }
}
impl AppState {
    /// Deployment-owned configuration, never sourced from request or peer data.
    pub fn with_pcp_mapping(mut self, allowed: bool) -> Self {
        self.allow_pcp_mapping = allowed;
        self
    }

    pub fn with_stun_servers(
        mut self,
        servers: Vec<std::net::SocketAddr>,
    ) -> Result<Self, StorageError> {
        nestlink_protocol::api::NativeDiscoveryConfig {
            deployment_id: self
                .store
                .lock()
                .map_err(|_| StorageError::Conflict)?
                .deployment_id()?,
            stun_servers: servers.clone(),
        }
        .validate()?;
        self.stun_servers = Arc::new(servers);
        Ok(self)
    }
    /// Configures another trusted management entry for this control instance.
    /// All database, event, quota and runtime owners remain shared. The origin
    /// must come from listener configuration, never from request headers.
    pub fn for_management_entry(&self, origin: String, secure_cookies: bool) -> Self {
        let mut entry = self.clone();
        entry.origin = Arc::new(origin);
        entry.secure_cookies = secure_cookies;
        entry
    }

    pub fn new(
        mut store: Store,
        vault: VaultKey,
        signer: PermitSigner,
        origin: String,
        secure_cookies: bool,
    ) -> Result<Self, StorageError> {
        let (events, _) = broadcast::channel(128);
        let dummy_hash = hash_password(token().expose())?;
        let node_signer = signer.node_policy_signer()?;
        let network_signer = signer.network_authority_signer()?;
        let relay_quota = store.relay_quota_current()?;
        let relay_lifecycle =
            store.relay_lifecycle(now_ms().map_err(|_| StorageError::Conflict)?)?;
        let service_lifecycle =
            store.service_lifecycle(now_ms().map_err(|_| StorageError::Conflict)?)?;
        let service_signer = signer.service_lease_signer()?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            vault: Arc::new(vault),
            signer: Arc::new(signer),
            dummy_hash: Arc::new(dummy_hash),
            work: database_admission::DatabaseAdmission::new(),
            passwords: Arc::new(Semaphore::new(2)),
            events,
            origin: Arc::new(origin),
            secure_cookies,
            rates: Arc::new(Mutex::new(HashMap::new())),
            relays: Arc::new(relay::RelayHub::new(relay_quota)),
            relay_lifecycle: Arc::new(relay_lifecycle),
            service_lifecycle: Arc::new(service_lifecycle),
            service_signer: Arc::new(service_signer),
            node_signer: Arc::new(node_signer),
            network_signer: Arc::new(network_signer),
            node_connections: Arc::new(Semaphore::new(128)),
            event_connections: Arc::new(Semaphore::new(256)),
            event_accounts: Arc::new(Mutex::new(HashMap::new())),
            stun_servers: Arc::new(Vec::new()),
            allow_pcp_mapping: false,
            connection_diagnostics: Arc::new(connection_diagnostics::SignalDiagnostics::default()),
        })
    }
    pub fn start_maintenance(&self) {
        let store = Arc::downgrade(&self.store);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                let Some(store) = store.upgrade() else {
                    return;
                };
                let result = tokio::task::spawn_blocking(move || {
                    let mut store = store.lock().map_err(|_| StorageError::Conflict)?;
                    store.cleanup_remote_signals(now()?)
                })
                .await;
                if !matches!(result, Ok(Ok(_))) {
                    tracing::warn!(
                        event = "signal_cleanup_failed",
                        "bounded signal maintenance failed"
                    );
                }
            }
        });
    }
    async fn db<R, F>(&self, action: F) -> Result<R, ApiError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store) -> Result<R, StorageError> + Send + 'static,
    {
        self.db_admission(action, false).await
    }
    async fn db_revocation<R, F>(&self, action: F) -> Result<R, ApiError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store) -> Result<R, StorageError> + Send + 'static,
    {
        self.db_admission(action, true).await
    }
    async fn db_admission<R, F>(&self, action: F, revocation: bool) -> Result<R, ApiError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store) -> Result<R, StorageError> + Send + 'static,
    {
        let admission = if revocation {
            self.work.acquire_revocation().await
        } else {
            self.work.acquire().await
        };
        let permit = admission.map_err(|_| {
            tracing::warn!(
                event = "database_capacity_exhausted",
                revocation,
                "bounded database queue is full or its wait deadline expired"
            );
            ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded)
        })?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut store = store.lock().map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
            })?;
            action(&mut store).map_err(ApiError::from)
        })
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?
    }
    async fn cpu<R, F>(&self, action: F) -> Result<R, ApiError>
    where
        R: Send + 'static,
        F: FnOnce() -> Result<R, StorageError> + Send + 'static,
    {
        let permit =
            self.passwords.clone().try_acquire_owned().map_err(|_| {
                ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded)
            })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            action().map_err(ApiError::from)
        })
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?
    }
    async fn password_proof(
        &self,
        token: String,
        password: Secret,
    ) -> Result<PasswordVerification, ApiError> {
        let snapshot = self
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.password_snapshot(&p)
            })
            .await?;
        self.cpu(move || snapshot.verify(password.expose())).await
    }
    fn emit(
        &self,
        kind: &str,
        resource: Option<String>,
        audience: Option<Vec<String>>,
        payload: Value,
    ) {
        let _ = self.events.send(Event {
            kind: kind.into(),
            resource_id: resource,
            audience,
            payload,
        });
    }
    fn limit(&self, bucket: &str) -> Result<(), ApiError> {
        self.limit_with_budget(bucket, 30)
    }
    fn limit_with_budget(&self, bucket: &str, maximum: u32) -> Result<(), ApiError> {
        let mut rates = self
            .rates
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
        let namespace = bucket.split('/').next().unwrap_or("other");
        let rates = rates.entry(namespace.into()).or_default();
        rates.retain(|_, (start, _)| start.elapsed().as_secs() < 60);
        if !rates.contains_key(bucket) && rates.len() >= 2048 {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::CapacityExceeded,
            ));
        }
        let (_, count) = rates.entry(bucket.into()).or_insert((Instant::now(), 0));
        *count = count.saturating_add(1);
        if *count > maximum {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::CapacityExceeded,
            ));
        }
        Ok(())
    }
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v3/health", get(health))
        .route("/api/v3/health/proof", post(server_identity_proof))
        .route(
            "/api/v3/network/discovery",
            get(native_discovery::configuration),
        )
        .route(
            "/api/v3/discovery/native/pcp",
            get(native_discovery::pcp_policy),
        )
        .route(
            "/api/v3/network/spaces/{space}/authority",
            get(network_policy::authority)
                .put(network_policy::configure)
                .delete(network_policy::revoke_authority),
        )
        .route(
            "/api/v3/network/spaces/{space}/authority/rotate",
            post(network_policy::rotate_authority),
        )
        .route(
            "/api/v3/network/spaces/{space}/policy/advance",
            post(network_policy::advance_epoch),
        )
        .route(
            "/api/v3/network/spaces",
            get(spaces::list).post(spaces::create),
        )
        .route("/api/v3/network/spaces/{space}", get(spaces::details))
        .route(
            "/api/v3/network/spaces/{space}/archive",
            post(spaces::archive),
        )
        .route(
            "/api/v3/network/spaces/{space}/people/{account}",
            put(spaces::update_member).delete(spaces::remove_member),
        )
        .route(
            "/api/v3/network/spaces/{space}/devices",
            post(spaces::join_device),
        )
        .route(
            "/api/v3/network/spaces/{space}/devices/{installation}",
            delete(spaces::remove_device),
        )
        .route(
            "/api/v3/network/spaces/{space}/invitations",
            post(spaces::invite),
        )
        .route(
            "/api/v3/network/spaces/{space}/invitations/{invitation}",
            delete(spaces::revoke_invitation),
        )
        .route(
            "/api/v3/network/spaces/{space}/invitations/{invitation}/accept",
            post(spaces::accept_invitation),
        )
        .route("/api/v3/network/spaces/{space}/audit", get(spaces::audit))
        .route(
            "/api/v3/network/spaces/{space}/services",
            get(spaces::service_policy),
        )
        .route(
            "/api/v3/network/spaces/{space}/addressing",
            get(spaces::addressing::list),
        )
        .route(
            "/api/v3/network/spaces/{space}/addresses",
            post(spaces::addressing::issue),
        )
        .route(
            "/api/v3/network/spaces/{space}/addresses/{installation}/reservation",
            put(spaces::addressing::reserve),
        )
        .route(
            "/api/v3/network/spaces/{space}/addresses/{installation}/name",
            put(spaces::addressing::rename),
        )
        .route(
            "/api/v3/network/spaces/{space}/addresses/{installation}",
            delete(spaces::addressing::revoke),
        )
        .route(
            "/api/v3/network/spaces/{space}/services/{service}",
            put(spaces::bind_service).delete(spaces::revoke_service),
        )
        .route(
            "/api/v3/network/spaces/{space}/services/{service}/rules",
            post(spaces::grant_service_rule),
        )
        .route(
            "/api/v3/network/spaces/{space}/services/{service}/rules/{rule}",
            delete(spaces::revoke_service_rule),
        )
        .route(
            "/api/v3/network/spaces/{space}/policy",
            get(network_policy::policy),
        )
        .route(
            "/api/v3/network/spaces/{space}/members/{installation}",
            get(network_policy::member)
                .put(network_policy::set_member)
                .delete(network_policy::revoke_member),
        )
        .route(
            "/api/v3/network/spaces/{space}/members/{installation}/grants",
            post(network_policy::issue),
        )
        .route(
            "/api/v3/network/spaces/{space}/grants/{grant}",
            get(network_policy::read_grant).delete(network_policy::revoke_grant),
        )
        .route(
            "/api/v3/network/spaces/{space}/remote/{request}/paths",
            post(network_policy::issue_path),
        )
        .route(
            "/api/v3/network/spaces/{space}/topology/publishers/{node}",
            get(network_policy::topology::publisher)
                .post(network_policy::topology::issue)
                .delete(network_policy::topology::revoke),
        )
        .route(
            "/api/v3/network/spaces/{space}/topology/reports/{node}",
            post(network_policy::topology::report),
        )
        .route(
            "/api/v3/network/spaces/{space}/topology/query",
            post(network_policy::topology::query),
        )
        .route(
            "/api/v3/network/spaces/{space}/route-exports/{node}",
            post(network_policy::route_exports::issue),
        )
        .route(
            "/api/v3/network/spaces/{space}/route-export-grants/{grant}",
            get(network_policy::route_exports::read).delete(network_policy::route_exports::revoke),
        )
        .route(
            "/api/v3/network/spaces/{space}/paths/{path}",
            get(network_policy::read_path).delete(network_policy::revoke_path),
        )
        .route(
            "/api/v3/network/spaces/{space}/remote/{request}/relays",
            post(network_policy::issue_relay),
        )
        .route(
            "/api/v3/network/spaces/{space}/relays/{allocation}",
            get(network_policy::read_relay).delete(network_policy::revoke_relay),
        )
        .route("/api/v3/relay/quota", get(quotas::get).put(quotas::set))
        .route(
            "/api/v3/network/spaces/{space}/remote/{request}/relay-chains",
            post(network_policy::chains::issue),
        )
        .route(
            "/api/v3/network/spaces/{space}/relay-chains/{route}",
            get(network_policy::chains::read).delete(network_policy::chains::revoke),
        )
        .route(
            "/api/v3/network/spaces/{space}/remote/{request}/route-sets",
            post(network_policy::route_sets::issue),
        )
        .route(
            "/api/v3/network/spaces/{space}/route-sets/{set}",
            get(network_policy::route_sets::read).delete(network_policy::route_sets::revoke),
        )
        .route("/api/v3/relay/usage", get(quotas::usage))
        .route("/api/v3/relay/reservations", get(relay::reservations))
        .route(
            "/api/v3/remote/{id}/relay/allocation",
            post(relay::allocate),
        )
        .route("/api/v3/audit", get(audit::query))
        .route(
            "/api/v3/audit/retention",
            get(audit::retention).put(audit::configure),
        )
        .route("/api/v3/auth/login", post(login))
        .route("/api/v3/auth/refresh", post(refresh))
        .route("/api/v3/auth/restore", post(restore_login))
        .route("/api/v3/auth/logout", post(logout))
        .route("/api/v3/auth/me", get(me))
        .route("/api/v3/auth/password", put(password))
        .route("/api/v3/accounts", get(accounts).post(create_account))
        .route("/api/v3/accounts/{id}", delete(disable_account))
        .route("/api/v3/devices/challenge", post(challenge))
        .route("/api/v3/devices", get(devices).post(register_device))
        .route("/api/v3/devices/browser", post(register_browser_endpoint))
        .route("/api/v3/devices/{id}", delete(revoke_device))
        .route(
            "/api/v3/devices/{id}/media/{direction}",
            get(media_authority::get).put(media_authority::replace),
        )
        .route("/api/v3/remote/media", post(media_authority::request))
        .route("/api/v3/remote/{id}/media", get(media_authority::scope))
        .route(
            "/api/v3/remote/{id}/media/approval",
            post(media_authority::approve),
        )
        .route(
            "/api/v3/devices/{id}/features",
            post(refresh_browser_features),
        )
        .route("/api/v3/devices/{id}/trust", get(trusted::list))
        .route(
            "/api/v3/devices/{id}/remote-password",
            get(remote_password::inspect)
                .put(remote_password::configure)
                .delete(remote_password::revoke),
        )
        .route(
            "/api/v3/devices/{id}/trust/{controller}",
            delete(trusted::revoke),
        )
        .route(
            "/api/v3/nodes",
            get(node_control::nodes).post(node_control::register),
        )
        .route("/api/v3/nodes/{id}", delete(node_control::revoke))
        .route(
            "/api/v3/nodes/{id}/relay-attributes",
            get(node_relay_attributes::get).put(node_relay_attributes::update),
        )
        .route(
            "/api/v3/nodes/{id}/endpoints",
            get(node_discovery::endpoints).put(node_discovery::update),
        )
        .route(
            "/api/v3/nodes/{id}/turn-endpoints",
            get(turn::endpoints).put(turn::configure),
        )
        .route("/api/v3/nodes/{id}/control", get(node_control::upgrade))
        .route("/api/v3/nodes/{id}/usage", get(node_control::usage))
        .route("/api/v3/nodes/{id}/report", post(node_control::report))
        .route("/api/v3/nodes/{id}/close", post(node_control::close))
        .route(
            "/api/v3/nodes/{id}/resources",
            post(node_control::resources),
        )
        .route(
            "/api/v3/nodes/{id}/turn-resources",
            post(node_turn::resources),
        )
        .route(
            "/api/v3/services",
            get(services::list).post(services::create),
        )
        .route(
            "/api/v3/services/{id}",
            get(services::inspect)
                .put(services::update)
                .delete(services::revoke),
        )
        .route(
            "/api/v3/services/{id}/approval/challenge",
            post(services::challenge),
        )
        .route("/api/v3/services/{id}/approval", post(services::approve))
        .route(
            "/api/v3/nodes/{id}/service-namespace",
            get(service_publication::namespace).put(service_publication::set_namespace),
        )
        .route(
            "/api/v3/nodes/{id}/service-resources",
            post(service_publication::resources),
        )
        .route(
            "/api/v3/nodes/{id}/service-usage",
            post(service_usage::report),
        )
        .route(
            "/api/v3/nodes/{id}/service-usage-stop",
            post(service_usage::stop),
        )
        .route(
            "/api/v3/service-usage/quota",
            get(service_usage::admin_usage).put(service_usage::set_limit),
        )
        .route(
            "/api/v3/services/{id}/publication",
            get(service_publication::inspect)
                .post(service_publication::publish)
                .delete(service_publication::stop),
        )
        .route("/api/v3/policy", get(policy).put(update_policy))
        .route("/api/v3/policy/scopes", get(path_limits))
        .route("/api/v3/policy/scopes/{scope}/{id}", put(update_path_limit))
        .route("/api/v3/remote", get(pending).post(create_remote))
        .route("/api/v3/remote/native-ready/{id}", get(native_ready))
        .route("/api/v3/remote/browser-ready/{id}", get(browser_ready))
        .route(
            "/api/v3/remote/{id}/browser-host-ready",
            get(browser_host_readiness).post(mark_browser_host_ready),
        )
        .route("/api/v3/remote/trusted", post(trusted::connect))
        .route("/api/v3/remote/{id}", get(remote).delete(revoke_remote))
        .route("/api/v3/remote/{id}/peer-keys", get(remote_peer_keys))
        .route("/api/v3/remote/{id}/approval", post(approve))
        .route("/api/v3/remote/{id}/trust", post(trusted::grant))
        .route(
            "/api/v3/remote/{id}/password",
            get(remote_password::offer).post(remote_password::authorize),
        )
        .route(
            "/api/v3/remote/{id}/permit",
            get(current_permit).post(permit),
        )
        .route("/api/v3/remote/{id}/renew", post(renew))
        .route(
            "/api/v3/remote/{id}/reconnect",
            get(reconnection::status).post(reconnection::commit),
        )
        .route(
            "/api/v3/remote/{id}/reconnect/offer",
            post(reconnection::offer),
        )
        .route(
            "/api/v3/remote/{id}/reconnect/approve",
            post(reconnection::approve),
        )
        .route("/api/v3/remote/{id}/relay", get(relay::upgrade))
        .route(
            "/api/v3/remote/{id}/relay/discovery",
            post(node_discovery::discover),
        )
        .route(
            "/api/v3/remote/{id}/relay/candidates",
            post(node_discovery::candidates),
        )
        .route(
            "/api/v3/remote/{id}/turn-credentials",
            post(turn::credentials),
        )
        .route(
            "/api/v3/remote/{id}/turn-peers",
            get(turn::peers).post(turn::prove_peers),
        )
        .route(
            "/api/v3/remote/{id}/signals",
            get(signals).post(submit_signal),
        )
        .route("/api/v3/events", get(events))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, ErrorCode::ProtocolMismatch) })
        .layer(DefaultBodyLimit::max(CONTROL_BYTES as usize))
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .with_state(state)
}
async fn security(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    let started = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let method = request.method().clone();
    let mut response = security_inner(state, request, next).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    if response.status().is_server_error() || elapsed_ms >= 1000 {
        tracing::warn!(event = "management_request", request_id, route, %method, status, elapsed_ms);
    } else {
        tracing::debug!(event = "management_request", request_id, route, %method, status, elapsed_ms);
    }
    if response.status().is_client_error()
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"))
    {
        let status = response.status();
        let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
            ErrorCode::CapacityExceeded
        } else {
            ErrorCode::InvalidMessage
        };
        response = ApiError(status, code).into_response();
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}
async fn security_inner(state: AppState, request: Request<Body>, next: Next) -> Response {
    if request.uri().path() == "/api/v3/auth/login"
        || (request.uri().path().split('/').nth(3) == Some("nodes")
            && request.uri().path().ends_with("/control"))
        || (request.uri().path().split('/').nth(3) == Some("nodes")
            && request.uri().path().ends_with("/report"))
        || (request.uri().path().split('/').nth(3) == Some("nodes")
            && request.uri().path().ends_with("/close"))
    {
        let peer = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|v| v.0.ip().to_string())
            .unwrap_or_else(|| "local".into());
        // The listener is loopback-only. Caddy replaces this header in the shipped recipe.
        let forwarded = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            .map(|v| v.to_string());
        let bucket = if request.uri().path() == "/api/v3/auth/login" {
            "login-ip"
        } else if request.uri().path().ends_with("/report") {
            "node-report-ip"
        } else if request.uri().path().ends_with("/close") {
            "node-close-ip"
        } else {
            "node-control-ip"
        };
        let maximum = if matches!(bucket, "node-report-ip" | "node-close-ip") {
            8192
        } else {
            30
        };
        if let Err(error) =
            state.limit_with_budget(&format!("{bucket}/{}", forwarded.unwrap_or(peer)), maximum)
        {
            return error.into_response();
        }
    }
    if request.uri().path() == "/api/v3/auth/password" {
        let token = match access(request.headers()) {
            Ok(token) => token,
            Err(error) => return error.into_response(),
        };
        let principal = match state.db(move |s| s.authenticate(&token, now()?)).await {
            Ok(principal) => principal,
            Err(error) => return error.into_response(),
        };
        if let Err(error) = state.limit(&format!("factor/{}", principal.session_id)) {
            return error.into_response();
        }
    }
    if request
        .headers()
        .get(header::ORIGIN)
        .is_some_and(|origin| origin.to_str().ok() != Some(state.origin.as_str()))
    {
        return ApiError(StatusCode::FORBIDDEN, ErrorCode::PermissionRequired).into_response();
    }
    if request.headers().get(header::COOKIE).is_some()
        && request.method() != axum::http::Method::GET
        && request.headers().get(header::ORIGIN).is_none()
    {
        return ApiError(StatusCode::FORBIDDEN, ErrorCode::PermissionRequired).into_response();
    }
    next.run(request).await
}
fn now() -> Result<u64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| StorageError::Invalid("system clock unavailable"))
}
fn now_ms() -> Result<u64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::Invalid("system clock unavailable"))?
        .as_millis()
        .try_into()
        .map_err(|_| StorageError::Invalid("invalid system clock"))
}
fn access(headers: &HeaderMap) -> Result<String, ApiError> {
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        let value = value
            .to_str()
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired))?;
        return value
            .strip_prefix("Bearer ")
            .filter(|v| v.len() == 43)
            .map(String::from)
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired));
    }
    cookie(headers, "nl15_access")
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired))
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && value.len() == 43).then(|| value.into())
        })
}
fn cookies(state: &AppState, grant: &LoginGrant) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    for (name, value, age) in [
        ("nl15_access", grant.access_token.expose(), 300),
        ("nl15_refresh", grant.refresh_token.expose(), 604800),
    ] {
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{name}={value}; HttpOnly; SameSite=Strict; Path=/api/v3; Max-Age={age}{secure}"
            ))
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?,
        );
    }
    Ok(headers)
}
fn login_response(state: &AppState, grant: LoginGrant) -> Result<Response, ApiError> {
    let mut headers = cookies(state, &grant)?;
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "nl15_restore_{}={}; HttpOnly; SameSite=Strict; Path=/api/v3/auth; Max-Age=604800{}",
            grant.principal.session_id,
            grant.refresh_token.expose(),
            secure
        ))
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?,
    );
    Ok((headers,Json(json!({"principal":grant.principal,"access_token":grant.access_token.expose(),"refresh_token":grant.refresh_token.expose(),"generation":grant.generation,"refresh_expires":grant.refresh_expires}))).into_response())
}
async fn path_limits(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok(Json(json!({"limits":s.path_limits(&p)?})))
        })
        .await
}
async fn update_path_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((scope, id)): Path<(String, String)>,
    Json(body): Json<PathLimitUpdate>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let revision = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.set_path_limit(&p, &scope, &id, &body.path_mode, body.expected_revision)
        })
        .await?;
    state.emit("policy_revoked", None, None, json!({"revision":revision}));
    Ok(Json(json!({"revision":revision})))
}
async fn health(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let issuer = URL_SAFE_NO_PAD.encode(state.signer.public_key());
    let node_issuer = URL_SAFE_NO_PAD.encode(state.node_signer.public_key());
    state.db(move|s|Ok(Json(json!({"product":"NestLink","version":env!("CARGO_PKG_VERSION"),"api_base":"/api/v3","alpn":"nestlink/1","deployment_id":s.deployment_id()?,"security_epoch":s.security_epoch()?,"permit_issuer":issuer,"node_policy_issuer":node_issuer,"native_ice_version":1})))).await
}
async fn server_identity_proof(
    State(state): State<AppState>,
    Json(challenge): Json<ServerIdentityChallenge>,
) -> Result<Json<ServerIdentityProof>, ApiError> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&challenge.nonce)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    if nonce.len() != 32 || URL_SAFE_NO_PAD.encode(&nonce) != challenge.nonce {
        return Err(ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage));
    }
    let (deployment_id, security_epoch) = state
        .db(|store| Ok((store.deployment_id()?, store.security_epoch()?)))
        .await?;
    let claims = ServerIdentityClaims {
        nonce: challenge.nonce,
        management_origin: state.origin.as_ref().clone(),
        product: "NestLink".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        api_base: "/api/v3".into(),
        alpn: "nestlink/1".into(),
        deployment_id,
        security_epoch,
        permit_issuer: URL_SAFE_NO_PAD.encode(state.signer.public_key()),
        node_policy_issuer: URL_SAFE_NO_PAD.encode(state.node_signer.public_key()),
    };
    let signature = state
        .signer
        .sign_server_identity(&claims)
        .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.code))?;
    Ok(Json(ServerIdentityProof {
        claims,
        signature: URL_SAFE_NO_PAD.encode(signature),
    }))
}
async fn login(
    State(state): State<AppState>,
    Json(body): Json<Login>,
) -> Result<Response, ApiError> {
    // User-controlled names never become unbounded rate-cache keys.
    state.limit(&format!(
        "login/{}",
        URL_SAFE_NO_PAD.encode(nestlink_auth::token_hash(
            "login-name",
            &body.username.to_lowercase()
        ))
    ))?;
    let vault = state.vault.clone();
    let dummy = state.dummy_hash.clone();
    let password = Secret::from_text(body.password);
    let factor = body.factor.map(Secret::from_text);
    let snapshot = state
        .db(move |s| s.login_snapshot(&body.username, now()?, &dummy))
        .await?;
    let verified = state
        .cpu(move || Ok(snapshot.verify(password.expose())))
        .await?;
    let grant = state
        .db(move |s| {
            s.complete_login(
                verified,
                factor.as_ref().map(|s| s.expose()),
                now()?,
                &vault,
            )
        })
        .await?;
    login_response(&state, grant)
}
async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Refresh>,
) -> Result<Response, ApiError> {
    let refresh = body
        .refresh_token
        .or_else(|| cookie(&headers, "nl15_refresh"))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired))?;
    let vault = state.vault.clone();
    let grant = state
        .db(move |s| s.refresh_login_recoverable(&refresh, body.generation, now()?, &vault))
        .await?;
    login_response(&state, grant)
}
async fn restore_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<nestlink_protocol::api::RestoreLogin>,
) -> Result<Response, ApiError> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(state.origin.as_str()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionRequired,
        ));
    }
    if !nestlink_protocol::valid_id(&body.session_id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage));
    }
    let refresh = cookie(&headers, &format!("nl15_restore_{}", body.session_id))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::AuthRequired))?;
    let vault = state.vault.clone();
    let grant = state
        .db(move |s| s.restore_browser_login(&body.session_id, &refresh, now()?, &vault))
        .await?;
    login_response(&state, grant)
}
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let principal = s.authenticate(&token, now()?)?;
            Ok(Json(json!({"principal":principal})))
        })
        .await
}
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token = access(&headers)?;
    let (account, session) = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.logout(&p)?;
            Ok((p.account_id, p.session_id))
        })
        .await?;
    state.emit(
        "authentication_changed",
        None,
        Some(vec![account]),
        json!({}),
    );
    let mut h = HeaderMap::new();
    h.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "nl15_restore_{session}=; HttpOnly; SameSite=Strict; Path=/api/v3/auth; Max-Age=0"
        ))
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?,
    );
    for name in ["nl15_access", "nl15_refresh"] {
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{name}=; HttpOnly; SameSite=Strict; Path=/api/v3; Max-Age=0"
            ))
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?,
        );
    }
    Ok((h, StatusCode::NO_CONTENT).into_response())
}
async fn password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasswordChange>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let vault = state.vault.clone();
    let proof = state
        .password_proof(token, Secret::from_text(body.current_password))
        .await?;
    let replacement = Secret::from_text(body.new_password);
    let factor = body.factor.map(Secret::from_text);
    let proof = state
        .cpu(move || proof.replacement(replacement.expose()))
        .await?;
    let account = proof.actor().account_id.clone();
    state
        .db(move |s| {
            s.complete_password_change(proof, factor.as_ref().map(|s| s.expose()), now()?, &vault)
        })
        .await?;
    state.emit(
        "authentication_changed",
        None,
        Some(vec![account]),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
async fn accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok(Json(json!({"accounts":s.accounts(&p)?})))
        })
        .await
}
async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewAccount>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    state
        .db(move |s| {
            let p = s.authenticate(&check, now()?)?;
            if p.is_admin {
                Ok(())
            } else {
                Err(StorageError::Forbidden)
            }
        })
        .await?;
    let password = Secret::from_text(body.password);
    let draft = state
        .cpu(move || MemberDraft::derive(&body.username, password.expose()))
        .await?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok((
                StatusCode::CREATED,
                Json(json!({"id":s.complete_member(&p,draft)?})),
            ))
        })
        .await
}
async fn disable_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let account = id.clone();
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.disable_account(&p, &id)
        })
        .await?;
    state.emit("account_revoked", None, Some(vec![account]), json!({}));
    Ok(StatusCode::NO_CONTENT)
}
async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok(Json(serde_json::to_value(
                s.enrollment_challenge(&p, now()?)?,
            )?))
        })
        .await
}
async fn devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok(Json(json!({"devices":s.devices_at(&p, now()?)?})))
        })
        .await
}
async fn refresh_browser_features(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DeviceRegistration>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            s.refresh_browser_features(&p, &id, body, at)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}
async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceRegistration>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.register_device(&p, body, now()?)
        })
        .await?;
    Ok(StatusCode::CREATED)
}
async fn register_browser_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BrowserEndpointRegistration>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let token = access(&headers)?;
    let lease = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.register_browser_endpoint(&p, body, now()?)
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(lease).map_err(StorageError::from)?),
    ))
}
async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RevokeDevice>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.revoke_device_as(&p, &body.request_id, &id, now()?)?;
            Ok(p.account_id)
        })
        .await?;
    state.emit(
        "device_revoked",
        Some(resource),
        Some(vec![audience]),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
async fn policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            s.authenticate(&token, now()?)?;
            let (revision, policy) = s.policy()?;
            Ok(Json(json!({"revision":revision,"policy":policy})))
        })
        .await
}
async fn update_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyUpdate>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let revision = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            if !p.is_admin {
                return Err(StorageError::Forbidden);
            }
            s.apply_policy_as(
                &p,
                now()?,
                body.expected_revision,
                serde_json::from_value(serde_json::to_value(body.policy)?)?,
            )
        })
        .await?;
    state.emit("policy_revoked", None, None, json!({"revision":revision}));
    Ok(Json(json!({"revision":revision})))
}
#[derive(Deserialize, Default)]
struct PendingQuery {
    after: Option<String>,
}
async fn pending(
    State(state): State<AppState>,
    Query(query): Query<PendingQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            let requests = s.pending_remote_page(&p, now()?, query.after.as_deref())?;
            let next_cursor = (requests.len() == 100)
                .then(|| requests.last().map(|r| r.id.clone()))
                .flatten();
            Ok(Json(
                json!({"requests":requests, "next_cursor": next_cursor}),
            ))
        })
        .await
}
async fn native_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let time = now()?;
            let principal = s.authenticate(&token, time)?;
            Ok(Json(
                json!({"requests": s.ready_native_remote(&principal, &id, time)?}),
            ))
        })
        .await
}
async fn browser_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let time = now()?;
            let principal = s.authenticate(&token, time)?;
            Ok(Json(
                json!({"requests": s.ready_browser_remote(&principal, &id, time)?}),
            ))
        })
        .await
}

async fn browser_host_readiness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<nestlink_protocol::api::BrowserHostReadiness>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let time = now()?;
                let principal = s.authenticate(&token, time)?;
                s.browser_host_readiness(&principal, &id, time)
            })
            .await?,
    ))
}

async fn mark_browser_host_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<nestlink_protocol::api::BrowserHostReadinessSubmission>,
) -> Result<Json<nestlink_protocol::api::BrowserHostReadiness>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let time = now()?;
                let principal = s.authenticate(&token, time)?;
                s.mark_browser_host_ready(&principal, &id, body, time)
            })
            .await?,
    ))
}

async fn remote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            Ok(Json(serde_json::to_value(s.remote(&p, &id)?)?))
        })
        .await
}
async fn create_remote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RemoteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let token = access(&headers)?;
    let (view, audience) = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            let view = s.create_remote(&p, body, now()?)?;
            let audience = s.remote_event_accounts(&view.id)?;
            Ok((view, audience))
        })
        .await?;
    state.emit(
        "approval_requested",
        Some(view.id.clone()),
        Some(audience),
        json!({}),
    );
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(view).map_err(StorageError::from)?),
    ))
}
async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ApprovalSubmission>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.approve_remote(&p, &id, body.choice, &body.signature, now()?)?;
            s.remote_event_accounts(&id)
        })
        .await?;
    state.emit(
        "approval_changed",
        Some(resource),
        Some(audience),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
async fn permit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let claims = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.initial_permit(&p, &id, now()?)
        })
        .await?;
    let signed = state.signer.sign(&claims).map_err(StorageError::from)?;
    Ok(Json(
        json!({"permit":URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),"claims":claims}),
    ))
}
async fn remote_peer_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RemotePeerKeys>, ApiError> {
    let token = access(&headers)?;
    let keys = state
        .db(move |store| {
            let now = now()?;
            let principal = store.authenticate(&token, now)?;
            store.remote_peer_keys(&principal, &id, now)
        })
        .await?;
    Ok(Json(keys))
}

async fn current_permit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let claims = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.current_permit(&p, &id, now()?)
        })
        .await?;
    let signed = state.signer.sign(&claims).map_err(StorageError::from)?;
    Ok(Json(
        json!({"permit":URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),"claims":claims}),
    ))
}
async fn renew(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RenewalSubmission>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let claims = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.renew_permit(&p, &id, body, now()?)
        })
        .await?;
    let signed = state.signer.sign(&claims).map_err(StorageError::from)?;
    Ok(Json(
        json!({"permit":URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),"claims":claims}),
    ))
}
async fn signals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let diagnostics = state.connection_diagnostics.clone();
    state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            let signals = s.remote_signals(&p, &id, now()?)?;
            for signal in &signals {
                diagnostics.record(
                    &id,
                    &p.session_id,
                    &signal.submission.device_id,
                    nestlink_protocol::diagnostics::ConnectionStage::SignalResponsePrepared,
                    signal.submission.payload.connection_generation,
                    nestlink_protocol::diagnostics::SignalSummary::from_payload(
                        &signal.submission.payload,
                    ),
                );
            }
            Ok(Json(json!({"signals": signals})))
        })
        .await
}
async fn submit_signal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SignalSubmission>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    state.limit(&format!("signal/{}", principal.session_id))?;
    let resource = id.clone();
    let diagnostics = state.connection_diagnostics.clone();
    let audience = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            let sender = body.device_id.clone();
            let generation = body.payload.connection_generation;
            let summary =
                nestlink_protocol::diagnostics::SignalSummary::from_payload(&body.payload);
            s.submit_signal(&p, &id, body, now()?)?;
            diagnostics.record(
                &id,
                &p.session_id,
                &sender,
                nestlink_protocol::diagnostics::ConnectionStage::SignalAccepted,
                generation,
                summary,
            );
            s.remote_event_accounts(&id)
        })
        .await?;
    state.emit("signal_changed", Some(resource), Some(audience), json!({}));
    Ok(StatusCode::NO_CONTENT)
}
async fn revoke_remote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.revoke_remote(&p, &id)?;
            s.remote_event_accounts(&id)
        })
        .await?;
    state.emit("remote_revoked", Some(resource), Some(audience), json!({}));
    Ok(StatusCode::NO_CONTENT)
}
async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    let global = state
        .event_connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded))?;
    let account = {
        let mut accounts = state
            .event_accounts
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
        accounts.retain(|_, slots| slots.available_permits() < 4);
        accounts
            .entry(principal.account_id.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(4)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded))?
    };
    let subscription = state.events.subscribe();
    Ok(ws
        .max_message_size(CONTROL_BYTES as usize)
        .max_frame_size(CONTROL_BYTES as usize)
        .on_upgrade(move |socket| async move {
            let _slots = (global, account);
            event_loop(socket, state, principal, token, subscription).await;
        }))
}
async fn event_loop(
    mut socket: WebSocket,
    state: AppState,
    principal: Principal,
    token: String,
    mut subscription: broadcast::Receiver<Event>,
) {
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut verified_at = Instant::now();
    loop {
        tokio::select! {
            _=heartbeat.tick()=>{
                let token=token.clone();
                match state.db(move|s|s.authenticate(&token,now()?)).await {
                    Ok(_) => verified_at = Instant::now(),
                    Err(ApiError(StatusCode::TOO_MANY_REQUESTS, _)) if verified_at.elapsed().as_secs() < 15 => {},
                    Err(_) => break,
                }
            },
            event=subscription.recv()=>{match event{Ok(event)if event.audience.as_ref().is_none_or(|v|v.contains(&principal.account_id))=>{let Ok(text)=serde_json::to_string(&event)else{break;};if !bounded_send(&mut socket,Message::Text(text.into())).await {break;}},Ok(_)=>{},Err(_)=>break,}},
            input=socket.recv()=>{match input{Some(Ok(Message::Ping(bytes)))=>{if !bounded_send(&mut socket,Message::Pong(bytes)).await {break;}},Some(Ok(Message::Pong(_)))=>{},_=>break,}}
        }
    }
    bounded_send(&mut socket, Message::Close(None)).await;
}
async fn bounded_send(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(std::time::Duration::from_millis(250), socket.send(message)).await,
        Ok(Ok(()))
    )
}
