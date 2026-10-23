#![allow(dead_code)] // Shared real-service fixtures are used by different test binaries.
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
};
use nestlink_app_core::{
    Action, AppCore, ApprovedServer, Completion, CoreHandle, OperationStatus, Ticket,
};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const PASSWORD: &str = "app-core-real-http-password";
pub fn password() -> Secret {
    Secret::from_text(PASSWORD.into())
}
pub fn seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub struct Server {
    pub config: ApprovedServer,
    forbidden_responses: Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    pub async fn start(gate: Option<Arc<Gate>>) -> Result<Self> {
        Self::start_with_namespace_entry(gate, false).await
    }
    pub async fn namespace_entry(gate: Option<Arc<Gate>>) -> Result<Self> {
        Self::start_with_namespace_entry(gate, true).await
    }
    async fn start_with_namespace_entry(
        gate: Option<Arc<Gate>>,
        namespace_entry: bool,
    ) -> Result<Self> {
        let deployment_id = random_id();
        let signer = PermitSigner::generate();
        let permit_issuer = signer.public_key();
        let mut store = Store::in_memory(&deployment_id)?;
        store.bootstrap_admin("admin", PASSWORD)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let state = AppState::new(
            store,
            VaultKey::from_bytes([17; 32]),
            signer,
            origin.clone(),
            false,
        )?;
        let mut app: Router = router(state.clone());
        if namespace_entry {
            // An explicit test reverse proxy forwards namespace requests into a
            // configured DNS management entry sharing the real registry. The SDK
            // retains its loopback trust proof; no business response is mocked.
            let entry =
                router(state.for_management_entry("https://manage.example.com".into(), true));
            app = app.layer(middleware::from_fn(
                move |mut request: Request, next: Next| {
                    let entry = entry.clone();
                    async move {
                        if request.uri().path().ends_with("/service-namespace") {
                            use tower::ServiceExt;
                            request.headers_mut().insert(
                                "origin",
                                axum::http::HeaderValue::from_static("https://manage.example.com"),
                            );
                            // Rebuild route extensions at this test proxy
                            // boundary; duplicate Axum path parameters would
                            // reject Path<String> before the real handler.
                            request.extensions_mut().clear();
                            match entry.oneshot(request).await {
                                Ok(response) => response,
                                Err(never) => match never {},
                            }
                        } else {
                            next.run(request).await
                        }
                    }
                },
            ));
        }
        let forbidden_responses = Arc::new(std::sync::Mutex::new(Vec::new()));
        app = app.layer(middleware::from_fn_with_state(
            forbidden_responses.clone(),
            observe_forbidden_responses,
        ));
        if let Some(gate) = gate {
            app = app.layer(middleware::from_fn_with_state(gate, intercept));
        }
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        Ok(Self {
            config: ApprovedServer {
                origin,
                deployment_id,
                permit_issuer,
                allow_loopback_http: true,
            },
            forbidden_responses,
            task,
        })
    }

    pub fn forbidden_responses(&self) -> Vec<String> {
        self.forbidden_responses
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

async fn observe_forbidden_responses(
    State(events): State<Arc<std::sync::Mutex<Vec<String>>>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path();
    let category = if path.ends_with("/reconnect/offer") {
        "reconnect_offer"
    } else if path.ends_with("/reconnect/approve") {
        "reconnect_approve"
    } else if path.ends_with("/reconnect") {
        if method == "GET" {
            "reconnect_status"
        } else {
            "reconnect_commit"
        }
    } else if path.ends_with("/permit") {
        "permit"
    } else if path.contains("/remote/") {
        "remote_resource"
    } else {
        "other_api"
    };
    let response = next.run(request).await;
    if response.status().as_u16() == 403
        && let Ok(mut events) = events.lock()
        && events.len() < 32
    {
        events.push(format!("{method} {category} 403"));
    }
    response
}

pub async fn done(ticket: Ticket) -> Result<Completion> {
    Ok(tokio::time::timeout(Duration::from_secs(10), ticket.wait()).await??)
}
pub async fn success(ticket: Ticket) -> Result<Completion> {
    let completion = done(ticket).await?;
    assert_eq!(
        completion.result.status,
        OperationStatus::Succeeded,
        "{:?}",
        completion.result
    );
    Ok(completion)
}
pub async fn connect(core: &AppCore, server: &Server) -> Result<CoreHandle> {
    let handle = core.handle();
    success(handle.switch_server(ApprovedServer::from_origin(
        server.config.origin.clone(),
        server.config.allow_loopback_http,
    ))?)
    .await?;
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    Ok(handle)
}
pub async fn wait_view(
    handle: &CoreHandle,
    predicate: impl Fn(&nestlink_app_core::Snapshot) -> bool,
) -> Result {
    let mut view = handle.observe();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if predicate(&view.borrow_and_update()) {
                return Ok::<(), tokio::sync::watch::error::RecvError>(());
            }
            view.changed().await?;
        }
    })
    .await??;
    Ok(())
}

enum GatePath {
    Exact(String),
    Suffix(String),
}

/// Holds one actual server response after its transaction/read completed. No
/// SDK or business response is mocked. Short expiry only changes the announced
/// access lifetime, testing the client's deadline independently of server TTL.
pub struct Gate {
    path: GatePath,
    pub method: &'static str,
    pub enabled: AtomicBool,
    pub arrived: Semaphore,
    pub release: Semaphore,
    pub logout_responses: AtomicUsize,
    pub shorten_lifetime: bool,
}
impl Gate {
    pub fn new(path: impl Into<String>, method: &'static str) -> Arc<Self> {
        Self::matching(GatePath::Exact(path.into()), method)
    }
    pub fn suffix(path: impl Into<String>, method: &'static str) -> Arc<Self> {
        Self::matching(GatePath::Suffix(path.into()), method)
    }
    fn matching(path: GatePath, method: &'static str) -> Arc<Self> {
        Arc::new(Self {
            path,
            method,
            enabled: AtomicBool::new(false),
            arrived: Semaphore::new(0),
            release: Semaphore::new(0),
            logout_responses: AtomicUsize::new(0),
            shorten_lifetime: false,
        })
    }
    pub fn expiring() -> Arc<Self> {
        Arc::new(Self {
            path: GatePath::Exact(String::new()),
            method: "",
            enabled: AtomicBool::new(false),
            arrived: Semaphore::new(0),
            release: Semaphore::new(0),
            logout_responses: AtomicUsize::new(0),
            shorten_lifetime: true,
        })
    }
    pub fn arm(&self) {
        self.enabled.store(true, Ordering::Release);
    }
    pub async fn entered(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(5), self.arrived.acquire())
            .await??
            .forget();
        Ok(())
    }
    pub fn unblock(&self) {
        self.release.add_permits(1);
    }
}
async fn intercept(State(gate): State<Arc<Gate>>, request: Request, next: Next) -> Response {
    let login = request.uri().path() == "/api/v3/auth/login";
    let me = request.uri().path() == "/api/v3/auth/me";
    let refresh = request.uri().path() == "/api/v3/auth/refresh";
    let logout = request.uri().path() == "/api/v3/auth/logout";
    let matches_path = match &gate.path {
        GatePath::Exact(path) => request.uri().path() == path.as_str(),
        GatePath::Suffix(path) => request.uri().path().ends_with(path.as_str()),
    };
    let hold = matches_path
        && request.method() == gate.method
        && gate.enabled.swap(false, Ordering::AcqRel);
    let mut response = next.run(request).await;
    if logout && response.status().is_success() {
        gate.logout_responses.fetch_add(1, Ordering::AcqRel);
    }
    if gate.shorten_lifetime && (login || me || refresh) && response.status().is_success() {
        response = match shorten_lifetime(response).await {
            Ok(response) => response,
            Err(error) => {
                panic!("Could not prepare the real-service expiry fixture: {error}");
            }
        };
    }
    if hold {
        gate.arrived.add_permits(1);
        if let Ok(permit) = gate.release.acquire().await {
            permit.forget();
        }
    }
    response
}

async fn shorten_lifetime(response: Response) -> Result<Response> {
    let (mut parts, body) = response.into_parts();
    let bytes = to_bytes(body, nestlink_protocol::CONTROL_BYTES as usize).await?;
    let mut data: serde_json::Value = serde_json::from_slice(&bytes)?;
    data["principal"]["access_expires"] =
        serde_json::json!(seconds()?.checked_add(1).ok_or("test clock overflow")?);
    let body = serde_json::to_vec(&data)?;
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(body)))
}
