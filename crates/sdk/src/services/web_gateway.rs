//! One explicitly authorized installation exposes one fixed private HTTP service.
//! Hyper owns HTTP/1 framing and upgrades; the existing private SDK and original
//! host retain possession proofs, target TLS, durable budget and revocation.
use super::LocalProxyServiceChoice;
use crate::{DeviceIdentity, Sdk, SdkError};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use nestlink_auth::{Secret, token, token_hash};
use reqwest::cookie::Jar;
use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use url::Url;
mod headers;
#[cfg(test)]
mod probe_tests;
mod tls;

const MAX_CONNECTIONS: usize = 32;
const SETUP: Duration = Duration::from_secs(3);
const TICKET_LIFETIME: Duration = Duration::from_secs(60);
const SESSION_COOKIE: &str = "__Host-nl_private_web";

/// The outer TLS terminator must enforce exact SNI/Host and set the generated
/// private-hop headers. Only its random loopback endpoint is bound here.
pub struct PrivateWebGatewayConfig {
    pub listen: SocketAddr,
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateWebGatewayStopReport {
    pub accepted_connections: u64,
    pub completed_workers: u64,
    pub failed_workers: u64,
    pub cleanup_failures: u64,
    pub listener_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateWebGatewayWait {
    CleanupPending,
    Stopped(PrivateWebGatewayStopReport),
    CleanupFailed(PrivateWebGatewayStopReport),
}

pub struct PrivateWebGateway {
    address: SocketAddr,
    origin: String,
    launch: Secret,
    private_hop: Secret,
    upstream_certificate: String,
    upstream_server_name: String,
    context: Arc<Context>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<PrivateWebGatewayStopReport>>,
    report: Option<PrivateWebGatewayStopReport>,
    runtime: tokio::runtime::Handle,
}

impl PrivateWebGateway {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Public correlation only. This value grants no service or browser access.
    pub fn owner_id(&self) -> &str {
        &self.context.owner_id
    }
    /// Invalidate the previous ticket atomically, keeping this same service,
    /// original expiry and quota. A consumed session can never be relaunched.
    pub fn renew_launch_url(&mut self) -> Result<String, SdkError> {
        let now = Instant::now();
        let mut admission = self.context.admission.lock().map_err(|_| SdkError::Trust)?;
        if *self.stop.borrow()
            || now >= self.context.deadline
            || admission.ticket_used
            || admission.session.is_some()
        {
            return Err(SdkError::Trust);
        }
        let launch = token();
        admission.ticket = Some((
            token_hash("private-web-launch", launch.expose()),
            self.context.deadline.min(now + TICKET_LIFETIME),
        ));
        self.launch = launch;
        Ok(self.launch_url())
    }
    pub fn public_route_probe(&self) -> Result<PrivateWebRouteProbe, SdkError> {
        self.route_probe(None)
    }
    /// Explicit native-local trust for an enterprise/test public HTTPS origin.
    /// The browser must independently trust this CA. No remote launch request
    /// can choose the CA, and default WebPKI roots are disabled for this mode.
    pub fn public_route_probe_with_root(&self, ca_der: &[u8]) -> Result<PrivateWebRouteProbe, SdkError> {
        if ca_der.is_empty() || ca_der.len() > 16_384 { return Err(SdkError::Invalid); }
        self.route_probe(Some(reqwest::Certificate::from_der(ca_der)?))
    }
    fn route_probe(&self, root: Option<reqwest::Certificate>) -> Result<PrivateWebRouteProbe, SdkError> {
        let mut client = reqwest::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).timeout(SETUP);
        if let Some(root) = root { client = client.tls_built_in_root_certs(false).add_root_certificate(root); }
        Ok(PrivateWebRouteProbe {
            client: client.build()?,
            url: format!("{}/.nestlink/ready", self.origin),
            owner_id: self.owner_id().to_owned(),
        })
    }
    /// Contains a single-use capability. Save only in an owner-private file.
    /// It belongs in a URL fragment, never a query, log or Referer.
    pub fn launch_url(&self) -> String {
        format!("{}/.nestlink/launch#{}", self.origin, self.launch.expose())
    }
    /// A route for a dedicated Caddy HTTPS server with strict_sni_host=true.
    /// The serialized value contains the private-hop secret and must be private.
    pub fn caddy_route(&self) -> serde_json::Value {
        let host = Url::parse(&self.origin)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default();
        serde_json::json!({"match":[{"host":[host]}],"terminal":true,"handle":[{
            "handler":"reverse_proxy","upstreams":[{"dial":self.address.to_string()}],
            "transport":{"protocol":"http","versions":["1.1"],"keep_alive":{"enabled":false},
                "tls":{"ca":{"provider":"inline","trusted_ca_certs":[self.upstream_certificate]},"server_name":self.upstream_server_name}},
            "headers":{"request":{"set":{
                "X-NestLink-Token":[self.private_hop.expose()],
                "X-NestLink-Scheme":["{http.request.scheme}"],
                "X-NestLink-SNI":["{http.request.tls.server_name}"]
            }}},"flush_interval":-1,"stream_close_delay":"1h"
        }]})
    }
    pub fn is_finished(&self) -> bool {
        self.report.is_some() || self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn request_shutdown(&self) {
        self.stop.send_replace(true);
    }
    /// Keep this same owner after a timeout. It retains every HTTP/upgraded
    /// worker and the original private carrier's physical release receipt.
    pub async fn wait_stopped(&mut self, budget: Duration) -> PrivateWebGatewayWait {
        self.request_shutdown();
        if let Some(task) = self.task.as_mut() {
            match tokio::time::timeout(budget, &mut *task).await {
                Err(_) => return PrivateWebGatewayWait::CleanupPending,
                Ok(result) => {
                    self.report = Some(result.unwrap_or_else(|_| PrivateWebGatewayStopReport {
                        cleanup_failures: 1,
                        ..Default::default()
                    }));
                    self.task.take();
                }
            }
        }
        let report = self
            .report
            .clone()
            .unwrap_or_else(|| PrivateWebGatewayStopReport {
                cleanup_failures: 1,
                ..Default::default()
            });
        if report.listener_closed && report.cleanup_failures == 0 {
            PrivateWebGatewayWait::Stopped(report)
        } else {
            PrivateWebGatewayWait::CleanupFailed(report)
        }
    }
}
/// A fixed public HTTPS readiness check. It sends no management authorization,
/// private-hop header, installation proof, browser cookie or launch ticket.
pub struct PrivateWebRouteProbe {
    client: reqwest::Client,
    url: String,
    owner_id: String,
}
impl PrivateWebRouteProbe {
    pub async fn check(&self) -> Result<bool, SdkError> {
        let mut response = self.client.get(&self.url).send().await?;
        if response.status() != reqwest::StatusCode::OK
            || response.content_length().is_some_and(|length| length > 64)
        {
            return Ok(false);
        }
        let mut bytes = Vec::with_capacity(64);
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > 64 - bytes.len() {
                return Ok(false);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes == self.owner_id.as_bytes())
    }
}
impl Drop for PrivateWebGateway {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}

struct BrowserSession {
    cookie_hash: [u8; 32],
    stopped: watch::Sender<bool>,
    cookies: Jar,
    cookie_bytes: AtomicUsize,
}
struct BrowserAdmission {
    ticket: Option<([u8; 32], Instant)>,
    session: Option<Arc<BrowserSession>>,
    ticket_used: bool,
}
struct Context {
    owner_id: String,
    sdk: Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    choice: LocalProxyServiceChoice,
    origin: Url,
    backend: Url,
    hop_hash: [u8; 32],
    admission: Mutex<BrowserAdmission>,
    stopped: watch::Receiver<bool>,
    shutdown: watch::Sender<bool>,
    deadline: Instant,
}
struct Forward {
    request: Request<Incoming>,
    upgrade: Option<hyper::upgrade::OnUpgrade>,
    session: Arc<BrowserSession>,
    response: oneshot::Sender<Response<Body>>,
}
enum WorkerError {
    Forward,
    Cleanup,
}

impl Sdk {
    /// The local caller selects an existing private directory entry and an
    /// explicitly enrolled gateway installation. A browser cannot choose a URL,
    /// local port, service, space, relay or target through this listener.
    pub async fn start_private_web_gateway(
        self: &Arc<Self>,
        consumer: Arc<DeviceIdentity>,
        choice: LocalProxyServiceChoice,
        config: PrivateWebGatewayConfig,
    ) -> Result<PrivateWebGateway, SdkError> {
        self.principal().ok_or(SdkError::SignIn)?;
        if !config.listen.ip().is_loopback() || !nestlink_protocol::valid_id(&consumer.device_id) {
            return Err(SdkError::Invalid);
        }
        let origin = headers::origin(&config.origin, &self.origin)?;
        if !origin.host_str().is_some_and(|host| {
            host.starts_with(&format!("{}.", choice.selected_entry().service.id))
        }) {
            return Err(SdkError::Invalid);
        }
        let backend =
            headers::backend(&choice.selected_entry().service.definition.requested_ingress)?;
        let tls = tls::UpstreamTls::generate(choice.lifetime())?;
        let deadline = Instant::now() + choice.lifetime();
        #[cfg(any(target_os = "linux", windows))]
        let listener = super::local_proxy::bind_tcp(config.listen).await?;
        #[cfg(not(any(target_os = "linux", windows)))]
        let listener = TcpListener::bind(config.listen).await?;
        let address = listener.local_addr()?;
        let launch = token();
        let private_hop = token();
        let (stop, stopped) = watch::channel(false);
        let context = Arc::new(Context {
            owner_id: nestlink_auth::random_id(),
            sdk: self.clone(),
            consumer,
            choice,
            origin: origin.clone(),
            backend,
            hop_hash: token_hash("private-web-hop", private_hop.expose()),
            admission: Mutex::new(BrowserAdmission {
                ticket: Some((
                    token_hash("private-web-launch", launch.expose()),
                    deadline.min(Instant::now() + TICKET_LIFETIME),
                )),
                session: None,
                ticket_used: false,
            }),
            stopped,
            shutdown: stop.clone(),
            deadline,
        });
        let task = tokio::spawn(run_owner(context.clone(), listener, tls.acceptor));
        Ok(PrivateWebGateway {
            address,
            origin: origin.origin().ascii_serialization(),
            launch,
            private_hop,
            upstream_certificate: tls.certificate,
            upstream_server_name: tls.server_name,
            context,
            stop,
            task: Some(task),
            report: None,
            runtime: tokio::runtime::Handle::current(),
        })
    }
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() || stop.changed().await.is_err() {
            return;
        }
    }
}
fn response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    headers::browser_response(response.headers_mut());
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}
fn finish(
    report: &mut PrivateWebGatewayStopReport,
    result: Option<Result<Result<(), WorkerError>, tokio::task::JoinError>>,
) {
    report.completed_workers += 1;
    match result {
        Some(Ok(Ok(()))) => {}
        Some(Ok(Err(WorkerError::Forward))) => report.failed_workers += 1,
        Some(Ok(Err(WorkerError::Cleanup))) => {
            report.failed_workers += 1;
            report.cleanup_failures += 1;
        }
        _ => report.cleanup_failures += 1,
    }
}
async fn run_owner(
    context: Arc<Context>,
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> PrivateWebGatewayStopReport {
    let mut report = PrivateWebGatewayStopReport::default();
    let (sender, mut queue) = mpsc::channel::<Forward>(MAX_CONNECTIONS);
    let mut workers = JoinSet::new();
    let mut stop = context.stopped.clone();
    loop {
        tokio::select! {biased;
            _=stopped(&mut stop)=>break,
            _=tokio::time::sleep_until(context.deadline)=>break,
            result=workers.join_next(),if !workers.is_empty()=>finish(&mut report,result),
            work=queue.recv()=>{
                let Some(work)=work else {break;};
                if workers.len()>=MAX_CONNECTIONS*2 {let _=work.response.send(response(StatusCode::SERVICE_UNAVAILABLE));continue;}
                workers.spawn(forward(context.clone(),work));
            },
            accepted=listener.accept()=>{
                let Ok((socket,peer))=accepted else {report.cleanup_failures+=1;break;};
                report.accepted_connections+=1;
                if !peer.ip().is_loopback() || workers.len()>=MAX_CONNECTIONS {drop(socket);continue;}
                let acceptor=acceptor.clone();
                let context=context.clone();let sender=sender.clone();let mut stop=context.stopped.clone();
                workers.spawn(async move {
                    let deadline=context.deadline;
                    let socket=tokio::select! {biased;
                        _=stopped(&mut stop)=>return Ok(()),
                        result=tokio::time::timeout_at(deadline.min(Instant::now()+SETUP),acceptor.accept(socket))=>match result {
                            Ok(Ok(socket))=>socket,
                            _=>return Err(WorkerError::Forward),
                        },
                    };
                    let service=service_fn(move |request|handle(context.clone(),sender.clone(),request));
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    // Disabling Hyper keep-alive appends `close` even to 101's
                    // Connection: upgrade. Ordinary responses close explicitly;
                    // upgraded responses retain only the valid upgrade header.
                    builder.keep_alive(true).max_headers(128).max_buf_size(32768).timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(2));
                    let connection=builder.serve_connection(TokioIo::new(socket),service).with_upgrades();
                    tokio::select! {biased;
                        _=stopped(&mut stop)=>Ok(()),
                        _=tokio::time::sleep_until(deadline)=>Ok(()),
                        result=connection=>result.map_err(|_|WorkerError::Forward),
                    }
                });
            }
        }
    }
    drop(listener);
    report.listener_closed = true;
    context.shutdown.send_replace(true);
    // The receiver closes ordinary HTTP sockets; session stop closes upgraded
    // streams whose outer Hyper driver already returned its upgrade ownership.
    if let Ok(mut admission) = context.admission.lock() {
        admission.ticket.take();
        if let Some(session) = admission.session.take() {
            session.stopped.send_replace(true);
        }
    }
    queue.close();
    while let Some(work) = queue.recv().await {
        let _ = work
            .response
            .send(response(StatusCode::SERVICE_UNAVAILABLE));
    }
    // Own stop can be false on natural expiry; every worker also uses deadline.
    while !workers.is_empty() {
        finish(&mut report, workers.join_next().await);
    }
    report
}

async fn handle(
    context: Arc<Context>,
    sender: mpsc::Sender<Forward>,
    mut request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let result = async {
        if Instant::now() >= context.deadline || *context.stopped.borrow() {
            return response(StatusCode::SERVICE_UNAVAILABLE);
        }
        if headers::authenticate(&request, &context.origin, &context.hop_hash).is_err() {
            return response(StatusCode::FORBIDDEN);
        }
        let path = request.uri().path();
        if path == "/.nestlink/ready" {
            if request.method() != hyper::Method::GET || request.uri().query().is_some() {
                return response(StatusCode::BAD_REQUEST);
            }
            let mut ready = response(StatusCode::OK);
            *ready.body_mut() = Body::from(context.owner_id.clone());
            return ready;
        }
        if path == "/.nestlink/launch" {
            if request.method() != hyper::Method::GET || request.uri().query().is_some() {
                return response(StatusCode::BAD_REQUEST);
            }
            let mut page = response(StatusCode::OK);
            page.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            *page.body_mut() = Body::from(headers::LAUNCH_PAGE);
            return page;
        }
        if path == "/.nestlink/session" {
            if request.method() != hyper::Method::POST
                || !headers::same_origin(request.headers(), &context.origin)
                || request.uri().query().is_some()
            {
                return response(StatusCode::FORBIDDEN);
            }
            let Some(ticket) = headers::launch_ticket(request.headers()) else {
                return response(StatusCode::UNAUTHORIZED);
            };
            let Ok(mut admission) = context.admission.lock() else {
                return response(StatusCode::SERVICE_UNAVAILABLE);
            };
            if !admission.ticket.as_ref().is_some_and(|(hash, end)| {
                Instant::now() < *end && *hash == token_hash("private-web-launch", ticket)
            }) {
                return response(StatusCode::UNAUTHORIZED);
            }
            admission.ticket.take();
            admission.ticket_used = true;
            let cookie = token();
            let (stopped, _) = watch::channel(false);
            admission.session = Some(Arc::new(BrowserSession {
                cookie_hash: token_hash("private-web-cookie", cookie.expose()),
                stopped,
                cookies: Jar::default(),
                cookie_bytes: AtomicUsize::new(0),
            }));
            let mut issued = response(StatusCode::NO_CONTENT);
            let value = format!(
                "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                cookie.expose(),
                context
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            );
            if let Ok(value) = value.parse() {
                issued
                    .headers_mut()
                    .insert(hyper::header::SET_COOKIE, value);
            } else {
                return response(StatusCode::SERVICE_UNAVAILABLE);
            }
            return issued;
        }
        let session = {
            let Ok(admission) = context.admission.lock() else {
                return response(StatusCode::SERVICE_UNAVAILABLE);
            };
            let Some(session) = admission.session.as_ref() else {
                return response(StatusCode::UNAUTHORIZED);
            };
            let Some(cookie) = headers::session_cookie(request.headers()) else {
                return response(StatusCode::UNAUTHORIZED);
            };
            if *session.stopped.borrow()
                || session.cookie_hash != token_hash("private-web-cookie", cookie)
            {
                return response(StatusCode::UNAUTHORIZED);
            }
            session.clone()
        };
        if path == "/.nestlink/logout" {
            if request.method() != hyper::Method::POST
                || !headers::same_origin(request.headers(), &context.origin)
            {
                return response(StatusCode::FORBIDDEN);
            }
            session.stopped.send_replace(true);
            if let Ok(mut admission) = context.admission.lock() {
                admission.session.take();
            }
            let mut removed = response(StatusCode::NO_CONTENT);
            removed.headers_mut().insert(
                hyper::header::SET_COOKIE,
                hyper::header::HeaderValue::from_static(
                    "__Host-nl_private_web=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
                ),
            );
            return removed;
        }
        if path.starts_with("/.nestlink/") {
            return response(StatusCode::NOT_FOUND);
        }
        let websocket = match headers::application_request(
            &mut request,
            &context.origin,
            &context.backend,
            &session,
        ) {
            Ok(upgrade) => upgrade,
            Err(_) => return response(StatusCode::FORBIDDEN),
        };
        let upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let (response_tx, response_rx) = oneshot::channel();
        if sender
            .try_send(Forward {
                request,
                upgrade,
                session,
                response: response_tx,
            })
            .is_err()
        {
            return response(StatusCode::SERVICE_UNAVAILABLE);
        }
        match response_rx.await {
            Ok(response) => response,
            Err(_) => response(StatusCode::BAD_GATEWAY),
        }
    }
    .await;
    Ok(result)
}

async fn admit(
    context: &Context,
) -> Result<nestlink_identity::services::private::VerifiedPrivateServiceLease, SdkError> {
    let request = context.choice.access_request(&context.consumer)?;
    let lease = context
        .sdk
        .request_private_service(&context.choice.selected_entry().service.id, request)
        .await?;
    if !context.choice.checks_lease(&lease) {
        return Err(SdkError::Trust);
    }
    Ok(lease)
}
async fn forward(context: Arc<Context>, work: Forward) -> Result<(), WorkerError> {
    let mut stop = context.stopped.clone();
    let mut session_stop = work.session.stopped.subscribe();
    let setup_deadline = context.deadline.min(Instant::now() + SETUP);
    let lease = tokio::select! {biased;
        _=stopped(&mut stop)=>return Ok(()),
        _=stopped(&mut session_stop)=>return Ok(()),
        result=tokio::time::timeout_at(setup_deadline,admit(&context))=>match result {
            Ok(Ok(lease))=>lease,
            _=>{let _=work.response.send(response(StatusCode::FORBIDDEN));return Ok(());}
        },
    };
    let connecting = context.sdk.connect_private_service_with_relay_policy(
        &context.consumer,
        lease,
        context.choice.relay_policy(),
    );
    tokio::pin!(connecting);
    let admitted = tokio::select! {biased;
        _=stopped(&mut stop)=>None,
        _=stopped(&mut session_stop)=>None,
        _=tokio::time::sleep_until(setup_deadline)=>None,
        result=&mut connecting=>Some(result),
    };
    let mut connection = match admitted {
        Some(Ok(connection)) => connection,
        Some(Err(_)) => return Err(WorkerError::Cleanup),
        None => {
            let mut connection = connecting.await.map_err(|_| WorkerError::Cleanup)?;
            connection.close().await.map_err(|_| WorkerError::Cleanup)?;
            return Ok(());
        }
    };
    let lease = connection.lease().clone();
    let grant: Result<nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims, _> =
        nestlink_protocol::service_plane::decode_service_message(
            &lease.lease().claims().usage_grant.claims,
            nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
        );
    let grant = match grant {
        Ok(grant) => grant,
        Err(_) => {
            connection.close().await.map_err(|_| WorkerError::Cleanup)?;
            return Err(WorkerError::Forward);
        }
    };
    let monitor = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let current = context
                .sdk
                .current_private_service(
                    &context.choice.selected_entry().service.id,
                    &grant.grant_id,
                )
                .await?;
            if current.digest() != lease.digest() {
                return Err::<(), SdkError>(SdkError::Trust);
            }
        }
    };
    let transfer = async {
        let stream = connection.take_stream().map_err(io::Error::other)?;
        let (mut sender, http) =
            hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
        let exchange = async {
            let backend = headers::application_url(
                &context.backend,
                work.request
                    .uri()
                    .path_and_query()
                    .ok_or_else(|| io::Error::other("private web request path missing"))?
                    .as_str(),
            )?;
            let mut upstream = sender
                .send_request(work.request)
                .await
                .map_err(io::Error::other)?;
            drop(sender);
            let websocket = work.upgrade.is_some();
            if (upstream.status() == StatusCode::SWITCHING_PROTOCOLS) != websocket {
                return Err(io::Error::other("private web upgrade was refused"));
            }
            let upgraded = websocket.then(|| hyper::upgrade::on(&mut upstream));
            headers::application_response(
                upstream.headers_mut(),
                &context.origin,
                &backend,
                &work.session,
                websocket,
            )?;
            if work.response.send(upstream.map(Body::new)).is_err() {
                return Err(io::Error::other("private web browser disconnected"));
            }
            if let (Some(browser), Some(upstream)) = (work.upgrade, upgraded) {
                let (browser, upstream) =
                    tokio::try_join!(browser, upstream).map_err(io::Error::other)?;
                tokio::io::copy_bidirectional(
                    &mut TokioIo::new(browser),
                    &mut TokioIo::new(upstream),
                )
                .await?;
            }
            Ok::<(), io::Error>(())
        };
        tokio::try_join!(
            async { http.with_upgrades().await.map_err(io::Error::other) },
            exchange
        )?;
        Ok::<(), io::Error>(())
    };
    let result = tokio::select! {biased;
        _=stopped(&mut stop)=>Ok(()),
        _=stopped(&mut session_stop)=>Ok(()),
        _=tokio::time::sleep_until(context.deadline)=>Ok(()),
        _=monitor=>Ok(()),
        result=transfer=>result,
    };
    connection.close().await.map_err(|_| WorkerError::Cleanup)?;
    result.map_err(|_| WorkerError::Forward)
}
