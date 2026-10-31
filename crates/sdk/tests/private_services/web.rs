//! L2: actual HTTP/WebSocket over the original private Quinn host, fixed target,
//! real management ACL, application cookie jar and original durable budget.
//! This exercises Caddy's strictly verified TLS loopback contract; public DNS/TLS and
//! a real browser require the separate operator HTTPS acceptance deployment.
use super::*;
use axum::{
    Router,
    body::Bytes,
    extract::{WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use nestlink_sdk::services::web_gateway::{
    PrivateWebGateway, PrivateWebGatewayConfig, PrivateWebGatewayWait,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

async fn backend_login() -> impl IntoResponse {
    (
        [(
            "Set-Cookie",
            "login=accepted; Path=/; HttpOnly; SameSite=Strict",
        )],
        "signed in",
    )
}
async fn backend_me(headers: HeaderMap) -> Response {
    if headers.get("Cookie").and_then(|value| value.to_str().ok()) != Some("login=accepted")
        || headers.get("Host").and_then(|value| value.to_str().ok())
            != Some("private.svc.example.test")
        || headers.contains_key("X-NestLink-Token")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    "authenticated fixed target".into_response()
}
async fn backend_upload(headers: HeaderMap, bytes: Bytes) -> Response {
    if headers.get("Origin").and_then(|value| value.to_str().ok())
        != Some("http://private.svc.example.test")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    bytes.into_response()
}
async fn backend_socket(headers: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    if headers.get("Cookie").and_then(|value| value.to_str().ok()) != Some("login=accepted")
        || headers.get("Origin").and_then(|value| value.to_str().ok())
            != Some("http://private.svc.example.test")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    upgrade.on_upgrade(async move |mut socket| {
        while let Some(Ok(message)) = socket.recv().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
            if socket.send(message).await.is_err() {
                break;
            }
        }
    })
}
async fn start_backend() -> Result<(SocketAddr, Abort<std::io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = Router::new()
        .route("/login", post(backend_login))
        .route("/me", get(backend_me))
        .route("/upload", post(backend_upload))
        .route("/socket", get(backend_socket))
        .route(
            "/same",
            get(|| async { ([("Location", "/me")], StatusCode::FOUND) }),
        )
        .route(
            "/outside",
            get(|| async {
                (
                    [("Location", "https://untrusted.invalid/")],
                    StatusCode::FOUND,
                )
            }),
        );
    Ok((
        address,
        Abort(tokio::spawn(
            async move { axum::serve(listener, app).await },
        )),
    ))
}
struct Browser {
    client: reqwest::Client,
    address: SocketAddr,
    origin: String,
    host: String,
    hop: String,
    cookie: Option<String>,
    upstream_name: String,
    upstream_url: String,
    tls: tokio_rustls::TlsConnector,
}
impl Browser {
    fn new(gateway: &PrivateWebGateway) -> Result<Self> {
        let route = gateway.caddy_route();
        let transport = route
            .pointer("/handle/0/transport/tls")
            .ok_or("upstream TLS missing")?;
        assert_eq!(
            transport
                .pointer("/ca/provider")
                .and_then(serde_json::Value::as_str),
            Some("inline")
        );
        assert!(transport.get("insecure_skip_verify").is_none());
        let der = STANDARD.decode(
            transport
                .pointer("/ca/trusted_ca_certs/0")
                .and_then(serde_json::Value::as_str)
                .ok_or("upstream CA missing")?,
        )?;
        let upstream_name = transport
            .get("server_name")
            .and_then(serde_json::Value::as_str)
            .ok_or("upstream name missing")?
            .to_owned();
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_der(&der)?)
            .resolve(&upstream_name, gateway.address())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(der))?;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            client,
            address: gateway.address(),
            origin: gateway.origin().into(),
            host: url::Url::parse(gateway.origin())?
                .host_str()
                .ok_or("gateway host missing")?
                .into(),
            hop: route
                .pointer("/handle/0/headers/request/set/X-NestLink-Token/0")
                .and_then(serde_json::Value::as_str)
                .ok_or("private hop missing")?
                .into(),
            cookie: None,
            upstream_url: format!("https://{upstream_name}:{}", gateway.address().port()),
            upstream_name,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.upstream_url))
            .header("Host", &self.host)
            .header("X-NestLink-Token", &self.hop)
            .header("X-NestLink-Scheme", "https")
            .header("X-NestLink-SNI", &self.host)
            .header("Sec-Fetch-Site", "same-origin");
        if let Some(cookie) = &self.cookie {
            request = request.header("Cookie", cookie);
        }
        request
    }
    async fn exchange(&mut self, gateway: &PrivateWebGateway) -> Result<String> {
        let url = gateway.launch_url();
        let ticket = url.split_once('#').ok_or("ticket missing")?.1;
        let response = self
            .request(reqwest::Method::POST, "/.nestlink/session")
            .header("Origin", &self.origin)
            .header("Authorization", format!("NestLinkTicket {ticket}"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get("Set-Cookie")
            .ok_or("session cookie missing")?
            .to_str()?;
        assert!(cookie.starts_with("__Host-nl_private_web="));
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
        assert!(!cookie.contains("Domain="));
        self.cookie = Some(cookie.split(';').next().ok_or("cookie empty")?.into());
        Ok(ticket.into())
    }
    async fn login(&self) -> Result {
        let response = self
            .request(reqwest::Method::POST, "/login")
            .header("Origin", &self.origin)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("Set-Cookie"));
        assert_eq!(response.text().await?, "signed in");
        Ok(())
    }
    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        Ok(self
            .tls
            .connect(
                ServerName::try_from(self.upstream_name.clone())?,
                TcpStream::connect(self.address).await?,
            )
            .await?)
    }
    async fn socket(
        &self,
    ) -> Result<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>>
    {
        let mut request = format!(
            "wss://{}:{}/socket",
            self.upstream_name,
            self.address.port()
        )
        .into_client_request()?;
        for (name, value) in [
            ("Host", self.host.as_str()),
            ("Origin", self.origin.as_str()),
            (
                "Cookie",
                self.cookie.as_deref().ok_or("browser session missing")?,
            ),
            ("X-NestLink-Token", self.hop.as_str()),
            ("X-NestLink-Scheme", "https"),
            ("X-NestLink-SNI", self.host.as_str()),
        ] {
            request.headers_mut().insert(
                name.parse::<tokio_tungstenite::tungstenite::http::HeaderName>()?,
                value.parse()?,
            );
        }
        let (socket, response) =
            tokio_tungstenite::client_async(request, self.connect().await?).await?;
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response
                .headers()
                .get("Connection")
                .ok_or("WebSocket Connection missing")?,
            "upgrade"
        );
        assert_eq!(
            response
                .headers()
                .get("Upgrade")
                .ok_or("WebSocket Upgrade missing")?,
            "websocket"
        );
        Ok(socket)
    }
}
async fn assert_replacement_rejected(browser: &Browser) -> Result {
    // Model an old installed Caddy route after this owner has physically stopped.
    // A different user can rebind the address and copy the public name, but has
    // neither the original CA signing key nor the original leaf private key.
    let listener = TcpListener::bind(browser.address).await?;
    let replacement = rcgen::generate_simple_self_signed(vec![browser.upstream_name.clone()])?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![replacement.cert.der().clone()],
        PrivatePkcs8KeyDer::from(replacement.signing_key.serialize_der()).into(),
    )?;
    let mut owner = Abort(tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let accepted = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(socket)
            .await;
        // No HTTP request, Cookie or private-hop header can be observed: the
        // strictly trusted client must refuse this server during the handshake.
        Ok::<_, std::io::Error>(accepted.is_ok())
    }));
    assert!(
        browser
            .request(reqwest::Method::GET, "/me")
            .send()
            .await
            .is_err()
    );
    assert!(!tokio::time::timeout(Duration::from_secs(3), &mut owner.0).await???);
    Ok(())
}
async fn finish_gateway(gateway: &mut PrivateWebGateway) -> Result {
    match gateway.wait_stopped(Duration::from_secs(5)).await {
        PrivateWebGatewayWait::Stopped(report) => {
            assert!(report.listener_closed);
            assert_eq!(report.cleanup_failures, 0);
            Ok(())
        }
        other => Err(format!("gateway cleanup receipt: {other:?}").into()),
    }
}

#[tokio::test]
async fn real_private_web_preserves_cookie_upload_redirect_and_websocket_then_logout_closes_upgrade()
-> Result {
    let (target, _backend) = start_backend().await?;
    let f = Fixture::new("http", target).await?;
    let mut host = f
        .sdk
        .start_private_service_host(
            f.host.clone(),
            f.consent,
            PrivateServiceHostConfig {
                listen: "127.0.0.1:0".parse()?,
                advertised_ip: "127.0.0.1".parse()?,
                usage_directory: f.usage.join("ledger"),
            },
        )
        .await?;
    let entry = f
        .sdk
        .private_services(&f.consumer.device_id, None, 10)
        .await?
        .entries
        .into_iter()
        .next()
        .ok_or("entry missing")?;
    let selection = nestlink_sdk::services::web_launch::PrivateWebLaunchRequest {
        schema_version: 1,
        management_origin: f.sdk.management_origin().into(),
        gateway_installation_id: f.consumer.device_id.clone(),
        service_id: entry.service.id.clone(),
        space_id: entry.exposure.space_id.clone(),
        expected_service_revision: entry.service.revision,
        expected_exposure_revision: entry.exposure.revision,
        target_sha256: entry.exposure.target_sha256,
        origin: format!("https://{}.private.example.net", f.view.id),
        maximum_bytes: 8192,
        lifetime_seconds: 20,
    };
    let selection = nestlink_sdk::services::web_launch::PrivateWebLaunchRequest::from_json(
        &serde_json::to_vec(&selection)?,
    )?;
    selection.validate(f.sdk.management_origin())?;
    assert!(selection.checks_entry(&f.consumer.device_id, &entry));
    assert!(!selection.checks_entry(&nestlink_auth::random_id(), &entry));
    let mut stale = entry.clone();
    stale.service.revision += 1;
    assert!(!selection.checks_entry(&f.consumer.device_id, &stale));
    let mut stale = entry.clone();
    stale.exposure.revision += 1;
    assert!(!selection.checks_entry(&f.consumer.device_id, &stale));
    let mut changed = entry.clone();
    changed.exposure.target_sha256 = [9; 32];
    assert!(!selection.checks_entry(&f.consumer.device_id, &changed));
    let choice = LocalProxyServiceChoice::from_local_choice(
        &entry,
        "private-web.nestlink.internal",
        443,
        8192,
        Duration::from_secs(20),
    )?;
    let origin = format!("https://{}.private.example.net", f.view.id);
    let mut gateway = f
        .sdk
        .start_private_web_gateway(
            Arc::new(f.consumer),
            choice,
            PrivateWebGatewayConfig {
                listen: "127.0.0.1:0".parse()?,
                origin,
            },
        )
        .await?;
    let mut browser = Browser::new(&gateway)?;
    let original_launch = gateway.launch_url();
    assert_ne!(gateway.renew_launch_url()?, original_launch);
    let original_ticket = original_launch
        .split_once('#')
        .ok_or("old ticket missing")?
        .1;
    assert_eq!(
        browser
            .request(reqwest::Method::POST, "/.nestlink/session")
            .header("Origin", &browser.origin)
            .header("Authorization", format!("NestLinkTicket {original_ticket}"))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let ready = browser
        .request(reqwest::Method::GET, "/.nestlink/ready")
        .send()
        .await?;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(ready.text().await?, gateway.owner_id());
    assert_eq!(
        browser
            .request(reqwest::Method::GET, "/me")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let ticket = browser.exchange(&gateway).await?;
    assert!(gateway.renew_launch_url().is_err());
    assert_eq!(
        browser
            .request(reqwest::Method::POST, "/.nestlink/session")
            .header("Origin", &browser.origin)
            .header("Authorization", format!("NestLinkTicket {ticket}"))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    browser.login().await?;
    let me = browser.request(reqwest::Method::GET, "/me").send().await?;
    assert_eq!(me.status(), StatusCode::OK);
    assert!(!me.headers().contains_key("Set-Cookie"));
    assert_eq!(me.text().await?, "authenticated fixed target");
    let upload = vec![27u8; 2048];
    let response = browser
        .request(reqwest::Method::POST, "/upload")
        .header("Origin", &browser.origin)
        .body(upload.clone())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await?.as_ref(), upload.as_slice());
    let response = browser
        .request(reqwest::Method::GET, "/same")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("Location")
            .ok_or("Location missing")?
            .to_str()?,
        format!("{}/me", browser.origin)
    );
    assert_eq!(
        browser
            .request(reqwest::Method::GET, "/outside")
            .send()
            .await?
            .status(),
        StatusCode::BAD_GATEWAY
    );
    let mut socket = browser.socket().await?;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "private websocket".into(),
        ))
        .await?;
    let echoed = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await?
        .ok_or("WebSocket ended")??;
    assert_eq!(echoed.into_text()?, "private websocket");
    assert_eq!(
        browser
            .request(reqwest::Method::POST, "/.nestlink/logout")
            .header("Origin", &browser.origin)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.next()).await?;
    assert!(
        closed.is_none()
            || matches!(
                closed,
                Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
            )
    );
    assert_eq!(
        browser
            .request(reqwest::Method::GET, "/me")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    drop(socket);
    assert!(gateway.renew_launch_url().is_err());
    finish_gateway(&mut gateway).await?;
    assert!(gateway.renew_launch_url().is_err());
    assert_replacement_rejected(&browser).await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let usage = f
                .sdk
                .service_quota_usage(ServiceQuotaUsageQuery {
                    scope: ServiceQuotaScope::Resource,
                    scope_key: f.view.id.clone(),
                })
                .await?;
            if usage.outstanding_bytes == 0 {
                assert!(usage.spent_bytes >= upload.len() as u64 * 2);
                assert_eq!(usage.limit_bytes, 131072);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    host.wait_stopped().await?;
    drop(host);
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}

#[tokio::test]
async fn real_private_web_rejects_host_origin_and_acl_revocation_closes_existing_upgrade() -> Result
{
    let (target, _backend) = start_backend().await?;
    let f = Fixture::new("http", target).await?;
    let mut host = f
        .sdk
        .start_private_service_host(
            f.host.clone(),
            f.consent,
            PrivateServiceHostConfig {
                listen: "127.0.0.1:0".parse()?,
                advertised_ip: "127.0.0.1".parse()?,
                usage_directory: f.usage.join("ledger"),
            },
        )
        .await?;
    let entry = f
        .sdk
        .private_services(&f.consumer.device_id, None, 10)
        .await?
        .entries
        .into_iter()
        .next()
        .ok_or("entry missing")?;
    let choice = LocalProxyServiceChoice::from_local_choice(
        &entry,
        "private-web.nestlink.internal",
        443,
        8192,
        Duration::from_secs(20),
    )?;
    let mut gateway = f
        .sdk
        .start_private_web_gateway(
            Arc::new(f.consumer),
            choice,
            PrivateWebGatewayConfig {
                listen: "127.0.0.1:0".parse()?,
                origin: format!("https://{}.private.example.net", f.view.id),
            },
        )
        .await?;
    let mut browser = Browser::new(&gateway)?;
    browser.exchange(&gateway).await?;
    assert_eq!(
        browser
            .request(reqwest::Method::GET, "/me")
            .header("X-NestLink-SNI", "control.example.com")
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        browser
            .request(reqwest::Method::POST, "/login")
            .header("Origin", "https://untrusted.invalid")
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let wrong_name = ServerName::try_from("different.private-web.nestlink.invalid")?;
    assert!(
        browser
            .tls
            .connect(wrong_name, TcpStream::connect(browser.address).await?)
            .await
            .is_err()
    );
    let mut plaintext = TcpStream::connect(browser.address).await?;
    plaintext
        .write_all(b"GET /me HTTP/1.1\r\nHost: untrusted.invalid\r\n\r\n")
        .await?;
    let mut refused = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(3), plaintext.read_to_end(&mut refused)).await?;
    assert!(read.is_err() || !refused.starts_with(b"HTTP/1.1"));
    drop(plaintext);
    let mut absolute = browser.connect().await?;
    absolute.write_all(format!("GET http://untrusted.invalid/ HTTP/1.1\r\nHost: {}\r\nX-NestLink-Token: {}\r\nX-NestLink-Scheme: https\r\nX-NestLink-SNI: {}\r\nCookie: {}\r\nConnection: close\r\n\r\n",browser.host,browser.hop,browser.host,browser.cookie.as_deref().ok_or("browser cookie missing")?).as_bytes()).await?;
    let mut refused = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), absolute.read_to_end(&mut refused)).await??;
    assert!(refused.starts_with(b"HTTP/1.1 403"));
    drop(absolute);
    browser.login().await?;
    let mut socket = browser.socket().await?;
    f.sdk
        .revoke_private_service(&f.view.id, &f.rule, f.exposure.revision)
        .await?;
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.next()).await?;
    assert!(
        closed.is_none()
            || matches!(
                closed,
                Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
            )
    );
    assert_eq!(
        browser
            .request(reqwest::Method::GET, "/me")
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    drop(socket);
    finish_gateway(&mut gateway).await?;
    host.wait_stopped().await?;
    drop(host);
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}
