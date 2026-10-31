use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn fixed_https_probe_is_credential_free_bounded_and_refuses_redirects() -> Result {
    let tls = tls::UpstreamTls::generate(Duration::from_secs(60))?;
    let root = STANDARD.decode(&tls.certificate)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let owner_id = nestlink_auth::random_id();
    let expected = owner_id.clone();
    let server = tokio::spawn(async move {
        for (status, body) in [
            (StatusCode::OK, expected),
            (StatusCode::OK, nestlink_auth::random_id()),
            (StatusCode::OK, "x".repeat(65)),
            (StatusCode::FOUND, String::new()),
        ] {
            let (socket, _) = listener.accept().await?;
            let socket = tls.acceptor.accept(socket).await?;
            let service = service_fn(move |request: Request<Incoming>| {
                let body = body.clone();
                async move {
                    assert_eq!(request.uri().path(), "/.nestlink/ready");
                    for name in ["authorization", "cookie", "x-nestlink-token", "x-nestlink-sni", "x-nestlink-scheme"] {
                        assert!(!request.headers().contains_key(name));
                    }
                    let mut response = Response::new(Body::from(body));
                    *response.status_mut() = status;
                    if status == StatusCode::FOUND {
                        response.headers_mut().insert(hyper::header::LOCATION, hyper::header::HeaderValue::from_static("https://untrusted.invalid/"));
                    }
                    Ok::<_, Infallible>(response)
                }
            });
            hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(socket), service).await.map_err(io::Error::other)?;
        }
        Ok::<_, io::Error>(())
    });
    let probe = PrivateWebRouteProbe {
        client: reqwest::Client::builder().no_proxy().https_only(true).tls_built_in_root_certs(false).add_root_certificate(reqwest::Certificate::from_der(&root)?).resolve(&tls.server_name, address).redirect(reqwest::redirect::Policy::none()).timeout(SETUP).build()?,
        url: format!("https://{}:{}/.nestlink/ready", tls.server_name, address.port()),
        owner_id,
    };
    for expected in [true, false, false, false] { assert_eq!(probe.check().await?, expected); }
    tokio::time::timeout(Duration::from_secs(3), server).await???;
    Ok(())
}
