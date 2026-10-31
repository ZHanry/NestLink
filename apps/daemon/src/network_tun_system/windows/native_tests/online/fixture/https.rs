//! A frozen official tool supplies a temporary public-PKI HTTPS origin only
//! for this disposable management database. It terminates TLS at Cloudflare;
//! its origin leg is bounded loopback HTTP, not end-to-end peer encryption.
use super::*;
use std::process::Stdio;

// This random deployment exposes only the operations used by the fixture.
// Accounts, policy mutation, services, relay, files and arbitrary resources
// remain unreachable through its temporary public management origin.
pub(super) async fn fixture_scope(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{
        http::{Method, StatusCode},
        response::IntoResponse,
    };
    let path = request
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let allowed = matches!(
        (request.method(), path.as_slice()),
        (&Method::GET, ["api", "v3", "health"])
            | (&Method::POST, ["api", "v3", "health", "proof"])
            | (
                &Method::POST,
                ["api", "v3", "auth", "login" | "restore" | "refresh"]
            )
            | (&Method::GET, ["api", "v3", "auth", "me"])
            | (&Method::POST, ["api", "v3", "devices"])
            | (&Method::POST, ["api", "v3", "devices", "challenge"])
            | (&Method::POST, ["api", "v3", "network", "spaces"])
            | (&Method::GET, ["api", "v3", "network", "spaces", _])
            | (
                &Method::GET,
                ["api", "v3", "network", "spaces", _, "addressing"]
            )
            | (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    _,
                    "devices" | "addresses" | "packet-access",
                ],
            )
            | (
                &Method::POST,
                ["api", "v3", "network", "spaces", _, "members", _, "grants"]
            )
            | (
                &Method::GET | &Method::DELETE,
                ["api", "v3", "network", "spaces", _, "packet-access", _],
            )
            | (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    _,
                    "packet-access",
                    _,
                    "start",
                ],
            )
    );
    if allowed {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

pub(super) async fn start(
    upstream: SocketAddr,
    case: &Path,
) -> Result<(tokio::process::Child, String)> {
    let tool = path("NESTLINK_TUN_NATIVE_CLOUDFLARED")?;
    let log = case.join("https-tunnel.log");
    let output = std::fs::File::create(&log)?;
    let mut child = tokio::process::Command::new(tool)
        .args([
            "--no-autoupdate",
            "tunnel",
            "--url",
            &format!("http://{upstream}"),
            "--protocol",
            "http2",
            "--loglevel",
            "info",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .kill_on_drop(true)
        .spawn()?;
    let identity = nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(
        child
            .id()
            .ok_or_else(|| io::Error::other("HTTPS fixture child PID missing"))?,
    )?;
    assert!(
        !identity.elevated && (0x2000..0x3000).contains(&identity.integrity),
        "HTTPS test tool must retain the real medium user token"
    );
    std::fs::write(
        case.join("https-tunnel-process.json"),
        serde_json::to_vec(&serde_json::json!({"identity":identity}))?,
    )?;
    let origin = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if child.try_wait()?.is_some() {
                return Err(io::Error::other(
                    "temporary HTTPS fixture tool stopped before publishing its origin",
                )
                .into());
            }
            let text = std::fs::read_to_string(&log)?;
            for word in text.split_whitespace() {
                if let Some(name) = word
                    .strip_prefix("https://")
                    .and_then(|value| value.strip_suffix(".trycloudflare.com"))
                    && !name.is_empty()
                    && name.len() <= 63
                    && name.bytes().all(|value| {
                        value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-'
                    })
                {
                    if text.contains("Registered tunnel connection") {
                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(format!(
                            "https://{name}.trycloudflare.com"
                        ));
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok((child, origin))
}
