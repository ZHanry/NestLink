//! Reuse the original Windows TUN acceptance fixture's frozen cloudflared
//! public-PKI HTTPS origin. TLS terminates at Cloudflare; its upstream is the
//! disposable loopback HTTP application, not end-to-end peer encryption.
use super::{Result, Sdk};
use axum::{http::Method, response::IntoResponse};
use std::{
    io,
    net::SocketAddr,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(super) struct Scope {
    pub space: String,
    pub devices: [String; 2],
    pub sessions: [String; 2],
    pub setup: Arc<AtomicBool>,
}
impl Scope {
    pub async fn serve(
        self,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let path = request
            .uri()
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        let method = request.method();
        let setup = self.setup.load(Ordering::Acquire);
        let allowed = match (method, path.as_slice()) {
            (&Method::GET, ["api", "v3", "health"])
            | (&Method::POST, ["api", "v3", "health", "proof"])
            | (&Method::POST, ["api", "v3", "auth", "login" | "restore" | "refresh"])
            | (&Method::GET, ["api", "v3", "auth", "me"]) => true,
            (&Method::POST, ["api", "v3", "accounts" | "devices" | "remote"])
            | (&Method::POST, ["api", "v3", "devices", "challenge"])
            | (&Method::POST, ["api", "v3", "remote", "trusted"]) => setup,
            (&Method::POST, ["api", "v3", "remote", session, "approval" | "trust"]) => {
                setup && self.sessions.iter().any(|id| id.as_str() == *session)
            }
            (&Method::GET | &Method::POST, ["api", "v3", "remote", session, "permit"]) => {
                self.sessions.iter().any(|id| id.as_str() == *session)
            }
            (&Method::GET, ["api", "v3", "network", "spaces", space, "policy"]) => {
                *space == self.space
            }
            (&Method::PUT, ["api", "v3", "network", "spaces", space, "authority"]) => {
                setup && *space == self.space
            }
            (&Method::PUT, ["api", "v3", "network", "spaces", space, "members", device]) => {
                setup
                    && *space == self.space
                    && self.devices.iter().any(|id| id.as_str() == *device)
            }
            (&Method::GET | &Method::PUT, ["api", "v3", "network", "spaces", space, "offline"])
            | (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    space,
                    "offline",
                    "remote-drafts",
                ],
            ) => *space == self.space,
            (
                &Method::GET | &Method::DELETE,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    space,
                    "offline",
                    "bundles",
                    bundle,
                ],
            )
            | (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    space,
                    "offline",
                    "bundles",
                    bundle,
                    "approval" | "consume",
                ],
            ) => *space == self.space && nestlink_protocol::valid_id(bundle),
            (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    space,
                    "offline",
                    "bundles",
                    bundle,
                    "consume-challenge",
                    "0" | "1",
                ],
            ) => *space == self.space && nestlink_protocol::valid_id(bundle),
            _ => false,
        };
        if allowed {
            next.run(request).await
        } else {
            axum::http::StatusCode::FORBIDDEN.into_response()
        }
    }
}

pub(super) async fn start(
    upstream: SocketAddr,
    area: &Path,
) -> Result<(tokio::process::Child, String)> {
    let tool = std::env::var_os("NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED")
        .ok_or_else(|| io::Error::other("the hosted pinned HTTPS fixture tool is required"))?;
    let log = area.join("https-tunnel.log");
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
    #[cfg(windows)]
    {
        let identity = nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(
            child
                .id()
                .ok_or_else(|| io::Error::other("HTTPS fixture child PID missing"))?,
        )?;
        assert!(
            !identity.elevated && (0x2000..0x3000).contains(&identity.integrity),
            "HTTPS test tool must retain the real medium user token"
        );
    }
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
                    && text.contains("Registered tunnel connection")
                {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(format!(
                        "https://{name}.trycloudflare.com"
                    ));
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok((child, origin))
}

pub(super) async fn login(
    origin: &str,
    deployment: &str,
    issuer: [u8; 32],
    account: &str,
    password: &nestlink_auth::Secret,
) -> Result<Sdk> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut sdk = loop {
        match Sdk::connect(
            origin,
            nestlink_sdk::DeploymentTrust {
                deployment_id: deployment.into(),
                permit_issuer: issuer,
            },
            false,
        )
        .await
        {
            Ok(sdk) => break sdk,
            Err(error)
                if Instant::now() < deadline
                    && match &error {
                        nestlink_sdk::SdkError::Transport(_) | nestlink_sdk::SdkError::Timeout => {
                            true
                        }
                        nestlink_sdk::SdkError::Api(status, _) => status.is_server_error(),
                        _ => false,
                    } =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await
            }
            Err(error) => return Err(error.into()),
        }
    };
    sdk.login(
        account.into(),
        nestlink_auth::Secret::from_text(password.expose().into()),
        None,
    )
    .await?;
    Ok(sdk)
}
