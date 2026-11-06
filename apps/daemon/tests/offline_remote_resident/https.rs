//! Reuse the original Windows TUN acceptance fixture's frozen cloudflared
//! public-PKI HTTPS origin. TLS terminates at Cloudflare; its upstream is the
//! disposable loopback HTTP application, not end-to-end peer encryption.
use super::{Result, Sdk};
use axum::{http::Method, response::IntoResponse};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

// This is an external fixture preparation failure, before any SDK login or
// product assertion. Keep it distinct from registration, TLS and SDK failures.
#[derive(Debug)]
struct DnsReadinessTimeout(String);
impl std::fmt::Display for DnsReadinessTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "temporary public-PKI HTTPS fixture DNS was not ready: {}",
            self.0
        )
    }
}
impl std::error::Error for DnsReadinessTimeout {}

fn setup_diagnostic(message: std::fmt::Arguments<'_>) {
    // libtest hides eprintln! output for successful tests. Write the original
    // preparation failures directly so a recovered fixture still retains them.
    let _ = writeln!(std::io::stderr().lock(), "{message}");
}

async fn prepare_with_dns_retry<T, F, Fut>(mut prepare: F) -> Result<T>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    const MAX_ATTEMPTS: usize = 3;
    let mut attempt = 1;
    loop {
        let result = prepare(attempt).await;
        match &result {
            Err(error) if error.is::<DnsReadinessTimeout>() && attempt < MAX_ATTEMPTS => {
                setup_diagnostic(format_args!(
                    "original_https_fixture_retry completed_attempt={attempt} maximum_attempts={MAX_ATTEMPTS} category=system_dns_before_product_setup reason={error}"
                ));
                attempt += 1;
            }
            _ => return result,
        }
    }
}

// Keep a bounded copy in the original harness stderr before TempDir cleanup.
// This observes setup failure only: the original resolver, trust and deadlines
// below still decide whether the fixture can be used.
struct StartupDiagnostic {
    log: PathBuf,
    started: Instant,
    stage: &'static str,
    origin: Option<String>,
    complete: bool,
}
impl Drop for StartupDiagnostic {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        setup_diagnostic(format_args!(
            "original_https_fixture_failed stage={} elapsed_ms={} origin={:?}",
            self.stage,
            self.started.elapsed().as_millis(),
            self.origin
        ));
        let tail = (|| -> io::Result<Vec<u8>> {
            let mut file = std::fs::File::open(&self.log)?;
            let start = file.metadata()?.len().saturating_sub(16_384);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(16_384).read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        match tail {
            Ok(bytes) => setup_diagnostic(format_args!(
                "original_https_fixture_tunnel_log_tail={}",
                String::from_utf8_lossy(&bytes)
            )),
            Err(error) => setup_diagnostic(format_args!(
                "original_https_fixture_tunnel_log_error={error}"
            )),
        }
        #[cfg(target_os = "linux")]
        if let Ok(file) = std::fs::File::open("/etc/resolv.conf") {
            let mut bytes = Vec::new();
            if file.take(4096).read_to_end(&mut bytes).is_ok() {
                setup_diagnostic(format_args!(
                    "original_https_fixture_system_resolver={}",
                    String::from_utf8_lossy(&bytes)
                ));
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Scope {
    pub space: Arc<OnceLock<String>>,
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
        let own_space = self.space.get().map(String::as_str);
        let allowed = match (method, path.as_slice()) {
            (&Method::GET, ["api", "v3", "health"])
            | (&Method::POST, ["api", "v3", "health", "proof"])
            | (&Method::POST, ["api", "v3", "auth", "login" | "restore" | "refresh"])
            | (&Method::GET, ["api", "v3", "auth", "me"]) => true,
            (&Method::POST, ["api", "v3", "accounts" | "devices" | "remote"])
            | (&Method::POST, ["api", "v3", "devices", "challenge"])
            | (&Method::POST, ["api", "v3", "remote", "trusted"]) => setup,
            (&Method::POST, ["api", "v3", "network", "spaces"]) => setup && own_space.is_none(),
            (&Method::GET, ["api", "v3", "network", "spaces", space]) => Some(*space) == own_space,
            (
                &Method::POST,
                [
                    "api",
                    "v3",
                    "network",
                    "spaces",
                    space,
                    "devices" | "invitations",
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
                    "invitations",
                    _,
                    "accept",
                ],
            ) => setup && Some(*space) == own_space,
            (&Method::POST, ["api", "v3", "remote", session, "approval" | "trust"]) => {
                setup && self.sessions.iter().any(|id| id.as_str() == *session)
            }
            (&Method::GET | &Method::POST, ["api", "v3", "remote", session, "permit"]) => {
                self.sessions.iter().any(|id| id.as_str() == *session)
            }
            (&Method::GET, ["api", "v3", "network", "spaces", space, "policy"]) => {
                Some(*space) == own_space
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
            ) => Some(*space) == own_space,
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
            ) => Some(*space) == own_space && nestlink_protocol::valid_id(bundle),
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
            ) => Some(*space) == own_space && nestlink_protocol::valid_id(bundle),
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
    prepare_with_dns_retry(|attempt| start_once(upstream, area, attempt)).await
}

async fn start_once(
    upstream: SocketAddr,
    area: &Path,
    attempt: usize,
) -> Result<(tokio::process::Child, String)> {
    let tool = std::env::var_os("NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED")
        .ok_or_else(|| io::Error::other("the hosted pinned HTTPS fixture tool is required"))?;
    let log = area.join(format!("https-tunnel-attempt-{attempt}.log"));
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
    let mut diagnostic = StartupDiagnostic {
        log: log.clone(),
        started: Instant::now(),
        stage: "tunnel_registration",
        origin: None,
        complete: false,
    };
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
    diagnostic.stage = "system_dns";
    diagnostic.origin = Some(origin.clone());
    // Tunnel registration precedes public DNS publication. Wait on the real
    // system resolver before the normal SDK's public-PKI health/proof checks;
    // this disposable fixture has no alternate address or trust bypass.
    let hostname = origin
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::other("temporary HTTPS origin is not HTTPS"))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::other(
                "temporary HTTPS fixture tool stopped before public DNS readiness",
            )
            .into());
        }
        let resolved =
            tokio::time::timeout_at(deadline.into(), tokio::net::lookup_host((hostname, 443)))
                .await;
        let diagnostic = match resolved {
            Ok(Ok(mut addresses)) => {
                if addresses.next().is_some() {
                    break;
                }
                "system resolver returned no public HTTPS address".to_owned()
            }
            Ok(Err(error)) => error.to_string(),
            Err(error) => error.to_string(),
        };
        if Instant::now() >= deadline {
            // Reap this unusable external fixture before another can start.
            // Cleanup failure is not a DNS preparation failure and is not retried.
            child.kill().await.map_err(|error| {
                io::Error::other(format!("unready HTTPS fixture cleanup failed: {error}"))
            })?;
            return Err(DnsReadinessTimeout(diagnostic).into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    diagnostic.complete = true;
    setup_diagnostic(format_args!(
        "original_https_fixture_ready attempt={attempt} origin={origin}"
    ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dns_preparation_stops_at_three_attempts() {
        let mut attempts = Vec::new();
        let result = prepare_with_dns_retry(|attempt| {
            attempts.push(attempt);
            std::future::ready(Err::<(), _>(DnsReadinessTimeout("not ready".into()).into()))
        })
        .await;
        assert_eq!(attempts, [1, 2, 3]);
        assert!(result.unwrap_err().is::<DnsReadinessTimeout>());
    }

    #[tokio::test]
    async fn dns_preparation_returns_only_the_ready_origin() {
        let mut attempts = Vec::new();
        let result = prepare_with_dns_retry(|attempt| {
            attempts.push(attempt);
            std::future::ready(if attempt == 3 {
                Ok("prepared origin")
            } else {
                Err(DnsReadinessTimeout("not ready".into()).into())
            })
        })
        .await;
        assert_eq!(attempts, [1, 2, 3]);
        assert_eq!(result.unwrap(), "prepared origin");
    }

    #[tokio::test]
    async fn registration_io_and_sdk_failures_are_never_retried() {
        let errors: Vec<Box<dyn std::error::Error + Send + Sync>> = vec![
            io::Error::new(io::ErrorKind::TimedOut, "registration timed out").into(),
            io::Error::other("fixture cleanup failed").into(),
            nestlink_sdk::SdkError::Timeout.into(),
        ];
        for error in errors {
            let expected = error.to_string();
            let mut error = Some(error);
            let mut attempts = Vec::new();
            let result = prepare_with_dns_retry(|attempt| {
                attempts.push(attempt);
                std::future::ready(Err::<(), _>(error.take().unwrap()))
            })
            .await;
            assert_eq!(attempts, [1]);
            assert_eq!(result.unwrap_err().to_string(), expected);
        }
    }
}
