use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner};
use nestlink_protocol::{
    Path as NetworkPath, Permission, api::*, network::SpaceRole, offline::management::*, spaces::*,
};
use nestlink_sdk::{DeviceIdentity, Sdk};
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
#[path = "https.rs"]
mod https;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn wall() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn password() -> Secret {
    Secret::from_text(URL_SAFE_NO_PAD.encode(nestlink_auth::random_bytes::<32>()))
}

/// Actual OS services are owned by this test, without changing process-global
/// environment or installing a replacement platform/keyring implementation.
pub struct Platform {
    env: Vec<(&'static str, String)>,
    children: Vec<Child>,
}
impl Platform {
    pub async fn new(area: &Path) -> Result<Self> {
        let value = Self {
            env: Vec::new(),
            children: Vec::new(),
        };
        #[cfg(target_os = "linux")]
        let mut value = value;
        #[cfg(target_os = "linux")]
        {
            for (name, directory) in [
                ("XDG_DATA_HOME", "keyring-data"),
                ("XDG_RUNTIME_DIR", "runtime"),
            ] {
                let path = area.join(directory);
                nestlink_platform_security::new_private_directory(&path)?;
                value.env.push((name, path.to_string_lossy().into_owned()));
            }
            let mut dbus = value
                .command("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut address = String::new();
            tokio::time::timeout(
                Duration::from_secs(5),
                BufReader::new(dbus.stdout.take().ok_or("dbus stdout")?).read_line(&mut address),
            )
            .await??;
            assert!(address.starts_with("unix:"));
            value
                .env
                .push(("DBUS_SESSION_BUS_ADDRESS", address.trim().into()));
            value.children.push(dbus);
            let mut x = Command::new("Xvfb")
                .args([
                    "-displayfd",
                    "1",
                    "-screen",
                    "0",
                    "640x480x24",
                    "-nolisten",
                    "tcp",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut display = String::new();
            tokio::time::timeout(
                Duration::from_secs(5),
                BufReader::new(x.stdout.take().ok_or("Xvfb stdout")?).read_line(&mut display),
            )
            .await??;
            let _: u16 = display.trim().parse()?;
            value.env.push(("DISPLAY", format!(":{}", display.trim())));
            value.children.push(x);
            let mut keyring = value.command("gnome-keyring-daemon");
            let mut keyring = keyring
                .args(["--foreground", "--unlock", "--components=secrets"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            keyring
                .stdin
                .take()
                .ok_or("keyring input")?
                .write_all(b"resident-keyring-test-password\n")
                .await?;
            value.children.push(keyring);
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let observed = value
                        .command("dbus-send")
                        .args([
                            "--session",
                            "--print-reply",
                            "--dest=org.freedesktop.DBus",
                            "/org/freedesktop/DBus",
                            "org.freedesktop.DBus.NameHasOwner",
                            "string:org.freedesktop.secrets",
                        ])
                        .output()
                        .await?;
                    if observed.status.success()
                        && String::from_utf8_lossy(&observed.stdout).contains("boolean true")
                    {
                        return Ok::<_, io::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original OS Secret Service did not register",
                )
            })??;
            let status = value
                .command("xsetroot")
                .args(["-solid", "#00ff00"])
                .status()
                .await?;
            assert!(status.success());
        }
        #[cfg(windows)]
        let _ = area;
        Ok(value)
    }
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command.kill_on_drop(true).env_remove("WAYLAND_DISPLAY");
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command
    }
    fn resident(&self) -> (Command, Option<String>) {
        #[cfg(target_os = "linux")]
        {
            // The production capture source requires a genuine logind desktop
            // session for this PID. PAM registers that original session; the
            // test never substitutes a bus, login service or accepted facts.
            let unit = format!("nestlink-offline-test-{}", random_id());
            let mut command = self.command("sudo");
            command
                .args([
                    "-n",
                    "systemd-run",
                    "--quiet",
                    "--wait",
                    "--pipe",
                    "--collect",
                    "--service-type=exec",
                ])
                .arg(format!("--unit={unit}"))
                .arg(format!("--uid={}", rustix::process::geteuid().as_raw()))
                .args([
                    "--property=PAMName=login",
                    "--property=TimeoutStopSec=5s",
                    "--property=RuntimeMaxSec=180s",
                    "--setenv=XDG_SESSION_TYPE=x11",
                    "--setenv=XDG_SESSION_CLASS=user",
                ]);
            for (name, value) in &self.env {
                command.arg(format!("--setenv={name}={value}"));
            }
            // pam_systemd can set the per-user bus/runtime environment. Restore
            // this test's actual private Secret Service after PAM registers the
            // real login session, without changing any original session facts.
            command.args(["--", "/usr/bin/env", "--unset=WAYLAND_DISPLAY"]);
            for (name, value) in &self.env {
                command.arg(format!("{name}={value}"));
            }
            command.arg(env!("CARGO_BIN_EXE_nestlink-daemon"));
            (command, Some(unit))
        }
        #[cfg(windows)]
        {
            (self.command(env!("CARGO_BIN_EXE_nestlink-daemon")), None)
        }
    }
    async fn protect_login(&self, directory: &Path, sdk: &Sdk) -> Result {
        let binding = URL_SAFE_NO_PAD.encode(nestlink_auth::token_hash(
            "management-store",
            &directory.to_string_lossy(),
        ));
        let key = zeroize::Zeroizing::new(nestlink_auth::random_bytes::<32>());
        #[cfg(windows)]
        nestlink_platform_security::create_key(&directory.join("management-login.key"), &key)?;
        #[cfg(target_os = "linux")]
        {
            let secret = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(*key));
            // This is the real Secret Service used by production SessionStore.
            // No plaintext fallback or test-only authentication path exists.
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let mut child = self
                        .command("secret-tool")
                        .args([
                            "store",
                            "--label=NestLink resident Actions test",
                            "application",
                            "NestLink",
                            "instance",
                            &binding,
                        ])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()?;
                    child
                        .stdin
                        .take()
                        .ok_or_else(|| io::Error::other("secret input"))?
                        .write_all(secret.as_bytes())
                        .await?;
                    if child.wait().await?.success() {
                        return Ok::<_, io::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original OS Secret Service rejected the protected-login key store",
                )
            })??;
            let lookup = self
                .command("secret-tool")
                .args(["lookup", "application", "NestLink", "instance", &binding])
                .output()
                .await?;
            assert!(
                lookup.status.success(),
                "actual Secret Service lookup failed after store"
            );
            let saved = zeroize::Zeroizing::new(lookup.stdout);
            let decoded = zeroize::Zeroizing::new(
                URL_SAFE_NO_PAD.decode(std::str::from_utf8(&saved)?.trim())?,
            );
            assert!(
                decoded.as_slice() == key.as_slice(),
                "original OS key store did not retain this private binding"
            );
        }
        let login = sdk
            .export_login()?
            .ok_or("actual protected login unavailable")?;
        let cipher = VaultKey::from_bytes(*key).encrypt_management(&binding, &login)?;
        nestlink_platform_security::create_private(
            &directory.join("remember-login.json"),
            b"true",
        )?;
        nestlink_platform_security::create_private(
            &directory.join("management-login.enc"),
            &cipher,
        )?;
        Ok(())
    }
    pub async fn shutdown(mut self) {
        for child in self.children.iter_mut().rev() {
            let _ = child.kill().await;
        }
    }
}

fn installation(directory: &Path) -> Result<DeviceIdentity> {
    nestlink_platform_security::new_private_directory(directory)?;
    let mut seed = zeroize::Zeroizing::new(nestlink_auth::random_bytes::<32>());
    nestlink_platform_security::create_key(&directory.join("installation-device.key"), &seed)?;
    let identity = DeviceIdentity {
        device_id: random_id(),
        identity: InstallationIdentity::from_seed_zeroizing(&mut seed),
    };
    nestlink_platform_security::create_private(
        &directory.join("installation-device.json"),
        &serde_json::to_vec(&json!({
            "schema_version":1,"device_id":identity.device_id,"public_key_sha256":identity.identity.fingerprint()
        }))?,
    )?;
    Ok(identity)
}

/// The original HTTP application and database issue every permit, approval and
/// one-use consumption. The gate only delays real HTTP responses for a fence
/// assertion; it cannot construct or modify authority.
struct Server {
    task: JoinHandle<io::Result<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}
impl Server {
    fn start(listener: tokio::net::TcpListener, router: axum::Router) -> Self {
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            task,
            shutdown: Some(shutdown),
        }
    }
    async fn stop(mut self) -> Result {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        tokio::time::timeout(Duration::from_secs(5), &mut self.task).await???;
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct Fixture {
    pub source: PathBuf,
    pub host: PathBuf,
    pub space: String,
    pub session: String,
    pub online_expiry: u64,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub policy_revision: u64,
    router: axum::Router,
    address: std::net::SocketAddr,
    server: Option<Server>,
    _tunnel: Child,
    pub gate: watch::Sender<bool>,
    pub requests: Arc<AtomicUsize>,
}
impl Fixture {
    pub async fn new(area: &Path, platform: &Platform) -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = nestlink_storage::Store::in_memory(&deployment)?;
        let source_account = format!("lab-{}", random_id());
        let host_account = format!("lab-{}", random_id());
        let source_password = password();
        let host_password = password();
        store.bootstrap_admin(&source_account, source_password.expose())?;
        let source = area.join("source");
        let host = area.join("host");
        let source_identity = installation(&source).map_err(|error| {
            io::Error::other(format!("resident fixture protected source installation: {error}"))
        })?;
        let host_identity = installation(&host).map_err(|error| {
            io::Error::other(format!("resident fixture protected host installation: {error}"))
        })?;
        let pinned_space = Arc::new(OnceLock::new());
        let sessions = [random_id(), random_id()];
        let setup = Arc::new(AtomicBool::new(true));
        let scope = https::Scope {
            space: pinned_space.clone(),
            sessions: sessions.clone(),
            setup: setup.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (tunnel, origin) = https::start(address, area).await.map_err(|error| {
            io::Error::other(format!("resident fixture public-PKI HTTPS startup: {error}"))
        })?;
        let app = nestlink_server::router(nestlink_server::AppState::new(
            store,
            VaultKey::from_bytes(nestlink_auth::random_bytes()),
            signer,
            origin.clone(),
            true,
        )?);
        let (gate, _) = watch::channel(false);
        let requests = Arc::new(AtomicUsize::new(0));
        let (held, observed) = (gate.clone(), requests.clone());
        let router = app
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let mut held = held.subscribe();
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::AcqRel);
                        loop {
                            let waiting = *held.borrow_and_update();
                            if !waiting || held.changed().await.is_err() {
                                break;
                            }
                        }
                        next.run(request).await
                    }
                },
            ))
            .layer(axum::middleware::from_fn(move |request, next| {
                scope.clone().serve(request, next)
            }));
        let server_router = router.clone();
        let server = Server::start(listener, server_router);
        let source_sdk = https::login(
            &origin,
            &deployment,
            issuer,
            &source_account,
            &source_password,
        )
        .await?;
        source_sdk
            .create_account(
                host_account.clone(),
                Secret::from_text(host_password.expose().into()),
            )
            .await?;
        let host_sdk =
            https::login(&origin, &deployment, issuer, &host_account, &host_password).await?;
        for (sdk, identity, role) in [
            (&source_sdk, &source_identity, "controller"),
            (&host_sdk, &host_identity, "host"),
        ] {
            sdk.enroll(
                identity,
                role.into(),
                if cfg!(windows) {
                    "windows"
                } else {
                    "linux-x11"
                }
                .into(),
                vec![
                    role.into(),
                    "vp8".into(),
                    nestlink_protocol::remote_budget::CAPABILITY.into(),
                ],
                "direct_only".into(),
            )
            .await?;
        }
        let created = source_sdk
            .create_space(SpaceCreateRequest {
                name: "Original resident protected HTTPS space".into(),
            })
            .await?;
        let space = created.space_id;
        pinned_space
            .set(space.clone())
            .map_err(|_| io::Error::other("fixture space was already pinned"))?;
        let invitation = source_sdk
            .invite_to_space(
                &space,
                SpaceInvitationRequest {
                    expected_revision: created.revision,
                    role: SpaceRole::Member,
                    target_account_id: Some(
                        host_sdk
                            .principal()
                            .ok_or("host principal")?
                            .account_id
                            .clone(),
                    ),
                    expires_at_unix_ms: wall()? + 120_000,
                },
            )
            .await?;
        let accepted = host_sdk
            .accept_space_invitation(
                &space,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token,
                },
            )
            .await?;
        assert_eq!(accepted.role, SpaceRole::Member);
        let mut revision = accepted.revision;
        for (sdk, identity) in [(&source_sdk, &source_identity), (&host_sdk, &host_identity)] {
            revision = sdk
                .join_space_device(
                    &space,
                    SpaceDeviceJoin {
                        expected_revision: revision,
                        expected_membership_epoch: 0,
                        installation_id: identity.device_id.clone(),
                    },
                )
                .await?
                .revision;
        }
        assert!(
            matches!(host_sdk.network_policy(&space).await,
            Err(nestlink_sdk::SdkError::Api(status, _)) if status.as_u16() == 403),
            "the actual host account must retain the original admin-only policy denial"
        );
        let member_view = host_sdk.space_details(&space).await?.space;
        assert_eq!(member_view.role, SpaceRole::Member);
        assert_eq!(
            member_view.authority_public_key,
            created.authority_public_key
        );
        let request = |id| RemoteRequest {
            id,
            controller_device_id: source_identity.device_id.clone(),
            host_device_id: host_identity.device_id.clone(),
            permissions: vec![Permission::View as i32, Permission::FileRead as i32],
            path_mode: "direct_only".into(),
        };
        let pending = source_sdk
            .create_remote(request(sessions[0].clone()))
            .await?;
        host_sdk
            .approve(
                &host_identity,
                &pending,
                ApprovalChoice {
                    approved: true,
                    permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                    paths: vec![NetworkPath::Direct as i32],
                },
            )
            .await?;
        let original = source_sdk.permit(&pending.id).await?;
        host_sdk
            .trust_remote(
                &host_identity,
                &original,
                TrustChoice {
                    expected_revision: 0,
                    expires_at_unix_ms: wall()? + 120_000,
                },
            )
            .await?;
        let trusted = source_sdk
            .create_trusted_remote(request(sessions[1].clone()))
            .await?;
        let original = source_sdk.permit(&trusted.id).await?;
        source_sdk
            .set_offline_enabled(
                &space,
                &OfflineEnableUpdate {
                    expected_revision: 0,
                    enabled: true,
                },
            )
            .await?;
        platform.protect_login(&source, &source_sdk).await?;
        platform.protect_login(&host, &host_sdk).await?;
        setup.store(false, Ordering::Release);
        Ok(Self {
            source,
            host,
            space,
            session: trusted.id,
            online_expiry: original.claims().expires_at_unix_ms,
            connection_generation: original.claims().connection_generation,
            lease_sequence: original.claims().lease_sequence,
            policy_revision: revision,
            router,
            address,
            server: Some(server),
            _tunnel: tunnel,
            gate,
            requests,
        })
    }
    pub async fn offline(&mut self) -> Result {
        if let Some(server) = self.server.take() {
            server.stop().await?;
        }
        drop(tokio::net::TcpListener::bind(self.address).await?);
        Ok(())
    }
    pub async fn hold_management(&mut self) -> Result<usize> {
        self.gate.send_replace(true);
        let listener = tokio::net::TcpListener::bind(self.address).await?;
        let router = self.router.clone();
        self.server = Some(Server::start(listener, router));
        Ok(self.requests.load(Ordering::Acquire))
    }
    pub async fn finish(mut self) -> Result {
        self.offline().await?;
        if self._tunnel.try_wait()?.is_none() {
            self._tunnel.kill().await?;
        }
        let _ = self._tunnel.wait().await?;
        Ok(())
    }
}
pub struct Resident {
    child: Child,
    input: Option<ChildStdin>,
    events: mpsc::UnboundedReceiver<Value>,
    stderr: Arc<Mutex<Vec<u8>>>,
    unit: Option<String>,
}
impl Resident {
    pub async fn spawn(
        platform: &Platform,
        fixture: &Fixture,
        host: bool,
        transport: &str,
        peer: std::net::SocketAddr,
    ) -> Result<Self> {
        let (mut command, unit) = platform.resident();
        command
            .arg("offline-remote")
            .arg("--state-dir")
            .arg(if host { &fixture.host } else { &fixture.source })
            .args([
                "--space",
                &fixture.space,
                "--session",
                &fixture.session,
                "--role",
                if host { "host" } else { "controller" },
                "--transport",
                transport,
                if host { "--listen" } else { "--peer" },
                &peer.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let input = child.stdin.take();
        let output = child.stdout.take().ok_or("resident stdout")?;
        let (send, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut lines = BufReader::new(output).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match serde_json::from_str(&line) {
                    Ok(event) => {
                        if send.send(event).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let error_output = child.stderr.take().ok_or("resident stderr")?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let collected = stderr.clone();
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            let _ = error_output.take(65536).read_to_end(&mut bytes).await;
            if let Ok(mut output) = collected.lock() {
                *output = bytes;
            }
        });
        let mut resident = Self {
            child,
            input,
            events,
            stderr,
            unit,
        };
        resident.event("ready").await?;
        Ok(resident)
    }
    pub async fn send(&mut self, command: Value) -> Result {
        let mut bytes = serde_json::to_vec(&command)?;
        bytes.push(b'\n');
        let input = self.input.as_mut().ok_or("resident stdin closed")?;
        input.write_all(&bytes).await?;
        input.flush().await?;
        Ok(())
    }
    pub async fn event(&mut self, expected: &str) -> Result<Value> {
        let mut last_event = None;
        let result = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = self.events.recv().await {
                last_event = Some(event.clone());
                if event["event"] == expected {
                    return Ok(event["data"].clone());
                }
                if event["event"] == "command_failed" || event["event"] == "connection_failed" {
                    return Err(io::Error::other(format!("waiting {expected}: {event}")));
                }
            }
            Err(io::Error::other(format!(
                "resident ended before {expected}"
            )))
        })
        .await;
        match result {
            Ok(Ok(data)) => Ok(data),
            error => {
                let diagnostic = self
                    .stderr
                    .lock()
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default();
                Err(io::Error::other(format!(
                    "resident event {expected}: {error:?}; last_event={last_event:?}; stderr={diagnostic}"
                ))
                .into())
            }
        }
    }
    pub async fn request(&mut self, command: Value, event: &str) -> Result<Value> {
        self.send(command).await?;
        self.event(event).await
    }
    pub async fn finish(&mut self, eof: bool) -> Result {
        if !eof {
            self.send(json!({"command":"stop"})).await?;
        }
        self.input.take();
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait()).await??;
        self.unit.take();
        assert!(status.success(), "resident exited with {status}");
        Ok(())
    }
    pub async fn exited(&mut self, success: bool) -> Result {
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait()).await??;
        self.unit.take();
        assert_eq!(status.success(), success, "resident exit {status}");
        Ok(())
    }
}
impl Drop for Resident {
    fn drop(&mut self) {
        if let Some(unit) = self.unit.take() {
            // Error/panic cleanup retains the exact service identity. Killing
            // only systemd-run would leave its original service and stdin open.
            let _ = std::process::Command::new("sudo")
                .args(["-n", "systemctl", "stop", &unit])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.start_kill();
    }
}

pub async fn activate(
    source: &mut Resident,
    host: &mut Resident,
    fixture: &Fixture,
) -> Result<String> {
    source.request(json!({"command":"help"}), "help").await?;
    source
        .request(json!({"command":"policy"}), "policy")
        .await?;
    let source_nonce = source
        .request(json!({"command":"begin"}), "process")
        .await?["process_nonce"]
        .clone();
    let host_nonce =
        host.request(json!({"command":"begin"}), "process").await?["process_nonce"].clone();
    let draft = source.request(json!({"command":"draft","request":{
        "session_id":fixture.session,"expected_policy_revision":fixture.policy_revision,"expected_connection_generation":fixture.connection_generation,"expected_lease_sequence":fixture.lease_sequence,
        "process_nonces":[source_nonce,host_nonce],"operations":["view","file_read"],"direct_transports":["quic","tls"],
        "maximum_bytes":16_777_216,"maximum_file_write_bytes":0,"maximum_connections":6,"expires_at_ms":wall()?+90_000
    }}),"draft").await?;
    let bundle = draft["claims"]["bundle_id"]
        .as_str()
        .ok_or("bundle ID")?
        .to_owned();
    let digest = draft["draft_digest"].clone();
    for resident in [&mut *source, &mut *host] {
        let review = resident
            .request(
                json!({"command":"review","bundle_id":bundle}),
                "complete_bundle_review",
            )
            .await?;
        assert_eq!(review["bundle"]["draft_digest"], digest);
        resident
            .request(
                json!({"command":"approve","draft_digest":digest}),
                "approval",
            )
            .await?;
    }
    for resident in [&mut *source, &mut *host] {
        let status = resident
            .request(
                json!({"command":"activate","draft_digest":digest}),
                "status",
            )
            .await?;
        assert_eq!(status["budget"]["stopped"], false);
        resident
            .request(
                json!({"command":"activate","draft_digest":digest}),
                "command_failed",
            )
            .await?;
    }
    Ok(bundle)
}

pub async fn start(source: &mut Resident, host: &mut Resident) -> Result {
    host.request(json!({"command":"start"}), "listening")
        .await?;
    source.send(json!({"command":"start"})).await?;
    source.event("connected").await?;
    host.event("connected").await?;
    let view = source
        .request(json!({"command":"status"}), "status")
        .await?;
    assert_eq!(view["status"], "connected");
    assert_eq!(view["budget"]["stopped"], false);
    Ok(())
}
