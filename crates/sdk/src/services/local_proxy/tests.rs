use super::*;
use fast_socks5::{
    AuthenticationMethod,
    client::{Config, Socks5Stream},
};
use nestlink_protocol::services::private::{ServiceAccessMode, ServiceExposureView};
use std::{
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

fn entry() -> Result<PrivateServiceEntry, Box<dyn std::error::Error>> {
    let definition = ServiceDefinition {
        name: "Private test target".into(),
        host_device_id: random_id(),
        edge_node_id: String::new(),
        requested_ingress: ServiceIngress::Tcp { port: 4444 },
        allowed_sources: vec![],
        limits: ServiceLimits {
            maximum_connections: 2,
            bytes_per_second: 4096,
            maximum_bytes: 8192,
            idle_timeout_seconds: 10,
        },
    };
    let service = ServiceView {
        id: random_id(),
        account_id: random_id(),
        management_session_id: random_id(),
        revision: 2,
        definition_sha256: URL_SAFE_NO_PAD
            .encode(nestlink_identity::services::definition_digest(&definition)?),
        definition,
        approval: ServiceApprovalState::ApprovedTarget,
        target_id: Some(random_id()),
        target_sha256: Some(URL_SAFE_NO_PAD.encode([7; 32])),
        approval_expires_at_unix_ms: Some(u64::MAX),
        publication: ServicePublicationStatus::NotPublished,
    };
    let exposure = ServiceExposureView {
        service_id: service.id.clone(),
        revision: 1,
        service_revision: 2,
        target_sha256: [7; 32],
        space_id: random_id(),
        mode: ServiceAccessMode::Private,
        private_maximum_bytes: 8192,
        public_maximum_bytes: 0,
    };
    Ok(PrivateServiceEntry {
        service,
        exposure,
        availability: PrivateServiceAvailability::Ready,
    })
}
fn choice() -> Result<LocalProxyServiceChoice, Box<dyn std::error::Error>> {
    Ok(LocalProxyServiceChoice::from_local_choice(
        &entry()?,
        "db.nestlink.internal",
        4444,
        4096,
        Duration::from_secs(30),
    )?)
}
fn password(credentials: &Credentials) -> AuthenticationMethod {
    AuthenticationMethod::Password {
        username: credentials.username.expose().to_owned(),
        password: credentials.password.expose().to_owned(),
    }
}

#[test]
fn explicit_choice_is_fixed_private_authority() -> Result<(), Box<dyn std::error::Error>> {
    let choice = choice()?;
    assert!(choice.accepts(&TargetAddr::Domain("DB.NESTLINK.INTERNAL".into(), 4444)));
    for target in [
        TargetAddr::Domain("example.com".into(), 4444),
        TargetAddr::Domain("db.nestlink.internal".into(), 80),
        TargetAddr::Ip("127.0.0.1:4444".parse()?),
    ] {
        assert!(!choice.accepts(&target));
    }
    for alias in [
        "example.com",
        "127.0.0.1",
        ".nestlink.internal",
        "a..nestlink.internal",
        "-db.nestlink.internal",
        "db_.nestlink.internal",
        "db.nestlink.internal.",
        "数据.nestlink.internal",
    ] {
        assert!(
            LocalProxyServiceChoice::from_local_choice(
                &entry()?,
                alias,
                4444,
                4096,
                Duration::from_secs(30)
            )
            .is_err()
        );
    }
    for mutate in [0, 1, 2, 3, 4, 5] {
        let mut entry = entry()?;
        match mutate {
            0 => entry.availability = PrivateServiceAvailability::Offline,
            1 => entry.exposure.mode = ServiceAccessMode::Public,
            2 => entry.exposure.service_revision += 1,
            3 => entry.exposure.target_sha256 = [8; 32],
            4 => entry.service.approval = ServiceApprovalState::Revoked,
            _ => entry.service.target_id = None,
        }
        assert!(
            LocalProxyServiceChoice::from_local_choice(
                &entry,
                "db.nestlink.internal",
                4444,
                4096,
                Duration::from_secs(30)
            )
            .is_err()
        );
    }
    for (port, bytes, lifetime) in [
        (0, 4096, Duration::from_secs(30)),
        (4444, 0, Duration::from_secs(30)),
        (4444, 8193, Duration::from_secs(30)),
        (4444, 4096, Duration::ZERO),
        (4444, 4096, MAX_LIFETIME + Duration::from_secs(1)),
    ] {
        assert!(
            LocalProxyServiceChoice::from_local_choice(
                &entry()?,
                "db.nestlink.internal",
                port,
                bytes,
                lifetime
            )
            .is_err()
        );
    }
    Ok(())
}

async fn protocol_attempt(
    credentials: Arc<Credentials>,
    auth: Option<AuthenticationMethod>,
    command: Socks5Command,
    alias: &str,
    port: u16,
) -> Result<bool, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let choice = choice()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.map_err(|_| ())?;
        let protocol = tokio::time::timeout(
            SETUP_BUDGET,
            authenticate_target(socket, &credentials, &choice),
        )
        .await
        .map_err(|_| ())??;
        protocol.reply_success(address).await.map_err(|_| ())?;
        Ok::<_, ()>(())
    });
    let accepted = tokio::time::timeout(
        SETUP_BUDGET,
        Socks5Stream::connect_raw(
            command,
            address,
            alias.to_owned(),
            port,
            auth,
            Config::default(),
        ),
    )
    .await?
    .is_ok();
    let server_accepted = server.await?.is_ok();
    assert_eq!(accepted, server_accepted);
    Ok(accepted)
}

#[tokio::test]
async fn standard_client_requires_password_and_one_exact_connect_target()
-> Result<(), Box<dyn std::error::Error>> {
    let credentials = Arc::new(Credentials::new());
    assert!(
        protocol_attempt(
            credentials.clone(),
            Some(password(&credentials)),
            Socks5Command::TCPConnect,
            "db.nestlink.internal",
            4444
        )
        .await?
    );
    let wrong = Credentials::new();
    assert!(
        !protocol_attempt(
            credentials.clone(),
            Some(password(&wrong)),
            Socks5Command::TCPConnect,
            "db.nestlink.internal",
            4444
        )
        .await?
    );
    assert!(
        !protocol_attempt(
            credentials.clone(),
            None,
            Socks5Command::TCPConnect,
            "db.nestlink.internal",
            4444
        )
        .await?
    );
    for (command, alias, port) in [
        (Socks5Command::TCPConnect, "example.com", 4444),
        (Socks5Command::TCPConnect, "db.nestlink.internal", 80),
        (Socks5Command::TCPConnect, "127.0.0.1", 4444),
        (Socks5Command::TCPBind, "db.nestlink.internal", 4444),
        (Socks5Command::UDPAssociate, "db.nestlink.internal", 4444),
    ] {
        assert!(
            !protocol_attempt(
                credentials.clone(),
                Some(password(&credentials)),
                command,
                alias,
                port
            )
            .await?
        );
    }
    Ok(())
}

#[tokio::test]
async fn component_preserves_fin_and_reverse_reply() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let credentials = Arc::new(Credentials::new());
    let server_credentials = credentials.clone();
    let choice = choice()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let protocol = authenticate_target(socket, &server_credentials, &choice)
            .await
            .map_err(|_| io::Error::other("component rejected valid test client"))?;
        let mut stream = protocol
            .reply_success(address)
            .await
            .map_err(|_| io::Error::other("component success reply failed"))?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        if request != b"request before FIN" {
            return Err(io::Error::other("request bytes differ"));
        }
        stream.write_all(b"reply after FIN").await?;
        stream.shutdown().await
    });
    let mut client = Socks5Stream::connect_with_password(
        address,
        "db.nestlink.internal".into(),
        4444,
        credentials.username.expose().to_owned(),
        credentials.password.expose().to_owned(),
        Config::default(),
    )
    .await
    .map_err(|_| io::Error::other("standard authenticated client failed"))?;
    client.write_all(b"request before FIN").await?;
    client.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(SETUP_BUDGET, client.read_to_end(&mut response)).await??;
    assert_eq!(response, b"reply after FIN");
    server.await??;
    Ok(())
}

// Test transport fault injection: corrupt the first byte written after the
// client's first read. fast-socks5 still creates the complete RFC1929 message;
// this wrapper implements neither a SOCKS parser nor an authentication codec.
struct CorruptAfterRead<S> {
    inner: S,
    corrupt: bool,
    changed: Arc<AtomicBool>,
}
impl<S: AsyncRead + Unpin> AsyncRead for CorruptAfterRead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() > before
            && !self.changed.load(Ordering::SeqCst)
        {
            self.corrupt = true;
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CorruptAfterRead<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.corrupt && !buf.is_empty() {
            let mut corrupted = Zeroizing::new(buf.to_vec());
            corrupted[0] ^= 0x80;
            let result = Pin::new(&mut self.inner).poll_write(cx, &corrupted);
            if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
                self.corrupt = false;
                self.changed.store(true, Ordering::SeqCst);
            }
            result
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn component_refuses_corrupted_rfc1929_version_before_credential_check()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, client) = tokio::io::duplex(1024);
    let checked = Arc::new(AtomicBool::new(false));
    let server_checked = checked.clone();
    let server = tokio::spawn(async move {
        Socks5ServerProtocol::accept_password_auth(server, |_, _| {
            server_checked.store(true, Ordering::SeqCst);
            true
        })
        .await
        .is_err()
    });
    let changed = Arc::new(AtomicBool::new(false));
    let credentials = Credentials::new();
    let client = CorruptAfterRead {
        inner: client,
        corrupt: false,
        changed: changed.clone(),
    };
    let result = tokio::time::timeout(
        SETUP_BUDGET,
        Socks5Stream::use_stream(client, Some(password(&credentials)), Config::default()),
    )
    .await?;
    assert!(result.is_err());
    assert!(server.await?);
    assert!(changed.load(Ordering::SeqCst));
    assert!(!checked.load(Ordering::SeqCst));
    Ok(())
}

struct ComponentLogs(Mutex<Vec<String>>);
static COMPONENT_LOGS: ComponentLogs = ComponentLogs(Mutex::new(Vec::new()));
impl log::Log for ComponentLogs {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Debug && metadata.target().starts_with("fast_socks5")
    }
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata())
            && let Ok(mut logs) = self.0.lock()
        {
            logs.push(format!("{}", record.args()));
        }
    }
    fn flush(&self) {}
}
#[tokio::test]
async fn debug_authentication_logs_never_contain_random_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    log::set_logger(&COMPONENT_LOGS)
        .map_err(|_| io::Error::other("component test logger already installed"))?;
    log::set_max_level(log::LevelFilter::Debug);
    let credentials = Arc::new(Credentials::new());
    assert!(
        protocol_attempt(
            credentials.clone(),
            Some(password(&credentials)),
            Socks5Command::TCPConnect,
            "db.nestlink.internal",
            4444
        )
        .await?
    );
    let wrong = Credentials::new();
    assert!(
        !protocol_attempt(
            credentials.clone(),
            Some(password(&wrong)),
            Socks5Command::TCPConnect,
            "db.nestlink.internal",
            4444
        )
        .await?
    );
    let logs = COMPONENT_LOGS
        .0
        .lock()
        .map_err(|_| io::Error::other("component test logger poisoned"))?;
    assert!(
        logs.iter()
            .any(|line| line.contains("Password authentication accepted"))
    );
    assert!(
        logs.iter()
            .any(|line| line.contains("Password authentication rejected"))
    );
    for credential in [
        &credentials.username,
        &credentials.password,
        &wrong.username,
        &wrong.password,
    ] {
        let decimal_bytes = format!("{:?}", credential.expose().as_bytes());
        assert!(
            !logs
                .iter()
                .any(|line| line.contains(credential.expose()) || line.contains(&decimal_bytes)),
            "component authentication log exposed a credential"
        );
    }
    Ok(())
}

#[test]
fn credential_cleanup_preserves_replacement_and_only_removes_original()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("private");
    nestlink_platform_security::new_private_directory(&directory)?;
    let file = CredentialFile {
        path: directory.join("credentials.json"),
        original: Zeroizing::new(b"original".to_vec()),
    };
    nestlink_platform_security::create_private(&file.path, &file.original)?;
    std::fs::write(&file.path, b"replacement")?;
    assert!(file.remove().is_err());
    assert_eq!(
        &*nestlink_platform_security::read_private(&file.path, CREDENTIAL_BYTES)?,
        b"replacement"
    );
    std::fs::write(&file.path, &file.original)?;
    file.remove()?;
    assert!(!file.path.exists());
    assert!(directory.exists());
    Ok(())
}

#[tokio::test]
async fn cancelled_wait_keeps_original_cleanup_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let (stop, mut stopped) = watch::channel(false);
    let (release, released) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        stopping(&mut stopped).await;
        let _ = released.await;
        LocalProxyStopReport {
            credentials_removed: true,
            completed_connections: 1,
            ..LocalProxyStopReport::default()
        }
    });
    let mut owner = LocalServiceProxy {
        address: "127.0.0.1:1".parse()?,
        credentials_path: PathBuf::new(),
        stop,
        task: Some(task),
        report: None,
        runtime: tokio::runtime::Handle::current(),
    };
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            owner.wait_stopped(Duration::from_secs(2))
        )
        .await
        .is_err()
    );
    assert!(owner.task.is_some());
    assert_eq!(
        owner.wait_stopped(Duration::from_millis(10)).await,
        LocalProxyWait::CleanupPending
    );
    release
        .send(())
        .map_err(|_| io::Error::other("original cleanup owner disappeared"))?;
    let LocalProxyWait::Stopped(report) = owner.wait_stopped(Duration::from_secs(2)).await else {
        return Err(io::Error::other("original cleanup receipt was not observed").into());
    };
    assert_eq!(report.completed_connections, 1);
    assert!(owner.task.is_none());
    assert_eq!(
        owner.wait_stopped(Duration::ZERO).await,
        LocalProxyWait::Stopped(report)
    );
    Ok(())
}
