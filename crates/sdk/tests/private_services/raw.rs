//! L2 hosted Linux experiment: real SDK authority, raw sockets and nft UID
//! fences. These ignored cases require the dedicated workflow. The helper and
//! probe roles run this same test executable; neither role is an acceptance case.
use super::*;
use nestlink_platform_security::local_port_gate::{
    GateOwner, GatePlan, ProcessIdentity, RootGateReceipt, Transport, wall_ms as gate_clock_ms,
};
use nestlink_sdk::services::{LocalProxyError, LocalRawServiceTls, RawProxyWait};
use serde_json::{Value, json};
use std::{fs::File, process::Stdio, sync::Mutex};
use tokio::{
    process::{Child, Command},
    sync::oneshot,
};

const ROLE_PREFIX: &str = "NESTLINK_RAW_ROLE_RESULT=";
const HOSTED_KEYS: [&str; 5] = [
    "GITHUB_ACTIONS",
    "RUNNER_ENVIRONMENT",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_SHA",
];

fn hosted() -> Result {
    if std::env::var("NESTLINK_RAW_KERNEL_GATE").as_deref() != Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("GITHUB_REPOSITORY").as_deref() != Ok("ZHanry/NestLink")
        || !std::env::var("GITHUB_WORKFLOW_REF")?
            .starts_with("ZHanry/NestLink/.github/workflows/local-port-gate.yml@refs/")
    {
        return Err("kernel gate experiment requires its dedicated GitHub-hosted workflow".into());
    }
    Ok(())
}

fn variable(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).ok_or("experiment path missing")?);
    if !path.is_absolute() {
        return Err("experiment path must be absolute".into());
    }
    Ok(path)
}

fn root_role(action: &str) -> Result<Command> {
    let mut command = Command::new("sudo");
    command.args(["--non-interactive", "env", "NESTLINK_RAW_KERNEL_GATE=1"]);
    for name in HOSTED_KEYS {
        command.arg(format!("{name}={}", std::env::var(name)?));
    }
    command.arg(format!("NESTLINK_RAW_KERNEL_ROLE={action}"));
    command.arg(format!(
        "NESTLINK_RAW_KERNEL_ROOT={}",
        variable("NESTLINK_RAW_KERNEL_ROOT")?.display()
    ));
    if action == "install" {
        command.arg(format!(
            "NESTLINK_RAW_KERNEL_PLAN={}",
            variable("NESTLINK_RAW_KERNEL_OUTPUT")?
                .join("private-plan/plan.json")
                .display()
        ));
    }
    command
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "raw::root_helper_role",
            "--nocapture",
            "--test-threads=1",
            "--color=never",
        ])
        .stdin(Stdio::null());
    Ok(command)
}

#[tokio::test]
#[ignore = "cooperation role; invoked explicitly by the hosted raw experiment"]
async fn root_helper_role() -> Result {
    hosted()?;
    if ProcessIdentity::read(std::process::id())?.uid != 0 {
        return Err("root helper must be root".into());
    }
    let root = variable("NESTLINK_RAW_KERNEL_ROOT")?;
    let directory = root.join("journal");
    match std::env::var("NESTLINK_RAW_KERNEL_ROLE")?.as_str() {
        "install" => {
            GateOwner::initialize_journal(&directory)?;
            let plan = GatePlan::read_public(&variable("NESTLINK_RAW_KERNEL_PLAN")?)?;
            let mut owner = GateOwner::install(plan, &directory).await?;
            owner.publish_receipt(&root.join("receipt.json")).await?;
            tokio::time::timeout(Duration::from_secs(90), async {
                loop {
                    if !owner.owner_alive()? {
                        return owner.cleanup_after_owner_exit().await;
                    }
                    if gate_clock_ms()? >= owner.plan().expires_at_ms && !owner.is_denied() {
                        owner.deny_all().await?;
                    }
                    owner.verify_unchanged().await?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await??;
            println!(
                "{ROLE_PREFIX}{}",
                json!({"role":"install", "cleaned_after_owner_exit":true})
            );
        }
        "recover" => {
            GateOwner::recover(&directory).await?;
            println!(
                "{ROLE_PREFIX}{}",
                json!({"role":"recover", "recovered":true})
            );
        }
        "inspect" => {
            println!(
                "{ROLE_PREFIX}{}",
                json!({"role":"inspect", "state":GateOwner::inspect_journal(&directory).await?})
            );
        }
        _ => return Err("unknown root cooperation role".into()),
    }
    Ok(())
}

#[tokio::test]
#[ignore = "cooperation role; invoked explicitly by the hosted raw experiment"]
async fn uid_probe_role() -> Result {
    hosted()?;
    let identity = ProcessIdentity::read(std::process::id())?;
    let address: SocketAddr = std::env::var("NESTLINK_RAW_PROBE_ADDRESS")?.parse()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("invalid probe target".into());
    }
    let payload = if std::env::var("NESTLINK_RAW_PROBE_EMPTY").as_deref() == Ok("1") {
        Vec::new()
    } else {
        let mut bytes = vec![0, 255, 128];
        bytes.extend_from_slice(std::env::var("NESTLINK_RAW_PROBE_NONCE")?.as_bytes());
        bytes
    };
    let transport = std::env::var("NESTLINK_RAW_PROBE_TRANSPORT")?;
    let exchange = async {
        if transport == "tcp" {
            let mut stream = TcpStream::connect(address).await?;
            stream
                .write_u16(payload.len().try_into().map_err(std::io::Error::other)?)
                .await?;
            stream.write_all(&payload).await?;
            let mut reply = vec![0; payload.len()];
            stream.read_exact(&mut reply).await?;
            Ok::<_, std::io::Error>(reply == payload)
        } else if transport == "udp" {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(address).await?;
            socket.send(&payload).await?;
            let mut reply = [0u8; 2048];
            let size = socket.recv(&mut reply).await?;
            Ok(reply[..size] == payload)
        } else {
            Err(std::io::Error::other("unknown probe transport"))
        }
    };
    let budget = Duration::from_secs(if identity.uid == 65534 { 2 } else { 5 });
    let allowed = matches!(tokio::time::timeout(budget, exchange).await, Ok(Ok(true)));
    println!(
        "{ROLE_PREFIX}{}",
        json!({
            "role":"probe", "uid":identity.uid, "pid":identity.pid, "transport":transport,
            "address":address, "allowed":allowed, "payload":payload,
        })
    );
    Ok(())
}

fn role_result(output: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(output)?;
    let rows: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.find(ROLE_PREFIX)
                .map(|index| &line[index + ROLE_PREFIX.len()..])
        })
        .collect();
    if rows.len() != 1 {
        return Err(format!("expected one cooperation result: {text}").into());
    }
    Ok(serde_json::from_str(rows[0])?)
}

async fn probe(
    address: SocketAddr,
    transport: &str,
    other_uid: bool,
    empty: bool,
    label: &str,
) -> Result<Value> {
    let choices = [
        ("NESTLINK_RAW_KERNEL_GATE", "1".into()),
        ("NESTLINK_RAW_PROBE_ADDRESS", address.to_string()),
        ("NESTLINK_RAW_PROBE_TRANSPORT", transport.into()),
        (
            "NESTLINK_RAW_PROBE_EMPTY",
            if empty { "1" } else { "0" }.into(),
        ),
        ("NESTLINK_RAW_PROBE_NONCE", random_id()),
    ];
    // sudo filters its inherited environment. Pass only these public probe
    // choices explicitly after env, never any management or installation data.
    let mut command = if other_uid {
        let mut command = Command::new("sudo");
        command.args([
            "--non-interactive",
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--no-new-privs",
            "env",
        ]);
        for name in HOSTED_KEYS {
            command.arg(format!("{name}={}", std::env::var(name)?));
        }
        for (name, value) in &choices {
            command.arg(format!("{name}={value}"));
        }
        command.arg(std::env::current_exe()?);
        command
    } else {
        let mut command = Command::new(std::env::current_exe()?);
        command.envs(choices);
        command
    };
    command
        .args([
            "--ignored",
            "--exact",
            "raw::uid_probe_role",
            "--nocapture",
            "--test-threads=1",
            "--color=never",
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(8), command.output()).await??;
    let directory = variable("NESTLINK_RAW_KERNEL_OUTPUT")?;
    std::fs::write(
        directory.join(format!("{label}.log")),
        [&output.stdout[..], &output.stderr[..]].concat(),
    )?;
    if !output.status.success() {
        return Err(format!("probe role {label} failed").into());
    }
    let result = role_result(&output.stdout)?;
    let expected_uid = if other_uid {
        65534
    } else {
        ProcessIdentity::read(std::process::id())?.uid
    };
    assert_eq!(result["uid"], expected_uid);
    assert_eq!(result["allowed"], !other_uid);
    Ok(result)
}

async fn nft_snapshot(table: &str, label: &str) -> Result<Value> {
    let output = Command::new("sudo")
        .args([
            "--non-interactive",
            "nft",
            "--json",
            "--handle",
            "--numeric",
            "list",
            "table",
            "inet",
            table,
        ])
        .output()
        .await?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    std::fs::write(
        variable("NESTLINK_RAW_KERNEL_OUTPUT")?.join(format!("{label}.nft.json")),
        &output.stdout,
    )?;
    Ok(value)
}

struct Backend {
    address: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result>,
}
async fn backend(transport: Transport) -> Result<Backend> {
    let received = Arc::new(Mutex::new(Vec::new()));
    let copy = received.clone();
    let (stop, mut stopped) = oneshot::channel();
    let (address, task) = match transport {
        Transport::Tcp => {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let task = tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! { biased; _ = &mut stopped => break, accepted = listener.accept() => accepted };
                    let (mut stream, _) = accepted?;
                    let packet = async {
                        let size = usize::from(stream.read_u16().await?);
                        if size > 2048 {
                            return Err(std::io::Error::other("backend frame too large"));
                        }
                        let mut buffer = vec![0; size];
                        stream.read_exact(&mut buffer).await?;
                        Ok::<_, std::io::Error>(buffer)
                    };
                    let buffer = tokio::time::timeout(Duration::from_secs(6), packet).await??;
                    copy.lock()
                        .map_err(|_| "backend witness poisoned")?
                        .push(buffer.clone());
                    stream.write_all(&buffer).await?;
                    stream.shutdown().await?;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            (address, task)
        }
        Transport::Udp => {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let address = socket.local_addr()?;
            let task = tokio::spawn(async move {
                let mut buffer = [0; 2048];
                loop {
                    let packet = tokio::select! { biased; _ = &mut stopped => break, packet = socket.recv_from(&mut buffer) => packet };
                    let (size, peer) = packet?;
                    copy.lock()
                        .map_err(|_| "backend witness poisoned")?
                        .push(buffer[..size].to_vec());
                    socket.send_to(&buffer[..size], peer).await?;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            (address, task)
        }
    };
    Ok(Backend {
        address,
        received,
        stop,
        task,
    })
}

enum Reservation {
    Tcp(std::net::TcpListener),
    Udp(std::net::UdpSocket),
}
impl Reservation {
    fn bind(transport: Transport, endpoint: SocketAddr) -> std::io::Result<Self> {
        match transport {
            Transport::Tcp => Ok(Self::Tcp(std::net::TcpListener::bind(endpoint)?)),
            Transport::Udp => Ok(Self::Udp(std::net::UdpSocket::bind(endpoint)?)),
        }
    }
    fn address(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            Self::Udp(socket) => socket.local_addr(),
        }
    }
}

async fn install(plan: &GatePlan) -> Result<(Child, RootGateReceipt)> {
    let output = variable("NESTLINK_RAW_KERNEL_OUTPUT")?;
    let private_plan = output.join("private-plan");
    nestlink_platform_security::new_private_directory(&private_plan)?;
    plan.save_new(&private_plan.join("plan.json"))?;
    let mut command = root_role("install")?;
    command
        .stdout(File::create(output.join("root-helper.log"))?)
        .stderr(File::create(output.join("root-helper.stderr.log"))?);
    let mut child = command.spawn()?;
    let path = variable("NESTLINK_RAW_KERNEL_ROOT")?.join("receipt.json");
    let receipt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(format!("root helper exited before receipt: {status}").into());
            }
            if path.try_exists()? {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    RootGateReceipt::read_for_current_process(&path, plan)?,
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    std::fs::write(
        output.join("root-receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok((child, receipt))
}

async fn local_tls_experiment(
    sdk: &Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    choice: LocalProxyServiceChoice,
    plan: &GatePlan,
    receipt_path: &std::path::Path,
    backend: &Backend,
    original_receipt: &RootGateReceipt,
) -> Result<Value> {
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    let name = "owned-raw.nestlink.internal";
    let certificate = rcgen::generate_simple_self_signed(vec![name.into()])?;
    // This local certificate is independent of the original remote service's
    // installation-pinned QUIC identity. Only its public DER becomes evidence.
    std::fs::write(
        variable("NESTLINK_RAW_KERNEL_OUTPUT")?.join("local-tls-certificate.der"),
        certificate.cert.der().as_ref(),
    )?;
    let local_tls = LocalRawServiceTls::from_der(
        vec![certificate.cert.der().to_vec()],
        certificate.signing_key.serialize_der(),
    )?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate.cert.der().clone())?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut proxy = sdk
        .start_private_service_raw_with_tls(
            consumer,
            choice,
            plan.clone(),
            receipt_path,
            Some(local_tls),
        )
        .await?;
    assert_eq!(proxy.address(), plan.endpoint);
    let receipt = RootGateReceipt::read_for_current_process(receipt_path, plan)?;
    assert_eq!(&receipt, original_receipt);
    let before_wrong = backend
        .received
        .lock()
        .map_err(|_| "backend witness poisoned")?
        .len();
    let wrong_name = ServerName::try_from("wrong-name.invalid")?;
    let wrong = tokio::time::timeout(Duration::from_secs(5), async {
        connector
            .connect(wrong_name, TcpStream::connect(plan.endpoint).await?)
            .await
    })
    .await?;
    let error = match wrong {
        Ok(_) => return Err("standard TLS client accepted the wrong certificate name".into()),
        Err(error) => error,
    };
    assert!(
        error.get_ref().is_some_and(|cause| {
            matches!(
                cause.downcast_ref::<rustls::Error>(),
                Some(rustls::Error::InvalidCertificate(_))
            )
        }),
        "wrong-name denial must be certificate validation, not transport failure: {error}"
    );
    assert_eq!(
        backend
            .received
            .lock()
            .map_err(|_| "backend witness poisoned")?
            .len(),
        before_wrong
    );
    assert!(
        !proxy.is_finished(),
        "certificate denial must leave the original owner alive"
    );
    let trusted_name = ServerName::try_from(name)?;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
        connector
            .connect(trusted_name, TcpStream::connect(plan.endpoint).await?)
            .await
    })
    .await??;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
    let mut payload = vec![0, 255, 128, 13, 10, 0];
    payload.extend_from_slice(random_id().as_bytes());
    let size = u16::try_from(payload.len())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_u16(size).await?;
        stream.write_all(&payload).await?;
        stream.shutdown().await
    })
    .await??;
    let mut reply = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        (&mut stream).take(2049).read_to_end(&mut reply),
    )
    .await??;
    assert_eq!(reply, payload);
    drop(stream);
    receipt.check_current(plan)?;
    {
        let received = backend
            .received
            .lock()
            .map_err(|_| "backend witness poisoned")?;
        assert_eq!(received.len(), before_wrong + 1);
        assert_eq!(received.last(), Some(&payload));
    }
    let report = match proxy.wait_stopped(Duration::from_secs(8)).await {
        RawProxyWait::Stopped(report) => report,
        other => {
            return Err(
                format!("local TLS cleanup was not physically confirmed: {other:?}").into(),
            );
        }
    };
    assert!(report.socket_closed);
    assert_eq!(report.accepted_connections, 2);
    assert_eq!(report.completed_connections, 2);
    assert_eq!(report.rejected_connections, 1);
    assert_eq!(report.failed_connections, 0);
    assert_eq!(report.cleanup_failures, 0);
    assert_eq!(
        RootGateReceipt::read_for_current_process(receipt_path, plan)?,
        receipt,
        "local TLS must preserve the exact original live-process gate receipt"
    );
    drop(TcpListener::bind(plan.endpoint).await?);
    Ok(json!({
        "kind":"local_tls_over_original_private_tcp_service",
        "plan":plan, "helper":receipt.helper,
        "trusted_name":name, "wrong_name":"wrong-name.invalid",
        "trusted_ca_validated":true, "wrong_name_rejected":true,
        "certificate_der":"local-tls-certificate.der",
        "client_trust":"explicit_generated_single_root",
        "original_receipt_unchanged":true,
        "wrong_name_error":error.to_string(),
        "rejected_handshake_backend_unchanged":true,
        "backend_payloads_before_tls":before_wrong,
        "backend_payloads_after_tls":before_wrong + 1,
        "payload":payload, "reply":reply,
        "accepted_connections":report.accepted_connections,
        "completed_connections":report.completed_connections,
        "rejected_connections":report.rejected_connections,
        "failed_connections":report.failed_connections,
        "cleanup_failures":report.cleanup_failures,
        "socket_closed":report.socket_closed, "socket_rebound":true,
        "remote_https_validated":false,
    }))
}

async fn exercise(transport: Transport, kill_helper: bool) -> Result {
    hosted()?;
    let identity = ProcessIdentity::read(std::process::id())?;
    if identity.uid == 0 || identity.uid == 65534 {
        return Err("SDK business owner must be ordinary runner UID".into());
    }
    let output = variable("NESTLINK_RAW_KERNEL_OUTPUT")?;
    let backend = backend(transport).await?;
    let protocol = if transport == Transport::Tcp {
        "tcp"
    } else {
        "udp"
    };
    let f = Fixture::new(protocol, backend.address).await?;
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
        .private_services(&f.consumer.device_id, None, 20)
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.service.id == f.view.id)
        .ok_or("ready private service missing")?;
    let choice = || {
        LocalProxyServiceChoice::from_local_choice(
            &entry,
            "fixed.nestlink.internal",
            29100,
            4096,
            Duration::from_secs(35),
        )
    };
    let reserved = Reservation::bind(transport, "127.0.0.1:0".parse()?)?;
    let endpoint = reserved.address()?;
    let plan =
        GatePlan::for_current_process(random_id(), endpoint, transport, wall_ms()? + 45_000)?;
    let table = format!("nlp_{}", plan.owner_id.replace('-', ""));
    let (mut helper, receipt) = install(&plan).await?;
    let receipt_path = variable("NESTLINK_RAW_KERNEL_ROOT")?.join("receipt.json");
    nft_snapshot(&table, "installed").await?;
    let consumer = Arc::new(f.consumer);
    let occupied = f
        .sdk
        .start_private_service_raw(consumer.clone(), choice()?, plan.clone(), &receipt_path)
        .await;
    assert!(
        matches!(occupied, Err(LocalProxyError::Io(error)) if error.kind() == std::io::ErrorKind::AddrInUse),
        "occupied endpoint must fail at its exact bind without adopting the socket"
    );
    assert_eq!(reserved.address()?, endpoint);
    drop(reserved);
    let mut proxy = f
        .sdk
        .start_private_service_raw(consumer.clone(), choice()?, plan.clone(), &receipt_path)
        .await?;
    assert_eq!(proxy.address(), endpoint);
    let mut probes = vec![probe(endpoint, protocol, false, false, "same-uid-before").await?];
    let before = backend
        .received
        .lock()
        .map_err(|_| "backend witness poisoned")?
        .len();
    probes.push(probe(endpoint, protocol, true, false, "different-uid").await?);
    assert_eq!(
        backend
            .received
            .lock()
            .map_err(|_| "backend witness poisoned")?
            .len(),
        before,
        "rejected UID reached the approved backend"
    );
    assert!(
        !proxy.is_finished(),
        "UID denial must not be explained by an exited raw owner"
    );
    probes.push(probe(endpoint, protocol, false, false, "same-uid-after").await?);
    if transport == Transport::Udp {
        probes.push(probe(endpoint, protocol, false, true, "empty-datagram").await?);
    }
    let installed = nft_snapshot(&table, "after-probes").await?;
    let mut early_recovery_rejected = false;
    if kill_helper {
        receipt.check_current(&plan)?;
        let killed = Command::new("sudo")
            .args([
                "--non-interactive",
                "kill",
                "-KILL",
                "--",
                &receipt.helper.pid.to_string(),
            ])
            .status()
            .await?;
        assert!(killed.success());
        let _ = tokio::time::timeout(Duration::from_secs(5), helper.wait()).await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !proxy.is_finished() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        assert!(receipt.check_current(&plan).is_err());
        assert_eq!(
            installed,
            nft_snapshot(&table, "after-helper-kill").await?,
            "helper crash must preserve the exact kernel fence"
        );
        let denied = root_role("recover")?.output().await?;
        std::fs::write(
            output.join("early-recover.log"),
            [&denied.stdout[..], &denied.stderr[..]].concat(),
        )?;
        assert!(
            !denied.status.success(),
            "socket owner process is still alive; gate deletion must fail"
        );
        early_recovery_rejected = true;
    }
    let report = match proxy.wait_stopped(Duration::from_secs(8)).await {
        RawProxyWait::Stopped(report) => report,
        other => return Err(format!("raw cleanup was not physically confirmed: {other:?}").into()),
    };
    assert!(report.socket_closed);
    assert_eq!(report.cleanup_failures, 0);
    match transport {
        // Tokio uses the same mature SO_REUSEADDR policy as the original
        // listener, so TCP TIME_WAIT cannot masquerade as a live accept socket.
        Transport::Tcp => drop(TcpListener::bind(endpoint).await?),
        Transport::Udp => drop(UdpSocket::bind(endpoint).await?),
    }
    let local_tls = if transport == Transport::Tcp {
        let result = local_tls_experiment(
            &f.sdk,
            consumer,
            choice()?,
            &plan,
            &receipt_path,
            &backend,
            &receipt,
        )
        .await?;
        assert_eq!(
            installed,
            nft_snapshot(&table, "after-local-tls").await?,
            "local TLS must reuse the original unchanged kernel gate"
        );
        Some(result)
    } else {
        None
    };
    // Ending a proxy is not process exit. The gate must still protect the
    // endpoint until this exact test process exits and the helper/recover joins.
    nft_snapshot(&table, "after-socket-close").await?;
    host.wait_stopped().await?;
    let received = backend
        .received
        .lock()
        .map_err(|_| "backend witness poisoned")?
        .clone();
    for result in probes.iter().filter(|probe| probe["allowed"] == true) {
        let payload: Vec<u8> = serde_json::from_value(result["payload"].clone())?;
        assert!(
            received.contains(&payload),
            "successful probe has no approved-backend witness"
        );
    }
    let _ = backend.stop.send(());
    tokio::time::timeout(Duration::from_secs(5), backend.task).await???;
    std::fs::write(
        output.join("scenario.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version":1, "evidence_level":"L2_hosted_sdk_kernel", "production_cli_validated":false,
            "source_revision":std::env::var("GITHUB_SHA")?, "owner":identity, "protocol":protocol,
            "table":table, "plan":plan, "probes":probes, "backend_payloads":received,
            "local_tls":local_tls,
            "occupied_port_rejected":true, "socket_closed":report.socket_closed,
            "cleanup_failures":report.cleanup_failures, "helper_killed":kill_helper,
            "live_process_recovery_rejected":early_recovery_rejected,
            "gate_retained_after_socket_close":true,
            "accepted_connections":report.accepted_connections,
            "forwarded_datagrams":report.forwarded_datagrams,
            "status":"passed_before_owner_process_exit",
        }))?,
    )?;
    drop(proxy);
    drop(host);
    std::fs::remove_dir_all(f.usage)?;
    // Dropping this Child handle deliberately does not kill the privileged
    // controller. The outer script waits for process-exit cleanup separately.
    drop(helper);
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated GitHub-hosted nftables workflow"]
async fn tcp_uid_fence_and_physical_cleanup() -> Result {
    tokio::time::timeout(Duration::from_secs(40), exercise(Transport::Tcp, false)).await?
}

#[tokio::test]
#[ignore = "requires dedicated GitHub-hosted nftables workflow"]
async fn udp_uid_fence_empty_datagrams_and_helper_crash() -> Result {
    tokio::time::timeout(Duration::from_secs(40), exercise(Transport::Udp, true)).await?
}
