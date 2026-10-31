//! Real hosted Windows SDK/WFP experiment. The external elevated coordinator
//! launches this exact protected executable with three actual OS identities.
//! These roles never run in the ordinary test suite or on a developer machine.
use super::*;
use nestlink_privileged::windows::{
    local_port_gate::{
        GateOwner, GatePlan, ProcessIdentity, RootGateReceipt, Transport, wall_ms as gate_clock,
    },
    require_administrator_process, require_normal_user_process,
};
use nestlink_sdk::services::RawProxyWait;
use serde_json::{Value, json};
use std::{fs, sync::Mutex};
use tokio::{sync::oneshot, task::JoinHandle};

const PREFIX: &str = "NESTLINK_WFP_ROLE_RESULT=";
fn hosted() -> Result {
    if std::env::var("NESTLINK_WFP_KERNEL").as_deref() != Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Windows")
        || std::env::var("GITHUB_REPOSITORY").as_deref() != Ok("ZHanry/NestLink")
        || !std::env::var("GITHUB_WORKFLOW_REF")?
            .starts_with("ZHanry/NestLink/.github/workflows/windows-local-port-gate.yml@refs/")
    {
        return Err("WFP experiment requires its dedicated GitHub-hosted Windows workflow".into());
    }
    Ok(())
}
fn path(name: &str) -> Result<PathBuf> {
    let value = PathBuf::from(std::env::var_os(name).ok_or("missing WFP experiment path")?);
    if !value.is_absolute() {
        return Err("absolute experiment path required".into());
    }
    Ok(value)
}
fn write(path: &std::path::Path, value: &Value) -> Result {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
async fn stage(root: &std::path::Path, expected: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(65), async {
        loop {
            if fs::read(root.join("control.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|value| value["stage"] == expected)
            {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await??;
    Ok(())
}
#[tokio::test]
#[ignore = "administrative cooperation role; dedicated hosted WFP workflow only"]
async fn administrator_role() -> Result {
    hosted()?;
    require_administrator_process()?;
    let root = path("NESTLINK_WFP_ROOT")?;
    let journal = root.join("journal");
    match std::env::var("NESTLINK_WFP_ACTION")?.as_str() {
        "install" => {
            GateOwner::initialize_journal(&journal)?;
            let plan = GatePlan::read_public(&path("NESTLINK_WFP_PLAN")?)?;
            let mut owner = GateOwner::install(plan, &journal).await?;
            owner.publish_receipt(&root.join("receipt.json")).await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
            let mut previous = gate_clock()?;
            loop {
                if !owner.owner_alive()? {
                    owner.cleanup_after_owner_exit().await?;
                    write(
                        &root.join("helper-finished.json"),
                        &json!({"cleaned_after_owner_exit":true}),
                    )?;
                    break;
                }
                let now = gate_clock()?;
                if (now < previous || now >= owner.plan().expires_at_ms) && !owner.is_denied() {
                    owner.deny_all().await?;
                }
                previous = now;
                owner.verify_unchanged().await?;
                write(&root.join("current.json"), &owner.receipt()?)?;
                if tokio::time::Instant::now() >= deadline {
                    return Err(
                        "helper observation budget exhausted; persistent fence retained".into(),
                    );
                }
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        }
        "inspect" => println!(
            "{PREFIX}{}",
            json!({"state":GateOwner::inspect_journal(&journal).await?})
        ),
        "recover" => {
            GateOwner::recover(&journal).await?;
            println!("{PREFIX}{}", json!({"recovered":true}));
        }
        _ => return Err("unknown administrator cooperation action".into()),
    }
    Ok(())
}
#[tokio::test]
#[ignore = "actual same/different SID probe; dedicated hosted WFP workflow only"]
async fn probe_role() -> Result {
    hosted()?;
    require_normal_user_process()?;
    let identity = ProcessIdentity::read(std::process::id())?;
    let role = std::env::var("NESTLINK_WFP_PROBE")?;
    let value = if role == "identity" {
        json!({"identity":identity,"role":"identity"})
    } else {
        let endpoint: SocketAddr = std::env::var("NESTLINK_WFP_ENDPOINT")?.parse()?;
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err("probe endpoint must be loopback".into());
        }
        let transport = std::env::var("NESTLINK_WFP_TRANSPORT")?;
        let payload = if std::env::var("NESTLINK_WFP_EMPTY").as_deref() == Ok("1") {
            Vec::new()
        } else {
            [
                vec![0, 255, 128],
                std::env::var("NESTLINK_WFP_NONCE")?.into_bytes(),
            ]
            .concat()
        };
        let exchange = async {
            if transport == "tcp" {
                let mut stream = TcpStream::connect(endpoint).await?;
                stream
                    .write_u16(u16::try_from(payload.len()).map_err(std::io::Error::other)?)
                    .await?;
                stream.write_all(&payload).await?;
                // The actual client actively half-closes its request. The
                // listener therefore need not own TIME_WAIT after replying;
                // immediate witness rebinding tests physical release rather
                // than Windows' unrelated active-close timeout policy.
                stream.shutdown().await?;
                let mut reply = vec![0; payload.len()];
                stream.read_exact(&mut reply).await?;
                Ok::<bool, std::io::Error>(reply == payload)
            } else if transport == "udp" {
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                socket.connect(endpoint).await?;
                socket.send(&payload).await?;
                let mut bytes = [0; 2048];
                let size = socket.recv(&mut bytes).await?;
                Ok(bytes[..size] == payload)
            } else {
                Err(std::io::Error::other("unknown probe transport"))
            }
        };
        let allowed = matches!(
            tokio::time::timeout(Duration::from_secs(2), exchange).await,
            Ok(Ok(true))
        );
        json!({"identity":identity,"role":"probe","endpoint":endpoint,"transport":transport,"payload":payload,"allowed":allowed})
    };
    write(&path("NESTLINK_WFP_RESULT")?, &value)?;
    println!("{PREFIX}{value}");
    Ok(())
}
struct Echo {
    address: SocketAddr,
    bytes: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result>,
}
async fn echo(transport: Transport, endpoint: SocketAddr) -> Result<Echo> {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let witness = bytes.clone();
    let (stop, mut stopped) = oneshot::channel();
    let (address, task) = match transport {
        Transport::Tcp => {
            let socket = TcpListener::bind(endpoint).await?;
            let address = socket.local_addr()?;
            let task = tokio::spawn(async move {
                let mut workers = tokio::task::JoinSet::new();
                loop {
                    tokio::select! { biased;
                        _=&mut stopped=>break,
                        result=workers.join_next(),if !workers.is_empty()=>{ if !matches!(result,Some(Ok(Ok(())))) { return Err("echo worker failed".into()); } },
                        accepted=socket.accept()=>{
                            let (mut stream,_)=accepted?; let witness=witness.clone();
                            workers.spawn(async move {
                                let size=stream.read_u16().await? as usize;
                                if size>2048 {return Err(std::io::Error::other("probe payload exceeds bound"));}
                                let mut bytes=vec![0;size];stream.read_exact(&mut bytes).await?;
                                witness.lock().map_err(|_|std::io::Error::other("witness poisoned"))?.push(bytes.clone());
                                stream.write_all(&bytes).await?;stream.shutdown().await
                            });
                        },
                    }
                }
                drop(socket);
                while let Some(result) = workers.join_next().await {
                    result??;
                }
                Ok(())
            });
            (address, task)
        }
        Transport::Udp => {
            let socket = UdpSocket::bind(endpoint).await?;
            let address = socket.local_addr()?;
            let task = tokio::spawn(async move {
                let mut buffer = [0; 2048];
                loop {
                    tokio::select! {biased;
                        _=&mut stopped=>break,
                        result=socket.recv_from(&mut buffer)=>{
                            let (size,peer)=result?;witness.lock().map_err(|_|"witness poisoned")?.push(buffer[..size].to_vec());
                            socket.send_to(&buffer[..size],peer).await?;
                        },
                    }
                }
                Ok(())
            });
            (address, task)
        }
    };
    Ok(Echo {
        address,
        bytes,
        stop,
        task,
    })
}
async fn finish_echo(echo: Echo) -> Result<Vec<Vec<u8>>> {
    let _ = echo.stop.send(());
    tokio::time::timeout(Duration::from_secs(5), echo.task).await???;
    let bytes = echo.bytes.lock().map_err(|_| "witness poisoned")?.clone();
    Ok(bytes)
}
#[tokio::test]
#[ignore = "real medium SDK owner; dedicated hosted WFP workflow only"]
async fn sdk_owner_role() -> Result {
    hosted()?;
    require_normal_user_process()?;
    tokio::time::timeout(Duration::from_secs(100), owner()).await?
}
async fn owner() -> Result {
    let identity = ProcessIdentity::read(std::process::id())?;
    let root = path("NESTLINK_WFP_ROOT")?;
    let output = path("NESTLINK_WFP_OUTPUT")?;
    let transport = match std::env::var("NESTLINK_WFP_TRANSPORT")?.as_str() {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        _ => return Err("unknown transport".into()),
    };
    let backend = echo(transport, "127.0.0.1:0".parse()?).await?;
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
        .ok_or("private entry missing")?;
    let choice = || {
        LocalProxyServiceChoice::from_local_choice(
            &entry,
            "fixed.nestlink.internal",
            29100,
            4096,
            Duration::from_secs(60),
        )
    };
    let reserved = echo(transport, "127.0.0.1:0".parse()?).await?;
    let endpoint = reserved.address;
    let network_control = echo(transport, "127.0.0.1:0".parse()?).await?;
    let plan = GatePlan::for_current_process(
        random_id(),
        endpoint,
        transport,
        gate_clock()?
            + if transport == Transport::Tcp {
                30_000
            } else {
                75_000
            },
    )?;
    let private = output.join("private-plan");
    nestlink_platform_security::new_private_directory(&private)?;
    plan.save_new(&private.join("plan.json"))?;
    write(
        &output.join("plan-ready.json"),
        &json!({"plan":plan,"identity":identity,"network_control_endpoint":network_control.address}),
    )?;
    let receipt_path = root.join("receipt.json");
    tokio::time::timeout(Duration::from_secs(20), async {
        while !receipt_path.try_exists()? {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        Ok::<(), std::io::Error>(())
    })
    .await??;
    let receipt = RootGateReceipt::read_for_current_process(&receipt_path, &plan)?;
    let consumer = Arc::new(f.consumer);
    let occupied = f
        .sdk
        .start_private_service_raw(consumer.clone(), choice()?, plan.clone(), &receipt_path)
        .await;
    assert!(
        matches!(occupied,Err(nestlink_sdk::services::LocalProxyError::Io(error)) if error.kind()==std::io::ErrorKind::AddrInUse)
    );
    finish_echo(reserved).await?;
    let mut proxy = f
        .sdk
        .start_private_service_raw(consumer, choice()?, plan.clone(), &receipt_path)
        .await?;
    write(
        &output.join("sdk-ready.json"),
        &json!({"plan":plan,"receipt":receipt,"occupied_port_rejected":true}),
    )?;
    stage(&root, "witness").await?;
    tokio::time::timeout(Duration::from_secs(7), async {
        while !proxy.is_finished() {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await?;
    let report = match proxy.wait_stopped(Duration::from_secs(8)).await {
        RawProxyWait::Stopped(report) => report,
        other => return Err(format!("SDK physical cleanup was not confirmed: {other:?}").into()),
    };
    assert!(report.socket_closed);
    assert_eq!(report.cleanup_failures, 0);
    assert!(receipt.check_current(&plan).is_err());
    host.wait_stopped().await?;
    drop(host);
    let backend_bytes = finish_echo(backend).await?;
    let minimum = backend_bytes
        .iter()
        .map(|bytes| bytes.len() as u64)
        .sum::<u64>()
        * 2;
    let usage=tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let usage=f.sdk.service_quota_usage(ServiceQuotaUsageQuery{scope:ServiceQuotaScope::Resource,scope_key:f.view.id.clone()}).await?;
            if usage.outstanding_bytes==0 {
                assert!(usage.spent_bytes>=minimum);assert_eq!(usage.limit_bytes,131072);
                return Ok::<Value,Box<dyn std::error::Error+Send+Sync>>(json!({"spent_bytes":usage.spent_bytes,"outstanding_bytes":usage.outstanding_bytes,"limit_bytes":usage.limit_bytes}));
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }).await??;
    // This intentionally has no service grant. It is a local-only socket
    // witness in the SAME still-live original process, proving kernel denial
    // after SDK cleanup cannot be explained by a closed port or dead owner.
    let witness = echo(transport, endpoint).await?;
    let control = echo(transport, "127.0.0.1:0".parse()?).await?;
    write(
        &output.join("witness-ready.json"),
        &json!({"endpoint":witness.address,"control_endpoint":control.address,"identity":ProcessIdentity::read(std::process::id())?,"socket_closed":report.socket_closed,"cleanup_failures":report.cleanup_failures,"backend_payloads":backend_bytes}),
    )?;
    stage(&root, "finish").await?;
    let witness_bytes = finish_echo(witness).await?;
    let control_bytes = finish_echo(control).await?;
    let network_control_bytes = finish_echo(network_control).await?;
    write(
        &output.join("scenario.json"),
        &json!({"schema_version":1,"kind":"actual_windows_sdk_wfp_kernel","source_revision":std::env::var("GITHUB_SHA")?,"owner":identity,"plan":plan,"backend_payloads":backend_bytes,"witness_payloads":witness_bytes,"control_payloads":control_bytes,"preflight_control_payloads":network_control_bytes,"original_usage":usage,"socket_closed":report.socket_closed,"cleanup_failures":report.cleanup_failures,"accepted_connections":report.accepted_connections,"forwarded_datagrams":report.forwarded_datagrams,"original_process_still_alive":true,"status":"passed_before_original_process_exit","production_cli_validated":false}),
    )?;
    drop(proxy);
    if !f.usage.is_absolute() || !f.usage.starts_with(&output) || f.usage == output {
        return Err("refuse cleanup outside this fresh fixture output".into());
    }
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}
