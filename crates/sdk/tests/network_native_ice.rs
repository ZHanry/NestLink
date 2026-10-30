//! Actions-only, ordinary-user roles for actual signed native ICE behind SNAT.
//! FileRead frames exercise the production business channel, not a file browser.
#![cfg(target_os = "linux")]
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner, digest};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path as ConnectionPath, Permission,
    api::{ApprovalChoice, RemoteRequest},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    native::{AddressPolicy, NativeEndpoint, NativeSessionOptions},
};
use nestlink_server::{AppState, router};
use nestlink_session::StopReason;
use nestlink_storage::Store;
use nestlink_transport_stream::Channel;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{sync::watch, task::JoinSet, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://127.0.0.1:28880";
const CONTROL: &str = "10.221.1.1:28880";
const STUN: &str = "10.221.1.1:3478";

fn fixture() -> Result<PathBuf> {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_eq!(std::env::var("GITHUB_REPOSITORY")?, "ZHanry/NestLink");
    let root = PathBuf::from(std::env::var("NESTLINK_NETWORK_FIXTURE")?).canonicalize()?;
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    assert!(root.starts_with(&temporary) && root != temporary);
    let namespace = fs::read_link("/proc/self/ns/net")?;
    let runner = std::env::var("NESTLINK_NETWORK_RUNNER_NAMESPACE")?;
    assert!(runner.starts_with("net:[") && runner.ends_with(']'));
    assert_ne!(namespace.to_string_lossy(), runner);
    let status = fs::read_to_string("/proc/self/status")?;
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or("missing process UID")?;
    assert!(uid.split_whitespace().skip(1).all(|id| id != "0"));
    println!(
        "NESTLINK_NATIVE_ICE namespace={namespace:?} pid={} {uid}",
        std::process::id()
    );
    Ok(root)
}
fn mark(root: &Path, name: &str) -> Result {
    fs::write(root.join(format!("{name}.pending")), b"observed\n")?;
    fs::rename(root.join(format!("{name}.pending")), root.join(name))?;
    println!("NESTLINK_NATIVE_ICE event={name}");
    Ok(())
}
async fn wait(root: &Path, name: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        while !root.join(name).is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(fs::read(root.join(name))?, b"observed\n");
    Ok(())
}
fn write_json(root: &Path, name: &str, value: &serde_json::Value) -> Result {
    fs::write(root.join(name), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn password(root: &Path) -> Result<Secret> {
    Ok(Secret::from_text(fs::read_to_string(
        root.join("password"),
    )?))
}
fn identity(root: &Path, role: &str) -> Result<DeviceIdentity> {
    let mut seed: [u8; 32] = fs::read(root.join(format!("{role}.seed")))?
        .try_into()
        .map_err(|_| "invalid installation seed")?;
    Ok(DeviceIdentity {
        device_id: fs::read_to_string(root.join(format!("{role}.id")))?,
        identity: InstallationIdentity::from_seed_zeroizing(&mut seed),
    })
}
#[derive(Deserialize)]
struct Trust {
    deployment_id: String,
    issuer: [u8; 32],
}
async fn sdk(root: &Path, account: &str) -> Result<Sdk> {
    let trust: Trust = serde_json::from_slice(&fs::read(root.join("trust.json"))?)?;
    let mut sdk = Sdk::connect(
        ORIGIN,
        DeploymentTrust {
            deployment_id: trust.deployment_id,
            permit_issuer: trust.issuer,
        },
        true,
    )
    .await?;
    sdk.login(account.into(), password(root)?, None).await?;
    Ok(sdk)
}

#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn central_process() -> Result {
    let root = fixture()?;
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("controller-owner", password(&root)?.expose())?;
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([57; 32]),
        signer,
        ORIGIN.into(),
        false,
    )?);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:28880").await?;
    let stun = tokio::net::UdpSocket::bind(STUN).await?;
    let (stop, mut stopped) = watch::channel(false);
    let http = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.changed().await;
            })
            .await
    });
    write_json(
        &root,
        "trust.json",
        &json!({"deployment_id":deployment,"issuer":issuer}),
    )?;
    let admin = sdk(&root, "controller-owner").await?;
    admin
        .create_account("host-owner".into(), password(&root)?)
        .await?;
    mark(&root, "central-ready")?;
    let mut observations = Vec::new();
    let mut packet = [0; 2048];
    loop {
        tokio::select! {
            result = wait(&root, "central-stop") => { result?; break; },
            result = stun.recv_from(&mut packet) => {
                let (length, peer) = result?;
                // The response reports the kernel-observed SNAT tuple. Never
                // synthesize a configured public address or inspect ICE secrets.
                let response = nestlink_traversal::stun::response(&packet[..length], peer)?;
                stun.send_to(&response, peer).await?;
                observations.push(json!({"observed_source":peer.to_string(),
                    "transaction":packet[8..20].to_vec(),"response_bytes":response.len()}));
            }
        }
    }
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(3), http).await???;
    drop(stun);
    let _rebound = UdpSocket::bind(STUN)?;
    write_json(
        &root,
        "central-receipt.json",
        &json!({"passed":true,
        "role":"central","released_udp_sockets":1,"stun_observations":observations,
        "management_origin":ORIGIN,"stun_uses_kernel_observed_source":true}),
    )?;
    mark(&root, "central-finished")
}

async fn proxy(
    mut stopped: watch::Receiver<bool>,
    listener: tokio::net::TcpListener,
) -> io::Result<()> {
    let mut copies = JoinSet::new();
    loop {
        tokio::select! { biased;
            _ = stopped.changed() => break,
            Some(_) = copies.join_next() => {},
            accepted = listener.accept() => {
                let (mut local, _) = accepted?;
                copies.spawn(async move {
                    let mut upstream = tokio::net::TcpStream::connect(CONTROL).await?;
                    tokio::io::copy_bidirectional(&mut local, &mut upstream).await?;
                    Ok::<_, io::Error>(())
                });
            }
        }
    }
    copies.abort_all();
    while copies.join_next().await.is_some() {}
    Ok(())
}
fn udp_addresses(ip: IpAddr) -> Result<BTreeSet<SocketAddr>> {
    let mut addresses = BTreeSet::new();
    for line in fs::read_to_string("/proc/net/udp")?.lines().skip(1) {
        let address = line
            .split_whitespace()
            .nth(1)
            .ok_or("missing UDP local address")?;
        let (address, port) = address.split_once(':').ok_or("invalid kernel UDP tuple")?;
        let address = Ipv4Addr::from(u32::from_str_radix(address, 16)?.to_le_bytes());
        let socket = SocketAddr::new(address.into(), u16::from_str_radix(port, 16)?);
        if socket.ip() == ip {
            addresses.insert(socket);
        }
    }
    Ok(addresses)
}
async fn rebind(address: SocketAddr) -> Result {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match UdpSocket::bind(address) {
                Ok(socket) => {
                    drop(socket);
                    return Ok::<_, io::Error>(());
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    Ok(())
}
async fn endpoint(role: &str) -> Result {
    let root = fixture()?;
    let case = std::env::var("NESTLINK_NETWORK_CASE")?;
    assert!(["success", "blackhole", "cancel"].contains(&case.as_str()));
    let controller = role == "controller";
    let index = if controller { 1 } else { 2 };
    let other = if controller { "host" } else { "controller" };
    let local: SocketAddr = format!("10.220.{index}.2:{}", 45000 + index).parse()?;
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:28880").await?;
    let (proxy_stop, proxy_stopped) = watch::channel(false);
    let forwarder = tokio::spawn(proxy(proxy_stopped, proxy_listener));
    let sdk = sdk(
        &root,
        if controller {
            "controller-owner"
        } else {
            "host-owner"
        },
    )
    .await?;
    let identity = identity(&root, role)?;
    fs::write(
        root.join(format!("{role}.public")),
        identity.identity.public_key(),
    )?;
    sdk.enroll(
        &identity,
        role.into(),
        "linux-x11".into(),
        vec![role.into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    mark(&root, &format!("{role}-enrolled"))?;
    wait(&root, &format!("{other}-enrolled")).await?;
    if controller {
        let request = sdk
            .create_remote(RemoteRequest {
                id: random_id(),
                controller_device_id: identity.device_id.clone(),
                host_device_id: fs::read_to_string(root.join("host.id"))?,
                permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                path_mode: "direct_only".into(),
            })
            .await?;
        fs::write(root.join("remote.id"), &request.id)?;
        mark(&root, "remote-created")?;
        wait(&root, "remote-approved").await?;
    } else {
        wait(&root, "remote-created").await?;
        let request = sdk
            .remote(&fs::read_to_string(root.join("remote.id"))?)
            .await?;
        sdk.approve(
            &identity,
            &request,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                paths: vec![ConnectionPath::Direct as i32],
            },
        )
        .await?;
        mark(&root, "remote-approved")?;
    }
    let remote = fs::read_to_string(root.join("remote.id"))?;
    let permit = if controller {
        let permit = sdk.permit(&remote).await?;
        fs::write(root.join("issued-permit-digest"), permit.digest())?;
        mark(&root, "permit-issued")?;
        permit
    } else {
        // Approval alone does not issue a permit. The host's readback must
        // follow the controller's actual initial issuance, as in production.
        wait(&root, "permit-issued").await?;
        sdk.host_permit(&identity, &remote).await?
    };
    assert_eq!(
        permit.digest().as_slice(),
        fs::read(root.join("issued-permit-digest"))?
    );
    assert!(
        permit
            .claims()
            .required_capabilities
            .iter()
            .any(|cap| cap == nestlink_protocol::native_ice::CAPABILITY)
    );
    fs::write(root.join(format!("{role}-permit-digest")), permit.digest())?;
    let peer: [u8; 32] = fs::read(root.join(format!("{other}.public")))?
        .try_into()
        .map_err(|_| "invalid peer public key")?;
    let endpoint = NativeEndpoint::new(
        local,
        &identity,
        &peer,
        permit,
        vec![],
        AddressPolicy::new(&["10.221.1.2/32".into(), "10.221.2.2/32".into()])?,
    )?;
    let (_cancel, cancelled) = watch::channel(false);
    let mut physical = BTreeSet::from([local]);
    let started = Instant::now();
    let established = {
        let establish = endpoint.establish(
            &sdk,
            &identity,
            NativeSessionOptions {
                granted_permissions: vec![Permission::View, Permission::FileRead],
                supported_capabilities: vec!["vp8".into()],
                local_paths: PathSet::DIRECT,
            },
            &[],
            vec![STUN.parse()?],
            cancelled,
        );
        tokio::pin!(establish);
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        loop {
            tokio::select! {
                result = &mut establish => break result,
                _ = tick.tick() => { physical.extend(udp_addresses(local.ip())?); },
                _ = tokio::time::sleep_until(started + Duration::from_secs(22)) => return Err("native ICE establishment exceeded role deadline".into()),
            }
        }
    };
    assert!(
        physical.len() >= 2,
        "the original ICE UDP socket was never observed"
    );
    let mut facts = json!({"role":role,"passed":false,"uses_bilateral_ice":false,
        "released_udp_sockets":physical.len(),"rebound_udp_addresses":physical.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "establish_elapsed_ms":started.elapsed().as_millis(),"input_rejected":false,
        "pending_read_cancelled":false,"file_bytes":0,"payload_verified":false});
    if case == "blackhole" {
        assert!(
            established.is_err(),
            "blackhole must reject every legacy or ICE session"
        );
        facts["setup_rejected"] = json!(true);
        mark(&root, &format!("{role}-rejected"))?;
    } else {
        let mut session = established?;
        assert!(
            session.uses_bilateral_ice(),
            "legacy fallback cannot qualify this experiment"
        );
        assert_eq!(session.candidate.path(), ConnectionPath::Direct);
        assert_eq!(
            session.candidate.address.ip(),
            format!("10.221.{}.2", if controller { 2 } else { 1 }).parse::<IpAddr>()?
        );
        physical.extend(udp_addresses(local.ip())?);
        facts["uses_bilateral_ice"] = json!(true);
        facts["selected_peer"] = json!(session.candidate.address.to_string());
        mark(&root, &format!("{role}-established"))?;
        let payload = fs::read(root.join("payload.bin"))?;
        assert_eq!(payload.len(), 262_144);
        if !controller {
            for chunk in payload.chunks(32_768) {
                session.channels.send(Channel::FileRead, chunk).await?;
            }
        }
        let mut received = Vec::with_capacity(payload.len());
        for _ in 0..8 {
            let frame =
                tokio::time::timeout(Duration::from_secs(3), session.channels.receive()).await??;
            assert_eq!(frame.channel, Channel::FileRead);
            assert_eq!(frame.payload.len(), 32_768);
            received.extend_from_slice(&frame.payload);
        }
        assert_eq!(received, payload);
        if controller {
            for chunk in received.chunks(32_768) {
                session.channels.send(Channel::FileRead, chunk).await?;
            }
        }
        assert!(matches!(session.channels.send(Channel::Input, &[1]).await,
            Err(nestlink_remote::RemoteError::Authorization(error))
                if error.code == nestlink_protocol::ErrorCode::PermissionRequired));
        facts["input_rejected"] = json!(true);
        facts["input_rejection_code"] = json!("permission_required");
        facts["file_bytes"] = json!(received.len());
        facts["payload_sha256"] = json!(digest(&received));
        facts["payload_verified"] = json!(true);
        mark(&root, &format!("{role}-payload-verified"))?;
        if case == "cancel" {
            if controller {
                session
                    .channels
                    .send(Channel::FileRead, b"next-owned-request")
                    .await?;
                wait(&root, "host-response-sent").await?;
                let control = session.channels.lease_control();
                {
                    let receive = session.channels.receive();
                    tokio::pin!(receive);
                    tokio::select! {
                        result = &mut receive => {
                            let detail = match result {
                                Ok(frame) => format!("channel {:?}, {} bytes", frame.channel, frame.payload.len()),
                                Err(error) => error.to_string(),
                            };
                            return Err(format!("expected a physically blocked read, got {detail}").into());
                        },
                        _ = tokio::time::sleep(Duration::from_millis(150)) => {},
                    }
                    mark(&root, "controller-read-blocked")?;
                    wait(&root, "cancel-now").await?;
                    control.stop(StopReason::ExplicitExit)?;
                    assert!(
                        tokio::time::timeout(Duration::from_secs(2), receive)
                            .await?
                            .is_err()
                    );
                }
                facts["pending_read_cancelled"] = json!(true);
                mark(&root, "controller-read-cancelled")?;
            } else {
                let request =
                    tokio::time::timeout(Duration::from_secs(3), session.channels.receive())
                        .await??;
                assert_eq!(request.channel, Channel::FileRead);
                assert_eq!(request.payload, b"next-owned-request");
                mark(&root, "host-request-received")?;
                wait(&root, "fault-installed").await?;
                session
                    .channels
                    .send(Channel::FileRead, b"response-under-blackhole")
                    .await?;
                mark(&root, "host-response-sent")?;
            }
        }
        wait(&root, "stop-all").await?;
        let stopped = tokio::time::timeout(
            Duration::from_secs(5),
            session.shutdown(StopReason::ExplicitExit),
        )
        .await??;
        if controller && case == "cancel" {
            assert_eq!(stopped.reason, StopReason::ExplicitExit);
        }
    }
    let mut owner = nestlink_sdk::network::LegacyEndpoint::new(endpoint);
    owner
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    for address in &physical {
        rebind(*address).await?;
    }
    proxy_stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(3), forwarder).await???;
    facts["released_udp_sockets"] = json!(physical.len());
    facts["rebound_udp_addresses"] =
        json!(physical.iter().map(ToString::to_string).collect::<Vec<_>>());
    facts["explicit_close_completed"] = json!(true);
    facts["passed"] = json!(true);
    write_json(&root, &format!("{role}-receipt.json"), &facts)?;
    mark(&root, &format!("{role}-finished"))
}

#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn controller_process() -> Result {
    endpoint("controller").await
}

#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn host_process() -> Result {
    endpoint("host").await
}
