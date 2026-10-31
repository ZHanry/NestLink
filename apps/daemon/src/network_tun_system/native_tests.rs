//! Explicit hosted Linux mechanism qualification, separate from production
//! login/online authorization and two-device acceptance. Never run locally.
use super::*;
use etherparse::PacketBuilder;
use std::{path::Path, process::Stdio};
use tokio::{
    process::{Child, Command},
    time::Instant,
};

const ROLE_TEST: &str = "network_tun_system::native_tests::hosted_native_role";
const HELPER_ID: &str = "native-test-helper.json";

fn lab() -> Result {
    if std::env::var("NESTLINK_TUN_NATIVE_LAB").as_deref() != Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return Err(io::Error::other("native TUN qualification requires an isolated GitHub-hosted Linux VM with NESTLINK_TUN_NATIVE_LAB=1").into());
    }
    Ok(())
}
fn role_command(role: &str, plan: &Path, journal: &Path, elevated: bool) -> Result<Command> {
    let image = std::env::current_exe()?;
    let mut command = if elevated {
        let mut command = Command::new("/usr/bin/sudo");
        command
            .args([
                "-n",
                "--",
                "/usr/bin/env",
                "GITHUB_ACTIONS=true",
                "NESTLINK_TUN_NATIVE_LAB=1",
            ])
            .arg(format!("NESTLINK_TUN_NATIVE_ROLE={role}"))
            .arg(format!("NESTLINK_TUN_NATIVE_PLAN={}", plan.display()))
            .arg(format!("NESTLINK_TUN_NATIVE_JOURNAL={}", journal.display()))
            .arg(image);
        command
    } else {
        let mut command = Command::new(image);
        command
            .env("NESTLINK_TUN_NATIVE_ROLE", role)
            .env("NESTLINK_TUN_NATIVE_PLAN", plan)
            .env("NESTLINK_TUN_NATIVE_JOURNAL", journal);
        command
    };
    command
        .args([
            "--exact",
            ROLE_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    Ok(command)
}
async fn status(role: &str, plan: &Path, journal: &Path) -> Result<bool> {
    Ok(tokio::time::timeout(
        Duration::from_secs(10),
        role_command(role, plan, journal, true)?.status(),
    )
    .await??
    .success())
}
async fn finished(child: &mut Child) -> Result<bool> {
    Ok(tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await??
        .success())
}
async fn wait_file(path: &Path, child: &mut Child) -> Result {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if path.try_exists()? {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "ordinary native TUN actor exited before its receipt: {status}"
                ))
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("bounded native TUN actor receipt timed out"))??;
    Ok(())
}

#[tokio::test]
#[ignore = "isolated GitHub-hosted Linux VM, ordinary UID, passwordless sudo, /dev/net/tun and NESTLINK_TUN_NATIVE_LAB=1 required"]
async fn ordinary_uid_root_helper_whole_packets_normal_close_and_crash_recovery() -> Result {
    lab()?;
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other(
            "start this test as the ordinary hosted runner user, never root",
        )
        .into());
    }
    for crash in [false, true] {
        let temporary = tempfile::tempdir()?;
        // tempfile's ordinary directory mode follows the process umask. Use
        // the production private-leaf creator instead of trusting that mode.
        let owner_directory=temporary.path().join("ordinary-owner");
        nestlink_platform_security::new_private_directory(&owner_directory)?;
        let plan_path = owner_directory.join("plan.json");
        let journal = PathBuf::from("/tmp").join(format!(
            "nestlink-tun-native-{}",
            nestlink_auth::random_id()
        ));
        if !status("init", &plan_path, &journal).await? {
            return Err(io::Error::other("root native journal initialization failed").into());
        }
        let mut ordinary = role_command("ordinary", &plan_path, &journal, false)?.spawn()?;
        wait_file(&plan_path, &mut ordinary).await?;
        let plan = TunPlan::read(&plan_path)?;
        let mut helper = role_command("apply", &plan_path, &journal, true)?.spawn()?;
        let outcome=async {
            wait_file(&plan_path.with_extension("ready"),&mut ordinary).await?;
            if crash {
                // SIGKILL bypasses the helper's destructor/monitor cleanup.
                if !status("kill-helper",&plan_path,&journal).await? { return Err(io::Error::other("exact original helper SIGKILL failed").into()); }
                assert!(!finished(&mut helper).await?,"killed root helper must fail");
                assert!(linux::inspect(&plan).await?.is_some(),"persistent original interface must survive helper crash");
                assert!(!status("recover",&plan_path,&journal).await?,"recovery must reject the still-live original ordinary owner");
                ordinary.start_kill()?;
                assert!(!finished(&mut ordinary).await?,"ordinary crash must bypass release_plan");
                assert!(linux::inspect(&plan).await?.is_some(),"dropping the last ordinary descriptor must not erase persistence or the recovery identity");
                if !status("recover",&plan_path,&journal).await? { return Err(io::Error::other("dead original owner recovery failed").into()); }
                assert!(linux::inspect(&plan).await?.is_none());
                println!("Native TUN receipt: actual ordinary UID {}, helper SIGKILL, live-owner recovery denied, ordinary SIGKILL, exact original root-journal recovery and kernel absence confirmed",plan.linux_uid()?);
            } else {
                let stopped=Instant::now();
                nestlink_platform_security::create_private(&plan_path.with_extension("stop"),b"stop")?;
                assert!(finished(&mut ordinary).await?,"ordinary descriptor drop and release_plan must succeed");
                assert!(stopped.elapsed()<Duration::from_secs(5),"normal original interface cleanup exceeded five seconds");
                assert!(finished(&mut helper).await?,"root helper must confirm exact physical cleanup");
                assert!(linux::inspect(&plan).await?.is_none());
                assert!(!plan_path.try_exists()?);
                println!("Native TUN receipt: actual ordinary UID {}, exclusive descriptor, real IPv4/IPv6 UDP full 1280-byte request and reply, normal plan stop and kernel absence in {} ms",plan.linux_uid()?,stopped.elapsed().as_millis());
            }
            Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())
        }.await;
        // On failure, stop both original actors, then attempt only the exact
        // durable journal recovery. Preserve any changed/foreign configuration.
        if outcome.is_err() {
            let _ = ordinary.start_kill();
            let _ = finished(&mut ordinary).await;
            let _ = status("kill-helper", &plan_path, &journal).await;
            let _ = finished(&mut helper).await;
            let _ = status("recover", &plan_path, &journal).await;
        }
        let teardown = status("teardown", &plan_path, &journal).await?;
        outcome?;
        if !teardown {
            return Err(io::Error::other(
                "native root journal teardown failed; exact recovery evidence retained",
            )
            .into());
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "internal exact-source subprocess role for the explicit hosted native TUN test"]
async fn hosted_native_role() -> Result {
    lab()?;
    let role = std::env::var("NESTLINK_TUN_NATIVE_ROLE")?;
    let plan = PathBuf::from(std::env::var("NESTLINK_TUN_NATIVE_PLAN")?);
    let journal = PathBuf::from(std::env::var("NESTLINK_TUN_NATIVE_JOURNAL")?);
    let suffix = journal
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix("nestlink-tun-native-"));
    if journal.parent() != Some(Path::new("/tmp"))
        || !suffix.is_some_and(nestlink_protocol::valid_id)
        || !plan.is_absolute()
    {
        return Err(io::Error::other("exact native test paths required").into());
    }
    if role == "ordinary" {
        return ordinary(&plan).await;
    }
    require_system_admin().await?;
    match role.as_str() {
        "init" => {
            run(SystemTunArgs {
                action: SystemTunAction::InitJournal {
                    journal_dir: journal,
                },
            })
            .await
        }
        "apply" => {
            let helper = nestlink_platform_security::local_port_gate::ProcessIdentity::read(
                std::process::id(),
            )?;
            nestlink_platform_security::create_private(
                &journal.join(HELPER_ID),
                &serde_json::to_vec(&helper)?,
            )?;
            run(SystemTunArgs {
                action: SystemTunAction::Apply {
                    plan,
                    journal_dir: journal,
                },
            })
            .await
        }
        "recover" => {
            run(SystemTunArgs {
                action: SystemTunAction::Recover {
                    journal_dir: journal,
                },
            })
            .await
        }
        "kill-helper" => {
            nestlink_platform_security::check_private_directory(&journal)?;
            let bytes = nestlink_platform_security::read_private(&journal.join(HELPER_ID), 4096)?;
            let original: nestlink_platform_security::local_port_gate::ProcessIdentity =
                serde_json::from_slice(&bytes)?;
            let current = match nestlink_platform_security::local_port_gate::ProcessIdentity::read(
                original.pid,
            ) {
                Ok(current) => current,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            let helper = nestlink_platform_security::local_port_gate::ProcessIdentity::read(
                std::process::id(),
            )?;
            if current != original
                || current.uid != 0
                || current.image_device != helper.image_device
                || current.image_inode != helper.image_inode
            {
                return Err(io::Error::other(
                    "native crash fixture must identify only its exact original root test helper",
                )
                .into());
            }
            if !Command::new("/bin/kill")
                .arg("-KILL")
                .arg(original.pid.to_string())
                .status()
                .await?
                .success()
            {
                return Err(io::Error::other("native test helper kill failed").into());
            }
            Ok(())
        }
        "teardown" => {
            let store = JournalStore::open(&journal)?;
            if store.read()?.is_some() {
                return Err(io::Error::other(
                    "native root journal is still needed; preserving exact evidence",
                )
                .into());
            }
            drop(store);
            for name in [HELPER_ID, "network-tun-owner.lock"] {
                match std::fs::remove_file(journal.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            std::fs::remove_dir(journal)?;
            Ok(())
        }
        _ => Err(io::Error::other("unknown native TUN fixture role").into()),
    }
}

async fn ordinary(path: &Path) -> Result {
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other("native packet owner must be an ordinary UID").into());
    }
    let mut plan = tests::plan()?;
    plan.principal = plan::HostPrincipal::current()?;
    plan.process = process_identity(std::process::id()).await?;
    plan.save_new(path)?;
    let state = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            plan.validate(true)?;
            if let Some(state) = linux::inspect(&plan).await?
                && state.up && state.persistent && state.addresses.len() == 2 {
                    linux::verify(&plan, &state, true)?;
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    // Root has configured but has not closed its single queue for a brief
    // interval. Retry only EBUSY while waiting for that one descriptor release.
    let device = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match linux::adopt(&plan, &state).await {
                Ok(device) => return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(device),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(16)) =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    assert!(
        linux::adopt(&plan, &state).await.is_err(),
        "a second ordinary descriptor must not attach the single queue"
    );
    for index in 0..2 {
        whole_udp(&plan, &device, index).await?;
    }
    nestlink_platform_security::create_private(
        &path.with_extension("ready"),
        b"exclusive;ipv4=1280;ipv6=1280;kernel-replies=2",
    )?;
    loop {
        plan.validate(true)?;
        if path.with_extension("stop").try_exists()? {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    drop(device);
    owner::release_plan(&plan, path).await
}

async fn whole_udp(plan: &TunPlan, device: &tun_rs::AsyncDevice, index: usize) -> Result {
    let socket = tokio::net::UdpSocket::bind((plan.local_hosts[index], 0)).await?;
    let payload = vec![73_u8; if index == 0 { 1252 } else { 1232 }];
    let target = std::net::SocketAddr::new(plan.remote_hosts[index], 443);
    assert_eq!(socket.send_to(&payload, target).await?, payload.len());
    let mut packet = vec![0_u8; 65_536];
    let length = tokio::time::timeout(Duration::from_secs(2), device.recv(&mut packet)).await??;
    assert_eq!(
        length, 1280,
        "kernel must deliver one whole minimum-MTU IP packet without PI/offload framing"
    );
    let sliced = etherparse::SlicedPacket::from_ip(&packet[..length])?;
    let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport else {
        return Err(io::Error::other("native kernel fixture did not emit UDP").into());
    };
    assert_eq!(udp.destination_port(), 443);
    assert_eq!(udp.source_port(), socket.local_addr()?.port());
    assert_eq!(udp.payload(), payload);
    let mut reply = Vec::new();
    match (plan.remote_hosts[index], plan.local_hosts[index]) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
            PacketBuilder::ipv4(source.octets(), destination.octets(), 64)
                .udp(443, socket.local_addr()?.port())
                .write(&mut reply, &payload)?
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            PacketBuilder::ipv6(source.octets(), destination.octets(), 64)
                .udp(443, socket.local_addr()?.port())
                .write(&mut reply, &payload)?
        }
        _ => return Err(io::Error::other("native dual-stack host family differs").into()),
    }
    assert_eq!(reply.len(), 1280);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), device.send(&reply)).await??,
        reply.len()
    );
    let mut received = vec![0_u8; 2048];
    let (length, remote) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut received)).await??;
    assert_eq!(remote, target);
    assert_eq!(&received[..length], payload);
    Ok(())
}
