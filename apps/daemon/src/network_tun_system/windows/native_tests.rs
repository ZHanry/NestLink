//! The dedicated hosted Windows workflow supplies real medium/high tokens and
//! the official pinned driver. This is a mechanism lab, not online acceptance.
use super::*;
use std::net::SocketAddr;
use tokio::time::Instant;

fn lab() -> Result {
    if std::env::var("NESTLINK_TUN_NATIVE_LAB").as_deref() != Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
    {
        return Err(io::Error::other(
            "Windows TUN native roles require the dedicated isolated GitHub-hosted workflow",
        )
        .into());
    }
    Ok(())
}
fn path(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var(name)?);
    if !path.is_absolute() {
        return Err(io::Error::other("absolute native TUN fixture path required").into());
    }
    Ok(path)
}
#[tokio::test]
#[ignore = "dedicated GitHub-hosted Windows VM, actual ordinary/admin roles and pinned signed driver required"]
async fn hosted_native_role() -> Result {
    lab()?;
    let role = std::env::var("NESTLINK_TUN_NATIVE_ROLE")?;
    let case = path("NESTLINK_TUN_NATIVE_CASE")?;
    let plan = case.join("private-plan/plan.json");
    let receipt = path("NESTLINK_TUN_NATIVE_RECEIPT")?;
    if role == "ordinary" {
        return ordinary(&case, &plan, &receipt).await;
    }
    if role == "foreign" {
        nestlink_privileged::windows::require_normal_user_process()?;
        let receipt: PacketReceipt = serde_json::from_slice(&std::fs::read(receipt)?)?;
        assert!(
            receipt.connect().await.is_err(),
            "another same-SID process must never adopt the original packet session"
        );
        std::fs::write(
            case.join("foreign-denied.json"),
            serde_json::to_vec(
                &serde_json::json!({"pid":std::process::id(),"original_pid":receipt.binding.process.pid,"denied":true}),
            )?,
        )?;
        return Ok(());
    }
    let journal = path("NESTLINK_TUN_NATIVE_JOURNAL")?;
    match role.as_str() {
        "apply" => {
            apply(
                plan,
                journal,
                path("NESTLINK_TUN_NATIVE_DRIVER")?,
                hash(&std::env::var("NESTLINK_TUN_NATIVE_DRIVER_SHA256")?)?,
                receipt,
            )
            .await
        }
        "recover" => recover(&AdminJournal::open(&journal)?).await,
        "inspect" => {
            let store = AdminJournal::open(&journal)?;
            let record = store
                .read()?
                .map(|bytes| Record::read(&bytes))
                .transpose()?;
            let current = record.as_ref().map(Record::capture).transpose()?.flatten();
            std::fs::write(
                case.join("inspection.json"),
                serde_json::to_vec(&serde_json::json!({"record":record,"current":current}))?,
            )?;
            Ok(())
        }
        _ => Err(io::Error::other("unknown bounded Windows TUN fixture role").into()),
    }
}
async fn ordinary(case: &Path, plan_path: &Path, receipt: &Path) -> Result {
    nestlink_privileged::windows::require_normal_user_process()?;
    nestlink_platform_security::new_private_directory(
        plan_path
            .parent()
            .ok_or_else(|| io::Error::other("native plan parent missing"))?,
    )?;
    let mut plan = super::super::tests::plan()?;
    plan.process = process_identity(std::process::id()).await?;
    plan.principal = plan::HostPrincipal::current()?;
    plan.save_new(plan_path)?;
    let binding = plan.windows_binding().await?;
    std::fs::write(
        case.join("plan-ready.json"),
        serde_json::to_vec(&serde_json::json!({"plan":plan,"identity":binding.process}))?,
    )?;
    let os = OwnerOs::new(receipt.to_path_buf())?;
    let state = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            plan.validate(true)?;
            if let Some(state) = os.inspect(&plan).await? {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let mut device = os.adopt(&plan, &state).await?;
    for family in 0..2 {
        whole_udp(&plan, &device, family).await?;
    }
    std::fs::write(
        case.join("packets-ready.json"),
        serde_json::to_vec(
            &serde_json::json!({"receipt":state,"ipv4_packet_bytes":1280,"ipv6_packet_bytes":1280,"kernel_udp_replies":2}),
        )?,
    )?;
    loop {
        plan.validate(true)?;
        if case.join("stop.json").try_exists()? {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let started = Instant::now();
    device.shutdown().await?;
    drop(device);
    super::super::owner::release_plan_with_os(&os, &plan, plan_path).await?;
    std::fs::write(
        case.join("ordinary-stopped.json"),
        serde_json::to_vec(
            &serde_json::json!({"normal_cleanup_ms":started.elapsed().as_millis(),"kernel_absent":os.absent(&plan).await?}),
        )?,
    )?;
    Ok(())
}
async fn whole_udp(plan: &TunPlan, device: &PacketDevice, index: usize) -> Result {
    let socket = tokio::net::UdpSocket::bind((plan.local_hosts[index], 0)).await?;
    let payload = vec![73; if index == 0 { 1252 } else { 1232 }];
    let target = SocketAddr::new(plan.remote_hosts[index], 443);
    assert_eq!(socket.send_to(&payload, target).await?, payload.len());
    let mut packet = [0; 65_536];
    let length = tokio::time::timeout(Duration::from_secs(2), device.recv(&mut packet)).await??;
    assert_eq!(
        length, 1280,
        "helper pipe must deliver one complete kernel IP packet"
    );
    let sliced = etherparse::SlicedPacket::from_ip(&packet[..length])?;
    let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport else {
        return Err(io::Error::other("native provider packet was not UDP").into());
    };
    assert_eq!(udp.source_port(), socket.local_addr()?.port());
    assert_eq!(udp.destination_port(), 443);
    assert_eq!(udp.payload(), payload);
    let mut reply = Vec::new();
    match (plan.remote_hosts[index], plan.local_hosts[index]) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            etherparse::PacketBuilder::ipv4(source.octets(), destination.octets(), 64)
                .udp(443, socket.local_addr()?.port())
                .write(&mut reply, &payload)?
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            etherparse::PacketBuilder::ipv6(source.octets(), destination.octets(), 64)
                .udp(443, socket.local_addr()?.port())
                .write(&mut reply, &payload)?
        }
        _ => return Err(io::Error::other("native dual-stack host families differ").into()),
    }
    assert_eq!(device.send(&reply).await?, 1280);
    let mut received = [0; 1280];
    let (count, peer) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut received)).await??;
    assert_eq!(peer, target);
    assert_eq!(&received[..count], payload);
    Ok(())
}
