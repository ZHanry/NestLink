//! The dedicated hosted Windows workflow supplies real medium/high tokens and
//! the official pinned driver. This is a mechanism lab, not online acceptance.
use super::*;
use std::net::SocketAddr;
use tokio::time::Instant;
mod online;

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
    if role == "provider-negative" {
        return provider_negative(&case);
    }
    if role == "ordinary" {
        return ordinary(&case, &plan, &receipt).await;
    }
    if role == "online" {
        return online::ordinary(&case, &plan, &receipt).await;
    }
    if role == "fault-inspect" {
        let observation: serde_json::Value = serde_json::from_slice(&std::fs::read(case.join("fault-observed.json"))?)?;
        let original: ProviderIdentity = serde_json::from_value(observation["provider"].clone())?;
        assert!(resources::absent(&original)?, "partial installation left its original native adapter or routes behind");
        std::fs::write(case.join("fault-absent.json"), serde_json::to_vec(&serde_json::json!({"original_provider":original,"kernel_absent":true}))?)?;
        return Ok(());
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
    if role == "raw-foreign" {
        return raw_foreign(&case, &receipt).await;
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
        "recovery-identity-negative" => recovery_identity_negative(&case, &receipt),
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
pub(super) fn fail_after(stage: &str, record: &Record) -> Result {
    if std::env::var("NESTLINK_TUN_NATIVE_FAULT").as_deref() != Ok(stage) { return Ok(()); }
    lab()?;
    let original = record.identity.as_ref().ok_or_else(|| io::Error::other("fault fixture original identity not journaled"))?;
    assert_eq!(record.capture()?.as_ref(), Some(original));
    let observed = match resources::inspect(original) {
        Ok(snapshot) => serde_json::json!({"snapshot":snapshot}),
        Err(error) => serde_json::json!({"incomplete_snapshot_error":error.to_string()}),
    };
    std::fs::write(path("NESTLINK_TUN_NATIVE_CASE")?.join("fault-observed.json"), serde_json::to_vec(&serde_json::json!({
        "stage":stage,"provider":original,"partial_snapshot":observed,"journaled_original_pnp_instance":record.device_instance,
        "receipt_unpublished":record.receipt.is_none(),"production_packet_readiness_claimed":false
    }))?)?;
    Err(io::Error::other(format!("injected bounded native installation failure after {stage}")).into())
}
fn provider_negative(case: &Path) -> Result {
    nestlink_privileged::windows::require_administrator_process()?;
    let driver = path("NESTLINK_TUN_NATIVE_DRIVER")?;
    let pin = hash(&std::env::var("NESTLINK_TUN_NATIVE_DRIVER_SHA256")?)?;
    let original = std::fs::read(&driver)?;
    let selected = PinnedProviderImage::open(&driver, pin)?;
    assert_eq!(selected.sha256(), pin);
    // The same locks which protect the production load keep the official
    // bytes immutable while the selected provider can still be loaded.
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&driver)
            .is_err(),
        "selected protected provider remained writable while pinned"
    );
    drop(selected);
    let mut wrong = pin;
    wrong[0] ^= 1;
    assert!(
        PinnedProviderImage::open(&driver, wrong).is_err(),
        "wrong operator digest admitted a provider"
    );
    let other_architecture =
        hash("d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931")?;
    assert_ne!(pin, other_architecture, "dedicated fixture requires amd64");
    assert!(
        PinnedProviderImage::open(&driver, other_architecture).is_err(),
        "another architecture's official pin admitted this process provider"
    );
    let unsigned = path("NESTLINK_TUN_NATIVE_UNSIGNED")?;
    let unsigned_pin = nestlink_identity::digest(&std::fs::read(&unsigned)?);
    assert!(
        PinnedProviderImage::open(&unsigned, unsigned_pin).is_err(),
        "an operator-selected matching hash admitted an unreviewed provider"
    );
    let writable = case.join("wintun.dll");
    std::fs::write(&writable, &original)?;
    assert!(
        PinnedProviderImage::open(&writable, pin).is_err(),
        "official bytes on an ordinary-writable path admitted a provider"
    );
    assert_eq!(
        std::fs::read(&driver)?,
        original,
        "provider rejection changed the original official image"
    );
    std::fs::write(
        case.join("provider-negative.json"),
        serde_json::to_vec(&serde_json::json!({
            "official_sha256":pin,"official_bytes_unchanged":true,"pinned_image_write_denied":true,
            "rejected":["wrong_digest","other_architecture","unreviewed_matching_digest","ordinary_writable_path"]
        }))?,
    )?;
    Ok(())
}
fn recovery_identity_negative(case: &Path, receipt: &Path) -> Result {
    // The original helper deliberately holds its recovery journal's exclusive
    // lock throughout packet ownership. Observe its published attestation and
    // native inventory instead of opening or weakening that ownership lock.
    let receipt: PacketReceipt = serde_json::from_slice(&std::fs::read(receipt)?)?;
    let original = &receipt.provider;
    let installed = resources::inspect(original)?
        .ok_or_else(|| io::Error::other("original OS snapshot missing"))?;
    assert_eq!(
        installed.digest()?,
        original.configuration_sha256,
        "live inventory differs from the original helper's published attestation"
    );
    let instance = device_instance::capture(original)?;
    let mut changed_index = original.clone();
    changed_index.index ^= 1;
    let mut changed_luid = original.clone();
    changed_luid.luid ^= 1;
    let mut changed_name = original.clone();
    changed_name.name = format!("NestLink-{}", nestlink_auth::random_id());
    let mut changed_guid = original.clone();
    changed_guid.adapter_guid = format!(
        "{}{}",
        if original.adapter_guid.starts_with('a') {
            'b'
        } else {
            'a'
        },
        &original.adapter_guid[1..]
    );
    for changed in [&changed_index, &changed_luid, &changed_name, &changed_guid] {
        assert!(
            device_instance::remove_original(changed, &instance).is_err(),
            "SetupAPI recovery accepted a nonoriginal kernel identity"
        );
        assert_eq!(
            resources::inspect(original)?.as_ref(),
            Some(&installed),
            "a refused nonoriginal recovery changed the original device resources"
        );
        assert_eq!(
            device_instance::capture(original)?,
            instance,
            "a refused nonoriginal recovery changed the captured PnP instance"
        );
    }
    let plan = TunPlan::read(&case.join("private-plan/plan.json"))?;
    let fresh = nestlink_auth::random_id();
    let fresh_name = format!("NestLink-{fresh}");
    let unassigned: [IpAddr;2] = ["198.18.99.2".parse()?,"fdfe:99::2".parse()?];
    for (guid,name,local,remote,message) in [
        (&original.adapter_guid,&original.name,&unassigned,&unassigned,"fresh TUN adapter identity already exists"),
        (&fresh,&fresh_name,&plan.local_hosts,&plan.remote_hosts,"signed TUN address is already configured"),
        (&fresh,&fresh_name,&unassigned,&plan.remote_hosts,"an existing specific route already captures a signed remote TUN host"),
    ] {
        let error = resources::preflight(guid,name,local,remote).expect_err("preflight accepted an original adapter, address or specific route conflict");
        assert!(error.to_string().contains(message),"preflight did not reject the selected conflict: {error}");
        assert_eq!(resources::inspect(original)?.as_ref(),Some(&installed),"preflight refusal changed the complete original snapshot");
        assert_eq!(device_instance::capture(original)?,instance,"preflight refusal changed the captured original PnP instance");
    }
    std::fs::write(
        case.join("recovery-identity-negative.json"),
        serde_json::to_vec(&serde_json::json!({
            "rejected_fields":["interface_index","luid","alias","guid"],"kernel_unchanged":true,
            "configuration_sha256":installed.digest()?
            ,"preflight_rejected":["existing_guid_alias","configured_host_address","specific_remote_route"]
        }))?,
    )?;
    Ok(())
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
    // In the raw-client negative scenario the original live owner never opens
    // its pipe. A distinct actual medium process gets the one connection and
    // must be rejected by the helper's OS-reported peer identity, before hello.
    if std::env::var("NESTLINK_TUN_NATIVE_PAUSE").as_deref() == Ok("1") {
        loop {
            plan.validate(true)?;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
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
    tokio::time::timeout(Duration::from_secs(2), async {
        // A newly enabled Windows IP interface can have queued OS-generated
        // control packets before isolation. They cannot replace the exact UDP
        // witness, and no truncated matching witness is ever skipped.
        for _ in 0..32 {
            let length = device.recv(&mut packet).await?;
            let sliced = etherparse::SlicedPacket::from_ip(&packet[..length])?;
            let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport else {
                continue;
            };
            if udp.source_port() != socket.local_addr()?.port() || udp.destination_port() != 443 {
                continue;
            }
            assert_eq!(
                length, 1280,
                "helper pipe must deliver the complete original kernel UDP IP packet"
            );
            assert_eq!(udp.payload(), payload);
            return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
        }
        Err(io::Error::other("bounded native kernel packet witness was not observed").into())
    })
    .await??;
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

async fn raw_foreign(case: &Path, receipt_path: &Path) -> Result {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
    };
    nestlink_privileged::windows::require_normal_user_process()?;
    let receipt: PacketReceipt = serde_json::from_slice(&std::fs::read(receipt_path)?)?;
    let identity =
        nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(std::process::id())?;
    assert_ne!(identity.pid, receipt.binding.process.pid);
    let endpoint = format!(r"\\.\pipe\NestLink.NetworkTun.{}", receipt.binding.owner_id);
    let mut client = ClientOptions::new()
        .security_qos_flags(0x0001_0000)
        .open(endpoint)?;
    let mut hello = [0_u8; 40];
    hello[..8].copy_from_slice(b"NLTUN/01");
    hello[8..].copy_from_slice(&receipt.binding.plan_sha256);
    // Possession of the exact public plan/hello and the same SID is deliberately
    // insufficient. The administrative server must close without its reply.
    let denied = tokio::time::timeout(Duration::from_secs(2), async {
        if client.write_all(&hello).await.is_err() {
            return true;
        }
        let mut response = [0_u8; 40];
        client.read_exact(&mut response).await.is_err()
    })
    .await?;
    assert!(
        denied,
        "a raw nonoriginal same-SID process obtained an authenticated packet pipe"
    );
    std::fs::write(
        case.join("raw-foreign-denied.json"),
        serde_json::to_vec(
            &serde_json::json!({"identity":identity,"original_pid":receipt.binding.process.pid,"helper_pid":receipt.helper.pid,"denied":denied}),
        )?,
    )?;
    Ok(())
}
