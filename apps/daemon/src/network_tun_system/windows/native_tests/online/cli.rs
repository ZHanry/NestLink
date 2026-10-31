//! Execute the unchanged production Clap/HTTPS/protected-login owner in a
//! distinct medium process. This process is its independent UDP application
//! and disposable remote protocol witness, not an independent target machine.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{ffi::OsString, process::Stdio};

pub(in super::super) async fn fixture(
    case: &Path,
    plan_path: &Path,
    receipt_path: &Path,
) -> Result {
    nestlink_privileged::windows::require_normal_user_process()?;
    let f = Fixture::new(Some(case)).await?;
    assert!(f.origin.starts_with("https://") && f.origin.ends_with(".trycloudflare.com"));
    nestlink_platform_security::create_private(&f.directory.join("remember-login.json"), b"true")?;
    crate::session_store::SessionStore::new(f.directory.clone()).save(
        &f.source
            .export_login()?
            .ok_or_else(|| io::Error::other("original HTTPS fixture login missing"))?,
    )?;
    let saved = crate::space_dns::session_snapshot(&f.directory)?;
    let pin = PinnedNetworkSpace::new(f.space.clone(), f.authority)?;
    let mut access = OnlinePacketAccess::start(
        &f.target,
        &pin,
        &f.target_device,
        &f.view.access.grant_id,
        f.approved,
        nestlink_auth::random_id(),
    )
    .await?;
    let interface = nestlink_platform_network::path::NetworkPathManager::interfaces()?
        .into_iter()
        .find(|row| row.up && row.default_route && row.addresses.iter().any(IpAddr::is_ipv4))
        .ok_or_else(|| io::Error::other("HTTPS CLI original underlay missing"))?;
    let bind = SocketAddr::new(
        *interface
            .addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or_else(|| io::Error::other("HTTPS CLI underlay IPv4 missing"))?,
        0,
    );
    let selected = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(interface.index),
    )?;
    let mut peer = DirectPacketEndpoint::bind(
        bind,
        &f.target_device.identity,
        access.remote_peer(),
        selected.clone(),
    )?;
    let remote_endpoint = peer.local_addr();
    let reserve = selected.bind_udp(bind)?;
    let owner_endpoint = reserve.local_addr()?;
    drop(reserve);
    nestlink_platform_security::new_private_directory(
        plan_path
            .parent()
            .ok_or_else(|| io::Error::other("HTTPS CLI plan parent missing"))?,
    )?;
    let mut args = vec![OsString::from("network-tun")];
    for (flag, value) in [
        ("--state-dir", f.directory.as_os_str().to_os_string()),
        ("--space", f.space.clone().into()),
        ("--grant", f.view.access.grant_id.clone().into()),
        ("--authority", URL_SAFE_NO_PAD.encode(f.authority).into()),
        (
            "--approve-digest",
            URL_SAFE_NO_PAD.encode(f.approved).into(),
        ),
        ("--interface", interface.index.to_string().into()),
        ("--bind", owner_endpoint.to_string().into()),
        ("--dial", peer.local_addr().to_string().into()),
        ("--plan", plan_path.as_os_str().to_os_string()),
        ("--receipt", receipt_path.as_os_str().to_os_string()),
    ] {
        args.push(flag.into());
        args.push(value);
    }
    let log = case.join("production-cli.log");
    let output = std::fs::File::create(&log)?;
    // This is the separately built product executable: its real main, Clap
    // dispatch, installation admission and owner run without cfg(test) hooks.
    let mut child = tokio::process::Command::new(path("NESTLINK_TUN_NATIVE_PRODUCTION_DAEMON")?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .kill_on_drop(true)
        .spawn()?;
    let child_identity = nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(
        child
            .id()
            .ok_or_else(|| io::Error::other("production CLI child PID missing"))?,
    )?;
    std::fs::write(
        case.join("cli-process.json"),
        serde_json::to_vec(&serde_json::json!({"identity":child_identity}))?,
    )?;
    let plan=tokio::time::timeout(Duration::from_secs(30),async{
        let mut refreshed=Instant::now();
        loop{
            if child.try_wait()?.is_some(){return Err(io::Error::other("production HTTPS CLI ended before publishing its original plan; see production-cli.log").into());}
            match TunPlan::read(plan_path){
                Ok(plan)=>return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(plan),
                Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|error.kind()==io::ErrorKind::NotFound)=>{},
                Err(error)=>return Err(error),
            }
            if refreshed.elapsed()>=Duration::from_secs(1){access.refresh(&f.target).await?;refreshed=Instant::now();}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await??;
    let identity = plan.windows_binding().await?.process;
    assert_eq!(Some(identity.pid), child.id());
    assert_ne!(identity.pid, std::process::id());
    assert_ne!(
        crate::space_dns::session_snapshot(&f.directory)?,
        saved,
        "the original production plan preceded protected HTTPS restoration"
    );
    for device in [&f.source_device, &f.target_device] {
        let repeated = f
            .target
            .start_network_access(
                &f.space,
                &f.view.access.grant_id,
                NetworkAccessStart {
                    installation_id: device.device_id.clone(),
                    owner_id: nestlink_auth::random_id(),
                },
            )
            .await;
        assert!(
            matches!(&repeated,Err(SdkError::Api(status,_)) if status.as_u16()==403),
            "production CLI and original remote claims must remain consumed: {repeated:?}"
        );
    }
    std::fs::write(
        case.join("plan-ready.json"),
        serde_json::to_vec(&serde_json::json!({"plan":plan,"identity":identity,
        "separate_application_pid":std::process::id(),"production_https_login_restore_before_plan":true,"fixture_origin":f.origin}))?,
    )?;
    let state = tokio::time::timeout(Duration::from_secs(15), async {
        let mut refreshed = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return Err(io::Error::other(
                    "production HTTPS CLI ended before native packet admission",
                )
                .into());
            }
            match std::fs::read(receipt_path) {
                Ok(bytes) => {
                    let state: PacketReceipt = serde_json::from_slice(&bytes)?;
                    let snapshot = resources::inspect(&state.provider)?
                        .ok_or_else(|| io::Error::other("original CLI native snapshot missing"))?;
                    snapshot.verify(&plan.local_hosts, &plan.remote_hosts)?;
                    assert_eq!(snapshot.digest()?, state.provider.configuration_sha256);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if refreshed.elapsed() >= Duration::from_secs(1) {
                access.refresh(&f.target).await?;
                refreshed = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let result=async{
        access.refresh(&f.target).await?;
        peer.establish(None,access.business_digest(),access.transport_group(),Instant::now()+Duration::from_secs(10)).await?;
        let revocation=std::sync::OnceLock::new();
        let application=super::probe(case,&f,&plan,&state,&mut peer,&mut access,&revocation);
        tokio::pin!(application);
        let exited=child.wait();tokio::pin!(exited);
        let (revoked,status)=tokio::select!{
            status=&mut exited=>{
                let started=*revocation.get().ok_or_else(||io::Error::other("production HTTPS CLI exited before the original online revocation"))?;
                (tokio::time::timeout_at(started+Duration::from_secs(5),&mut application).await??,status?)
            },
            revoked=&mut application=>{
                let revoked=revoked?;
                (revoked,tokio::time::timeout_at(revoked+Duration::from_secs(5),&mut exited).await??)
            },
        };
        assert_eq!(status.code(),Some(1),"the actual product CLI must return its original revocation error");
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(revoked)
    }.await;
    access.stop();
    peer.close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    let revoked = result?;
    assert!(resources::absent(&state.provider)?);
    assert!(
        !plan_path.try_exists()?,
        "the production CLI retained its original public plan after cleanup"
    );
    assert!(
        std::net::UdpSocket::bind(owner_endpoint).is_ok(),
        "the actual production CLI still owns its original physical UDP endpoint"
    );
    assert!(
        std::net::UdpSocket::bind(remote_endpoint).is_ok(),
        "the original remote witness still owns its physical UDP endpoint"
    );
    let text = std::fs::read_to_string(log)?;
    assert!(
        text.contains(
            "NestLink user daemon stopped: management operation rejected (403 Forbidden): PermissionRequired"
        ),
        "the real product main did not report the original HTTP revocation error: {text}"
    );
    let retained = crate::identity(&f.directory)?;
    assert_eq!(retained.device_id, f.source_device.device_id);
    assert_eq!(
        retained.identity.fingerprint(),
        f.source_device.identity.fingerprint()
    );
    let stopped = serde_json::json!({"owner_pid":identity.pid,"actual_product_main":true,"actual_clap_entry":true,
        "actual_session_store_restore":true,"original_installation_retained":true,"online_http_403_observed":true,
        "production_cleanup_returned":true,"product_exit_code":1});
    std::fs::write(case.join("cli-stopped.json"), serde_json::to_vec(&stopped)?)?;
    let counters: serde_json::Value = text
        .lines()
        .find_map(|line| line.strip_prefix("Packet owner counters: "))
        .ok_or_else(|| io::Error::other("production CLI packet counters missing"))
        .and_then(|line| serde_json::from_str(line).map_err(io::Error::other))?;
    assert_eq!(counters["sent_packets"], 2);
    assert_eq!(counters["received_packets"], 2);
    assert_eq!(counters["spent_bytes"], 5120);
    let physical_ms = revoked.elapsed().as_millis();
    assert!(
        physical_ms < 5000,
        "real HTTPS revocation must release the production original OS/UDP resources within five seconds"
    );
    let remote_spent = access.spent_bytes();
    f.finish().await?;
    std::fs::write(
        case.join("ordinary-stopped.json"),
        serde_json::to_vec(&serde_json::json!({
            "kernel_absent":true,"normal_cleanup_ms":physical_ms,"revocation_to_physical_cleanup_ms":physical_ms,
            "online_http_403_observed":true,"original_udp_endpoints_rebound":true,"local_original_spent_bytes":counters["spent_bytes"],
            "remote_original_spent_bytes":remote_spent,"one_use_replay_denials":2,"production_cli_validated":true,
            "production_https_login_resume_validated":true,"actual_owner":stopped,"same_host_only":true,
            "fixture_accounts_deleted":true,"temporary_https_tunnel_joined":true,
            "tls_boundary":"standard product webpki HTTPS to Cloudflare termination; temporary tunnel HTTP origin is loopback only; peer packet QUIC remains independently pinned mTLS"
        }))?,
    )?;
    Ok(())
}
