//! One original online owner combines actual Linux host TUN TCP/HTTP/UDP and
//! real LAN DNS on the production composite device and packet loop. A second
//! actual kernel is reached through an explicit owner-private local IPC fixture
//! boundary; TCP and HTTP are never synthesized. Hosted mechanism evidence only.
use super::*;
use crate::network_packet_runtime::{self, OwnerGuard};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    network::{Direction, GrantClaims, IpProtocol, NetworkRule},
    network_access::NetworkAccessStart,
};
use nestlink_sdk::{
    Sdk, SdkError,
    network::{
        lan::{LanPolicy, UdpRule},
        packet_access::OnlinePacketAccess,
        routed::PinnedNetworkSpace,
    },
};
use nestlink_transport_quic::packet_codec::DirectPacketEndpoint;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

// Reuse the same real management/store/grant fixture as the Windows owner.
// Its Windows HTTPS process branch remains compiled only on Windows.
#[path = "../windows/native_tests/online/fixture.rs"]
mod fixture;
mod kernel_peer;

#[derive(clap::Parser)]
struct LanOptions {
    #[command(flatten)]
    options: crate::network_lan::attached::Options,
}
fn policy(space: &str, index: usize) -> Result<LanPolicy> {
    let value = |field: &str| std::env::var(format!("NESTLINK_LAN_{index}_{field}"));
    let port = if index == 0 { 38303 } else { 38403 };
    Ok(LanPolicy {
        schema_version: 1,
        space_id: space.into(),
        interface_index: value("INDEX")?.parse()?,
        interface_address: value("ADDRESS")?.parse()?,
        local_prefix: value("PREFIX")?,
        transport_port: 37828,
        packets_per_second: 100,
        bytes_per_second: 131_072,
        mdns: vec![],
        udp: vec![UdpRule {
            id: "actual-combined-dns".into(),
            port,
            local_target: SocketAddrV4::new(value("SERVER")?.parse()?, port),
            allow_local_to_peer: true,
            allow_peer_to_local: true,
            allow_broadcast_discovery: true,
        }],
    })
}
struct Guard<'a> {
    plan: &'a TunPlan,
    state: &'a TunState,
    attached: &'a crate::network_lan::attached::Attached,
}
impl OwnerGuard for Guard<'_> {
    fn check_local(&self) -> Result {
        self.plan.validate(true)?;
        self.attached.check()
    }
    fn check(&self) -> network_packet_runtime::GuardFuture<'_> {
        Box::pin(async move {
            if linux::inspect(self.plan).await?.as_ref() != Some(self.state) {
                return Err(io::Error::other("original combined TUN snapshot changed").into());
            }
            Ok(())
        })
    }
}
async fn application(plan: &TunPlan) -> Result {
    for index in 0..2 {
        let socket = tokio::net::UdpSocket::bind((plan.local_hosts[index], 0)).await?;
        let payload = vec![73_u8; if index == 0 { 1252 } else { 1232 }];
        let remote = SocketAddr::new(plan.remote_hosts[index], 4443);
        assert_eq!(socket.send_to(&payload, remote).await?, payload.len());
        let mut received = vec![0_u8; 2048];
        let (count, source) =
            tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut received)).await??;
        assert_eq!(source, remote);
        assert_eq!(&received[..count], payload);
    }
    Ok(())
}
async fn http(plan: &TunPlan) -> Result<serde_json::Value> {
    let mut bodies = Vec::new();
    for index in 0..2 {
        let url = format!(
            "http://{}/probe",
            SocketAddr::new(plan.remote_hosts[index], 8080)
        );
        let output = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--max-time",
                "3",
                "--interface",
                &plan.local_hosts[index].to_string(),
                &url,
            ])
            .kill_on_drop(true)
            .output()
            .await?;
        assert!(
            output.status.success(),
            "actual cross-TUN HTTP failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            vec![83_u8; 32_768],
            "unmodified remote HTTP service body differs"
        );
        bodies.push(serde_json::json!({"family": if index == 0 {"IPv4"} else {"IPv6"}, "body_bytes": output.stdout.len(), "body_sha256_base64url": URL_SAFE_NO_PAD.encode(nestlink_identity::digest(&output.stdout))}));
    }
    Ok(serde_json::json!(bodies))
}
async fn dns(index: usize) -> Result<serde_json::Value> {
    let output = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            &std::env::var(format!("NESTLINK_LAN_{index}_NAMESPACE"))?,
            "python3",
            "-B",
            "scripts/network-lan-client.py",
            "--gateway",
            &std::env::var(format!("NESTLINK_LAN_{index}_ADDRESS"))?,
            "--port",
            if index == 0 { "38303" } else { "38403" },
            "--expected",
            if index == 0 {
                "10.222.0.2"
            } else {
                "10.222.0.1"
            },
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "actual combined LAN client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
struct PeerGuard<'a> {
    kernel: &'a kernel_peer::KernelPeer,
    attached: &'a crate::network_lan::attached::Attached,
}
impl OwnerGuard for PeerGuard<'_> {
    fn check_local(&self) -> Result {
        self.kernel.plan.validate(true)?;
        self.attached.check()
    }
    fn check(&self) -> network_packet_runtime::GuardFuture<'_> {
        Box::pin(self.kernel.check())
    }
}
fn attach(
    f: &fixture::Fixture,
    policy: &LanPolicy,
    access: &OnlinePacketAccess,
    index: usize,
) -> Result<crate::network_lan::attached::Attached> {
    use clap::Parser;
    let policy_path = f
        .directory
        .join(format!("reviewed-combined-lan-{index}.json"));
    let bytes = serde_json::to_vec(policy)?;
    nestlink_platform_security::create_private(&policy_path, &bytes)?;
    let approval = URL_SAFE_NO_PAD.encode(nestlink_identity::digest(&bytes));
    let options = LanOptions::try_parse_from([
        "combined-lab",
        "--lan-policy",
        policy_path
            .to_str()
            .ok_or_else(|| io::Error::other("policy path encoding"))?,
        "--approve-lan-policy",
        &approval,
    ])?;
    options
        .options
        .prepare(&f.space)?
        .ok_or_else(|| io::Error::other("explicit combined LAN approval missing"))?
        .bind(access)
}
async fn exercise(
    f: &fixture::Fixture,
    plan: &TunPlan,
    device: &PacketDevice,
    state: &TunState,
    source: &mut OnlinePacketAccess,
    target: &mut OnlinePacketAccess,
) -> Result<(serde_json::Value, Instant)> {
    assert_eq!(source.local_hosts(), plan.local_hosts);
    assert_eq!(source.remote_hosts(), plan.remote_hosts);
    for installation in [&f.source_device, &f.target_device] {
        let repeated = f
            .target
            .start_network_access(
                &f.space,
                &f.view.access.grant_id,
                NetworkAccessStart {
                    installation_id: installation.device_id.clone(),
                    owner_id: nestlink_auth::random_id(),
                },
            )
            .await;
        assert!(matches!(repeated,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    }
    let policies = [policy(&f.space, 0)?, policy(&f.space, 1)?];
    let attached = attach(f, &policies[0], source, 0)?;
    let remote_lan = attach(f, &policies[1], target, 1)?;
    let interface = nestlink_platform_network::path::NetworkPathManager::interfaces()?
        .into_iter()
        .find(|row| row.up && row.default_route && row.addresses.iter().any(IpAddr::is_ipv4))
        .ok_or_else(|| io::Error::other("combined original physical underlay missing"))?;
    let bind = SocketAddr::new(
        *interface
            .addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or_else(|| io::Error::other("combined physical IPv4 missing"))?,
        0,
    );
    let underlay = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(interface.index),
    )?;
    let mut endpoint = DirectPacketEndpoint::bind(
        bind,
        &f.source_device.identity,
        source.remote_peer(),
        underlay.clone(),
    )?;
    let mut peer = DirectPacketEndpoint::bind(
        bind,
        &f.target_device.identity,
        target.remote_peer(),
        underlay,
    )?;
    let sockets = [endpoint.local_addr(), peer.local_addr()];
    let mut template = plan.clone();
    template.owner_id = target.owner_id().into();
    template.local_hosts = target.local_hosts();
    template.remote_hosts = target.remote_hosts();
    template.local_peer = plan.remote_peer;
    template.remote_peer = plan.local_peer;
    let mut kernel =
        kernel_peer::KernelPeer::start(template, std::env::var("NESTLINK_LAN_1_NAMESPACE")?)
            .await?;
    let result=async {
        let guard=Guard {plan,state,attached:&attached};
        let peer_guard=PeerGuard {kernel:&kernel,attached:&remote_lan};
        tokio::try_join!(network_packet_runtime::establish(&mut endpoint,Some(peer.local_addr()),&f.source,source,&guard),
            network_packet_runtime::establish(&mut peer,None,&f.target,target,&peer_guard))?;
        let combined=crate::network_lan::attached::Device {host:device,lan:Some(&attached)};
        let remote_device=crate::network_lan::attached::Device {host:&kernel,lan:Some(&remote_lan)};
        let work=async {
            let ((),http,left,right)=tokio::try_join!(application(plan),http(plan),dns(0),dns(1))?;
            let revision=f.target.space_details(&f.space).await?.space.revision;
            let revoked=Instant::now();f.target.revoke_network_access(&f.space,&f.view.access.grant_id,revision).await?;
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>((http,left,right,revoked))
        };
        let (local,remote,work)=tokio::time::timeout(Duration::from_secs(20),async {
            tokio::join!(network_packet_runtime::packet_loop(&combined,&mut endpoint,&f.source,source,&guard),network_packet_runtime::packet_loop(&remote_device,&mut peer,&f.target,target,&peer_guard),work)
        }).await?;
        let (http,left,right,revoked)=work?;assert!(local.is_err() && remote.is_err(),"both original online owners must stop on management revocation");
        assert!(revoked.elapsed()<Duration::from_secs(5));
        assert!(source.spent_bytes()>5120 && target.spent_bytes()>5120 && source.spent_bytes()<=1_048_576 && target.spent_bytes()<=1_048_576);
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>((serde_json::json!({"actual_kernel_ipv4_and_ipv6_udp_bytes":5120,"actual_cross_tun_http":http,"actual_lan_dns":[left,right],
            "remote_kernel":{"fixture_boundary":"private local Unix datagrams carrying complete IP packets","ordinary_uid":kernel.plan.linux_uid()?,"tcp_implementation":"Linux kernel","http_implementation":"unmodified python3 -m http.server"},
            "original_source_spent_bytes":source.spent_bytes(),"original_target_spent_bytes":target.spent_bytes(),"revoked_owner_stop_ms":revoked.elapsed().as_millis(),"one_use_replay_denials":2}),revoked))
    }.await;
    source.stop();
    target.stop();
    let first = attached.shutdown();
    let second = remote_lan.shutdown();
    let local_closed = endpoint
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await;
    let peer_closed = peer
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await;
    let kernel_closed = kernel.shutdown().await;
    first?;
    second?;
    local_closed?;
    peer_closed?;
    kernel_closed?;
    for socket in sockets {
        drop(std::net::UdpSocket::bind(socket)?);
    }
    for policy in policies {
        drop(std::net::UdpSocket::bind((
            Ipv4Addr::UNSPECIFIED,
            policy.udp[0].port,
        ))?);
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "exact isolated GitHub-hosted dual-LAN/TUN workflow, ordinary UID, root helper and real dnsmasq required"]
async fn actual_tun_and_lan_share_original_online_owner_and_release_together() -> Result {
    lab()?;
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    let rules = [
        (IpProtocol::Udp, 4443),
        (IpProtocol::Udp, 37828),
        (IpProtocol::Tcp, 8080),
    ]
    .into_iter()
    .flat_map(|(protocol, port)| {
        [Direction::Inbound, Direction::Outbound]
            .into_iter()
            .map(move |direction| NetworkRule {
                protocol,
                direction,
                ports: Some([port, port]),
            })
    })
    .collect();
    let f = fixture::Fixture::with_rules(None, rules).await?;
    assert!(f.origin.starts_with("http://127.0.0.1:"));
    let pin = PinnedNetworkSpace::new(f.space.clone(), f.authority)?;
    // Consume both original durable one-use claims before creating any OS
    // plan, LAN socket or physical endpoint, just like the production owner.
    let mut source = OnlinePacketAccess::start(
        &f.source,
        &pin,
        &f.source_device,
        &f.view.access.grant_id,
        f.approved,
        nestlink_auth::random_id(),
    )
    .await?;
    let mut target = OnlinePacketAccess::start(
        &f.target,
        &pin,
        &f.target_device,
        &f.view.access.grant_id,
        f.approved,
        nestlink_auth::random_id(),
    )
    .await?;
    let signed = nestlink_sdk::network_management::decode_network_grant(&f.view.access)?;
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    let now = system_wall_ms()?;
    let plan = TunPlan {
        schema_version: 2,
        owner_id: source.owner_id().into(),
        space_id: f.space.clone(),
        process: process_identity(std::process::id()).await?,
        principal: plan::HostPrincipal::current()?,
        created_at_ms: now,
        expires_at_ms: claims
            .scope()
            .expires_at_ms
            .min(now + u64::try_from(source.remaining_lifetime().as_millis())?),
        deployment_id: claims.scope().deployment_id.clone(),
        authority_key: f.authority,
        local_peer: nestlink_protocol::network::PeerId(f.source_device.identity.fingerprint()),
        remote_peer: nestlink_protocol::network::PeerId(f.target_device.identity.fingerprint()),
        local_hosts: source.local_hosts(),
        remote_hosts: source.remote_hosts(),
        approved_digest: f.approved,
        policy_epoch: claims.scope().policy_epoch,
        signed_claims: f.view.access.claims.clone(),
        signature: f.view.access.signature.clone(),
    };
    let plan_path = f.directory.join("combined-tun.json");
    plan.save_new(&plan_path)?;
    let journal = PathBuf::from("/tmp").join(format!(
        "nestlink-tun-native-{}",
        nestlink_auth::random_id()
    ));
    assert!(status("init", &plan_path, &journal).await?);
    let mut helper = role_command("apply", &plan_path, &journal, true)?.spawn()?;
    let result = async {
        let state = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(state) = linux::inspect(&plan).await?
                    && state.up
                    && state.persistent
                {
                    linux::verify(&plan, &state, true)?;
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
                }
                if helper.try_wait()?.is_some() {
                    return Err(io::Error::other(
                        "original combined root helper stopped before admission",
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        let native = tokio::time::timeout(Duration::from_secs(2), async {
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
        let mut device = PacketDevice::linux(native);
        let result = exercise(&f, &plan, &device, &state, &mut source, &mut target).await;
        device.shutdown().await?;
        result
    }
    .await;
    source.stop();
    target.stop();
    let cleanup_started = Instant::now();
    let released = owner::release_plan(&plan, &plan_path).await;
    let joined = finished(&mut helper).await;
    if released.is_err() || !matches!(joined, Ok(true)) {
        let _ = status("kill-helper", &plan_path, &journal).await;
        let _ = finished(&mut helper).await;
        let _ = status("recover", &plan_path, &journal).await;
    }
    let teardown = status("teardown", &plan_path, &journal).await?;
    released?;
    assert!(
        joined?,
        "original combined helper must confirm physical cleanup"
    );
    assert!(teardown);
    assert!(cleanup_started.elapsed() < Duration::from_secs(5));
    assert!(linux::inspect(&plan).await?.is_none());
    let (mut details, revoked) = result?;
    assert!(
        revoked.elapsed() < Duration::from_secs(5),
        "one original revocation must release TUN, LAN and physical QUIC resources together within five seconds"
    );
    details["revoked_all_physical_cleanup_ms"] = serde_json::json!(revoked.elapsed().as_millis());
    f.finish().await?;
    let receipt = serde_json::json!({"schema_version":1,"source_revision":std::env::var("GITHUB_SHA")?,"passed":true,
        "scope":"hosted original production attached device and packet loops: actual source Linux TUN IPv4/IPv6 UDP and curl to unmodified remote Python HTTP over kernel TCP plus real dual-LAN DNS on one HTTP/SQLite one-use authority and QUIC; remote kernel TUN uses explicit private local IPC fixture, no production CLI, second physical device or target-site claim",
        "execution":details,"cleanup":{"original_source_and_remote_kernel_tun_and_routes_absent":true,"original_root_helpers_joined":true,"remote_http_services_stopped":true,"lan_udp_and_physical_quic_ports_rebound":true}});
    std::fs::write(
        std::env::var("NESTLINK_LAN_EVIDENCE")?,
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(())
}
