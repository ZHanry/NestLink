//! One actual Linux host TUN and two real LAN adapters share the production
//! packet loop and its original HTTP/SQLite one-use authority. The remote host
//! UDP witness is explicit packet-level test code, not a second OS or TCP/HTTP
//! service qualification. Never execute this isolated hosted fixture locally.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::network_packet_runtime::{self, OwnerGuard};
use nestlink_protocol::{network::{Direction, GrantClaims, IpProtocol, NetworkRule}, network_access::NetworkAccessStart};
use nestlink_sdk::{Sdk, SdkError, network::{lan::{LanBridge, LanPolicy, UdpRule}, packet_access::{OnlinePacketAccess, PACKET_MTU}, routed::PinnedNetworkSpace}};
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint, PacketAssembler, encode_direct};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

// Reuse the same real management/store/grant fixture as the Windows owner.
// Its Windows HTTPS process branch remains compiled only on Windows.
#[path = "../windows/native_tests/online/fixture.rs"]
mod fixture;

#[derive(clap::Parser)]
struct LanOptions {
    #[command(flatten)]
    options: crate::network_lan::attached::Options,
}
fn policy(space: &str, index: usize) -> Result<LanPolicy> {
    let value = |field: &str| std::env::var(format!("NESTLINK_LAN_{index}_{field}"));
    let port = if index == 0 {38303} else {38403};
    Ok(LanPolicy {schema_version:1,space_id:space.into(),interface_index:value("INDEX")?.parse()?,
        interface_address:value("ADDRESS")?.parse()?,local_prefix:value("PREFIX")?,transport_port:37828,
        packets_per_second:100,bytes_per_second:131_072,mdns:vec![],udp:vec![UdpRule {
            id:"actual-combined-dns".into(),port,local_target:SocketAddrV4::new(value("SERVER")?.parse()?,port),
            allow_local_to_peer:true,allow_peer_to_local:true,allow_broadcast_discovery:true}]})
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
        let socket = tokio::net::UdpSocket::bind((plan.local_hosts[index],0)).await?;
        let payload = vec![73_u8;if index==0 {1252}else{1232}];
        let remote = SocketAddr::new(plan.remote_hosts[index],443);
        assert_eq!(socket.send_to(&payload,remote).await?,payload.len());
        let mut received=vec![0_u8;2048];
        let (count,source)=tokio::time::timeout(Duration::from_secs(3),socket.recv_from(&mut received)).await??;
        assert_eq!(source,remote);
        assert_eq!(&received[..count],payload);
    }
    Ok(())
}
async fn dns(index:usize)->Result<serde_json::Value>{
    let output=Command::new("sudo").args(["-n","ip","netns","exec",
        &std::env::var(format!("NESTLINK_LAN_{index}_NAMESPACE"))?,"python3","-B","scripts/network-lan-client.py",
        "--gateway",&std::env::var(format!("NESTLINK_LAN_{index}_ADDRESS"))?,"--port",if index==0 {"38303"}else{"38403"},
        "--expected",if index==0 {"10.222.0.2"}else{"10.222.0.1"}]).kill_on_drop(true).output().await?;
    if !output.status.success(){return Err(io::Error::other(format!("actual combined LAN client failed: {}",String::from_utf8_lossy(&output.stderr))).into());}
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn send(endpoint:&DirectPacketEndpoint,access:&mut OnlinePacketAccess,sequence:&mut u64,packet:&[u8])->Result {
    access.admit_local(packet)?;
    *sequence=sequence.checked_add(1).ok_or_else(||io::Error::other("combined witness sequence exhausted"))?;
    for fragment in encode_direct(access.business_digest(),access.wire_direction(),*sequence,packet)? {
        endpoint.connection()?.send_datagram(fragment.into())?;
    }
    Ok(())
}
async fn remote(endpoint:&DirectPacketEndpoint,access:&mut OnlinePacketAccess,sdk:&Sdk,bridge:&LanBridge)->Result {
    let connection=endpoint.connection()?.clone();
    let mut assembly=PacketAssembler::new(access.business_digest(),access.wire_direction().reverse(),PACKET_MTU)?;
    let mut buffer=vec![0_u8;65_536];let mut sequence=0;let mut host_packets=0;
    let mut refresh=tokio::time::interval(Duration::from_secs(1));
    loop {tokio::select! {
        _=refresh.tick()=>{bridge.check_current()?;endpoint.validate_underlay()?;access.refresh(sdk).await?;},
        result=connection.read_datagram()=>{
            let Some(packet)=assembly.insert(&result?,std::time::Instant::now())? else {continue;};
            access.admit_remote(&packet)?;
            if bridge.handles_admitted(&packet){bridge.receive_admitted(&packet)?;continue;}
            // Only these exact original native UDP probes are simulated at
            // the remote host boundary. Real LAN DNS uses the actual process.
            let sliced=etherparse::SlicedPacket::from_ip(&packet)?;
            let Some(etherparse::TransportSlice::Udp(udp))=sliced.transport else {return Err(io::Error::other("unexpected combined host packet").into());};
            assert_eq!(udp.destination_port(),443);assert_eq!(packet.len(),1280);
            assert!(udp.payload().iter().all(|byte|*byte==73));
            let mut reply=vec![];
            let index=if packet[0]>>4==4 {0}else{1};
            match (access.local_hosts()[index],access.remote_hosts()[index]) {
                (IpAddr::V4(source),IpAddr::V4(destination))=>PacketBuilder::ipv4(source.octets(),destination.octets(),64).udp(443,udp.source_port()).write(&mut reply,udp.payload())?,
                (IpAddr::V6(source),IpAddr::V6(destination))=>PacketBuilder::ipv6(source.octets(),destination.octets(),64).udp(443,udp.source_port()).write(&mut reply,udp.payload())?,
                _=>return Err(io::Error::other("combined host family mismatch").into())
            }
            host_packets+=1;assert!(host_packets<=2);send(endpoint,access,&mut sequence,&reply)?;
        },
        result=bridge.recv(&mut buffer)=>{let count=result?;send(endpoint,access,&mut sequence,&buffer[..count])?;}
    }}
}
async fn exercise(f:&fixture::Fixture,plan:&TunPlan,device:&PacketDevice,state:&TunState,source:&mut OnlinePacketAccess,target:&mut OnlinePacketAccess)->Result<(serde_json::Value,Instant)>{
    use clap::Parser;
    assert_eq!(source.local_hosts(),plan.local_hosts);
    assert_eq!(source.remote_hosts(),plan.remote_hosts);
    for installation in [&f.source_device,&f.target_device] {
        let repeated=f.target.start_network_access(&f.space,&f.view.access.grant_id,NetworkAccessStart {
            installation_id:installation.device_id.clone(),owner_id:nestlink_auth::random_id()}).await;
        assert!(matches!(repeated,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    }
    let policies=[policy(&f.space,0)?,policy(&f.space,1)?];
    let policy_path=f.directory.join("reviewed-combined-lan.json");let bytes=serde_json::to_vec(&policies[0])?;
    nestlink_platform_security::create_private(&policy_path,&bytes)?;
    let approval=URL_SAFE_NO_PAD.encode(nestlink_identity::digest(&bytes));
    let options=LanOptions::try_parse_from(["combined-lab","--lan-policy",policy_path.to_str().ok_or_else(||io::Error::other("policy path encoding"))?,"--approve-lan-policy",&approval])?;
    let attached=options.options.prepare(&f.space)?.ok_or_else(||io::Error::other("explicit combined LAN approval missing"))?.bind(source)?;
    let bridge=LanBridge::bind(policies[1].clone(),&f.space,target)?;
    let interface=nestlink_platform_network::path::NetworkPathManager::interfaces()?.into_iter().find(|row|row.up && row.default_route && row.addresses.iter().any(IpAddr::is_ipv4)).ok_or_else(||io::Error::other("combined original physical underlay missing"))?;
    let bind=SocketAddr::new(*interface.addresses.iter().find(|ip|ip.is_ipv4()).ok_or_else(||io::Error::other("combined physical IPv4 missing"))?,0);
    let underlay=nestlink_platform_network::path::NetworkPathManager::new(nestlink_platform_network::path::RoutePolicy::Interface(interface.index))?;
    let mut endpoint=DirectPacketEndpoint::bind(bind,&f.source_device.identity,source.remote_peer(),underlay.clone())?;
    let mut peer=DirectPacketEndpoint::bind(bind,&f.target_device.identity,target.remote_peer(),underlay)?;
    let sockets=[endpoint.local_addr(),peer.local_addr()];
    let result=async {
        let guard=Guard {plan,state,attached:&attached};
        tokio::try_join!(network_packet_runtime::establish(&mut endpoint,Some(peer.local_addr()),&f.source,source,&guard),
            async {peer.establish(None,target.business_digest(),target.transport_group(),Instant::now()+Duration::from_secs(5)).await?;Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())})?;
        let combined=crate::network_lan::attached::Device {host:device,lan:Some(&attached)};
        let work=async {
            let ((),left,right)=tokio::try_join!(application(plan),dns(0),dns(1))?;
            let revision=f.target.space_details(&f.space).await?.space.revision;
            let revoked=Instant::now();f.target.revoke_network_access(&f.space,&f.view.access.grant_id,revision).await?;
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>((left,right,revoked))
        };
        let (local,remote,work)=tokio::time::timeout(Duration::from_secs(20),async {
            tokio::join!(network_packet_runtime::packet_loop(&combined,&mut endpoint,&f.source,source,&guard),remote(&peer,target,&f.target,&bridge),work)
        }).await?;
        let (left,right,revoked)=work?;assert!(local.is_err() && remote.is_err(),"both original online owners must stop on management revocation");
        assert!(revoked.elapsed()<Duration::from_secs(5));
        assert!(source.spent_bytes()>5120 && target.spent_bytes()>5120 && source.spent_bytes()<=1_048_576 && target.spent_bytes()<=1_048_576);
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>((serde_json::json!({"actual_kernel_ipv4_and_ipv6_udp_bytes":5120,"actual_lan_dns":[left,right],
            "original_source_spent_bytes":source.spent_bytes(),"original_target_spent_bytes":target.spent_bytes(),"revoked_owner_stop_ms":revoked.elapsed().as_millis(),"one_use_replay_denials":2}),revoked))
    }.await;
    source.stop();target.stop();
    let first=attached.shutdown();let second=bridge.shutdown(std::time::Instant::now()+Duration::from_secs(5));
    let local_closed=endpoint.close_and_wait(Instant::now()+Duration::from_secs(5)).await;
    let peer_closed=peer.close_and_wait(Instant::now()+Duration::from_secs(5)).await;
    first?;second?;local_closed?;peer_closed?;
    for socket in sockets {drop(std::net::UdpSocket::bind(socket)?);}
    for policy in policies {drop(std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,policy.udp[0].port))?);}
    result
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="exact isolated GitHub-hosted dual-LAN/TUN workflow, ordinary UID, root helper and real dnsmasq required"]
async fn actual_tun_and_lan_share_original_online_owner_and_release_together()->Result {
    lab()?;assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?,"github-hosted");assert_ne!(rustix::process::geteuid().as_raw(),0);
    let rules=[443,37828].into_iter().flat_map(|port|[Direction::Inbound,Direction::Outbound].into_iter().map(move|direction|NetworkRule {protocol:IpProtocol::Udp,direction,ports:Some([port,port])})).collect();
    let f=fixture::Fixture::with_rules(None,rules).await?;assert!(f.origin.starts_with("http://127.0.0.1:"));
    let pin=PinnedNetworkSpace::new(f.space.clone(),f.authority)?;
    // Consume both original durable one-use claims before creating any OS
    // plan, LAN socket or physical endpoint, just like the production owner.
    let mut source=OnlinePacketAccess::start(&f.source,&pin,&f.source_device,&f.view.access.grant_id,f.approved,nestlink_auth::random_id()).await?;
    let mut target=OnlinePacketAccess::start(&f.target,&pin,&f.target_device,&f.view.access.grant_id,f.approved,nestlink_auth::random_id()).await?;
    let signed=nestlink_sdk::network_management::decode_network_grant(&f.view.access)?;let claims=GrantClaims::decode_canonical(&signed.claims)?;
    let now=system_wall_ms()?;
    let plan=TunPlan {schema_version:2,owner_id:source.owner_id().into(),space_id:f.space.clone(),process:process_identity(std::process::id()).await?,principal:plan::HostPrincipal::current()?,
        created_at_ms:now,expires_at_ms:claims.scope().expires_at_ms.min(now+u64::try_from(source.remaining_lifetime().as_millis())?),deployment_id:claims.scope().deployment_id.clone(),authority_key:f.authority,
        local_peer:nestlink_protocol::network::PeerId(f.source_device.identity.fingerprint()),remote_peer:nestlink_protocol::network::PeerId(f.target_device.identity.fingerprint()),
        local_hosts:source.local_hosts(),remote_hosts:source.remote_hosts(),approved_digest:f.approved,policy_epoch:claims.scope().policy_epoch,
        signed_claims:f.view.access.claims.clone(),signature:f.view.access.signature.clone()};
    let plan_path=f.directory.join("combined-tun.json");plan.save_new(&plan_path)?;
    let journal=PathBuf::from("/tmp").join(format!("nestlink-tun-native-{}",nestlink_auth::random_id()));
    assert!(status("init",&plan_path,&journal).await?);
    let mut helper=role_command("apply",&plan_path,&journal,true)?.spawn()?;
    let result=async {
        let state=tokio::time::timeout(Duration::from_secs(15),async {loop {
            if let Some(state)=linux::inspect(&plan).await? && state.up && state.persistent {linux::verify(&plan,&state,true)?;return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(state);}
            if helper.try_wait()?.is_some(){return Err(io::Error::other("original combined root helper stopped before admission").into());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }}).await??;
        let native=tokio::time::timeout(Duration::from_secs(2),async {loop {match linux::adopt(&plan,&state).await {
            Ok(device)=>return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(device),
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|error.raw_os_error()==Some(16))=>tokio::time::sleep(Duration::from_millis(25)).await,
            Err(error)=>return Err(error),
        }}}).await??;
        let mut device=PacketDevice::linux(native);let result=exercise(&f,&plan,&device,&state,&mut source,&mut target).await;
        device.shutdown().await?;result
    }.await;
    source.stop();target.stop();
    let cleanup_started=Instant::now();
    let released=owner::release_plan(&plan,&plan_path).await;
    let joined=finished(&mut helper).await;
    if released.is_err() || !matches!(joined,Ok(true)) {
        let _=status("kill-helper",&plan_path,&journal).await;let _=finished(&mut helper).await;let _=status("recover",&plan_path,&journal).await;
    }
    let teardown=status("teardown",&plan_path,&journal).await?;
    released?;assert!(joined?,"original combined helper must confirm physical cleanup");assert!(teardown);
    assert!(cleanup_started.elapsed()<Duration::from_secs(5));assert!(linux::inspect(&plan).await?.is_none());
    let (mut details,revoked)=result?;
    assert!(revoked.elapsed()<Duration::from_secs(5),"one original revocation must release TUN, LAN and physical QUIC resources together within five seconds");
    details["revoked_all_physical_cleanup_ms"]=serde_json::json!(revoked.elapsed().as_millis());
    f.finish().await?;
    let receipt=serde_json::json!({"schema_version":1,"source_revision":std::env::var("GITHUB_SHA")?,"passed":true,
        "scope":"hosted original production attached device and packet loop: actual single Linux TUN IPv4/IPv6 UDP plus real dual-LAN DNS on one HTTP/SQLite one-use authority and QUIC; remote host packet witness, no peer OS/TCP/virtual HTTP/CLI/target claim",
        "execution":details,"cleanup":{"original_kernel_tun_and_routes_absent":true,"original_root_helper_joined":true,"lan_udp_and_physical_quic_ports_rebound":true}});
    std::fs::write(std::env::var("NESTLINK_LAN_EVIDENCE")?,serde_json::to_vec_pretty(&receipt)?)?;
    Ok(())
}
