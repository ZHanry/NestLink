//! Actual two-LAN UDP/DNS-SD mechanism through the original online packet
//! authority. This fixture explicitly does not qualify a game or real sites.
use super::*;
use nestlink_sdk::network::{lan::{LanBridge,LanPolicy,MdnsRule,UdpRule},packet_access::{OnlinePacketAccess,PACKET_MTU},routed::PinnedNetworkSpace};
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint,PacketAssembler,encode_direct};
use std::{io,net::Ipv4Addr,time::Duration};
use tokio::{sync::watch,time::Instant};
type TaskResult<T=()>=std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;

async fn pump(sdk:&Sdk,access:&mut OnlinePacketAccess,bridge:&LanBridge,endpoint:&DirectPacketEndpoint,mut stop:watch::Receiver<bool>)->TaskResult<u64> {
    let connection=endpoint.connection()?.clone();
    let mut assembly=PacketAssembler::new(access.business_digest(),access.wire_direction().reverse(),PACKET_MTU)?;
    let mut buffer=vec![0_u8;65_536];let mut sequence=0_u64;
    let mut refresh=tokio::time::interval(Duration::from_millis(250));
    let mut fetched=Instant::now();
    let result=loop {
        tokio::select! {biased;
            result=stop.changed()=>{result?;if *stop.borrow(){break Ok(access.spent_bytes());}},
            _=refresh.tick()=>{
                bridge.check_current()?;endpoint.validate_underlay()?;
                if fetched.elapsed()>=Duration::from_secs(1){access.refresh(sdk).await?;fetched=Instant::now();}
            },
            received=connection.read_datagram()=>{
                if let Some(packet)=assembly.insert(&received?,std::time::Instant::now())? {
                    access.admit_remote(&packet)?;bridge.receive_admitted(&packet)?;
                }
            },
            received=bridge.recv(&mut buffer)=>{
                let length=received?;access.admit_local(&buffer[..length])?;
                sequence=sequence.checked_add(1).ok_or_else(||io::Error::other("fixture outer sequence overflow"))?;
                for fragment in encode_direct(access.business_digest(),access.wire_direction(),sequence,&buffer[..length])?{connection.send_datagram(fragment.into())?;}
            },
        }
    };
    access.stop();result
}
fn value(name:&str)->Result<String>{Ok(std::env::var(name)?)}
fn policy(space:&str,index:usize)->Result<LanPolicy> {
    let address:Ipv4Addr=value(&format!("NESTLINK_LAN_{index}_ADDRESS"))?.parse()?;
    let port=if index==0{38303}else{38403};
    Ok(LanPolicy{schema_version:1,space_id:space.into(),interface_index:value(&format!("NESTLINK_LAN_{index}_INDEX"))?.parse()?,interface_address:address,local_prefix:value(&format!("NESTLINK_LAN_{index}_PREFIX"))?,transport_port:37828,packets_per_second:100,bytes_per_second:131_072,udp:vec![UdpRule{id:"actual-dns-service".into(),port,local_target:(value(&format!("NESTLINK_LAN_{index}_SERVER"))?.parse::<Ipv4Addr>()?,port).into(),allow_local_to_peer:true,allow_peer_to_local:true,allow_broadcast_discovery:true}],mdns:vec![MdnsRule{service_type:"_http._tcp.local.".into(),port:38080,allow_export:true,allow_import:true}]})
}
async fn client(index:usize)->TaskResult<serde_json::Value> {
    let namespace=std::env::var(format!("NESTLINK_LAN_{index}_NAMESPACE"))?;
    let gateway=std::env::var(format!("NESTLINK_LAN_{index}_ADDRESS"))?;
    let port=if index==0{"38303"}else{"38403"};
    let expected=if index==0{"10.222.0.2"}else{"10.222.0.1"};
    let output=tokio::process::Command::new("sudo").args(["-n","ip","netns","exec",&namespace,"python3","-B","scripts/network-lan-client.py","--gateway",&gateway,"--port",port,"--expected",expected]).kill_on_drop(true).output().await?;
    if !output.status.success(){return Err(io::Error::other(format!("real LAN client failed: {}",String::from_utf8_lossy(&output.stderr))).into());}
    Ok(serde_json::from_slice(&output.stdout)?)
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires exact GitHub-hosted isolated dual-LAN namespace workflow"]
async fn actual_lan_dns_sd_and_udp_use_original_online_owner_and_release_sockets()->Result {
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?,"github-hosted");
    let f=Fixture::new().await?;
    let mut request=f.fresh_request().await?;
    request.rules=vec![Direction::Inbound,Direction::Outbound].into_iter().map(|direction|NetworkRule{protocol:IpProtocol::Udp,direction,ports:Some([37828,37828])}).collect();
    let issued=f.target.issue_network_access(&f.space,request.clone()).await?;
    let approved=super::subnet::digest(&f,&issued)?;
    let pin=PinnedNetworkSpace::new(f.space.clone(),f.authority)?;
    let mut source=OnlinePacketAccess::start(&f.source,&pin,&f.source_device,&request.access_grant_id,approved,random_id()).await?;
    let mut target=OnlinePacketAccess::start(&f.target,&pin,&f.target_device,&request.access_grant_id,approved,random_id()).await?;
    let policies=[policy(&f.space,0)?,policy(&f.space,1)?];
    let bridges=[LanBridge::bind(policies[0].clone(),&f.space,&source)?,LanBridge::bind(policies[1].clone(),&f.space,&target)?];
    let interfaces=nestlink_platform_network::path::NetworkPathManager::interfaces()?;
    let underlay=interfaces.iter().find(|interface|interface.up && !policies.iter().any(|policy|policy.interface_index==interface.index) && interface.addresses.iter().any(|ip|ip.is_ipv4() && !ip.is_loopback())).ok_or("missing actual carrier underlay")?;
    let address=underlay.addresses.iter().copied().find(|ip|ip.is_ipv4() && !ip.is_loopback()).ok_or("missing actual carrier source")?;
    let path=nestlink_platform_network::path::NetworkPathManager::new(nestlink_platform_network::path::RoutePolicy::Interface(underlay.index))?;
    let mut endpoints=[DirectPacketEndpoint::bind((address,0).into(),&f.source_device.identity,source.remote_peer(),path.clone())?,DirectPacketEndpoint::bind((address,0).into(),&f.target_device.identity,target.remote_peer(),path)?];
    let [first,second]=&mut endpoints;
    let second_address=second.local_addr();
    tokio::try_join!(first.establish(Some(second_address),source.business_digest(),source.transport_group(),Instant::now()+Duration::from_secs(5)),second.establish(None,target.business_digest(),target.transport_group(),Instant::now()+Duration::from_secs(5)))?;
    let publisher=mdns_sd::ServiceDaemon::new()?;
    publisher.disable_interface(mdns_sd::IfKind::All)?;publisher.enable_interface(mdns_sd::IfKind::IndexV4(policies[1].interface_index))?;
    let properties=vec![mdns_sd::TxtProperty::from(("binary",[0_u8,255,7]))];
    let mut record=mdns_sd::ServiceInfo::new("_http._tcp.local.","actual-lan-http","actual-lan-http.local.",policies[1].interface_address,38080,properties)?;
    record.set_interfaces(vec![mdns_sd::IfKind::IndexV4(policies[1].interface_index)]);publisher.register(record)?;
    let observer=mdns_sd::ServiceDaemon::new()?;
    observer.disable_interface(mdns_sd::IfKind::All)?;observer.enable_interface(mdns_sd::IfKind::IndexV4(policies[0].interface_index))?;
    let browsing=observer.browse("_http._tcp.local.")?;
    let http=tokio::net::TcpListener::bind((policies[1].interface_address,38080)).await?;
    let app=axum::Router::new().route("/",axum::routing::get(||async{"actual separately observed HTTP service"}));
    let http_task=tokio::spawn(async move{axum::serve(http,app).await});
    let (stop,stopped)=watch::channel(false);
    let exercise=async {
        let result:TaskResult<serde_json::Value>=async {
            let mut imported=None;let deadline=Instant::now()+Duration::from_secs(12);
            while Instant::now()<deadline {
                if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info))=browsing.try_recv() {
                    if info.get_property("nestlink-proxy").is_some() {
                        let remote:Ipv4Addr=issued.address_directory.addresses.iter().find(|row|row.installation_id==f.target_device.device_id).ok_or_else(||io::Error::other("missing original target assignment"))?.ipv4.parse()?;
                        if info.port!=38080 || !info.get_addresses_v4().contains(&remote) || info.get_addresses_v4().contains(&policies[1].interface_address) || info.get_property_val("binary")!=Some(Some(&[0,255,7][..])) {return Err(io::Error::other("actual imported DNS-SD endpoint or binary TXT mismatch").into());}
                        imported=Some(serde_json::json!({"fullname":info.fullname,"host":info.host,"port":info.port,"virtual_ipv4":remote.to_string(),"binary_txt_preserved":true}));break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let imported=imported.ok_or_else(||io::Error::other("actual permitted DNS-SD service was not discovered"))?;
            let response=reqwest::get(format!("http://{}:38080/",policies[1].interface_address)).await?.text().await?;
            if response!="actual separately observed HTTP service"{return Err(io::Error::other("actual local advertised service unavailable").into());}
            let left=client(0).await?;let right=client(1).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(serde_json::json!({"actual_dns_sd":imported,"actual_udp_dns_clients":[left,right],"game_acceptance_claimed":false,"http_virtual_data_path_qualification_claimed":false}))
        }.await;
        let _=stop.send(true);result
    };
    let owner_pair=async{tokio::try_join!(pump(&f.source,&mut source,&bridges[0],&endpoints[0],stopped.clone()),pump(&f.target,&mut target,&bridges[1],&endpoints[1],stopped))};
    let execution=tokio::try_join!(owner_pair,exercise);
    let mut cleanup=Vec::new();
    for bridge in &bridges {cleanup.push(bridge.shutdown(std::time::Instant::now()+Duration::from_secs(5)).is_ok());}
    for endpoint in &mut endpoints {endpoint.close_and_wait(Instant::now()+Duration::from_secs(5)).await?;}
    source.stop();target.stop();
    observer.stop_browse("_http._tcp.local.")?;
    let observer_stopped=observer.shutdown()?.recv_timeout(Duration::from_secs(2))?==mdns_sd::DaemonStatus::Shutdown;
    let publisher_stopped=publisher.shutdown()?.recv_timeout(Duration::from_secs(2))?==mdns_sd::DaemonStatus::Shutdown;
    http_task.abort();let _=http_task.await;
    assert!(cleanup.iter().all(|value|*value) && observer_stopped && publisher_stopped);
    for policy in &policies {let rebound=std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,policy.udp[0].port))?;drop(rebound);}
    let ((left_bytes,right_bytes),details)=execution.map_err(|error|error as Box<dyn std::error::Error>)?;
    assert!(left_bytes>0 && right_bytes>0 && left_bytes<=request.byte_limit && right_bytes<=request.byte_limit);
    let output=std::path::PathBuf::from(value("NESTLINK_LAN_EVIDENCE")?);
    std::fs::write(output,serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"source_revision":value("GITHUB_SHA")?,"passed":true,"scope":"L2 actual dual LAN UDP DNS and mDNS/DNS-SD on original online HTTP/SQLite/QUIC packet owner; no game, target or virtual HTTP data path qualification","spent_bytes_original_source":left_bytes,"spent_bytes_original_destination":right_bytes,"execution":details,"cleanup":{"original_carriers_joined":true,"lan_udp_ports_rebound":true,"mdns_unregister_and_shutdown_acknowledged":true}}))?)?;
    f.finish().await?;Ok(())
}
