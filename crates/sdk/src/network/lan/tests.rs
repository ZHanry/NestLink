use super::*;
use super::wire::{Body,Envelope,Replay,UdpRequest};
use prost::Message;
use std::net::Ipv4Addr;
type Result<T=()>=std::result::Result<T,Box<dyn std::error::Error>>;
const SPACE:&str="20000000-0000-4000-8000-000000000002";
fn policy()->LanPolicy {
    LanPolicy {schema_version:1,space_id:SPACE.into(),interface_index:2,interface_address:Ipv4Addr::new(192,168,42,2),local_prefix:"192.168.42.0/24".into(),transport_port:37828,packets_per_second:20,bytes_per_second:32_768,udp:vec![UdpRule{id:"teeworlds".into(),port:8303,local_target:std::net::SocketAddrV4::new(Ipv4Addr::new(192,168,42,3),8303),allow_local_to_peer:true,allow_peer_to_local:true,allow_broadcast_discovery:true}],mdns:vec![MdnsRule{service_type:"_http._tcp.local.".into(),port:8080,allow_export:true,allow_import:true,allow_routable_publication:true}]}
}
fn envelope(sequence:u64)->Result<Envelope> {
    Ok(Envelope{version:1,space:SPACE.into(),business:vec![9;32],sequence,sent_ms:wall_ms()?,hops:1,body:Some(Body::Request(UdpRequest{rule:"teeworlds".into(),flow:1,payload:vec![17;1024],discovery:true}))})
}
#[test]
fn local_policy_requires_exact_lan_ports_directions_and_dns_sd_scope()->Result {
    let value=policy();value.validate()?;
    let mut invalid=value.clone();invalid.local_prefix="192.168.42.7/24".into();assert!(invalid.validate().is_err());
    let mut invalid=value.clone();invalid.udp[0].local_target.set_ip(value.interface_address);assert!(invalid.validate().is_err());
    let mut invalid=value.clone();invalid.udp.push(value.udp[0].clone());assert!(invalid.validate().is_err());
    let mut invalid=value.clone();invalid.udp[0].allow_local_to_peer=false;invalid.udp[0].allow_peer_to_local=false;assert!(invalid.validate().is_err());
    for kind in ["_http._tcp.example.com.","_http._tcp.local..","_services._dns-sd._udp.local.","_http._tcp.local","_._tcp.local."] {
        let mut invalid=value.clone();invalid.mdns[0].service_type=kind.into();assert!(invalid.validate().is_err(),"{kind}");
    }
    let mut invalid=value.clone();invalid.mdns[0].allow_routable_publication=false;assert!(invalid.validate().is_err());
    let mut invalid=value.clone();invalid.mdns[0].allow_import=false;assert!(invalid.validate().is_err());
    let mut export_only=value.clone();export_only.mdns[0].allow_import=false;export_only.mdns[0].allow_routable_publication=false;export_only.validate()?;
    let mut invalid=value;invalid.packets_per_second=101;assert!(invalid.validate().is_err());Ok(())
}
#[test]
fn original_unicast_packet_roundtrip_preserves_payload_and_refuses_corruption()->Result {
    let source=Ipv4Addr::new(10,44,0,2);let destination=Ipv4Addr::new(10,44,0,3);
    let message=envelope(1)?;
    let packet=wire::packet(source,destination,37828,&message)?;
    assert!(packet.len()<=super::super::packet_access::PACKET_MTU);
    assert_eq!(wire::parse(&packet,source,destination,37828)?,message);
    assert!(wire::parse(&packet,destination,source,37828).is_err());
    assert!(wire::parse(&packet,source,destination,37829).is_err());
    let mut corrupt=packet.clone();*corrupt.last_mut().ok_or("missing packet")?^=1;assert!(wire::parse(&corrupt,source,destination,37828).is_err());
    let mut oversized=message.clone();if let Some(Body::Request(request))=&mut oversized.body{request.payload.resize(1500,1);}
    assert!(wire::packet(source,destination,37828,&oversized).is_err());
    let mut unknown=message.encode_to_vec();unknown.extend_from_slice(&[0x58,1]);
    let builder=etherparse::PacketBuilder::ipv4(source.octets(),destination.octets(),16).udp(37828,37828);let mut other=Vec::new();builder.write(&mut other,&unknown)?;
    assert!(wire::parse(&other,source,destination,37828).is_err());Ok(())
}
#[test]
fn envelope_replay_ttl_space_and_original_business_are_independent()->Result {
    let mut replay=Replay::default();let value=envelope(2)?;
    let mut wrong=value.clone();wrong.space=nestlink_auth::random_id();assert!(replay.admit(&wrong,SPACE,&[9;32]).is_err());
    let mut wrong=value.clone();wrong.business[0]=8;assert!(replay.admit(&wrong,SPACE,&[9;32]).is_err());
    let mut wrong=value.clone();wrong.hops=2;assert!(replay.admit(&wrong,SPACE,&[9;32]).is_err());
    let mut wrong=value.clone();wrong.sent_ms=wrong.sent_ms.saturating_sub(2001);assert!(replay.admit(&wrong,SPACE,&[9;32]).is_err());
    replay.admit(&value,SPACE,&[9;32])?;assert!(replay.admit(&value,SPACE,&[9;32]).is_err());
    replay.admit(&envelope(1)?,SPACE,&[9;32])?;
    replay.admit(&envelope(70)?,SPACE,&[9;32])?;
    assert!(replay.admit(&envelope(3)?,SPACE,&[9;32]).is_err());Ok(())
}
#[test]
fn dns_sd_preserves_binary_txt_and_rejects_proxy_loops_or_oversized_catalog_data()->Result {
    let mut service=wire::Service{service_type:"_http._tcp.local.".into(),instance:"svc-0123456789abcdef".into(),port:8080,properties:vec![wire::Txt{key:"binary".into(),value:Some(vec![0,255,7])}]};
    mdns::validate(&service)?;service.properties.push(wire::Txt{key:"nestlink-proxy".into(),value:Some(b"1".to_vec())});assert!(mdns::validate(&service).is_err());
    service.properties.pop();service.properties.push(wire::Txt{key:"BINARY".into(),value:None});assert!(mdns::validate(&service).is_err());
    service.properties.pop();service.properties[0].value=Some(vec![1;193]);assert!(mdns::validate(&service).is_err());Ok(())
}
#[test]
fn complete_game_datagram_reuses_original_fragment_owner_with_flow_and_mode_separation()->Result {
    use nestlink_protocol::network_datagram::Direction;
    use nestlink_transport_quic::packet_codec::{PacketAssembler,encode_direct};
    let data:Vec<_>=(0..1400).map(|index|(index%251)as u8).collect();
    let binding=wire::flow_binding([9;32],"teeworlds",1,false,true);
    let fragments=encode_direct(binding,Direction::FirstToSecond,1,&data)?;
    assert_eq!(fragments.len(),2);
    let mut receiver=PacketAssembler::new(binding,Direction::FirstToSecond,1400)?;
    let now=std::time::Instant::now();
    assert!(receiver.insert(&fragments[1],now)?.is_none());
    assert_eq!(receiver.insert(&fragments[0],now)?,Some(data));
    assert!(receiver.insert(&fragments[0],now)?.is_none());
    for other in [wire::flow_binding([9;32],"teeworlds",2,false,true),wire::flow_binding([9;32],"teeworlds",1,true,true),wire::flow_binding([9;32],"teeworlds",1,false,false),wire::flow_binding([8;32],"teeworlds",1,false,true)] {
        let mut denied=PacketAssembler::new(other,Direction::FirstToSecond,1400)?;
        assert!(denied.insert(&fragments[0],now).is_err());
    }
    Ok(())
}
