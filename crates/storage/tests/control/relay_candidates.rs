use super::*;
use nestlink_identity::{nodes::NodeIdentity,node_discovery::discovery_transcript};
use nestlink_protocol::{NodeRole,Path,api::{NodeDiscoveryRequest,NodeEndpoints,NodeEndpointsUpdate,NodeRegistration,NodeRelayAttributes,NodeRelayAttributesUpdate}};
use prost::Message;
const NOW:u64=1_002_000;

#[test]
fn consumer_candidates_preserve_signed_discovery_and_reveal_only_its_registered_nodes() -> Result {
    let (mut store,_,_,admin,member)=fixture()?;
    store.apply_policy(1,nestlink_policy::NetworkPolicy{server_forwarding:nestlink_policy::ServerForwarding::Allow,peer_path_mode:nestlink_policy::PeerPathMode::DirectPreferred,..Default::default()})?;
    let controller=InstallationIdentity::generate();
    let host=InstallationIdentity::generate();
    let cid=enroll(&mut store,&admin,&controller,"controller")?;
    let hid=enroll(&mut store,&member,&host,"host")?;
    let remote=store.create_remote(&admin,RemoteRequest{id:random_id(),controller_device_id:cid,host_device_id:hid.clone(),permissions:vec![Permission::View as i32],path_mode:"relay_only".into()},NOW/1000)?;
    let choice=ApprovalChoice{approved:true,permissions:vec![Permission::View as i32],paths:vec![Path::Relay as i32]};
    let proof=store.approval_transcript(&member,&remote.id,&choice,NOW/1000)?;
    store.approve_remote(&member,&remote.id,choice,&URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),NOW/1000)?;
    let permit=store.initial_permit(&admin,&remote.id,NOW/1000)?;
    let mut visible=Vec::new();
    let mut hidden=String::new();
    for i in 0..3 {
        let node=NodeIdentity::generate();
        let id=random_id();
        store.register_node(&admin,NodeRegistration{id:id.clone(),name:format!("candidate-{i}"),public_key:URL_SAFE_NO_PAD.encode(node.public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:16,bytes_per_second:1048576})?;
        store.set_node_relay_attributes(&admin,&id,NodeRelayAttributesUpdate{expected_revision:0,attributes:NodeRelayAttributes{region:Some("ap-east".into()),cost_weight:Some(i)}},NOW)?;
        if i==2 {hidden=id;continue;}
        store.set_node_endpoints(&admin,&id,NodeEndpointsUpdate{expected_revision:0,endpoints:NodeEndpoints{quic_uri:Some(format!("quic://relay-{i}.example:28743")),..Default::default()}},NOW)?;
        let challenge=store.node_challenge(&id,NOW)?;
        store.issue_node_lease(&node.prove(&challenge,&random_id())?,NOW)?;
        visible.push(id);
    }
    visible.sort();
    let nonce=[9;32];
    let transcript=discovery_transcript(&permit,&member.account_id,&hid,&nonce)?;
    let request=NodeDiscoveryRequest{device_id:hid.clone(),nonce:URL_SAFE_NO_PAD.encode(nonce),permit_sha256:URL_SAFE_NO_PAD.encode(digest(&permit.encode_to_vec())),signature:URL_SAFE_NO_PAD.encode(host.sign_action(&transcript)?)};
    let lifecycle=store.relay_lifecycle(NOW)?;
    let old=store.discover_relay_nodes(&lifecycle,&member,&remote.id,request.clone(),NOW)?;
    let (claims,attrs)=store.discover_relay_candidates(&lifecycle,&member,&remote.id,request.clone(),NOW)?;
    assert_eq!(old.encode_to_vec(),claims.encode_to_vec());
    assert_eq!(claims.nodes.iter().map(|n|n.node_id.clone()).collect::<Vec<_>>(),visible);
    assert_eq!(attrs.iter().map(|a|a.node_id.clone()).collect::<Vec<_>>(),visible);
    assert!(attrs.iter().all(|a|a.node_id!=hidden&&a.revision==1));
    assert!(store.node_relay_attributes(&member,&visible[0],NOW).is_err());
    let mut forged=request.clone();
    forged.signature=URL_SAFE_NO_PAD.encode(controller.sign_action(&transcript)?);
    assert!(store.discover_relay_candidates(&lifecycle,&member,&remote.id,forged,NOW).is_err());
    assert!(store.discover_relay_candidates(&lifecycle,&admin,&remote.id,request,NOW).is_err());
    Ok(())
}
