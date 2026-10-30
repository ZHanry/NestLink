//! NRD2 uses the original signed node resources, selector, Pair and byte meter.
use super::*;
use nestlink_identity::{network::NodeRemoteChainBinding,nodes::NodeIdentity};
use nestlink_node::control::{NetworkChainNeighborProof,NetworkChainRoute};
use nestlink_protocol::{
    api::{NetworkNodeChallenge,NetworkChainNodeHello,NetworkChainNodeProof,NetworkNodeReady},
    network::PeerId,network_datagram_v2 as wire,
};
use nestlink_transport_quic::routed::{FragmentReplayWindow,authenticated_peer_fingerprint};
use tokio::time::Instant as Deadline;

fn decode<const N:usize>(value:&str) -> io::Result<[u8;N]> {
    let bytes=URL_SAFE_NO_PAD.decode(value).map_err(|_|failed())?;
    if URL_SAFE_NO_PAD.encode(&bytes)!=value { return Err(failed()); }
    bytes.try_into().map_err(|_|failed())
}
fn check_connection(connection:&quinn::Connection) -> io::Result<[u8;32]> {
    if connection.max_datagram_size().is_none_or(|size|size<wire::HEADER+wire::FRAGMENT_BYTES) {
        return Err(failed());
    }
    authenticated_peer_fingerprint(connection)
}
pub(super) async fn incoming(
    connection:quinn::Connection,control:Arc<NodeControl>,hub:Arc<Hub>,
    selector:Arc<RelaySelector>,endpoint:quinn::Endpoint,identity:Arc<NodeIdentity>,
) -> io::Result<()> {
    let tls_peer=check_connection(&connection)?;
    let deadline=Deadline::now()+Duration::from_secs(3);
    let (mut write,mut read)=tokio::time::timeout_at(deadline,connection.open_bi()).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
    let nonce=random_bytes::<32>();
    tokio::time::timeout_at(deadline,write_message(&mut write,&NetworkNodeChallenge {
        schema_version:2,nonce:URL_SAFE_NO_PAD.encode(nonce),
    })).await.map_err(io::Error::other)??;
    let hello:NetworkChainNodeHello=tokio::time::timeout_at(deadline,read_message(&mut read)).await.map_err(io::Error::other)??;
    if hello.schema_version!=2 { return Err(failed()); }
    let binding=decode::<32>(&hello.binding_sha256)?;
    let public_key=decode::<32>(&hello.public_key)?;
    let signature=decode::<64>(&hello.signature)?;
    let returning=decode::<32>(&hello.nonce)?;
    let candidate=control.prepare_network_chain_neighbor(&hello.allocation_id,&binding,&tls_peer,
        NetworkChainNeighborProof {public_key:&public_key,signature:&signature},&nonce).map_err(|_|failed())?;
    let route=control.network_chain_route(&hello.allocation_id).map_err(|_|failed())?;
    let chain=candidate.network_chain().ok_or_else(failed)?;
    if chain!=route.binding || PeerId::from_public_key(&identity.public_key())!=chain.relay { return Err(failed()); }
    let other=if chain.relay==chain.chain.relays[0] {chain.chain.relays[1]} else {chain.chain.relays[0]};
    let return_id=if tls_peer==other.0 {&route.neighbor_allocation_id} else {&route.allocation_id};
    if &hello.return_allocation_id!=return_id { return Err(failed()); }
    let proof=NetworkChainNodeProof {
        schema_version:2,allocation_id:hello.return_allocation_id,
        binding_sha256:URL_SAFE_NO_PAD.encode(binding),public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),
        signature:URL_SAFE_NO_PAD.encode(identity.sign_network_chain_admission(return_id,&binding,PeerId(tls_peer),&returning).map_err(io::Error::other)?),
    };
    tokio::time::timeout_at(deadline,write_message(&mut write,&proof)).await.map_err(io::Error::other)??;
    activate(connection,(write,read),candidate,hub,selector,endpoint,chain,true).await
}

/// Only the first ordered relay dials. Exactly three attempts share the
/// original absolute budget; failure never creates a fresh grant or Pair.
pub(super) async fn outgoing(
    route:NetworkChainRoute,control:Arc<NodeControl>,hub:Arc<Hub>,selector:Arc<RelaySelector>,
    endpoint:quinn::Endpoint,identity:Arc<NodeIdentity>,deadline:Deadline,
) -> io::Result<()> {
    for attempt in 0..3 {
        if Deadline::now()>=deadline { return Err(failed()); }
        let current=control.network_chain_route(&route.allocation_id).map_err(|_|failed())?;
        if current.binding!=route.binding || current.neighbor_allocation_id!=route.neighbor_allocation_id
            || current.neighbor_node.node_id!=route.neighbor_node.node_id
            || current.neighbor_node.revision!=route.neighbor_node.revision
            || current.neighbor_node.endpoints!=route.neighbor_node.endpoints
        { return Err(failed()); }
        match tokio::time::timeout_at(deadline,dial(&route,control.clone(),hub.clone(),selector.clone(),endpoint.clone(),identity.clone())).await {
            Ok(Ok(())) => return Ok(()),
            // Resource polls are independent on both nodes. Space the bounded
            // attempts across their existing poll/HTTP window, rather than
            // exhausting all TLS pin attempts before the peer's next poll.
            _ if attempt<2 => tokio::time::sleep_until((Deadline::now()+Duration::from_millis(500*(attempt+1))).min(deadline)).await,
            _ => return Err(failed()),
        }
    }
    Err(failed())
}
async fn dial(
    route:&NetworkChainRoute,control:Arc<NodeControl>,hub:Arc<Hub>,selector:Arc<RelaySelector>,
    endpoint:quinn::Endpoint,identity:Arc<NodeIdentity>,
) -> io::Result<()> {
    let uri=url::Url::parse(route.neighbor_node.endpoints.quic_uri.as_deref().ok_or_else(failed)?).map_err(|_|failed())?;
    let host=uri.host_str().ok_or_else(failed)?;
    let port=uri.port().ok_or_else(failed)?;
    let address=tokio::time::timeout(Duration::from_millis(700),tokio::net::lookup_host((host,port)))
        .await.map_err(io::Error::other)??.next().ok_or_else(failed)?;
    let _slot=selector.socket(address.ip())?;
    let remote=route.binding.chain.relays[1];
    if route.binding.relay!=route.binding.chain.relays[0] || route.binding.relay!=PeerId::from_public_key(&identity.public_key()) { return Err(failed()); }
    let config=nestlink_transport_quic::routed::chain_node_client_config(&identity,remote.0).map_err(io::Error::other)?;
    let connection=tokio::time::timeout(Duration::from_secs(3),endpoint.connect_with(config,address,"peer.nestlink.invalid").map_err(io::Error::other)?)
        .await.map_err(io::Error::other)?.map_err(io::Error::other)?;
    let _close=Close(connection.clone());
    if check_connection(&connection)?!=remote.0 { return Err(failed()); }
    let (mut write,mut read)=connection.accept_bi().await.map_err(io::Error::other)?;
    let challenge:NetworkNodeChallenge=read_message(&mut read).await?;
    if challenge.schema_version!=2 { return Err(failed()); }
    let nonce=decode::<32>(&challenge.nonce)?;
    let returning=random_bytes::<32>();
    let binding=route.binding.chain.digest;
    let hello=NetworkChainNodeHello {
        schema_version:2,allocation_id:route.neighbor_allocation_id.clone(),binding_sha256:URL_SAFE_NO_PAD.encode(binding),
        public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),
        signature:URL_SAFE_NO_PAD.encode(identity.sign_network_chain_admission(&route.neighbor_allocation_id,&binding,remote,&nonce).map_err(io::Error::other)?),
        return_allocation_id:route.allocation_id.clone(),nonce:URL_SAFE_NO_PAD.encode(returning),
    };
    write_message(&mut write,&hello).await?;
    let proof:NetworkChainNodeProof=read_message(&mut read).await?;
    if proof.schema_version!=2 || proof.allocation_id!=route.allocation_id || decode::<32>(&proof.binding_sha256)?!=binding { return Err(failed()); }
    let key=decode::<32>(&proof.public_key)?;
    let signature=decode::<64>(&proof.signature)?;
    let candidate=control.prepare_network_chain_neighbor(&route.allocation_id,&binding,&remote.0,
        NetworkChainNeighborProof {public_key:&key,signature:&signature},&returning).map_err(|_|failed())?;
    if candidate.network_chain()!=Some(route.binding) { return Err(failed()); }
    activate(connection,(write,read),candidate,hub,selector,endpoint,route.binding,false).await
}

#[allow(clippy::too_many_arguments)]
async fn activate(
    connection:quinn::Connection,streams:(quinn::SendStream,quinn::RecvStream),candidate:RelayEndpointCandidate,
    hub:Arc<Hub>,selector:Arc<RelaySelector>,endpoint:quinn::Endpoint,chain:NodeRemoteChainBinding,incoming:bool,
) -> io::Result<()> {
    let allocation=candidate.allocation_id().to_owned();
    let direction=if candidate.is_controller() {wire::Direction::FirstToSecond} else {wire::Direction::SecondToFirst};
    let remaining=chain.chain.remaining_hops(chain.relay,direction).ok_or_else(failed)?;
    let selection=selector.register(candidate)?;
    let (write,mut read)=streams;
    let mut extra=[0;1];
    let guard=tokio::select! { biased;
        _=connection.closed()=>return Err(failed()),
        _=read.read(&mut extra),if incoming=>return Err(failed()),
        _=connection.accept_bi()=>return Err(failed()),
        _=connection.accept_uni()=>return Err(failed()),
        result=selection.wait()=>result?,
    };
    let mut io=RelayIo {endpoint,connection,streams:Some((write,read)),registration:None,guard:Some(guard)};
    let (registration,mut paired)=hub.register(io.guard.as_ref().ok_or_else(failed)?,&io.connection)?;
    io.registration=Some(registration);
    let guard=io.guard.as_ref().ok_or_else(failed)?;
    let connection=&io.connection;
    let (write,read)=io.streams.as_mut().ok_or_else(failed)?;
    tokio::time::timeout(Duration::from_secs(5),async {
        while !*paired.borrow() {
            guard.check_live().map_err(|_|failed())?;
            tokio::select! { biased;
                _=guard.wait_stopped()=>return Err(failed()),
                _=read.read(&mut extra),if incoming=>return Err(failed()),
                _=connection.accept_bi()=>return Err(failed()),
                _=connection.accept_uni()=>return Err(failed()),
                changed=paired.changed()=>changed.map_err(|_|failed())?,
            }
        }
        let ready=NetworkNodeReady {schema_version:2,allocation_id:allocation.clone(),binding_sha256:URL_SAFE_NO_PAD.encode(chain.chain.digest)};
        if incoming { write_message(write,&ready).await?; }
        let peer_ready:NetworkNodeReady=tokio::select! {biased;
            _=guard.wait_stopped()=>return Err(failed()),
            _=connection.accept_bi()=>return Err(failed()),
            _=connection.accept_uni()=>return Err(failed()),
            ready=read_message(read)=>ready?,
        };
        // The remote node acknowledges our admission ID. On an outgoing link
        // its initial Ready refers to its own original allocation instead.
        let expected=if incoming {allocation.clone()} else {
            selector.control().network_chain_route(&allocation).map_err(|_|failed())?.neighbor_allocation_id
        };
        if peer_ready.schema_version!=2 || peer_ready.allocation_id!=expected
            || decode::<32>(&peer_ready.binding_sha256)?!=chain.chain.digest { return Err(failed()); }
        if !incoming { write_message(write,&peer_ready).await?; }
        guard.check_live().map_err(|_|failed())
    }).await.map_err(io::Error::other)??;
    let peer=hub.peer(io.registration.as_ref().ok_or_else(failed)?)?;
    let mut replay=FragmentReplayWindow::default();
    let mut processed=0u32;
    loop {
        let bytes=tokio::select! { biased;
            _=guard.wait_stopped()=>return Err(failed()),
            _=read.read(&mut extra)=>return Err(failed()),
            _=connection.accept_bi()=>return Err(failed()),
            _=connection.accept_uni()=>return Err(failed()),
            bytes=connection.read_datagram()=>bytes.map_err(io::Error::other)?,
        };
        let fragment=wire::decode(&bytes).map_err(io::Error::other)?;
        if fragment.binding!=chain.chain.digest || fragment.direction!=direction || fragment.remaining_hops!=remaining { return Err(failed()); }
        if !replay.accept(&fragment)? { continue; }
        let mut bytes=bytes.to_vec();
        wire::forward(&mut bytes,chain.chain.digest,direction,remaining).map_err(io::Error::other)?;
        guard.admit(bytes.len() as u64,|| {
            if peer.datagram_send_buffer_space()>=bytes.len() {
                peer.send_datagram(bytes.into()).map_err(|_|ContractError::new(ErrorCode::LeaseExpired,"NRD2 neighbor closed"))?;
            }
            Ok(())
        }).map_err(|_|failed())?;
        processed=(processed+1)%32;
        if processed==0 {tokio::task::yield_now().await;}
    }
}
