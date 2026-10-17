//! Actual UDP ingress and one native QUIC DATAGRAM mapping per visitor peer.
use super::*;
use nestlink_node::service_plane::{DatagramPacket, DatagramReply, PendingServiceDatagram};
use tokio::sync::mpsc;

const MAX_MAPPING_AGE: Duration = Duration::from_secs(60);
const PEER_QUEUE: usize = 16;

struct PeerEntry {
    token: u64,
    packets: mpsc::Sender<Vec<u8>>,
}
#[derive(Default)]
struct PeerMappings {
    next: u64,
    entries: HashMap<std::net::SocketAddr, PeerEntry>,
}
impl PeerMappings {
    fn prune_closed(&mut self) {
        self.entries.retain(|_, entry| !entry.packets.is_closed());
    }
    fn available(&mut self) -> bool {
        self.prune_closed();
        self.entries.len() < SERVICE_MAX_OPENINGS
    }
    /// Full queues drop their packet. A closed queue relinquishes this peer so
    /// the next packet can create a fresh mapping before the old task is joined.
    fn offer(&mut self, peer: std::net::SocketAddr, payload: Vec<u8>) -> Option<Vec<u8>> {
        let Some(entry) = self.entries.get(&peer) else {
            return Some(payload);
        };
        match entry.packets.try_send(payload) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => None,
            Err(mpsc::error::TrySendError::Closed(payload)) => {
                self.entries.remove(&peer);
                Some(payload)
            }
        }
    }
    fn insert(
        &mut self,
        peer: std::net::SocketAddr,
        packets: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<u64> {
        if !self.available() || self.entries.contains_key(&peer) || packets.is_closed() {
            return Err(denied());
        }
        let token = self.next.checked_add(1).ok_or_else(denied)?;
        self.next = token;
        self.entries.insert(peer, PeerEntry { token, packets });
        Ok(token)
    }
    fn finished(&mut self, peer: std::net::SocketAddr, token: u64) {
        if self
            .entries
            .get(&peer)
            .is_some_and(|entry| entry.token == token)
        {
            self.entries.remove(&peer);
        }
    }
}

pub(super) async fn listener(
    edge: Arc<Edge>,
    host: Host,
    publication: ServicePublicationHandle,
    ingress: ServiceUdpIngress,
) -> io::Result<()> {
    configured(&edge, &publication)?;
    if !carrier::datagram::supports_native(&host.connection) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let mut tasks = JoinSet::new();
    let mut peers = PeerMappings::default();
    let result = loop {
        tokio::select! {biased;
            _=stopped(&publication,&edge.node)=>break Err(denied()),
            _=host.connection.closed()=>break Err(denied()),
            Some(joined)=tasks.join_next()=>{
                if let Ok((peer,token,_))=joined {peers.finished(peer,token);}
                // A panic/abort carries no peer key, but dropping its receiver
                // makes the exact sender observable as closed here.
                peers.prune_closed();
            },
            packet=ingress.receive(&edge.node)=>{
                let (peer,payload)=match packet {Ok(packet)=>packet,Err(error)=>break Err(fault(error))};
                let Some(payload)=peers.offer(peer,payload)else{continue;};
                if tasks.len()>=SERVICE_MAX_OPENINGS || !peers.available() {continue;}
                let Ok(slot)=edge.openings.clone().try_acquire_owned() else {continue;};
                let pending=match ingress.challenge(&edge.node,&edge.identity,peer) {Ok(pending)=>pending,Err(_)=>continue};
                let (sender,packets)=mpsc::channel(PEER_QUEUE);
                let _=sender.try_send(payload);
                let token=match peers.insert(peer,sender){Ok(token)=>token,Err(_)=>continue};
                let host=host.clone();
                tasks.spawn(async move {let _slot=slot;let result=forward(host,pending,packets).await;(peer,token,result)});
            },
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(peers);
    drop(ingress);
    result
}

async fn forward(
    host: Host,
    pending: PendingServiceDatagram,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let stream_id = pending.mapping_id().to_owned();
    let offer = ServiceStreamOffer {
        lease: pending.lease().signed().clone(),
        challenge: pending.challenge().clone(),
    };
    let negotiate = async {
        let (send, recv) = host.connection.open_bi().await.map_err(fault)?;
        let mut stream = BiStream::new(send, recv);
        write_message(stream.parts_mut().0, &offer).await?;
        let proof: ServiceTunnelProof = read_message(stream.parts_mut().1).await?;
        if proof.host_runtime_id != host.runtime {
            return Err(denied());
        }
        let lease_sha256 = proof.lease_sha256;
        Ok::<_, io::Error>((stream, proof, lease_sha256))
    };
    let (mut stream, proof, lease_sha256) = tokio::select! {biased;
        _=pending.wait_stopped()=>return Err(denied()),
        result=tokio::time::timeout_at(deadline.into(),negotiate)=>result.map_err(fault)??,
    };
    let mapping = pending.accept(&host.key, &proof).map_err(fault)?;
    let mut replies = host
        .datagrams
        .register(DatagramPacket::mapping_key(mapping.mapping_id()).map_err(fault)?)?;
    tokio::time::timeout_at(
        deadline.into(),
        write_message(
            stream.parts_mut().0,
            &ServiceStreamReady {
                stream_id,
                lease_sha256,
            },
        ),
    )
    .await
    .map_err(fault)??;
    let expires = tokio::time::sleep(MAX_MAPPING_AGE);
    tokio::pin!(expires);
    loop {
        let mut unexpected = [0];
        tokio::select! {biased;
            _=mapping.wait_stopped()=>return Ok(()),
            _=&mut expires=>return Ok(()),
            _=host.connection.closed()=>return Ok(()),
            _=AsyncReadExt::read(&mut stream,&mut unexpected)=>return Ok(()),
            packet=packets.recv()=>{
                let Some(payload)=packet else{return Ok(())};
                let Ok(packet)=mapping.packet(payload) else{continue;};
                let _=carrier::datagram::send(&host.connection,packet.encode().map_err(fault)?);
            },
            reply=replies.receive()=>{
                let Some(reply)=reply else{return Ok(())};
                let Ok(reply)=DatagramReply::decode(&reply) else{continue;};
                let _=mapping.reply(&reply).await;
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn peer(n: usize) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 10000 + n as u16))
    }
    #[tokio::test]
    async fn old_mapping_completion_cannot_remove_same_peer_replacement() -> Result {
        let mut peers = PeerMappings::default();
        let (old_sender, old_receiver) = mpsc::channel(PEER_QUEUE);
        let old = peers.insert(peer(1), old_sender)?;
        drop(old_receiver);
        assert_eq!(
            peers.offer(peer(1), b"reopen".to_vec()),
            Some(b"reopen".to_vec())
        );
        let (sender, mut receiver) = mpsc::channel(PEER_QUEUE);
        let replacement = peers.insert(peer(1), sender)?;
        assert!(replacement > old);
        peers.finished(peer(1), old);
        assert!(peers.offer(peer(1), b"replacement".to_vec()).is_none());
        assert_eq!(receiver.recv().await, Some(b"replacement".to_vec()));
        peers.finished(peer(1), replacement);
        assert!(peers.entries.is_empty());
        Ok(())
    }
    #[test]
    fn closed_receivers_are_pruned_and_peer_table_has_its_own_capacity_bound() -> Result {
        let mut peers = PeerMappings::default();
        let mut receivers = Vec::new();
        for n in 0..SERVICE_MAX_OPENINGS {
            let (sender, receiver) = mpsc::channel(PEER_QUEUE);
            peers.insert(peer(n), sender)?;
            receivers.push(receiver);
        }
        assert!(!peers.available());
        let (extra, _receiver) = mpsc::channel(PEER_QUEUE);
        assert!(peers.insert(peer(SERVICE_MAX_OPENINGS), extra).is_err());
        assert_eq!(peers.entries.len(), SERVICE_MAX_OPENINGS);
        drop(receivers);
        peers.prune_closed();
        assert!(peers.entries.is_empty());
        for n in 0..SERVICE_MAX_OPENINGS * 3 {
            let (sender, receiver) = mpsc::channel(PEER_QUEUE);
            peers.insert(peer(n), sender)?;
            drop(receiver);
            assert!(peers.available());
            assert!(peers.entries.is_empty());
        }
        Ok(())
    }
}
