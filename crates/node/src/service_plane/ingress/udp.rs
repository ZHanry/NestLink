//! One public UDP socket, actual visitor peers, and independent native mappings.
use super::*;
use crate::service_plane::{DatagramPacket, DatagramReply, datagram::ReplayWindow};
use tokio::net::UdpSocket;

pub struct ServiceUdpIngress {
    socket: Arc<UdpSocket>,
    reservation: IngressReservation,
}
pub struct PendingServiceDatagram {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    pending: PendingTunnelOpen,
    mapping_id: String,
}
pub struct EdgeDatagramMapping {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    flow: ServiceFlowPermit,
    mapping_id: String,
    received: Mutex<ReplayWindow>,
    sequence: Mutex<u64>,
}
impl ServiceUdpIngress {
    pub async fn bind(
        reservation: IngressReservation,
        node: &NodeControl,
        bind_ip: IpAddr,
    ) -> Result<Self, Error> {
        reservation.deadline(node)?;
        let port = match &reservation.key {
            Key::Udp(port) => *port,
            _ => return Err(Error::Ingress),
        };
        if bind_ip.is_multicast() || matches!(bind_ip,IpAddr::V4(ip) if ip.is_broadcast()) {
            return Err(Error::Ingress);
        }
        let socket = tokio::select! { biased;
            _=reservation.wait_stopped(node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            socket=UdpSocket::bind(SocketAddr::new(bind_ip,port))=>socket?,
        };
        reservation.deadline(node)?;
        Ok(Self {
            socket: Arc::new(socket),
            reservation,
        })
    }
    /// Oversized visitor datagrams are dropped individually. No fragmentation
    /// or reliable queue is introduced, and empty datagrams are preserved.
    pub async fn receive(&self, node: &NodeControl) -> Result<(SocketAddr, Vec<u8>), Error> {
        let mut bytes = [0; DatagramPacket::MAX_PAYLOAD + 1];
        loop {
            self.reservation.deadline(node)?;
            let received = tokio::select! {biased;
                _=self.reservation.wait_stopped(node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
                packet=self.socket.recv_from(&mut bytes)=>packet,
            };
            let (n, peer) = match received {
                Ok(packet) => packet,
                // Windows reports WSAEMSGSIZE after discarding an oversized
                // datagram. This rejects that packet rather than the socket.
                Err(error) if cfg!(windows) && error.raw_os_error() == Some(10040) => continue,
                Err(error) => return Err(error.into()),
            };
            if n > DatagramPacket::MAX_PAYLOAD {
                continue;
            }
            return Ok((peer, bytes[..n].to_vec()));
        }
    }
    /// A rejected peer or exhausted per-flow budget rejects just this mapping;
    /// it does not revoke the public socket or another visitor's mapping.
    pub fn challenge(
        &self,
        node: &NodeControl,
        edge: &NodeIdentity,
        peer: SocketAddr,
    ) -> Result<PendingServiceDatagram, Error> {
        self.reservation.deadline(node)?;
        let flow = self.reservation.publication.reserve_edge(node, peer.ip())?;
        let pending =
            PendingTunnelOpen::new(flow, edge, peer, ServiceTunnelTransport::NativeDatagram)?;
        let mapping_id = nestlink_identity::service_plane::verify_tunnel_challenge(
            pending.challenge(),
            pending.lease(),
            &edge.public_key(),
        )?
        .stream_id;
        Ok(PendingServiceDatagram {
            socket: self.socket.clone(),
            peer,
            pending,
            mapping_id,
        })
    }
}
impl PendingServiceDatagram {
    pub fn mapping_id(&self) -> &str {
        &self.mapping_id
    }
    pub fn lease(&self) -> &VerifiedServiceLease {
        self.pending.lease()
    }
    pub fn challenge(&self) -> &SignedServiceTunnelChallenge {
        self.pending.challenge()
    }
    pub async fn wait_stopped(&self) {
        self.pending.wait_stopped().await;
    }
    pub fn accept(
        self,
        host_key: &[u8; 32],
        proof: &ServiceTunnelProof,
    ) -> Result<EdgeDatagramMapping, Error> {
        let mapping_id = self.mapping_id;
        let flow = self.pending.accept(host_key, proof)?;
        Ok(EdgeDatagramMapping {
            socket: self.socket,
            peer: self.peer,
            flow,
            mapping_id,
            received: Mutex::new(ReplayWindow::default()),
            sequence: Mutex::new(0),
        })
    }
}
impl EdgeDatagramMapping {
    pub fn mapping_id(&self) -> &str {
        &self.mapping_id
    }
    pub async fn wait_stopped(&self) {
        self.flow.wait_stopped().await;
    }
    pub fn packet(&self, payload: Vec<u8>) -> Result<DatagramPacket, Error> {
        if payload.len() > DatagramPacket::MAX_PAYLOAD {
            return Err(Error::Datagram);
        }
        self.flow.try_charge(payload.len())?;
        let mut sequence = self.sequence.lock().map_err(|_| Error::Datagram)?;
        *sequence = sequence
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Datagram)?;
        self.flow.activity()?;
        Ok(DatagramPacket {
            mapping_id: self.mapping_id.clone(),
            sequence: *sequence,
            payload,
        })
    }
    pub async fn reply(&self, reply: &DatagramReply) -> Result<(), Error> {
        if reply.mapping_id != self.mapping_id || reply.payload.len() > DatagramPacket::MAX_PAYLOAD
        {
            return Err(Error::Datagram);
        }
        self.flow.check_live()?;
        {
            let mut window = self.received.lock().map_err(|_| Error::Datagram)?;
            let mut next = *window;
            next.accept(reply.sequence)?;
            self.flow.try_charge(reply.payload.len())?;
            *window = next;
        }
        let n = tokio::select! {biased;
            _=self.flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            sent=self.socket.send_to(&reply.payload,self.peer)=>sent?,
        };
        if n != reply.payload.len() {
            return Err(Error::Datagram);
        }
        self.flow.activity()?;
        Ok(())
    }
}
