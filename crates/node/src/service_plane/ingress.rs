use super::{
    Error, PendingTunnelOpen, ServiceFlowPermit, ServicePublicationHandle, forward_streams,
    gate::rejected,
};
use crate::control::NodeControl;
use nestlink_identity::{nodes::NodeIdentity, service_plane::VerifiedServiceLease};
use nestlink_protocol::{
    ErrorCode,
    api::ServiceIngress,
    service_plane::{
        SERVICE_PUBLICATIONS_PER_NODE, ServiceTunnelProof, ServiceTunnelTransport,
        SignedServiceTunnelChallenge,
    },
    valid_id,
};
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
mod udp;
mod web;
pub use udp::{EdgeDatagramMapping, PendingServiceDatagram, ServiceUdpIngress};
pub use web::{AuthorizedServiceWeb, PendingServiceWebOpen, ServiceWebIngress, ServiceWebVisitor};

/// Operator-configured local namespace. DNS/control-plane ownership still has
/// to be authenticated and persisted before issuing the signed ingress claim.
pub struct IngressNamespace {
    edge_node_id: String,
    service_suffix: String,
    management_hostname: String,
    public_ports: BTreeSet<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    // HTTP and HTTPS deliberately share one hostname ownership key.
    Host(String),
    Tcp(u16),
    Udp(u16),
}
struct Entry {
    token: String,
    publication_id: String,
    ingress_claim_id: String,
    ingress_claim_revision: u64,
    binding: [u8; 32],
}
struct Ownership {
    namespace: IngressNamespace,
    entries: Mutex<HashMap<Key, Entry>>,
}
#[derive(Clone)]
pub struct IngressOwnership {
    shared: Arc<Ownership>,
}
/// Unique, non-cloneable reservation. Drop releases only its exact token.
pub struct IngressReservation {
    shared: Arc<Ownership>,
    key: Key,
    token: String,
    binding: [u8; 32],
    publication: ServicePublicationHandle,
}
fn dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && !value.ends_with('.')
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}
fn below(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix)
        .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
}
impl IngressNamespace {
    pub fn new(
        edge_node_id: String,
        service_suffix: String,
        management_hostname: String,
        public_ports: Vec<u16>,
    ) -> Result<Self, Error> {
        if !valid_id(&edge_node_id)
            || !dns_name(&service_suffix)
            || !dns_name(&management_hostname)
            || management_hostname == service_suffix
            || below(&management_hostname, &service_suffix)
            || public_ports.len() > 1024
            || public_ports
                .iter()
                .any(|p| *p < 1024 || (28743..=29055).contains(p))
        {
            return Err(Error::Ingress);
        }
        let ports: BTreeSet<_> = public_ports.iter().copied().collect();
        if ports.len() != public_ports.len() {
            return Err(Error::Ingress);
        }
        Ok(Self {
            edge_node_id,
            service_suffix,
            management_hostname,
            public_ports: ports,
        })
    }
    fn key(&self, lease: &VerifiedServiceLease) -> Result<Key, Error> {
        let definition = &lease.claims().definition;
        if lease.claims().edge_node_id() != self.edge_node_id {
            return Err(Error::Ingress);
        }
        match &definition.requested_ingress {
            ServiceIngress::Http { hostname } | ServiceIngress::Https { hostname } => {
                if !dns_name(hostname)
                    || !below(hostname, &self.service_suffix)
                    || hostname == &self.management_hostname
                {
                    return Err(Error::Ingress);
                }
                Ok(Key::Host(hostname.clone()))
            }
            ServiceIngress::Tcp { port } if self.public_ports.contains(port) => Ok(Key::Tcp(*port)),
            ServiceIngress::Udp { port } if self.public_ports.contains(port) => Ok(Key::Udp(*port)),
            _ => Err(Error::Ingress),
        }
    }
}
impl IngressOwnership {
    pub fn new(namespace: IngressNamespace) -> Self {
        Self {
            shared: Arc::new(Ownership {
                namespace,
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }
    pub fn reserve(
        &self,
        publication: &ServicePublicationHandle,
        node: &NodeControl,
    ) -> Result<IngressReservation, Error> {
        let lease = publication.lease()?;
        node.inspect_service_lease(&lease)?;
        let key = self.shared.namespace.key(&lease)?;
        let mut entries = self.shared.entries.lock().map_err(|_| Error::Ingress)?;
        if entries.len() >= SERVICE_PUBLICATIONS_PER_NODE
            || entries.contains_key(&key)
            || entries
                .values()
                .any(|e| e.publication_id == lease.claims().publication_id)
        {
            return Err(Error::Ingress);
        }
        let token = uuid::Uuid::new_v4().to_string();
        entries.insert(
            key.clone(),
            Entry {
                token: token.clone(),
                publication_id: lease.claims().publication_id.clone(),
                ingress_claim_id: lease.claims().ingress_claim_id.clone(),
                ingress_claim_revision: lease.claims().ingress_claim_revision,
                binding: lease.binding(),
            },
        );
        Ok(IngressReservation {
            shared: self.shared.clone(),
            key,
            token,
            binding: lease.binding(),
            publication: publication.clone(),
        })
    }
}
impl IngressReservation {
    fn deadline(&self, node: &NodeControl) -> Result<Instant, Error> {
        let lease = self.publication.lease()?;
        let node_end = node.inspect_service_lease(&lease)?;
        if lease.binding() != self.binding || self.shared.namespace.key(&lease)? != self.key {
            return Err(Error::Ingress);
        }
        let entries = self.shared.entries.lock().map_err(|_| Error::Ingress)?;
        let entry = entries.get(&self.key).ok_or(Error::Ingress)?;
        if entry.token != self.token
            || entry.binding != lease.binding()
            || entry.publication_id != lease.claims().publication_id
            || entry.ingress_claim_id != lease.claims().ingress_claim_id
            || entry.ingress_claim_revision != lease.claims().ingress_claim_revision
        {
            return Err(Error::Ingress);
        }
        Ok(self.publication.deadline()?.min(node_end))
    }
    pub async fn wait_stopped(&self, node: &NodeControl) {
        let mut publication = self.publication.changes();
        let mut node_stop = node.stopped();
        loop {
            let Ok(deadline) = self.deadline(node) else {
                return;
            };
            tokio::select! { biased;
                changed=node_stop.changed()=>{if changed.is_err(){return;}},
                changed=publication.changed()=>{if changed.is_err(){return;}},
                _=tokio::time::sleep_until(deadline.into())=>{},
                _=tokio::time::sleep(Duration::from_millis(25))=>{},
            }
        }
    }
}
impl Drop for IngressReservation {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.shared.entries.lock()
            && entries
                .get(&self.key)
                .is_some_and(|entry| entry.token == self.token)
        {
            entries.remove(&self.key);
        }
    }
}

/// Raw TCP ingress owns its actual OS listener. Its public API never detaches a
/// listener or visitor socket from the matching flow/target proof lifecycle.
pub struct ServiceTcpIngress {
    listener: Option<TcpListener>,
    reservation: Option<IngressReservation>,
}
pub struct AcceptedServiceTcp {
    visitor: TcpStream,
    peer: SocketAddr,
    flow: ServiceFlowPermit,
}
pub struct PendingServiceTcp {
    visitor: TcpStream,
    pending: PendingTunnelOpen,
}
pub struct AuthorizedServiceTcp {
    visitor: TcpStream,
    flow: ServiceFlowPermit,
}
impl ServiceTcpIngress {
    pub async fn bind(
        reservation: IngressReservation,
        node: &NodeControl,
        bind_ip: IpAddr,
    ) -> Result<Self, Error> {
        reservation.deadline(node)?;
        let port = match &reservation.key {
            Key::Tcp(port) => *port,
            _ => return Err(Error::Ingress),
        };
        if bind_ip.is_multicast() || matches!(bind_ip, IpAddr::V4(ip) if ip.is_broadcast()) {
            return Err(Error::Ingress);
        }
        let listener = tokio::select! { biased;
            _=reservation.wait_stopped(node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            bound=TcpListener::bind(SocketAddr::new(bind_ip,port))=>bound?,
        };
        reservation.deadline(node)?;
        Ok(Self {
            listener: Some(listener),
            reservation: Some(reservation),
        })
    }
    /// Stops accepts and releases this ingress. Accepted flows retain their
    /// independent permits; publication/node revocation cancels those flows.
    pub fn close(&mut self) {
        self.listener.take();
        self.reservation.take();
    }
    pub async fn accept(&mut self, node: &NodeControl) -> Result<AcceptedServiceTcp, Error> {
        loop {
            let result = {
                let reservation = self.reservation.as_ref().ok_or(Error::Ingress)?;
                let listener = self.listener.as_ref().ok_or(Error::Ingress)?;
                tokio::select! { biased;
                    _=reservation.wait_stopped(node)=>Err(rejected(ErrorCode::PolicyRevoked).into()),
                    accepted=listener.accept()=>accepted.map_err(Error::from),
                }
            };
            let (visitor, peer) = match result {
                Ok(pair) => pair,
                Err(error) => {
                    self.close();
                    return Err(error);
                }
            };
            let reservation = self.reservation.as_ref().ok_or(Error::Ingress)?;
            if let Err(error) = reservation.deadline(node) {
                self.close();
                return Err(error);
            }
            let flow = match reservation.publication.reserve_edge(node, peer.ip()) {
                Ok(flow) => flow,
                Err(error) if visitor_admission_refused(&error) => {
                    // A rejected visitor owns no listener or attachment authority.
                    // Keep the original reservation and check revocation again
                    // before waiting for another connection.
                    drop(visitor);
                    if let Err(error) = reservation.deadline(node) {
                        self.close();
                        return Err(error);
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(error) => {
                    self.close();
                    return Err(error);
                }
            };
            return Ok(AcceptedServiceTcp {
                visitor,
                peer,
                flow,
            });
        }
    }
}
fn visitor_admission_refused(error: &Error) -> bool {
    match error {
        Error::Authorization(error) => matches!(
            error.code,
            ErrorCode::PermissionRequired | ErrorCode::CapacityExceeded
        ),
        Error::Node(crate::control::Error::Authorization(error)) => {
            error.code == ErrorCode::CapacityExceeded
        }
        _ => false,
    }
}
impl AcceptedServiceTcp {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
    pub fn challenge(self, edge: &NodeIdentity) -> Result<PendingServiceTcp, Error> {
        let pending =
            PendingTunnelOpen::new(self.flow, edge, self.peer, ServiceTunnelTransport::Stream)?;
        Ok(PendingServiceTcp {
            visitor: self.visitor,
            pending,
        })
    }
}
impl PendingServiceTcp {
    pub fn lease(&self) -> &VerifiedServiceLease {
        self.pending.lease()
    }
    pub fn challenge(&self) -> &SignedServiceTunnelChallenge {
        self.pending.challenge()
    }
    /// Negotiation adapters must select this alongside their bounded carrier I/O.
    pub async fn wait_stopped(&self) {
        self.pending.wait_stopped().await;
    }
    pub fn accept_proof(
        self,
        host_key: &[u8; 32],
        proof: &ServiceTunnelProof,
    ) -> Result<AuthorizedServiceTcp, Error> {
        let flow = self.pending.accept(host_key, proof)?;
        Ok(AuthorizedServiceTcp {
            visitor: self.visitor,
            flow,
        })
    }
}
impl AuthorizedServiceTcp {
    /// The production adapter supplies a carrier encrypted to the leased edge
    /// identity; this kernel deliberately does not invent a cleartext tunnel.
    pub async fn forward<S>(self, carrier: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        forward_streams(self.visitor, carrier, self.flow).await
    }
}
