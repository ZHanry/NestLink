//! Bounded service data-plane kernel. Production listeners must supply an
//! encrypted, mutually authenticated carrier for the tunnel adapter.
mod datagram;
pub(crate) mod gate;
mod ingress;
mod resources;
mod private;
mod stream;
mod target;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

pub use datagram::{DatagramMapping, DatagramPacket, DatagramReply, ReplayWindow as ServiceDatagramReplayWindow};
pub use gate::{
    PublicationContext, ServiceDrainToken, ServiceFlowPermit, ServicePublication,
    ServicePublicationHandle,
};
pub use ingress::{
    AcceptedServiceTcp, AuthorizedServiceTcp, AuthorizedServiceWeb, EdgeDatagramMapping,
    IngressNamespace, IngressOwnership, IngressReservation, PendingServiceDatagram,
    PendingServiceTcp, PendingServiceWebOpen, ServiceTcpIngress, ServiceUdpIngress,
    ServiceWebIngress, ServiceWebVisitor,
};
pub use resources::ServiceResourceSet;
pub use stream::forward_streams;
pub use target::{LocalTargetOwner, PendingTunnelOpen, PreparedLocalTunnel, PreparedPrivateLocalTunnel};
pub use private::PrivateServicePublication;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("service authority failed: {0}")]
    Authorization(#[from] nestlink_protocol::ContractError),
    #[error("service node control failed: {0}")]
    Node(#[from] crate::control::Error),
    #[error("service I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("service operation timed out: {0}")]
    Timeout(&'static str),
    #[error("service target or tunnel metadata does not match the local choice")]
    Target,
    #[error("service ingress is occupied or outside the configured namespace")]
    Ingress,
    #[error("service datagram is oversized, stale, duplicated, or has an invalid peer")]
    Datagram,
    #[error("service total byte budget is exhausted")]
    Quota,
}
