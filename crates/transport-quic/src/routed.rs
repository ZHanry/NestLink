//! One-hop opaque network transport. Route permission is distinct from business
//! stream proof: callers must still run the existing SessionPermit handshake.
//! No migration, raw IP injection, automatic fallback or route discovery occurs.
mod adjacency;
mod authorization;
mod socket;
mod forwarding;
pub use adjacency::{Adjacency, AdjacencyEndpoint};
pub use authorization::{RouteAuthorization, RouteRevocation};
pub use forwarding::RelayForwarder;

use crate::*;
use nestlink_protocol::{network::PeerId, network_datagram as wire};
use nestlink_transport_stream::owner::TaskOwner;
use std::io;
use tokio::time::Instant;

/// An endpoint-pinned inner QUIC connection over a single authenticated relay.
/// Exposing the mature connection does not grant business channel permission.
pub struct RoutedTransport {
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
    adjacency: Adjacency,
    receiver: TaskOwner,
    close_deadline: Option<Instant>,
}
impl RoutedTransport {
    pub fn connection(&self) -> io::Result<&Connection> { self.connection.as_ref().ok_or_else(|| io::ErrorKind::NotConnected.into()) }
    pub fn request_close(&self) {
        if let Some(connection) = &self.connection { connection.close(0u32.into(), b"routed transport stopping"); }
        if let Some(endpoint) = &self.endpoint { endpoint.close(0u32.into(), b"routed transport stopping"); }
        self.receiver.request_close();
        self.adjacency.request_close();
    }
    /// Cancellation retains all original task/socket receipts and the first
    /// absolute close budget. External Quinn clones can keep release pending.
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        self.receiver.close_and_wait(deadline).await?;
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle()).await.map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.connection = None;
        self.endpoint = None;
        self.adjacency.close_and_wait(deadline).await
    }
}
impl Drop for RoutedTransport {
    fn drop(&mut self) { self.request_close(); }
}

/// Consume the original physical owner. The local identity, the TLS relay
/// identity and the peer pair must all agree with the verified route binding.
pub async fn establish(
    authorization: RouteAuthorization,
    adjacency: Adjacency,
    identity: &InstallationIdentity,
    deadline: Instant,
) -> Result<RoutedTransport> {
    authorization.live()?;
    let local = PeerId(identity.fingerprint());
    let peers = authorization.peers();
    if adjacency.local() != local || adjacency.remote() != authorization.relay() || !peers.contains(local) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    }
    let peer = if local == peers.first { peers.second } else { peers.first };
    let first = local == peers.first;
    let (socket, receiver) = socket::RoutedSocket::new(authorization, adjacency.connection()?.clone(), first)?;
    let destination = socket.peer_addr();
    let mut config = transport_value();
    config.initial_mtu(wire::PACKET_BYTES as u16);
    config.min_mtu(wire::PACKET_BYTES as u16);
    config.mtu_discovery_config(None);
    let config = Arc::new(config);
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls::server_config(identity, peer.0)?)?));
    server.transport_config(config.clone());
    server.migration(false);
    let mut settings = quinn::EndpointConfig::default();
    settings.max_udp_payload_size(wire::PACKET_BYTES as u16)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(settings, Some(server), socket, Arc::new(quinn::TokioRuntime))?;
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls::client_config(identity, peer.0)?)?));
    client.transport_config(config);
    endpoint.set_default_client_config(client);
    // Retain owners before the first await: cancelling establishment closes the
    // original outer socket and aborts the one virtual receive task.
    let mut pending = Pending { endpoint: Some(endpoint), adjacency: Some(adjacency), receiver: Some(receiver) };
    let endpoint = pending.endpoint.as_ref().ok_or(io::ErrorKind::NotConnected)?;
    let connect = async {
        if first { endpoint.connect(destination, "peer.nestlink.invalid").map_err(io::Error::other)?.await.map_err(io::Error::other) }
        else { endpoint.accept().await.ok_or(io::ErrorKind::NotConnected)?.await.map_err(io::Error::other) }
    };
    let connection = tokio::time::timeout_at(deadline, connect).await.map_err(|_| io::ErrorKind::TimedOut)??;
    Ok(RoutedTransport { connection: Some(connection), endpoint: pending.endpoint.take(),
        adjacency: pending.adjacency.take().ok_or(io::ErrorKind::NotConnected)?,
        receiver: pending.receiver.take().ok_or(io::ErrorKind::NotConnected)?, close_deadline: None })
}
struct Pending {
    endpoint: Option<Endpoint>,
    adjacency: Option<Adjacency>,
    receiver: Option<TaskOwner>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint { endpoint.close(0u32.into(), b"routed setup ended"); }
        if let Some(adjacency) = &self.adjacency { adjacency.request_close(); }
        if let Some(receiver) = &self.receiver { receiver.request_close(); }
    }
}

#[cfg(test)]
mod tests;
