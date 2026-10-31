//! Opaque network transport. Route permission is distinct from business
//! stream proof: callers must still run the existing SessionPermit handshake.
//! No migration, raw IP injection, automatic fallback or route discovery occurs.
mod adjacency;
mod authorization;
mod forwarding;
mod listener;
mod socket;
pub use adjacency::{Adjacency, AdjacencyEndpoint};
pub use authorization::{RouteAuthorization, RouteRevocation};
pub use forwarding::{FragmentReplayWindow, RelayForwarder};
pub use listener::{
    NetworkNodeListener, authenticated_peer_fingerprint, chain_node_client_config, node_listener,
    node_listener_with_legacy, topology_node_client_config,
};

use crate::*;
use nestlink_protocol::{network::{PeerId, Purpose}, network_datagram as wire};
use nestlink_transport_stream::owner::TaskOwner;
use std::io;
use tokio::time::Instant;

/// Authenticated advisory that this original carrier has retired. It grants
/// no new allocation, route or business permission; recovery is independent.
pub const RETIRED_CLOSE_CODE: u32 = 0x4e02;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DatagramVersion {
    One,
    Two,
}
impl DatagramVersion {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::One => wire::ALPN,
            Self::Two => nestlink_protocol::network_datagram_v2::ALPN,
        }
    }
}

/// An endpoint-pinned inner QUIC connection over an authenticated relay chain.
/// Exposing the mature connection does not grant business channel permission.
pub struct RoutedTransport {
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
    released: Option<tokio::sync::oneshot::Receiver<()>>,
    adjacency: Adjacency,
    receiver: TaskOwner,
    failure: tokio::sync::watch::Receiver<Option<io::ErrorKind>>,
    close_deadline: Option<Instant>,
}
impl RoutedTransport {
    /// Original carrier facts are published before inner Quinn I/O closes.
    pub fn subscribe_failure(&self) -> tokio::sync::watch::Receiver<Option<io::ErrorKind>> {
        self.failure.clone()
    }
    pub fn connection(&self) -> io::Result<&Connection> {
        self.connection
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    pub fn request_close(&self) {
        self.request_close_with_code(0);
    }
    /// End the original carrier without labeling its own cleanup a revocation.
    /// A true grant revocation still takes precedence in the local observer.
    pub fn request_close_for_recovery(&self) {
        self.request_close_with_code(RETIRED_CLOSE_CODE);
    }
    fn request_close_with_code(&self, code: u32) {
        let already_closed = self.connection.as_ref().is_some_and(|connection| connection.close_reason().is_some());
        if let Some(connection) = &self.connection
            && connection.close_reason().is_none()
        {
            connection.close(0u32.into(), b"routed transport stopping");
        }
        if !already_closed && let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"routed transport stopping");
        }
        self.receiver.request_close();
        self.adjacency.request_close_with_code(code);
    }
    /// Cancellation retains all original task/socket receipts and the first
    /// absolute close budget. External Quinn clones can keep release pending.
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        self.receiver.close_and_wait(deadline).await?;
        // A failed abstract receive can stop Quinn's endpoint driver before it
        // notifies wait_idle. Release our handles, then observe the real socket
        // and every writable poller dropping instead of waiting on that signal.
        self.connection = None;
        self.endpoint = None;
        wait_socket_released(&mut self.released, deadline).await?;
        self.adjacency.close_and_wait(deadline).await
    }
}
impl Drop for RoutedTransport {
    fn drop(&mut self) {
        self.request_close();
    }
}

/// Consume the original physical owner. The local identity, the TLS relay
/// identity and the peer pair must all agree with the verified route binding.
pub async fn establish(
    authorization: RouteAuthorization,
    adjacency: Adjacency,
    identity: &InstallationIdentity,
    deadline: Instant,
) -> Result<RoutedTransport> {
    let mut pending = RoutedEstablishment::new(authorization, adjacency);
    if let Err(error) = pending.establish(identity, deadline).await {
        pending.close_and_wait(deadline).await?;
        return Err(error);
    }
    Ok(pending.take_transport()?)
}

/// Keep this owner outside a cancellable establishment future. Dropping only
/// the borrowed future preserves the original physical and task receipts for
/// close_and_wait. One owner permits one establishment attempt.
pub struct RoutedEstablishment {
    authorization: Option<RouteAuthorization>,
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
    released: Option<tokio::sync::oneshot::Receiver<()>>,
    adjacency: Option<Adjacency>,
    receiver: Option<TaskOwner>,
    failure: Option<tokio::sync::watch::Receiver<Option<io::ErrorKind>>>,
    attempted: bool,
    close_deadline: Option<Instant>,
}
impl RoutedEstablishment {
    pub fn new(authorization: RouteAuthorization, adjacency: Adjacency) -> Self {
        Self {
            authorization: Some(authorization),
            connection: None,
            endpoint: None,
            released: None,
            adjacency: Some(adjacency),
            receiver: None,
            failure: None,
            attempted: false,
            close_deadline: None,
        }
    }
    pub async fn establish(
        &mut self,
        identity: &InstallationIdentity,
        deadline: Instant,
    ) -> Result<()> {
        if self.attempted || self.close_deadline.is_some() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
        }
        self.attempted = true;
        let authorization = self.authorization.take().ok_or_else(not_connected)?;
        authorization.live()?;
        // The independently verified business purpose selects protocol
        // isolation. A caller cannot relabel a service grant as remote control
        // or supply an arbitrary ALPN for an authenticated route.
        let inner_alpn = match authorization.purpose() {
            Purpose::RemoteControl => nestlink_protocol::ALPN.as_bytes(),
            Purpose::PrivateService => nestlink_protocol::service_plane::publication::SERVICE_ALPN,
            _ => return Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
        };
        let deadline = deadline.min(authorization.deadline());
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }
        let local = PeerId(identity.fingerprint());
        let peers = authorization.peers();
        let adjacency = self.adjacency.as_ref().ok_or_else(not_connected)?;
        if adjacency.local() != local
            || Some(adjacency.remote()) != authorization.endpoint_relay(local)
            || adjacency.version() != authorization.version()
            || !peers.contains(local)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let peer = if local == peers.first {
            peers.second
        } else {
            peers.first
        };
        let first = local == peers.first;
        let mut config = transport_value();
        config.initial_mtu(wire::PACKET_BYTES as u16);
        config.min_mtu(wire::PACKET_BYTES as u16);
        config.mtu_discovery_config(None);
        let config = Arc::new(config);
        let mut server_tls = tls::server_config(identity, peer.0)?;
        server_tls.alpn_protocols = vec![inner_alpn.to_vec()];
        let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
        server.transport_config(config.clone());
        server.migration(false);
        let mut client_tls = tls::client_config(identity, peer.0)?;
        client_tls.alpn_protocols = vec![inner_alpn.to_vec()];
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        client.transport_config(config);
        let mut settings = quinn::EndpointConfig::default();
        settings.max_udp_payload_size(wire::PACKET_BYTES as u16)?;
        let (socket, receiver) =
            socket::RoutedSocket::new(authorization, adjacency.connection()?.clone(), first)?;
        self.receiver = Some(receiver);
        self.failure = Some(socket.subscribe_failure());
        let destination = socket.peer_addr();
        // Reuse the physical carrier's existing tracking adapter. Quinn keeps
        // this owner in both Endpoint and Connection state; each writable
        // poller retains it too. External clones therefore keep release pending.
        let (socket, released) = crate::service::socket::tracked(socket);
        self.released = Some(released);
        let mut endpoint = Endpoint::new_with_abstract_socket(
            settings,
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client);
        self.endpoint = Some(endpoint);
        let endpoint = self.endpoint.as_ref().ok_or_else(not_connected)?;
        let connect = async {
            if first {
                endpoint
                    .connect(destination, "peer.nestlink.invalid")
                    .map_err(io::Error::other)?
                    .await
                    .map_err(io::Error::other)
            } else {
                endpoint
                    .accept()
                    .await
                    .ok_or_else(not_connected)?
                    .await
                    .map_err(io::Error::other)
            }
        };
        self.connection = Some(
            tokio::time::timeout_at(deadline, connect)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
        );
        let connection = self.connection.as_ref().ok_or_else(not_connected)?;
        let negotiated = connection.handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .is_some_and(|data| data.protocol.as_deref() == Some(inner_alpn));
        if !negotiated {
            connection.close(1u32.into(), b"routed business ALPN mismatch");
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        Ok(())
    }
    pub fn take_transport(&mut self) -> io::Result<RoutedTransport> {
        if self.close_deadline.is_some()
            || self.connection.is_none()
            || self.endpoint.is_none()
            || self.released.is_none()
            || self.adjacency.is_none()
            || self.receiver.is_none()
            || self.failure.is_none()
        {
            return Err(not_connected());
        }
        Ok(RoutedTransport {
            connection: self.connection.take(),
            endpoint: self.endpoint.take(),
            released: self.released.take(),
            adjacency: self.adjacency.take().ok_or_else(not_connected)?,
            receiver: self.receiver.take().ok_or_else(not_connected)?,
            failure: self.failure.take().ok_or_else(not_connected)?,
            close_deadline: None,
        })
    }
    pub fn request_close(&self) {
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"routed setup ended");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"routed setup ended");
        }
        if let Some(adjacency) = &self.adjacency {
            adjacency.request_close();
        }
        if let Some(receiver) = &self.receiver {
            receiver.request_close();
        }
    }
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(receiver) = &mut self.receiver {
            receiver.close_and_wait(deadline).await?;
        }
        self.connection = None;
        self.endpoint = None;
        wait_socket_released(&mut self.released, deadline).await?;
        if let Some(adjacency) = &mut self.adjacency {
            adjacency.close_and_wait(deadline).await?;
        }
        Ok(())
    }
}
impl Drop for RoutedEstablishment {
    fn drop(&mut self) {
        self.request_close();
    }
}
fn not_connected() -> io::Error {
    io::ErrorKind::NotConnected.into()
}

/// Keep the original completion receiver in the owner across cancellation or
/// timeout. Completion requires the original socket and its pollers to drop;
/// connection close and endpoint idle are insufficient release receipts.
async fn wait_socket_released(
    released: &mut Option<tokio::sync::oneshot::Receiver<()>>,
    deadline: Instant,
) -> io::Result<()> {
    if let Some(completion) = released.as_mut() {
        tokio::time::timeout_at(deadline, completion)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "routed inner socket or writable poller release pending",
                )
            })?
            .map_err(|_| io::Error::other("routed inner socket release was not confirmed"))?;
        *released = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod migration_experiment;
