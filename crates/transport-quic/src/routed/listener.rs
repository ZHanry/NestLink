//! One node UDP owner; accepted connections borrow its physical socket.
use crate::*;
use nestlink_identity::nodes::NodeIdentity;
use nestlink_transport_stream::tls::CurrentClientPins;
use std::io;
use tokio::{sync::oneshot, time::Instant};

pub struct NetworkNodeListener {
    endpoint: Option<Endpoint>,
    released: Option<oneshot::Receiver<()>>,
    close_deadline: Option<Instant>,
}
pub fn authenticated_peer_fingerprint(connection: &Connection) -> io::Result<[u8; 32]> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    tls::peer_identity_fingerprint(identity.as_ref()).map_err(io::Error::other)
}
/// Dial from the existing node listener socket, with its registered identity
/// and exactly the original chain neighbor pin. No additional UDP owner.
pub fn chain_node_client_config(identity: &NodeIdentity, remote: [u8; 32]) -> Result<ClientConfig> {
    let crypto = tls::network_node_client_config(identity, remote)?;
    node_client_config(crypto)
}
/// Reuse the registered node socket and TLS pin for a bounded topology probe.
pub fn topology_node_client_config(identity: &NodeIdentity, remote: [u8; 32]) -> Result<ClientConfig> {
    let crypto = tls::topology_node_client_config(identity, remote)?;
    node_client_config(crypto)
}
fn node_client_config(crypto: rustls::ClientConfig) -> Result<ClientConfig> {
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    let mut transport = transport_value();
    transport.max_concurrent_bidi_streams(1u8.into());
    transport.max_concurrent_uni_streams(0u8.into());
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    transport.mtu_discovery_config(None);
    client.transport_config(Arc::new(transport));
    Ok(client)
}
pub fn node_listener(
    address: SocketAddr,
    identity: &NodeIdentity,
    pins: Arc<dyn CurrentClientPins>,
) -> Result<NetworkNodeListener> {
    bind(address, identity, pins, false)
}

/// Existing native clients already supply their installation certificate. Both
/// protocols share the operator-configured endpoint but retain distinct ALPNs.
pub fn node_listener_with_legacy(
    address: SocketAddr,
    identity: &NodeIdentity,
    pins: Arc<dyn CurrentClientPins>,
) -> Result<NetworkNodeListener> {
    bind(address, identity, pins, true)
}

fn bind(
    address: SocketAddr,
    identity: &NodeIdentity,
    pins: Arc<dyn CurrentClientPins>,
    legacy: bool,
) -> Result<NetworkNodeListener> {
    let mut crypto = tls::network_node_server_config(identity, pins)?;
    if legacy {
        crypto
            .alpn_protocols
            .push(nestlink_protocol::relay_datagram::ALPN.to_vec());
    }
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let mut transport = transport_value();
    transport.max_concurrent_bidi_streams(1u8.into());
    transport.max_concurrent_uni_streams(0u8.into());
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    transport.mtu_discovery_config(None);
    server.transport_config(Arc::new(transport));
    server.migration(false);
    let (endpoint, released) = crate::service::socket::client(address)?;
    endpoint.set_server_config(Some(server));
    Ok(NetworkNodeListener {
        endpoint: Some(endpoint),
        released: Some(released),
        close_deadline: None,
    })
}
impl NetworkNodeListener {
    pub fn endpoint(&self) -> io::Result<&Endpoint> {
        self.endpoint
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint()?.local_addr()
    }
    pub fn request_close(&self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"network node listener stopping");
        }
    }
    /// Call only after accepted tasks have dropped their original connections
    /// and endpoint clones. A canceled/expired wait retains the original receipt.
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?;
        }
        drop(self.endpoint.take());
        if let Some(released) = self.released.as_mut() {
            tokio::time::timeout_at(deadline, released)
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(|_| io::Error::other("network node UDP release was not confirmed"))?;
            self.released = None;
        }
        Ok(())
    }
}
impl Drop for NetworkNodeListener {
    fn drop(&mut self) {
        self.request_close();
    }
}
