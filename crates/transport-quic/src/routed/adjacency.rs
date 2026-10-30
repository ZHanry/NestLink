use crate::*;
use nestlink_protocol::{network::PeerId, network_datagram as wire};
use std::io;
use tokio::{sync::oneshot, time::Instant};

/// A unique physical endpoint with one configured mutual-TLS neighbor and a
/// separate ALPN. Accepting/dialing consumes it, so it cannot mint a second
/// receiver or transfer the same physical release receipt twice.
pub struct AdjacencyEndpoint {
    endpoint: Option<Endpoint>,
    released: Option<oneshot::Receiver<()>>,
    local: PeerId,
    remote: PeerId,
}
impl AdjacencyEndpoint {
    pub fn bind(
        address: SocketAddr,
        identity: &InstallationIdentity,
        remote: PeerId,
    ) -> Result<Self> {
        remote.validate()?;
        let local = PeerId(identity.fingerprint());
        if local == remote {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let mut server_tls = tls::server_config(identity, remote.0)?;
        server_tls.alpn_protocols = vec![wire::ALPN.to_vec()];
        let mut server =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
        server.transport_config(config());
        server.migration(false);
        let (mut endpoint, released) = crate::service::socket::client(address)?;
        endpoint.set_server_config(Some(server));
        let mut client_tls = tls::client_config(identity, remote.0)?;
        client_tls.alpn_protocols = vec![wire::ALPN.to_vec()];
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        client.transport_config(config());
        endpoint.set_default_client_config(client);
        Ok(Self {
            endpoint: Some(endpoint),
            released: Some(released),
            local,
            remote,
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .local_addr()
    }
    pub async fn connect(mut self, address: SocketAddr, deadline: Instant) -> Result<Adjacency> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let connection = tokio::time::timeout_at(
            deadline,
            endpoint.connect(address, "peer.nestlink.invalid")?,
        )
        .await??;
        self.finish(connection)
    }
    pub async fn accept(mut self, deadline: Instant) -> Result<Adjacency> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let incoming = tokio::time::timeout_at(deadline, endpoint.accept())
            .await?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let connection = tokio::time::timeout_at(deadline, incoming).await??;
        self.finish(connection)
    }
    fn finish(&mut self, connection: Connection) -> Result<Adjacency> {
        if connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .is_none_or(|data| data.protocol.as_deref() != Some(wire::ALPN))
        {
            connection.close(1u32.into(), b"network datagram ALPN mismatch");
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        Ok(Adjacency {
            endpoint: self.endpoint.take(),
            released: self.released.take(),
            connection: Some(connection),
            local: self.local,
            remote: self.remote,
            close_deadline: None,
        })
    }
}
impl Drop for AdjacencyEndpoint {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"network adjacency setup ended");
        }
    }
}
pub struct Adjacency {
    endpoint: Option<Endpoint>,
    released: Option<oneshot::Receiver<()>>,
    connection: Option<Connection>,
    local: PeerId,
    remote: PeerId,
    close_deadline: Option<Instant>,
}
impl Adjacency {
    pub fn local(&self) -> PeerId {
        self.local
    }
    pub fn remote(&self) -> PeerId {
        self.remote
    }
    pub(crate) fn connection(&self) -> io::Result<&Connection> {
        self.connection
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    pub fn request_close(&self) {
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"network adjacency stopping");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"network adjacency stopping");
        }
    }
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.connection = None;
        self.endpoint = None;
        if let Some(released) = self.released.as_mut() {
            tokio::time::timeout_at(deadline, released)
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(|_| io::Error::other("network adjacency UDP release unconfirmed"))?;
            self.released = None;
        }
        Ok(())
    }
}
impl Drop for Adjacency {
    fn drop(&mut self) {
        self.request_close();
    }
}
fn config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(0u8.into());
    config.max_concurrent_uni_streams(0u8.into());
    config.initial_mtu(1200);
    config.min_mtu(1200);
    config.mtu_discovery_config(None);
    config.datagram_receive_buffer_size(Some(
        wire::PENDING_PACKETS * (wire::HEADER + wire::FRAGMENT_BYTES),
    ));
    config.datagram_send_buffer_size(wire::PENDING_PACKETS * (wire::HEADER + wire::FRAGMENT_BYTES));
    config.max_idle_timeout(Some(quinn::VarInt::from_u32(10_000).into()));
    config.keep_alive_interval(Some(Duration::from_secs(2)));
    Arc::new(config)
}
