use crate::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{network::PeerId, network_datagram as wire};
use nestlink_transport_stream::owner::TaskOwner;
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
    node: bool,
    version: super::DatagramVersion,
    attempted: bool,
    pending: Option<Connection>,
    close_deadline: Option<Instant>,
}
impl AdjacencyEndpoint {
    pub fn bind(
        address: SocketAddr,
        identity: &InstallationIdentity,
        remote: PeerId,
    ) -> Result<Self> {
        Self::bind_version(address, identity, remote, super::DatagramVersion::One)
    }
    /// Explicit NRD2 negotiation; a legacy ALPN cannot carry this chain.
    pub fn bind_chain(
        address: SocketAddr,
        identity: &InstallationIdentity,
        remote: PeerId,
    ) -> Result<Self> {
        Self::bind_version(address, identity, remote, super::DatagramVersion::Two)
    }
    fn bind_version(
        address: SocketAddr,
        identity: &InstallationIdentity,
        remote: PeerId,
        version: super::DatagramVersion,
    ) -> Result<Self> {
        remote.validate()?;
        let local = PeerId(identity.fingerprint());
        if local == remote {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let mut server_tls = tls::server_config(identity, remote.0)?;
        server_tls.alpn_protocols = vec![version.alpn().to_vec()];
        let mut server =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
        server.transport_config(config());
        server.migration(false);
        let (mut endpoint, released) = crate::service::socket::client(address)?;
        endpoint.set_server_config(Some(server));
        let mut client_tls = tls::client_config(identity, remote.0)?;
        client_tls.alpn_protocols = vec![version.alpn().to_vec()];
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        client.transport_config(config());
        endpoint.set_default_client_config(client);
        Ok(Self {
            endpoint: Some(endpoint),
            released: Some(released),
            local,
            remote,
            node: false,
            version,
            attempted: false,
            pending: None,
            close_deadline: None,
        })
    }
    /// A node uses one authenticated admission stream before forwarding. The
    /// node fingerprint must come from a verified TransitGrant, not its URI.
    pub fn bind_node(
        address: SocketAddr,
        identity: &InstallationIdentity,
        remote: PeerId,
    ) -> Result<Self> {
        Self::bind_node_version(address,identity,remote,super::DatagramVersion::One)
    }
    pub fn bind_chain_node(address:SocketAddr,identity:&InstallationIdentity,remote:PeerId) -> Result<Self> {
        Self::bind_node_version(address,identity,remote,super::DatagramVersion::Two)
    }
    fn bind_node_version(address:SocketAddr,identity:&InstallationIdentity,remote:PeerId,version:super::DatagramVersion) -> Result<Self> {
        let mut owner = Self::bind_version(address, identity, remote,version)?;
        let mut client_tls = tls::client_config(identity, remote.0)?;
        client_tls.alpn_protocols = vec![version.alpn().to_vec()];
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        let mut transport = transport_config();
        transport.max_concurrent_bidi_streams(1u8.into());
        client.transport_config(Arc::new(transport));
        let endpoint = owner
            .endpoint
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        endpoint.set_server_config(None);
        endpoint.set_default_client_config(client);
        owner.node = true;
        Ok(owner)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .local_addr()
    }
    pub async fn connect(mut self, address: SocketAddr, deadline: Instant) -> Result<Adjacency> {
        if self.node {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
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
        if self.node {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
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
    /// Keep this owner outside a cancellable future. Failure and cancellation
    /// retain its original physical receipt for close_and_wait; no retry can
    /// create another connection from the same owner.
    pub async fn connect_node(
        &mut self,
        address: SocketAddr,
        identity: &InstallationIdentity,
        device_id: &str,
        allocation_id: &str,
        binding: [u8; 32],
        deadline: Instant,
    ) -> Result<Adjacency> {
        use nestlink_protocol::api::{NetworkNodeChallenge, NetworkNodeHello, NetworkNodeReady};
        if !self.node
            || self.version != super::DatagramVersion::One
            || self.attempted
            || self.close_deadline.is_some()
            || self.local != PeerId(identity.fingerprint())
            || !nestlink_protocol::valid_id(device_id)
            || !nestlink_protocol::valid_id(allocation_id)
            || binding == [0; 32]
            || Instant::now() >= deadline
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        self.attempted = true;
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let connection = tokio::time::timeout_at(
            deadline,
            endpoint.connect(address, "peer.nestlink.invalid")?,
        )
        .await??;
        self.pending = Some(connection.clone());
        let (mut write, mut read) =
            tokio::time::timeout_at(deadline, connection.accept_bi()).await??;
        let challenge: NetworkNodeChallenge =
            tokio::time::timeout_at(deadline, crate::node::read_message(&mut read)).await??;
        let nonce: [u8; 32] = decode_exact(&challenge.nonce)?;
        if challenge.schema_version != 1 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let signature =
            identity.sign_network_node_admission(allocation_id, &binding, device_id, &nonce)?;
        let hello = NetworkNodeHello {
            schema_version: 1,
            allocation_id: allocation_id.into(),
            binding_sha256: URL_SAFE_NO_PAD.encode(binding),
            device_id: device_id.into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            signature: URL_SAFE_NO_PAD.encode(signature),
        };
        tokio::time::timeout_at(deadline, crate::node::write_message(&mut write, &hello)).await??;
        let ready: NetworkNodeReady =
            tokio::time::timeout_at(deadline, crate::node::read_message(&mut read)).await??;
        if ready.schema_version != 1
            || ready.allocation_id != allocation_id
            || decode_exact::<32>(&ready.binding_sha256)? != binding
            || Instant::now() >= deadline
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let mut adjacency = self.finish(connection.clone())?;
        self.pending = None;
        adjacency.control = Some(TaskOwner::new(tokio::spawn(async move {
            let _close = ControlClose(connection.clone());
            let _write = write;
            let mut byte = [0u8; 1];
            // The admission stream stays open. EOF, reset or additional data
            // terminate the route; it is never a business stream.
            let _ = read.read(&mut byte).await;
        })));
        Ok(adjacency)
    }
    /// Complete symmetric NRD2 possession before returning a business carrier.
    /// The node and allocation pin must come from the original verified chain.
    pub async fn connect_chain_node(
        &mut self,address:SocketAddr,identity:&InstallationIdentity,allocation_id:&str,
        binding:[u8;32],deadline:Instant,
    ) -> Result<Adjacency> {
        use nestlink_protocol::api::{NetworkNodeChallenge,NetworkChainNodeHello,NetworkChainNodeProof,NetworkNodeReady};
        if !self.node || self.version != super::DatagramVersion::Two || self.attempted
            || self.close_deadline.is_some() || self.local != PeerId(identity.fingerprint())
            || !nestlink_protocol::valid_id(allocation_id) || binding==[0;32] || Instant::now()>=deadline
        { return Err(io::Error::from(io::ErrorKind::PermissionDenied).into()); }
        self.attempted=true;
        let endpoint=self.endpoint.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let connection=tokio::time::timeout_at(deadline,endpoint.connect(address,"peer.nestlink.invalid")?).await??;
        self.pending=Some(connection.clone());
        let (mut write,mut read)=tokio::time::timeout_at(deadline,connection.accept_bi()).await??;
        let challenge:NetworkNodeChallenge=tokio::time::timeout_at(deadline,crate::node::read_message(&mut read)).await??;
        if challenge.schema_version!=2 { return Err(io::Error::from(io::ErrorKind::PermissionDenied).into()); }
        let nonce=decode_exact::<32>(&challenge.nonce)?;
        let mut returning=[0;32];
        connection.export_keying_material(&mut returning,b"NestLink/NRD2/client-nonce",&binding)
            .map_err(|_|io::Error::from(io::ErrorKind::PermissionDenied))?;
        let signature=identity.sign_network_chain_admission(allocation_id,&binding,self.remote,&nonce)?;
        let hello=NetworkChainNodeHello {
            schema_version:2,allocation_id:allocation_id.into(),binding_sha256:URL_SAFE_NO_PAD.encode(binding),
            public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),signature:URL_SAFE_NO_PAD.encode(signature),
            return_allocation_id:allocation_id.into(),nonce:URL_SAFE_NO_PAD.encode(returning),
        };
        tokio::time::timeout_at(deadline,crate::node::write_message(&mut write,&hello)).await??;
        let proof:NetworkChainNodeProof=tokio::time::timeout_at(deadline,crate::node::read_message(&mut read)).await??;
        let key=decode_exact::<32>(&proof.public_key)?;
        let signature=decode_exact::<64>(&proof.signature)?;
        if proof.schema_version!=2 || proof.allocation_id!=allocation_id
            || decode_exact::<32>(&proof.binding_sha256)?!=binding || PeerId::from_public_key(&key)!=self.remote
        { return Err(io::Error::from(io::ErrorKind::PermissionDenied).into()); }
        nestlink_identity::network::verify_network_chain_admission(allocation_id,&binding,self.local,&key,&returning,&signature)?;
        let ready:NetworkNodeReady=tokio::time::timeout_at(deadline,crate::node::read_message(&mut read)).await??;
        if ready.schema_version!=2 || ready.allocation_id!=allocation_id || decode_exact::<32>(&ready.binding_sha256)?!=binding
        { return Err(io::Error::from(io::ErrorKind::PermissionDenied).into()); }
        tokio::time::timeout_at(deadline,crate::node::write_message(&mut write,&ready)).await??;
        if Instant::now()>=deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }
        let mut adjacency=self.finish(connection.clone())?;
        self.pending=None;
        adjacency.control=Some(TaskOwner::new(tokio::spawn(async move {
            let _close=ControlClose(connection);
            let _write=write;
            let mut byte=[0;1];
            let _=read.read(&mut byte).await;
        })));
        Ok(adjacency)
    }
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        if let Some(connection) = &self.pending {
            connection.close(0u32.into(), b"node setup stopping");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"node setup stopping");
            tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.pending = None;
        self.endpoint = None;
        if let Some(released) = self.released.as_mut() {
            tokio::time::timeout_at(deadline, released)
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(|_| io::Error::other("network node setup UDP release unconfirmed"))?;
            self.released = None;
        }
        Ok(())
    }
    fn finish(&mut self, connection: Connection) -> Result<Adjacency> {
        if connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .is_none_or(|data| data.protocol.as_deref() != Some(self.version.alpn()))
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
            version: self.version,
            close_deadline: None,
            control: None,
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
    version: super::DatagramVersion,
    close_deadline: Option<Instant>,
    control: Option<TaskOwner>,
}
impl Adjacency {
    pub(super) fn version(&self) -> super::DatagramVersion {
        self.version
    }
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
        if let Some(control) = &self.control {
            control.request_close();
        }
    }
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        if let Some(control) = &self.control {
            control.close_and_wait(deadline).await?;
        }
        self.control = None;
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
    Arc::new(transport_config())
}
fn transport_config() -> TransportConfig {
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
    config
}
fn decode_exact<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(io::ErrorKind::InvalidData.into());
    }
    bytes
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
struct ControlClose(Connection);
impl Drop for ControlClose {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"network node control ended");
    }
}
