//! Control-allocation-pinned outer QUIC plus endpoint-pinned inner QUIC.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    VerifiedPermit, digest,
    nodes::NodeIdentity,
    relay::{VerifiedRelayAllocation, node_relay_transcript},
};
use nestlink_protocol::{
    RELAY_UDP_FRAGMENT_BYTES, RELAY_UDP_PACKET_BYTES, RELAY_UDP_PENDING_PACKETS, RelayTransport,
    api::{NodeRelayChallenge, NodeRelayHello, RelayReady},
    relay_datagram,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MESSAGE: usize = 16384;
fn outer_transport() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(1u8.into());
    config.max_concurrent_uni_streams(0u8.into());
    config.stream_receive_window((MESSAGE as u32).into());
    config.receive_window((2 * MESSAGE as u32).into());
    config.send_window((2 * MESSAGE) as u64);
    config.datagram_receive_buffer_size(Some(
        RELAY_UDP_PENDING_PACKETS as usize
            * (relay_datagram::HEADER + RELAY_UDP_FRAGMENT_BYTES as usize),
    ));
    config.datagram_send_buffer_size(
        RELAY_UDP_PENDING_PACKETS as usize
            * (relay_datagram::HEADER + RELAY_UDP_FRAGMENT_BYTES as usize),
    );
    config.keep_alive_interval(Some(Duration::from_secs(2)));
    config.max_idle_timeout(Some(quinn::VarInt::from_u32(10000).into()));
    Arc::new(config)
}
/// TLS authenticates the node's registered installation key; endpoint authority
/// follows on the fresh challenge stream and never relies on a management token.
pub fn listener(address: SocketAddr, identity: &NodeIdentity) -> Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls::node_server_config(identity)?)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(outer_transport());
    config.migration(false);
    Ok(Endpoint::server(config, address)?)
}
pub async fn write_message(
    write: &mut quinn::SendStream,
    value: &impl Serialize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MESSAGE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    write
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(io::Error::other)?;
    write.write_all(&bytes).await.map_err(io::Error::other)?;
    write.flush().await
}
pub async fn read_message<T: DeserializeOwned>(read: &mut quinn::RecvStream) -> io::Result<T> {
    let n = read.read_u32().await? as usize;
    if n == 0 || n > MESSAGE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0u8; n];
    read.read_exact(&mut bytes)
        .await
        .map_err(io::Error::other)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
pub struct Connected {
    pub connection: Connection,
    pub endpoint: Endpoint,
    pub carrier: Carrier,
}
/// An explicit owner bounds the lifetime of the close watcher, including when
/// an established candidate is discarded or its business runtime is canceled.
pub struct Carrier {
    inner: Option<Connection>,
    outer: Option<Connection>,
    endpoint: Option<Endpoint>,
    watcher: nestlink_transport_stream::owner::TaskOwner,
    receiver: nestlink_transport_stream::owner::TaskOwner,
    released: Option<tokio::sync::oneshot::Receiver<()>>,
    failure: tokio::sync::watch::Sender<Option<io::ErrorKind>>,
}
impl Carrier {
    fn new(
        inner: &Connection,
        outer: Connection,
        endpoint: Endpoint,
        receiver: nestlink_transport_stream::owner::TaskOwner,
        released: tokio::sync::oneshot::Receiver<()>,
        mut socket_failure: tokio::sync::watch::Receiver<Option<io::ErrorKind>>,
    ) -> Self {
        let watch_inner = inner.clone();
        let watch_outer = outer.clone();
        let (failure, _) = tokio::sync::watch::channel(None);
        let failed = failure.clone();
        let watcher = tokio::spawn(async move {
            tokio::select! {
                _ = watch_inner.closed() => { watch_outer.close(0u32.into(), b"inner QUIC ended"); },
                error = watch_outer.closed() => {
                    let kind = socket_failure.borrow().unwrap_or_else(|| crate::virtual_udp::connection_fault(error));
                    failed.send_replace(Some(kind));
                    watch_inner.close(0u32.into(), b"outer QUIC ended");
                },
                _ = socket_failure.changed() => {
                    let kind = socket_failure.borrow().unwrap_or(io::ErrorKind::Other);
                    failed.send_replace(Some(kind));
                    watch_inner.close(0u32.into(), b"outer QUIC failed");
                    watch_outer.close(0u32.into(), b"outer QUIC failed");
                },
            }
        });
        Self {
            inner: Some(inner.clone()),
            outer: Some(outer),
            endpoint: Some(endpoint),
            watcher: nestlink_transport_stream::owner::TaskOwner::new(watcher),
            receiver,
            released: Some(released),
            failure,
        }
    }
    pub fn subscribe_failure(&self) -> tokio::sync::watch::Receiver<Option<io::ErrorKind>> {
        self.failure.subscribe()
    }
    pub fn request_close(&self) {
        if let Some(inner) = &self.inner { inner.close(0u32.into(), b"QUIC carrier stopping"); }
        if let Some(outer) = &self.outer { outer.close(0u32.into(), b"QUIC carrier stopping"); }
        if let Some(endpoint) = &self.endpoint { endpoint.close(0u32.into(), b"QUIC carrier stopping"); }
        self.watcher.request_close();
        self.receiver.request_close();
    }
    /// Wait for the real watcher/receiver and physical outer UDP socket. The
    /// caller must release its inner connection/endpoint clones first.
    pub async fn close_and_wait(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        self.request_close();
        self.watcher.close_and_wait(deadline).await?;
        self.receiver.close_and_wait(deadline).await?;
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle()).await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        }
        drop(self.inner.take());
        drop(self.outer.take());
        drop(self.endpoint.take());
        if let Some(released) = self.released.as_mut() {
            tokio::time::timeout_at(deadline, released).await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                .map_err(|_| io::Error::other("relay UDP release was not confirmed"))?;
            self.released = None;
        }
        Ok(())
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.request_close();
    }
}
struct Cleanup {
    outer: Option<Connection>,
    inner: Option<Endpoint>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.inner {
            endpoint.close(1u32.into(), b"relay setup cancelled");
        }
        if let Some(connection) = &self.outer {
            connection.close(1u32.into(), b"relay setup cancelled");
        }
    }
}
/// Creates a single allocation-bound virtual UDP path. The host accepts inner
/// QUIC; the controller dials it. Neither opens a direct peer socket.
pub async fn connect_at(
    address: SocketAddr,
    installation: (&str, &InstallationIdentity),
    permit: &VerifiedPermit,
    allocation: &VerifiedRelayAllocation,
) -> Result<Connected> {
    let c = allocation.claims();
    let (device, identity) = installation;
    let (controller, local, peer) = if device == c.controller_device_id {
        (true, &c.controller_key_sha256, &c.host_key_sha256)
    } else if device == c.host_device_id {
        (false, &c.host_key_sha256, &c.controller_key_sha256)
    } else {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    };
    if !allocation.matches(permit.claims())?
        || *local != digest(&identity.public_key())
        || !c
            .transports
            .contains(&(RelayTransport::QuicDatagram as i32))
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    }
    let node: [u8; 32] = c.node_key_sha256.as_slice().try_into()?;
    let peer: [u8; 32] = peer.as_slice().try_into()?;
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let remaining = c
        .expires_at_unix_ms
        .checked_sub(now)
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    if c.issued_at_unix_ms > now.saturating_add(1000) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    }
    let exchange = async {
        let bound = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let (mut outer, released) = crate::service::socket::client(bound)?;
        let mut tls = tls::client_config(identity, node)?;
        tls.alpn_protocols = vec![relay_datagram::ALPN.to_vec()];
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        client.transport_config(outer_transport());
        outer.set_default_client_config(client);
        let connection = outer.connect(address, "peer.nestlink.invalid")?.await?;
        let mut cleanup = Cleanup {
            outer: Some(connection.clone()),
            inner: None,
        };
        let (mut write, mut read) = connection.accept_bi().await?;
        let challenge: NodeRelayChallenge = read_message(&mut read).await?;
        let nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(challenge.nonce)?
            .try_into()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let proof = node_relay_transcript(c, device, RelayTransport::QuicDatagram, &nonce)?;
        write_message(
            &mut write,
            &NodeRelayHello {
                device_id: device.into(),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                allocation: URL_SAFE_NO_PAD.encode(allocation.signed_bytes()),
                signature: URL_SAFE_NO_PAD.encode(identity.sign_action(&proof)?),
            },
        )
        .await?;
        let ready: RelayReady = read_message(&mut read).await?;
        if !ready.ready {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let carrier_connection = connection.clone();
        let socket =
            crate::virtual_udp::RelaySocket::new(connection, outer, controller, read, write)?;
        let destination = socket.peer_addr();
        let socket_failure = socket.subscribe_failure();
        let receiver = socket.close_owner();
        let mut config = transport_value();
        config.initial_mtu(RELAY_UDP_PACKET_BYTES as u16);
        config.min_mtu(RELAY_UDP_PACKET_BYTES as u16);
        config.mtu_discovery_config(None);
        let config = Arc::new(config);
        let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(
            tls::server_config(identity, peer)?,
        )?));
        server.transport_config(config.clone());
        server.migration(false);
        let mut settings = quinn::EndpointConfig::default();
        settings.max_udp_payload_size(RELAY_UDP_PACKET_BYTES as u16)?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            settings,
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        cleanup.inner = Some(endpoint.clone());
        let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            tls::client_config(identity, peer)?,
        )?));
        client.transport_config(config);
        endpoint.set_default_client_config(client);
        let connection = if controller {
            endpoint
                .connect(destination, "peer.nestlink.invalid")?
                .await?
        } else {
            endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
                .await?
        };
        cleanup.inner = None;
        cleanup.outer = None;
        let carrier = Carrier::new(&connection, carrier_connection, endpoint.clone(), receiver, released, socket_failure);
        Ok(Connected {
            connection,
            endpoint,
            carrier,
        })
    };
    tokio::time::timeout(Duration::from_millis(remaining.min(10000)), exchange)
        .await
        .map_err(io::Error::other)?
}
