//! Pinned, service-only QUIC carrier. Authentication above TLS uses attachment
//! and visitor proofs, independently of remote desktop and relay allocation.
use super::*;
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::service_plane::{
    SERVICE_MESSAGE_BYTES,
    publication::{SERVICE_ALPN, SERVICE_MAX_OPENINGS},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
pub mod datagram;
pub(crate) mod socket;

// Signed JSON byte envelopes expand when nested in an offer. The framing limit
// applies to the entire envelope, independently of the 32 KiB signed payload.
pub const CARRIER_MESSAGE_BYTES: usize = SERVICE_MESSAGE_BYTES * 6;
fn transport() -> Arc<TransportConfig> {
    let mut value = TransportConfig::default();
    value.max_concurrent_bidi_streams(((SERVICE_MAX_OPENINGS + 1) as u32).into());
    value.max_concurrent_uni_streams(0u8.into());
    value.stream_receive_window((256 * 1024u32).into());
    value.receive_window((8 * 1024 * 1024u32).into());
    value.send_window(4 * 1024 * 1024);
    value.initial_mtu(1280);
    value.min_mtu(1280);
    value.datagram_receive_buffer_size(Some(
        128 * nestlink_protocol::service_plane::SERVICE_DATAGRAM_BYTES,
    ));
    value.datagram_send_buffer_size(64 * nestlink_protocol::service_plane::SERVICE_DATAGRAM_BYTES);
    value.keep_alive_interval(Some(Duration::from_secs(2)));
    value.max_idle_timeout(Some(quinn::VarInt::from_u32(10000).into()));
    Arc::new(value)
}
pub fn listener(address: SocketAddr, identity: &NodeIdentity) -> Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls::service_node_server_config(identity)?)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport());
    config.migration(false);
    Ok(Endpoint::server(config, address)?)
}
pub struct Connected {
    pub connection: Connection,
    pub endpoint: Endpoint,
    socket_closed: Option<tokio::sync::oneshot::Receiver<()>>,
}
/// A single-use receipt for the actual UDP socket and all of its pollers.
/// Closing a connection or observing an idle endpoint cannot create this proof.
pub struct SocketRelease {
    completion: tokio::sync::oneshot::Receiver<()>,
}
impl SocketRelease {
    pub async fn wait(self) -> io::Result<()> {
        socket::wait_released(self.completion).await
    }
}
/// One installation listener with the same physical socket receipt as service
/// clients. The coordinator drops every connection/task clone before closing.
pub struct PrivateListener {
    pub endpoint: Endpoint,
    socket_closed: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl PrivateListener {
    pub fn bind(address: SocketAddr, identity: &InstallationIdentity) -> Result<Self> {
        let crypto = QuicServerConfig::try_from(tls::private_service_server_config(identity)?)?;
        let mut config = ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        config.migration(false);
        let (endpoint, completion) = socket::client(address)?;
        endpoint.set_server_config(Some(config));
        Ok(Self {
            endpoint,
            socket_closed: Some(completion),
        })
    }
    pub async fn close_and_wait(mut self) -> io::Result<()> {
        self.endpoint
            .close(0u32.into(), b"private service listener stopping");
        self.endpoint.wait_idle().await;
        let completion = self
            .socket_closed
            .take()
            .ok_or_else(|| io::Error::other("private service release owner missing"))?;
        drop(self);
        socket::wait_released(completion).await
    }
}
impl Drop for PrivateListener {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"private service listener owner dropped");
    }
}
impl Connected {
    /// Transfer the original physical release receipt to a longer lived cleanup
    /// owner. After transfer that owner must close/drop every endpoint and
    /// connection clone before awaiting the receipt.
    pub fn take_socket_release(&mut self) -> io::Result<SocketRelease> {
        self.socket_closed.take().map(|completion| SocketRelease { completion })
            .ok_or_else(|| io::Error::other("service UDP release receipt already transferred"))
    }
    /// Consumes this owner and confirms physical UDP socket release after all
    /// connection/endpoint/poller references are gone. Drop external clones
    /// before awaiting; an idle endpoint alone does not certify release.
    pub async fn close_and_wait(mut self) -> io::Result<()> {
        self.connection
            .close(0u32.into(), b"service carrier stopping");
        self.endpoint
            .close(0u32.into(), b"service carrier stopping");
        self.endpoint.wait_idle().await;
        let completion = self
            .socket_closed
            .take()
            .ok_or_else(|| io::Error::other("service UDP socket release owner is missing"))?;
        drop(self);
        socket::wait_released(completion).await
    }
}
impl Drop for Connected {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"service carrier owner dropped");
        self.endpoint
            .close(0u32.into(), b"service carrier owner dropped");
    }
}
pub async fn connect(
    address: SocketAddr,
    identity: &InstallationIdentity,
    edge_fingerprint: [u8; 32],
) -> Result<Connected> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let (mut endpoint, socket_closed) = socket::client(bind)?;
    let attempt: Result<Connection> = async {
        let crypto =
            QuicClientConfig::try_from(tls::service_client_config(identity, edge_fingerprint)?)?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());
        endpoint.set_default_client_config(config);
        let connection = tokio::time::timeout(
            Duration::from_secs(2),
            endpoint.connect(address, "peer.nestlink.invalid")?,
        )
        .await??;
        if !negotiated_service(&connection) {
            connection.close(1u32.into(), b"service ALPN mismatch");
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        Ok(connection)
    }
    .await;
    let connection = match attempt {
        Ok(connection) => connection,
        Err(error) => {
            endpoint.close(0u32.into(), b"service dial ended");
            endpoint.wait_idle().await;
            drop(endpoint);
            socket::wait_released(socket_closed).await?;
            return Err(error);
        }
    };
    Ok(Connected {
        connection,
        endpoint,
        socket_closed: Some(socket_closed),
    })
}
pub fn negotiated_service(connection: &Connection) -> bool {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .is_some_and(|data| data.protocol.as_deref() == Some(SERVICE_ALPN))
}
pub async fn write_message(
    write: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > CARRIER_MESSAGE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    write
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(io::Error::other)?;
    write.write_all(&bytes).await.map_err(io::Error::other)?;
    write.flush().await
}
pub async fn read_message<T: DeserializeOwned>(read: &mut (impl AsyncRead + Unpin)) -> io::Result<T> {
    let n = read.read_u32().await? as usize;
    if n == 0 || n > CARRIER_MESSAGE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; n];
    read.read_exact(&mut bytes)
        .await
        .map_err(io::Error::other)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
/// Owns both halves. Cancellation resets unfinished directions; a successful
/// FIN/EOF is preserved so normal half-close does not truncate a late response.
pub struct BiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_finished: bool,
    read_finished: bool,
}
impl BiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            write_finished: false,
            read_finished: false,
        }
    }
    pub fn parts_mut(&mut self) -> (&mut quinn::SendStream, &mut quinn::RecvStream) {
        (&mut self.send, &mut self.recv)
    }
    /// Quinn confirms that the peer acknowledged every byte and FIN. A reset
    /// is not a successful half-close receipt, and an unfinished writer cannot
    /// certify queued application bytes before its connection is closed.
    pub async fn wait_finished(&mut self) -> io::Result<()> {
        if !self.write_finished {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        match self.send.stopped().await.map_err(io::Error::other)? {
            None => Ok(()),
            Some(_) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}
impl AsyncRead for BiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let remaining = buf.remaining();
        let result = AsyncRead::poll_read(Pin::new(&mut this.recv), cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) && remaining != 0 && buf.filled().len() == before
        {
            this.read_finished = true;
        }
        result
    }
}
impl AsyncWrite for BiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = AsyncWrite::poll_shutdown(Pin::new(&mut this.send), cx);
        if matches!(&result, Poll::Ready(Ok(()))) {
            this.write_finished = true;
        }
        result
    }
}
impl Drop for BiStream {
    fn drop(&mut self) {
        if !self.write_finished {
            let _ = self.send.reset(1u32.into());
        }
        if !self.read_finished {
            let _ = self.recv.stop(1u32.into());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    #[tokio::test]
    async fn service_framing_uses_bounded_generic_streams_and_preserves_half_close() -> TestResult {
        let (mut left, mut right) = tokio::io::duplex(17);
        let worker = tokio::spawn(async move {
            let request: Vec<String> = read_message(&mut right).await?;
            if request != ["fixed approved service"] { return Err(io::ErrorKind::InvalidData.into()); }
            let mut end = [0;1];
            if right.read(&mut end).await? != 0 { return Err(io::ErrorKind::InvalidData.into()); }
            write_message(&mut right, &"response after request FIN").await?;
            right.shutdown().await
        });
        write_message(&mut left, &vec!["fixed approved service"]).await?;
        left.shutdown().await?;
        assert_eq!(read_message::<String>(&mut left).await?, "response after request FIN");
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        for length in [0, CARRIER_MESSAGE_BYTES as u32 + 1] {
            // There is deliberately no payload: invalid headers must return
            // before allocating or waiting for an attacker-controlled body.
            let bytes = length.to_be_bytes();
            let mut input = bytes.as_slice();
            assert_eq!(read_message::<Vec<u8>>(&mut input).await.err()
                .ok_or("invalid service frame accepted")?.kind(), io::ErrorKind::InvalidData);
        }
        let bytes = [0,0,0,8,b'['];
        let mut input = bytes.as_slice();
        assert_eq!(read_message::<Vec<u8>>(&mut input).await.err()
            .ok_or("truncated service frame accepted")?.kind(), io::ErrorKind::UnexpectedEof);
        Ok(())
    }
    #[tokio::test]
    async fn service_owner_confirms_real_udp_release_before_returning() -> TestResult {
        service_owner_release("127.0.0.1:0".parse()?).await
    }
    #[tokio::test]
    async fn service_owner_confirms_real_ipv6_udp_release_before_returning() -> TestResult {
        service_owner_release("[::1]:0".parse()?).await
    }
    async fn service_owner_release(bind: SocketAddr) -> TestResult {
        let edge = NodeIdentity::generate();
        let host = InstallationIdentity::generate();
        let endpoint = listener(bind, &edge)?;
        let address = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            let incoming = endpoint
                .accept()
                .await
                .ok_or("missing service connection")?;
            let connection = incoming.await?;
            connection.closed().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let connected = connect(
            address,
            &host,
            nestlink_identity::digest(&edge.public_key()),
        )
        .await?;
        let port = connected.endpoint.local_addr()?.port();
        tokio::time::timeout(Duration::from_secs(3), connected.close_and_wait()).await??;
        let rebound = std::net::UdpSocket::bind(SocketAddr::new(bind.ip(), port))?;
        drop(rebound);
        tokio::time::timeout(Duration::from_secs(3), server).await???;
        Ok(())
    }
    #[tokio::test]
    async fn pinned_service_quic_preserves_response_after_request_fin() -> TestResult {
        let edge = NodeIdentity::generate();
        let host = InstallationIdentity::generate();
        let endpoint = listener("127.0.0.1:0".parse()?, &edge)?;
        let address = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted))?;
            let connection = incoming.await?;
            if !negotiated_service(&connection) {
                return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                    io::Error::from(io::ErrorKind::PermissionDenied).into(),
                );
            }
            let (send, recv) = connection.accept_bi().await?;
            let mut stream = BiStream::new(send, recv);
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            if request != b"request before FIN" {
                return Err(io::Error::other("QUIC request changed").into());
            }
            stream.write_all(b"response after FIN").await?;
            stream.shutdown().await?;
            let _ = connection.closed().await;
            Ok(())
        });
        let connected = connect(
            address,
            &host,
            nestlink_identity::digest(&edge.public_key()),
        )
        .await?;
        let (send, recv) = connected.connection.open_bi().await?;
        let mut stream = BiStream::new(send, recv);
        stream.write_all(b"request before FIN").await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
        assert_eq!(response, b"response after FIN");
        drop(stream);
        drop(connected);
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        Ok(())
    }
    #[tokio::test]
    async fn service_carrier_rejects_the_wrong_installation_pin() -> TestResult {
        let edge = NodeIdentity::generate();
        let host = InstallationIdentity::generate();
        let endpoint = listener("127.0.0.1:0".parse()?, &edge)?;
        let address = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        assert!(connect(address, &host, [0; 32]).await.is_err());
        tokio::time::timeout(Duration::from_secs(3), server).await??;
        Ok(())
    }
    #[tokio::test]
    async fn service_carrier_does_not_negotiate_the_remote_desktop_alpn() -> TestResult {
        let edge = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let endpoint = crate::listener(
            "127.0.0.1:0".parse()?,
            &edge,
            nestlink_identity::digest(&host.public_key()),
        )?;
        let address = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        assert!(
            connect(
                address,
                &host,
                nestlink_identity::digest(&edge.public_key())
            )
            .await
            .is_err()
        );
        tokio::time::timeout(Duration::from_secs(3), server).await??;
        Ok(())
    }
}
