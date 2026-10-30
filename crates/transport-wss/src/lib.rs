//! WSS carriage with an inner mutually pinned TLS 1.3 channel. No plaintext media API.
pub mod node;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use nestlink_identity::{InstallationIdentity, VerifiedPermit, relay_transcript};
use nestlink_protocol::api::{RelayChallenge, RelayHello, RelayReady};
use nestlink_transport_stream::tls;
use nestlink_transport_stream::owner::TaskOwner;
use serde::de::DeserializeOwned;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpStream,
};
pub use tokio_tungstenite::tungstenite::{
    Error as WebSocketError,
    error::{
        ProtocolError as WebSocketProtocolError, TlsError as WebSocketTlsError,
        UrlError as WebSocketUrlError,
    },
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{
        Message, client::IntoClientRequest, http::HeaderValue, protocol::WebSocketConfig,
    },
};

const CHUNK: usize = 65536;
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid relay identity, URL or challenge")]
    Invalid,
    #[error("outer relay WebSocket failed")]
    WebSocket(#[source] Box<WebSocketError>),
    #[error("relay operation timed out")]
    Timeout,
    #[error("inner relay TLS failed")]
    Tls(#[source] io::Error),
    #[error("relay TLS configuration failed")]
    TlsSetup(#[source] Box<dyn std::error::Error + Send + Sync>),
}
impl From<WebSocketError> for Error {
    fn from(error: WebSocketError) -> Self {
        Self::WebSocket(Box::new(error))
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        WebSocketError::Io(error).into()
    }
}
/// Bounded carrier. Drop tears down the WebSocket pump and both relay endpoints.
pub struct ByteStream {
    io: DuplexStream,
    pump: TaskOwner,
    failure: Arc<Mutex<Option<io::ErrorKind>>>,
}
impl Drop for ByteStream {
    fn drop(&mut self) {
        self.pump.request_close();
    }
}
impl ByteStream {
    /// Close capability and join receipt for the existing WebSocket pump.
    /// Cloning it starts no task and performs no additional socket reads.
    pub fn close_owner(&self) -> TaskOwner {
        self.pump.clone()
    }
}
impl AsyncRead for ByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && let Some(kind) = *self
                .failure
                .lock()
                .map_err(|_| io::Error::other("relay carrier state poisoned"))?
        {
            return Poll::Ready(Err(io::Error::new(kind, "relay carrier failed")));
        }
        result
    }
}
impl AsyncWrite for ByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn bridge(socket: Socket) -> ByteStream {
    let (io, carrier) = tokio::io::duplex(CHUNK);
    // A panic/aborted owner remains a terminal local failure. A completed pump
    // publishes its actual result before either stream half is dropped.
    let failure = Arc::new(Mutex::new(Some(io::ErrorKind::Other)));
    let finished = failure.clone();
    let pump = tokio::spawn(async move {
        let (mut sink, mut source) = socket.split();
        let (mut local_read, mut local_write) = tokio::io::split(carrier);
        let outgoing = async {
            let mut buffer = vec![0; CHUNK];
            loop {
                let size = local_read.read(&mut buffer).await?;
                if size == 0 {
                    break;
                }
                sink.send(Message::Binary(buffer[..size].to_vec().into()))
                    .await
                    .map_err(carrier_error)?;
            }
            sink.close().await.map_err(carrier_error)
        };
        let incoming = async {
            while let Some(message) = source.next().await {
                match message.map_err(carrier_error)? {
                    Message::Binary(bytes) if !bytes.is_empty() && bytes.len() <= CHUNK => {
                        local_write.write_all(&bytes).await?
                    }
                    Message::Close(_) => break,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected relay frame",
                        ));
                    }
                }
            }
            local_write.shutdown().await
        };
        let result = tokio::select! {result=outgoing=>result,result=incoming=>result};
        if let Ok(mut failure) = finished.lock() {
            *failure = result.err().map(|error| error.kind());
        }
    });
    ByteStream { io, pump: TaskOwner::new(pump), failure }
}
fn carrier_error(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::Io(error) => error,
        Error::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ) => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "relay carrier ended before close handshake",
        ),
        Error::ConnectionClosed | Error::AlreadyClosed => {
            io::Error::new(io::ErrorKind::BrokenPipe, "relay closed")
        }
        Error::Protocol(_)
        | Error::Capacity(_)
        | Error::Utf8(_)
        | Error::AttackAttempt
        | Error::Tls(_) => io::Error::new(io::ErrorKind::InvalidData, "relay protocol failed"),
        _ => io::Error::other("relay carrier failed"),
    }
}

async fn text<T: DeserializeOwned>(socket: &mut Socket, budget: Duration) -> Result<T, Error> {
    let message = tokio::time::timeout(budget, socket.next())
        .await
        .map_err(|_| Error::Timeout)?
        .ok_or_else(|| Error::from(WebSocketError::ConnectionClosed))?
        .map_err(Error::from)?;
    let Message::Text(text) = message else {
        return Err(Error::Invalid);
    };
    if text.len() > 4096 {
        return Err(Error::Invalid);
    }
    serde_json::from_str(&text).map_err(|_| Error::Invalid)
}
pub async fn connect(
    url: &str,
    bearer: &str,
    account_id: &str,
    device_id: &str,
    identity: &InstallationIdentity,
    permit: &VerifiedPermit,
) -> Result<tokio_rustls::TlsStream<ByteStream>, Error> {
    connect_inner(url, bearer, account_id, device_id, identity, permit, None).await
}
/// The caller approves this literal socket address against its configured relay
/// authority. The original URL still supplies Host, SNI and certificate checks.
pub async fn connect_at(
    url: &str,
    bearer: &str,
    account_id: &str,
    installation: (&str, &InstallationIdentity),
    permit: &VerifiedPermit,
    address: SocketAddr,
) -> Result<tokio_rustls::TlsStream<ByteStream>, Error> {
    connect_inner(
        url,
        bearer,
        account_id,
        installation.0,
        installation.1,
        permit,
        Some(address),
    )
    .await
}
async fn connect_inner(
    url: &str,
    bearer: &str,
    account_id: &str,
    device_id: &str,
    identity: &InstallationIdentity,
    permit: &VerifiedPermit,
    address: Option<SocketAddr>,
) -> Result<tokio_rustls::TlsStream<ByteStream>, Error> {
    let (controller, expected) = peer_endpoint(device_id, identity, permit)?;
    let claims = permit.claims();
    let mut socket = open_socket(url, Some(bearer), address).await?;
    let challenge: RelayChallenge = text(&mut socket, Duration::from_secs(3)).await?;
    if challenge.lease_sequence != claims.lease_sequence {
        return Err(Error::Invalid);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(challenge.nonce)
        .map_err(|_| Error::Invalid)?;
    let proof =
        relay_transcript(claims, account_id, device_id, &nonce).map_err(|_| Error::Invalid)?;
    let hello = RelayHello {
        device_id: device_id.into(),
        signature: URL_SAFE_NO_PAD
            .encode(identity.sign_action(&proof).map_err(|_| Error::Invalid)?),
    };
    socket
        .send(Message::Text(
            serde_json::to_string(&hello)
                .map_err(|_| Error::Invalid)?
                .into(),
        ))
        .await
        .map_err(Error::from)?;
    let ready: RelayReady = text(&mut socket, Duration::from_secs(6)).await?;
    if !ready.ready {
        return Err(Error::Invalid);
    }
    secure(socket, identity, controller, expected).await
}
fn peer_endpoint(
    device_id: &str,
    identity: &InstallationIdentity,
    permit: &VerifiedPermit,
) -> Result<(bool, [u8; 32]), Error> {
    let claims = permit.claims();
    if !claims
        .paths
        .contains(&(nestlink_protocol::Path::Relay as i32))
    {
        return Err(Error::Invalid);
    }
    let (controller, expected) = if device_id == claims.controller_device_id
        && identity.fingerprint() == claims.controller_key_sha256.as_slice()
    {
        (true, &claims.host_key_sha256)
    } else if device_id == claims.host_device_id
        && identity.fingerprint() == claims.host_key_sha256.as_slice()
    {
        (false, &claims.controller_key_sha256)
    } else {
        return Err(Error::Invalid);
    };
    let expected: [u8; 32] = expected.as_slice().try_into().map_err(|_| Error::Invalid)?;
    Ok((controller, expected))
}
async fn open_socket(
    url: &str,
    bearer: Option<&str>,
    address: Option<SocketAddr>,
) -> Result<Socket, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::Invalid)?;
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !(url.scheme() == "wss" || (url.scheme() == "ws" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid);
    }
    if address.is_some_and(|a| {
        a.port() != url.port_or_known_default().unwrap_or(0)
            || (url.scheme() == "ws" && !a.ip().is_loopback())
    }) {
        return Err(Error::Invalid);
    }
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| Error::Invalid)?;
    if let Some(bearer) = bearer {
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| Error::Invalid)?,
        );
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(CHUNK))
        .max_frame_size(Some(CHUNK))
        .write_buffer_size(0)
        .max_write_buffer_size(CHUNK * 2);
    let outer = async {
        let connector = Some(tokio_tungstenite::Connector::Rustls(Arc::new(
            tls::public_client_config().map_err(|error| Error::TlsSetup(Box::new(error)))?,
        )));
        // Plaintext development traffic must stay on loopback even if a
        // localhost resolver has been misconfigured. Pin it before the request.
        let address = if address.is_none() && url.scheme() == "ws" {
            let port = url.port_or_known_default().ok_or(Error::Invalid)?;
            let resolved: Vec<_> = match url.host().ok_or(Error::Invalid)? {
                url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Domain(host) => tokio::net::lookup_host((host, port))
                    .await
                    .map_err(Error::from)?
                    .take(33)
                    .collect(),
            };
            if resolved.is_empty()
                || resolved.len() > 32
                || resolved.iter().any(|a| !a.ip().is_loopback())
            {
                return Err(Error::Invalid);
            }
            resolved.into_iter().next()
        } else {
            address
        };
        if let Some(address) = address {
            let tcp = TcpStream::connect(address).await.map_err(Error::from)?;
            tcp.set_nodelay(true).map_err(Error::from)?;
            tokio_tungstenite::client_async_tls_with_config(request, tcp, Some(config), connector)
                .await
                .map_err(Error::from)
        } else {
            tokio_tungstenite::connect_async_tls_with_config(request, Some(config), true, connector)
                .await
                .map_err(Error::from)
        }
    };
    let (socket, _) = tokio::time::timeout(Duration::from_secs(3), outer)
        .await
        .map_err(|_| Error::Timeout)??;
    Ok(socket)
}
async fn secure(
    socket: Socket,
    identity: &InstallationIdentity,
    controller: bool,
    expected: [u8; 32],
) -> Result<tokio_rustls::TlsStream<ByteStream>, Error> {
    let stream = bridge(socket);
    let pump = stream.close_owner();
    let secured = async {
        if controller {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(
                tls::client_config(identity, expected).map_err(Error::TlsSetup)?,
            ));
            let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
                .map_err(|_| Error::Invalid)?;
            Ok(tokio_rustls::TlsStream::Client(
                connector.connect(name, stream).await.map_err(Error::Tls)?,
            ))
        } else {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
                tls::server_config(identity, expected).map_err(Error::TlsSetup)?,
            ));
            Ok(tokio_rustls::TlsStream::Server(
                acceptor.accept(stream).await.map_err(Error::Tls)?,
            ))
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(3), secured)
        .await
        .unwrap_or(Err(Error::Timeout));
    if result.is_err() {
        pump.close_and_wait(tokio::time::Instant::now() + Duration::from_secs(2))
            .await.map_err(Error::from)?;
    }
    result
}

#[cfg(test)]
mod carrier_tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[tokio::test]
    async fn close_receipt_joins_the_real_idle_websocket_pump_and_closes_tcp() -> Result {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("ws://{}", listener.local_addr()?);
        let server = async {
            let (tcp, _) = listener.accept().await?;
            let mut socket = tokio_tungstenite::accept_async(tcp).await?;
            // Closing the carrier must terminate this actual idle socket read.
            let result = socket.next().await;
            assert!(!matches!(result, Some(Ok(Message::Binary(_)))));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let client = async {
            let (socket, _) = tokio_tungstenite::connect_async(&url).await?;
            let carrier = bridge(socket);
            let pump = carrier.close_owner();
            drop(carrier);
            pump.close_and_wait(tokio::time::Instant::now() + Duration::from_secs(1)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::time::timeout(Duration::from_secs(3), async { tokio::try_join!(server, client) }).await??;
        Ok(())
    }

    fn has_certificate_error(error: &(dyn std::error::Error + 'static), depth: u8) -> bool {
        if depth >= 16 {
            return false;
        }
        if matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ) {
            return true;
        }
        if let Some(error) = error.downcast_ref::<io::Error>()
            && let Some(source) = error.get_ref()
        {
            return has_certificate_error(source, depth + 1);
        }
        if let Some(WebSocketTlsError::Rustls(source)) = error.downcast_ref::<WebSocketTlsError>() {
            return has_certificate_error(source.as_ref(), depth + 1);
        }
        error
            .source()
            .is_some_and(|source| has_certificate_error(source, depth + 1))
    }

    #[tokio::test]
    async fn outer_wss_untrusted_certificate_retains_actual_rustls_failure() -> Result {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let identity = InstallationIdentity::generate();
        let mut config = tls::server_config(&identity, [0; 32])?;
        config.alpn_protocols.clear();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let server = async {
            let (tcp, _) = listener.accept().await?;
            assert!(acceptor.accept(tcp).await.is_err());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let client = async {
            let error = open_socket(
                &format!("wss://localhost:{}", address.port()),
                None,
                Some(address),
            )
            .await
            .err()
            .ok_or("untrusted outer certificate was accepted")?;
            assert!(has_certificate_error(&error, 0));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(server, client)
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn actual_outer_websocket_rejection_and_connection_refusal_keep_their_sources() -> Result
    {
        for status in [401, 403, 503] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let server = async {
                let (mut tcp, _) = listener.accept().await?;
                let mut request = [0; 4096];
                let _ = tcp.read(&mut request).await?;
                let response = format!(
                    "HTTP/1.1 {status} Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                tcp.write_all(response.as_bytes()).await?;
                tcp.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let client = async {
                let error = open_socket(&format!("ws://{address}"), None, Some(address))
                    .await
                    .err()
                    .ok_or("rejected WebSocket upgrade was accepted")?;
                assert!(matches!(
                    error,
                    Error::WebSocket(source)
                        if matches!(source.as_ref(), WebSocketError::Http(response)
                            if response.status().as_u16() == status)
                ));
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let (served, received) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server, client)
            })
            .await?;
            served?;
            received?;
        }
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = unused.local_addr()?;
        drop(unused);
        let error = open_socket(&format!("ws://{address}"), None, Some(address))
            .await
            .err()
            .ok_or("unused port unexpectedly accepted a connection")?;
        assert!(matches!(
            error,
            Error::WebSocket(source)
                if matches!(source.as_ref(), WebSocketError::Io(error)
                    if error.kind() == io::ErrorKind::ConnectionRefused)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn real_websocket_protocol_failure_is_preserved_in_byte_stream_instead_of_eof() -> Result
    {
        for malicious in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("ws://{}", listener.local_addr()?);
            let server = async {
                let (tcp, _) = listener.accept().await?;
                let mut socket = tokio_tungstenite::accept_async(tcp).await?;
                if malicious {
                    socket
                        .send(Message::Text("not an authorized binary carrier".into()))
                        .await?;
                } else {
                    socket.close(None).await?;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let client = async {
                let (socket, _) = tokio_tungstenite::connect_async(&url).await?;
                let mut carrier = bridge(socket);
                let mut empty = [];
                assert_eq!(carrier.read(&mut empty).await?, 0);
                let mut bytes = [0; 1];
                let result =
                    tokio::time::timeout(Duration::from_secs(1), carrier.read(&mut bytes)).await?;
                if malicious {
                    assert_eq!(
                        result.err().ok_or("failure became EOF")?.kind(),
                        io::ErrorKind::InvalidData
                    );
                } else {
                    assert_eq!(result?, 0);
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::try_join!(server, client)?;
        }
        Ok(())
    }
}
