//! WSS carriage with an inner mutually pinned TLS 1.3 channel. No plaintext media API.
pub mod node;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use nestlink_identity::{InstallationIdentity, VerifiedPermit, relay_transcript};
use nestlink_protocol::api::{RelayChallenge, RelayHello, RelayReady};
use nestlink_transport_stream::tls;
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
    task::JoinHandle,
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
    WebSocket,
    #[error("relay operation timed out")]
    Timeout,
    #[error("inner relay TLS failed")]
    Tls,
}
/// Bounded carrier. Drop tears down the WebSocket pump and both relay endpoints.
pub struct ByteStream {
    io: DuplexStream,
    pump: JoinHandle<()>,
    failure: Arc<Mutex<Option<io::ErrorKind>>>,
}
impl Drop for ByteStream {
    fn drop(&mut self) {
        self.pump.abort();
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
    ByteStream { io, pump, failure }
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
        .ok_or(Error::WebSocket)?
        .map_err(|_| Error::WebSocket)?;
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
        .map_err(|_| Error::WebSocket)?;
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
        // Plaintext development traffic must stay on loopback even if a
        // localhost resolver has been misconfigured. Pin it before the request.
        let address = if address.is_none() && url.scheme() == "ws" {
            let port = url.port_or_known_default().ok_or(Error::Invalid)?;
            let resolved: Vec<_> = match url.host().ok_or(Error::Invalid)? {
                url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Domain(host) => tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|_| Error::WebSocket)?
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
            let tcp = TcpStream::connect(address)
                .await
                .map_err(|_| Error::WebSocket)?;
            tcp.set_nodelay(true).map_err(|_| Error::WebSocket)?;
            tokio_tungstenite::client_async_tls_with_config(request, tcp, Some(config), None)
                .await
                .map_err(|_| Error::WebSocket)
        } else {
            tokio_tungstenite::connect_async_with_config(request, Some(config), true)
                .await
                .map_err(|_| Error::WebSocket)
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
    let secured = async {
        if controller {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(
                tls::client_config(identity, expected).map_err(|_| Error::Tls)?,
            ));
            let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
                .map_err(|_| Error::Tls)?;
            Ok(tokio_rustls::TlsStream::Client(
                connector
                    .connect(name, stream)
                    .await
                    .map_err(|_| Error::Tls)?,
            ))
        } else {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
                tls::server_config(identity, expected).map_err(|_| Error::Tls)?,
            ));
            Ok(tokio_rustls::TlsStream::Server(
                acceptor.accept(stream).await.map_err(|_| Error::Tls)?,
            ))
        }
    };
    tokio::time::timeout(Duration::from_secs(3), secured)
        .await
        .map_err(|_| Error::Timeout)?
}

#[cfg(test)]
mod carrier_tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
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
