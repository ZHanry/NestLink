//! The public HTTP parser lives in Caddy. This second bounded parser authenticates
//! its private hop, enforces Host/SNI/source and removes internal credentials.
use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncReadExt, ReadBuf};

const MAX_HEAD: usize = 32 * 1024;
const MAX_HEADERS: usize = 128;
const HEADER_TIME: Duration = Duration::from_secs(2);
struct WebAuth {
    hostname: String,
    scheme: &'static str,
    token: String,
}
pub struct ServiceWebIngress {
    listener: Option<TcpListener>,
    reservation: Option<IngressReservation>,
    auth: Arc<WebAuth>,
}
pub struct ServiceWebVisitor {
    visitor: TcpStream,
    auth: Arc<WebAuth>,
    publication: ServicePublicationHandle,
    binding: [u8; 32],
}
pub struct PendingServiceWebOpen {
    visitor: PrefixedVisitor,
    pending: PendingTunnelOpen,
}
pub struct AuthorizedServiceWeb {
    visitor: PrefixedVisitor,
    flow: ServiceFlowPermit,
}
struct PrefixedVisitor {
    socket: TcpStream,
    prefix: Vec<u8>,
    offset: usize,
}
impl ServiceWebIngress {
    /// The private hop always binds a fresh loopback port. The public hostname
    /// remains owned by the unique reservation until this listener is closed.
    pub async fn bind(reservation: IngressReservation, node: &NodeControl) -> Result<Self, Error> {
        reservation.deadline(node)?;
        let lease = reservation.publication.lease()?;
        let (hostname, scheme) = match &lease.claims().definition.requested_ingress {
            ServiceIngress::Http { hostname } => (hostname.clone(), "http"),
            ServiceIngress::Https { hostname } => (hostname.clone(), "https"),
            _ => return Err(Error::Ingress),
        };
        if reservation.key != Key::Host(hostname.clone()) {
            return Err(Error::Ingress);
        }
        let listener = tokio::select! {biased;
            _=reservation.wait_stopped(node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            socket=TcpListener::bind("127.0.0.1:0")=>socket?,
        };
        reservation.deadline(node)?;
        Ok(Self {
            listener: Some(listener),
            reservation: Some(reservation),
            auth: Arc::new(WebAuth {
                hostname,
                scheme,
                token: format!(
                    "{}{}",
                    uuid::Uuid::new_v4().simple(),
                    uuid::Uuid::new_v4().simple()
                ),
            }),
        })
    }
    pub fn private_address(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.as_ref().ok_or(Error::Ingress)?.local_addr()?)
    }
    pub fn hostname(&self) -> &str {
        &self.auth.hostname
    }
    pub fn scheme(&self) -> &'static str {
        self.auth.scheme
    }
    /// Used solely to configure the private Caddy hop. Never expose this value
    /// in management responses, logs, public headers or local preview metadata.
    pub fn private_token(&self) -> &str {
        &self.auth.token
    }
    pub fn close(&mut self) {
        self.listener.take();
        self.reservation.take();
    }
    pub async fn accept(&self, node: &NodeControl) -> Result<ServiceWebVisitor, Error> {
        loop {
            let reservation = self.reservation.as_ref().ok_or(Error::Ingress)?;
            reservation.deadline(node)?;
            let listener = self.listener.as_ref().ok_or(Error::Ingress)?;
            let (visitor, peer) = tokio::select! {biased;
                _=reservation.wait_stopped(node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
                visitor=listener.accept()=>visitor?,
            };
            if !peer.ip().is_loopback() {
                drop(visitor);
                continue;
            }
            reservation.deadline(node)?;
            return Ok(ServiceWebVisitor {
                visitor,
                auth: self.auth.clone(),
                publication: reservation.publication.clone(),
                binding: reservation.binding,
            });
        }
    }
}
async fn authority_ended(publication: &ServicePublicationHandle, node: &NodeControl) {
    let mut node_stop = node.stopped();
    let mut changed = publication.changes();
    loop {
        let live = publication
            .lease()
            .and_then(|lease| node.inspect_service_lease(&lease).map_err(Error::from));
        if live.is_err() || *node_stop.borrow() {
            return;
        }
        tokio::select! {biased;
            _=node_stop.changed()=>{},
            _=changed.changed()=>{},
            _=tokio::time::sleep(Duration::from_millis(25))=>{},
        }
    }
}
impl ServiceWebVisitor {
    pub async fn authenticate(
        mut self,
        node: &NodeControl,
        edge: &NodeIdentity,
    ) -> Result<PendingServiceWebOpen, Error> {
        let head = tokio::select! {biased;
            _=authority_ended(&self.publication,node)=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            head=tokio::time::timeout(HEADER_TIME, read_head(&mut self.visitor))=>head.map_err(|_| Error::Timeout("private Caddy headers"))??,
        };
        let (peer, prefix) = authenticate_head(&head, &self.auth)?;
        let lease = self.publication.lease()?;
        if lease.binding() != self.binding {
            return Err(Error::Ingress);
        }
        let flow = self.publication.reserve_edge(node, peer.ip())?;
        let pending = PendingTunnelOpen::new(flow, edge, peer, ServiceTunnelTransport::Stream)?;
        Ok(PendingServiceWebOpen {
            visitor: PrefixedVisitor {
                socket: self.visitor,
                prefix,
                offset: 0,
            },
            pending,
        })
    }
}
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        if bytes.len() >= MAX_HEAD {
            return Err(Error::Ingress);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Ingress);
        }
        bytes.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&bytes).map_err(|_| Error::Ingress)? {
            httparse::Status::Complete(n) if n <= MAX_HEAD => return Ok(bytes),
            httparse::Status::Complete(_) => return Err(Error::Ingress),
            httparse::Status::Partial => {}
        }
    }
}
fn one<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Result<&'a [u8], Error> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = values.next().ok_or(Error::Ingress)?.value;
    if values.next().is_some() {
        return Err(Error::Ingress);
    }
    Ok(value)
}
fn optional_one<'a>(
    headers: &'a [httparse::Header<'a>],
    name: &str,
) -> Result<Option<&'a [u8]>, Error> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|header| header.value);
    if values.next().is_some() {
        return Err(Error::Ingress);
    }
    Ok(value)
}
fn authenticate_head(bytes: &[u8], auth: &WebAuth) -> Result<(SocketAddr, Vec<u8>), Error> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(bytes).map_err(|_| Error::Ingress)? {
        httparse::Status::Complete(n) if n <= MAX_HEAD => n,
        _ => return Err(Error::Ingress),
    };
    let method = request.method.ok_or(Error::Ingress)?;
    let path = request.path.ok_or(Error::Ingress)?;
    if request.version != Some(1)
        || method == "CONNECT"
        || !(path.starts_with('/') || method == "OPTIONS" && path == "*")
    {
        return Err(Error::Ingress);
    }
    let host = one(request.headers, "Host")?;
    let port = if auth.scheme == "https" { 443 } else { 80 };
    if host != auth.hostname.as_bytes() && host != format!("{}:{port}", auth.hostname).as_bytes()
        || one(request.headers, "X-NestLink-Token")? != auth.token.as_bytes()
        || one(request.headers, "X-NestLink-Scheme")? != auth.scheme.as_bytes()
    {
        return Err(Error::Ingress);
    }
    let sni = one(request.headers, "X-NestLink-SNI")?;
    if auth.scheme == "https" && sni != auth.hostname.as_bytes()
        || auth.scheme == "http" && !sni.is_empty()
    {
        return Err(Error::Ingress);
    }
    let peer = std::str::from_utf8(one(request.headers, "X-NestLink-Peer")?)
        .map_err(|_| Error::Ingress)?;
    let peer: SocketAddr = peer.parse().map_err(|_| Error::Ingress)?;
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || peer.to_string().as_bytes() != one(request.headers, "X-NestLink-Peer")?
    {
        return Err(Error::Ingress);
    }
    let length = optional_one(request.headers, "Content-Length")?;
    let transfer = optional_one(request.headers, "Transfer-Encoding")?;
    if length.is_some() && transfer.is_some()
        || length.is_some_and(|n| n.is_empty() || n.len() > 20 || !n.iter().all(u8::is_ascii_digit))
        || transfer.is_some_and(|value| !value.eq_ignore_ascii_case(b"chunked"))
    {
        return Err(Error::Ingress);
    }
    if let Some(length) = length {
        std::str::from_utf8(length)
            .map_err(|_| Error::Ingress)?
            .parse::<u64>()
            .map_err(|_| Error::Ingress)?;
    }
    optional_one(request.headers, "Connection")?;
    let upgrade = optional_one(request.headers, "Upgrade")?;
    if upgrade.is_some_and(|value| !value.eq_ignore_ascii_case(b"websocket")) {
        return Err(Error::Ingress);
    }
    let mut output = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        if name.starts_with("x-nestlink-")
            || matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "forwarded"
                    | "x-forwarded-for"
                    | "x-forwarded-host"
                    | "x-forwarded-proto"
                    | "proxy-connection"
                    | "proxy-authorization"
            )
        {
            continue;
        }
        output.extend_from_slice(header.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(header.value);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("Host: {}\r\nX-Forwarded-For: {}\r\nX-Forwarded-Host: {}\r\nX-Forwarded-Proto: {}\r\nConnection: {}\r\n\r\n",auth.hostname,peer.ip(),auth.hostname,auth.scheme,if upgrade.is_some(){"upgrade"}else{"close"}).as_bytes());
    output.extend_from_slice(&bytes[consumed..]);
    Ok((peer, output))
}
impl PendingServiceWebOpen {
    pub fn lease(&self) -> &VerifiedServiceLease {
        self.pending.lease()
    }
    pub fn challenge(&self) -> &SignedServiceTunnelChallenge {
        self.pending.challenge()
    }
    pub async fn wait_stopped(&self) {
        self.pending.wait_stopped().await;
    }
    pub fn accept_proof(
        self,
        host: &[u8; 32],
        proof: &ServiceTunnelProof,
    ) -> Result<AuthorizedServiceWeb, Error> {
        Ok(AuthorizedServiceWeb {
            visitor: self.visitor,
            flow: self.pending.accept(host, proof)?,
        })
    }
}
impl AuthorizedServiceWeb {
    pub async fn forward<S>(self, carrier: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        forward_streams(self.visitor, carrier, self.flow).await
    }
}
impl AsyncRead for PrefixedVisitor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.offset);
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            Poll::Ready(Ok(()))
        } else {
            AsyncRead::poll_read(Pin::new(&mut this.socket), cx, buf)
        }
    }
}
impl AsyncWrite for PrefixedVisitor {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().socket), cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().socket), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().socket), cx)
    }
}
#[cfg(test)]
mod tests;
