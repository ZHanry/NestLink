//! Retain the existing loopback transport and reuse the OS-authenticated native
//! stream beneath the same pinned TLS handshake on Windows.
use super::*;
use std::{pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A cancelled partial TLS frame must also retire all exported process proof.
pub(crate) struct PeerOperation {
    #[cfg(windows)]
    peer: Option<nestlink_platform_security::local_stream::VerifiedPeerProcess>,
    complete: bool,
}
impl PeerOperation {
    pub(crate) fn new(_transport: &LocalTransport) -> Self {
        Self {
            #[cfg(windows)]
            peer: _transport.verified_peer_process(),
            complete: false,
        }
    }
    pub(crate) fn complete(&mut self, success: bool) { self.complete = success; }
    fn fence(&self) {
        #[cfg(windows)]
        if let Some(peer) = &self.peer { peer.fence(); }
    }
}
impl Drop for PeerOperation {
    fn drop(&mut self) {
        if !self.complete {
            self.fence();
        }
    }
}

pub(crate) enum LocalTransport {
    Tcp(TcpStream),
    #[cfg(windows)]
    Native(nestlink_platform_security::local_stream::LocalStream),
}
impl LocalTransport {
    pub(crate) async fn tcp(listener: &TcpListener) -> Result<Self> {
        let (socket, address) = listener.accept().await?;
        if !address.ip().is_loopback() { return Err(Error::Authentication); }
        socket.set_nodelay(true)?;
        Ok(Self::Tcp(socket))
    }
    pub(crate) async fn connect(endpoint: &state::Endpoint) -> Result<Self> {
        #[cfg(windows)]
        {
            let pipe = nestlink_platform_security::local_stream::endpoint_for(&endpoint.runtime_id)?;
            match nestlink_platform_security::local_stream::connect(&pipe).await {
                Ok(stream) => return Ok(Self::Native(stream)),
                // An old daemon has only the original endpoint. Authentication,
                // access, busy and timeout failures never downgrade to TCP.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Self::connect_tcp(endpoint).await
    }
    pub(crate) async fn connect_tcp(endpoint: &state::Endpoint) -> Result<Self> {
        let socket = TcpStream::connect(endpoint.address).await?;
        socket.set_nodelay(true)?;
        Ok(Self::Tcp(socket))
    }
    #[cfg(windows)]
    pub(crate) fn verified_peer_process(&self) -> Option<nestlink_platform_security::local_stream::VerifiedPeerProcess> {
        match self {
            Self::Tcp(_) => None,
            Self::Native(stream) => stream.verified_peer_process(),
        }
    }
}
impl AsyncRead for LocalTransport {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(windows)]
            Self::Native(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}
impl AsyncWrite for LocalTransport {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(windows)]
            Self::Native(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(windows)]
            Self::Native(stream) => Pin::new(stream).poll_flush(context),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(windows)]
            Self::Native(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}
