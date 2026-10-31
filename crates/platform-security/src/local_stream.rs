//! OS-authenticated local byte streams. This module grants no network authority.
//! It reuses Tokio native transports, owner-private directories, Unix peer
//! credentials and the Windows broker's protected-pipe/token boundary.
use std::{io, path::{Path, PathBuf}, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
mod stdio;
pub use stdio::relay_stdio;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Listener, connect};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Listener, connect};

trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> StreamIo for T {}
pub struct LocalStream(Box<dyn StreamIo>);
impl LocalStream {
    fn new(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        Self(Box::new(stream))
    }
}
impl AsyncRead for LocalStream {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(context, buffer)
    }
}
impl AsyncWrite for LocalStream {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(context, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(context)
    }
}
fn valid_owner_id(id: &str) -> bool {
    (16..=64).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "local stream OS owner or endpoint rejected")
}
