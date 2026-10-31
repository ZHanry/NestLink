use super::*;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

struct RestoreFlags {
    fd: OwnedFd,
    original: OFlags,
}
impl AsRawFd for RestoreFlags {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
impl AsFd for RestoreFlags {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl Drop for RestoreFlags {
    fn drop(&mut self) {
        let _ = fcntl_setfl(&self.fd, self.original);
    }
}
struct Fd(AsyncFd<RestoreFlags>);
impl Fd {
    fn new(fd: OwnedFd, original: OFlags) -> io::Result<Self> {
        let fd = RestoreFlags { fd, original };
        fcntl_setfl(&fd, original | OFlags::NONBLOCK)?;
        Ok(Self(AsyncFd::new(fd)?))
    }
    fn restore(&self) -> io::Result<()> {
        let owner = self.0.get_ref();
        fcntl_setfl(&owner.fd, owner.original).map_err(io::Error::from)
    }
}
impl AsyncRead for Fd {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = match self.0.poll_read_ready(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            };
            match ready.try_io(|inner| {
                rustix::io::read(inner.get_ref(), buffer.initialize_unfilled())
                    .map_err(io::Error::from)
            }) {
                Ok(Ok(length)) => {
                    buffer.advance(length);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}
impl AsyncWrite for Fd {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = match self.0.poll_write_ready(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            };
            match ready
                .try_io(|inner| rustix::io::write(inner.get_ref(), buffer).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
pub(super) async fn relay(
    stream: LocalStream,
    stop: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
    // Capture both original descriptions before changing either. This also
    // restores correctly if stdin/stdout happen to share one open description.
    let (input_flags, output_flags) = (fcntl_getfl(stdin.as_fd())?, fcntl_getfl(stdout.as_fd())?);
    let mut input = Fd::new(rustix::io::dup(stdin.as_fd())?, input_flags)?;
    let mut output = Fd::new(rustix::io::dup(stdout.as_fd())?, output_flags)?;
    let operation = relay_io(&mut input, &mut output, stream, stop).await;
    let input_cleanup = input.restore();
    let output_cleanup = output.restore();
    input_cleanup?;
    output_cleanup?;
    operation
}
