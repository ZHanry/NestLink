//! Completion is reported after the real socket and every writable poller drop.
use quinn::{AsyncUdpSocket, Endpoint, Runtime, UdpPoller};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

pub(crate) fn client(address: SocketAddr) -> io::Result<(Endpoint, oneshot::Receiver<()>)> {
    let runtime = Arc::new(quinn::TokioRuntime);
    let inner = runtime.wrap_udp_socket(std::net::UdpSocket::bind(address)?)?;
    let (socket, completion) = tracked(inner);
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    Ok((endpoint, completion))
}

/// Reuse the service carrier's physical socket/poller receipt for discovery
/// and node carriers. The caller transfers its original inner reference.
pub(crate) fn tracked(
    inner: Arc<dyn AsyncUdpSocket>,
) -> (Arc<dyn AsyncUdpSocket>, oneshot::Receiver<()>) {
    let (released, completion) = oneshot::channel();
    (
        Arc::new(TrackedSocket {
            inner,
            _release: Release(Some(released)),
        }),
        completion,
    )
}

pub(super) async fn wait_released(completion: oneshot::Receiver<()>) -> io::Result<()> {
    completion
        .await
        .map_err(|_| io::Error::other("service UDP socket release was not confirmed"))
}

#[derive(Debug)]
struct TrackedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    // Fields drop in declaration order: close the last inner socket reference
    // before publishing completion. Pollers retain this owner as well.
    _release: Release,
}

#[derive(Debug)]
struct Release(Option<oneshot::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(released) = self.0.take() {
            let _ = released.send(());
        }
    }
}

#[derive(Debug)]
struct TrackedPoller {
    // Drop the poller's inner socket reference before its retained owner.
    inner: Pin<Box<dyn UdpPoller>>,
    _socket: Arc<TrackedSocket>,
}
impl UdpPoller for TrackedPoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_writable(context)
    }
}

impl AsyncUdpSocket for TrackedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TrackedPoller {
            inner: self.inner.clone().create_io_poller(),
            _socket: self,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(context, buffers, metadata)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn release_completion_waits_for_the_last_real_writable_poller() -> io::Result<()> {
        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0")?)?;
        let address = inner.local_addr()?;
        let (released, mut completion) = oneshot::channel();
        let socket = Arc::new(TrackedSocket {
            inner,
            _release: Release(Some(released)),
        });
        let poller = socket.clone().create_io_poller();
        drop(socket);
        assert!(matches!(
            completion.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            std::net::UdpSocket::bind(address),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse
        ));
        drop(poller);
        wait_released(completion).await?;
        let rebound = std::net::UdpSocket::bind(address)?;
        drop(rebound);
        Ok(())
    }
}
