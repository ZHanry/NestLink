//! A non-authorizing, bounded original-owner readiness endpoint for a mature
//! fixed-entry health checker. A Caddy TCP port alone is not service readiness.
use super::*;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, watch},
    time::Sleep,
};

struct HealthIo {
    socket: TcpStream,
    _slot: OwnedSemaphorePermit,
    deadline: Pin<Box<Sleep>>,
}
impl AsyncRead for HealthIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut this.socket).poll_read(cx, buffer)
    }
}
impl AsyncWrite for HealthIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut this.socket).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}
struct Listener {
    socket: TcpListener,
    slots: Arc<Semaphore>,
}
impl axum::serve::Listener for Listener {
    type Io = HealthIo;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok(slot) = self
                .slots
                .clone()
                .acquire_owned()
                .await
            else {
                // Listener::accept is infallible. A closed admission owner
                // cannot accept more sockets; server shutdown cancels this wait.
                std::future::pending::<()>().await;
                continue;
            };
            match self.socket.accept().await {
                Ok((socket, peer)) => {
                    return (
                        HealthIo {
                            socket,
                            _slot: slot,
                            deadline: Box::pin(tokio::time::sleep(Duration::from_secs(2))),
                        },
                        peer,
                    );
                }
                Err(_) => {
                    drop(slot);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
async fn ready(
    State(edge): State<Arc<Edge>>,
    Path((group, revision, digest)): Path<(String, u64, String)>,
) -> StatusCode {
    if !valid_id(&group)
        || revision == 0
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return StatusCode::NOT_FOUND;
    }
    let Ok(hosts) = edge.hosts.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    for (id, host) in hosts.iter() {
        if !host.ready.load(std::sync::atomic::Ordering::SeqCst)
            || host.connection.close_reason().is_some()
        {
            continue;
        }
        let Ok(publication) = edge.node.service_publication(id) else {
            continue;
        };
        if configured(&edge, &publication).is_err() {
            continue;
        }
        let Ok(lease) = publication.lease() else {
            continue;
        };
        let Some(binding) = &lease.claims().edge_group else {
            continue;
        };
        let actual: String = binding
            .aggregate_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if binding.group.group_id == group && binding.group.revision == revision && actual == digest
        {
            return StatusCode::OK;
        }
    }
    StatusCode::SERVICE_UNAVAILABLE
}
pub(super) struct Driver {
    stop: watch::Sender<bool>,
    worker: Option<tokio::task::JoinHandle<io::Result<()>>>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}
struct Ended(Arc<std::sync::atomic::AtomicBool>);
impl Drop for Ended {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Driver {
    pub(super) async fn start(address: SocketAddr, edge: Arc<Edge>) -> io::Result<Self> {
        if address.ip() != edge.bind_ip
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || address.port() < 1024
            || (28743..=29055).contains(&address.port())
            || edge.namespace.config.public_ports.contains(&address.port())
        {
            return Err(denied());
        }
        let listener = Listener {
            socket: TcpListener::bind(address).await?,
            slots: Arc::new(Semaphore::new(32)),
        };
        let app = Router::new()
            .route("/service-group/{group}/{revision}/{digest}", get(ready))
            .with_state(edge);
        let (stop, mut stopped) = watch::channel(false);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ended = finished.clone();
        let worker = tokio::spawn(async move {
            let _ended = Ended(ended);
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    while !*stopped.borrow() {
                        if stopped.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
        });
        Ok(Self {
            stop,
            worker: Some(worker),
            finished,
        })
    }
    pub(super) fn failed(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let finished = self.finished.clone();
        Box::pin(async move {
            loop {
                if finished.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    }
    pub(super) async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        if let Some(worker) = self.worker.take() {
            worker.await.map_err(fault)??;
        }
        Ok(())
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
