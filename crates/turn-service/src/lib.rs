//! A bounded TURN listener service for grants verified by NodeControl.
//!
//! This crate owns the UDP, TCP, TLS, and relay-port sockets. It does not
//! authenticate or construct snapshots; callers install only grants that have
//! already passed the control-plane signature and lease checks.

mod config;
mod relay;
mod stream_conn;

pub use config::{RelayPortPool, TurnListenAddresses, TurnServiceConfig, TurnServiceError};

use crate::{relay::RelayPortGenerator, stream_conn::StreamConn};
use futures_util::future::join_all;
use nestlink_traversal::turn::{TurnAction, TurnAuthorization};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};
use turn::{
    Error,
    auth::{AllocationOperation, AuthHandler},
    relay::RelayAddressGenerator,
    server::{
        Server,
        config::{ConnConfig, ServerConfig},
    },
};
use webrtc_util::Conn;

const REAPER_INTERVAL: Duration = Duration::from_millis(250);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CHANNEL_BIND_TIMEOUT: Duration = Duration::from_secs(600);

/// Running listeners and their actual bound addresses. Use [`TurnControl`] to
/// revoke a live allocation or stop all listeners.
pub struct TurnService {
    inner: Arc<ServiceInner>,
    addresses: TurnListenAddresses,
}

/// Online control for a running TURN service.
#[derive(Clone)]
pub struct TurnControl {
    inner: Arc<ServiceInner>,
}

struct ServiceInner {
    realm: String,
    authorization: Arc<TurnAuthorization>,
    online: watch::Receiver<bool>,
    relay_generator: RelayPortGenerator,
    servers: Mutex<HashMap<u64, Arc<Server>>>,
    next_server_id: AtomicU64,
    shutdown_tx: watch::Sender<bool>,
    connection_limit: Arc<Semaphore>,
    listener_tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown_lock: Mutex<()>,
}

impl TurnService {
    /// Binds all configured listeners. The online watch must be `true` for the
    /// lifetime of the node; changing it to `false` revokes grants and closes
    /// this service.
    pub async fn bind(
        config: TurnServiceConfig,
        authorization: Arc<TurnAuthorization>,
        mut online: watch::Receiver<bool>,
    ) -> Result<(Self, TurnControl), TurnServiceError> {
        config.validate()?;
        if !online_is_active(&online) {
            return Err(TurnServiceError::Offline);
        }

        // Bind every configured socket before starting any background task so
        // a partial bind failure cannot leave an externally visible service.
        let udp_socket = match config.udp_bind {
            Some(address) => Some(Arc::new(UdpSocket::bind(address).await?)),
            None => None,
        };
        let tcp_listener = match config.tcp_bind {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let tls_listener = match config.tls_bind {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };

        let addresses = TurnListenAddresses {
            udp: udp_socket
                .as_ref()
                .map(|socket| socket.local_addr())
                .transpose()?,
            tcp: tcp_listener
                .as_ref()
                .map(|listener| listener.local_addr())
                .transpose()?,
            tls: tls_listener
                .as_ref()
                .map(|listener| listener.local_addr())
                .transpose()?,
        };
        // Listener binding may await the OS. Recheck before constructing a
        // TURN server so a lease that expired during startup never serves.
        if !online_is_active(&online) {
            return Err(TurnServiceError::Offline);
        }
        let relay_generator = RelayPortGenerator::new(&config.relay_port_pools)?;
        let (shutdown_tx, _) = watch::channel(false);
        let inner = Arc::new(ServiceInner {
            realm: config.realm,
            authorization,
            online: online.clone(),
            relay_generator,
            servers: Mutex::new(HashMap::new()),
            next_server_id: AtomicU64::new(1),
            shutdown_tx,
            connection_limit: Arc::new(Semaphore::new(config.max_connections)),
            listener_tasks: Mutex::new(Vec::new()),
            shutdown_lock: Mutex::new(()),
        });

        if let Some(socket) = udp_socket {
            let conn: Arc<dyn Conn + Send + Sync> = socket;
            let server = Arc::new(new_server(&inner, conn).await?);
            if inner.register_server(server).await.is_none() {
                return Err(TurnServiceError::ServerCommand);
            }
        }
        if let Some(listener) = tcp_listener {
            let task = tokio::spawn(accept_loop(Arc::clone(&inner), listener));
            inner.listener_tasks.lock().await.push(task);
        }
        if let Some(listener) = tls_listener {
            let tls_config = config
                .tls_server_config
                .clone()
                .ok_or(TurnServiceError::Configuration)?;
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            let task = tokio::spawn(accept_tls_loop(Arc::clone(&inner), listener, acceptor));
            inner.listener_tasks.lock().await.push(task);
        }

        let control = TurnControl {
            inner: Arc::clone(&inner),
        };
        let reaper = tokio::spawn(expiry_reaper(Arc::clone(&inner)));
        inner.listener_tasks.lock().await.push(reaper);

        // The monitor isn't part of listener_tasks: it may itself initiate
        // shutdown and must never try to join itself.
        let online_control = control.clone();
        tokio::spawn(async move {
            if !*online.borrow() {
                let _ = online_control.shutdown().await;
                return;
            }
            let mut service_shutdown = online_control.inner.shutdown_tx.subscribe();
            if *service_shutdown.borrow() {
                return;
            }
            loop {
                tokio::select! {
                    changed = online.changed() => {
                        if changed.is_err() || !*online.borrow() {
                            let _ = online_control.shutdown().await;
                            return;
                        }
                    }
                    _ = service_shutdown.changed() => return,
                }
            }
        });

        Ok((Self { inner, addresses }, control))
    }

    pub fn listen_addresses(&self) -> TurnListenAddresses {
        self.addresses
    }

    /// Stops listeners, closes allocations, and waits for listener workers.
    pub async fn shutdown(&self) -> Result<(), TurnServiceError> {
        self.inner.shutdown().await
    }
}

impl TurnControl {
    /// Revokes the exact allocation id and removes its relay allocation from
    /// every UDP and stream TURN server currently serving this node.
    pub async fn revoke(&self, allocation_id: &str) -> Result<(), TurnServiceError> {
        let username = self.inner.authorization.revoke(allocation_id)?;
        self.inner.delete_allocations(&username).await
    }

    /// Revokes all grants and closes every listener and active allocation.
    pub async fn shutdown(&self) -> Result<(), TurnServiceError> {
        self.inner.shutdown().await
    }
}

fn online_is_active(online: &watch::Receiver<bool>) -> bool {
    *online.borrow() && online.has_changed().is_ok()
}

impl ServiceInner {
    async fn register_server(&self, server: Arc<Server>) -> Option<u64> {
        let mut servers = self.servers.lock().await;
        if *self.shutdown_tx.borrow() {
            return None;
        }
        let id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        servers.insert(id, server);
        Some(id)
    }

    async fn remove_server(&self, id: u64) -> Option<Arc<Server>> {
        self.servers.lock().await.remove(&id)
    }

    async fn delete_allocations(&self, username: &str) -> Result<(), TurnServiceError> {
        let servers = self
            .servers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let results = join_all(servers.iter().map(|server| {
            let username = username.to_owned();
            async move { server.delete_allocations_by_username(username).await }
        }))
        .await;
        if results.iter().any(Result::is_err) {
            return Err(TurnServiceError::ServerCommand);
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), TurnServiceError> {
        let _guard = self.shutdown_lock.lock().await;
        self.shutdown_tx.send_replace(true);
        self.authorization.revoke_all();
        let servers = self
            .servers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let results = join_all(
            servers
                .iter()
                .map(|server| async move { server.close().await }),
        )
        .await;
        let mut worker_failed = false;
        let tasks = std::mem::take(&mut *self.listener_tasks.lock().await);
        for task in tasks {
            worker_failed |= task.await.is_err();
        }
        if worker_failed || results.iter().any(Result::is_err) {
            return Err(TurnServiceError::ServerCommand);
        }
        Ok(())
    }
}

async fn new_server(
    inner: &ServiceInner,
    conn: Arc<dyn Conn + Send + Sync>,
) -> Result<Server, TurnServiceError> {
    let generator: Box<dyn RelayAddressGenerator + Send + Sync> =
        Box::new(inner.relay_generator.clone());
    Ok(Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: generator,
        }],
        realm: inner.realm.clone(),
        auth_handler: Arc::new(ManagedAuth {
            authorization: Arc::clone(&inner.authorization),
            online: inner.online.clone(),
        }),
        channel_bind_timeout: CHANNEL_BIND_TIMEOUT,
        alloc_close_notify: None,
    })
    .await?)
}

struct ManagedAuth {
    authorization: Arc<TurnAuthorization>,
    online: watch::Receiver<bool>,
}

impl ManagedAuth {
    fn is_online(&self) -> bool {
        online_is_active(&self.online)
    }
}

impl AuthHandler for ManagedAuth {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        _src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
        if !self.is_online() {
            return Err(Error::ErrNoSuchUser);
        }
        self.authorization
            .auth_key(username, realm)
            .map(|key| key.to_vec())
            .ok_or(Error::ErrNoSuchUser)
    }

    fn authorize_allocation(&self, username: &str, realm: &str, src_addr: SocketAddr) -> bool {
        self.is_online()
            && self
                .authorization
                .authorize_allocation(username, realm, src_addr)
    }

    fn allocation_ready(&self, username: &str, src_addr: SocketAddr) -> bool {
        self.is_online() && self.authorization.allocation_ready(username, src_addr)
    }

    fn allocation_failed(&self, username: &str, src_addr: SocketAddr) {
        self.authorization.allocation_failed(username, src_addr);
    }

    fn allocation_closed(&self, username: &str, src_addr: SocketAddr) {
        self.authorization.allocation_closed(username, src_addr);
    }

    fn authorize_operation(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
        operation: AllocationOperation,
        peer_addr: Option<SocketAddr>,
        bytes: u64,
    ) -> bool {
        if !self.is_online() {
            return false;
        }
        let action = match operation {
            AllocationOperation::Refresh => TurnAction::Refresh,
            AllocationOperation::CreatePermission => TurnAction::CreatePermission,
            AllocationOperation::ChannelBind => TurnAction::ChannelBind,
            AllocationOperation::SendIndication => TurnAction::SendIndication,
            AllocationOperation::ChannelData => TurnAction::ChannelData,
            AllocationOperation::RelayToClient => TurnAction::RelayToClient,
        };
        self.authorization
            .authorize_action(username, realm, src_addr, action, peer_addr, bytes)
    }
}

async fn accept_loop(inner: Arc<ServiceInner>, listener: TcpListener) {
    let mut shutdown = inner.shutdown_tx.subscribe();
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(permit) = Arc::clone(&inner.connection_limit).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    connections.spawn(serve_stream(Arc::clone(&inner), stream, permit));
                }
                Err(error) => {
                    tracing::warn!(%error, "TURN TCP accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    close_connections(&mut connections).await;
}

async fn accept_tls_loop(
    inner: Arc<ServiceInner>,
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    let mut shutdown = inner.shutdown_tx.subscribe();
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(permit) = Arc::clone(&inner.connection_limit).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let inner = Arc::clone(&inner);
                    let acceptor = acceptor.clone();
                    connections.spawn(async move {
                        let tls = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
                        if let Ok(Ok(stream)) = tls {
                            serve_stream(inner, stream, permit).await;
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "TURN TLS accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    close_connections(&mut connections).await;
}

trait StreamAddresses {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

impl StreamAddresses for TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

impl StreamAddresses for tokio_rustls::server::TlsStream<TcpStream> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.get_ref().0.peer_addr()
    }
}

async fn serve_stream<S>(
    inner: Arc<ServiceInner>,
    stream: S,
    _permit: tokio::sync::OwnedSemaphorePermit,
) where
    S: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + StreamAddresses
        + Unpin
        + Send
        + Sync
        + 'static,
{
    let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else {
        return;
    };
    let conn = Arc::new(StreamConn::new(stream, local, peer));
    let server = match new_server(&inner, conn.clone()).await {
        Ok(server) => Arc::new(server),
        Err(error) => {
            tracing::warn!(%error, "failed to start per-stream TURN server");
            let _ = conn.close().await;
            return;
        }
    };
    let Some(id) = inner.register_server(Arc::clone(&server)).await else {
        let _ = server.close().await;
        return;
    };
    conn.wait_closed().await;
    let _ = server.close().await;
    inner.remove_server(id).await;
}

async fn close_connections(connections: &mut JoinSet<()>) {
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "TURN stream worker stopped");
        }
    }
}

async fn expiry_reaper(inner: Arc<ServiceInner>) {
    let mut shutdown = inner.shutdown_tx.subscribe();
    let mut timer = interval(REAPER_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = timer.tick() => {
                for allocation_id in inner.authorization.expired_allocations() {
                    match inner.authorization.revoke(&allocation_id) {
                        Ok(username) => {
                            if let Err(error) = inner.delete_allocations(&username).await {
                                tracing::warn!(%error, "failed to remove expired TURN allocation");
                            }
                        }
                        Err(error) => tracing::debug!(%error, "expired TURN grant already retired"),
                    }
                }
                for (allocation_id, username) in inner.authorization.expired_peer_allocations() {
                    if let Err(error) = inner.delete_allocations(&username).await {
                        tracing::warn!(%error, allocation_id, "failed to remove TURN allocation after peer binding expiry");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
