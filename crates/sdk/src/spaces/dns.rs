//! Same-account, one-space authoritative DNS. Names confer no traffic authority.
mod authority;
mod handler;

use crate::{Sdk, SdkError};
use authority::Authority;
use hickory_server::Server;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{RwLock, watch},
    task::JoinHandle,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const AUTHORIZATION_INTERVAL: Duration = Duration::from_millis(250);
const AUTOMATIC_BIND_ATTEMPTS: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum SpaceDnsError {
    #[error("space DNS requires an explicit loopback bind address and valid space")]
    InvalidConfiguration,
    #[error("space DNS session changed or expired")]
    SessionChanged,
    #[error("space DNS directory observation is invalid or expired")]
    InvalidDirectory,
    #[error("space DNS authorization timed out")]
    Timeout,
    #[error("space DNS authorization failed: {0}")]
    Authorization(#[from] SdkError),
    #[error("space DNS query authorization terminated the owner: {0}")]
    QueryAuthorization(Arc<SpaceDnsError>),
    #[error("space DNS socket failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("space DNS {transport} listener bind failed: {source}")]
    ListenerBind {
        transport: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("space DNS runtime stopped unexpectedly")]
    Runtime,
}

/// Owns both DNS sockets and their authorization monitor. Call `shutdown` before
/// replacing the selected space. Replacing/logging out the shared SDK terminates
/// this owner; it never silently rebinds to another account or session.
pub struct SpaceDns {
    address: SocketAddr,
    suffix: String,
    stop: watch::Sender<StopState>,
    task: Option<JoinHandle<Result<(), SpaceDnsError>>>,
    cleanup_deadline: Option<tokio::time::Instant>,
}

#[derive(Clone)]
pub(super) enum StopState {
    Running,
    Requested,
    Failed(Arc<SpaceDnsError>),
}

impl SpaceDns {
    pub async fn start(
        current: Arc<RwLock<Sdk>>,
        space: &str,
        bind: SocketAddr,
    ) -> Result<Self, SpaceDnsError> {
        if !bind.ip().is_loopback() || !nestlink_protocol::valid_id(space) {
            return Err(SpaceDnsError::InvalidConfiguration);
        }
        let authority = Arc::new(
            tokio::time::timeout(REQUEST_TIMEOUT, Authority::bind(current, space))
                .await
                .map_err(|_| SpaceDnsError::Timeout)??,
        );
        let suffix = authority.suffix.clone();
        let udp = UdpSocket::bind(bind)
            .await
            .map_err(|source| SpaceDnsError::ListenerBind {
                transport: "UDP",
                source,
            })?;
        let (udp, tcp, address) = finish_listener_bind(bind, udp).await?;
        let (stop, mut stopping) = watch::channel(StopState::Running);
        let mut server = Server::new(handler::Handler::new(authority.clone(), stop.clone()));
        server.register_socket(udp);
        server.register_listener(tcp, REQUEST_TIMEOUT, 8);
        let cancel = server.shutdown_token().clone();
        let task = tokio::spawn(async move {
            let authorization = async {
                loop {
                    tokio::select! {
                        biased;
                        changed = stopping.changed() => {
                            if changed.is_err() { return Ok(()); }
                            match &*stopping.borrow() {
                                StopState::Running => {},
                                StopState::Requested => return Ok(()),
                                StopState::Failed(cause) => return Err(SpaceDnsError::QueryAuthorization(cause.clone())),
                            }
                        }
                        _ = tokio::time::sleep(AUTHORIZATION_INTERVAL) => {
                            authority.observe().await?;
                        }
                    }
                }
            };
            let result = tokio::select! {
                result = server.block_until_done() => {
                    result.map_err(|_| SpaceDnsError::Runtime)?;
                    return Err(SpaceDnsError::Runtime);
                }
                result = authorization => result,
            };
            cancel.cancel();
            tokio::time::timeout(CLEANUP_TIMEOUT, server.shutdown_gracefully())
                .await
                .map_err(|_| SpaceDnsError::Timeout)?
                .map_err(|_| SpaceDnsError::Runtime)?;
            result
        });
        Ok(Self {
            address,
            suffix,
            stop,
            task: Some(task),
            cleanup_deadline: None,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn request_shutdown(&self) {
        self.stop.send_if_modified(|state| {
            if matches!(state, StopState::Running) {
                *state = StopState::Requested;
                true
            } else {
                false
            }
        });
    }

    pub async fn wait(&mut self) -> Result<(), SpaceDnsError> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = if let Some(deadline) = self.cleanup_deadline {
            match tokio::time::timeout_at(deadline, &mut *task).await {
                Ok(result) => result
                    .map_err(|_| SpaceDnsError::Runtime)
                    .and_then(|result| result),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(SpaceDnsError::Timeout)
                }
            }
        } else {
            task.await
                .map_err(|_| SpaceDnsError::Runtime)
                .and_then(|result| result)
        };
        self.task.take();
        result
    }

    pub async fn shutdown(&mut self) -> Result<(), SpaceDnsError> {
        self.request_shutdown();
        self.cleanup_deadline.get_or_insert_with(|| {
            tokio::time::Instant::now() + CLEANUP_TIMEOUT + Duration::from_secs(1)
        });
        // Retain the handle and original deadline in the owner across every
        // await. Canceling this future cannot detach the owned server task or
        // give a subsequent wait/shutdown a new cleanup budget.
        self.wait().await
    }
}

impl Drop for SpaceDns {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn finish_listener_bind(
    requested: SocketAddr,
    mut udp: UdpSocket,
) -> Result<(UdpSocket, TcpListener, SocketAddr), SpaceDnsError> {
    let mut attempts = 0;
    loop {
        let address = udp.local_addr()?;
        attempts += 1;
        match TcpListener::bind(address).await {
            Ok(tcp) => return Ok((udp, tcp, address)),
            Err(source)
                if requested.port() == 0
                    && source.kind() == std::io::ErrorKind::AddrInUse
                    && attempts < AUTOMATIC_BIND_ATTEMPTS =>
            {
                // UDP and TCP have separate port namespaces. An OS-assigned
                // UDP port can already belong to a TCP listener. Release this
                // attempt before asking for another automatic pair.
                drop(udp);
                udp = UdpSocket::bind(requested).await.map_err(|source| {
                    SpaceDnsError::ListenerBind {
                        transport: "UDP",
                        source,
                    }
                })?;
            }
            Err(source) => {
                return Err(SpaceDnsError::ListenerBind {
                    transport: "TCP",
                    source,
                });
            }
        }
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[tokio::test]
    async fn automatic_pair_retries_a_real_tcp_collision_and_releases_old_udp()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let requested: SocketAddr = "127.0.0.1:0".parse()?;
        let (udp, reserved_tcp, occupied) =
            finish_listener_bind(requested, UdpSocket::bind(requested).await?).await?;
        // Keep the real TCP listener, then reuse its UDP half as the first
        // automatic attempt so collision recovery is exercised deterministically.
        let (udp, tcp, address) = finish_listener_bind(requested, udp).await?;
        assert_ne!(address, occupied);
        assert_eq!(udp.local_addr()?, address);
        assert_eq!(tcp.local_addr()?, address);
        let reclaimed_udp = UdpSocket::bind(occupied).await?;
        assert_eq!(reserved_tcp.local_addr()?, reclaimed_udp.local_addr()?);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_port_collision_is_reported_and_releases_udp()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let requested: SocketAddr = "127.0.0.1:0".parse()?;
        let (udp, reserved_tcp, occupied) =
            finish_listener_bind(requested, UdpSocket::bind(requested).await?).await?;
        let Err(error) = finish_listener_bind(occupied, udp).await else {
            return Err("explicit TCP collision unexpectedly succeeded".into());
        };
        assert!(
            matches!(error, SpaceDnsError::ListenerBind { transport: "TCP", source }
            if source.kind() == std::io::ErrorKind::AddrInUse)
        );
        let reclaimed_udp = UdpSocket::bind(occupied).await?;
        assert_eq!(reserved_tcp.local_addr()?, reclaimed_udp.local_addr()?);
        Ok(())
    }
}
