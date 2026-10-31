//! Same-account, one-space authoritative DNS. Names confer no traffic authority.
mod authority;
mod handler;

use crate::{Sdk, SdkError};
use authority::Authority;
use hickory_server::Server;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::{TcpListener, UdpSocket}, sync::{RwLock, watch}, task::JoinHandle};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const AUTHORIZATION_INTERVAL: Duration = Duration::from_millis(250);

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
        let authority = Arc::new(tokio::time::timeout(REQUEST_TIMEOUT, Authority::bind(current, space))
            .await.map_err(|_| SpaceDnsError::Timeout)??);
        let suffix = authority.suffix.clone();
        let udp = UdpSocket::bind(bind).await?;
        let address = udp.local_addr()?;
        // Either both protocols bind the same port, or neither remains owned.
        let tcp = TcpListener::bind(address).await?;
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
                .await.map_err(|_| SpaceDnsError::Timeout)?
                .map_err(|_| SpaceDnsError::Runtime)?;
            result
        });
        Ok(Self { address, suffix, stop, task: Some(task), cleanup_deadline: None })
    }

    pub fn local_addr(&self) -> SocketAddr { self.address }
    pub fn suffix(&self) -> &str { &self.suffix }
    pub fn is_finished(&self) -> bool { self.task.as_ref().is_none_or(JoinHandle::is_finished) }
    pub fn request_shutdown(&self) {
        self.stop.send_if_modified(|state| {
            if matches!(state, StopState::Running) { *state = StopState::Requested; true } else { false }
        });
    }

    pub async fn wait(&mut self) -> Result<(), SpaceDnsError> {
        let Some(task) = self.task.as_mut() else { return Ok(()); };
        let result = if let Some(deadline) = self.cleanup_deadline {
            match tokio::time::timeout_at(deadline, &mut *task).await {
                Ok(result) => result.map_err(|_| SpaceDnsError::Runtime).and_then(|result| result),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(SpaceDnsError::Timeout)
                }
            }
        } else { task.await.map_err(|_| SpaceDnsError::Runtime).and_then(|result| result) };
        self.task.take();
        result
    }

    pub async fn shutdown(&mut self) -> Result<(), SpaceDnsError> {
        self.request_shutdown();
        self.cleanup_deadline.get_or_insert_with(|| tokio::time::Instant::now() + CLEANUP_TIMEOUT + Duration::from_secs(1));
        // Retain the handle and original deadline in the owner across every
        // await. Canceling this future cannot detach the owned server task or
        // give a subsequent wait/shutdown a new cleanup budget.
        self.wait().await
    }
}

impl Drop for SpaceDns {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() { task.abort(); }
    }
}
