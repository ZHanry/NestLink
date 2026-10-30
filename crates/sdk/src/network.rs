//! One legacy connection owner on the product path. This facade reuses native
//! discovery, scheduling, TLS, SessionPermit proof and bounded business queues.
//! New space/path grants are not issued or negotiated by this adapter.
pub mod routed;
pub use crate::network_topology as topology;
use crate::{
    DeviceIdentity, NativeRelayRoute, Sdk,
    native::{NativeEndpoint, NativeMediaSessionOptions, NativeSession, SessionEstablishError},
};
use nestlink_remote::{RemoteError, StopReport, TransportOwner};
use nestlink_session::StopReason;
use nestlink_transport_stream::owner::TaskOwner;
use std::{
    future::Future,
    io,
    ops::{Deref, DerefMut},
    pin::Pin,
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    time::Instant,
};

const CLOSE_BUDGET: Duration = Duration::from_secs(5);

/// A unique endpoint owner before proof. It cannot be cloned or manufacture
/// business rights from discovery or a new network membership certificate.
pub struct LegacyEndpoint {
    endpoint: NativeEndpoint,
    cleanup: Option<EndpointCleanup>,
    cleanup_deadline: Option<Instant>,
}
impl LegacyEndpoint {
    pub fn new(endpoint: NativeEndpoint) -> Self {
        Self {
            endpoint,
            cleanup: None,
            cleanup_deadline: None,
        }
    }
    pub fn native(&self) -> &NativeEndpoint {
        &self.endpoint
    }
    pub async fn establish_with_media(
        mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        options: NativeMediaSessionOptions,
        routes: &[NativeRelayRoute<'_>],
        stun_servers: Vec<std::net::SocketAddr>,
        cancel: watch::Receiver<bool>,
    ) -> Result<LegacyConnection, SessionEstablishError> {
        let result = self
            .endpoint
            .establish_with_media(sdk, local, options, routes, stun_servers, cancel)
            .await;
        match result {
            Ok(session) => Ok(self.proved(session)),
            Err(error) => {
                self.close_and_wait(Instant::now() + CLOSE_BUDGET)
                    .await
                    .map_err(RemoteError::from)?;
                Err(error)
            }
        }
    }
    // Only a result of native endpoint proof enters this constructor. It is
    // crate-visible so real transport tests can exercise the owner without a
    // second management server or an alternate production scheduler.
    pub(crate) fn proved(self, session: NativeSession) -> LegacyConnection {
        LegacyConnection {
            endpoint: self,
            session,
            closed: false,
        }
    }
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = *self.cleanup_deadline.get_or_insert(deadline);
        if self.cleanup.is_none() {
            self.cleanup = Some(self.endpoint.take_cleanup()?);
        }
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.close_and_wait(deadline).await?;
        }
        Ok(())
    }
}
impl Drop for LegacyEndpoint {
    fn drop(&mut self) {
        self.endpoint.request_close();
    }
}

/// The proved business session and its actual original endpoint travel together.
/// Deref exposes the existing bounded channel API, not a second transport API.
pub struct LegacyConnection {
    endpoint: LegacyEndpoint,
    session: NativeSession,
    closed: bool,
}
impl Deref for LegacyConnection {
    type Target = NativeSession;
    fn deref(&self) -> &Self::Target {
        &self.session
    }
}
impl DerefMut for LegacyConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}
impl LegacyConnection {
    /// Wait for an externally stopped lease, business tasks, carrier tasks,
    /// endpoint monitor, and final physical UDP socket/poller release.
    pub async fn wait_stopped(&mut self) -> Result<StopReport, RemoteError> {
        let report = self.session.channels.wait_stopped().await;
        self.endpoint
            .close_and_wait(Instant::now() + CLOSE_BUDGET)
            .await?;
        let report = report?;
        self.closed = true;
        Ok(report)
    }
    /// A caller's absolute close deadline cannot be renewed by retrying or
    /// cancelling this wait. An outstanding external socket holder times out.
    pub async fn close_and_wait(
        &mut self,
        reason: StopReason,
        deadline: Instant,
    ) -> Result<StopReport, RemoteError> {
        self.session.control.stop(reason)?;
        self.endpoint.cleanup_deadline.get_or_insert(deadline);
        self.endpoint.endpoint.request_close();
        tokio::time::timeout_at(deadline, self.wait_stopped())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
    /// Only a completed receipt can be split for the existing bounded recovery
    /// flow. Retaining the now-closed endpoint keeps its lifecycle sender alive.
    pub fn into_stopped_parts(self) -> Result<(NativeSession, LegacyEndpoint), Box<Self>> {
        if self.closed {
            Ok((self.session, self.endpoint))
        } else {
            Err(Box::new(self))
        }
    }
}

pub(crate) struct EndpointCleanup {
    pub(crate) endpoints: Vec<quinn::Endpoint>,
    pub(crate) released: Vec<oneshot::Receiver<()>>,
    pub(crate) monitor: Option<TaskOwner>,
}
impl EndpointCleanup {
    fn request_close(&self) {
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"native owner stopping");
        }
        if let Some(monitor) = &self.monitor {
            monitor.request_close();
        }
    }
    async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        self.request_close();
        if let Some(monitor) = &self.monitor {
            monitor.close_and_wait(deadline).await?;
        }
        self.monitor = None;
        while let Some(endpoint) = self.endpoints.first() {
            tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.endpoints.remove(0);
        }
        while let Some(receipt) = self.released.first_mut() {
            tokio::time::timeout_at(deadline, receipt)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                .map_err(|_| io::Error::other("native UDP release was not confirmed"))?;
            self.released.remove(0);
        }
        Ok(())
    }
}
impl Drop for EndpointCleanup {
    fn drop(&mut self) {
        self.request_close();
    }
}

pub(crate) enum CarrierOwner {
    Quic(nestlink_transport_quic::node::Carrier),
    Wss(TaskOwner),
}
impl TransportOwner for CarrierOwner {
    fn request_close(&self) {
        match self {
            Self::Quic(carrier) => carrier.request_close(),
            Self::Wss(pump) => pump.request_close(),
        }
    }
    fn close_and_wait(
        &mut self,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            match self {
                Self::Quic(carrier) => carrier.close_and_wait(deadline).await,
                Self::Wss(pump) => pump.close_and_wait(deadline).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_tests::{loopback_policy, permit};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[tokio::test]
    async fn endpoint_receipt_cannot_claim_release_while_a_socket_holder_remains() -> Result {
        let local = DeviceIdentity::generate();
        let peer = DeviceIdentity::generate();
        let endpoint = NativeEndpoint::new(
            "127.0.0.1:0".parse()?,
            &local,
            &peer.identity.public_key(),
            permit(&local, &peer)?,
            vec![],
            loopback_policy()?,
        )?;
        let address = endpoint.local_addr()?;
        let socket = endpoint.discovery_socket().ok_or("missing socket")?;
        let mut owner = LegacyEndpoint::new(endpoint);
        let deadline = Instant::now() + Duration::from_millis(100);
        assert_eq!(
            owner
                .close_and_wait(deadline)
                .await
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(
            std::net::UdpSocket::bind(address)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        drop(socket);
        // A timed-out wait never gets a fresh budget. A later successful poll
        // is allowed only if the original receipt is already ready.
        let _ = owner.close_and_wait(Instant::now() + CLOSE_BUDGET).await;
        let rebound = std::net::UdpSocket::bind(address)?;
        drop(rebound);
        Ok(())
    }
}
