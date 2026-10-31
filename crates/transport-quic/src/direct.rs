//! Ordinary pinned remote QUIC with the existing physical socket/poller receipt.
use super::*;
use std::io;
use tokio::{sync::oneshot, time::Instant};

/// Retains the original endpoint and its unique physical release observer.
/// Callers drop all connection/endpoint clones before awaiting final release.
pub struct DirectEndpoint {
    endpoint: Option<Endpoint>,
    released: Option<oneshot::Receiver<()>>,
}
impl DirectEndpoint {
    fn bind(address: SocketAddr) -> Result<Self> {
        let (endpoint, released) = service::socket::client(address)?;
        Ok(Self {
            endpoint: Some(endpoint),
            released: Some(released),
        })
    }
    pub fn listener(
        address: SocketAddr,
        identity: &InstallationIdentity,
        peer_fingerprint: [u8; 32],
    ) -> Result<Self> {
        let crypto = QuicServerConfig::try_from(tls::server_config(identity, peer_fingerprint)?)?;
        let mut config = ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        let owner = Self::bind(address)?;
        owner.endpoint()?.set_server_config(Some(config));
        Ok(owner)
    }
    pub fn connector(
        address: SocketAddr,
        identity: &InstallationIdentity,
        peer_fingerprint: [u8; 32],
    ) -> Result<Self> {
        let crypto = QuicClientConfig::try_from(tls::client_config(identity, peer_fingerprint)?)?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());
        let mut owner = Self::bind(address)?;
        owner.endpoint.as_mut().ok_or_else(|| io::Error::other("direct endpoint closed"))?
            .set_default_client_config(config);
        Ok(owner)
    }
    pub fn endpoint(&self) -> io::Result<&Endpoint> {
        self.endpoint.as_ref().ok_or_else(|| io::Error::other("direct endpoint closed"))
    }
    pub fn request_close(&self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"direct remote owner stopping");
        }
    }
    /// Cancellation keeps the original receipt owned. Idle and task join alone
    /// cannot report physical release while any actual socket/poller survives.
    pub async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        self.request_close();
        if let Some(endpoint) = &self.endpoint {
            tokio::time::timeout_at(deadline, endpoint.wait_idle()).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct endpoint still active"))?;
        }
        drop(self.endpoint.take());
        if let Some(released) = &mut self.released {
            tokio::time::timeout_at(deadline, released).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP socket release pending"))?
                .map_err(|_| io::Error::other("direct UDP socket release was not confirmed"))?;
            self.released = None;
        }
        Ok(())
    }
}
impl Drop for DirectEndpoint {
    fn drop(&mut self) {
        self.request_close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_release_retains_original_receipt_across_cancelled_wait() -> Result<()> {
        let identity = InstallationIdentity::generate();
        let peer = InstallationIdentity::generate();
        let mut owner = DirectEndpoint::listener("127.0.0.1:0".parse()?, &identity, peer.fingerprint())?;
        let address = owner.endpoint()?.local_addr()?;
        let retained = owner.endpoint()?.clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(tokio::time::timeout(Duration::from_millis(20), owner.close_and_wait(deadline)).await.is_err());
        assert!(owner.released.is_some());
        assert!(std::net::UdpSocket::bind(address).is_err());
        drop(retained);
        owner.close_and_wait(deadline).await?;
        let _rebound = std::net::UdpSocket::bind(address)?;
        Ok(())
    }
}
