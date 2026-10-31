//! Explicitly approved direct TLS carrier for the same original offline owner.
use super::*;
use nestlink_transport_stream::tls;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// One accepted connection consumes this listener. Dropping the listener stops
/// acceptance; live business and its cleanup belong to the original runtime.
pub struct OfflineRemoteTlsListener {
    owner: Arc<Inner>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

fn valid_address(address: SocketAddr, listener: bool) -> bool {
    !address.ip().is_unspecified() && !address.ip().is_multicast()
        && (listener || address.port() != 0)
}
impl OfflineRemoteOwner {
    pub async fn listen_tls(&self, address: SocketAddr) -> Result<OfflineRemoteTlsListener, SdkError> {
        if self.0.role != EndpointRole::Host || !valid_address(address, true) {
            return Err(SdkError::Invalid);
        }
        self.0.authority.check(wall()?)?;
        let claims = self.0.authority.claims()?;
        if !claims.connection.direct_transports.contains(&OfflineDirectTransport::Tls) {
            return Err(SdkError::Trust);
        }
        let config = tls::server_config(&self.0.local.identity, digest(&claims.members[0].public_key))
            .map_err(SdkError::NodeQuic)?;
        let listener = TcpListener::bind(address).await?;
        self.0.authority.check(wall()?)?;
        Ok(OfflineRemoteTlsListener {
            owner: self.0.clone(), listener, acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
    /// This is an explicit choice among the signed direct transports, not an
    /// automatic downgrade or a continuation of an expired online transport.
    pub async fn connect_tls(
        &self,
        peer: SocketAddr,
        lifecycle: SessionLifecycle,
    ) -> Result<OfflineRemoteRuntime, SdkError> {
        if self.0.role != EndpointRole::Controller || !valid_address(peer, false) {
            return Err(SdkError::Invalid);
        }
        self.0.authority.reserve_attempt(wall()?, OfflineDirectTransport::Tls)?;
        let key = self.0.authority.claims()?.members[1].public_key;
        let config = tls::client_config(&self.0.local.identity, digest(&key))
            .map_err(SdkError::NodeQuic)?;
        let stream = tokio::time::timeout(self.0.budget()?, async {
            let tcp = TcpStream::connect(peer).await?;
            tcp.set_nodelay(true)?;
            let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
                .map_err(|_| io::Error::other("invalid internal TLS name"))?;
            TlsConnector::from(Arc::new(config)).connect(name, tcp).await
        }).await.map_err(|_| SdkError::Timeout)??;
        self.0.finish_tls(stream.into(), lifecycle).await
    }
}
impl OfflineRemoteTlsListener {
    pub fn address(&self) -> Result<SocketAddr, SdkError> {
        Ok(self.listener.local_addr()?)
    }
    pub async fn accept(self, lifecycle: SessionLifecycle) -> Result<OfflineRemoteRuntime, SdkError> {
        let (tcp, _) = tokio::time::timeout(self.owner.budget()?, self.listener.accept())
            .await.map_err(|_| SdkError::Timeout)??;
        self.owner.authority.reserve_attempt(wall()?, OfflineDirectTransport::Tls)?;
        tcp.set_nodelay(true)?;
        let stream = tokio::time::timeout(self.owner.budget()?, self.acceptor.accept(tcp))
            .await.map_err(|_| SdkError::Timeout)??;
        drop(self.listener);
        self.owner.finish_tls(stream.into(), lifecycle).await
    }
}
impl Inner {
    async fn finish_tls(
        self: &Arc<Self>,
        mut stream: TlsStream<TcpStream>,
        lifecycle: SessionLifecycle,
    ) -> Result<OfflineRemoteRuntime, SdkError> {
        let index = match self.role {EndpointRole::Controller => 0, EndpointRole::Host => 1};
        let peer = self.authority.claims()?.members[1-index].public_key;
        let (tcp, state) = stream.get_ref();
        let local_address = tcp.local_addr()?;
        let certificates = state.peer_certificates().filter(|certs| certs.len() == 1).ok_or(SdkError::Trust)?;
        if state.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || state.alpn_protocol() != Some(ALPN.as_bytes())
            || tls::certificate_fingerprint(&certificates[0]).map_err(|_| SdkError::Trust)? != digest(&peer)
        {
            return Err(SdkError::Trust);
        }
        tokio::time::timeout(self.budget()?, async {
            let (mut read, mut write) = tokio::io::split(&mut stream);
            crate::offline_channel::prove(&self.authority, &self.local, &mut read, &mut write,
                index as u8, OfflineDirectTransport::Tls, &peer).await
        }).await.map_err(|_| SdkError::Timeout)??;
        let clock = RuntimeClock::default();
        let session = Session::activate_offline(self.original.clone(), self.binding.clone(),
            self.authority.clone(), clock.sample()?)?;
        let channels = crate::native::authorize_stream(stream, SessionSetup {
            session, path: Path::Direct, role: self.role, clock, lifecycle,
        }, &self.local.identity, &peer).await?;
        Ok(self.runtime(channels, local_address))
    }
}
