//! Explicit backend HTTPS trust. Rustls validates the supplied local CA chain,
//! certificate validity, server name and handshake signatures on the fixed socket.
use super::*;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

#[derive(Clone)]
pub struct HttpsBackendTls {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}
impl HttpsBackendTls {
    pub fn new(
        server_name: String,
        locally_trusted_ca_der: Vec<Vec<u8>>,
    ) -> Result<Self, SdkError> {
        if server_name.len() > 253
            || locally_trusted_ca_der.is_empty()
            || locally_trusted_ca_der.len() > 8
            || locally_trusted_ca_der
                .iter()
                .any(|ca| ca.is_empty() || ca.len() > 16384)
        {
            return Err(SdkError::Invalid);
        }
        let name = ServerName::try_from(server_name).map_err(|_| SdkError::Invalid)?;
        let mut roots = RootCertStore::empty();
        for ca in locally_trusted_ca_der {
            roots
                .add(CertificateDer::from(ca))
                .map_err(|_| SdkError::Trust)?;
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| SdkError::Trust)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
            name,
        })
    }
    pub(super) async fn connect(self, target: TcpStream) -> std::io::Result<TlsStream<TcpStream>> {
        TlsConnector::from(self.config)
            .connect(self.name, target)
            .await
    }
}
#[cfg(test)]
mod tests;
