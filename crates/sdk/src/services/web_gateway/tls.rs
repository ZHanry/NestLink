//! Each owner has a fresh upstream TLS identity. Caddy authenticates this
//! identity before it sends the private-hop token or any browser credentials.
use crate::SdkError;
use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

pub(super) struct UpstreamTls {
    pub(super) acceptor: tokio_rustls::TlsAcceptor,
    pub(super) certificate: String,
    pub(super) server_name: String,
}

impl UpstreamTls {
    pub(super) fn generate(lifetime: Duration) -> Result<Self, SdkError> {
        Self::create(lifetime).map_err(|error| std::io::Error::other(error).into())
    }

    fn create(lifetime: Duration) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now();
        let not_before = (now - Duration::from_secs(60)).into();
        let not_after = (now + lifetime + Duration::from_secs(60)).into();
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key)?;
        let certificate = STANDARD.encode(ca.der());
        let issuer = Issuer::new(ca_params, ca_key);
        let server_name = format!(
            "{}.private-web.nestlink.invalid",
            nestlink_auth::random_id()
        );
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![server_name.clone()])?;
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params.signed_by(&key, &issuer)?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            certificate,
            server_name,
        })
    }
}
