//! Pinned installation Ed25519 keys plus rustls TLS transcript signature checks.
use nestlink_identity::{InstallationIdentity, digest};
use nestlink_protocol::ALPN;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::Arc;

/// Service carriers reuse the installation-key pin and TLS transcript verifier,
/// while negotiating a distinct application protocol and service-only proofs.
pub fn service_client_config(
    identity: &InstallationIdentity,
    edge_fingerprint: [u8; 32],
) -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = client_config(identity, edge_fingerprint)?;
    config.alpn_protocols =
        vec![nestlink_protocol::service_plane::publication::SERVICE_ALPN.to_vec()];
    Ok(config)
}
pub fn service_node_server_config(
    identity: &nestlink_identity::nodes::NodeIdentity,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = node_server_config(identity)?;
    config.alpn_protocols =
        vec![nestlink_protocol::service_plane::publication::SERVICE_ALPN.to_vec()];
    Ok(config)
}
use x509_parser::prelude::FromDer;

#[derive(Debug)]
struct ExpectedPeer {
    fingerprint: [u8; 32],
    hints: Vec<DistinguishedName>,
}
impl ExpectedPeer {
    fn check(&self, certificate: &CertificateDer<'_>) -> Result<(), Error> {
        let (rest, certificate) =
            x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
                .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let spki = certificate.public_key();
        if !rest.is_empty()
            || spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
            || spki.subject_public_key.unused_bits != 0
            || spki.subject_public_key.data.len() != 32
            || digest(&spki.subject_public_key.data) != self.fingerprint
        {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(())
    }
}
impl ServerCertVerifier for ExpectedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General("unexpected peer certificate chain".into()));
        }
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for ExpectedPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General("unexpected peer certificate chain".into()));
        }
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
fn certificate(
    identity: &InstallationIdentity,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    encoded_certificate(&identity.tls_pkcs8()?)
}
fn encoded_certificate(
    encoded: &[u8],
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(encoded.to_vec()),
        &rcgen::PKCS_ED25519,
    )?;
    let mut params = rcgen::CertificateParams::new(vec!["peer.nestlink.invalid".into()])?;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = params.self_signed(&pair)?.der().clone();
    Ok((cert, PrivatePkcs8KeyDer::from(encoded.to_vec())))
}
/// A node authenticates endpoints by signed allocation/socket proofs after TLS.
/// Its certificate key is pinned by the control-signed allocation.
pub fn node_server_config(
    identity: &nestlink_identity::nodes::NodeIdentity,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = encoded_certificate(&identity.tls_pkcs8()?)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    config.alpn_protocols = vec![nestlink_protocol::relay_datagram::ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok(config)
}
pub fn client_config(
    identity: &InstallationIdentity,
    expected_peer_fingerprint: [u8; 32],
) -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = certificate(identity)?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ExpectedPeer {
            fingerprint: expected_peer_fingerprint,
            hints: vec![],
        }))
        .with_client_auth_cert(vec![cert], key.into())?;
    config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}
pub fn server_config(
    identity: &InstallationIdentity,
    expected_peer_fingerprint: [u8; 32],
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = certificate(identity)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(ExpectedPeer {
            fingerprint: expected_peer_fingerprint,
            hints: vec![],
        }))
        .with_single_cert(vec![cert], key.into())?;
    config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok(config)
}
