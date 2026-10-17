use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Fixture {
    ca: Vec<u8>,
    server: Arc<ServerConfig>,
}
fn fixture(expired: bool) -> Result<Fixture> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["backend.nestlink.test".into()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if expired {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    let certificate = params.signed_by(&key, &issuer)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok(Fixture {
        ca: ca.der().to_vec(),
        server: Arc::new(server),
    })
}
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn exchange(tls: HttpsBackendTls, server: Arc<ServerConfig>) -> Result<bool> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixed = listener.local_addr()?;
    let mut worker = Abort(tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let Ok(mut tls) = TlsAcceptor::from(server).accept(socket).await else {
            return Ok::<_, std::io::Error>(false);
        };
        let mut request = [0; 7];
        tls.read_exact(&mut request).await?;
        if &request != b"request" {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        tls.write_all(b"encrypted response").await?;
        tls.shutdown().await?;
        Ok(true)
    }));
    // The TLS adapter receives only this connected socket; the server name
    // participates in certificate validation and never selects a remote IP.
    let connected = TcpStream::connect(fixed).await?;
    let success = match tls.connect(connected).await {
        Ok(mut stream) => {
            stream.write_all(b"request").await?;
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await?;
            assert_eq!(reply, b"encrypted response");
            true
        }
        Err(_) => false,
    };
    let accepted = tokio::time::timeout(Duration::from_secs(2), &mut worker.0).await???;
    assert_eq!(success, accepted);
    Ok(success)
}

#[tokio::test]
async fn fixed_backend_tls_checks_actual_chain_name_and_certificate_expiry() -> Result {
    let valid = fixture(false)?;
    let unknown = fixture(false)?;
    let expired = fixture(true)?;
    for (name, root, server, expected) in [
        (
            "backend.nestlink.test",
            valid.ca.clone(),
            valid.server.clone(),
            true,
        ),
        (
            "wrong.nestlink.test",
            valid.ca.clone(),
            valid.server.clone(),
            false,
        ),
        ("backend.nestlink.test", unknown.ca, valid.server, false),
        ("backend.nestlink.test", expired.ca, expired.server, false),
    ] {
        let tls = HttpsBackendTls::new(name.into(), vec![root])?;
        assert_eq!(exchange(tls, server).await?, expected);
    }
    Ok(())
}

#[test]
fn backend_tls_refuses_empty_unbounded_or_invalid_local_trust() {
    assert!(HttpsBackendTls::new("backend.nestlink.test".into(), vec![]).is_err());
    assert!(HttpsBackendTls::new("backend.nestlink.test".into(), vec![vec![0; 16385]]).is_err());
    assert!(HttpsBackendTls::new("backend.nestlink.test".into(), vec![vec![0]; 9]).is_err());
    assert!(HttpsBackendTls::new("backend.nestlink.test".into(), vec![vec![0]]).is_err());
}
