use super::*;
use rustls::{ClientConfig, RootCertStore, pki_types::{CertificateDer, ServerName}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(windows)]
#[tokio::test]
async fn original_windows_listeners_refuse_reuse_address_replacement_until_closed() -> Result {
    for tcp in [true, false] {
        let listener_tcp = if tcp { Some(bind_tcp("127.0.0.1:0".parse()?).await?) } else { None };
        let listener_udp = if tcp { None } else { Some(bind_udp("127.0.0.1:0".parse()?).await?) };
        let address = match (&listener_tcp, &listener_udp) {
            (Some(listener), _) => listener.local_addr()?,
            (_, Some(listener)) => listener.local_addr()?,
            _ => return Err("missing original listener".into()),
        };
        let replacement = socket2::Socket::new(socket2::Domain::IPV4,
            if tcp { socket2::Type::STREAM } else { socket2::Type::DGRAM },
            Some(if tcp { socket2::Protocol::TCP } else { socket2::Protocol::UDP }))?;
        replacement.set_reuse_address(true)?;
        assert!(replacement.bind(&address.into()).is_err(), "a reuse-address socket shared the original {address}");
        drop(replacement);
        drop(listener_tcp);
        drop(listener_udp);
        if tcp { drop(bind_tcp(address).await?); } else { drop(bind_udp(address).await?); }
    }
    Ok(())
}

#[test]
fn local_tls_rejects_missing_oversized_or_mismatched_material() -> Result {
    assert!(LocalRawServiceTls::from_der(vec![], vec![1]).is_err());
    assert!(LocalRawServiceTls::from_der(vec![vec![1; 16385]], vec![1]).is_err());
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    assert!(LocalRawServiceTls::from_der(vec![first.cert.der().to_vec()], second.signing_key.serialize_der()).is_err());
    assert!(LocalRawServiceTls::from_der(vec![first.cert.der().to_vec()], first.signing_key.serialize_der()).is_ok());
    Ok(())
}

#[tokio::test]
async fn local_tls_uses_standard_name_validation_and_has_a_finite_handshake() -> Result {
    tokio::time::timeout(Duration::from_secs(10), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = LocalRawServiceTls::from_der(vec![certificate.cert.der().to_vec()], certificate.signing_key.serialize_der())?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(certificate.cert.der().to_vec()))?;
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = async {
            let (socket, _) = listener.accept().await?;
            assert!(tls.acceptor.accept(socket).await.is_err(), "the client rejects the wrong certificate name");
            let (socket, _) = listener.accept().await?;
            let mut stream = tls.acceptor.accept(socket).await?;
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await?;
            assert_eq!(request, [0, 255, 128, 13, 10]);
            stream.write_all(&request).await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let client = async {
            let wrong = connector.connect(ServerName::try_from("wrong.invalid")?, TcpStream::connect(address).await?).await;
            assert!(wrong.is_err());
            let mut stream = connector.connect(ServerName::try_from("localhost")?, TcpStream::connect(address).await?).await?;
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
            stream.write_all(&[0, 255, 128, 13, 10]).await?;
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await?;
            assert_eq!(reply, [0, 255, 128, 13, 10]);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (server, client) = tokio::join!(server, client);
        server?;
        client?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    Ok(())
}
