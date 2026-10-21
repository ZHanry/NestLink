use nestlink_identity::InstallationIdentity;
use nestlink_transport_stream::{Channel, connect, read_frame, tls, write_frame};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn public_carrier_tls_does_not_accept_an_installation_self_signed_certificate() -> Result {
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls::server_config(
        &host,
        controller.fingerprint(),
    )?));
    let mut config = tls::public_client_config()?;
    config.alpn_protocols = vec![nestlink_protocol::ALPN.as_bytes().to_vec()];
    let server = async {
        let (tcp, _) = listener.accept().await?;
        assert!(acceptor.accept(tcp).await.is_err());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let client = async {
        let error = connect(address, config, Duration::from_secs(3))
            .await
            .err()
            .ok_or("public TLS accepted an untrusted installation certificate")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ));
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(server, client)
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn direct_tcp_tls_checks_both_installation_keys() -> Result {
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls::server_config(
        &host,
        controller.fingerprint(),
    )?));
    let config = tls::client_config(&controller, host.fingerprint())?;
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = acceptor.accept(tcp).await?;
        let frame = read_frame(&mut stream).await?;
        assert_eq!(frame.payload, b"direct-path");
        write_frame(&mut stream, Channel::Control, b"accepted").await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut stream = connect(address, config, Duration::from_secs(3)).await?;
    write_frame(&mut stream, Channel::Control, b"direct-path").await?;
    assert_eq!(read_frame(&mut stream).await?.payload, b"accepted");
    task.await??;
    Ok(())
}
#[tokio::test]
async fn invalid_frame_length_is_rejected_before_payload_allocation() -> Result {
    use tokio::io::AsyncWriteExt;
    let (mut a, mut b) = tokio::io::duplex(32);
    a.write_all(&[1, 2, 0, 1, 0, 1]).await?;
    assert!(read_frame(&mut b).await.is_err());
    Ok(())
}
