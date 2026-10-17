use nestlink_identity::InstallationIdentity;
use nestlink_transport_quic::{connect, connector, listener};
use nestlink_transport_stream::{Channel, read_frame, write_frame};
use std::time::Duration;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[tokio::test]
async fn real_udp_quic_mutual_key_binding_and_channel_frames() -> Result {
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
    let client = connector("127.0.0.1:0".parse()?, &controller, host.fingerprint())?;
    let address = server.local_addr()?;
    let task = tokio::spawn(async move {
        let incoming = server.accept().await.ok_or("no incoming QUIC connection")?;
        let connection = incoming.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;
        let frame = read_frame(&mut receive).await?;
        assert_eq!(frame.channel, Channel::Input);
        assert_eq!(frame.payload, b"key-release");
        write_frame(&mut send, Channel::Control, b"ack").await?;
        send.finish()?;
        send.stopped().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = connect(&client, address, Duration::from_secs(3)).await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_frame(&mut send, Channel::Input, b"key-release").await?;
    let response = read_frame(&mut receive).await?;
    assert_eq!(response.payload, b"ack");
    drop(receive);
    connection.close(0_u8.into(), b"done");
    task.await??;
    Ok(())
}
#[tokio::test]
async fn wrong_host_key_is_rejected_on_real_socket() -> Result {
    let host = InstallationIdentity::generate();
    let controller = InstallationIdentity::generate();
    let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
    let client = connector(
        "127.0.0.1:0".parse()?,
        &controller,
        InstallationIdentity::generate().fingerprint(),
    )?;
    let address = server.local_addr()?;
    let task = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });
    assert!(
        connect(&client, address, Duration::from_secs(3))
            .await
            .is_err()
    );
    task.await?;
    Ok(())
}
