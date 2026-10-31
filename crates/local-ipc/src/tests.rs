use super::*;
use serde_json::json;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn headless_session_owner_and_daemon_share_one_singleton_without_fake_endpoint() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let headless = HeadlessRuntimeLease::acquire(&directory)?;
    assert!(!directory.join("daemon-endpoint.json").exists());
    assert!(matches!(LocalServer::bind(&directory).await, Err(Error::AlreadyRunning)));
    assert!(matches!(HeadlessRuntimeLease::acquire(&directory), Err(Error::AlreadyRunning)));
    drop(headless);
    let daemon = LocalServer::bind(&directory).await?;
    assert!(matches!(HeadlessRuntimeLease::acquire(&directory), Err(Error::AlreadyRunning)));
    drop(daemon);
    let _headless = HeadlessRuntimeLease::acquire(&directory)?;
    Ok(())
}

#[tokio::test]
async fn duplex_partial_prefix_cancel_poison_is_shared_with_writer() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, accepted) = pair(&daemon, &directory).await?;
    let (mut read, mut write, _owner) = accepted.into_duplex()?;
    client.stream.write_all(&[0, 0]).await?;
    client.stream.flush().await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read.receive_bytes(4096))
            .await
            .is_err()
    );
    assert!(matches!(
        write.send(&json!({"must":"fail"})).await,
        Err(Error::Stopped)
    ));
    assert!(matches!(
        read.receive_bytes(4096).await,
        Err(Error::Stopped)
    ));
    Ok(())
}

#[tokio::test]
async fn duplex_owner_drop_wakes_idle_reader_and_retires_writer() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (_client, accepted) = pair(&daemon, &directory).await?;
    let (mut read, mut write, owner) = accepted.into_duplex()?;
    let pending = tokio::spawn(async move { read.receive_bytes(4096).await });
    tokio::task::yield_now().await;
    drop(owner);
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(100), pending).await??,
        Err(Error::Stopped)
    ));
    assert!(matches!(
        write.send(&json!({"must":"fail"})).await,
        Err(Error::Stopped)
    ));
    Ok(())
}

#[tokio::test]
async fn cancelling_a_partial_frame_receive_permanently_retires_that_stream() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    client.stream.write_all(&[0, 0]).await?;
    client.stream.flush().await?;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            accepted.receive::<serde_json::Value>()
        )
        .await
        .is_err()
    );
    assert!(matches!(
        accepted.receive::<serde_json::Value>().await,
        Err(Error::Stopped)
    ));
    assert!(matches!(
        accepted.send(&json!({"response":1})).await,
        Err(Error::Stopped)
    ));
    Ok(())
}

#[tokio::test]
async fn binary_video_round_trip_uses_the_authenticated_tls_stream_and_never_returns_to_json()
-> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    assert_eq!(client.runtime_id(), daemon.runtime_id());

    let request_id = "00000000-0000-4000-8000-000000000002";
    let width = 640_u32;
    let height = 100_u32;
    let payload_bytes = (width * height * 4) as usize;
    let mut header = [0_u8; VIDEO_HEADER_BYTES];
    header[..8].copy_from_slice(b"NLVID001");
    header[8] = 2;
    header[9] = 1;
    header[12..48].copy_from_slice(daemon.runtime_id().as_bytes());
    header[48..84].copy_from_slice(request_id.as_bytes());
    header[84..92].copy_from_slice(&7_u64.to_be_bytes());
    header[92..100].copy_from_slice(&9_u64.to_be_bytes());
    header[100..108].copy_from_slice(&2_u64.to_be_bytes());
    header[112..120].copy_from_slice(&3_u64.to_be_bytes());
    header[120..128].copy_from_slice(&90_u64.to_be_bytes());
    header[128..132].copy_from_slice(&width.to_be_bytes());
    header[132..136].copy_from_slice(&height.to_be_bytes());
    header[136..140].copy_from_slice(&(payload_bytes as u32).to_be_bytes());
    let payload: Vec<u8> = (0..payload_bytes)
        .map(|index| (index % 251) as u8)
        .collect();
    // Drive both ends of the real socket concurrently: a correct bounded
    // transport may apply backpressure before this entire frame is buffered.
    let send = async {
        client.send_video_header(&header, payload.len()).await?;
        for chunk in payload.chunks(VIDEO_CHUNK_BYTES) {
            client.send_video_payload_chunk(chunk).await?;
        }
        Ok::<_, Error>(())
    };
    let receive = async {
        let (received_header, received_bytes) = accepted.receive_video_header().await?;
        assert_eq!(received_header, header);
        assert_eq!(received_bytes, payload_bytes);
        let received = accepted.receive_video_payload().await?;
        assert_eq!(received.as_slice(), payload.as_slice());
        Ok::<_, Error>(())
    };
    tokio::try_join!(send, receive)?;
    assert!(matches!(
        client
            .send(&json!({"must":"stay JSON only before video"}))
            .await,
        Err(Error::Stopped)
    ));
    assert!(matches!(
        accepted.receive::<serde_json::Value>().await,
        Err(Error::Stopped)
    ));
    Ok(())
}

#[tokio::test]
async fn video_payload_budget_and_wire_length_are_checked_before_payload_allocation() -> TestResult
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    let header = [0_u8; VIDEO_HEADER_BYTES];

    assert!(matches!(
        client
            .send_video_header(&header, VIDEO_PAYLOAD_BYTES + 1)
            .await,
        Err(Error::Protocol)
    ));
    client
        .send(&json!({"still":"JSON before mode switch"}))
        .await?;
    assert_eq!(
        accepted.receive::<serde_json::Value>().await?["still"],
        "JSON before mode switch"
    );
    drop((client, accepted));

    for body_size in [
        0_u32,
        (VIDEO_HEADER_BYTES - 1) as u32,
        (VIDEO_FRAME_BYTES + 1) as u32,
        u32::MAX,
    ] {
        let (mut client, mut accepted) = pair(&daemon, &directory).await?;
        client.stream.write_u32(body_size).await?;
        client.stream.flush().await?;
        assert!(matches!(
            accepted.receive_video_header().await,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            accepted.receive_video_header().await,
            Err(Error::Protocol)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_backpressured_video_chunk_permanently_retires_the_tls_stream() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    let header = [0_u8; VIDEO_HEADER_BYTES];
    client
        .send_video_header(&header, VIDEO_PAYLOAD_BYTES)
        .await?;
    let (_, declared_bytes) = accepted.receive_video_header().await?;
    assert_eq!(declared_bytes, VIDEO_PAYLOAD_BYTES);

    // Keep the authenticated peer alive but stop reading its body. Once the
    // TCP/TLS send window fills, cancelling the pending bounded chunk must
    // poison the stream rather than permit another frame to reuse its prefix.
    let chunk = vec![0x5a_u8; VIDEO_CHUNK_BYTES];
    let mut cancelled = false;
    let mut sent_chunks = 0;
    for _ in 0..VIDEO_PAYLOAD_BYTES / VIDEO_CHUNK_BYTES {
        match tokio::time::timeout(
            Duration::from_millis(250),
            client.send_video_payload_chunk(&chunk),
        )
        .await
        {
            Ok(Ok(())) => sent_chunks += 1,
            Err(_) => {
                cancelled = true;
                break;
            }
            Ok(Err(Error::Timeout)) => {
                cancelled = true;
                break;
            }
            Ok(Err(error)) => {
                return Err(format!("video chunk failed unexpectedly: {error}").into());
            }
        }
    }
    assert!(
        sent_chunks > 0,
        "the TLS peer accepted no initial video chunks"
    );
    assert!(
        cancelled,
        "an unread 64 MiB video body did not backpressure the sender"
    );
    assert!(matches!(
        client.send_video_payload_chunk(&chunk).await,
        Err(Error::Protocol)
    ));
    assert!(matches!(
        client.send(&json!({"replay":true})).await,
        Err(Error::Stopped)
    ));
    Ok(())
}

#[tokio::test]
async fn cancelling_mid_video_payload_read_drops_the_zeroizing_buffer_and_retires_tls() -> TestResult
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    let header = [0_u8; VIDEO_HEADER_BYTES];
    client.send_video_header(&header, 1024 * 1024).await?;
    let (_, payload_bytes) = accepted.receive_video_header().await?;
    assert_eq!(payload_bytes, 1024 * 1024);

    // The TLS peer keeps the connection open without sending pixels. The
    // cancelled read owns a Zeroizing allocation, and that stream cannot be
    // reused to parse another frame or fall back to JSON.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), accepted.receive_video_payload(),)
            .await
            .is_err()
    );
    assert!(matches!(
        accepted.receive_video_payload().await,
        Err(Error::Protocol)
    ));
    assert!(matches!(
        accepted.receive_video_header().await,
        Err(Error::Protocol)
    ));
    assert!(matches!(
        accepted.receive::<serde_json::Value>().await,
        Err(Error::Stopped)
    ));
    Ok(())
}

async fn pair(server: &LocalServer, directory: &Path) -> TestResult<(LocalStream, LocalStream)> {
    let client = LocalStream::connect(directory);
    let accept = async { server.accept().await?.authenticate().await };
    let (client, server) = tokio::join!(client, accept);
    Ok((client?, server?))
}

#[tokio::test]
async fn real_tls_ipc_owns_singleton_and_shutdown_interrupts_idle_clients() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let old_runtime = daemon.runtime_id().to_owned();
    match LocalServer::bind(&directory).await {
        Err(Error::AlreadyRunning) => {}
        Err(error) => {
            return Err(format!("second daemon returned an unexpected error: {error}").into());
        }
        Ok(_) => return Err("second daemon bypassed the held OS singleton lock".into()),
    }
    let (mut client, mut accepted) = pair(&daemon, &directory).await?;
    assert_eq!(client.runtime_id(), old_runtime);
    client
        .send(&json!({"request_id":1,"action":"devices"}))
        .await?;
    let action: serde_json::Value = accepted.receive().await?;
    assert_eq!(action["request_id"], 1);
    accepted.send(&json!({"request_id":1,"devices":[]})).await?;
    let response: serde_json::Value = client.receive().await?;
    assert_eq!(response["devices"], json!([]));
    let wait = accepted.receive::<serde_json::Value>();
    daemon.stop();
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(250), wait).await?,
        Err(Error::Stopped)
    ));
    drop(client);
    drop(accepted);
    drop(daemon);
    assert!(!directory.join("daemon-endpoint.json").exists());
    let replacement = LocalServer::bind(&directory).await?;
    assert_ne!(replacement.runtime_id(), old_runtime);
    let (_client, _accepted) = pair(&replacement, &directory).await?;
    Ok(())
}

#[tokio::test]
async fn stale_runtime_manifest_is_rejected_by_the_authenticated_daemon_hello() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let mut endpoint = state::endpoint(&directory)?;
    endpoint.runtime_id = nestlink_auth::random_id();
    std::fs::write(
        directory.join("daemon-endpoint.json"),
        serde_json::to_vec(&endpoint)?,
    )?;
    let (client, accepted) = tokio::join!(LocalStream::connect(&directory), async {
        daemon.accept().await?.authenticate().await
    });
    let _accepted = accepted?;
    assert!(matches!(client, Err(Error::Authentication)));
    Ok(())
}

#[tokio::test]
async fn substituting_the_local_key_cannot_authenticate_to_a_live_daemon() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    std::fs::remove_file(directory.join("local-ipc.key"))?;
    nestlink_platform_security::create_key(
        &directory.join("local-ipc.key"),
        &nestlink_auth::random_bytes::<32>(),
    )?;
    let (client, accepted) = tokio::join!(LocalStream::connect(&directory), async {
        daemon.accept().await?.authenticate().await
    });
    assert!(matches!(client, Err(Error::Authentication)));
    assert!(matches!(accepted, Err(Error::Authentication)));
    Ok(())
}

#[tokio::test]
async fn frame_lengths_fail_before_body_allocation_and_poison_the_stream() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    for size in [0, FRAME_BYTES as u32 + 1, u32::MAX] {
        let (mut client, mut accepted) = pair(&daemon, &directory).await?;
        client.stream.write_u32(size).await?;
        client.stream.flush().await?;
        let result = tokio::time::timeout(
            Duration::from_millis(250),
            accepted.receive::<serde_json::Value>(),
        )
        .await?;
        assert!(
            matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(matches!(
            accepted.receive::<serde_json::Value>().await,
            Err(Error::Stopped)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn accepted_handshake_slots_are_bounded_and_stop_cancels_incomplete_tls() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let address = state::endpoint(&directory)?.address;
    let mut clients = Vec::new();
    let mut pending = Vec::new();
    for _ in 0..CLIENTS {
        clients.push(TcpStream::connect(address).await?);
        pending.push(daemon.accept().await?);
    }
    let _extra = TcpStream::connect(address).await?;
    assert!(matches!(daemon.accept().await, Err(Error::Protocol)));
    daemon.stop();
    let first = pending.pop().ok_or("missing pending handshake")?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(250), first.authenticate()).await?,
        Err(Error::Stopped)
    ));
    drop(clients);
    drop(pending);
    Ok(())
}

#[test]
fn non_loopback_or_unknown_endpoints_do_not_become_dial_targets() -> TestResult {
    for address in [
        "192.0.2.1:1234",
        "[::1]:1234",
        "127.0.0.2:1234",
        "127.0.0.1:0",
    ] {
        let endpoint = state::Endpoint {
            version: VERSION,
            runtime_id: nestlink_auth::random_id(),
            address: address.parse()?,
        };
        assert!(endpoint.validate().is_err());
    }
    assert!(serde_json::from_value::<state::Endpoint>(json!({
        "version": VERSION, "runtime_id":nestlink_auth::random_id(), "address":"127.0.0.1:1234", "server_key":"attacker"
    })).is_err());
    Ok(())
}
