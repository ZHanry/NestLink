use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn original_carrier_facts_precede_synthetic_endpoint_shutdown_but_not_protocol_failure()
-> Result {
    for (carrier_kind, code, expected) in [
        (
            io::ErrorKind::PermissionDenied,
            quinn::TransportErrorCode::INTERNAL_ERROR,
            StopReason::Revoked,
        ),
        (
            io::ErrorKind::ConnectionReset,
            quinn::TransportErrorCode::INTERNAL_ERROR,
            StopReason::TransportLost,
        ),
        (
            io::ErrorKind::InvalidData,
            quinn::TransportErrorCode::INTERNAL_ERROR,
            StopReason::ProtocolViolation,
        ),
        (
            io::ErrorKind::PermissionDenied,
            quinn::TransportErrorCode::PROTOCOL_VIOLATION,
            StopReason::ProtocolViolation,
        ),
    ] {
        let (session, clock) = super::file_disclosure_tests::active()?;
        let (_keep, stop) = watch::channel(None);
        let (facts, carrier) = watch::channel(None);
        let mut lifecycle = crate::SessionLifecycle::new(stop);
        lifecycle.carrier = Some(carrier);
        let (_peer, stream) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(stream);
        let mut runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            nestlink_protocol::Path::Direct,
            clock,
            lifecycle,
        )?
        .into_channels();
        facts.send_replace(Some(carrier_kind));
        let result: std::result::Result<(), RemoteError> = Err(io::Error::other(
            quinn::ReadError::ConnectionLost(quinn::ConnectionError::TransportError(
                quinn::TransportError {
                    code,
                    frame: None,
                    reason: "owned endpoint terminated".into(),
                },
            )),
        )
        .into());
        stop_io_result(&runtime.lease_control(), &result);
        let report = tokio::time::timeout(Duration::from_secs(1), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, expected);
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_and_expired_cleanup_retains_unjoined_socket_task_without_renewing_budget()
-> Result {
    let (session, clock) = super::file_disclosure_tests::active()?;
    let (_keep, stop) = watch::channel(None);
    let (_peer, stream) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(stream);
    let mut runtime = AuthorizedConnection::new(
        read,
        write,
        session,
        nestlink_protocol::Path::Direct,
        clock,
        stop,
    )?
    .into_channels();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    let (release, blocked) = std::sync::mpsc::channel();
    let (started, ready) = tokio::sync::oneshot::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        let _socket = socket;
        let _ = started.send(());
        // A running blocking task ignores abort. Sender Drop also releases it
        // if an assertion fails, so this regression test cannot strand CI.
        let _ = blocked.recv();
        Ok::<_, RemoteError>(())
    });
    ready.await?;
    runtime.tasks.insert(0, blocker);
    let original_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    runtime.cleanup_deadline = Some(original_deadline);
    let cancelled_while_pending = {
        let mut stopping = Box::pin(runtime.shutdown(StopReason::ExplicitExit));
        std::future::poll_fn(|context| {
            std::task::Poll::Ready(stopping.as_mut().poll(context).is_pending())
        })
        .await
        // `stopping` drops here, cancelling the first wait without detaching
        // the task. Polling once avoids relying on a short scheduling timer.
    };
    assert!(cancelled_while_pending);
    assert_eq!(runtime.cleanup_deadline, Some(original_deadline));
    assert_eq!(runtime.tasks.len(), 3);
    let result = tokio::time::timeout(Duration::from_millis(250), runtime.wait_stopped()).await?;
    assert!(
        matches!(result, Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert_eq!(runtime.cleanup_deadline, Some(original_deadline));
    assert_eq!(runtime.tasks.len(), 3);
    assert_eq!(
        std::net::UdpSocket::bind(address)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    let retry = tokio::time::timeout(Duration::from_millis(50), runtime.wait_stopped()).await?;
    assert!(
        matches!(retry, Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert_eq!(runtime.cleanup_deadline, Some(original_deadline));
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.tasks.iter().any(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    // Reaping already finished handles is nonblocking, but missing the fixed
    // budget remains a failure rather than becoming a successful receipt.
    let reaped = runtime.wait_stopped().await;
    assert!(
        matches!(reaped, Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(runtime.tasks.is_empty());
    let rebound = std::net::UdpSocket::bind(address)?;
    drop(rebound);
    Ok(())
}
