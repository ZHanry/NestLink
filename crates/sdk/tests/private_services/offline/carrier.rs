//! Real original QUIC/mTLS, fixed target and private native OS stream after the
//! management listener has physically stopped. No manufactured online lease.
use super::*;
use nestlink_sdk::{
    network_management::ConsumedOfflineBundle,
    services::offline::{OfflinePrivateRuntime, OfflinePrivateWait},
};
use std::sync::atomic::{AtomicU64, Ordering};

fn native_directory() -> Result<PathBuf> {
    // The durable usage fixture is deliberately longer than a Unix socket path.
    // Use another real owner-private directory for the authenticated endpoint.
    let directory=std::env::temp_dir().join(random_id());
    nestlink_platform_security::new_private_directory(&directory)?;
    Ok(directory)
}

struct Pair {
    source_process: OfflineProcess,
    _host_process: OfflineProcess,
    source: ConsumedOfflineBundle,
    host: ConsumedOfflineBundle,
    bundle_id: String,
    expires: u64,
}
async fn pair(f: &Fixture, bytes: u64, lifetime: u64) -> Result<Pair> {
    let space = &f.exposure.space_id;
    let enabled = f
        .sdk
        .set_offline_enabled(
            space,
            &OfflineEnableUpdate {
                expected_revision: 0,
                enabled: true,
            },
        )
        .await?;
    let policy = f.sdk.network_policy(space).await?;
    let authority: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&policy.authority_public_key)?
        .try_into()
        .map_err(|_| "key length")?;
    let mut source_process = OfflineProcess::new(
        f.consumer.device_id.clone(),
        f.consumer.identity.public_key(),
        wall_ms()?,
        enabled.highest_revocation_epoch,
    )?;
    let mut host_process = OfflineProcess::new(
        f.host.device_id.clone(),
        f.host.identity.public_key(),
        wall_ms()?,
        enabled.highest_revocation_epoch,
    )?;
    let request = OfflinePrivateDraftRequest {
        consumer_device_id: f.consumer.device_id.clone(),
        service_id: f.view.id.clone(),
        process_nonces: [source_process.nonce(), host_process.nonce()],
        expected_policy_revision: policy.revision,
        expected_service_revision: f.view.revision,
        expected_exposure_revision: f.exposure.revision,
        direct_transports: vec![OfflineDirectTransport::Quic],
        maximum_bytes: bytes,
        maximum_connections: 4,
        expires_at_ms: wall_ms()? + lifetime,
    };
    let view = f.sdk.create_offline_private_draft(space, &request).await?;
    f.sdk
        .approve_offline_bundle(
            &f.consumer,
            &source_process,
            &view,
            &authority,
            0,
            view.draft_digest,
        )
        .await?;
    let signed = f
        .sdk
        .approve_offline_bundle(
            &f.host,
            &host_process,
            &view,
            &authority,
            1,
            view.draft_digest,
        )
        .await?;
    let source = f
        .sdk
        .activate_offline_bundle(
            &f.consumer,
            &mut source_process,
            &signed,
            &authority,
            0,
            signed.draft_digest,
        )
        .await?;
    let host = f
        .sdk
        .activate_offline_bundle(
            &f.host,
            &mut host_process,
            &signed,
            &authority,
            1,
            signed.draft_digest,
        )
        .await?;
    Ok(Pair {
        source_process,
        _host_process: host_process,
        source,
        host,
        bundle_id: signed.claims.bundle_id,
        expires: signed.claims.expires_at_ms,
    })
}
async fn echo() -> Result<(SocketAddr, Arc<AtomicU64>, Abort<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let count = Arc::new(AtomicU64::new(0));
    let counter = count.clone();
    let task = Abort(tokio::spawn(async move {
        let mut workers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result=listener.accept()=>{
                    let Ok((mut stream,_))=result else {break;};
                    let counter=counter.clone();
                    workers.spawn(async move {
                        let mut bytes=[0u8;4096];
                        loop {let n=stream.read(&mut bytes).await?;if n==0 {return Ok::<_,std::io::Error>(());}
                            counter.fetch_add(n as u64,Ordering::AcqRel);stream.write_all(&bytes[..n]).await?;}
                    });
                },
                _=workers.join_next(),if !workers.is_empty()=>{},
            }
        }
    }));
    Ok((address, count, task))
}
async fn roundtrip(endpoint: &std::path::Path, bytes: &[u8]) -> Result {
    let mut stream = nestlink_platform_security::local_stream::connect(endpoint).await?;
    stream.write_all(bytes).await?;
    let mut reply = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply)).await??;
    assert_eq!(reply, bytes);
    #[cfg(unix)]
    {
        stream.shutdown().await?;
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut tail)).await??;
        assert!(
            tail.is_empty(),
            "original half-close preserves the already delivered reply"
        );
    }
    Ok(())
}
async fn cleaned(
    owner: &mut OfflinePrivateRuntime,
) -> Result<nestlink_sdk::services::offline::OfflinePrivateReport> {
    match owner.wait_stopped(Duration::from_secs(5)).await {
        OfflinePrivateWait::Stopped(report) => {
            assert_eq!(report.cleanup_failures, 0);
            assert!(report.local_endpoint_removed);
            Ok(report)
        }
        other => Err(format!("physical offline cleanup did not finish: {other:?}").into()),
    }
}

#[tokio::test]
async fn original_quic_real_center_disconnect_reconnect_half_close_and_socket_release() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (target, count, _echo) = echo().await?;
        let mut f = Fixture::new("tcp", target).await?;
        let directory = native_directory()?;
        let pair = pair(&f, 32768, 20_000).await?;
        let Pair {
            source_process: _source_process,
            _host_process,
            source,
            host,
            ..
        } = pair;
        let mut host = f
            .sdk
            .start_offline_private_service_host(
                f.host.clone(),
                host,
                f.consent,
                "127.0.0.1:0".parse()?,
            )
            .await?;
        let address = host.address().ok_or("host address")?;
        let mut proxy = f
            .sdk
            .start_offline_private_service_proxy(Arc::new(f.consumer), source, address, &directory)
            .await?;
        let endpoint = proxy.endpoint().ok_or("native endpoint")?.to_path_buf();
        let checkpoint = b"authenticated recovery keeps the same budget";
        roundtrip(&endpoint, checkpoint).await?;
        proxy.synchronize_online(&f.sdk).await?;
        host.synchronize_online(&f.sdk).await?;
        // The automatic original management-recovery monitor must also keep
        // a live unchanged owner without treating response latency as rollback.
        tokio::time::sleep(Duration::from_millis(2250)).await;
        assert!(!proxy.status()?.stopped);
        f._server.0.abort();
        let _ = (&mut f._server.0).await;
        assert!(
            reqwest::Client::new()
                .get(format!("{}/api/v3/health", f.origin))
                .send()
                .await
                .is_err()
        );
        let first = b"first actual direct offline business";
        let second = b"second connection keeps the original cumulative authority";
        roundtrip(&endpoint, first).await?;
        roundtrip(&endpoint, second).await?;
        let bytes = (checkpoint.len() + first.len() + second.len()) as u64;
        assert_eq!(count.load(Ordering::Acquire), bytes);
        assert_eq!(proxy.status()?.cumulative_connections, 3);
        assert_eq!(host.status()?.cumulative_connections, 3);
        assert_eq!(proxy.status()?.remaining_bytes, 32768 - 2 * bytes);
        let source_report = cleaned(&mut proxy).await?;
        assert_eq!(source_report.released_quic_sockets, 3);
        let host_report = cleaned(&mut host).await?;
        assert_eq!(host_report.released_quic_sockets, 1);
        assert!(!endpoint.exists());
        drop(std::net::UdpSocket::bind(address)?);
        std::fs::remove_dir(directory)?;
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn original_offline_deadline_closes_idle_real_stream_and_native_listener() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (target, _, _echo) = echo().await?;
        let mut f = Fixture::new("tcp", target).await?;
        let directory = native_directory()?;
        let pair = pair(&f, 32768, 3000).await?;
        let Pair {
            source_process: _source_process,
            _host_process,
            source,
            host,
            expires,
            ..
        } = pair;
        let mut host = f
            .sdk
            .start_offline_private_service_host(
                f.host.clone(),
                host,
                f.consent,
                "127.0.0.1:0".parse()?,
            )
            .await?;
        let address = host.address().ok_or("host address")?;
        let mut proxy = f
            .sdk
            .start_offline_private_service_proxy(Arc::new(f.consumer), source, address, &directory)
            .await?;
        let endpoint = proxy.endpoint().ok_or("endpoint")?.to_path_buf();
        let mut stream = nestlink_platform_security::local_stream::connect(&endpoint).await?;
        stream.write_all(b"live").await?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        f._server.0.abort();
        let _ = (&mut f._server.0).await;
        let mut byte = [0];
        let result = tokio::time::timeout(
            Duration::from_millis(expires.saturating_sub(wall_ms()?) + 1500),
            stream.read(&mut byte),
        )
        .await?;
        assert!(matches!(result, Ok(0) | Err(_)));
        assert!(wall_ms()? >= expires);
        assert!(proxy.status()?.stopped);
        cleaned(&mut proxy).await?;
        cleaned(&mut host).await?;
        assert!(!endpoint.exists());
        drop(std::net::UdpSocket::bind(address)?);
        std::fs::remove_dir(directory)?;
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn original_offline_shared_byte_budget_stops_actual_reconnect_traffic() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (target, count, _echo) = echo().await?;
        let f = Fixture::new("tcp", target).await?;
        let directory = native_directory()?;
        let pair = pair(&f, 1024, 15_000).await?;
        let Pair {
            source_process: _source_process,
            _host_process,
            source,
            host,
            ..
        } = pair;
        let mut host = f
            .sdk
            .start_offline_private_service_host(
                f.host.clone(),
                host,
                f.consent,
                "127.0.0.1:0".parse()?,
            )
            .await?;
        let mut proxy = f
            .sdk
            .start_offline_private_service_proxy(
                Arc::new(f.consumer),
                source,
                host.address().ok_or("address")?,
                &directory,
            )
            .await?;
        let endpoint = proxy.endpoint().ok_or("endpoint")?.to_path_buf();
        roundtrip(&endpoint, &[11; 200]).await?;
        roundtrip(&endpoint, &[12; 200]).await?;
        assert_eq!(proxy.status()?.remaining_bytes, 224);
        let mut stream = nestlink_platform_security::local_stream::connect(&endpoint).await?;
        stream.write_all(&[13; 300]).await?;
        let mut reply = [0; 300];
        assert!(
            tokio::time::timeout(Duration::from_secs(4), stream.read_exact(&mut reply))
                .await?
                .is_err()
        );
        assert_eq!(proxy.status()?.remaining_bytes, 0);
        assert!(count.load(Ordering::Acquire) <= 1024);
        assert!(proxy.status()?.cumulative_connections <= 3);
        cleaned(&mut proxy).await?;
        cleaned(&mut host).await?;
        assert!(!endpoint.exists());
        std::fs::remove_dir(directory)?;
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn original_offline_process_exit_and_authenticated_recovery_close_actual_channels() -> Result
{
    for recovery in [false, true] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let (target, _, _echo) = echo().await?;
            let f = Fixture::new("tcp", target).await?;
            let directory = native_directory()?;
        let pair = pair(&f, 32768, 15_000).await?;
            let Pair {
                source_process,
                _host_process,
                source,
                host,
                bundle_id,
                ..
            } = pair;
            let mut host = f
                .sdk
                .start_offline_private_service_host(
                    f.host.clone(),
                    host,
                    f.consent,
                    "127.0.0.1:0".parse()?,
                )
                .await?;
            let mut proxy = f
                .sdk
                .start_offline_private_service_proxy(
                    Arc::new(f.consumer),
                    source,
                    host.address().ok_or("address")?,
                    &directory,
                )
                .await?;
            let mut stream = nestlink_platform_security::local_stream::connect(
                proxy.endpoint().ok_or("endpoint")?,
            )
            .await?;
            stream.write_all(b"live").await?;
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await?;
            if recovery {
                f.sdk
                    .revoke_offline_bundle(&f.exposure.space_id, &bundle_id)
                    .await?;
                assert!(proxy.synchronize_online(&f.sdk).await.is_err());
                assert!(host.synchronize_online(&f.sdk).await.is_err());
            } else {
                drop(source_process);
            }
            let mut byte = [0];
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await?,
                Ok(0) | Err(_)
            ));
            cleaned(&mut proxy).await?;
            cleaned(&mut host).await?;
            std::fs::remove_dir(directory)?;
        std::fs::remove_dir_all(f.usage)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
    }
    Ok(())
}
