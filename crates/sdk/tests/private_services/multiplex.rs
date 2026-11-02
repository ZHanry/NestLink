//! Real private management, original pinned Quinn and original local HTTP flows.
//! One durable owner admits every signed stream through the existing flow gate.
use super::*;
use nestlink_identity::services::private::{
    VerifiedPrivateServiceLease, verify_private_service_ready,
};
use nestlink_sdk::services::{PrivateServiceConnection, PrivateServiceHost};
use nestlink_transport_quic::service::{self as carrier, BiStream, read_message, write_message};
use serde_json::json;
use std::{io, path::Path};
use tokio::{sync::Barrier, task::JoinSet};

const REQUEST: &[u8] = b"GET /fixed HTTP/1.1\r\nHost: private.svc.example.test\r\nConnection: close\r\n\r\n";
const BODY: &str = "Independent HTTP through the original private target";
const HELD_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nheld\r\n";

async fn start_host(
    sdk: &Arc<Sdk>,
    identity: Arc<DeviceIdentity>,
    consent: LocalServiceTargetConsent,
    usage: &Path,
) -> Result<PrivateServiceHost> {
    Ok(sdk.start_private_service_host(identity, consent, PrivateServiceHostConfig {
        listen: "127.0.0.1:0".parse()?,
        advertised_ip: "127.0.0.1".parse()?,
        usage_directory: usage.join("ledger"),
    }).await?)
}

async fn finish_host(mut host: PrivateServiceHost, usage: &Path, owner_failure: bool) -> Result {
    let endpoint = host.address();
    let result = host.wait_stopped().await;
    if owner_failure {
        // The original duplicate durable-owner error remains visible after all
        // original workers and the physical listener have actually completed.
        assert!(result.is_err());
    } else {
        result?;
    }
    drop(host);
    drop(std::net::UdpSocket::bind(endpoint)?);
    std::fs::remove_dir_all(usage)?;
    Ok(())
}

async fn terminal_usage(sdk: &Sdk, service: &str, host: &str, spent: u64) -> Result {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let usage = sdk.service_quota_usage(ServiceQuotaUsageQuery {
                scope: ServiceQuotaScope::Resource, scope_key: service.into(),
            }).await?;
            if usage.outstanding_bytes == 0 {
                assert_eq!(usage.spent_bytes, spent);
                assert_eq!(usage.active_grants, 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    for scope in [ServiceQuotaScope::Device, ServiceQuotaScope::Node] {
        let usage = sdk.service_quota_usage(ServiceQuotaUsageQuery {
            scope, scope_key: host.into(),
        }).await?;
        assert_eq!(usage.spent_bytes, spent);
        assert_eq!(usage.outstanding_bytes, 0);
        assert_eq!(usage.active_grants, 0);
    }
    Ok(())
}

async fn http_exchange(mut stream: BiStream) -> Result<u64> {
    stream.write_all(REQUEST).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(BODY.as_bytes()));
    Ok((REQUEST.len() + response.len()) as u64)
}

#[tokio::test]
async fn multiplex_real_http_shares_one_grant_and_refuses_fifth_original_flow() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let overlap = Arc::new(Barrier::new(2));
        let app = axum::Router::new().route("/fixed", axum::routing::get(move || {
            let overlap = overlap.clone();
            async move {
                // A serialized forwarding implementation cannot finish either
                // request. Both independent HTTP handlers must really be live.
                overlap.wait().await;
                BODY
            }
        }));
        let _backend = Abort(tokio::spawn(async move { axum::serve(backend, app).await }));
        let f = Fixture::new("http", address).await?;
        let request = f.request(&f.consumer);
        let host = start_host(&f.sdk, f.host.clone(), f.consent, &f.usage).await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        let original_digest = lease.digest();
        let original_expiry = lease.lease().claims().expires_at_unix_ms;
        let mut connection = f.sdk.connect_private_service_multiplexed(&f.consumer, lease).await?;
        assert!(connection.is_multiplexed());
        assert!(connection.stream().is_err());
        assert!(connection.open_stream(&f.outsider).await.is_err());
        let (first, second) = tokio::try_join!(
            connection.open_stream(&f.consumer), connection.open_stream(&f.consumer)
        )?;
        let third = connection.open_stream(&f.consumer).await?;
        let fourth = connection.open_stream(&f.consumer).await?;
        assert!(connection.open_stream(&f.consumer).await.is_err());
        let usage = f.sdk.service_quota_usage(ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Resource, scope_key: f.view.id.clone(),
        }).await?;
        assert_eq!(usage.active_grants, 1);
        assert_eq!(usage.outstanding_bytes, 4096);
        assert_eq!(usage.spent_bytes, 0);
        drop(third);
        drop(fourth);
        let (first, second) = tokio::try_join!(http_exchange(first), http_exchange(second))?;
        assert_eq!(connection.lease().digest(), original_digest);
        assert_eq!(connection.lease().lease().claims().expires_at_unix_ms, original_expiry);
        connection.close().await?;
        terminal_usage(&f.sdk, &f.view.id, &f.host.device_id, first + second).await?;
        finish_host(host, &f.usage, false).await
    }).await??;
    Ok(())
}

// A real, valid HTTP response remains in progress. EOF on the real backend
// socket proves cancellation reached the original local forwarding owners.
async fn held_http_backend() -> Result<(SocketAddr, Abort<io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let backend = Abort(tokio::spawn(async move {
        let mut flows = JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await?;
            flows.spawn(async move {
                let mut request = vec![0; REQUEST.len()];
                stream.read_exact(&mut request).await?;
                if request != REQUEST {
                    return Err(io::Error::other("unexpected private HTTP request"));
                }
                stream.write_all(HELD_RESPONSE).await?;
                stream.flush().await?;
                let mut byte = [0; 1];
                if stream.read(&mut byte).await? != 0 {
                    return Err(io::Error::other("unexpected byte after held HTTP request"));
                }
                Ok::<(), io::Error>(())
            });
        }
        while let Some(flow) = flows.join_next().await {
            flow.map_err(io::Error::other)??;
        }
        Ok(())
    }));
    Ok((address, backend))
}

async fn hold_http(stream: &mut BiStream) -> Result {
    stream.write_all(REQUEST).await?;
    let mut response = vec![0; HELD_RESPONSE.len()];
    stream.read_exact(&mut response).await?;
    assert_eq!(response, HELD_RESPONSE);
    Ok(())
}

async fn two_held_streams(
    owner: &PrivateServiceConnection,
    consumer: &DeviceIdentity,
) -> Result<[BiStream; 2]> {
    let mut first = owner.open_stream(consumer).await?;
    let mut second = owner.open_stream(consumer).await?;
    tokio::try_join!(hold_http(&mut first), hold_http(&mut second))?;
    Ok([first, second])
}

async fn ended(streams: &mut [BiStream; 2]) -> Result {
    for stream in streams {
        let mut byte = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte)).await?;
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    Ok(())
}

const HELD_SPENT: u64 = 2 * (REQUEST.len() + HELD_RESPONSE.len()) as u64;

#[tokio::test]
async fn multiplex_acl_revocation_drains_every_original_flow_and_actual_usage() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (address, mut backend) = held_http_backend().await?;
        let f = Fixture::new("http", address).await?;
        let request = f.request(&f.consumer);
        let host = start_host(&f.sdk, f.host.clone(), f.consent, &f.usage).await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        let mut owner = f.sdk.connect_private_service_multiplexed(&f.consumer, lease).await?;
        let mut streams = two_held_streams(&owner, &f.consumer).await?;
        f.sdk.revoke_private_service(&f.view.id, &f.rule, f.exposure.revision).await?;
        ended(&mut streams).await?;
        assert!(owner.open_stream(&f.consumer).await.is_err());
        drop(streams);
        owner.close().await?;
        tokio::time::timeout(Duration::from_secs(3), &mut backend.0).await???;
        terminal_usage(&f.sdk, &f.view.id, &f.host.device_id, HELD_SPENT).await?;
        finish_host(host, &f.usage, false).await
    }).await??;
    Ok(())
}

async fn raw_open(
    connection: &quinn::Connection,
    lease: &VerifiedPrivateServiceLease,
    consumer: &DeviceIdentity,
    mode: &str,
    replay: Option<&PrivateServiceOpen>,
) -> Result<(BiStream, PrivateServiceOpen)> {
    let grant: ServiceUsageBudgetGrantClaims = decode_service_message(
        &lease.lease().claims().usage_grant.claims, SERVICE_USAGE_BYTES,
    )?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_message(&mut send, &json!({
        "service_id": grant.service_id, "grant_id": grant.grant_id,
        "version": 1, "mode": mode,
    })).await?;
    let nonce: [u8; 32] = read_message(&mut recv).await?;
    let open = match replay {
        Some(open) => {
            assert_ne!(open.nonce, nonce);
            open.clone()
        }
        None => consumer.identity.private_service_open(lease, nonce)?,
    };
    write_message(&mut send, &open).await?;
    let ready: PrivateServiceReady = read_message(&mut recv).await?;
    verify_private_service_ready(lease, &open, &ready)?;
    Ok((BiStream::new(send, recv), open))
}

#[tokio::test]
async fn multiplex_control_fin_closes_two_flows_and_replayed_stream_proof_is_refused() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (address, mut backend) = held_http_backend().await?;
        let f = Fixture::new("http", address).await?;
        let request = f.request(&f.consumer);
        let host = start_host(&f.sdk, f.host.clone(), f.consent, &f.usage).await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        let connected = carrier::connect(
            lease.lease().claims().edge_service_address.parse()?, &f.consumer.identity,
            nestlink_identity::digest(&lease.claims().host_public_key),
        ).await?;
        let (mut control, control_open) = raw_open(
            &connected.connection, &lease, &f.consumer, "multiplex-control", None,
        ).await?;
        let accepted: serde_json::Value = read_message(control.parts_mut().1).await?;
        assert_eq!(accepted, json!({"version": 1, "mode": "multiplex-control"}));
        assert!(raw_open(
            &connected.connection, &lease, &f.consumer, "multiplex-stream", Some(&control_open),
        ).await.is_err());
        let (mut first, _) = raw_open(
            &connected.connection, &lease, &f.consumer, "multiplex-stream", None,
        ).await?;
        let (mut second, _) = raw_open(
            &connected.connection, &lease, &f.consumer, "multiplex-stream", None,
        ).await?;
        tokio::try_join!(hold_http(&mut first), hold_http(&mut second))?;
        let mut streams = [first, second];
        // FIN only the authenticated control stream while retaining this real
        // Quinn carrier and both application streams at the consumer.
        control.shutdown().await?;
        ended(&mut streams).await?;
        drop(streams);
        drop(control);
        tokio::time::timeout(Duration::from_secs(3), &mut backend.0).await???;
        terminal_usage(&f.sdk, &f.view.id, &f.host.device_id, HELD_SPENT).await?;
        connected.close_and_wait().await?;
        finish_host(host, &f.usage, false).await
    }).await??;
    Ok(())
}

#[tokio::test]
async fn multiplex_duplicate_owner_is_fenced_and_owner_drop_drains_original_flows() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (address, mut backend) = held_http_backend().await?;
        let f = Fixture::new("http", address).await?;
        let request = f.request(&f.consumer);
        let host = start_host(&f.sdk, f.host.clone(), f.consent, &f.usage).await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        let owner = f.sdk.connect_private_service_multiplexed(&f.consumer, lease.clone()).await?;
        assert!(f.sdk.connect_private_service_multiplexed(&f.consumer, lease).await.is_err());
        // A refused second durable owner cannot retire the first owner or
        // create another grant. Its real HTTP flows still use the same gate.
        let mut streams = two_held_streams(&owner, &f.consumer).await?;
        let usage = f.sdk.service_quota_usage(ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Resource, scope_key: f.view.id.clone(),
        }).await?;
        assert_eq!(usage.active_grants, 1);
        drop(owner);
        ended(&mut streams).await?;
        drop(streams);
        tokio::time::timeout(Duration::from_secs(3), &mut backend.0).await???;
        terminal_usage(&f.sdk, &f.view.id, &f.host.device_id, HELD_SPENT).await?;
        finish_host(host, &f.usage, true).await
    }).await??;
    Ok(())
}

#[tokio::test]
async fn multiplex_udp_refusal_keeps_original_datagram_entry() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let f = Fixture::new("udp", backend.local_addr()?).await?;
        let request = f.request(&f.consumer);
        let host = start_host(&f.sdk, f.host.clone(), f.consent, &f.usage).await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        assert!(f.sdk.connect_private_service_multiplexed(&f.consumer, lease.clone()).await.is_err());
        let mut legacy = f.sdk.connect_private_service(&f.consumer, lease).await?;
        assert!(!legacy.is_multiplexed());
        assert!(legacy.open_stream(&f.consumer).await.is_err());
        legacy.send_datagram(b"original UDP entry")?;
        let mut bytes = [0; 64];
        let (length, _) = backend.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..length], b"original UDP entry");
        legacy.close().await?;
        terminal_usage(&f.sdk, &f.view.id, &f.host.device_id, length as u64).await?;
        finish_host(host, &f.usage, false).await
    }).await??;
    Ok(())
}
