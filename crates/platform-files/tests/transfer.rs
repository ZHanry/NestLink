use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, digest, verify_permit};
use nestlink_platform_files::{ApprovedReadRoot, FileRoots, ReadRootConsent};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    FILE_READ_ACTIVE, FILE_SIZE_BYTES, FileReadChunk, FileReadErrorCode, FileReadManifest,
    FileReadNext, FileReadOpen, NativeFileRead, Path, Permission, PermitClaims, SCHEMA_VERSION,
    native_file_read::Action,
};
use nestlink_remote::{
    AuthorizedConnection, ChannelRuntime, RuntimeClock, SessionLifecycle, SessionSetup,
    files::{
        FileReadClient, FileReadConsent, FileReadDevice, FileReadError, FileReadServer,
        FileReadSource, FileReadVerifier, FileShutdown,
    },
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_stream::{Channel, tls};
use prost::Message;
use std::{
    fs, io,
    path::Path as FsPath,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;
#[path = "transfer/browse.rs"]
mod browse;
#[path = "transfer/download_deadlines.rs"]
mod download_deadlines;
#[path = "transfer/download_drop.rs"]
mod download_drop;
#[path = "transfer/download_workers.rs"]
mod download_workers;
#[path = "transfer/downloads.rs"]
mod downloads;
#[path = "transfer/uploads.rs"]
mod uploads;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Sessions {
    c: ChannelRuntime,
    h: ChannelRuntime,
    stops: [watch::Sender<Option<StopReason>>; 2],
    scope: ConnectionScope,
}
#[derive(Clone)]
struct ConnectionScope {
    controller_seed: [u8; 32],
    host_seed: [u8; 32],
    signer_seed: [u8; 32],
    claims: PermitClaims,
}
impl Sessions {
    async fn new(quic: bool, permissions: Vec<Permission>) -> Result<Self> {
        Self::with_scope(quic, permissions, None, 9).await
    }
    async fn with_scope(
        quic: bool,
        permissions: Vec<Permission>,
        previous: Option<&ConnectionScope>,
        generation: u64,
    ) -> Result<Self> {
        let controller_seed = previous
            .map(|s| s.controller_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let host_seed = previous
            .map(|s| s.host_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let signer_seed = previous
            .map(|s| s.signer_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let controller = InstallationIdentity::from_seed(controller_seed);
        let host = InstallationIdentity::from_seed(host_seed);
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        let mut c = previous
            .map(|s| s.claims.clone())
            .unwrap_or_else(|| PermitClaims {
                media_format_version: 0,
                media_formats: Vec::new(),
                media_format_sha256: Vec::new(),
                schema_version: SCHEMA_VERSION,
                deployment_id: random_id(),
                security_epoch: 1,
                session_id: random_id(),
                account_id: random_id(),
                controller_device_id: random_id(),
                host_device_id: random_id(),
                controller_key_sha256: controller.fingerprint().to_vec(),
                host_key_sha256: host.fingerprint().to_vec(),
                resource_id: random_id(),
                permissions: permissions.iter().map(|p| *p as i32).collect(),
                paths: vec![Path::Direct as i32],
                policy_revision: 1,
                connection_generation: 9,
                lease_sequence: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now.unix_ms + 15000,
                capability_sha256: vec![7; 32],
                required_capabilities: vec!["vp8".into()],
            });
        c.connection_generation = generation;
        c.permissions = permissions.iter().map(|p| *p as i32).collect();
        c.issued_at_unix_ms = now.unix_ms;
        c.expires_at_unix_ms = now.unix_ms + 15000;
        let signer = PermitSigner::from_seed(signer_seed);
        let permit = verify_permit(&signer.sign(&c)?.encode_to_vec(), &signer.public_key())?;
        let session = || {
            Session::activate(
                permit.clone(),
                SessionBinding {
                    media: None,
                    deployment_id: c.deployment_id.clone(),
                    security_epoch: c.security_epoch,
                    session_id: c.session_id.clone(),
                    account_id: c.account_id.clone(),
                    controller_device_id: c.controller_device_id.clone(),
                    host_device_id: c.host_device_id.clone(),
                    controller_key_sha256: controller.fingerprint(),
                    host_key_sha256: host.fingerprint(),
                    resource_id: c.resource_id.clone(),
                    policy_revision: 1,
                    connection_generation: generation,
                    capability_sha256: [7; 32],
                    granted_permissions: permissions.clone(),
                    supported_capabilities: vec!["vp8".into()],
                    local_paths: PathSet::DIRECT,
                },
                Path::Direct,
                now.monotonic_ms,
                now,
            )
        };
        let (c_stop, cs) = watch::channel(None);
        let (h_stop, hs) = watch::channel(None);
        let scope = ConnectionScope {
            controller_seed,
            host_seed,
            signer_seed,
            claims: c.clone(),
        };
        let (c, h) = if quic {
            let he = nestlink_transport_quic::listener(
                "127.0.0.1:0".parse()?,
                &host,
                controller.fingerprint(),
            )?;
            let ce = nestlink_transport_quic::connector(
                "127.0.0.1:0".parse()?,
                &controller,
                host.fingerprint(),
            )?;
            let address = he.local_addr()?;
            let accepted = async {
                he.accept()
                    .await
                    .ok_or("QUIC listener closed")?
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            };
            let (connected, accepted) = tokio::join!(
                nestlink_transport_quic::connect(&ce, address, Duration::from_secs(3)),
                accepted
            );
            let host_key = host.public_key();
            let controller_key = controller.public_key();
            let c_setup = SessionSetup {
                session: session()?,
                path: Path::Direct,
                role: EndpointRole::Controller,
                clock: clock.clone(),
                lifecycle: SessionLifecycle::new(cs),
            };
            let h_setup = SessionSetup {
                session: session()?,
                path: Path::Direct,
                role: EndpointRole::Host,
                clock,
                lifecycle: SessionLifecycle::new(hs),
            };
            let (c, h) = tokio::join!(
                nestlink_remote::quic::authorize(
                    connected?,
                    Some(ce),
                    c_setup,
                    &controller,
                    &host_key
                ),
                nestlink_remote::quic::authorize(
                    accepted?,
                    Some(he),
                    h_setup,
                    &host,
                    &controller_key
                )
            );
            (c?, h?)
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let cc = tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(
                &controller,
                host.fingerprint(),
            )?));
            let hc = tokio_rustls::TlsAcceptor::from(Arc::new(tls::server_config(
                &host,
                controller.fingerprint(),
            )?));
            let controller_side = async {
                // Match the low-latency socket used by the production TLS
                // connector. Delayed ACK/Nagle interaction must not dominate
                // the bounded capacity test's hundreds of short RPCs.
                let tcp = tokio::net::TcpStream::connect(address).await?;
                tcp.set_nodelay(true)?;
                assert!(tcp.nodelay()?);
                let io = cc
                    .connect(
                        rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")?,
                        tcp,
                    )
                    .await?;
                let (mut read, mut write) = tokio::io::split(io);
                let mut session = session()?;
                nestlink_remote::controller_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    &controller,
                    &host.public_key(),
                    &clock,
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    AuthorizedConnection::new(
                        read,
                        write,
                        session,
                        Path::Direct,
                        clock.clone(),
                        cs,
                    )?
                    .into_channels(),
                )
            };
            let host_side = async {
                let tcp = listener.accept().await?.0;
                tcp.set_nodelay(true)?;
                assert!(tcp.nodelay()?);
                let io = hc.accept(tcp).await?;
                let (mut read, mut write) = tokio::io::split(io);
                let mut session = session()?;
                nestlink_remote::host_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    &host,
                    &controller.public_key(),
                    &clock,
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    AuthorizedConnection::new(
                        read,
                        write,
                        session,
                        Path::Direct,
                        clock.clone(),
                        hs,
                    )?
                    .into_channels(),
                )
            };
            let (c, h) = tokio::join!(controller_side, host_side);
            (c?, h?)
        };
        Ok(Self {
            c,
            h,
            stops: [c_stop, h_stop],
            scope,
        })
    }
}
fn roots(path: &FsPath) -> Result<(String, FileRoots, ReadRootConsent)> {
    let id = random_id();
    let (root, consent) = ApprovedReadRoot::open(&id, path, FILE_SIZE_BYTES)?;
    Ok((id, FileRoots::new(vec![root])?, consent))
}
async fn worker_finished(server: &FileReadServer) -> Result {
    let monitor = server.monitor();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().finished {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}
#[tokio::test]
async fn encrypted_tls_and_quic_download_real_files_and_verify_resume_and_empty_files() -> Result {
    for quic in [false, true] {
        let dir = tempfile::tempdir()?;
        let bytes: Vec<_> = (0..2 * 1024 * 1024 + 73).map(|i| (i % 251) as u8).collect();
        fs::write(dir.path().join("file"), &bytes)?;
        fs::write(dir.path().join("empty"), b"")?;
        let (id, roots, _consent) = roots(dir.path())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, roots)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut first = client.open(&random_id(), &id, "file", 0, None).await?;
        let whole: [u8; 32] = first.manifest().sha256.as_slice().try_into()?;
        assert_eq!(whole, digest(&bytes));
        let prefix = client
            .next(&mut first)
            .await?
            .ok_or("missing first chunk")?
            .data;
        client.cancel(&mut first).await?;
        assert!(client.next(&mut first).await.is_err());
        let mut resumed = client
            .open(&random_id(), &id, "file", prefix.len() as u64, Some(whole))
            .await?;
        let mut verified = FileReadVerifier::new(resumed.manifest().clone())?;
        verified.seed_prefix(&prefix)?;
        let mut corrupted = FileReadVerifier::new(resumed.manifest().clone())?;
        corrupted.seed_prefix(&vec![0; prefix.len()])?;
        let mut received = prefix;
        while let Some(chunk) = client.next(&mut resumed).await? {
            verified.accept(&chunk)?;
            corrupted.accept(&chunk)?;
            received.extend_from_slice(&chunk.data);
        }
        assert!(resumed.finished());
        verified.finish()?;
        assert!(corrupted.finish().is_err());
        assert_eq!(received, bytes);
        assert!(matches!(
            client
                .open(&random_id(), &id, "file", 0, Some([0; 32]))
                .await,
            Err(FileReadError::Source(
                FileReadErrorCode::FileReadChecksumMismatch
            ))
        ));
        let mut empty = client.open(&random_id(), &id, "empty", 0, None).await?;
        let verifier = FileReadVerifier::new(empty.manifest().clone())?;
        assert!(client.next(&mut empty).await?.is_none());
        verifier.finish()?;
        assert_eq!(
            server.shutdown(StopReason::ExplicitExit).await?,
            FileShutdown::Finished
        );
    }
    Ok(())
}
#[tokio::test]
async fn file_read_permissions_generation_and_local_root_revocation_are_independent() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("file"), b"approved")?;
    let (_, provider, _keep) = roots(dir.path())?;
    let mut forbidden = Sessions::new(true, vec![Permission::View]).await?;
    assert!(FileReadServer::start(&mut forbidden.h, 9, provider).is_err());
    assert!(FileReadClient::attach(&mut forbidden.c, 9).is_err());
    let (id, provider, consent) = roots(dir.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    assert!(FileReadClient::attach(&mut s.c, 8).is_err());
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "file", 0, None).await?;
    consent.revoke();
    // Idle worker must retire the handle; Windows sharing makes this observable.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fs::write(
        dir.path().join("file"),
        b"local edit after file-only revoke",
    )?;
    assert!(matches!(
        client.next(&mut download).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadDenied))
    ));
    s.h.send(Channel::Video, b"file-only revoke keeps approved view")
        .await?;
    assert_eq!(
        s.c.receive().await?.payload,
        b"file-only revoke keeps approved view"
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn exact_retry_is_cached_but_altered_retry_cannot_read_again() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("file"), b"retry proof")?;
    let (id, provider, _consent) = roots(dir.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut request = NativeFileRead {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence: 1,
        transfer_id: random_id(),
        action: Some(Action::Open(FileReadOpen {
            root_id: id,
            path: "file".into(),
            offset: 0,
            expected_sha256: vec![],
        })),
    };
    let mut previous = None;
    for _ in 0..2 {
        s.c.send(Channel::FileRead, &request.encode_validated()?)
            .await?;
        let reply = s.c.receive().await?.payload;
        if let Some(previous) = &previous {
            assert_eq!(&reply, previous);
        }
        previous = Some(reply);
    }
    request.sequence = 2;
    request.action = Some(Action::Next(FileReadNext { offset: 0 }));
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    let reply = s.c.receive().await?.payload;
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    assert_eq!(s.c.receive().await?.payload, reply);
    request.action = Some(Action::Next(FileReadNext { offset: 1 }));
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    let stopped = tokio::time::timeout(Duration::from_secs(2), s.h.wait_stopped()).await??;
    assert_eq!(stopped.reason, StopReason::ProtocolViolation);
    server.shutdown(StopReason::ExplicitExit).await?;
    worker_finished(&server).await?;
    Ok(())
}
#[tokio::test]
async fn active_file_limit_and_retired_transfer_ids_cannot_reopen() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("file"), b"four handles")?;
    let (id, provider, _consent) = roots(dir.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut transfers = Vec::new();
    for _ in 0..FILE_READ_ACTIVE {
        transfers.push(client.open(&random_id(), &id, "file", 0, None).await?);
    }
    assert!(matches!(
        client.open(&random_id(), &id, "file", 0, None).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity))
    ));
    let mut retired = transfers.remove(0);
    client.cancel(&mut retired).await?;
    let next = client.open(&random_id(), &id, "file", 0, None).await?;
    assert!(!next.finished());
    assert!(
        client
            .open(retired.transfer_id(), &id, "file", 0, None)
            .await
            .is_err()
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn a_cached_chunk_retry_is_denied_after_local_root_revocation() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join("file"),
        b"cached bytes must stop at consent revoke",
    )?;
    let (id, provider, consent) = roots(dir.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut request = NativeFileRead {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence: 1,
        transfer_id: random_id(),
        action: Some(Action::Open(FileReadOpen {
            root_id: id,
            path: "file".into(),
            offset: 0,
            expected_sha256: vec![],
        })),
    };
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    assert!(matches!(
        NativeFileRead::decode_validated(&s.c.receive().await?.payload)?.action,
        Some(Action::Manifest(_))
    ));
    request.sequence = 2;
    request.action = Some(Action::Next(FileReadNext { offset: 0 }));
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    assert!(matches!(
        NativeFileRead::decode_validated(&s.c.receive().await?.payload)?.action,
        Some(Action::Chunk(_))
    ));
    consent.revoke();
    // Repeat immediately; revoked consent also gates the exact cached bytes.
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    let reply = NativeFileRead::decode_validated(&s.c.receive().await?.payload)?;
    assert!(
        matches!(reply.action, Some(Action::Failure(failure)) if failure.code == FileReadErrorCode::FileReadDenied as i32)
    );
    s.h.send(Channel::Video, b"view remains authorized").await?;
    assert_eq!(s.c.receive().await?.payload, b"view remains authorized");
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
    dropped: AtomicUsize,
}

#[tokio::test]
async fn a_peer_with_valid_tls_keys_cannot_substitute_response_identity_or_chunk_content() -> Result
{
    for mutation in 0..4 {
        let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let transfer = random_id();
        let root = random_id();
        let peer = async {
            let request = s.h.receive().await?;
            let mut reply = NativeFileRead::decode_validated(&request.payload)?;
            reply.action = Some(Action::Manifest(FileReadManifest {
                size: 4,
                sha256: digest(b"data").to_vec(),
                offset: 0,
            }));
            match mutation {
                0 => reply.connection_generation = 8,
                1 => reply.sequence = 2,
                2 => reply.transfer_id = random_id(),
                _ => {}
            }
            s.h.send(Channel::FileRead, &reply.encode_validated()?)
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (opened, peer) = tokio::join!(client.open(&transfer, &root, "file", 0, None), peer);
        peer?;
        if mutation == 3 {
            let mut download = opened?;
            let peer = async {
                let request = s.h.receive().await?;
                let mut reply = NativeFileRead::decode_validated(&request.payload)?;
                reply.action = Some(Action::Chunk(FileReadChunk {
                    offset: 0,
                    data: b"data".to_vec(),
                    sha256: vec![0; 32],
                }));
                s.h.send(Channel::FileRead, &reply.encode_validated()?)
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let (received, peer) = tokio::join!(client.next(&mut download), peer);
            peer?;
            assert!(received.is_err());
        } else {
            assert!(opened.is_err());
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), s.c.wait_stopped())
                .await??
                .reason,
            StopReason::ProtocolViolation
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_valid_tls_peer_cannot_create_duplicate_client_bindings_or_exceed_local_active_bounds()
-> Result {
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let root = random_id();
    let mut downloads = Vec::new();
    for _ in 0..FILE_READ_ACTIVE {
        let id = random_id();
        let peer = async {
            let frame = s.h.receive().await?;
            let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
            assert!(matches!(reply.action, Some(Action::Open(_))));
            reply.action = Some(Action::Manifest(FileReadManifest {
                size: 4,
                offset: 0,
                sha256: digest(b"data").to_vec(),
            }));
            s.h.send(Channel::FileRead, &reply.encode_validated()?)
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (opened, replied) = tokio::join!(client.open(&id, &root, "source", 0, None), peer);
        replied?;
        downloads.push(opened?);
        assert!(client.open(&id, &root, "source", 0, None).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), s.h.receive())
                .await
                .is_err()
        );
        assert!(!downloads.last().ok_or("missing source")?.finished());
    }
    assert!(matches!(
        client.open(&random_id(), &root, "source", 0, None).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), s.h.receive())
            .await
            .is_err()
    );
    for download in &mut downloads {
        let peer = async {
            let frame = s.h.receive().await?;
            let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
            assert!(matches!(reply.action, Some(Action::Cancel(true))));
            reply.action = Some(Action::Cancelled(true));
            s.h.send(Channel::FileRead, &reply.encode_validated()?)
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (cancelled, replied) = tokio::join!(client.cancel(download), peer);
        cancelled?;
        replied?;
    }
    assert!(
        client
            .open(downloads[0].transfer_id(), &root, "source", 0, None)
            .await
            .is_err()
    );
    client.retire()?;
    s.c.lease_control().check_media_binding(Channel::Video, 9)?;
    s.c.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn source_rejections_are_bounded_local_tombstones_and_cannot_reuse_client_identity() -> Result
{
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let root = random_id();
    let first = random_id();
    for index in 0..nestlink_protocol::FILE_READ_TRANSFERS {
        let id = if index == 0 {
            first.clone()
        } else {
            random_id()
        };
        let peer = async {
            let frame = s.h.receive().await?;
            let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
            reply.action = Some(Action::Failure(nestlink_protocol::FileReadFailure {
                code: FileReadErrorCode::FileReadDenied as i32,
            }));
            s.h.send(Channel::FileRead, &reply.encode_validated()?)
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (opened, replied) = tokio::join!(client.open(&id, &root, "source", 0, None), peer);
        replied?;
        assert!(matches!(
            opened,
            Err(FileReadError::Source(FileReadErrorCode::FileReadDenied))
        ));
    }
    assert!(client.open(&first, &root, "source", 0, None).await.is_err());
    assert!(matches!(
        client.open(&random_id(), &root, "source", 0, None).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), s.h.receive())
            .await
            .is_err()
    );
    client.retire()?;
    s.c.lease_control().check_media_binding(Channel::Video, 9)?;
    s.c.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn finished_transfer_tombstones_bound_requests_without_reopening_or_leaking_handles() -> Result
{
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("empty"), b"")?;
    let (id, provider, _consent) = roots(dir.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    for _ in 0..nestlink_protocol::FILE_READ_TRANSFERS {
        let mut download = client.open(&random_id(), &id, "empty", 0, None).await?;
        assert!(client.next(&mut download).await?.is_none());
    }
    assert!(matches!(
        client.open(&random_id(), &id, "empty", 0, None).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity))
    ));
    fs::write(
        dir.path().join("empty"),
        b"all original source handles are closed",
    )?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
impl Gate {
    fn release(&self) {
        if let Ok(mut released) = self.released.lock() {
            *released = true;
            self.changed.notify_all();
        }
    }
    async fn entered(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
}
struct BlockingDevice(Arc<Gate>);
struct BlockingSource(Arc<Gate>);
impl FileReadDevice for BlockingDevice {
    fn open(&mut self, _: &str, _: &str) -> io::Result<Box<dyn FileReadSource>> {
        Ok(Box::new(BlockingSource(self.0.clone())))
    }
}
impl FileReadSource for BlockingSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(AtomicBool::new(true))
    }
    fn describe(
        &mut self,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        check()?;
        self.0.entered.store(true, Ordering::Release);
        let guard = self
            .0
            .released
            .lock()
            .map_err(|_| io::Error::other("test gate poisoned"))?;
        let (guard, _) = self
            .0
            .changed
            .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
            .map_err(|_| io::Error::other("test gate poisoned"))?;
        if !*guard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test gate not released",
            ));
        }
        drop(guard);
        check()?;
        Ok(FileReadManifest {
            size: 1,
            sha256: digest(b"x").to_vec(),
            offset: 0,
        })
    }
    fn read_chunk(
        &mut self,
        _: u64,
        _: usize,
        _: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        Err(io::Error::other("test source must never read after revoke"))
    }
    fn verify(
        &mut self,
        _: &FileReadManifest,
        _: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "test source must never finish after revoke",
        ))
    }
}
impl Drop for BlockingSource {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
#[tokio::test]
async fn blocked_disk_does_not_block_input_or_revoke_and_cleanup_timeout_remains_truthful() -> Result
{
    let gate = Arc::new(Gate::default());
    let mut s = Sessions::new(
        true,
        vec![Permission::View, Permission::Input, Permission::FileRead],
    )
    .await?;
    let mut server = FileReadServer::start(&mut s.h, 9, BlockingDevice(gate.clone()))?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let transfer = random_id();
    let root = random_id();
    let open = client.open(&transfer, &root, "file", 0, None);
    tokio::pin!(open);
    tokio::select! {
        result = &mut open => return Err(format!("file opened before test gate: {}", result.is_ok()).into()),
        result = gate.entered() => result?,
    }
    s.c.send(Channel::Input, b"independent authenticated input queue")
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), s.h.receive())
            .await??
            .payload,
        b"independent authenticated input queue"
    );
    let start = Instant::now();
    s.stops[1].send_replace(Some(StopReason::Revoked));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), s.h.wait_stopped())
            .await??
            .reason,
        StopReason::Revoked
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(
        server.shutdown(StopReason::Revoked).await?,
        FileShutdown::TimedOut
    );
    let monitor = server.monitor();
    assert!(monitor.status().cleanup_timed_out);
    assert!(!monitor.status().finished);
    assert_eq!(gate.dropped.load(Ordering::Acquire), 0);
    gate.release();
    worker_finished(&server).await?;
    assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
    assert!(monitor.status().cleanup_timed_out);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut open)
            .await?
            .is_err()
    );
    assert_eq!(
        server.shutdown(StopReason::Revoked).await?,
        FileShutdown::Finished
    );
    Ok(())
}
#[tokio::test]
async fn cancelling_a_request_cannot_let_its_late_reply_answer_a_new_transfer() -> Result {
    let gate = Arc::new(Gate::default());
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, BlockingDevice(gate.clone()))?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let transfer = random_id();
    let root = random_id();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(40),
            client.open(&transfer, &root, "file", 0, None)
        )
        .await
        .is_err()
    );
    gate.entered().await?;
    assert!(
        client
            .open(&random_id(), &root, "file", 0, None)
            .await
            .is_err()
    );
    gate.release();
    server.shutdown(StopReason::ExplicitExit).await?;
    worker_finished(&server).await?;
    Ok(())
}
#[tokio::test]
async fn file_retirement_requires_an_exact_source_close_even_after_local_download_drop() -> Result {
    for local_drop in [false, true] {
        let source = tempfile::tempdir()?;
        fs::write(source.path().join("source"), b"still-open source")?;
        let (id, provider, _consent) = roots(source.path())?;
        let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let download = client.open(&random_id(), &id, "source", 0, None).await?;
        let retained = if local_drop {
            drop(download);
            None
        } else {
            Some(download)
        };
        assert!(client.retire().is_err());
        assert_eq!(
            s.c.wait_stopped().await?.reason,
            StopReason::ProtocolViolation
        );
        drop(retained);
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}
#[test]
fn local_verifier_rejects_corrupt_truncated_and_out_of_order_content() -> Result {
    let manifest = FileReadManifest {
        size: 4,
        sha256: digest(b"data").to_vec(),
        offset: 0,
    };
    let chunk = FileReadChunk {
        offset: 0,
        data: b"data".to_vec(),
        sha256: digest(b"data").to_vec(),
    };
    let mut good = FileReadVerifier::new(manifest.clone())?;
    good.accept(&chunk)?;
    good.finish()?;
    assert!(FileReadVerifier::new(manifest.clone())?.finish().is_err());
    let mut wrong = chunk.clone();
    wrong.sha256 = vec![0; 32];
    assert!(
        FileReadVerifier::new(manifest.clone())?
            .accept(&wrong)
            .is_err()
    );
    wrong = chunk;
    wrong.offset = 1;
    assert!(FileReadVerifier::new(manifest)?.accept(&wrong).is_err());
    Ok(())
}
