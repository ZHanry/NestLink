//! Real online consume, expired online permit and independent AppCore data routes.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_app_core::*;
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_identity::offline::OfflineProcess;
use nestlink_protocol::{
    Path, Permission,
    api::*,
    network::SpaceRole,
    offline::{OfflineDirectTransport, OfflineRemoteOperation, management::*},
};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk};
use nestlink_session::{EndpointRole, SessionBinding};
use std::io;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn wall() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn password() -> Secret {
    Secret::from_text("offline-original-remote-test-password".into())
}

async fn exercise(transport: NativeOfflineTransport) -> Result {
    tokio::time::timeout(Duration::from_secs(60), async {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = nestlink_storage::Store::in_memory(&deployment)?;
        store.bootstrap_admin("admin", password().expose())?;
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = http.local_addr()?;
        let origin = format!("http://{address}");
        let app = nestlink_server::router(nestlink_server::AppState::new(
            store,
            VaultKey::from_bytes([71; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let server = tokio::spawn(async move { axum::serve(http, app).await });
        let mut controller_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        controller_sdk
            .login("admin".into(), password(), None)
            .await?;
        controller_sdk
            .create_account("host-owner".into(), password())
            .await?;
        let mut host_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment,
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        host_sdk
            .login("host-owner".into(), password(), None)
            .await?;
        let controller = Arc::new(DeviceIdentity::generate());
        let host = Arc::new(DeviceIdentity::generate());
        for (sdk, identity, role) in [
            (&controller_sdk, &controller, "controller"),
            (&host_sdk, &host, "host"),
        ] {
            sdk.enroll(
                identity,
                role.into(),
                "linux-x11".into(),
                vec![
                    role.into(),
                    "vp8".into(),
                    nestlink_protocol::remote_budget::CAPABILITY.into(),
                ],
                "direct_only".into(),
            )
            .await?;
        }
        let request = || RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![
                Permission::View as i32,
                Permission::Input as i32,
                Permission::FileRead as i32,
                Permission::FileWrite as i32,
            ],
            path_mode: "direct_only".into(),
        };
        let pending = controller_sdk.create_remote(request()).await?;
        host_sdk
            .approve(
                &host,
                &pending,
                ApprovalChoice {
                    approved: true,
                    permissions: vec![
                        Permission::View as i32,
                        Permission::Input as i32,
                        Permission::FileRead as i32,
                        Permission::FileWrite as i32,
                    ],
                    paths: vec![Path::Direct as i32],
                },
            )
            .await?;
        let initial = controller_sdk.permit(&pending.id).await?;
        host_sdk
            .trust_remote(
                &host,
                &initial,
                TrustChoice {
                    expected_revision: 0,
                    expires_at_unix_ms: wall()? + 120_000,
                },
            )
            .await?;
        let trusted = controller_sdk.create_trusted_remote(request()).await?;
        let original = controller_sdk.permit(&trusted.id).await?;
        let host_original = host_sdk.host_permit(&host, &trusted.id).await?;
        let space = random_id();
        let policy = controller_sdk
            .configure_network_authority(&space, 0)
            .await?;
        let authority: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&policy.authority_public_key)?
            .try_into()
            .map_err(|_| "authority length")?;
        for (revision, identity) in [(1, &controller), (2, &host)] {
            controller_sdk
                .set_network_member(
                    &space,
                    &identity.device_id,
                    NetworkMemberRequest {
                        expected_policy_revision: revision,
                        expected_membership_epoch: 0,
                        role: SpaceRole::Member,
                    },
                )
                .await?;
        }
        let policy = controller_sdk
            .set_offline_enabled(
                &space,
                &OfflineEnableUpdate {
                    expected_revision: 0,
                    enabled: true,
                },
            )
            .await?;
        let mut source_process = OfflineProcess::new(
            controller.device_id.clone(),
            controller.identity.public_key(),
            wall()?,
            policy.highest_revocation_epoch,
        )?;
        let mut host_process = OfflineProcess::new(
            host.device_id.clone(),
            host.identity.public_key(),
            wall()?,
            policy.highest_revocation_epoch,
        )?;
        let draft = controller_sdk
            .create_offline_remote_draft(
                &space,
                &OfflineRemoteDraftRequest {
                    session_id: trusted.id,
                    expected_policy_revision: 3,
                    expected_connection_generation: original.claims().connection_generation,
                    expected_lease_sequence: original.claims().lease_sequence,
                    process_nonces: [source_process.nonce(), host_process.nonce()],
                    operations: vec![
                        OfflineRemoteOperation::View,
                        OfflineRemoteOperation::FileRead,
                    ],
                    direct_transports: vec![
                        OfflineDirectTransport::Quic,
                        OfflineDirectTransport::Tls,
                    ],
                    maximum_bytes: 1048576,
                    maximum_file_write_bytes: 0,
                    maximum_connections: 4,
                    expires_at_ms: wall()? + 45_000,
                },
            )
            .await?;
        assert!(
            host_sdk
                .create_offline_remote_draft(
                    &space,
                    &OfflineRemoteDraftRequest {
                        session_id: original.claims().session_id.clone(),
                        expected_policy_revision: 3,
                        expected_connection_generation: original.claims().connection_generation,
                        expected_lease_sequence: original.claims().lease_sequence,
                        process_nonces: [source_process.nonce(), host_process.nonce()],
                        operations: vec![
                            OfflineRemoteOperation::View,
                            OfflineRemoteOperation::FileRead
                        ],
                        direct_transports: vec![OfflineDirectTransport::Quic],
                        maximum_bytes: 1048576,
                        maximum_file_write_bytes: 0,
                        maximum_connections: 4,
                        expires_at_ms: wall()? + 45_000,
                    }
                )
                .await
                .is_err()
        );
        controller_sdk
            .approve_offline_bundle(
                &controller,
                &source_process,
                &draft,
                &authority,
                0,
                draft.draft_digest,
            )
            .await?;
        let signed = host_sdk
            .approve_offline_bundle(
                &host,
                &host_process,
                &draft,
                &authority,
                1,
                draft.draft_digest,
            )
            .await?;
        let source = controller_sdk
            .activate_offline_bundle(
                &controller,
                &mut source_process,
                &signed,
                &authority,
                0,
                signed.draft_digest,
            )
            .await?;
        let target = host_sdk
            .activate_offline_bundle(
                &host,
                &mut host_process,
                &signed,
                &authority,
                1,
                signed.draft_digest,
            )
            .await?;
        assert!(
            controller_sdk
                .activate_offline_bundle(
                    &controller,
                    &mut source_process,
                    &signed,
                    &authority,
                    0,
                    signed.draft_digest
                )
                .await
                .is_err()
        );
        let c = original.claims();
        let binding = SessionBinding {
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            session_id: c.session_id.clone(),
            account_id: c.account_id.clone(),
            controller_device_id: c.controller_device_id.clone(),
            host_device_id: c.host_device_id.clone(),
            controller_key_sha256: controller.identity.fingerprint(),
            host_key_sha256: host.identity.fingerprint(),
            resource_id: c.resource_id.clone(),
            policy_revision: c.policy_revision,
            connection_generation: c.connection_generation,
            capability_sha256: c.capability_sha256.as_slice().try_into()?,
            granted_permissions: vec![
                Permission::View,
                Permission::Input,
                Permission::FileRead,
                Permission::FileWrite,
            ],
            supported_capabilities: c.required_capabilities.clone(),
            local_paths: nestlink_policy::PathSet::DIRECT,
            media: None,
        };
        let online_expiry = c.expires_at_unix_ms;
        let controller_sdk = Arc::new(controller_sdk);
        let host_sdk = Arc::new(host_sdk);
        let source = controller_sdk.prepare_offline_remote(
            controller.clone(),
            source,
            original.clone(),
            binding.clone(),
            EndpointRole::Controller,
        )?;
        let target = host_sdk.prepare_offline_remote(
            host.clone(),
            target,
            host_original,
            binding,
            EndpointRole::Host,
        )?;
        server.abort();
        let _ = server.await;
        let proof = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("management TCP listener was not released: {error}"),
                )
            })?;
        drop(proof);
        tokio::time::sleep(Duration::from_millis(
            online_expiry.saturating_sub(wall()?) + 20,
        ))
        .await;
        assert!(wall()? >= original.claims().expires_at_unix_ms);
        let source = NativeOfflineRemote::new(source, Limits::default())?;
        let target = NativeOfflineRemote::new(target, Limits::default())?;
        let original_bundle = source.binding()?.bundle_id;
        let original_lifetime = source.budget()?.remaining_lifetime_ms;
        // A real silent peer consumes one signed attempt. Returning that error
        // must release the original carrier and preserve this same authority,
        // rather than stop it or create a new budget for the next explicit try.
        let silent_udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let silent_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let silent_peer = match transport {
            NativeOfflineTransport::Quic => silent_udp.local_addr()?,
            NativeOfflineTransport::Tls => silent_tcp.local_addr()?,
        };
        assert!(source.connect(transport, silent_peer).await.is_err());
        drop(silent_udp);
        drop(silent_tcp);
        assert!(!source.budget()?.stopped);
        assert_eq!(source.binding()?.bundle_id, original_bundle);
        assert_eq!(source.budget()?.connection_attempts, 1);
        assert!(source.budget()?.remaining_lifetime_ms < original_lifetime);
        let listener = target.listen(transport, "127.0.0.1:0".parse()?).await?;
        let peer = listener.address()?;
        assert!(matches!(
            target.listen(transport, "127.0.0.1:0".parse()?).await,
            Err(NativeOfflineError::Active)
        ));
        let (host_session, controller_session) =
            tokio::join!(listener.accept(), source.connect(transport, peer));
        let mut host_session = host_session?;
        let mut controller_session = controller_session?;
        let host_handle = host_session.handle();
        let controller_handle = controller_session.handle();
        for handle in [&host_handle, &controller_handle] {
            let snapshot = handle.snapshot();
            assert_eq!(snapshot.authentication, Authentication::Disconnected);
            assert!(snapshot.server.is_none());
            assert!(snapshot.principal.is_none());
            let offline = snapshot
                .native_offline
                .as_ref()
                .ok_or("offline product scope missing")?;
            assert_eq!(offline.transport, transport);
            assert_eq!(
                offline.operations,
                vec![
                    OfflineRemoteOperation::View,
                    OfflineRemoteOperation::FileRead
                ]
            );
            assert_eq!(offline.budget.connection_attempts, if offline.is_host { 1 } else { 2 });
            assert!(handle.native_input_layout().is_err());
            assert!(handle.native_audio_binding().is_none());
        }
        let session_binding = host_handle
            .native_host_session_binding()
            .ok_or("host offline View missing")?;
        let forbidden = controller_handle
            .submit(Action::StartNativeSession {
                relay_node_id: None,
                request_id: session_binding.request_id.clone(),
            })?
            .wait()
            .await?;
        assert_eq!(forbidden.result.status, OperationStatus::Failed);
        assert_eq!(
            forbidden
                .result
                .failure
                .ok_or("online action failure missing")?
                .kind,
            FailureKind::SignInRequired
        );
        let resets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        host_handle.publish_native_display_candidates(
            &session_binding,
            vec![DisplayDescriptor {
                source: 0,
                left: 0,
                top: 0,
                width: 64,
                height: 48,
                label: "Explicit offline test display".into(),
            }],
            true,
        )?;
        host_handle
            .configure_native_video_stream(&session_binding, 0, 64, 48, 1)
            .await?;
        host_handle
            .advertise_native_displays(&session_binding)
            .await?;
        let request = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(request) =
                    host_handle.native_display_switch_request(&session_binding)?
                {
                    return Ok::<_, io::Error>(request);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        let selection = host_handle
            .commit_native_display_switch(&session_binding, &request)
            .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if controller_handle
                    .native_displays(&session_binding)?
                    .selected
                    .as_ref()
                    == Some(&selection)
                {
                    return Ok::<_, io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        let capture = host_handle.attach_native_video_capture(
            &session_binding,
            1,
            Capture {
                resets: resets.clone(),
                emitted: false,
            },
            nestlink_remote::video::Display {
                source: 0,
                logical: nestlink_remote::input::InputLayout {
                    left: 0,
                    top: 0,
                    width: 64,
                    height: 48,
                },
            },
        )?;
        let raw = capture.poll()?.ok_or("actual capture frame missing")?;
        let pixels = raw.frame.pixels.clone();
        drop(raw);
        let pts =
            host_handle.native_video_capture_pts(&session_binding, std::time::Instant::now())?;
        let packet = tokio::task::spawn_blocking(move || {
            nestlink_media_codec::Vp8Encoder::new(nestlink_media_codec::VideoConfig {
                width: 64,
                height: 48,
                fps: 30,
                bitrate_kbps: 1000,
            })?
            .encode(&pixels, pts, true)
        })
        .await??;
        host_handle
            .send_native_video_frame(
                &session_binding,
                NativeVideoBinding {
                    source: 0,
                    width: 64,
                    height: 48,
                    layout_epoch: 1,
                },
                pts,
                packet.keyframe,
                packet.data,
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(frame) = controller_handle.poll_native_video()? {
                    assert_eq!((frame.width, frame.height), (64, 48));
                    assert_eq!(frame.pixels.len(), 64 * 48 * 4);
                    assert!(frame.pixels.chunks_exact(4).all(|pixel| pixel[1] > 240));
                    return Ok::<_, NativeVideoError>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        let temporary_parent = std::env::temp_dir().canonicalize()?;
        let directory = temporary_parent.join(format!("nestlink-offline-core-{}", random_id()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let bytes: Vec<u8> = (0..262_144).map(|index| (index % 251) as u8).collect();
        std::fs::write(directory.join("source.bin"), &bytes)?;
        let root_id = random_id();
        let (root, _root_consent) = nestlink_platform_files::ApprovedReadRoot::open(
            &root_id,
            &directory,
            bytes.len() as u64,
        )?;
        host_handle
            .native_host_start_file_read(
                &session_binding,
                1,
                nestlink_platform_files::FileRoots::new(vec![root])?,
            )
            .await?;
        assert_eq!(
            controller_handle.native_file_access(&session_binding, 1)?,
            NativeFileAccess {
                is_host: false,
                read: true,
                write: false
            }
        );
        assert!(
            controller_handle
                .native_file_write_roots(&session_binding, 1)
                .await
                .is_err()
        );
        let output = directory.join("download");
        let (destination, _destination_consent) =
            nestlink_platform_files::download::LocalDownloadSelection::new(
                &output,
                "received.bin",
                bytes.len() as u64,
            )?;
        let task = controller_handle.native_download(
            &session_binding,
            1,
            nestlink_sdk::files::NativeDownloadRequest::new(&root_id, "source.bin")?,
            destination,
        )?;
        let downloaded = tokio::time::timeout(Duration::from_secs(5), task.wait_finished()).await?;
        assert_eq!(downloaded.phase, NativeFileTaskPhase::Completed);
        assert_eq!(downloaded.confirmed_bytes, bytes.len() as u64);
        assert_eq!(std::fs::read(output.join("received.bin"))?, bytes);
        assert!(source.budget()?.remaining_bytes < 1048576 - 262144);
        if transport == NativeOfflineTransport::Quic {
            let stop = controller_handle.submit(Action::StopNativeSession {
                request_id: session_binding.request_id.clone(),
                connection_generation: session_binding.connection_generation,
            })?;
            let completed = tokio::time::timeout(Duration::from_secs(5), stop.wait()).await??;
            assert_eq!(completed.result.status, OperationStatus::Succeeded);
        } else {
            source_process.stop();
        }
        let report = controller_session.wait_stopped().await?;
        let host_report = host_session.wait_stopped().await?;
        assert_eq!(report.cleanup, NativeSessionCleanup::Succeeded);
        assert!(report.failure.is_none());
        assert_eq!(host_report.cleanup, NativeSessionCleanup::Succeeded);
        assert!(host_report.failure.is_none());
        assert!(controller_handle.poll_native_video().is_err());
        assert!(controller_handle.native_file_session_binding().is_none());
        assert!(host_handle.native_host_session_binding().is_none());
        assert_eq!(resets.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(capture.poll().is_err());
        assert!(source.connect(transport, peer).await.is_err());
        match transport {
            NativeOfflineTransport::Quic => drop(std::net::UdpSocket::bind(peer)?),
            NativeOfflineTransport::Tls => drop(tokio::net::TcpListener::bind(peer).await?),
        }
        source_process.stop();
        host_process.stop();
        drop(capture);
        drop(host_session);
        drop(controller_session);
        drop(host_handle);
        drop(controller_handle);
        let resolved = directory.canonicalize()?;
        if resolved.parent() != Some(temporary_parent.as_path()) {
            return Err("test cleanup escaped temporary parent".into());
        }
        std::fs::remove_dir_all(resolved)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

struct Capture {
    resets: Arc<std::sync::atomic::AtomicUsize>,
    emitted: bool,
}
impl nestlink_remote::video::CaptureDevice for Capture {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<nestlink_remote::video::RawFrame>> {
        if std::mem::replace(&mut self.emitted, true) {
            return Ok(None);
        }
        Ok(Some(nestlink_remote::video::RawFrame {
            source: 0,
            width: 64,
            height: 48,
            captured_at: std::time::Instant::now(),
            pixels: [0, 255, 0, 255].repeat(64 * 48),
        }))
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_offline_app_core_quic_delivers_pixels_and_actual_file_after_online_expiry()
-> Result {
    exercise(NativeOfflineTransport::Quic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_offline_app_core_tls_delivers_pixels_and_actual_file_after_online_expiry()
-> Result {
    exercise(NativeOfflineTransport::Tls).await
}
