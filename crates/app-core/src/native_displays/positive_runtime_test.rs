//! Debug-only signed fixture. Encoded bytes and both direction announcements
//! come from actual software MF owners; no synthetic SPS or decoder is used.
use super::*;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_media_codec::{EncodedVideo, VideoConfig, VideoEncoder};
use nestlink_protocol::{Permission, PermitClaims, media_authority::*};
use nestlink_remote::{AuthorizedConnection, RuntimeClock, controller_proof, host_proof};
use nestlink_session::{EndpointRole, MediaSessionBinding, Session, SessionBinding};
use prost::Message;
use tokio::io::split;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Hold the real serialized ACK in transit, without manufacturing or changing it.
// The opposite direction keeps flowing, so Core's format gate is observable.
struct AckBarrier {
    task: JoinHandle<io::Result<()>>,
    ack: Arc<Mutex<Option<FormatSelection>>>,
    release: Arc<tokio::sync::Semaphore>,
}
impl AckBarrier {
    fn start(host: tokio::io::DuplexStream, controller: tokio::io::DuplexStream) -> Self {
        let (mut hr, mut hw) = split(host);
        let (mut cr, mut cw) = split(controller);
        let ack = Arc::new(Mutex::new(None));
        let observed = ack.clone();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let wait = release.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                result=tokio::io::copy(&mut hr,&mut cw)=>result.map(|_|()),
                result=async {
                    loop {
                        let frame=nestlink_transport_stream::read_frame(&mut cr).await?;
                        if frame.channel==Channel::VideoFeedback && frame.payload.starts_with(b"NLMF") {
                            if let FormatEnvelope::Ack(value)=FormatEnvelope::decode(&frame.payload).map_err(io::Error::other)? {
                                *observed.lock().map_err(|_|io::Error::other("ACK barrier poisoned"))?=Some(value);
                                wait.acquire().await.map_err(io::Error::other)?.forget();
                            }
                        }
                        nestlink_transport_stream::write_frame(&mut hw,frame.channel,&frame.payload).await?;
                    }
                }=>result,
            }
        });
        Self { task, ack, release }
    }
}
impl Drop for AckBarrier {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn until(mut predicate: impl FnMut() -> TestResult<bool>) -> TestResult {
    tokio::time::timeout(Duration::from_secs(8), async {
        while !predicate()? {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

// Only fixture assembly is local: the shared objects, public Core APIs,
// NativeDisplayRoute workers, ChannelRuntime and VideoReceiver are production.
fn core_handle(core: &AppCore, host: bool) -> (CoreHandle, watch::Sender<Arc<Snapshot>>) {
    let mut handle = core.handle();
    let mut snapshot = (*handle.snapshot()).clone();
    snapshot.native_session.replace(NativeSessionView {
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(),
        connection_generation: 9,
        lease_sequence: 1,
        status: NativeSessionStatus::Connected,
        host_view_authorized: host,
        path: Some(nestlink_protocol::Path::Direct as i32),
        stop_reason: None,
        stop_effects: None,
        cleanup: None,
        failure: None,
    });
    let (view, receiver) = watch::channel(Arc::new(snapshot));
    handle.view = receiver;
    (handle, view)
}
fn key(host: bool) -> NativeSessionKey {
    NativeSessionKey {
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(),
        connection_generation: 9,
        lease_sequence: 1,
        is_host: host,
        host_view_authorized: host,
        controller_view_authorized: !host,
        input_authorized: false,
        audio_authorized: false,
        file_read_authorized: false,
        file_write_authorized: false,
        clipboard_read_authorized: false,
        clipboard_write_authorized: false,
        path: nestlink_protocol::Path::Direct as i32,
    }
}

struct ActualEncoder {
    requests: Option<std::sync::mpsc::Sender<()>>,
    packets: std::sync::mpsc::Receiver<
        io::Result<(EncodedVideo, nestlink_protocol::media_format::VideoFormat)>,
    >,
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
}
impl ActualEncoder {
    fn start(config: VideoConfig, target: nestlink_protocol::media_format::VideoFormat) -> Self {
        let (requests, receive) = std::sync::mpsc::channel();
        let (send, packets) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut encoder = VideoEncoder::new_h264_software(
                config,
                nestlink_media_session::software_h264_execution_limits(target)?,
            )?;
            let mut prepare = nestlink_media_session::LegacyPrepare::new(
                nestlink_media_codec::VideoCodec::H264Baseline,
                config.width,
                config.height,
            )?;
            let pixels =
                Zeroizing::new([16, 128, 240, 255].repeat((config.width * config.height) as usize));
            let mut accepted = 0u64;
            while receive.recv().is_ok() {
                let result = (|| {
                    for _ in 0..256 {
                        let step = encoder.encode_step(
                            &pixels,
                            1 + accepted * 90_000 / u64::from(config.fps),
                            true,
                        )?;
                        accepted += u64::from(step.accepted);
                        if let Some(packet) = step.output {
                            let sps = prepare.validate(&packet.data, packet.keyframe)?;
                            let format = prepare.configured(config, sps)?;
                            return Ok((packet, format));
                        }
                    }
                    Err(io::Error::other("actual software encoder produced no AU"))
                })();
                if send.send(result).is_err() {
                    break;
                }
            }
            encoder.close()
        });
        Self {
            requests: Some(requests),
            packets,
            worker: Some(worker),
        }
    }
    fn next(&self) -> TestResult<(EncodedVideo, nestlink_protocol::media_format::VideoFormat)> {
        self.requests.as_ref().ok_or("encoder closed")?.send(())?;
        Ok(self.packets.recv_timeout(Duration::from_secs(10))??)
    }
    fn close(mut self) -> TestResult {
        self.requests.take();
        self.worker
            .take()
            .ok_or("encoder worker absent")?
            .join()
            .map_err(|_| io::Error::other("encoder worker panicked"))??;
        Ok(())
    }
}

impl Drop for ActualEncoder {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn positive_signed_software_core_ack_au() -> TestResult {
    let config = VideoConfig {
        width: 320,
        height: 240,
        fps: 30,
        bitrate_kbps: 1000,
    };
    let host_identity = InstallationIdentity::generate();
    let controller_identity = InstallationIdentity::generate();
    let host_device = random_id();
    let controller_device = random_id();
    let provider = crate::NativeMediaProvider::cpu_software(config)?;
    let cancelled = AtomicBool::new(false);
    let encode = provider
        .announcement(&host_device, MediaDirection::Encode, &cancelled)
        .await?;
    let decode = provider
        .announcement(&controller_device, MediaDirection::Decode, &cancelled)
        .await?;
    assert_eq!(encode.formats, decode.formats);
    assert_eq!(encode.probe.backend, "cpu-software");
    assert_eq!(decode.probe.backend, "cpu-software");
    let set = decode_formats(&encode.formats, false)?;
    let frozen = FrozenMediaScope {
        version: FORMAT_VERSION,
        controller_revision: decode.revision,
        host_revision: encode.revision,
        formats: encode.formats.clone(),
        sha256: set.digest().to_vec(),
    };
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: nestlink_session::MEDIA_REGRESSION_SESSION_ID.into(),
        account_id: random_id(),
        controller_device_id: controller_device,
        host_device_id: host_device,
        controller_key_sha256: controller_identity.fingerprint(),
        host_key_sha256: host_identity.fingerprint(),
        resource_id: random_id(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec![
            nestlink_protocol::media::H264_CAPABILITY.into(),
            FORMAT_CAPABILITY.into(),
        ],
        local_paths: nestlink_policy::PathSet::DIRECT,
        media: None,
    };
    let claims = PermitClaims {
        schema_version: 1,
        deployment_id: binding.deployment_id.clone(),
        security_epoch: 1,
        session_id: binding.session_id.clone(),
        account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(),
        host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: binding.controller_key_sha256.to_vec(),
        host_key_sha256: binding.host_key_sha256.to_vec(),
        resource_id: binding.resource_id.clone(),
        permissions: vec![Permission::View as i32],
        paths: vec![nestlink_protocol::Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
        capability_sha256: binding.capability_sha256.to_vec(),
        required_capabilities: binding.supported_capabilities.clone(),
        media_format_version: FORMAT_VERSION,
        media_formats: frozen.formats.clone(),
        media_format_sha256: frozen.sha256.clone(),
    };
    let signer = PermitSigner::generate();
    let wire = signer.sign(&claims)?.encode_to_vec();
    let host_permit = verify_permit(&wire, &signer.public_key())?;
    let controller_permit = verify_permit(&wire, &signer.public_key())?;
    let mut host_binding = binding.clone();
    host_binding.media = Some(MediaSessionBinding::from_local_announcement(
        &host_permit,
        &frozen,
        &encode,
        EndpointRole::Host,
        now.unix_ms,
    )?);
    let mut controller_binding = binding;
    controller_binding.media = Some(MediaSessionBinding::from_local_announcement(
        &controller_permit,
        &frozen,
        &decode,
        EndpointRole::Controller,
        now.unix_ms,
    )?);
    // Feature selection itself never changes ordinary Session activation.
    assert!(
        Session::activate(
            verify_permit(&wire, &signer.public_key())?,
            host_binding.clone(),
            nestlink_protocol::Path::Direct,
            now.monotonic_ms,
            now
        )
        .is_err()
    );
    assert!(
        Session::activate_media_runtime_regression(
            verify_permit(&wire, &signer.public_key())?,
            host_binding.clone(),
            nestlink_protocol::Path::Direct,
            now.monotonic_ms,
            now,
            &random_id()
        )
        .is_err()
    );
    assert!(
        Session::activate_with_retained_deadline(
            verify_permit(&wire, &signer.public_key())?,
            host_binding.clone(),
            nestlink_protocol::Path::Direct,
            now,
            now.monotonic_ms + 10000
        )
        .is_err()
    );
    let mut no_local = host_binding.clone();
    no_local.media = None;
    assert!(
        Session::activate_media_runtime_regression(
            verify_permit(&wire, &signer.public_key())?,
            no_local,
            nestlink_protocol::Path::Direct,
            now.monotonic_ms,
            now,
            nestlink_session::MEDIA_REGRESSION_REQUEST_ID
        )
        .is_err()
    );
    let mut no_view = host_binding.clone();
    no_view.granted_permissions.clear();
    assert!(
        Session::activate_media_runtime_regression(
            verify_permit(&wire, &signer.public_key())?,
            no_view,
            nestlink_protocol::Path::Direct,
            now.monotonic_ms,
            now,
            nestlink_session::MEDIA_REGRESSION_REQUEST_ID
        )
        .is_err()
    );
    let mut host_session = Session::activate_media_runtime_regression(
        host_permit,
        host_binding,
        nestlink_protocol::Path::Direct,
        now.monotonic_ms,
        now,
        nestlink_session::MEDIA_REGRESSION_REQUEST_ID,
    )?;
    let mut controller_session = Session::activate_media_runtime_regression(
        controller_permit,
        controller_binding,
        nestlink_protocol::Path::Direct,
        now.monotonic_ms,
        now,
        nestlink_session::MEDIA_REGRESSION_REQUEST_ID,
    )?;
    let (h, host_bridge) = tokio::io::duplex(1 << 20);
    let (c, controller_bridge) = tokio::io::duplex(1 << 20);
    let barrier = AckBarrier::start(host_bridge, controller_bridge);
    let (mut hr, mut hw) = split(h);
    let (mut cr, mut cw) = split(c);
    let host_public = host_identity.public_key();
    let controller_public = controller_identity.public_key();
    tokio::try_join!(
        host_proof(
            &mut hr,
            &mut hw,
            &mut host_session,
            &host_identity,
            &controller_public,
            &clock
        ),
        controller_proof(
            &mut cr,
            &mut cw,
            &mut controller_session,
            &controller_identity,
            &host_public,
            &clock
        ),
    )?;
    let (_host_revoke, host_stop) = watch::channel(None);
    let (_controller_revoke, controller_stop) = watch::channel(None);
    let mut host_channels = AuthorizedConnection::new(
        hr,
        hw,
        host_session,
        nestlink_protocol::Path::Direct,
        clock.clone(),
        host_stop,
    )?
    .into_channels();
    let mut controller_channels = AuthorizedConnection::new(
        cr,
        cw,
        controller_session,
        nestlink_protocol::Path::Direct,
        clock,
        controller_stop,
    )?
    .into_channels();
    let host_lease = host_channels.lease_control();
    assert!(host_lease.check_media_binding(Channel::Video, 9).is_ok());
    assert!(host_lease.check_channel_binding(Channel::Input, 9).is_err());
    assert!(host_lease.check_media_binding(Channel::Video, 8).is_err());
    let mut host_core = AppCore::start(Limits::default())?;
    let mut controller_core = AppCore::start(Limits::default())?;
    let (host, _host_view) = core_handle(&host_core, true);
    let (controller, _controller_view) = core_handle(&controller_core, false);
    let mut receiver = VideoReceiver::attach_advertised_channel_timed(
        &mut controller_channels,
        9,
        SessionMediaTiming::default().playout,
    )?;
    controller
        .shared
        .set_native_video_presentation(Some(Arc::new(NativeVideoPresentationRoute {
            request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(),
            connection_generation: 9,
            generation: 1,
            presentation: receiver.presentation(),
        })));
    let video = Arc::new(NativeVideoRoute {
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(),
        connection_generation: 9,
        sender: host_channels.sender(),
        lease: host_lease.clone(),
        gate: Arc::new(HostVideoGate {
            state: Mutex::new(HostVideoGateState::default()),
        }),
        format_gate: Arc::new(HostVideoGate {
            state: Mutex::new(HostVideoGateState {
                active: true,
                ..HostVideoGateState::default()
            }),
        }),
        send_order: AsyncMutex::new(()),
        cursor: Mutex::new(NativeVideoCursor::default()),
        timing: SessionMediaTiming::default(),
    });
    host.shared.set_native_video_route(Some(video.clone()));
    let (host_route, host_feedback) =
        NativeDisplayRoute::attach(&host.shared, &mut host_channels, &key(true), 1)?;
    let (controller_route, controller_feedback) =
        NativeDisplayRoute::attach(&controller.shared, &mut controller_channels, &key(false), 1)?;
    host.shared.set_native_display_route(Some(host_route));
    controller
        .shared
        .set_native_display_route(Some(controller_route.clone()));
    let session_binding = NativeSessionBinding {
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(),
        connection_generation: 9,
    };
    host.publish_native_display_candidates(
        &session_binding,
        vec![DisplayDescriptor {
            source: 42,
            left: 0,
            top: 0,
            width: config.width,
            height: config.height,
            label: "Software regression".into(),
        }],
        true,
    )?;
    host.advertise_native_displays(&session_binding).await?;
    until(|| {
        Ok(host
            .native_display_switch_request(&session_binding)?
            .is_some())
    })
    .await?;
    let request = host
        .native_display_switch_request(&session_binding)?
        .ok_or("no display switch")?;
    let selection = host
        .commit_native_display_switch(&session_binding, &request)
        .await?;
    until(|| Ok(host.native_displays(&session_binding)?.selected.as_ref() == Some(&selection)))
        .await?;
    assert!(video.gate.is_active()); // Actual encoder may progress before NLMF ACK.
    let encoder =
        ActualEncoder::start(config, *set.formats().first().ok_or("empty signed target")?);
    let (first, actual) = encoder.next()?;
    assert!(first.keyframe);
    assert!(set.contains(&actual));
    let source = NativeVideoBinding {
        source: 42,
        width: config.width,
        height: config.height,
        layout_epoch: selection.layout_epoch,
    };
    assert!(
        !host
            .propose_native_video_format(&session_binding, actual)
            .await?
    );
    until(|| {
        Ok(barrier
            .ack
            .lock()
            .map_err(|_| "ACK barrier poisoned")?
            .is_some())
    })
    .await?;
    assert!(
        host.native_confirmed_video_format(&session_binding)?
            .is_none()
    );
    assert!(!video.format_gate.is_active());
    assert!(
        host.send_native_video_frame(
            &session_binding,
            source,
            first.pts_90khz,
            first.keyframe,
            first.data.clone()
        )
        .await
        .is_err()
    );
    // Zero AU has been submitted; format preparation alone cannot publish pixels.
    assert!(
        controller
            .poll_native_video_for_selection(&session_binding, &selection)?
            .is_none()
    );
    barrier.release.add_permits(1);
    until(|| {
        Ok(host
            .native_confirmed_video_format(&session_binding)?
            .is_some())
    })
    .await?;
    let confirmed = host
        .native_confirmed_video_format(&session_binding)?
        .ok_or("missing format ACK")?;
    until(|| {
        Ok(controller.native_displays(&session_binding)?.format_epoch == confirmed.format_epoch)
    })
    .await?;
    assert_eq!(confirmed.format, actual);
    assert_eq!(
        barrier
            .ack
            .lock()
            .map_err(|_| "ACK barrier poisoned")?
            .as_ref(),
        Some(&confirmed)
    );
    assert_eq!(
        controller.native_displays(&session_binding)?.format_sha256,
        confirmed.format_sha256
    );
    assert!(video.format_gate.is_active());
    assert!(
        host.propose_native_video_format(&session_binding, actual)
            .await?
    );
    host.send_native_video_frame(
        &session_binding,
        source,
        first.pts_90khz,
        first.keyframe,
        first.data,
    )
    .await?;
    let mut decoded = None;
    // Some software decoders buffer; submit additional real independent IDRs.
    for _ in 0..8 {
        let (packet, receipt) = encoder.next()?;
        assert_eq!(receipt, actual);
        host.send_native_video_frame(
            &session_binding,
            source,
            packet.pts_90khz,
            packet.keyframe,
            packet.data,
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(35)).await;
        if let Some(frame) =
            controller.poll_native_video_for_selection(&session_binding, &selection)?
        {
            decoded = Some(frame);
            break;
        }
    }
    let frame = decoded.ok_or("actual software AU produced no decoded pixels")?;
    assert!(!frame.hardware_decode);
    assert_eq!((frame.width, frame.height), (config.width, config.height));
    assert_eq!(frame.epoch.connection, 9);
    assert_eq!(frame.source, 42);
    assert!(frame.pixels.chunks_exact(4).all(|p| p[0].abs_diff(16) <= 40
        && p[1].abs_diff(128) <= 40
        && p[2].abs_diff(240) <= 40
        && p[3] == 255));
    let request = NativeVideoFeedback {
        schema_version: 1,
        connection_generation: 9,
        layout_epoch: selection.layout_epoch,
        source: 42,
        request_sequence: 1,
        last_sequence: frame.sequence,
        reason: nestlink_protocol::VideoRecoveryReason::KeyframeMissing as i32,
        format_epoch: confirmed.format_epoch,
        format_sha256: confirmed.format_sha256.to_vec(),
    };
    let mut retired_request = request.clone();
    retired_request.format_epoch = 0;
    retired_request.format_sha256.clear();
    // A pre-format recovery already in transit cannot consume the new ledger.
    controller_route
        .send(DisplayEnvelope::Recovery(retired_request))
        .await?;
    controller_route
        .send(DisplayEnvelope::Recovery(request.clone()))
        .await?;
    until(|| {
        Ok(video
            .cursor
            .lock()
            .map_err(|_| "cursor poisoned")?
            .last_feedback
            .as_ref()
            == Some(&request))
    })
    .await?;
    let (packet, receipt) = encoder.next()?;
    assert_eq!(receipt, actual);
    host.send_native_video_recovery_frame(&session_binding, source, packet.pts_90khz, packet.data)
        .await?;
    let mut stale = session_binding.clone();
    stale.connection_generation = 8;
    assert!(host.native_displays(&stale).is_err());
    assert!(
        controller
            .poll_native_video_for_selection(&stale, &selection)
            .is_err()
    );
    host_lease.stop(StopReason::ExplicitExit)?;
    assert!(
        host.propose_native_video_format(&session_binding, actual)
            .await
            .is_err()
    );
    assert!(
        host.send_native_video_frame(&session_binding, source, 999_999, true, Vec::new())
            .await
            .is_err()
    );
    encoder.close()?;
    assert_eq!(
        receiver.shutdown(StopReason::ExplicitExit)?,
        nestlink_media_session::ShutdownReport::Joined
    );
    host_feedback.abort();
    controller_feedback.abort();
    let _ = host_feedback.await;
    let _ = controller_feedback.await;
    let _ = host_core.shutdown(Duration::from_secs(2)).await;
    let _ = controller_core.shutdown(Duration::from_secs(2)).await;
    Ok(())
}
