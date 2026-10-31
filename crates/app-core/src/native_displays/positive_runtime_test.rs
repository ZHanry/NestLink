//! Debug-only Core fixture using ordinary explicit candidate activation.
//! Encoded bytes and both direction announcements come from actual software MF
//! owners; no synthetic SPS or decoder is used.
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
                        if frame.channel==Channel::VideoFeedback && frame.payload.starts_with(b"NLMF")
                            && let FormatEnvelope::Ack(value)=FormatEnvelope::decode(&frame.payload).map_err(io::Error::other)?
                        {
                            *observed.lock().map_err(|_|io::Error::other("ACK barrier poisoned"))?=Some(value);
                            wait.acquire().await.map_err(io::Error::other)?.forget();
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
        quality: None,
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

// Match production capture timing: encoder work and request gaps consume real
// session time. A nominal accepted-frame counter hides those gaps from playout.
fn capture_pts(origin: Instant, captured_at: Instant, last: Option<u64>) -> io::Result<u64> {
    let elapsed = captured_at
        .checked_duration_since(origin)
        .ok_or_else(|| io::Error::other("fixture capture precedes origin"))?;
    let pts =
        u64::try_from(elapsed.as_nanos() * 90_000 / 1_000_000_000).map_err(io::Error::other)?;
    let minimum = last.map_or(Ok(0), |value| {
        value
            .checked_add(1)
            .ok_or_else(|| io::Error::other("fixture capture clock exhausted"))
    })?;
    Ok(pts.max(minimum))
}

fn first_au_capture_origin(first_pts: u64, released_at: Instant) -> io::Result<Instant> {
    let offset = Duration::from_nanos(
        u64::try_from(u128::from(first_pts) * 1_000_000_000 / 90_000).map_err(io::Error::other)?,
    );
    released_at
        .checked_sub(offset)
        .ok_or_else(|| io::Error::other("fixture clock rebase overflow"))
}

#[test]
fn actual_encoder_capture_timeline_retains_slow_request_gaps() -> io::Result<()> {
    use nestlink_media_session::{PlayoutDecision, SessionPlayoutClock};
    let origin = Instant::now();
    let clock = SessionPlayoutClock::default();
    let first = capture_pts(origin, origin, None)?;
    let due = clock.presentation_time(first, 90_000, origin)?;
    // A real encoder/request delay must advance PTS by the same elapsed time.
    // Count-based 30fps PTS would now be permanently behind the 40ms budget.
    let later = origin + Duration::from_millis(220);
    assert!(matches!(
        clock.schedule(3000, 90_000, later)?,
        PlayoutDecision::DropLate
    ));
    let next = capture_pts(origin, later, Some(first))?;
    assert_eq!(next, 19_800);
    assert!(
        matches!(clock.schedule(next, 90_000, later)?, PlayoutDecision::At(at)
        if at == due + Duration::from_millis(220))
    );
    assert_eq!(capture_pts(origin, later, Some(next))?, next + 1);
    // A replacement owner shares the session origin rather than restarting PTS.
    assert!(capture_pts(origin, later + Duration::from_millis(100), None)? > next);
    assert!(capture_pts(later, origin, None).is_err());
    // Initial ACK negotiation is outside the live media stream. Align to the
    // first AU's unchanged sealed PTS, not its much earlier encoding time.
    let released = origin + Duration::from_millis(1500);
    let rebased = first_au_capture_origin(9000, released)?;
    assert_eq!(capture_pts(rebased, released, None)?, 9000);
    assert_eq!(
        capture_pts(rebased, released + Duration::from_millis(220), Some(9000))?,
        28_800
    );
    Ok(())
}

// Presentation consumes its scheduled mailbox independently of synthetic
// capture/encoder request latency, as the real UI consumer does. The driver
// still submits at most eight further AUs with its existing 35ms cadence.
struct PresentationObserver {
    task: Option<JoinHandle<TestResult<DecodedVideo>>>,
}
impl PresentationObserver {
    fn start(
        controller: &CoreHandle,
        binding: &NativeSessionBinding,
        selection: &DisplaySelection,
    ) -> Self {
        let controller = controller.clone();
        let binding = binding.clone();
        let selection = selection.clone();
        Self {
            task: Some(tokio::spawn(async move {
                loop {
                    if let Some(frame) =
                        controller.poll_native_video_for_selection(&binding, &selection)?
                    {
                        return Ok(frame);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })),
        }
    }
    async fn take_if_ready(&mut self) -> TestResult<Option<DecodedVideo>> {
        if !self.task.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(None);
        }
        let task = self.task.take().ok_or("presentation observer absent")?;
        Ok(Some(task.await.map_err(io::Error::other)??))
    }
}
impl Drop for PresentationObserver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct ActualEncoder {
    requests_seen: std::sync::atomic::AtomicUsize,
    requests: Option<std::sync::mpsc::Sender<()>>,
    packets: std::sync::mpsc::Receiver<
        io::Result<(
            EncodedVideo,
            nestlink_protocol::media_format::VideoFormat,
            nestlink_media_codec::ExecutionReceipt,
        )>,
    >,
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
}
impl ActualEncoder {
    fn start(
        config: VideoConfig,
        target: nestlink_protocol::media_format::VideoFormat,
        capture_origin: Arc<Mutex<Instant>>,
        source: (u32, u32),
    ) -> Self {
        let (requests, receive) = std::sync::mpsc::channel();
        let (send, packets) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut encoder = VideoEncoder::with_execution_target(
                nestlink_media_session::h264_execution_target(target, config)?,
            )?;
            let mut prepare = nestlink_media_session::LegacyPrepare::new(
                nestlink_media_codec::VideoCodec::H264Baseline,
                config.width,
                config.height,
            )?;
            let original_pixels =
                Zeroizing::new([16, 128, 240, 255].repeat((source.0 * source.1) as usize));
            let pixels = nestlink_media_codec::scale_bgra(
                &original_pixels,
                source,
                (config.width, config.height),
            )?;
            let mut last_accepted_pts = None;
            let mut pending_pts = None;
            let mut request = 0usize;
            while receive.recv().is_ok() {
                request += 1;
                let request_started = Instant::now();
                let mut encode_elapsed = Duration::ZERO;
                let mut accepted_count = 0usize;
                let result = (|| {
                    for _ in 0..256 {
                        let pts = match pending_pts {
                            Some(pts) => pts,
                            None => capture_pts(
                                *capture_origin
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture clock poisoned"))?,
                                Instant::now(),
                                last_accepted_pts,
                            )?,
                        };
                        let step_started = Instant::now();
                        let step = encoder.encode_step(&pixels, pts, true)?;
                        encode_elapsed += step_started.elapsed();
                        if step.accepted {
                            accepted_count += 1;
                            last_accepted_pts = Some(pts);
                            pending_pts = None;
                        } else {
                            // Backpressure retries the same captured input and timestamp.
                            pending_pts = Some(pts);
                        }
                        if let Some(packet) = step.output {
                            let prepare_started = Instant::now();
                            let sps = prepare.validate(&packet.data, packet.keyframe)?;
                            let format = prepare.configured(config, sps)?;
                            let execution = encoder.execution_receipt().ok_or_else(|| {
                                io::Error::other("actual output lacks execution receipt")
                            })?;
                            if request <= 9 {
                                let origin = *capture_origin
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture clock poisoned"))?;
                                let output_clock_pts = capture_pts(origin, Instant::now(), None)?;
                                eprintln!(
                                    "fixture encode: request={} last_input_pts={} output_pts={} accepted_count={} encode_step_us={} prepare_receipt_us={} request_us={} capture_to_output_us={}",
                                    request,
                                    pts,
                                    packet.pts_90khz,
                                    accepted_count,
                                    encode_elapsed.as_micros(),
                                    prepare_started.elapsed().as_micros(),
                                    request_started.elapsed().as_micros(),
                                    u128::from(output_clock_pts.saturating_sub(packet.pts_90khz))
                                        * 1_000_000
                                        / 90_000
                                );
                            }
                            return Ok((packet, format, execution));
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
            requests_seen: std::sync::atomic::AtomicUsize::new(0),
            requests: Some(requests),
            packets,
            worker: Some(worker),
        }
    }
    async fn next(
        &self,
        route: &NativeVideoRoute,
    ) -> TestResult<(
        EncodedVideo,
        nestlink_protocol::media_format::VideoFormat,
        nestlink_media_codec::ExecutionReceipt,
    )> {
        // This fixture intentionally generates only independent IDRs. Core
        // rate-limits IDRs; wait before capturing their timestamp, rather than
        // presenting an already sealed AU after the pacing deadline expires.
        let deadline = route
            .cursor
            .lock()
            .map_err(|_| "fixture video cursor poisoned")?
            .last_keyframe
            .map(|last| {
                last + Duration::from_millis(nestlink_protocol::VIDEO_KEYFRAME_INTERVAL_MS)
            });
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline.into()).await;
        }
        let request = self.requests_seen.fetch_add(1, Ordering::Relaxed) + 1;
        let started = Instant::now();
        self.requests.as_ref().ok_or("encoder closed")?.send(())?;
        let output = self.packets.recv_timeout(Duration::from_secs(10))??;
        if request <= 9 {
            eprintln!(
                "fixture next: request={} output_pts={} next_wait_us={}",
                request,
                output.0.pts_90khz,
                started.elapsed().as_micros()
            );
        }
        Ok(output)
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
    let provider = crate::NativeMediaProvider::cpu_software_adaptive(config)?;
    let cancelled = AtomicBool::new(false);
    let encode = provider
        .announcement(&host_device, MediaDirection::Encode, &cancelled)
        .await?;
    let decode = provider
        .announcement(&controller_device, MediaDirection::Decode, &cancelled)
        .await?;
    assert_eq!(encode.formats, decode.formats);
    assert_eq!(encode.formats.len(), 3); // Every exact budget was independently probed.
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
            nestlink_protocol::native_qos::CAPABILITY.into(),
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
    let primary = *set
        .formats()
        .iter()
        .find(|format| {
            (
                format.width,
                format.height,
                format.frame_rate.numerator,
                format.max_kbps,
            ) == (config.width, config.height, config.fps, config.bitrate_kbps)
        })
        .ok_or("actual primary probe target missing")?;
    let policy =
        nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate {
            deployment_id: host_binding.deployment_id.clone(),
            account_id: host_binding.account_id.clone(),
            controller_device_id: host_binding.controller_device_id.clone(),
            host_device_id: host_binding.host_device_id.clone(),
            format: primary.encode()?,
            format_sha256: primary.digest()?,
            additional_formats: set
                .formats()
                .iter()
                .filter(|format| **format != primary)
                .map(|format| format.encode())
                .collect::<Result<Vec<_>, _>>()?,
        };
    host_binding.media = Some(
        host_binding
            .media
            .take()
            .ok_or("host local evidence absent")?
            .with_internal_software_candidate(policy.clone(), &host_permit, &encode, now.unix_ms)?,
    );
    controller_binding.media = Some(
        controller_binding
            .media
            .take()
            .ok_or("controller local evidence absent")?
            .with_internal_software_candidate(policy, &controller_permit, &decode, now.unix_ms)?,
    );
    // Use ordinary production activation with the exact local opt-in policy.
    // The debug fixture is still only the Core assembly and ACK barrier.
    let mut host_session = Session::activate(
        host_permit,
        host_binding,
        nestlink_protocol::Path::Direct,
        now.monotonic_ms,
        now,
    )?;
    let mut controller_session = Session::activate(
        controller_permit,
        controller_binding,
        nestlink_protocol::Path::Direct,
        now.monotonic_ms,
        now,
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
        receiver_qos: Mutex::new(nestlink_media_session::ReceiverReportTracker::default()),
        execution: Mutex::new(None),
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
    let capture_origin = Arc::new(Mutex::new(Instant::now()));
    let encoder = ActualEncoder::start(
        config,
        *set.formats()
            .iter()
            .find(|format| {
                format.frame_rate.numerator == config.fps && format.max_kbps == config.bitrate_kbps
            })
            .ok_or("empty signed maximum target")?,
        capture_origin.clone(),
        (config.width, config.height),
    );
    let (first, actual, first_execution) = encoder.next(&video).await?;
    host.register_native_video_execution(&session_binding, first_execution.clone())
        .await?;
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
    let mut altered = first.data.clone();
    if let Some(byte) = altered.first_mut() {
        *byte ^= 1;
    }
    assert!(
        host.send_native_video_execution_frame(
            &session_binding,
            source,
            first.pts_90khz,
            first.keyframe,
            false,
            altered,
            first_execution.clone()
        )
        .await
        .is_err()
    );
    // The first real AU was held for format negotiation. Receiver playout
    // anchors its sealed PTS at ingress; start subsequent captures from that
    // same point, excluding only this fixture's pre-stream ACK barrier pause.
    *capture_origin
        .lock()
        .map_err(|_| "fixture clock poisoned")? =
        first_au_capture_origin(first.pts_90khz, Instant::now())?;
    let mut observer = PresentationObserver::start(&controller, &session_binding, &selection);
    let send_started = Instant::now();
    host.send_native_video_execution_frame(
        &session_binding,
        source,
        first.pts_90khz,
        first.keyframe,
        false,
        first.data,
        first_execution.clone(),
    )
    .await?;
    eprintln!(
        "fixture send: phase=initial request=0 send_us={}",
        send_started.elapsed().as_micros()
    );
    let mut decoded = None;
    // Some software decoders buffer; submit additional real independent IDRs.
    for request in 1..=8 {
        let (packet, receipt, execution) = encoder.next(&video).await?;
        assert_eq!(receipt, actual);
        let send_started = Instant::now();
        host.send_native_video_execution_frame(
            &session_binding,
            source,
            packet.pts_90khz,
            packet.keyframe,
            false,
            packet.data,
            execution,
        )
        .await?;
        eprintln!(
            "fixture send: phase=initial request={request} send_us={}",
            send_started.elapsed().as_micros()
        );
        tokio::time::sleep(Duration::from_millis(35)).await;
        if let Some(frame) = observer.take_if_ready().await? {
            decoded = Some(frame);
            break;
        }
    }
    let frame = decoded.ok_or_else(|| {
        format!(
            "actual software AU produced no decoded pixels; receiver={:?}; stats={:?}",
            receiver.monitor().status(),
            receiver.stats()
        )
    })?;
    assert!(!frame.hardware_decode);
    assert_eq!((frame.width, frame.height), (config.width, config.height));
    assert_eq!(frame.epoch.connection, 9);
    assert_eq!(frame.source, 42);
    assert!(frame.pixels.chunks_exact(4).all(|p| p[0].abs_diff(16) <= 40
        && p[1].abs_diff(128) <= 40
        && p[2].abs_diff(240) <= 40
        && p[3] == 255));
    // The exact-format receiver uses the same original Core feedback owner.
    // Keep producing sealed actual AUs until its observed report reaches Core;
    // no report or manually injected health value stands in for this path.
    let feedback_deadline = Instant::now() + Duration::from_secs(2);
    while host.native_video_receiver_condition(&session_binding, source, config.fps)?
        == Some(nestlink_media_codec::ReceiverCondition::Unknown)
        && Instant::now() < feedback_deadline
    {
        let (packet, receipt, execution) = encoder.next(&video).await?;
        assert_eq!(receipt, actual);
        host.send_native_video_execution_frame(
            &session_binding,
            source,
            packet.pts_90khz,
            packet.keyframe,
            false,
            packet.data,
            execution,
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(35)).await;
    }
    let observed = host.native_video_receiver_condition(&session_binding, source, config.fps)?;
    assert!(matches!(
        observed,
        Some(
            nestlink_media_codec::ReceiverCondition::Healthy
                | nestlink_media_codec::ReceiverCondition::Congested
        )
    ));
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
    let (packet, receipt, execution) = encoder.next(&video).await?;
    assert_eq!(receipt, actual);
    host.send_native_video_execution_frame(
        &session_binding,
        source,
        packet.pts_90khz,
        packet.keyframe,
        true,
        packet.data,
        execution,
    )
    .await?;
    let decoder_before =
        controller.native_media_execution(&session_binding, MediaDirection::Decode)?;
    let encoder_before = host.native_media_execution(&session_binding, MediaDirection::Encode)?;
    encoder.close()?;
    assert!(encoder_before.retired_joined());
    assert!(encoder_before.check_current().is_err());
    assert!(decoder_before.check_current().is_ok()); // Encode cannot retire Decode's slot.
    let next_format = nestlink_media_session::select_h264_display_budget(
        &set,
        actual,
        (config.width, config.height),
        config.fps / 2,
        config.bitrate_kbps / 2,
    )?;
    assert_ne!(next_format, actual);
    assert!(set.contains(&next_format));
    let next_config =
        nestlink_media_session::h264_display_config(next_format, config.width, config.height)?;
    assert_eq!(
        (next_config.width, next_config.height),
        (config.width / 2, config.height / 2)
    );
    let encoder = ActualEncoder::start(
        next_config,
        next_format,
        capture_origin,
        (config.width, config.height),
    );
    let (fresh, receipt, fresh_execution) = encoder.next(&video).await?;
    assert_eq!(receipt, next_format);
    assert!(fresh_execution.identity()?.generation() > encoder_before.identity()?.generation());
    host.register_native_video_execution(&session_binding, fresh_execution.clone())
        .await?;
    assert!(
        !host
            .propose_native_video_format(&session_binding, next_format)
            .await?
    );
    until(|| {
        Ok(barrier
            .ack
            .lock()
            .map_err(|_| "ACK barrier poisoned")?
            .as_ref()
            .is_some_and(|ack| ack.format_epoch > confirmed.format_epoch))
    })
    .await?;
    assert!(
        host.native_confirmed_video_format(&session_binding)?
            .is_none()
    );
    barrier.release.add_permits(1);
    until(|| {
        Ok(host
            .native_confirmed_video_format(&session_binding)?
            .is_some_and(|value| value.format_epoch > confirmed.format_epoch))
    })
    .await?;
    let replacement = host
        .native_confirmed_video_format(&session_binding)?
        .ok_or("replacement ACK absent")?;
    assert_eq!(replacement.format, next_format);
    let original_display = controller.native_displays(&session_binding)?;
    assert_eq!(original_display.selected.as_ref(), Some(&selection));
    let original_source = original_display
        .displays
        .iter()
        .find(|display| display.source == source.source)
        .ok_or("source absent after downscale")?;
    assert_eq!(
        (original_source.width, original_source.height),
        (config.width, config.height)
    );
    let decoder_after =
        controller.native_media_execution(&session_binding, MediaDirection::Decode)?;
    assert!(decoder_before.retired_joined());
    assert!(decoder_before.check_current().is_err());
    assert!(decoder_after.identity()?.generation() > decoder_before.identity()?.generation());
    assert!(
        host.send_native_video_execution_frame(
            &session_binding,
            source,
            fresh.pts_90khz,
            fresh.keyframe,
            false,
            fresh.data.clone(),
            first_execution
        )
        .await
        .is_err()
    );
    let mut replacement_observer =
        PresentationObserver::start(&controller, &session_binding, &selection);
    assert!(
        host.send_native_video_execution_frame(
            &session_binding,
            NativeVideoBinding {
                width: next_config.width,
                height: next_config.height,
                ..source
            },
            fresh.pts_90khz,
            fresh.keyframe,
            false,
            fresh.data.clone(),
            fresh_execution.clone(),
        )
        .await
        .is_err(),
        "encoded output cannot relabel the approved physical source binding"
    );
    let send_started = Instant::now();
    host.send_native_video_execution_frame(
        &session_binding,
        source,
        fresh.pts_90khz,
        fresh.keyframe,
        false,
        fresh.data,
        fresh_execution,
    )
    .await?;
    eprintln!(
        "fixture send: phase=replacement request=0 send_us={}",
        send_started.elapsed().as_micros()
    );
    let mut replacement_pixels = false;
    for request in 1..=8 {
        let (packet, receipt, execution) = encoder.next(&video).await?;
        assert_eq!(receipt, next_format);
        let send_started = Instant::now();
        host.send_native_video_execution_frame(
            &session_binding,
            source,
            packet.pts_90khz,
            packet.keyframe,
            false,
            packet.data,
            execution,
        )
        .await?;
        eprintln!(
            "fixture send: phase=replacement request={request} send_us={}",
            send_started.elapsed().as_micros()
        );
        tokio::time::sleep(Duration::from_millis(35)).await;
        if let Some(frame) = replacement_observer.take_if_ready().await? {
            assert!(!frame.hardware_decode);
            assert_eq!(
                (frame.width, frame.height),
                (next_config.width, next_config.height)
            );
            assert!(frame.pixels.chunks_exact(4).all(|p| p[0].abs_diff(16) <= 40
                && p[1].abs_diff(128) <= 40
                && p[2].abs_diff(240) <= 40
                && p[3] == 255));
            replacement_pixels = true;
            break;
        }
    }
    assert!(
        replacement_pixels,
        "replacement actual owner produced no pixels; receiver={:?}; stats={:?}",
        receiver.monitor().status(),
        receiver.stats()
    );
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
        host.native_video_receiver_condition(&session_binding, source, config.fps)
            .is_err()
    );
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
