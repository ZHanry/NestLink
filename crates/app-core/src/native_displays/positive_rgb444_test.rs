//! The v6 case uses real fixed libvpx direction probes, production activation,
//! NLMF selection/ACK, sealed AUs and original-decoder export. This finite
//! hosted test makes no desktop scanout or sustained target performance claim.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn positive_signed_rgb444_core_ack_au_and_original_decoded_export() -> TestResult {
    let config = VideoConfig { width: 65, height: 33, fps: 30, bitrate_kbps: 4000 };
    let host_identity = InstallationIdentity::generate();
    let controller_identity = InstallationIdentity::generate();
    let host_device = random_id();
    let controller_device = random_id();
    let provider = crate::NativeMediaProvider::software_vp9_rgb444(config)?;
    let cancelled = AtomicBool::new(false);
    let encode = provider.announcement(&host_device, MediaDirection::Encode, &cancelled).await?;
    let decode = provider.announcement(&controller_device, MediaDirection::Decode, &cancelled).await?;
    assert_eq!(encode.formats, decode.formats);
    assert_eq!(encode.formats.len(), 1);
    assert_eq!(encode.version, VP9_RGB444_FORMAT_VERSION);
    assert_eq!(encode.probe.backend, "cpu-software");
    assert_eq!(decode.probe.backend, "cpu-software");
    assert_ne!(encode.probe.resource_id, decode.probe.resource_id);
    let set = decode_formats_for_version(&encode.formats, false, VP9_RGB444_FORMAT_VERSION)?;
    let frozen = FrozenMediaScope { version: VP9_RGB444_FORMAT_VERSION,
        controller_revision: decode.revision, host_revision: encode.revision,
        formats: encode.formats.clone(), sha256: set.digest().to_vec() };
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        deployment_id: random_id(), security_epoch: 1,
        session_id: nestlink_session::MEDIA_REGRESSION_SESSION_ID.into(), account_id: random_id(),
        controller_device_id: controller_device, host_device_id: host_device,
        controller_key_sha256: controller_identity.fingerprint(), host_key_sha256: host_identity.fingerprint(),
        resource_id: random_id(), policy_revision: 1, connection_generation: 9, capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into(), VP9_RGB444_FORMAT_CAPABILITY.into(), nestlink_protocol::native_qos::CAPABILITY.into()],
        local_paths: nestlink_policy::PathSet::DIRECT, media: None,
    };
    let claims = PermitClaims {
        schema_version: 1, deployment_id: binding.deployment_id.clone(), security_epoch: 1,
        session_id: binding.session_id.clone(), account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(), host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: binding.controller_key_sha256.to_vec(), host_key_sha256: binding.host_key_sha256.to_vec(),
        resource_id: binding.resource_id.clone(), permissions: vec![Permission::View as i32],
        paths: vec![nestlink_protocol::Path::Direct as i32], policy_revision: 1,
        connection_generation: 9, lease_sequence: 1, issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + nestlink_protocol::SESSION_LEASE_MS,
        capability_sha256: binding.capability_sha256.to_vec(), required_capabilities: binding.supported_capabilities.clone(),
        media_format_version: VP9_RGB444_FORMAT_VERSION, media_formats: frozen.formats.clone(), media_format_sha256: frozen.sha256.clone(),
    };
    let signer = PermitSigner::from_seed([77; 32]);
    let wire = signer.sign(&claims)?.encode_to_vec();
    let host_permit = verify_permit(&wire, &signer.public_key())?;
    let controller_permit = verify_permit(&wire, &signer.public_key())?;
    let mut host_binding = binding.clone();
    let host_media = MediaSessionBinding::from_local_announcement(&host_permit, &frozen, &encode, EndpointRole::Host, now.unix_ms)?;
    host_binding.media = Some(host_media.clone());
    assert!(Session::activate(host_permit.clone(), host_binding.clone(), nestlink_protocol::Path::Direct, now.monotonic_ms, now).is_err());
    host_binding.media = Some(host_media.with_explicit_media_selection(set.clone(), &host_permit, &encode, now.unix_ms)?);
    let mut controller_binding = binding;
    controller_binding.media = Some(MediaSessionBinding::from_local_announcement(&controller_permit, &frozen, &decode, EndpointRole::Controller, now.unix_ms)?
        .with_explicit_media_selection(set.clone(), &controller_permit, &decode, now.unix_ms)?);
    let mut host_session = Session::activate(host_permit, host_binding, nestlink_protocol::Path::Direct, now.monotonic_ms, now)?;
    let mut controller_session = Session::activate(controller_permit, controller_binding, nestlink_protocol::Path::Direct, now.monotonic_ms, now)?;
    let (h, host_bridge) = tokio::io::duplex(1 << 20);
    let (c, controller_bridge) = tokio::io::duplex(1 << 20);
    let barrier = AckBarrier::start(host_bridge, controller_bridge);
    let (mut hr, mut hw) = split(h); let (mut cr, mut cw) = split(c);
    let host_public = host_identity.public_key();
    let controller_public = controller_identity.public_key();
    tokio::try_join!(
        host_proof(&mut hr, &mut hw, &mut host_session, &host_identity, &controller_public, &clock),
        controller_proof(&mut cr, &mut cw, &mut controller_session, &controller_identity, &host_public, &clock),
    )?;
    let (_host_revoke, host_stop) = watch::channel(None);
    let (_controller_revoke, controller_stop) = watch::channel(None);
    let mut host_channels = AuthorizedConnection::new(hr, hw, host_session, nestlink_protocol::Path::Direct, clock.clone(), host_stop)?.into_channels();
    let mut controller_channels = AuthorizedConnection::new(cr, cw, controller_session, nestlink_protocol::Path::Direct, clock, controller_stop)?.into_channels();
    let host_lease = host_channels.lease_control();
    let mut host_core = AppCore::start(Limits::default())?;
    let mut controller_core = AppCore::start(Limits::default())?;
    let (host, _host_view) = core_handle(&host_core, true);
    let (controller, _controller_view) = core_handle(&controller_core, false);
    let mut receiver = VideoReceiver::attach_advertised_channel_timed(&mut controller_channels, 9, SessionMediaTiming::default().playout)?;
    controller.shared.set_native_video_presentation(Some(Arc::new(NativeVideoPresentationRoute {
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(), connection_generation: 9, generation: 1, presentation: receiver.presentation(),
    })));
    let video = Arc::new(NativeVideoRoute {
        receiver_qos: Mutex::new(nestlink_media_session::ReceiverReportTracker::default()), execution: Mutex::new(None),
        request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(), connection_generation: 9,
        sender: host_channels.sender(), lease: host_lease.clone(),
        gate: Arc::new(HostVideoGate { state: Mutex::new(HostVideoGateState::default()) }),
        format_gate: Arc::new(HostVideoGate { state: Mutex::new(HostVideoGateState { active: true, ..HostVideoGateState::default() }) }),
        send_order: AsyncMutex::new(()), cursor: Mutex::new(NativeVideoCursor::default()), timing: SessionMediaTiming::default(),
    });
    host.shared.set_native_video_route(Some(video.clone()));
    let (host_route, host_feedback) = NativeDisplayRoute::attach(&host.shared, &mut host_channels, &key(true), 1)?;
    let (controller_route, controller_feedback) = NativeDisplayRoute::attach(&controller.shared, &mut controller_channels, &key(false), 1)?;
    host.shared.set_native_display_route(Some(host_route));
    controller.shared.set_native_display_route(Some(controller_route));
    let session_binding = NativeSessionBinding { request_id: nestlink_session::MEDIA_REGRESSION_REQUEST_ID.into(), connection_generation: 9 };
    host.publish_native_display_candidates(&session_binding, vec![DisplayDescriptor { source: 42, left: 0, top: 0, width: config.width, height: config.height, label: "RGB444 software regression".into() }], true)?;
    host.advertise_native_displays(&session_binding).await?;
    until(|| Ok(host.native_display_switch_request(&session_binding)?.is_some())).await?;
    let request = host.native_display_switch_request(&session_binding)?.ok_or("RGB444 switch absent")?;
    let selection = host.commit_native_display_switch(&session_binding, &request).await?;
    until(|| Ok(host.native_displays(&session_binding)?.selected.as_ref() == Some(&selection))).await?;
    let target = *set.formats().first().ok_or("RGB444 exact format absent")?;
    let capture_origin = Arc::new(Mutex::new(Instant::now()));
    let encoder = ActualEncoder::start(config, target, capture_origin.clone(), (config.width, config.height));
    let (first, actual, execution) = encoder.next(&video).await?;
    assert_eq!(actual, target);
    assert!(first.keyframe);
    host.register_native_video_execution(&session_binding, execution.clone()).await?;
    let source = NativeVideoBinding { source: 42, width: config.width, height: config.height, layout_epoch: selection.layout_epoch };
    assert!(!host.propose_native_video_format(&session_binding, actual).await?);
    until(|| Ok(barrier.ack.lock().map_err(|_| "RGB444 ACK barrier poisoned")?.is_some())).await?;
    assert!(host.native_confirmed_video_format(&session_binding)?.is_none());
    assert!(host.send_native_video_execution_frame(&session_binding, source, first.pts_90khz, true, false, first.data.clone(), execution.clone()).await.is_err());
    assert!(controller.poll_native_video_for_selection(&session_binding, &selection)?.is_none());
    barrier.release.add_permits(1);
    until(|| Ok(host.native_confirmed_video_format(&session_binding)?.is_some())).await?;
    let confirmed = host.native_confirmed_video_format(&session_binding)?.ok_or("RGB444 ACK absent")?;
    assert_eq!(confirmed.format, target);
    until(|| Ok(controller.native_displays(&session_binding)?.format_sha256 == confirmed.format_sha256)).await?;
    assert!(controller.open_native_compressed(&session_binding, 42).is_err());
    let mut altered = first.data.clone(); altered[0] ^= 1;
    assert!(host.send_native_video_execution_frame(&session_binding, source, first.pts_90khz, true, false, altered, execution.clone()).await.is_err());
    *capture_origin.lock().map_err(|_| "RGB444 fixture clock poisoned")? = first_au_capture_origin(first.pts_90khz, Instant::now())?;
    let mut observer = PresentationObserver::start(&controller, &session_binding, &selection);
    host.send_native_video_execution_frame(&session_binding, source, first.pts_90khz, true, false, first.data, execution.clone()).await?;
    let mut decoded = None;
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(35)).await;
        if let Some(frame) = observer.take_if_ready().await? { decoded = Some(frame); break; }
        let (packet, format, receipt) = encoder.next(&video).await?;
        assert_eq!(format, target);
        host.send_native_video_execution_frame(&session_binding, source, packet.pts_90khz, packet.keyframe, false, packet.data, receipt).await?;
    }
    let frame = decoded.ok_or_else(|| format!("actual RGB444 AU produced no original decoded pixels; receiver={:?}; stats={:?}", receiver.monitor().status(), receiver.stats()))?;
    assert_eq!(frame.codec, nestlink_protocol::NativeVideoCodec::Vp9Rgb444 as u8);
    assert!(!frame.hardware_decode);
    assert_eq!((frame.width, frame.height), (65, 33));
    assert_eq!(frame.source_color, nestlink_protocol::media_format::Color::RGB_SRGB_FULL);
    assert_eq!(frame.epoch.connection, 9);
    assert_eq!(frame.source, 42);
    assert!(frame.pixels.chunks_exact(4).all(|p| p[0].abs_diff(16) <= 40 && p[1].abs_diff(128) <= 40 && p[2].abs_diff(240) <= 40 && p[3] == 255));
    let mut exports = nestlink_media_session::DecodedExportLedger::default();
    let mut export = exports.begin(&frame)?;
    export.transferred(frame.pixels.len())?; export.finish()?;
    assert!(exports.begin(&frame).is_err());
    let decoder = controller.native_media_execution(&session_binding, MediaDirection::Decode)?;
    assert!(decoder.check_current().is_ok());
    encoder.close()?;
    assert!(execution.retired_joined());
    host_lease.stop(StopReason::ExplicitExit)?;
    assert_eq!(receiver.shutdown(StopReason::ExplicitExit)?, nestlink_media_session::ShutdownReport::Joined);
    assert!(decoder.retired_joined());
    host_feedback.abort(); controller_feedback.abort();
    let _ = host_feedback.await; let _ = controller_feedback.await;
    let _ = host_core.shutdown(Duration::from_secs(2)).await;
    let _ = controller_core.shutdown(Duration::from_secs(2)).await;
    Ok(())
}
