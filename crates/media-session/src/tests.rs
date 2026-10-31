use crate::{ShutdownReport, VideoReceiver, VideoSender, VideoStream};
mod advertised;
mod dynamic;
mod feedback;
mod receiver_qos;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_media_codec::{VideoConfig, Vp8Encoder};
use nestlink_policy::PathSet;
use nestlink_protocol::{NativeVideo, Path, Permission, PermitClaims};
use nestlink_remote::{
    AuthorizedConnection, ChannelRuntime, RuntimeClock, controller_proof, host_proof,
    input::InputLayout,
    video::{CaptureDevice, Display, RawFrame, VideoEpoch},
};
use nestlink_session::{Session, SessionBinding, StopReason};
use nestlink_transport_stream::Channel;
use prost::Message;
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{io::split, sync::watch};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
trait TestWire: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestWire for T {}
pub(super) const EPOCH: VideoEpoch = VideoEpoch {
    layout: 3,
    connection: 9,
};
pub(super) fn selected(source: u32) -> VideoStream {
    VideoStream {
        source,
        codec: VideoConfig {
            width: 64,
            height: 48,
            fps: 120,
            bitrate_kbps: 1000,
        },
    }
}
pub(super) struct Pair {
    pub(super) host: ChannelRuntime,
    pub(super) controller: ChannelRuntime,
    pub(super) revoke: watch::Sender<Option<StopReason>>,
    pub(super) controller_revoke: watch::Sender<Option<StopReason>>,
    bridge: Option<feedback::FrameBridge>,
}
#[test]
fn extreme_untrusted_stream_geometry_is_rejected_without_overflow() {
    let mut stream = selected(42);
    stream.codec.width = u32::MAX;
    stream.codec.height = u32::MAX;
    assert!(crate::video::streams(EPOCH, &[stream]).is_err());
}
pub(super) async fn pair() -> Result<Pair> {
    pair_with_transport(false).await
}
pub(super) async fn pair_with_transport(quic: bool) -> Result<Pair> {
    pair_with_fault(quic, None).await
}
async fn pair_with_fault(quic: bool, dropped_video: Option<u64>) -> Result<Pair> {
    pair_with_profile(quic, dropped_video, false).await
}
async fn pair_with_profile(quic: bool, dropped_video: Option<u64>, h264: bool) -> Result<Pair> {
    pair_with_features(quic, dropped_video, h264, false).await
}
async fn pair_with_features(
    quic: bool,
    dropped_video: Option<u64>,
    h264: bool,
    qos: bool,
) -> Result<Pair> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let permissions = vec![Permission::View, Permission::Audio, Permission::FileRead];
    let mut binding = SessionBinding {
        media: None,
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: random_id(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [9; 32],
        granted_permissions: permissions.clone(),
        supported_capabilities: if h264 {
            vec![
                "vp8".into(),
                nestlink_protocol::media::H264_CAPABILITY.into(),
            ]
        } else {
            vec!["vp8".into()]
        },
        local_paths: PathSet::DIRECT,
    };
    if qos {
        binding
            .supported_capabilities
            .push(nestlink_protocol::native_qos::CAPABILITY.into());
    }
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: 1,
        deployment_id: binding.deployment_id.clone(),
        security_epoch: 1,
        session_id: binding.session_id.clone(),
        account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(),
        host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: binding.resource_id.clone(),
        permissions: permissions.iter().map(|p| *p as i32).collect(),
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
        capability_sha256: vec![9; 32],
        required_capabilities: binding.supported_capabilities.clone(),
    };
    let signer = PermitSigner::generate();
    let permit = signer.sign(&claims)?.encode_to_vec();
    let mut host_session = Session::activate(
        verify_permit(&permit, &signer.public_key())?,
        binding.clone(),
        Path::Direct,
        now.monotonic_ms,
        now,
    )?;
    let mut controller_session = Session::activate(
        verify_permit(&permit, &signer.public_key())?,
        binding,
        Path::Direct,
        now.monotonic_ms,
        now,
    )?;
    let (revoke, host_stop) = watch::channel(None);
    let (controller_stop, stop) = watch::channel(None);
    if quic {
        use nestlink_remote::{SessionLifecycle, SessionSetup};
        use nestlink_session::EndpointRole;
        use nestlink_transport_quic::{connect, connector, listener};
        let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
        let client = connector("127.0.0.1:0".parse()?, &controller, host.fingerprint())?;
        let address = server.local_addr()?;
        let accept = async {
            server
                .accept()
                .await
                .ok_or("missing QUIC request")?
                .await
                .map_err(Into::into)
        };
        let (c, h) = tokio::try_join!(connect(&client, address, Duration::from_secs(2)), accept)?;
        let host_key = host.public_key();
        let controller_key = controller.public_key();
        let (controller, host) = tokio::try_join!(
            nestlink_remote::quic::authorize(
                c,
                Some(client),
                SessionSetup {
                    session: controller_session,
                    path: Path::Direct,
                    role: EndpointRole::Controller,
                    clock: clock.clone(),
                    lifecycle: SessionLifecycle::new(stop)
                },
                &controller,
                &host_key
            ),
            nestlink_remote::quic::authorize(
                h,
                Some(server),
                SessionSetup {
                    session: host_session,
                    path: Path::Direct,
                    role: EndpointRole::Host,
                    clock,
                    lifecycle: SessionLifecycle::new(host_stop)
                },
                &host,
                &controller_key
            )
        )?;
        return Ok(Pair {
            host,
            controller,
            revoke,
            controller_revoke: controller_stop,
            bridge: None,
        });
    }
    let (host_wire, controller_wire, bridge): (
        Box<dyn TestWire>,
        Box<dyn TestWire>,
        Option<feedback::FrameBridge>,
    ) = match dropped_video {
        Some(sequence) => {
            let (host_wire, host_bridge) = tokio::io::duplex(16384);
            let (controller_wire, controller_bridge) = tokio::io::duplex(16384);
            (
                Box::new(host_wire),
                Box::new(controller_wire),
                Some(feedback::FrameBridge::drop_video(
                    host_bridge,
                    controller_bridge,
                    sequence,
                )),
            )
        }
        None if qos => {
            use nestlink_transport_stream::tls;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let server = tokio_rustls::TlsAcceptor::from(Arc::new(tls::server_config(
                &host,
                controller.fingerprint(),
            )?));
            let client_config = tls::client_config(&controller, host.fingerprint())?;
            let accept = async {
                let (tcp, _) = listener.accept().await?;
                tcp.set_nodelay(true)?;
                server.accept(tcp).await
            };
            let (controller_wire, host_wire) =
                tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::try_join!(
                        nestlink_transport_stream::connect(
                            address,
                            client_config,
                            Duration::from_secs(2),
                        ),
                        accept,
                    )
                })
                .await??;
            let host_tls = host_wire.get_ref().1;
            let controller_tls = controller_wire.get_ref().1;
            let connections: [&tokio_rustls::rustls::CommonState; 2] = [host_tls, controller_tls];
            for connection in connections {
                assert_eq!(
                    connection.protocol_version(),
                    Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
                );
                assert_eq!(
                    connection.alpn_protocol(),
                    Some(nestlink_protocol::ALPN.as_bytes())
                );
            }
            assert_eq!(
                tls::certificate_fingerprint(
                    host_tls
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .ok_or("missing mTLS client certificate")?
                )?,
                controller.fingerprint(),
            );
            assert_eq!(
                tls::certificate_fingerprint(
                    controller_tls
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .ok_or("missing mTLS server certificate")?
                )?,
                host.fingerprint(),
            );
            (Box::new(host_wire), Box::new(controller_wire), None)
        }
        None => {
            let (host, controller) = tokio::io::duplex(16384);
            (Box::new(host), Box::new(controller), None)
        }
    };
    let (mut host_read, mut host_write) = split(host_wire);
    let (mut controller_read, mut controller_write) = split(controller_wire);
    let controller_key = controller.public_key();
    let host_key = host.public_key();
    tokio::try_join!(
        host_proof(
            &mut host_read,
            &mut host_write,
            &mut host_session,
            &host,
            &controller_key,
            &clock
        ),
        controller_proof(
            &mut controller_read,
            &mut controller_write,
            &mut controller_session,
            &controller,
            &host_key,
            &clock
        ),
    )?;
    Ok(Pair {
        host: AuthorizedConnection::new(
            host_read,
            host_write,
            host_session,
            Path::Direct,
            clock.clone(),
            host_stop,
        )?
        .into_channels(),
        controller: AuthorizedConnection::new(
            controller_read,
            controller_write,
            controller_session,
            Path::Direct,
            clock,
            stop,
        )?
        .into_channels(),
        revoke,
        controller_revoke: controller_stop,
        bridge,
    })
}
pub(super) async fn wait_until(predicate: impl FnMut() -> Result<bool>) -> Result {
    wait_until_named("unspecified phase", predicate).await
}

pub(super) async fn wait_until_named(
    phase: &str,
    mut predicate: impl FnMut() -> Result<bool>,
) -> Result {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if predicate()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("media fixture timed out during {phase}").into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
struct Capture {
    frames: Arc<Mutex<VecDeque<RawFrame>>>,
    stopped: Arc<AtomicBool>,
}
impl CaptureDevice for Capture {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        Ok(self
            .frames
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .pop_front())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.frames
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .clear();
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }
}
fn push(frames: &Mutex<VecDeque<RawFrame>>, source: u32, color: [u8; 4]) -> Result {
    frames
        .lock()
        .map_err(|_| "fixture poisoned")?
        .push_back(RawFrame {
            source,
            width: 64,
            height: 48,
            captured_at: Instant::now(),
            pixels: color.repeat(64 * 48),
        });
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorized_capture_vp8_roundtrip_multiple_sources_and_other_channels() -> Result {
    video_roundtrip(false).await?;
    video_roundtrip(true).await
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_h264_roundtrip_recovers_a_reference_gap_and_stops_on_revoke() -> Result {
    h264_roundtrip_geometry(320, 240).await
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_h264_odd_visible_sender_and_cpu_receiver_preserve_layout() -> Result {
    h264_roundtrip_geometry(321, 241).await
}
#[cfg(windows)]
async fn h264_roundtrip_geometry(width: u32, height: u32) -> Result {
    let mut pair = pair_with_profile(false, Some(3), true).await?;
    let host_stop = pair.host.lease_control().subscribe_stopped();
    let controller_stop = pair.controller.lease_control().subscribe_stopped();
    let frames = Arc::new(Mutex::new(VecDeque::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let stream = VideoStream {
        source: 42,
        codec: VideoConfig {
            width,
            height,
            fps: 30,
            bitrate_kbps: 2_000,
        },
    };
    let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![stream])?;
    receiver.wait_ready().await?;
    let mut sender = VideoSender::attach(
        &mut pair.host,
        Capture {
            frames: frames.clone(),
            stopped: stopped.clone(),
        },
        EPOCH,
        vec![Display {
            source: 42,
            logical: InputLayout {
                left: 0,
                top: 0,
                width,
                height,
            },
        }],
        vec![stream],
    )?;
    let mut presented = 0;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        frames
            .lock()
            .map_err(|_| "fixture poisoned")?
            .push_back(RawFrame {
                source: 42,
                width,
                height,
                captured_at: Instant::now(),
                pixels: [32, 160, 64, 255].repeat((width * height) as usize),
            });
        tokio::time::sleep(Duration::from_millis(45)).await;
        let frame = receiver.poll_video().map_err(|error| {
            format!(
                "H.264 poll failed after sequence {presented}: {error}; sender={:?}; receiver={:?}; host_stop={:?}; controller_stop={:?}; bridge={:?}",
                sender.monitor().status(),
                receiver.monitor().status(),
                *host_stop.borrow(),
                *controller_stop.borrow(),
                pair.bridge.as_ref().map(feedback::FrameBridge::diagnostics),
            )
        })?;
        if let Some(frame) = frame {
            assert!(frame.sequence > presented);
            assert_eq!(frame.epoch, EPOCH);
            assert_eq!((frame.width, frame.height), (width, height));
            assert_eq!(frame.pixels.len(), (width * height * 4) as usize);
            assert!(
                frame
                    .pixels
                    .chunks_exact(4)
                    .step_by(137)
                    .all(|pixel| (i32::from(pixel[1]) - 160).abs() < 20 && pixel[3] == 255)
            );
            presented = frame.sequence;
        }
        if presented > 5 && receiver.stats().completed_recoveries > 0 {
            break;
        }
    }
    assert!(presented > 5, "H.264 produced no post-gap decoded frame");
    assert!(receiver.stats().completed_recoveries > 0);
    pair.revoke.send_replace(Some(StopReason::Revoked));
    wait_until(|| Ok(stopped.load(Ordering::SeqCst) && receiver.monitor().status().finished))
        .await?;
    assert!(receiver.poll_video().is_err());
    assert_eq!(
        sender.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    Ok(())
}
async fn video_roundtrip(quic: bool) -> Result {
    let mut pair = pair_with_transport(quic).await?;
    let frames = Arc::new(Mutex::new(VecDeque::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let displays = [42, 43]
        .map(|source| Display {
            source,
            logical: InputLayout {
                left: -100,
                top: -20,
                width: 128,
                height: 96,
            },
        })
        .to_vec();
    let mut sender = VideoSender::attach(
        &mut pair.host,
        Capture {
            frames: frames.clone(),
            stopped: stopped.clone(),
        },
        EPOCH,
        displays,
        vec![selected(42), selected(43)],
    )?;
    let mut receiver =
        VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42), selected(43)])?;
    for (source, color) in [(42, [0, 0, 255, 255]), (43, [255, 0, 0, 255])] {
        push(&frames, source, color)?;
        let mut decoded = None;
        wait_until_named(&format!("source {source} initial decoded frame"), || {
            decoded = receiver.poll_video()?;
            Ok(decoded.is_some())
        })
        .await?;
        let decoded = decoded.ok_or("no decoded frame")?;
        assert_eq!(
            (decoded.source, decoded.sequence, decoded.epoch),
            (source, 1, EPOCH)
        );
        assert_eq!(decoded.pixels.len(), 64 * 48 * 4);
        let component = if source == 42 { 2 } else { 0 };
        assert!(
            decoded
                .pixels
                .chunks_exact(4)
                .all(|pixel| pixel[component] > 220 && pixel[3] == 255)
        );
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    push(&frames, 42, [0, 255, 0, 255])?;
    let mut sequence = 0;
    wait_until_named("source 42 delta frame", || {
        if let Some(decoded) = receiver.poll_video()? {
            assert_eq!(decoded.source, 42);
            assert!(decoded.pixels.chunks_exact(4).all(|pixel| pixel[1] > 220));
            sequence = decoded.sequence;
        }
        Ok(sequence == 2)
    })
    .await?;
    pair.host
        .send(Channel::FileRead, b"preserved-file-message")
        .await?;
    let mut delivered = false;
    wait_until_named("file channel delivery", || {
        if let Some(event) = receiver.poll_event()? {
            assert_eq!(event.channel, Channel::FileRead);
            assert_eq!(event.payload, b"preserved-file-message");
            delivered = true;
        }
        Ok(delivered)
    })
    .await?;
    pair.revoke.send_replace(Some(StopReason::Revoked));
    wait_until_named("revocation shutdown", || {
        Ok(stopped.load(Ordering::SeqCst) && receiver.monitor().status().finished)
    })
    .await?;
    assert!(receiver.poll_video().is_err());
    assert!(receiver.poll_event().is_err());
    assert_eq!(
        sender.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    assert_eq!(
        receiver.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    Ok(())
}

fn envelope(encoder: &mut Vp8Encoder, sequence: u64, pts: u64) -> Result<NativeVideo> {
    let packet = encoder.encode(&[0, 255, 0, 255].repeat(64 * 48), pts, false)?;
    Ok(NativeVideo {
        format_epoch: 0,
        format_sha256: Vec::new(),
        codec: 0,
        schema_version: 1,
        connection_generation: EPOCH.connection,
        layout_epoch: EPOCH.layout,
        source: 42,
        sequence,
        pts_90khz: packet.pts_90khz,
        width: 64,
        height: 48,
        keyframe: packet.keyframe,
        repeated_source: false,
        payload: packet.data,
    })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_generation_unapproved_source_and_layout_are_terminal() -> Result {
    for case in 0..3 {
        let pair = pair().await?;
        let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
        let mut encoder = Vp8Encoder::new(selected(42).codec)?;
        let mut packet = envelope(&mut encoder, 1, 0)?;
        match case {
            0 => packet.connection_generation += 1,
            1 => packet.source = 43,
            _ => packet.layout_epoch += 1,
        }
        pair.host
            .send(Channel::Video, &packet.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(receiver.monitor().status().error.is_some(), "case {case}");
        assert_eq!(receiver.stats().feedback_requests, 0);
        assert!(receiver.poll_video().is_err());
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_sequence_and_timestamp_cannot_change_decode_history() -> Result {
    for bad_timestamp in [false, true] {
        let pair = pair().await?;
        let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
        let mut encoder = Vp8Encoder::new(selected(42).codec)?;
        let first = envelope(&mut encoder, 1, 0)?;
        pair.host
            .send(Channel::Video, &first.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.poll_video()?.is_some())).await?;
        let mut bad = envelope(&mut encoder, 2, 1)?;
        if bad_timestamp {
            bad.pts_90khz = 0;
        } else {
            bad.sequence = 1;
        }
        pair.host
            .send(Channel::Video, &bad.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(receiver.monitor().status().error.is_some());
        assert!(receiver.poll_video().is_err());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_other_channel_mailbox_is_bounded_and_revocation_interrupts_wait() -> Result {
    let pair = pair().await?;
    let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
    for byte in 0..12 {
        pair.host.send(Channel::FileRead, &[byte]).await?;
    }
    wait_until(|| Ok(receiver.event_count_for_test() == 4)).await?;
    let start = Instant::now();
    // Control-plane revocation does not wait for the business FIFO. Peer EOF
    // may be behind already queued reliable messages on a TCP/WSS stream.
    pair.controller_revoke
        .send_replace(Some(StopReason::Revoked));
    pair.revoke.send_replace(Some(StopReason::Revoked));
    wait_until(|| Ok(receiver.monitor().status().finished)).await?;
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(receiver.poll_event().is_err());
    assert_eq!(
        receiver.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stuck_codec_cleanup_is_bounded_then_owner_can_reap_without_rewriting_receipt() -> Result {
    struct CodecOwner(Arc<AtomicUsize>);
    impl Drop for CodecOwner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let pair = pair().await?;
    let (release, wait) = std::sync::mpsc::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let owner = CodecOwner(dropped.clone());
    let mut worker = crate::worker::Worker::spawn(
        "nestlink-owned-stuck-fixture",
        pair.host.lease_control(),
        move |_| {
            let _owner = owner;
            let _ = entered.send(());
            wait.recv().map_err(io::Error::other)
        },
    )?;
    tokio::time::timeout(Duration::from_secs(2), started).await??;
    let monitor = worker.monitor();
    let start = Instant::now();
    assert_eq!(
        worker.shutdown(StopReason::Revoked)?,
        ShutdownReport::TimedOutDetached
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(monitor.status().cleanup_timed_out);
    assert!(!monitor.status().finished);
    assert!(!worker.reap_finished()?);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    // Lease cleanup has published its receipt; this fixture is stalled in the
    // codec task outside that lease, so this is an actual worker join timeout.
    assert!(
        pair.host
            .lease_control()
            .subscribe_stopped()
            .borrow()
            .is_some()
    );
    release.send(())?;
    // Consume the real JoinHandle. A monitor's finished flag alone is earlier
    // than the thread return and does not prove its owner has been joined.
    wait_until(|| Ok(worker.reap_finished()?)).await?;
    assert!(monitor.status().finished);
    assert!(monitor.status().error.is_none());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(monitor.status().cleanup_timed_out);
    assert_eq!(
        worker.shutdown(StopReason::Revoked)?,
        ShutdownReport::TimedOutDetached
    );
    assert!(worker.reap_finished()?);
    Ok(())
}
