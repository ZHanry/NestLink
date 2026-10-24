use super::*;
use nestlink_protocol::webrtc::video::{H264Format, VideoFormat};
use webrtc::rtp::packetizer::Depacketizer;

#[test]
fn h264_rtp_fragments_reassemble_and_preserve_output_pts() -> TestResult {
    let format = H264Format::parse("packetization-mode=1;profile-level-id=42e029")?
        .ok_or_else(|| io::Error::other("missing H.264 test format"))?;
    let mut writer = video::VideoRtpWriter::new(VideoFormat::H264(format))?;
    let mut access_unit = vec![0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x29, 0x55];
    access_unit.extend_from_slice(&[0, 0, 0, 1, 0x68, 0x55]);
    access_unit.extend_from_slice(&[0, 0, 0, 1, 0x65]);
    access_unit.extend_from_slice(&vec![0x55; 5000]);
    let pts = u64::from(u32::MAX) - 90;
    let packets = writer.packets(Bytes::from(access_unit.clone()), pts)?;
    assert!(packets.len() > 4);
    let mut depacketizer = webrtc::rtp::codecs::h264::H264Packet::default();
    let mut reassembled = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        assert!(packet.payload.len() <= 1100);
        assert_eq!(packet.header.timestamp, packets[0].header.timestamp);
        assert_eq!(packet.header.marker, index == packets.len() - 1);
        if index != 0 {
            assert_eq!(
                packet.header.sequence_number,
                packets[index - 1].header.sequence_number.wrapping_add(1)
            );
        }
        reassembled.extend_from_slice(&depacketizer.depacketize(&packet.payload)?);
    }
    assert_eq!(reassembled, access_unit);
    let next = writer.packets(Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x55]), pts + 3000)?;
    assert_eq!(
        next[0]
            .header
            .timestamp
            .wrapping_sub(packets[0].header.timestamp),
        3000
    );
    assert_eq!(
        next[0].header.sequence_number,
        packets
            .last()
            .ok_or("missing packets")?
            .header
            .sequence_number
            .wrapping_add(1)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_video_au_fences_queued_delta_frames_until_a_complete_keyframe() -> TestResult {
    let controller = DeviceIdentity::generate();
    let identity = DeviceIdentity::generate();
    let permit = test_permit(&controller, &identity)?;
    let (host, track, _, _) =
        make_peer_with_mdns(&permit, false, MulticastDnsMode::Disabled).await?;
    let browser = make_browser_peer().await?;
    let (remote_tx, mut remote_rx) = mpsc::channel(1);
    browser.on_track(Box::new(move |remote, _, _| {
        let remote_tx = remote_tx.clone();
        Box::pin(async move {
            let _ = remote_tx.send(remote).await;
        })
    }));

    let result: TestResult = async {
        let offer = browser.create_offer(None).await?;
        let mut gathered = browser.gathering_complete_promise().await;
        browser.set_local_description(offer).await?;
        tokio::time::timeout(Duration::from_secs(10), gathered.recv()).await?;
        host.set_remote_description(browser.local_description().await.ok_or("missing offer")?)
            .await?;
        let answer = host.create_answer(None).await?;
        let mut gathered = host.gathering_complete_promise().await;
        host.set_local_description(answer).await?;
        tokio::time::timeout(Duration::from_secs(10), gathered.recv()).await?;
        browser
            .set_remote_description(host.local_description().await.ok_or("missing answer")?)
            .await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            while host.connection_state() != RTCPeerConnectionState::Connected
                || browser.connection_state() != RTCPeerConnectionState::Connected
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;

        let runtime = Handle::current();
        let sending_peer = host.clone();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            let (_permit_tx, permit_rx) = watch::channel(permit);
            let (_cancel_tx, cancel_rx) = watch::channel(false);
            let (_authority_tx, authority_rx) = watch::channel(true);
            let mut writer = video::VideoRtpWriter::new(VideoFormat::Vp8)?;
            // Transport-only samples: no capture, encoder, decoder or product
            // remote-session permission is opened by this regression.
            let data = Bytes::from_static(&[0x10, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00]);
            let context = |deadline| video::VideoWriteContext {
                peer: &sending_peer,
                runtime: &runtime,
                permit: &permit_rx,
                cancel: &cancel_rx,
                selected_path: Path::Direct,
                path_authority: &authority_rx,
                deadline,
            };
            assert!(!writer.write(
                data.clone(),
                0,
                false,
                &track,
                &context(Instant::now() + Duration::from_secs(1)),
            )?);
            assert!(writer.write(
                data.clone(),
                3000,
                true,
                &track,
                &context(Instant::now() + Duration::from_secs(1)),
            )?);
            assert!(!writer.write(
                data.clone(),
                6000,
                false,
                &track,
                &context(Instant::now() - Duration::from_millis(1)),
            )?);
            assert!(!writer.write(
                data.clone(),
                9000,
                false,
                &track,
                &context(Instant::now() + Duration::from_secs(1)),
            )?);
            assert!(writer.write(
                data.clone(),
                12000,
                true,
                &track,
                &context(Instant::now() + Duration::from_secs(1)),
            )?);
            assert!(writer.write(
                data,
                15000,
                false,
                &track,
                &context(Instant::now() + Duration::from_secs(1)),
            )?);
            Ok(())
        })
        .await??;
        let remote = tokio::time::timeout(Duration::from_secs(3), remote_rx.recv())
            .await?
            .ok_or("missing remote video track")?;
        let mut timestamps = Vec::new();
        for _ in 0..3 {
            let (packet, _) =
                tokio::time::timeout(Duration::from_secs(3), remote.read_rtp()).await??;
            timestamps.push(packet.header.timestamp);
        }
        assert_eq!(timestamps[1].wrapping_sub(timestamps[0]), 9000);
        assert_eq!(timestamps[2].wrapping_sub(timestamps[1]), 3000);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), remote.read_rtp())
                .await
                .is_err()
        );
        Ok(())
    }
    .await;
    let browser_closed = browser.close().await;
    let host_closed = host.close().await;
    result?;
    browser_closed?;
    host_closed?;
    Ok(())
}

#[tokio::test]
async fn legacy_host_selects_vp8_before_answer_and_pins_it_on_restart() -> TestResult {
    let controller = DeviceIdentity::generate();
    let identity = DeviceIdentity::generate();
    let permit = test_permit(&controller, &identity)?;
    let mut host =
        test_host_peer_state(&permit, &identity, controller.identity.public_key()).await?;
    let browser = make_browser_peer().await?;
    let offer = browser.create_offer(None).await?;
    host.select_video_codec(&offer.sdp).await?;
    assert_eq!(host.video_format, VideoFormat::Vp8);
    host.peer.set_remote_description(offer.clone()).await?;
    let answer = host.peer.create_answer(None).await?;
    host.validate_video_answer(&answer.sdp)?;
    nestlink_protocol::webrtc::video::validate_answer(&offer.sdp, &answer.sdp)?;
    host.media_started = true;
    let h264_only = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 102\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 packetization-mode=1;profile-level-id=42e029\r\n";
    assert!(host.select_video_codec(h264_only).await.is_err());
    browser.close().await?;
    let _ = host
        .close_with_reason_report(StopReason::ExplicitExit)
        .await;
    Ok(())
}

#[tokio::test]
async fn media_drain_cancellation_retains_join_ownership() -> TestResult {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut workers = vec![tokio::spawn(async {
        let _ = release_rx.await;
    })];
    assert!(
        tokio::time::timeout(Duration::from_millis(10), drain_media_workers(&mut workers))
            .await
            .is_err()
    );
    assert_eq!(workers.len(), 1);
    release_tx.send(()).map_err(|_| "worker already released")?;
    assert!(!drain_media_workers(&mut workers).await);
    assert!(workers.is_empty());
    Ok(())
}

#[tokio::test]
async fn media_drain_timeout_reports_failure_and_retains_worker() -> TestResult {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut workers = vec![tokio::spawn(async {
        let _ = release_rx.await;
    })];
    assert!(drain_media_workers(&mut workers).await);
    assert_eq!(workers.len(), 1);
    release_tx.send(()).map_err(|_| "worker already released")?;
    assert!(!drain_media_workers(&mut workers).await);
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn windows_h264_target_preflight_negotiates_a_real_peer_answer() -> TestResult {
    let controller = DeviceIdentity::generate();
    let identity = DeviceIdentity::generate();
    let permit = test_permit(&controller, &identity)?;
    let mut host =
        test_host_peer_state(&permit, &identity, controller.identity.public_key()).await?;
    host.set_video_preflight(HostVideoPreflight {
        source: 1,
        connection_generation: permit.claims().connection_generation,
        config: VideoConfig {
            width: 640,
            height: 480,
            fps: 30,
            bitrate_kbps: 1000,
        },
    })?;
    let mut media = MediaEngine::default();
    video::register_h264(&mut media)?;
    let browser = APIBuilder::new()
        .with_media_engine(media)
        .build()
        .new_peer_connection(RTCConfiguration::default())
        .await?;
    browser
        .add_transceiver_from_kind(
            RTPCodecType::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                send_encodings: Vec::new(),
            }),
        )
        .await?;
    let offer = browser.create_offer(None).await?;
    host.select_video_codec(&offer.sdp).await?;
    assert!(matches!(host.video_format, VideoFormat::H264(_)));
    host.peer.set_remote_description(offer.clone()).await?;
    let answer = host.peer.create_answer(None).await?;
    host.validate_video_answer(&answer.sdp)?;
    nestlink_protocol::webrtc::video::validate_answer(&offer.sdp, &answer.sdp)?;
    assert!(!answer.sdp.contains("VP8/90000"));
    browser.close().await?;
    let _ = host
        .close_with_reason_report(StopReason::ExplicitExit)
        .await;
    Ok(())
}
