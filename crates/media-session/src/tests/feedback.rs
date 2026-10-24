use super::*;
use nestlink_protocol::{NativeVideoFeedback, VIDEO_KEYFRAME_INTERVAL_MS, VideoRecoveryReason};
use nestlink_transport_stream::{read_frame, write_frame};
use std::sync::atomic::AtomicUsize;
use tokio::{io::DuplexStream, task::JoinHandle};

// This fixture omits an entire application frame after encoding. It is not a
// network-loss test: QUIC and TLS retransmit lost reliable transport bytes.
pub(super) struct FrameBridge {
    task: JoinHandle<io::Result<()>>,
    dropped: Arc<AtomicUsize>,
    progress: Arc<Mutex<String>>,
}
impl FrameBridge {
    pub(super) fn drop_video(host: DuplexStream, controller: DuplexStream, sequence: u64) -> Self {
        let (mut host_read, mut host_write) = split(host);
        let (mut controller_read, mut controller_write) = split(controller);
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let progress = Arc::new(Mutex::new("awaiting frame".to_owned()));
        let task_progress = progress.clone();
        let task = tokio::spawn(async move {
            // Both halves are owned by one task so EOF closes the bridge in
            // both directions, including the write half held by io::split.
            let result = tokio::select! {
                result = async {
                    loop {
                        let frame = read_frame(&mut host_read).await?;
                        if frame.channel == Channel::Video {
                            let packet = NativeVideo::decode_validated(&frame.payload)
                                .map_err(io::Error::other)?;
                            *task_progress.lock().map_err(|_| io::Error::other("bridge poisoned"))? =
                                format!("read video sequence {} ({} bytes)", packet.sequence, frame.payload.len());
                        }
                        if frame.channel == Channel::Video
                            && NativeVideo::decode_validated(&frame.payload)
                                .map_err(io::Error::other)?
                                .sequence
                                == sequence
                        {
                            count.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        write_frame(&mut controller_write, frame.channel, &frame.payload).await?;
                    }
                } => result,
                result = tokio::io::copy(&mut controller_read, &mut host_write) => result.map(|_| ()),
            };
            if let Err(error) = &result
                && let Ok(mut progress) = task_progress.lock()
            {
                *progress = format!("{progress}; bridge error: {error}");
            }
            result
        });
        Self {
            task,
            dropped,
            progress,
        }
    }
    pub(super) fn diagnostics(&self) -> String {
        format!(
            "finished={}, dropped={}, progress={}",
            self.task.is_finished(),
            self.dropped.load(Ordering::SeqCst),
            self.progress
                .lock()
                .map_or_else(|_| "poisoned".to_owned(), |progress| progress.clone())
        )
    }
}
impl Drop for FrameBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn omitted_reference_frame_recovers_through_automatic_feedback_on_a_static_source() -> Result
{
    let mut pair = pair_with_fault(false, Some(2)).await?;
    let dropped = pair
        .bridge
        .as_ref()
        .ok_or("missing fault bridge")?
        .dropped
        .clone();
    let frames = Arc::new(Mutex::new(VecDeque::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let mut sender = VideoSender::attach(
        &mut pair.host,
        Capture {
            frames: frames.clone(),
            stopped: stopped.clone(),
        },
        EPOCH,
        vec![display()],
        vec![selected(42)],
    )?;
    let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
    push(&frames, 42, [0, 255, 0, 255])?;
    wait_until(|| {
        if let Some(frame) = receiver.poll_video()? {
            assert_eq!(frame.sequence, 1);
            assert!(!frame.repeated_source);
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    push(&frames, 42, [0, 255, 0, 255])?;
    wait_until(|| Ok(dropped.load(Ordering::SeqCst) == 1)).await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    push(&frames, 42, [0, 255, 0, 255])?;
    let started = Instant::now();
    wait_until(|| {
        if let Some(frame) = receiver.poll_video()? {
            assert_eq!(frame.sequence, 4);
            assert!(frame.repeated_source);
            assert!(
                frame
                    .pixels
                    .chunks_exact(4)
                    .all(|pixel| pixel[1] > 220 && pixel[3] == 255)
            );
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?;
    assert!(started.elapsed() < Duration::from_millis(nestlink_protocol::VIDEO_RECOVERY_MS));
    assert_eq!(receiver.stats().completed_recoveries, 1);
    assert_eq!(receiver.stats().discarded_frames, 1);
    assert!(receiver.stats().feedback_requests >= 1);
    assert!(sender.stats().feedback_requests >= 1);
    assert_eq!(sender.stats().keyframes_encoded, 2);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "{}",
        pair.bridge
            .as_ref()
            .ok_or("missing fault bridge")?
            .diagnostics()
    );
    pair.revoke.send_replace(Some(StopReason::Revoked));
    wait_until(|| Ok(stopped.load(Ordering::SeqCst) && receiver.monitor().status().finished))
        .await?;
    assert!(receiver.poll_video().is_err());
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

fn display() -> Display {
    Display {
        source: 42,
        logical: InputLayout {
            left: 0,
            top: 0,
            width: 64,
            height: 48,
        },
    }
}

struct BusyCapture(Capture);
impl CaptureDevice for BusyCapture {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        Ok(self.0.poll_frame()?.or_else(|| {
            Some(RawFrame {
                source: 43,
                width: 64,
                height: 48,
                captured_at: Instant::now(),
                pixels: [0, 255, 0, 255].repeat(64 * 48),
            })
        }))
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_source_cannot_starve_a_static_sources_recovery_keyframe() -> Result {
    let mut pair = pair().await?;
    let frames = Arc::new(Mutex::new(VecDeque::new()));
    push(&frames, 42, [0, 255, 0, 255])?;
    let mut sender = VideoSender::attach(
        &mut pair.host,
        BusyCapture(Capture {
            frames,
            stopped: Arc::new(AtomicBool::new(false)),
        }),
        EPOCH,
        vec![
            display(),
            Display {
                source: 43,
                ..display()
            },
        ],
        vec![selected(42), selected(43)],
    )?;
    let mut video = pair.controller.claim_channel(Channel::Video)?;
    let first = NativeVideo::decode_validated(
        &tokio::time::timeout(Duration::from_secs(2), video.receive())
            .await??
            .payload,
    )?;
    assert_eq!((first.source, first.sequence), (42, 1));

    // Establish that the busy source is producing frames before starting the
    // recovery deadline. Otherwise the test can race the capture worker and
    // fail its fairness assertion before the busy source has had a chance to run.
    let busy = NativeVideo::decode_validated(
        &tokio::time::timeout(Duration::from_secs(2), video.receive())
            .await??
            .payload,
    )?;
    assert_eq!((busy.source, busy.sequence), (43, 1));

    pair.controller
        .send(
            Channel::VideoFeedback,
            &nestlink_protocol::native_displays::DisplayEnvelope::Recovery(request(1, 1))
                .encode()?,
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = NativeVideo::decode_validated(&video.receive().await?.payload)?;
            if frame.source == 42 {
                assert_eq!(frame.sequence, 2);
                assert!(frame.keyframe && frame.repeated_source);
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    })
    .await??;
    assert_eq!(
        sender.shutdown(StopReason::ExplicitExit)?,
        ShutdownReport::Joined
    );
    Ok(())
}

fn request(sequence: u64, last_sequence: u64) -> NativeVideoFeedback {
    NativeVideoFeedback {
        format_epoch: 0,
        format_sha256: Vec::new(),
        schema_version: 1,
        connection_generation: EPOCH.connection,
        layout_epoch: EPOCH.layout,
        source: 42,
        request_sequence: sequence,
        last_sequence,
        reason: VideoRecoveryReason::KeyframeMissing as i32,
    }
}
fn forced(encoder: &mut Vp8Encoder, sequence: u64, pts: u64) -> Result<NativeVideo> {
    let encoded = encoder.encode(&[0, 255, 0, 255].repeat(64 * 48), pts, true)?;
    Ok(NativeVideo {
        format_epoch: 0,
        format_sha256: Vec::new(),
        codec: 0,
        schema_version: 1,
        connection_generation: EPOCH.connection,
        layout_epoch: EPOCH.layout,
        source: 42,
        sequence,
        pts_90khz: pts,
        width: 64,
        height: 48,
        keyframe: encoded.keyframe,
        payload: encoded.data,
        repeated_source: false,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_source_feedback_forces_marked_keyframe_and_duplicate_is_idempotent() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let frames = Arc::new(Mutex::new(VecDeque::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let mut sender = VideoSender::attach(
            &mut pair.host,
            Capture {
                frames: frames.clone(),
                stopped: stopped.clone(),
            },
            EPOCH,
            vec![display()],
            vec![selected(42)],
        )?;
        let mut video = pair.controller.claim_channel(Channel::Video)?;
        push(&frames, 42, [0, 255, 0, 255])?;
        let first = NativeVideo::decode_validated(
            &tokio::time::timeout(Duration::from_secs(2), video.receive())
                .await??
                .payload,
        )?;
        assert!(first.keyframe && !first.repeated_source);
        let feedback = nestlink_protocol::native_displays::DisplayEnvelope::Recovery(request(
            1,
            first.sequence,
        ))
        .encode()?;
        pair.controller
            .send(Channel::VideoFeedback, &feedback)
            .await?;
        let repeated = NativeVideo::decode_validated(
            &tokio::time::timeout(Duration::from_secs(2), video.receive())
                .await??
                .payload,
        )?;
        assert!(repeated.keyframe && repeated.repeated_source);
        assert_eq!(repeated.sequence, 2);
        assert!(repeated.pts_90khz - first.pts_90khz >= VIDEO_KEYFRAME_INTERVAL_MS * 90);
        let mut decoder = nestlink_media_codec::Vp8Decoder::new(64, 48)?;
        assert!(
            decoder
                .decode(&repeated.payload)?
                .chunks_exact(4)
                .all(|pixel| pixel[1] > 220)
        );
        assert_eq!(sender.stats().feedback_requests, 1);
        pair.controller
            .send(Channel::VideoFeedback, &feedback)
            .await?;
        wait_until(|| Ok(sender.stats().duplicate_requests == 1)).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), video.receive())
                .await
                .is_err()
        );
        assert_eq!(sender.stats().keyframes_encoded, 2);
        pair.revoke.send_replace(Some(StopReason::Revoked));
        wait_until(|| Ok(sender.monitor().status().finished)).await?;
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(
            sender.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_reference_or_initial_keyframe_requests_recovery_without_publishing_deltas() -> Result
{
    for (quic, initial) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut pair = pair_with_transport(quic).await?;
        let mut feedback = pair.host.claim_channel(Channel::VideoFeedback)?;
        let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
        let mut encoder = Vp8Encoder::new(selected(42).codec)?;
        let first = envelope(&mut encoder, 1, 0)?;
        if !initial {
            pair.host
                .send(Channel::Video, &first.encode_validated()?)
                .await?;
            wait_until(|| Ok(receiver.poll_video()?.is_some())).await?;
        }
        let missing = envelope(&mut encoder, 2, 1)?;
        assert!(!missing.keyframe);
        let delta = if initial {
            NativeVideo {
                sequence: 1,
                ..missing
            }
        } else {
            envelope(&mut encoder, 3, 2)?
        };
        let last_sequence = delta.sequence;
        pair.host
            .send(Channel::Video, &delta.encode_validated()?)
            .await?;
        let nestlink_protocol::native_displays::DisplayEnvelope::Recovery(message) =
            nestlink_protocol::native_displays::DisplayEnvelope::decode(
                &tokio::time::timeout(Duration::from_secs(1), feedback.receive())
                    .await??
                    .payload,
            )?
        else {
            return Err("expected explicit recovery envelope".into());
        };
        assert_eq!(message.last_sequence, last_sequence);
        assert_eq!(
            message.reason,
            if initial {
                VideoRecoveryReason::KeyframeMissing
            } else {
                VideoRecoveryReason::ReferenceGap
            } as i32
        );
        assert!(receiver.poll_video()?.is_none());
        let keyframe = forced(&mut encoder, last_sequence + 1, 3)?;
        pair.host
            .send(Channel::Video, &keyframe.encode_validated()?)
            .await?;
        let mut decoded = None;
        wait_until(|| {
            decoded = receiver.poll_video()?;
            Ok(decoded.is_some())
        })
        .await?;
        assert_eq!(
            decoded.ok_or("missing recovered video")?.sequence,
            last_sequence + 1
        );
        assert_eq!(receiver.stats().discarded_frames, 1);
        assert_eq!(receiver.stats().completed_recoveries, 1);
        assert!(!receiver.monitor().status().finished);
        assert_eq!(
            receiver.shutdown(StopReason::ExplicitExit)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_file_event_mailbox_cannot_block_video_recovery_and_its_deadline() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let mut feedback = pair.host.claim_channel(Channel::VideoFeedback)?;
        let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
        for _ in 0..5 {
            pair.host
                .send(Channel::FileRead, b"unconsumed-file-event")
                .await?;
        }
        wait_until(|| Ok(receiver.event_count_for_test() == 4)).await?;
        let mut encoder = Vp8Encoder::new(selected(42).codec)?;
        let _first = envelope(&mut encoder, 1, 0)?;
        let delta = envelope(&mut encoder, 1, 1)?;
        pair.host
            .send(Channel::Video, &delta.encode_validated()?)
            .await?;
        tokio::time::timeout(Duration::from_secs(1), feedback.receive()).await??;
        assert_eq!(receiver.event_count_for_test(), 4);
        assert!(receiver.poll_video()?.is_none());
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(
            receiver
                .monitor()
                .status()
                .error
                .is_some_and(|error| error.contains("recovery budget exhausted"))
        );
        assert!(receiver.poll_event().is_err());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_feedback_identity_replay_and_future_ack_terminate_capture() -> Result {
    for case in 0..6 {
        let mut pair = pair().await?;
        let frames = Arc::new(Mutex::new(VecDeque::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let sender = VideoSender::attach(
            &mut pair.host,
            Capture {
                frames,
                stopped: stopped.clone(),
            },
            EPOCH,
            vec![display()],
            vec![selected(42)],
        )?;
        let mut message = request(1, 0);
        match case {
            0 => message.connection_generation += 1,
            1 => message.layout_epoch += 1,
            2 => message.source += 1,
            3 => message.request_sequence = 2,
            4 => message.last_sequence = 1,
            _ => message.reason = 99,
        }
        let mut envelope = b"NLDF\x01\x00".to_vec();
        envelope.extend_from_slice(&message.encode_to_vec());
        pair.controller
            .send(Channel::VideoFeedback, &envelope)
            .await?;
        wait_until(|| Ok(sender.monitor().status().finished)).await?;
        assert!(sender.monitor().status().error.is_some());
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(sender.stats().keyframes_encoded, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_entropy_failures_have_a_fixed_attempt_budget_and_no_output() -> Result {
    let pair = pair().await?;
    let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
    for sequence in 1..=4 {
        let packet = NativeVideo {
            format_epoch: 0,
            format_sha256: Vec::new(),
            codec: 0,
            schema_version: 1,
            connection_generation: EPOCH.connection,
            layout_epoch: EPOCH.layout,
            source: 42,
            sequence,
            pts_90khz: sequence,
            width: 64,
            height: 48,
            keyframe: true,
            repeated_source: false,
            payload: vec![0x30, 0, 0, 0x9d, 1, 0x2a, 64, 0, 48, 0, 0, 0],
        };
        pair.host
            .send(Channel::Video, &packet.encode_validated()?)
            .await?;
    }
    wait_until(|| Ok(receiver.monitor().status().finished)).await?;
    assert!(
        receiver
            .monitor()
            .status()
            .error
            .is_some_and(|error| error.contains("attempt budget exhausted"))
    );
    assert_eq!(receiver.stats().completed_recoveries, 0);
    assert!(receiver.poll_video().is_err());
    Ok(())
}
