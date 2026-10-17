use super::*;
use crate::{
    VideoReceiver,
    tests::{EPOCH, pair, selected, wait_until},
};
use nestlink_remote::{
    RemoteError,
    audio::{AudioDevice, CapturedAudio},
};
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Instant,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn stream(channels: u8) -> AudioStream {
    AudioStream {
        binding: AudioBinding {
            source: 51,
            connection: 9,
            channels,
        },
        bitrate: 96_000,
    }
}
fn tone(channels: u8, pts: u64) -> AudioChunk {
    let samples = (0..CHUNK_FRAMES)
        .flat_map(|i| {
            let phase = (i as u64 + pts) as f64 / 48_000.0;
            (0..channels).map(move |channel| {
                let hz = if channel == 0 { 440.0 } else { 880.0 };
                (12_000.0 * (phase * hz * std::f64::consts::TAU).sin()) as i16
            })
        })
        .collect();
    AudioChunk {
        source: 51,
        channels,
        pts_48khz: pts,
        samples,
    }
}
fn packet(codec: &mut OpusEncoder, sequence: u64, pts: u64) -> Result<NativeAudio> {
    let channels = codec.config().channels;
    Ok(NativeAudio {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        source: 51,
        sequence,
        pts_48khz: pts,
        channels: u32::from(channels),
        payload: codec.encode(&tone(channels, pts).samples)?,
    })
}

#[test]
fn audio_gap_policy_has_bounded_plc_and_large_gap_resets_without_a_loop() -> Result {
    for channels in [1, 2] {
        let mut codec = OpusEncoder::new(OpusConfig {
            channels,
            bitrate: 96_000,
        })?;
        let mut decoder = Decoder::new(stream(channels).binding)?;
        let mut reference = OpusDecoder::new(channels)?;
        let initial = packet(&mut codec, 1, 0)?;
        let first = decoder.decode(initial.clone())?;
        assert_eq!(first.chunks[0].samples, reference.decode(&initial.payload)?);
        // Encode/drop the second interval, as a bounded local/network queue can.
        packet(&mut codec, 2, 960)?;
        let after_gap = packet(&mut codec, 3, 1920)?;
        let expected_plc = reference.conceal_loss()?;
        let expected_decoded = reference.decode(&after_gap.payload)?;
        let decoded = decoder.decode(after_gap)?;
        assert_eq!(
            (decoded.concealed, decoded.reset, decoded.chunks.len()),
            (1, false, 2)
        );
        assert_eq!(decoded.chunks[0].samples, expected_plc);
        assert_eq!(decoded.chunks[1].samples, expected_decoded);
        assert_eq!(
            (decoded.chunks[0].pts_48khz, decoded.chunks[1].pts_48khz),
            (960, 1920)
        );
        let huge_pts = (i64::MAX as u64 / 960) * 960;
        let last = packet(&mut codec, 4, huge_pts)?;
        reference.reset()?;
        let expected = reference.decode(&last.payload)?;
        let now = Instant::now();
        let decoded = decoder.decode(last)?;
        assert!(now.elapsed() < Duration::from_millis(100));
        assert_eq!(
            (decoded.concealed, decoded.reset, decoded.chunks.len()),
            (0, true, 1)
        );
        assert_eq!(decoded.chunks[0].samples, expected);
    }
    Ok(())
}

#[test]
fn malformed_loss_trigger_and_identity_replay_never_advance_valid_decoder_history() -> Result {
    let mut codec = OpusEncoder::new(OpusConfig {
        channels: 1,
        bitrate: 96_000,
    })?;
    let first = packet(&mut codec, 1, 0)?;
    packet(&mut codec, 2, 960)?;
    let third = packet(&mut codec, 3, 1920)?;
    for case in 0..8 {
        let mut decoder = Decoder::new(stream(1).binding)?;
        decoder.decode(first.clone())?;
        let mut bad = third.clone();
        match case {
            0 => bad.source = 52,
            1 => bad.connection_generation = 8,
            2 => bad.channels = 2,
            3 => bad.sequence = 1,
            4 => bad.pts_48khz = 0,
            5 => bad.pts_48khz = 1921,
            6 => bad.sequence = 100,
            7 => bad.payload.truncate(1),
            _ => unreachable!(),
        }
        assert!(decoder.decode(bad).is_err(), "case {case}");
        assert_eq!((decoder.sequence, decoder.pts), (Some(1), Some(0)));
        let mut reference = Decoder::new(stream(1).binding)?;
        reference.decode(first.clone())?;
        let expected = reference.decode(third.clone())?;
        let actual = decoder.decode(third.clone())?;
        assert_eq!(actual.concealed, 1);
        assert_eq!(
            actual
                .chunks
                .iter()
                .map(|chunk| &chunk.samples)
                .collect::<Vec<_>>(),
            expected
                .chunks
                .iter()
                .map(|chunk| &chunk.samples)
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

struct Capture {
    frames: Arc<Mutex<VecDeque<CapturedAudio>>>,
    stopped: Arc<AtomicBool>,
}
impl AudioDevice for Capture {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
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
impl AudioCaptureDevice for Capture {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        Ok(self
            .frames
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .pop_front())
    }
}
#[derive(Default)]
struct SinkState {
    played: Vec<AudioChunk>,
    resets: u32,
}
struct Sink(Arc<Mutex<SinkState>>);
impl AudioDevice for Sink {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        state.played.clear();
        state.resets += 1;
        Ok(())
    }
}
impl AudioPlaybackDevice for Sink {
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        if state.played.len() == 5 {
            state.played.remove(0);
        }
        state.played.push(AudioChunk {
            source: chunk.source,
            channels: chunk.channels,
            pts_48khz: chunk.pts_48khz,
            samples: chunk.samples.clone(),
        });
        Ok(())
    }
}

struct TimedSink {
    sink: Sink,
    accepted: Arc<Mutex<Vec<(u64, Instant)>>>,
}
impl AudioDevice for TimedSink {
    fn check(&mut self) -> io::Result<()> {
        self.sink.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.sink.reset()
    }
}
impl AudioPlaybackDevice for TimedSink {
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        self.sink.enqueue(chunk)?;
        self.accepted
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .push((chunk.pts_48khz, Instant::now()));
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_audio_attachment_keeps_the_video_clock_and_trims_old_pcm() -> Result {
    for quic in [false, true] {
        let mut pair = crate::tests::pair_with_transport(quic).await?;
        let sink = Arc::new(Mutex::new(SinkState::default()));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let mut codec = OpusEncoder::new(OpusConfig {
            channels: 1,
            bitrate: 96_000,
        })?;
        let stale = packet(&mut codec, 1, 48_000)?.encode_validated()?;
        let fresh = packet(&mut codec, 2, 76_800)?.encode_validated()?;
        let clock = SessionPlayoutClock::default();
        let started = Instant::now();
        // An earlier video established this immutable playout origin. The
        // subsequently opened audio endpoint must not anchor its old PCM now.
        let _ = clock.schedule(90_000, 90_000, started - Duration::from_millis(500))?;
        let PlayoutDecision::At(due) = clock.schedule(144_000, 90_000, started)? else {
            return Err("fixture playout deadline missing".into());
        };
        let incoming = pair.controller.claim_channel(Channel::Audio)?;
        let mut receiver = AudioReceiver::attach_channel_timed(
            incoming,
            TimedSink {
                sink: Sink(sink.clone()),
                accepted: accepted.clone(),
            },
            stream(1),
            clock,
        )?;
        pair.host.send(Channel::Audio, &stale).await?;
        wait_until(|| Ok(receiver.stats().discarded_late_chunks == 1)).await?;
        assert!(accepted.lock().map_err(|_| "poisoned")?.is_empty());
        pair.host.send(Channel::Audio, &fresh).await?;
        wait_until(|| Ok(receiver.stats().played_chunks == 1)).await?;
        {
            let accepted = accepted.lock().map_err(|_| "poisoned")?;
            assert_eq!(accepted.len(), 1);
            assert_eq!(accepted[0].0, 76_800);
            assert!(
                accepted[0].1 >= due,
                "PCM escaped before the common video deadline"
            );
        }
        assert_eq!(receiver.stats().decoder_resets, 1);
        assert!(receiver.stats().output_timing.hardware_latency.is_none());
        pair.controller_revoke
            .send_replace(Some(StopReason::Revoked));
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(sink.lock().map_err(|_| "poisoned")?.played.is_empty());
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_interrupts_a_pending_common_clock_audio_deadline() -> Result {
    for quic in [false, true] {
        let mut pair = crate::tests::pair_with_transport(quic).await?;
        let sink = Arc::new(Mutex::new(SinkState::default()));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let clock = SessionPlayoutClock::default();
        let incoming = pair.controller.claim_channel(Channel::Audio)?;
        let mut receiver = AudioReceiver::attach_channel_timed(
            incoming,
            TimedSink {
                sink: Sink(sink.clone()),
                accepted: accepted.clone(),
            },
            stream(1),
            clock.clone(),
        )?;
        let mut codec = OpusEncoder::new(OpusConfig {
            channels: 1,
            bitrate: 96_000,
        })?;
        let pending = packet(&mut codec, 1, 48_000)?.encode_validated()?;
        let _ = clock.schedule(48_000, 48_000, Instant::now() + Duration::from_millis(120))?;
        pair.host.send(Channel::Audio, &pending).await?;
        wait_until(|| Ok(receiver.stats().received_packets == 1)).await?;
        assert_eq!(receiver.stats().played_chunks, 0);
        pair.controller_revoke
            .send_replace(Some(StopReason::Revoked));
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(accepted.lock().map_err(|_| "poisoned")?.is_empty());
        assert_eq!(sink.lock().map_err(|_| "poisoned")?.resets, 1);
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

struct ResetProbe {
    resets: Arc<AtomicUsize>,
    fail_reset: bool,
}
impl AudioDevice for ResetProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        if self.fail_reset {
            Err(io::Error::other("simulated audio reset failure"))
        } else {
            Ok(())
        }
    }
}
impl AudioCaptureDevice for ResetProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        Ok(None)
    }
}
impl AudioPlaybackDevice for ResetProbe {
    fn enqueue(&mut self, _: &AudioChunk) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_audio_attachments_reset_devices_and_report_cleanup_failure() -> Result {
    let mut pair = pair().await?;
    let resets = Arc::new(AtomicUsize::new(0));

    let mut invalid = stream(1);
    invalid.binding.connection = 0;
    assert!(
        AudioSender::attach_channel(
            pair.host.sender(),
            ResetProbe {
                resets: resets.clone(),
                fail_reset: false,
            },
            invalid,
        )
        .is_err()
    );
    assert_eq!(resets.load(Ordering::SeqCst), 1);

    let mut wrong_generation = stream(1);
    wrong_generation.binding.connection = 10;
    assert!(
        AudioSender::attach_channel(
            pair.host.sender(),
            ResetProbe {
                resets: resets.clone(),
                fail_reset: false,
            },
            wrong_generation,
        )
        .is_err()
    );
    assert_eq!(resets.load(Ordering::SeqCst), 2);

    let _claimed = pair.controller.claim_channel(Channel::Audio)?;
    assert!(
        AudioReceiver::attach(
            &mut pair.controller,
            ResetProbe {
                resets: resets.clone(),
                fail_reset: false,
            },
            stream(1),
        )
        .is_err()
    );
    assert_eq!(resets.load(Ordering::SeqCst), 3);

    let mut invalid = stream(1);
    invalid.binding.connection = 0;
    let error = AudioSender::attach_channel(
        pair.host.sender(),
        ResetProbe {
            resets: resets.clone(),
            fail_reset: true,
        },
        invalid,
    )
    .err()
    .ok_or("invalid audio attachment unexpectedly succeeded")?;
    assert!(matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RemoteError>()),
        Some(RemoteError::Cleanup(_))
    ));
    assert_eq!(resets.load(Ordering::SeqCst), 4);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorized_opus_capture_transport_decode_and_playback_revoke_together() -> Result {
    for (channels, quic) in [(1, false), (2, false), (1, true), (2, true)] {
        let mut pair = crate::tests::pair_with_transport(quic).await?;
        let frames = Arc::new(Mutex::new(VecDeque::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(Mutex::new(SinkState::default()));
        let mut sender = AudioSender::attach(
            &pair.host,
            Capture {
                frames: frames.clone(),
                stopped: stopped.clone(),
            },
            stream(channels),
        )?;
        let mut receiver =
            AudioReceiver::attach(&mut pair.controller, Sink(sink.clone()), stream(channels))?;
        for index in 0..3 {
            frames
                .lock()
                .map_err(|_| "poisoned")?
                .push_back(CapturedAudio {
                    captured_at: Instant::now(),
                    chunk: tone(channels, index * 960),
                });
            wait_until(|| Ok(receiver.stats().played_chunks == index + 1)).await?;
        }
        {
            let state = sink.lock().map_err(|_| "poisoned")?;
            assert_eq!(state.played.len(), 3);
            assert_eq!(state.played[2].pts_48khz, 1920);
            for chunk in &state.played {
                chunk.validate(stream(channels).binding)?;
            }
            // Opus has startup delay; inspect sustained decoded output per channel.
            let samples = &state.played[2].samples;
            for channel in 0..channels as usize {
                let signal: Vec<_> = samples
                    .iter()
                    .skip(channel)
                    .step_by(channels as usize)
                    .map(|sample| f64::from(*sample))
                    .collect();
                let rms = (signal.iter().map(|x| x * x).sum::<f64>() / signal.len() as f64).sqrt();
                assert!(rms > 4000.0 && rms < 15000.0, "decoded rms {rms}");
                let crossings = signal
                    .windows(2)
                    .filter(|values| values[0] <= 0.0 && values[1] > 0.0)
                    .count();
                let expected = if channel == 0 { 9i32 } else { 18 };
                assert!((crossings as i32 - expected).abs() <= 2);
            }
        }
        pair.controller_revoke
            .send_replace(Some(StopReason::Revoked));
        pair.revoke.send_replace(Some(StopReason::Revoked));
        wait_until(|| {
            Ok(receiver.monitor().status().finished && sender.monitor().status().finished)
        })
        .await?;
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(sink.lock().map_err(|_| "poisoned")?.resets, 1);
        assert!(sink.lock().map_err(|_| "poisoned")?.played.is_empty());
        assert_eq!(
            sender.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claimed_audio_decodes_while_the_video_receivers_file_fifo_is_full() -> Result {
    let mut pair = pair().await?;
    let sink = Arc::new(Mutex::new(SinkState::default()));
    let mut audio = AudioReceiver::attach(&mut pair.controller, Sink(sink.clone()), stream(1))?;
    let mut video = VideoReceiver::attach(pair.controller, EPOCH, vec![selected(42)])?;
    for _ in 0..5 {
        pair.host.send(Channel::FileRead, b"file-event").await?;
    }
    wait_until(|| Ok(video.event_count_for_test() == 4)).await?;
    let mut codec = OpusEncoder::new(OpusConfig {
        channels: 1,
        bitrate: 96_000,
    })?;
    for index in 0..3 {
        pair.host
            .send(
                Channel::Audio,
                &packet(&mut codec, index + 1, index * 960)?.encode_validated()?,
            )
            .await?;
        wait_until(|| Ok(audio.stats().played_chunks == index + 1)).await?;
    }
    assert_eq!(sink.lock().map_err(|_| "poisoned")?.played.len(), 3);
    assert_eq!(video.event_count_for_test(), 4);
    pair.controller_revoke
        .send_replace(Some(StopReason::Revoked));
    wait_until(|| Ok(audio.monitor().status().finished && video.monitor().status().finished))
        .await?;
    assert!(sink.lock().map_err(|_| "poisoned")?.played.is_empty());
    assert_eq!(audio.shutdown(StopReason::Revoked)?, ShutdownReport::Joined);
    assert_eq!(video.shutdown(StopReason::Revoked)?, ShutdownReport::Joined);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_remote_audio_terminates_without_publishing_the_triggered_plc() -> Result {
    let mut pair = pair().await?;
    let sink = Arc::new(Mutex::new(SinkState::default()));
    let mut receiver = AudioReceiver::attach(&mut pair.controller, Sink(sink.clone()), stream(1))?;
    let mut codec = OpusEncoder::new(OpusConfig {
        channels: 1,
        bitrate: 96_000,
    })?;
    pair.host
        .send(
            Channel::Audio,
            &packet(&mut codec, 1, 0)?.encode_validated()?,
        )
        .await?;
    wait_until(|| Ok(receiver.stats().played_chunks == 1)).await?;
    let mut malformed = packet(&mut codec, 3, 1920)?;
    malformed.payload.truncate(1);
    // Stateless envelope passes a valid TOC; the full Opus parser must reject.
    pair.host
        .send(Channel::Audio, &malformed.encode_validated()?)
        .await?;
    wait_until(|| Ok(receiver.monitor().status().finished)).await?;
    assert!(receiver.monitor().status().error.is_some());
    assert_eq!(
        (
            receiver.stats().played_chunks,
            receiver.stats().concealed_chunks
        ),
        (1, 0)
    );
    assert!(sink.lock().map_err(|_| "poisoned")?.played.is_empty());
    assert_eq!(sink.lock().map_err(|_| "poisoned")?.resets, 1);
    assert_eq!(
        receiver.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transmitted_sequence_and_sample_clock_gaps_produce_only_bounded_audio() -> Result {
    let mut pair = pair().await?;
    let sink = Arc::new(Mutex::new(SinkState::default()));
    let mut receiver = AudioReceiver::attach(&mut pair.controller, Sink(sink.clone()), stream(1))?;
    let mut codec = OpusEncoder::new(OpusConfig {
        channels: 1,
        bitrate: 96_000,
    })?;
    // Audio can start after an initial queue drop, without a fabricated packet.
    pair.host
        .send(
            Channel::Audio,
            &packet(&mut codec, 5, 3840)?.encode_validated()?,
        )
        .await?;
    wait_until(|| Ok(receiver.stats().played_chunks == 1)).await?;
    packet(&mut codec, 6, 4800)?;
    pair.host
        .send(
            Channel::Audio,
            &packet(&mut codec, 7, 5760)?.encode_validated()?,
        )
        .await?;
    wait_until(|| Ok(receiver.stats().played_chunks == 3)).await?;
    assert_eq!(receiver.stats().concealed_chunks, 1);
    assert_eq!(
        sink.lock()
            .map_err(|_| "poisoned")?
            .played
            .iter()
            .map(|p| p.pts_48khz)
            .collect::<Vec<_>>(),
        [3840, 4800, 5760]
    );
    // Large gaps reset once, instead of generating an unbounded PCM backlog.
    pair.host
        .send(
            Channel::Audio,
            &packet(&mut codec, 8, 480_000)?.encode_validated()?,
        )
        .await?;
    wait_until(|| Ok(receiver.stats().played_chunks == 4)).await?;
    assert_eq!(
        (
            receiver.stats().received_packets,
            receiver.stats().concealed_chunks,
            receiver.stats().decoder_resets
        ),
        (3, 1, 1)
    );
    pair.controller_revoke
        .send_replace(Some(StopReason::Revoked));
    wait_until(|| Ok(receiver.monitor().status().finished)).await?;
    assert!(sink.lock().map_err(|_| "poisoned")?.played.is_empty());
    assert_eq!(
        receiver.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    Ok(())
}
