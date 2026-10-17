use crate::worker::{self, Worker};
use crate::{
    AudioCaptureTimeline, MAX_PLAYOUT_LATE, PlayoutDecision, SessionCaptureClock,
    SessionPlayoutClock, ShutdownReport, WorkerMonitor,
};
use nestlink_media_codec::{OpusConfig, OpusDecoder, OpusEncoder};
use nestlink_protocol::{NativeAudio, SCHEMA_VERSION};
use nestlink_remote::{
    ChannelReceiver, ChannelRuntime, ChannelSender, LeaseControl,
    audio::{
        AudioBinding, AudioCaptureController, AudioCaptureDevice, AudioChunk,
        AudioPlaybackController, AudioPlaybackDevice, AudioPlaybackTiming, CAPTURE_AGE,
        CHUNK_FRAMES,
    },
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug)]
pub struct AudioStream {
    pub binding: AudioBinding,
    pub bitrate: u32,
}
impl AudioStream {
    fn validate(self) -> io::Result<()> {
        self.binding.validate()?;
        if !(6_000..=256_000).contains(&self.bitrate) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid negotiated Opus bitrate",
            ));
        }
        Ok(())
    }
}
pub struct AudioSender {
    worker: Worker,
}
impl AudioSender {
    /// Capture and sender come from the same approved runtime. No public raw
    /// PCM submission entry point can accidentally join different sessions.
    pub fn attach<D: AudioCaptureDevice>(
        runtime: &ChannelRuntime,
        device: D,
        stream: AudioStream,
    ) -> io::Result<Self> {
        Self::attach_channel(runtime.sender(), device, stream)
    }
    /// Attach to a sender already derived from the approved runtime. The
    /// lease comes from that exact sender, so a caller cannot splice together
    /// the transport and authority of different sessions.
    pub fn attach_channel<D: AudioCaptureDevice>(
        sender: ChannelSender,
        device: D,
        stream: AudioStream,
    ) -> io::Result<Self> {
        Self::attach_capture_clock(sender, device, stream, None)
    }
    pub fn attach_channel_timed<D: AudioCaptureDevice>(
        sender: ChannelSender,
        device: D,
        stream: AudioStream,
        clock: SessionCaptureClock,
    ) -> io::Result<Self> {
        Self::attach_capture_clock(sender, device, stream, Some(clock))
    }
    fn attach_capture_clock<D: AudioCaptureDevice>(
        sender: ChannelSender,
        device: D,
        stream: AudioStream,
        clock: Option<SessionCaptureClock>,
    ) -> io::Result<Self> {
        if let Err(error) = stream.validate() {
            return Err(reject_audio_device(device, error));
        }
        let lease = sender.lease_control();
        if let Err(error) = lease.check_media_binding(Channel::Audio, stream.binding.connection) {
            return Err(reject_audio_device(device, io::Error::other(error)));
        }
        let controller = AudioCaptureController::attach(lease.clone(), device, stream.binding)
            .map_err(io::Error::other)?;
        let authority = lease.clone();
        let worker = Worker::spawn("nestlink-audio-send", lease, move |stop| {
            send(controller, sender, authority, stream, clock, stop)
        })?;
        Ok(Self { worker })
    }
    pub fn monitor(&self) -> WorkerMonitor {
        self.worker.monitor()
    }
    pub fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        self.worker.shutdown(reason)
    }
    /// Join a worker that finished after its shutdown budget expired.
    pub fn reap_finished(&mut self) -> io::Result<bool> {
        self.worker.reap_finished()
    }
}
fn send<D: AudioCaptureDevice>(
    controller: AudioCaptureController<D>,
    sender: ChannelSender,
    lease: LeaseControl,
    stream: AudioStream,
    clock: Option<SessionCaptureClock>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let runtime = worker::runtime()?;
    let mut codec = OpusEncoder::new(OpusConfig {
        channels: stream.binding.channels,
        bitrate: stream.bitrate,
    })?;
    let mut sequence = 0u64;
    let mut timeline = clock.map(AudioCaptureTimeline::new);
    runtime.block_on(async {
        loop {
            if worker::stopped(&stop) { return Ok(()); }
            let Some(mut captured) = controller.poll().map_err(io::Error::other)? else {
                tokio::select! { biased; _ = stop.changed() => {}, _ = tokio::time::sleep(Duration::from_millis(2)) => {} }
                continue;
            };
            if let Some(timeline)=timeline.as_mut(){
                let Some(pts)=timeline.map(captured.chunk.pts_48khz,captured.captured_at)? else{continue;};
                captured.chunk.pts_48khz=pts;
            }
            // Controller locks have been released before calling native Opus.
            let payload = codec.encode(&captured.chunk.samples)?;
            lease.check_media_binding(Channel::Audio, stream.binding.connection).map_err(io::Error::other)?;
            if worker::stopped(&stop) { return Ok(()); }
            // Once encoded, do not silently reuse its sequence for a later
            // packet. Expired audio may be dropped by the bounded channel queue.
            sequence = sequence.checked_add(1).ok_or_else(|| io::Error::other("audio sequence exhausted"))?;
            if captured.captured_at.elapsed() >= CAPTURE_AGE { continue; }
            let packet = NativeAudio {
                schema_version: SCHEMA_VERSION,
                connection_generation: stream.binding.connection,
                source: stream.binding.source,
                sequence,
                pts_48khz: captured.chunk.pts_48khz,
                channels: u32::from(stream.binding.channels),
                payload,
            }.encode_validated().map_err(io::Error::other)?;
            tokio::select! { biased;
                _ = stop.changed() => { return Ok(()); }
                result = sender.send(Channel::Audio, &packet) => { result.map_err(io::Error::other)?; }
            }
        }
    })
}

fn reject_audio_device<D: nestlink_remote::audio::AudioDevice>(
    mut device: D,
    primary: io::Error,
) -> io::Error {
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.reset()))
        .unwrap_or_else(|_| Err(io::Error::other("audio device cleanup panicked")));
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => io::Error::other(nestlink_remote::RemoteError::Cleanup(io::Error::new(
            cleanup.kind(),
            format!("audio attachment failed ({primary}); device cleanup failed: {cleanup}"),
        ))),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AudioStats {
    pub received_packets: u64,
    /// PCM accepted into the platform queue; not an audible completion count.
    pub played_chunks: u64,
    pub discarded_late_chunks: u64,
    pub discarded_future_chunks: u64,
    pub output_timing: AudioPlaybackTiming,
    /// Explicit history synthesis, never recovery of an authenticated packet.
    pub concealed_chunks: u64,
    pub decoder_resets: u64,
}
pub struct AudioReceiver {
    worker: Worker,
    stats: Arc<Mutex<AudioStats>>,
}
impl AudioReceiver {
    /// Claims incoming audio before another owner takes the runtime. Video or
    /// file consumers cannot steal audio packets, and decoding has its own
    /// thread. Native TCP/WSS can still block before an audio frame is received.
    pub fn attach<D: AudioPlaybackDevice>(
        runtime: &mut ChannelRuntime,
        device: D,
        stream: AudioStream,
    ) -> io::Result<Self> {
        if let Err(error) = stream.validate() {
            return Err(reject_audio_device(device, error));
        }
        if let Err(error) = runtime
            .lease_control()
            .check_media_binding(Channel::Audio, stream.binding.connection)
        {
            return Err(reject_audio_device(device, io::Error::other(error)));
        }
        let incoming = match runtime.claim_channel(Channel::Audio) {
            Ok(incoming) => incoming,
            Err(error) => return Err(reject_audio_device(device, io::Error::other(error))),
        };
        Self::attach_channel(incoming, device, stream)
    }
    /// Attach to an exclusive incoming Audio claim. Its lease is derived from
    /// the claim itself; other channels and other sessions cannot be paired
    /// with this playback controller.
    pub fn attach_channel<D: AudioPlaybackDevice>(
        incoming: ChannelReceiver,
        device: D,
        stream: AudioStream,
    ) -> io::Result<Self> {
        Self::attach_playout_clock(incoming, device, stream, None)
    }
    pub fn attach_channel_timed<D: AudioPlaybackDevice>(
        incoming: ChannelReceiver,
        device: D,
        stream: AudioStream,
        clock: SessionPlayoutClock,
    ) -> io::Result<Self> {
        Self::attach_playout_clock(incoming, device, stream, Some(clock))
    }
    fn attach_playout_clock<D: AudioPlaybackDevice>(
        incoming: ChannelReceiver,
        device: D,
        stream: AudioStream,
        clock: Option<SessionPlayoutClock>,
    ) -> io::Result<Self> {
        if let Err(error) = stream.validate() {
            return Err(reject_audio_device(device, error));
        }
        if incoming.channel() != Channel::Audio {
            return Err(reject_audio_device(
                device,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "audio receiver requires an Audio channel claim",
                ),
            ));
        }
        let lease = incoming.lease_control();
        if let Err(error) = lease.check_media_binding(Channel::Audio, stream.binding.connection) {
            return Err(reject_audio_device(device, io::Error::other(error)));
        }
        let playback = AudioPlaybackController::attach(lease.clone(), device, stream.binding)
            .map_err(io::Error::other)?;
        let stats = Arc::new(Mutex::new(AudioStats::default()));
        let recorded = stats.clone();
        let authority = lease.clone();
        let worker = Worker::spawn("nestlink-audio-receive", lease, move |stop| {
            receive(incoming, playback, authority, stream, recorded, clock, stop)
        })?;
        Ok(Self { worker, stats })
    }
    pub fn monitor(&self) -> WorkerMonitor {
        self.worker.monitor()
    }
    pub fn stats(&self) -> AudioStats {
        *self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        self.worker.shutdown(reason)
    }
    /// Join a worker that finished after its shutdown budget expired.
    pub fn reap_finished(&mut self) -> io::Result<bool> {
        self.worker.reap_finished()
    }
}
const MAX_PLC_CHUNKS: u64 = 3;
struct Decoded {
    chunks: Vec<AudioChunk>,
    concealed: u64,
    reset: bool,
}
struct Decoder {
    codec: OpusDecoder,
    binding: AudioBinding,
    sequence: Option<u64>,
    pts: Option<u64>,
}
impl Decoder {
    fn new(binding: AudioBinding) -> io::Result<Self> {
        binding.validate()?;
        Ok(Self {
            codec: OpusDecoder::new(binding.channels)?,
            binding,
            sequence: None,
            pts: None,
        })
    }
    fn decode(&mut self, packet: NativeAudio) -> io::Result<Decoded> {
        packet.validate().map_err(io::Error::other)?;
        if packet.connection_generation != self.binding.connection
            || packet.source != self.binding.source
            || packet.channels != u32::from(self.binding.channels)
            || !packet.pts_48khz.is_multiple_of(CHUNK_FRAMES as u64)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audio stream identity or sample clock changed",
            ));
        }
        let missing = if let (Some(sequence), Some(pts)) = (self.sequence, self.pts) {
            let elapsed = packet
                .pts_48khz
                .checked_sub(pts)
                .filter(|delta| *delta != 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "audio sample clock replay")
                })?
                / CHUNK_FRAMES as u64;
            let delta = packet
                .sequence
                .checked_sub(sequence)
                .filter(|delta| *delta != 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "audio sequence replay")
                })?;
            if delta > elapsed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audio sequence exceeds elapsed sample clock",
                ));
            }
            elapsed - 1
        } else {
            0
        };
        // Invalid packet framing never requests PLC or resets valid history.
        self.codec.validate_packet(&packet.payload)?;
        let reset = missing > MAX_PLC_CHUNKS;
        let concealed = if reset { 0 } else { missing };
        let mut chunks = Vec::with_capacity(concealed as usize + 1);
        if reset {
            self.codec.reset()?;
        }
        for offset in 1..=concealed {
            chunks.push(AudioChunk {
                source: self.binding.source,
                channels: self.binding.channels,
                pts_48khz: self
                    .pts
                    .ok_or_else(|| io::Error::other("PLC has no history"))?
                    + offset * CHUNK_FRAMES as u64,
                samples: self.codec.conceal_loss()?,
            });
        }
        // Stage the entire bounded batch until the actual decode succeeds, so
        // compressed-syntax failures do not publish its preceding PLC samples.
        chunks.push(AudioChunk {
            source: self.binding.source,
            channels: self.binding.channels,
            pts_48khz: packet.pts_48khz,
            samples: self.codec.decode(&packet.payload)?,
        });
        self.sequence = Some(packet.sequence);
        self.pts = Some(packet.pts_48khz);
        Ok(Decoded {
            chunks,
            concealed,
            reset,
        })
    }
}
fn receive<D: AudioPlaybackDevice>(
    mut incoming: ChannelReceiver,
    playback: AudioPlaybackController<D>,
    lease: LeaseControl,
    stream: AudioStream,
    stats: Arc<Mutex<AudioStats>>,
    clock: Option<SessionPlayoutClock>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let runtime = worker::runtime()?;
    let mut decoder = Decoder::new(stream.binding)?;
    let mut reports = lease.subscribe_stopped();
    runtime.block_on(async {
        loop {
            if worker::stopped(&stop) || reports.borrow().is_some() {
                return Ok(());
            }
            let frame = tokio::select! { biased;
                _ = stop.changed() => { return Ok(()); }
                _ = reports.changed() => { return Ok(()); }
                frame = incoming.receive() => { frame.map_err(io::Error::other)? }
            };
            let packet = NativeAudio::decode_validated(&frame.payload).map_err(io::Error::other)?;
            lease
                .check_media_binding(Channel::Audio, packet.connection_generation)
                .map_err(io::Error::other)?;
            let decoded = decoder.decode(packet)?;
            lease
                .check_media_binding(Channel::Audio, stream.binding.connection)
                .map_err(io::Error::other)?;
            {
                let mut current = stats
                    .lock()
                    .map_err(|_| io::Error::other("audio stats poisoned"))?;
                current.received_packets = current.received_packets.saturating_add(1);
                current.decoder_resets = current
                    .decoder_resets
                    .saturating_add(u64::from(decoded.reset));
            }
            for (index, chunk) in decoded.chunks.iter().enumerate() {
                if let Some(clock) = clock.as_ref() {
                    let decision = clock.schedule(chunk.pts_48khz, 48_000, Instant::now())?;
                    let due = match decision {
                        PlayoutDecision::At(due) => due,
                        PlayoutDecision::DropLate => {
                            let mut current = stats
                                .lock()
                                .map_err(|_| io::Error::other("audio stats poisoned"))?;
                            current.discarded_late_chunks =
                                current.discarded_late_chunks.saturating_add(1);
                            continue;
                        }
                        PlayoutDecision::DropFuture => {
                            let mut current = stats
                                .lock()
                                .map_err(|_| io::Error::other("audio stats poisoned"))?;
                            current.discarded_future_chunks =
                                current.discarded_future_chunks.saturating_add(1);
                            continue;
                        }
                    };
                    let timing = playback.timing().map_err(io::Error::other)?;
                    stats
                        .lock()
                        .map_err(|_| io::Error::other("audio stats poisoned"))?
                        .output_timing = timing;
                    let lead = timing
                        .known_output_delay(Instant::now())
                        .unwrap_or_default()
                        .min(Duration::from_millis(100));
                    let enqueue_at = due.checked_sub(lead).unwrap_or(due);
                    tokio::select! {biased;
                        _=stop.changed()=>return Ok(()),
                        _=reports.changed()=>return Ok(()),
                        _=tokio::time::sleep_until(enqueue_at.into())=>{}
                    }
                    if Instant::now().saturating_duration_since(due) > MAX_PLAYOUT_LATE {
                        let mut current = stats
                            .lock()
                            .map_err(|_| io::Error::other("audio stats poisoned"))?;
                        current.discarded_late_chunks =
                            current.discarded_late_chunks.saturating_add(1);
                        continue;
                    }
                }
                // Native decode is over. The small OS enqueue is serialized
                // with revocation/reset and rechecks this exact generation.
                playback.play(chunk).map_err(io::Error::other)?;
                let mut current = stats
                    .lock()
                    .map_err(|_| io::Error::other("audio stats poisoned"))?;
                current.played_chunks = current.played_chunks.saturating_add(1);
                current.concealed_chunks = current
                    .concealed_chunks
                    .saturating_add(u64::from((index as u64) < decoded.concealed));
            }
        }
    })
}

#[cfg(test)]
mod tests;
