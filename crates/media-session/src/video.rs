use crate::worker::{self, Worker};
use crate::{ShutdownReport, WorkerMonitor};
use nestlink_media_codec::{VideoCodec, VideoConfig, VideoEncoder};
use nestlink_protocol::{
    NativeVideo, NativeVideoFeedback, SCHEMA_VERSION, VIDEO_KEYFRAME_INTERVAL_MS,
};
use nestlink_remote::{
    ChannelReceiver, ChannelRuntime, ChannelSender, LeaseControl,
    video::{CaptureDevice, Display, RAW_FRAME_AGE, VideoController, VideoEpoch},
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

/// Fixed negotiated physical pixel dimensions; logical coordinates stay in the
/// approved display layout owned by VideoController.
#[derive(Clone, Copy, Debug)]
pub struct VideoStream {
    pub source: u32,
    pub codec: VideoConfig,
}
pub(crate) fn streams(epoch: VideoEpoch, streams: &[VideoStream]) -> io::Result<()> {
    if epoch.layout == 0
        || epoch.connection == 0
        || epoch.layout > i64::MAX as u64
        || epoch.connection > i64::MAX as u64
        || streams.is_empty()
        || streams.len() > 64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid media epoch/source count",
        ));
    }
    let mut sources = BTreeSet::new();
    let mut bytes = 0u64;
    for stream in streams {
        let config = stream.codec;
        let raw = u64::from(config.width)
            .checked_mul(u64::from(config.height))
            .and_then(|pixels| pixels.checked_mul(4));
        if !sources.insert(stream.source)
            || config.width == 0
            || config.height == 0
            || config.width > 8192
            || config.height > 8192
            || raw.is_none_or(|bytes| bytes > 64 * 1024 * 1024)
            || !(1..=120).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or duplicate fixed video stream",
            ));
        }
        bytes += raw.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "video geometry overflow")
        })?;
    }
    if bytes > 128 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selected raw output exceeds 128 MiB",
        ));
    }
    Ok(())
}
pub struct VideoSender {
    worker: Worker,
    stats: Arc<Mutex<VideoSenderStats>>,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct VideoSenderStats {
    pub feedback_requests: u64,
    pub duplicate_requests: u64,
    pub keyframes_encoded: u64,
}
impl VideoSender {
    /// Binds capture and sending to the same authorized session. There is no
    /// public raw-frame submission API or way to mix two sessions' authorities.
    pub fn attach<D: CaptureDevice>(
        runtime: &mut ChannelRuntime,
        device: D,
        epoch: VideoEpoch,
        displays: Vec<Display>,
        selected: Vec<VideoStream>,
    ) -> io::Result<Self> {
        streams(epoch, &selected)?;
        let approved: BTreeSet<_> = displays.iter().map(|display| display.source).collect();
        let expected: BTreeSet<_> = selected.iter().map(|stream| stream.source).collect();
        if approved != expected || displays.len() != expected.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "codec sources differ from approved capture sources",
            ));
        }
        let lease = runtime.lease_control();
        lease
            .check_media_binding(Channel::Video, epoch.connection)
            .map_err(io::Error::other)?;
        let controller = VideoController::attach(lease.clone(), device, epoch, displays)
            .map_err(io::Error::other)?;
        let feedback = runtime
            .claim_channel(Channel::VideoFeedback)
            .map_err(io::Error::other)?;
        let sender = runtime.sender();
        let worker_lease = lease.clone();
        let stats = Arc::new(Mutex::new(VideoSenderStats::default()));
        let worker_stats = stats.clone();
        let worker = Worker::spawn("nestlink-video-send", lease, move |stop| {
            send(
                controller,
                SendContext {
                    sender,
                    feedback,
                    lease: worker_lease,
                    epoch,
                    selected,
                    stats: worker_stats,
                },
                stop,
            )
        })?;
        Ok(Self { worker, stats })
    }
    pub fn stats(&self) -> VideoSenderStats {
        *self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn monitor(&self) -> WorkerMonitor {
        self.worker.monitor()
    }
    pub fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        self.worker.shutdown(reason)
    }
}
struct Encoder {
    prepare: crate::legacy_format::LegacyPrepare,
    codec: VideoEncoder,
    config: VideoConfig,
    sequence: u64,
    last_pts: Option<u64>,
    next_frame: Instant,
    force_keyframe: bool,
    next_keyframe: Instant,
    last_feedback: Option<NativeVideoFeedback>,
    last_pixels: Option<Zeroizing<Vec<u8>>>,
    pending_sources: BTreeMap<u64, bool>,
}
fn apply_feedback(
    bytes: &[u8],
    lease: &LeaseControl,
    epoch: VideoEpoch,
    codecs: &mut BTreeMap<u32, Encoder>,
    stats: &Mutex<VideoSenderStats>,
) -> io::Result<()> {
    let nestlink_protocol::native_displays::DisplayEnvelope::Recovery(request) =
        nestlink_protocol::native_displays::DisplayEnvelope::decode(bytes)
            .map_err(io::Error::other)?
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "static sender only accepts explicit Recovery envelopes",
        ));
    };
    lease
        .check_channel_binding(Channel::VideoFeedback, request.connection_generation)
        .map_err(io::Error::other)?;
    let encoder = codecs
        .get_mut(&request.source)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unapproved feedback source"))?;
    if request.layout_epoch != epoch.layout
        || request.connection_generation != epoch.connection
        || request.last_sequence > encoder.sequence
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "feedback changed its stream binding or acknowledged an unsent frame",
        ));
    }
    let mut stats = stats
        .lock()
        .map_err(|_| io::Error::other("video stats poisoned"))?;
    if encoder.last_feedback.as_ref() == Some(&request) {
        stats.duplicate_requests = stats.duplicate_requests.saturating_add(1);
        return Ok(());
    }
    let expected = encoder
        .last_feedback
        .as_ref()
        .map_or(Some(1), |last| last.request_sequence.checked_add(1));
    if expected != Some(request.request_sequence)
        || encoder
            .last_feedback
            .as_ref()
            .is_some_and(|last| request.last_sequence < last.last_sequence)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "replayed or conflicting video feedback",
        ));
    }
    encoder.last_feedback = Some(request);
    encoder.force_keyframe = true;
    stats.feedback_requests = stats.feedback_requests.saturating_add(1);
    Ok(())
}
struct SendContext {
    sender: ChannelSender,
    feedback: ChannelReceiver,
    lease: LeaseControl,
    epoch: VideoEpoch,
    selected: Vec<VideoStream>,
    stats: Arc<Mutex<VideoSenderStats>>,
}
fn send<D: CaptureDevice>(
    controller: VideoController<D>,
    context: SendContext,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let SendContext {
        sender,
        mut feedback,
        lease,
        epoch,
        selected,
        stats,
    } = context;
    // Generic fixed-source sender has no authenticated NLMF selection route.
    // V2 native producers use AppCore's exact proposal/ACK send gate instead.
    if lease.media_formats().map_err(io::Error::other)?.is_some() {
        return Err(io::Error::other(
            "fixed-source video sender cannot activate negotiated formats",
        ));
    }
    let capture_sources = selected
        .iter()
        .map(|stream| stream.source)
        .collect::<Vec<_>>();
    let runtime = worker::runtime()?;
    let origin = Instant::now();
    let codec_kind = if lease
        .media_capability(nestlink_protocol::media::H264_CAPABILITY)
        .map_err(io::Error::other)?
    {
        VideoCodec::H264Baseline
    } else {
        VideoCodec::Vp8
    };
    let mut codecs = BTreeMap::new();
    for stream in selected {
        codecs.insert(
            stream.source,
            Encoder {
                prepare: crate::legacy_format::LegacyPrepare::new_cpu_visible(
                    codec_kind,
                    stream.codec.width,
                    stream.codec.height,
                )?,
                codec: VideoEncoder::new(codec_kind, stream.codec)?,
                config: stream.codec,
                sequence: 0,
                last_pts: None,
                next_frame: origin,
                force_keyframe: true,
                next_keyframe: origin,
                last_feedback: None,
                last_pixels: None,
                pending_sources: BTreeMap::new(),
            },
        );
    }
    runtime.block_on(async {
        loop {
            if worker::stopped(&stop) {
                return Ok(());
            }
            tokio::select! { biased;
                _ = stop.changed() => { return Ok(()); }
                request = feedback.receive() => {
                    let request = request.map_err(io::Error::other)?;
                    apply_feedback(&request.payload, &lease, epoch, &mut codecs, &stats)?;
                }
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
            lease
                .check_media_binding(Channel::Video, epoch.connection)
                .map_err(io::Error::other)?;
            // poll checks current lease, layout and platform facts even when
            // the desktop is static. A recovery request may then re-encode the
            // latest approved image; the wire explicitly marks it as cached.
            let mut captured = controller
                .poll_sources(&capture_sources)
                .map_err(io::Error::other)?;
            let now = Instant::now();
            if let Some(captured) = &captured {
                if captured.epoch != epoch || captured.frame.source != captured.display.source {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "capture changed its stream binding",
                    ));
                }
                let encoder = codecs.get(&captured.frame.source).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unapproved capture source")
                })?;
                if captured.frame.width != encoder.config.width
                    || captured.frame.height != encoder.config.height
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "capture changed its negotiated physical dimensions",
                    ));
                }
            }
            let recovery_source = codecs.iter().find_map(|(&source, encoder)| {
                (encoder.force_keyframe
                    && now >= encoder.next_keyframe
                    && now >= encoder.next_frame
                    && encoder.last_pixels.is_some())
                .then_some(source)
            });
            // A continuously changing display must not starve an approved
            // static display's pending recovery. Only raw, unencoded pixels
            // may be deferred here; encoded reference packets remain FIFO.
            if recovery_source.is_some()
                && captured
                    .as_ref()
                    .is_some_and(|frame| Some(frame.frame.source) != recovery_source)
            {
                let mut frame = captured
                    .take()
                    .ok_or_else(|| io::Error::other("missing capture"))?
                    .frame;
                if frame.captured_at <= now
                    && now.duration_since(frame.captured_at) <= RAW_FRAME_AGE
                {
                    codecs
                        .get_mut(&frame.source)
                        .ok_or_else(|| io::Error::other("missing capture encoder"))?
                        .last_pixels = Some(Zeroizing::new(std::mem::take(&mut frame.pixels)));
                }
            }
            let (source, width, height, sampled_at, pixels, repeated_source) =
                if let Some(captured) = captured {
                    let mut frame = captured.frame;
                    (
                        frame.source,
                        frame.width,
                        frame.height,
                        frame.captured_at,
                        Zeroizing::new(std::mem::take(&mut frame.pixels)),
                        false,
                    )
                } else {
                    let Some(source) = recovery_source else {
                        continue;
                    };
                    let encoder = codecs
                        .get_mut(&source)
                        .ok_or_else(|| io::Error::other("missing recovery encoder"))?;
                    (
                        source,
                        encoder.config.width,
                        encoder.config.height,
                        now,
                        encoder
                            .last_pixels
                            .take()
                            .ok_or_else(|| io::Error::other("missing cached recovery pixels"))?,
                        true,
                    )
                };
            let encoder = codecs.get_mut(&source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unapproved capture source")
            })?;
            // Only unencoded raw frames may be skipped. While send is blocked
            // below, no more capture is polled; the platform retains latest raw.
            if sampled_at > now || now.duration_since(sampled_at) > RAW_FRAME_AGE {
                continue;
            }
            if now < encoder.next_frame {
                encoder.last_pixels = Some(pixels);
                continue;
            }
            let elapsed = sampled_at
                .checked_duration_since(origin)
                .unwrap_or_default();
            let pts =
                u64::try_from(elapsed.as_nanos() / 1_000_000 * 90).map_err(io::Error::other)?;
            let pts = pts.max(encoder.last_pts.map_or(0, |last| last.saturating_add(1)));
            // poll() has released the lease and platform locks before encoding.
            if encoder.pending_sources.len() >= 8 {
                return Err(io::Error::other(
                    "encoder output delay exceeded bounded metadata queue",
                ));
            }
            encoder.pending_sources.insert(pts, repeated_source);
            let packet = encoder.codec.encode(
                &pixels,
                pts,
                encoder.force_keyframe && now >= encoder.next_keyframe,
            )?;
            encoder.last_pixels = Some(pixels);
            encoder.last_pts = Some(pts);
            let Some(packet) = packet else {
                continue;
            };
            // Validate actual emitted bytes and real configured target before
            // making this packet visible to the authorized transport.
            let sps = encoder.prepare.validate(&packet.data, packet.keyframe)?;
            let _actual_format = encoder.prepare.configured(encoder.config, sps)?;
            let repeated_source = encoder
                .pending_sources
                .remove(&packet.pts_90khz)
                .ok_or_else(|| {
                    io::Error::other("encoder output has an unknown source timestamp")
                })?;
            if packet.keyframe {
                encoder.force_keyframe = false;
                encoder.next_keyframe = now + Duration::from_millis(VIDEO_KEYFRAME_INTERVAL_MS);
                let mut stats = stats
                    .lock()
                    .map_err(|_| io::Error::other("video stats poisoned"))?;
                stats.keyframes_encoded = stats.keyframes_encoded.saturating_add(1);
            }
            encoder.last_pts = Some(pts);
            encoder.next_frame =
                now + Duration::from_nanos(1_000_000_000 / u64::from(encoder.config.fps));
            if worker::stopped(&stop) {
                return Ok(());
            }
            lease
                .check_media_binding(Channel::Video, epoch.connection)
                .map_err(io::Error::other)?;
            let sequence = encoder
                .sequence
                .checked_add(1)
                .filter(|sequence| *sequence <= i64::MAX as u64)
                .ok_or_else(|| io::Error::other("video sequence exhausted"))?;
            let mut envelope = NativeVideo {
                format_epoch: 0,
                format_sha256: Vec::new(),
                codec: match codec_kind {
                    VideoCodec::Vp8 => 0,
                    VideoCodec::H264Baseline => 1,
                },
                schema_version: SCHEMA_VERSION,
                connection_generation: epoch.connection,
                layout_epoch: epoch.layout,
                source,
                sequence,
                pts_90khz: packet.pts_90khz,
                width,
                height,
                keyframe: packet.keyframe,
                payload: packet.data,
                repeated_source,
            };
            let bytes = envelope.encode_validated();
            envelope.payload.zeroize();
            let bytes = Zeroizing::new(bytes.map_err(io::Error::other)?);
            // Publish the prepared sequence before enqueue: the peer can see a
            // queued frame before this thread is scheduled again. A failed
            // enqueue is terminal; its sequence is never reused.
            encoder.sequence = sequence;
            let pending = sender.send(Channel::Video, &bytes);
            tokio::pin!(pending);
            let result = loop {
                tokio::select! { biased;
                    _ = stop.changed() => { return Ok(()); }
                    result = &mut pending => { break result; }
                    request = feedback.receive() => {
                        let request = request.map_err(io::Error::other)?;
                        apply_feedback(&request.payload, &lease, epoch, &mut codecs, &stats)?;
                    }
                }
            };
            // No encoded reference frame is replaced or dropped. An actual send
            // error terminates this stream, so it cannot feed dependent deltas.
            result.map_err(io::Error::other)?;
        }
    })
}
