//! Codec selection is complete before an answer is signed. Capture is never
//! opened by preflight: only locally generated pixels reach the encoder.
use super::*;
use nestlink_media_codec::{
    EncodedVideo, H264EncodingLimits, H264Validator, VideoEncodeStep, VideoEncoder,
};
use nestlink_protocol::webrtc::video::{H264Format, H264Profile, VideoFormat, offered_formats};

#[derive(Clone, Copy, Debug)]
pub struct HostVideoPreflight {
    pub source: u32,
    pub connection_generation: u64,
    pub config: VideoConfig,
}

/// GPU ownership stays behind the permission controller and its owner thread.
/// Only scalar tickets and bounded encoded access units enter this worker.
pub(super) enum HostEncoder {
    Cpu(VideoEncoder),
    Owner {
        validator: H264Validator,
        hardware: bool,
    },
}

pub(super) enum HostFrame {
    Cpu(CapturedVideo),
    Owner(CapturedHostFrame),
}

impl HostFrame {
    pub(super) fn encode_at(&self) -> Instant {
        match self {
            Self::Cpu(value) => value.frame.captured_at,
            Self::Owner(value) => value.frame.encode_at,
        }
    }

    pub(super) fn validate(&self, selection: HostVideoSelection) -> io::Result<()> {
        let (epoch, display, source, width, height, captured_at, encode_at, repeated) = match self {
            Self::Cpu(value) => {
                value.frame.validate()?;
                (
                    value.epoch,
                    value.display,
                    value.frame.source,
                    value.frame.width,
                    value.frame.height,
                    value.frame.captured_at,
                    value.frame.captured_at,
                    false,
                )
            }
            Self::Owner(value) => {
                if value.frame.ticket == 0 || value.frame.generation == 0 {
                    return Err(io::Error::other("invalid owner capture ticket"));
                }
                (
                    value.epoch,
                    value.display,
                    value.frame.source,
                    value.frame.width,
                    value.frame.height,
                    value.frame.captured_at,
                    value.frame.encode_at,
                    value.frame.repeated,
                )
            }
        };
        let now = Instant::now();
        if epoch != selection.epoch
            || display.source != selection.display.source
            || source != selection.display.source
            || width != selection.codec.width
            || height != selection.codec.height
            || captured_at > encode_at
            || encode_at > now
            || now.duration_since(encode_at) > MAX_VIDEO_FRAME_AGE
            || (!repeated && captured_at != encode_at)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured video does not match its approved source/epoch/geometry",
            ));
        }
        Ok(())
    }
}

impl HostEncoder {
    pub(super) fn prepare(
        source: &HostVideoSource,
        selected_source: u32,
        format: VideoFormat,
        config: VideoConfig,
    ) -> io::Result<Self> {
        if let VideoFormat::H264(value) = format {
            let limits = H264EncodingLimits {
                max_level_idc: value.level_idc,
                require_constrained_baseline: value.profile == H264Profile::ConstrainedBaseline,
            };
            limits.validate_config(config)?;
            if source
                .source
                .host_configure(HostVideoConfig {
                    source: selected_source,
                    width: config.width,
                    height: config.height,
                    fps: config.fps,
                    bitrate_kbps: config.bitrate_kbps,
                    max_level_idc: limits.max_level_idc,
                    require_constrained_baseline: limits.require_constrained_baseline,
                })
                .map_err(io::Error::other)?
            {
                return Ok(Self::Owner {
                    validator: H264Validator::with_limits(config.width, config.height, limits)?,
                    // The real transform has not produced output yet. Start
                    // conservatively until its output establishes the backend.
                    hardware: false,
                });
            }
        }
        prepare_encoder(format, config).map(Self::Cpu)
    }

    pub(super) fn capture(
        &self,
        source: &HostVideoSource,
        allow_cached: bool,
    ) -> io::Result<Option<HostFrame>> {
        match self {
            Self::Cpu(_) => source.poll().map(|value| value.map(HostFrame::Cpu)),
            Self::Owner { .. } => source
                .source
                .host_capture(allow_cached)
                .map(|value| value.map(HostFrame::Owner)),
        }
        .map_err(io::Error::other)
    }

    pub(super) fn encode(
        &mut self,
        source: &HostVideoSource,
        frame: HostFrame,
        pts: u64,
        keyframe: bool,
        selection: HostVideoSelection,
        format: VideoFormat,
    ) -> io::Result<VideoEncodeStep> {
        match (self, frame) {
            (Self::Cpu(encoder), HostFrame::Cpu(frame)) => {
                encoder.encode_step(&frame.frame.pixels, pts, keyframe)
            }
            (
                Self::Owner {
                    validator,
                    hardware,
                },
                HostFrame::Owner(frame),
            ) => {
                let step = source
                    .source
                    .host_encode(frame, pts, keyframe)
                    .map_err(io::Error::other)?;
                owner_step(step, validator, hardware, selection, format)
            }
            _ => Err(io::Error::other("capture and encoder backend changed")),
        }
    }

    pub(super) fn drain(
        &mut self,
        source: &HostVideoSource,
        selection: HostVideoSelection,
        format: VideoFormat,
    ) -> io::Result<VideoEncodeStep> {
        match self {
            Self::Cpu(encoder) => encoder.drain_encoded(),
            Self::Owner {
                validator,
                hardware,
            } => owner_step(
                source.source.host_drain().map_err(io::Error::other)?,
                validator,
                hardware,
                selection,
                format,
            ),
        }
    }

    pub(super) fn set_bitrate(&mut self, source: &HostVideoSource, kbps: u32) -> io::Result<()> {
        match self {
            Self::Cpu(encoder) => encoder.set_bitrate(kbps),
            Self::Owner { .. } => source
                .source
                .host_set_bitrate(kbps)
                .map_err(io::Error::other),
        }
    }

    pub(super) fn sps(&self) -> Option<nestlink_media_codec::H264SpsInfo> {
        match self {
            Self::Cpu(encoder) => encoder.h264_sps_info(),
            Self::Owner { validator, .. } => validator.sps_info(),
        }
    }

    pub(super) fn frame_period(&self, requested_fps: u32) -> Duration {
        let fps = if matches!(self, Self::Owner { hardware: true, .. }) {
            requested_fps
        } else {
            requested_fps.min(30)
        };
        Duration::from_nanos(1_000_000_000 / u64::from(fps.max(1)))
    }
}

fn owner_step(
    step: HostVideoStep,
    validator: &mut H264Validator,
    observed_hardware: &mut bool,
    selection: HostVideoSelection,
    format: VideoFormat,
) -> io::Result<VideoEncodeStep> {
    // A hardware MFT may accept input before it produces its first output.
    // The owner can also retire a lost device and start a fresh software
    // reference chain. Both remain subject to the same AU and epoch checks.
    *observed_hardware = step.hardware;
    let output = step
        .output
        .map(|mut output| {
            if output.epoch != selection.epoch || output.source != selection.display.source {
                return Err(io::Error::other("stale GPU encoder output"));
            }
            let unit = validator.validate(&output.packet.data)?;
            if unit.keyframe != output.packet.keyframe {
                return Err(io::Error::other(
                    "GPU encoder keyframe metadata differs from actual AU",
                ));
            }
            if let Some(sps) = unit.sps {
                validate_sps(format, sps)?;
            }
            Ok(EncodedVideo {
                pts_90khz: output.packet.pts_90khz,
                keyframe: unit.keyframe,
                data: std::mem::take(&mut output.packet.data),
            })
        })
        .transpose()?;
    Ok(VideoEncodeStep {
        accepted: step.accepted,
        output,
    })
}

fn capability(format: VideoFormat) -> RTCRtpCodecCapability {
    RTCRtpCodecCapability {
        mime_type: match format {
            VideoFormat::Vp8 => MIME_TYPE_VP8,
            VideoFormat::H264(_) => "video/H264",
        }
        .into(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: match format {
            VideoFormat::Vp8 => String::new(),
            VideoFormat::H264(value) => value.fmtp(),
        },
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "nack".into(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".into(),
                parameter: "pli".into(),
            },
            RTCPFeedback {
                typ: "ccm".into(),
                parameter: "fir".into(),
            },
            RTCPFeedback {
                typ: "goog-remb".into(),
                parameter: String::new(),
            },
        ],
    }
}

pub(super) fn register_h264(media: &mut MediaEngine) -> Result<(), WebRtcError> {
    // Register both profiles; the actual target probe and signed offer choose
    // a single format before answer creation. Linux retains VP8-only encoding.
    #[cfg(windows)]
    for (payload, constraints, profile) in [
        (102, 0xe0, H264Profile::ConstrainedBaseline),
        (104, 0, H264Profile::Baseline),
    ] {
        media.register_codec(
            RTCRtpCodecParameters {
                capability: capability(VideoFormat::H264(H264Format {
                    profile,
                    profile_idc: 0x42,
                    constraints,
                    level_idc: 52,
                    level_asymmetry_allowed: false,
                })),
                payload_type: payload,
                ..Default::default()
            },
            RTPCodecType::Video,
        )?;
    }
    #[cfg(not(windows))]
    let _ = media;
    Ok(())
}

pub(super) fn encoder(format: VideoFormat, config: VideoConfig) -> io::Result<VideoEncoder> {
    match format {
        VideoFormat::Vp8 => VideoEncoder::new(nestlink_media_codec::VideoCodec::Vp8, config),
        VideoFormat::H264(value) => {
            if !config.width.is_multiple_of(2)
                || !config.height.is_multiple_of(2)
                || !value.supports(config.width, config.height, config.fps, config.bitrate_kbps)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "video configuration exceeds negotiated H.264 format",
                ));
            }
            VideoEncoder::new_h264(
                config,
                H264EncodingLimits {
                    max_level_idc: value.level_idc,
                    require_constrained_baseline: value.profile == H264Profile::ConstrainedBaseline,
                },
            )
        }
    }
}

impl WebRtcHostPeer {
    /// Metadata of the locally approved initial source. This does not open a
    /// capture device and is rechecked against the post-proof media factory.
    pub fn set_video_preflight(
        &mut self,
        value: HostVideoPreflight,
    ) -> Result<(), WebRtcHostError> {
        self.ensure_open()?;
        if self.remote_offer_sequence != 0
            || value.connection_generation != self.current_permit().claims().connection_generation
            || value.config.width == 0
            || value.config.height == 0
            || value.config.fps == 0
        {
            return Err(WebRtcHostError::Permit);
        }
        self.video_preflight = Some(value);
        Ok(())
    }

    pub(super) async fn select_video_codec(&mut self, sdp: &str) -> Result<(), WebRtcHostError> {
        let offered = offered_formats(sdp)?;
        if self.media_started {
            // ICE restarts cannot change the codec beneath the running worker.
            if !offered
                .iter()
                .any(|(_, format)| compatible(*format, self.video_format))
            {
                return Err(WebRtcHostError::InvalidOffer);
            }
            return Ok(());
        }
        let mut chosen = None;
        #[cfg(windows)]
        if let Some(preflight) = self.video_preflight {
            let mut candidates = offered
                .iter()
                .filter_map(|(_, format)| match format {
                    // webrtc 0.14 compares the first two profile bytes literally.
                    // A partial MIME match cannot be trusted when VP8 is present.
                    VideoFormat::H264(value)
                        if value.profile_idc == 0x42 && matches!(value.constraints, 0xe0 | 0) =>
                    {
                        Some(*value)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|value| std::cmp::Reverse(value.level_idc));
            let mut attempted = Vec::new();
            for remote in candidates {
                let config = preflight.config;
                if !config.width.is_multiple_of(2)
                    || !config.height.is_multiple_of(2)
                    || !remote.supports(
                        config.width,
                        config.height,
                        config.fps,
                        config.bitrate_kbps,
                    )
                {
                    continue;
                }
                if attempted.contains(&remote.profile) {
                    continue;
                }
                attempted.push(remote.profile);
                self.ensure_open()?;
                let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
                self.media_workers.push(tokio::spawn(async move {
                    let probe = tokio::task::spawn_blocking(move || {
                        nestlink_media_codec::probe_h264_encoder(
                            config,
                            Some(H264EncodingLimits {
                                max_level_idc: remote.level_idc,
                                require_constrained_baseline: remote.profile
                                    == H264Profile::ConstrainedBaseline,
                            }),
                        )
                    })
                    .await
                    .map_err(io::Error::other)
                    .and_then(|value| value);
                    let _ = probe_tx.send(probe);
                }));
                let mut cancel = self.cancel_tx.subscribe();
                let probe = tokio::select! {
                    biased;
                    _ = cancel.changed() => return Err(WebRtcHostError::Closed),
                    result = probe_rx => result.map_err(io::Error::other)?,
                };
                self.ensure_open()?;
                let Ok(probe) = probe else {
                    continue;
                };
                let Some(local) = H264Format::parse(&format!(
                    "packetization-mode=1;profile-level-id={}",
                    probe.sps.profile_level_id()
                ))?
                else {
                    continue;
                };
                if local.profile == remote.profile
                    && local.level_idc <= remote.level_idc
                    && local.supports(config.width, config.height, config.fps, config.bitrate_kbps)
                {
                    chosen = Some(VideoFormat::H264(H264Format {
                        level_idc: local.level_idc,
                        level_asymmetry_allowed: false,
                        ..remote
                    }));
                    break;
                }
            }
        }
        if chosen.is_none()
            && offered
                .iter()
                .any(|(_, format)| *format == VideoFormat::Vp8)
        {
            chosen = Some(VideoFormat::Vp8);
        }
        let chosen = chosen.ok_or(WebRtcHostError::InvalidOffer)?;
        let codec = capability(chosen);
        // Payload is selected from the signed offer; no fixed browser PT is assumed.
        let payload_type = offered
            .iter()
            .find(|(_, remote)| {
                compatible(*remote, chosen)
                    && match (*remote, chosen) {
                        (VideoFormat::H264(remote), VideoFormat::H264(local)) => {
                            remote.profile_idc == local.profile_idc
                                && remote.constraints == local.constraints
                        }
                        _ => true,
                    }
            })
            .map(|(payload, _)| *payload)
            .ok_or(WebRtcHostError::InvalidOffer)?;
        for transceiver in self.peer.get_transceivers().await {
            if Arc::ptr_eq(&transceiver.sender().await, &self.video_sender) {
                transceiver
                    .set_codec_preferences(vec![RTCRtpCodecParameters {
                        capability: codec.clone(),
                        payload_type,
                        ..Default::default()
                    }])
                    .await?;
            }
        }
        let track = Arc::new(TrackLocalStaticRTP::new(
            codec,
            "nestlink-video".into(),
            self.current_permit().claims().session_id.clone(),
        ));
        self.video_sender.replace_track(Some(track.clone())).await?;
        self.video_track = track;
        self.video_format = chosen;
        Ok(())
    }

    pub(super) fn validate_video_answer(&self, sdp: &str) -> Result<(), WebRtcHostError> {
        let formats = offered_formats(sdp)?;
        if formats.len() != 1
            || !formats
                .iter()
                .all(|(_, format)| compatible(*format, self.video_format))
        {
            return Err(WebRtcHostError::InvalidOffer);
        }
        Ok(())
    }
}

fn compatible(remote: VideoFormat, local: VideoFormat) -> bool {
    match (remote, local) {
        (VideoFormat::Vp8, VideoFormat::Vp8) => true,
        (VideoFormat::H264(remote), VideoFormat::H264(local)) => {
            remote.profile == local.profile && local.level_idc <= remote.level_idc
        }
        _ => false,
    }
}

pub(super) struct VideoRtpWriter {
    payloader: Box<dyn webrtc::rtp::packetizer::Payloader + Send + Sync>,
    sequence: Box<dyn webrtc::rtp::sequence::Sequencer + Send + Sync>,
    timestamp_base: u32,
}

impl VideoRtpWriter {
    pub(super) fn new(format: VideoFormat) -> io::Result<Self> {
        Ok(Self {
            payloader: capability(format)
                .payloader_for_codec()
                .map_err(io::Error::other)?,
            sequence: Box::new(webrtc::rtp::sequence::new_random_sequencer()),
            timestamp_base: uuid::Uuid::new_v4().as_u128() as u32,
        })
    }

    pub(super) fn packets(
        &mut self,
        data: Bytes,
        pts: u64,
    ) -> io::Result<Vec<webrtc::rtp::packet::Packet>> {
        // Reserve space for RTP extensions and SRTP below the network MTU.
        let payloads = self
            .payloader
            .payload(1100, &data)
            .map_err(io::Error::other)?;
        let last = payloads.len().saturating_sub(1);
        Ok(payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| webrtc::rtp::packet::Packet {
                header: webrtc::rtp::header::Header {
                    version: 2,
                    marker: index == last,
                    sequence_number: self.sequence.next_sequence_number(),
                    timestamp: self.timestamp_base.wrapping_add(pts as u32),
                    ..Default::default()
                },
                payload,
            })
            .collect())
    }

    pub(super) fn write(
        &mut self,
        data: Bytes,
        pts: u64,
        track: &TrackLocalStaticRTP,
        context: &VideoWriteContext<'_>,
    ) -> io::Result<bool> {
        let packets = self.packets(data, pts)?;
        if packets.is_empty() {
            return Err(io::Error::other("empty video access unit"));
        }
        for packet in packets {
            if *context.cancel.borrow() {
                return Ok(false);
            }
            let Some(remaining) = context.deadline.checked_duration_since(Instant::now()) else {
                // A partial AU is abandoned as one frame. The caller requests
                // an independent recovery frame instead of queuing stale RTP.
                return Ok(false);
            };
            ensure_media_permit(context.permit, Permission::View)?;
            if context.selected_path == Path::Relay && !*context.path_authority.borrow() {
                return Ok(false);
            }
            let result = context.runtime.block_on(async {
                let mut cancel = context.cancel.clone();
                tokio::select! {
                    biased;
                    _ = cancel.changed() => Err(io::Error::new(io::ErrorKind::Interrupted, "video cancelled")),
                    result = tokio::time::timeout(remaining.min(Duration::from_millis(500)), track.write_rtp(&packet)) => {
                        result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "video RTP write timed out"))?
                            .map_err(io::Error::other)
                    }
                }
            });
            if let Err(error) = result {
                if *context.cancel.borrow()
                    || Instant::now() >= context.deadline
                    || is_transient_media_write_state(context.peer.connection_state())
                {
                    return Ok(false);
                }
                return Err(error);
            }
        }
        Ok(true)
    }
}

pub(super) struct VideoWriteContext<'a> {
    pub peer: &'a RTCPeerConnection,
    pub runtime: &'a Handle,
    pub permit: &'a watch::Receiver<VerifiedPermit>,
    pub cancel: &'a watch::Receiver<bool>,
    pub selected_path: Path,
    pub path_authority: &'a watch::Receiver<bool>,
    pub deadline: Instant,
}

pub(super) fn packet_deadline(origin: Instant, pts: u64) -> io::Result<Instant> {
    let nanos =
        u64::try_from(u128::from(pts) * 1_000_000_000 / 90_000).map_err(io::Error::other)?;
    origin
        .checked_add(Duration::from_nanos(nanos))
        .and_then(|created| created.checked_add(MAX_VIDEO_FRAME_AGE))
        .ok_or_else(|| io::Error::other("video send deadline overflow"))
}

pub(super) struct PrepareVideo {
    pub source: u32,
    pub config: VideoConfig,
    pub done: tokio::sync::oneshot::Sender<io::Result<()>>,
}

pub(super) fn prepare_encoder(
    format: VideoFormat,
    config: VideoConfig,
) -> io::Result<VideoEncoder> {
    if let VideoFormat::H264(value) = format {
        let probe = nestlink_media_codec::probe_h264_encoder(
            config,
            Some(H264EncodingLimits {
                max_level_idc: value.level_idc,
                require_constrained_baseline: value.profile == H264Profile::ConstrainedBaseline,
            }),
        )?;
        validate_sps(format, probe.sps)?;
        if !probe.hardware {
            return VideoEncoder::new_h264_software(
                config,
                H264EncodingLimits {
                    max_level_idc: value.level_idc,
                    require_constrained_baseline: value.profile == H264Profile::ConstrainedBaseline,
                },
            );
        }
    }
    encoder(format, config)
}

pub(super) fn validate_sps(
    format: VideoFormat,
    sps: nestlink_media_codec::H264SpsInfo,
) -> io::Result<()> {
    let actual = H264Format::parse(&format!(
        "packetization-mode=1;profile-level-id={}",
        sps.profile_level_id()
    ))
    .map_err(io::Error::other)?
    .map(VideoFormat::H264);
    if !actual.is_some_and(|actual| compatible(format, actual)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "H.264 SPS exceeds negotiated profile/level",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod backend_tests {
    use super::*;
    use nestlink_remote::input::InputLayout;

    fn selection() -> HostVideoSelection {
        HostVideoSelection {
            epoch: VideoEpoch {
                layout: 2,
                connection: 3,
            },
            display: Display {
                source: 4,
                logical: InputLayout {
                    left: -1280,
                    top: 0,
                    width: 1280,
                    height: 720,
                },
            },
            codec: VideoConfig {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 4000,
            },
        }
    }

    #[test]
    fn owner_can_accept_input_before_observed_output_and_paces_software_fallback() -> io::Result<()>
    {
        let mut encoder = HostEncoder::Owner {
            validator: H264Validator::new(1280, 720)?,
            hardware: true,
        };
        assert_eq!(
            encoder.frame_period(60),
            Duration::from_nanos(1_000_000_000 / 60)
        );
        let HostEncoder::Owner {
            validator,
            hardware,
        } = &mut encoder
        else {
            unreachable!();
        };
        let step = owner_step(
            HostVideoStep {
                accepted: true,
                hardware: false,
                output: None,
            },
            validator,
            hardware,
            selection(),
            VideoFormat::Vp8,
        )?;
        assert!(step.accepted);
        assert!(step.output.is_none());
        assert_eq!(
            encoder.frame_period(60),
            Duration::from_nanos(1_000_000_000 / 30)
        );
        Ok(())
    }

    #[test]
    fn cached_recovery_preserves_capture_age_without_accepting_stale_fresh_frames() -> io::Result<()>
    {
        let selection = selection();
        let now = Instant::now();
        let mut frame = CapturedHostFrame {
            epoch: selection.epoch,
            display: selection.display,
            frame: nestlink_remote::video::HostFrame {
                ticket: 1,
                generation: 1,
                source: 4,
                width: 1280,
                height: 720,
                captured_at: now - Duration::from_secs(2),
                encode_at: now,
                repeated: true,
            },
        };
        HostFrame::Owner(frame).validate(selection)?;
        frame.frame.repeated = false;
        assert!(HostFrame::Owner(frame).validate(selection).is_err());
        frame.frame.repeated = true;
        frame.epoch.layout += 1;
        assert!(HostFrame::Owner(frame).validate(selection).is_err());
        frame.epoch = selection.epoch;
        frame.frame.encode_at = Instant::now() + Duration::from_secs(1);
        assert!(HostFrame::Owner(frame).validate(selection).is_err());
        Ok(())
    }

    #[test]
    fn rtp_send_budget_belongs_to_actual_output_pts() -> io::Result<()> {
        let origin = Instant::now();
        assert_eq!(packet_deadline(origin, 0)?, origin + MAX_VIDEO_FRAME_AGE);
        assert_eq!(
            packet_deadline(origin, 90_000)?,
            origin + Duration::from_secs(1) + MAX_VIDEO_FRAME_AGE
        );
        assert!(packet_deadline(origin, u64::MAX).is_err());
        Ok(())
    }
}
