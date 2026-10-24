//! Codec choice is made before negotiation. Runtime fallback preserves that
//! codec and reports the backend actually producing frames.
use crate::{EncodedVideo, H264EncodingLimits, H264SpsInfo, VideoConfig, Vp8Decoder, Vp8Encoder};
use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VideoCodec {
    #[default]
    Vp8,
    H264Baseline,
}
impl VideoCodec {
    pub fn name(self) -> &'static str {
        match self {
            Self::Vp8 => "VP8",
            Self::H264Baseline => "H.264 Baseline",
        }
    }
}

/// Input acceptance and output availability are independent for delayed MFTs.
#[derive(Debug)]
pub struct VideoEncodeStep {
    pub accepted: bool,
    pub output: Option<EncodedVideo>,
}
#[derive(Clone, Copy, Debug)]
pub struct H264EncoderProbe {
    /// Requested target; odd visible dimensions may be rounded for the codec.
    pub config: VideoConfig,
    /// Actual display dimensions supplied to the encoder and independent decoder.
    pub encoded_config: VideoConfig,
    /// Actual SPS coded dimensions and crop, retained before resource shutdown.
    pub geometry: crate::H264Geometry,
    pub sps: H264SpsInfo,
    /// Observed encoded output from a hardware MFT, not a zero-copy claim.
    pub hardware: bool,
}

pub enum VideoEncoder {
    Vp8(Vp8Encoder),
    #[cfg(windows)]
    H264(H264Encoder),
}
impl VideoEncoder {
    /// Create and retain this encoder on the dedicated media worker. MF owners
    /// are !Send and must be destroyed on the same thread that created them.
    pub fn new_h264(config: VideoConfig, limits: H264EncodingLimits) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self::H264(H264Encoder::with_limits(
                config,
                Some(limits),
                true,
            )?))
        }
        #[cfg(not(windows))]
        {
            let _ = (config, limits);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "H.264 encoder unavailable on this platform",
            ))
        }
    }
    pub fn new_h264_software(config: VideoConfig, limits: H264EncodingLimits) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self::H264(H264Encoder::with_limits(
                config,
                Some(limits),
                false,
            )?))
        }
        #[cfg(not(windows))]
        {
            let _ = (config, limits);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "H.264 encoder unavailable on this platform",
            ))
        }
    }
    pub fn h264_sps_info(&self) -> Option<H264SpsInfo> {
        match self {
            Self::Vp8(_) => None,
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.sps_info(),
        }
    }
    pub fn encode_step(
        &mut self,
        bgra: &[u8],
        pts: u64,
        keyframe: bool,
    ) -> io::Result<VideoEncodeStep> {
        match self {
            Self::Vp8(codec) => Ok(VideoEncodeStep {
                accepted: true,
                output: Some(codec.encode(bgra, pts, keyframe)?),
            }),
            #[cfg(windows)]
            Self::H264(codec) => codec.encode_step(bgra, pts, keyframe),
        }
    }
    pub fn new(codec: VideoCodec, config: VideoConfig) -> io::Result<Self> {
        match codec {
            VideoCodec::Vp8 => Ok(Self::Vp8(Vp8Encoder::new(config)?)),
            #[cfg(windows)]
            VideoCodec::H264Baseline => Ok(Self::H264(H264Encoder::new(config)?)),
            #[cfg(not(windows))]
            VideoCodec::H264Baseline => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "H.264 encoder unavailable on this platform",
            )),
        }
    }
    pub fn encode(
        &mut self,
        bgra: &[u8],
        pts: u64,
        keyframe: bool,
    ) -> io::Result<Option<EncodedVideo>> {
        match self {
            Self::Vp8(codec) => codec.encode(bgra, pts, keyframe).map(Some),
            #[cfg(windows)]
            Self::H264(codec) => codec.encode(bgra, pts, keyframe),
        }
    }
    pub fn close(self) -> io::Result<()> {
        match self {
            Self::Vp8(_) => Ok(()),
            #[cfg(windows)]
            Self::H264(codec) => (*codec.inner).close(),
        }
    }
    pub fn drain_encoded(&mut self) -> io::Result<VideoEncodeStep> {
        match self {
            Self::Vp8(_) => Ok(VideoEncodeStep {
                accepted: false,
                output: None,
            }),
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.drain_encoded(),
        }
    }
    pub fn set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        match self {
            Self::Vp8(codec) => codec.set_bitrate(kbps),
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.set_bitrate(kbps),
        }
    }
    pub fn hardware(&self) -> bool {
        match self {
            Self::Vp8(_) => false,
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.hardware(),
        }
    }
}

pub enum VideoDecoder {
    Vp8(Vp8Decoder),
    #[cfg(windows)]
    H264(H264Decoder),
}
impl VideoDecoder {
    /// Reuse an H.264 transform after discarding buffered references. Other
    /// backends request recreation. Callers must wait for an independent IDR.
    pub fn reset_for_keyframe(&mut self) -> io::Result<bool> {
        match self {
            Self::Vp8(_) => Ok(false),
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.reset_for_keyframe().map(|()| true),
        }
    }
    /// Explicit software owner; never silently upgrades to an unprobed GPU.
    pub fn with_config_software(codec: VideoCodec, config: VideoConfig) -> io::Result<Self> {
        match codec {
            VideoCodec::Vp8 => Ok(Self::Vp8(Vp8Decoder::new(config.width, config.height)?)),
            #[cfg(windows)]
            VideoCodec::H264Baseline => Ok(Self::H264(H264Decoder::with_config_software(config)?)),
            #[cfg(not(windows))]
            VideoCodec::H264Baseline => {
                let _ = config;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "H.264 decoder unavailable on this platform",
                ))
            }
        }
    }
    /// Exact negotiated timing/bitrate target; raw visible geometry may require
    /// the existing CPU-only even padding and presentation crop wrapper.
    pub fn with_config(codec: VideoCodec, config: VideoConfig) -> io::Result<Self> {
        match codec {
            VideoCodec::Vp8 => Ok(Self::Vp8(Vp8Decoder::new(config.width, config.height)?)),
            #[cfg(windows)]
            VideoCodec::H264Baseline => Ok(Self::H264(H264Decoder::with_config(config)?)),
            #[cfg(not(windows))]
            VideoCodec::H264Baseline => {
                let _ = config;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "H.264 decoder unavailable on this platform",
                ))
            }
        }
    }
    pub fn new(codec: VideoCodec, width: u32, height: u32) -> io::Result<Self> {
        match codec {
            VideoCodec::Vp8 => Ok(Self::Vp8(Vp8Decoder::new(width, height)?)),
            #[cfg(windows)]
            VideoCodec::H264Baseline => Ok(Self::H264(H264Decoder::new(width, height)?)),
            #[cfg(not(windows))]
            VideoCodec::H264Baseline => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "H.264 decoder unavailable on this platform",
            )),
        }
    }
    pub fn decode(&mut self, packet: &[u8], pts: u64) -> io::Result<Option<(Vec<u8>, u64)>> {
        match self {
            Self::Vp8(codec) => codec.decode(packet).map(|pixels| Some((pixels, pts))),
            #[cfg(windows)]
            Self::H264(codec) => codec.decode(packet, pts),
        }
    }
    pub fn hardware(&self) -> bool {
        match self {
            Self::Vp8(_) => false,
            #[cfg(windows)]
            Self::H264(codec) => codec.inner.hardware(),
        }
    }
}

// 4:2:0 has even chroma geometry. The authenticated envelope keeps the exact
// approved desktop dimensions; at most one edge pixel is replicated for the
// coded surface, then removed before display. Input coordinates never change.
#[cfg(windows)]
pub struct H264Encoder {
    inner: Box<crate::MfH264Encoder>,
    width: u32,
    height: u32,
}
#[cfg(windows)]
pub(crate) fn coded_size(width: u32, height: u32) -> io::Result<(u32, u32)> {
    if width == 0
        || height == 0
        || width > 8192
        || height > 8192
        || u64::from(width + width % 2) * u64::from(height + height % 2) * 4 > 64 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid visible H.264 geometry",
        ));
    }
    Ok((width + width % 2, height + height % 2))
}
#[cfg(windows)]
impl H264Encoder {
    fn new(config: VideoConfig) -> io::Result<Self> {
        Self::with_limits(config, None, true)
    }
    fn with_limits(
        mut config: VideoConfig,
        limits: Option<H264EncodingLimits>,
        hardware_first: bool,
    ) -> io::Result<Self> {
        let (width, height) = (config.width, config.height);
        (config.width, config.height) = coded_size(width, height)?;
        let inner = if hardware_first {
            crate::MfH264Encoder::with_limits(config, true, limits)
                .or_else(|_| crate::MfH264Encoder::with_limits(config, false, limits))?
        } else {
            crate::MfH264Encoder::with_limits(config, false, limits)?
        };
        Ok(Self {
            inner: Box::new(inner),
            width,
            height,
        })
    }
    fn encode(
        &mut self,
        bgra: &[u8],
        pts: u64,
        keyframe: bool,
    ) -> io::Result<Option<EncodedVideo>> {
        Ok(self.encode_step(bgra, pts, keyframe)?.output)
    }
    fn encode_step(
        &mut self,
        bgra: &[u8],
        pts: u64,
        keyframe: bool,
    ) -> io::Result<VideoEncodeStep> {
        if bgra.len() != self.width as usize * self.height as usize * 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid visible BGRA length",
            ));
        }
        let (width, height) = coded_size(self.width, self.height)?;
        if (width, height) == (self.width, self.height) {
            return self.inner.encode_step(bgra, pts, keyframe);
        }
        let mut padded = zeroize::Zeroizing::new(vec![0; width as usize * height as usize * 4]);
        for y in 0..height as usize {
            let source_y = y.min(self.height as usize - 1);
            let source =
                &bgra[source_y * self.width as usize * 4..(source_y + 1) * self.width as usize * 4];
            let row = &mut padded[y * width as usize * 4..(y + 1) * width as usize * 4];
            row[..source.len()].copy_from_slice(source);
            if width != self.width {
                row[source.len()..].copy_from_slice(&source[source.len() - 4..]);
            }
        }
        self.inner.encode_step(&padded, pts, keyframe)
    }
}
#[cfg(windows)]
pub struct H264Decoder {
    inner: Box<crate::MfH264Decoder>,
    width: u32,
    height: u32,
}
#[cfg(windows)]
impl H264Decoder {
    fn with_config_software(config: VideoConfig) -> io::Result<Self> {
        let (width, height) = (config.width, config.height);
        let (coded_width, coded_height) = coded_size(width, height)?;
        let inner = crate::MfH264Decoder::with_config(
            VideoConfig {
                width: coded_width,
                height: coded_height,
                ..config
            },
            false,
        )?;
        if inner.hardware() {
            return Err(io::Error::other(
                "software decoder unexpectedly returned hardware output",
            ));
        }
        Ok(Self {
            inner: Box::new(inner),
            width,
            height,
        })
    }
    fn with_config(config: VideoConfig) -> io::Result<Self> {
        let (width, height) = (config.width, config.height);
        let (coded_width, coded_height) = coded_size(width, height)?;
        let encoded = VideoConfig {
            width: coded_width,
            height: coded_height,
            ..config
        };
        let inner = crate::MfH264Decoder::with_config(encoded, true)
            .or_else(|_| crate::MfH264Decoder::with_config(encoded, false))?;
        Ok(Self {
            inner: Box::new(inner),
            width,
            height,
        })
    }
    fn new(width: u32, height: u32) -> io::Result<Self> {
        let (coded_width, coded_height) = coded_size(width, height)?;
        let inner = crate::MfH264Decoder::new(coded_width, coded_height, true)
            .or_else(|_| crate::MfH264Decoder::new(coded_width, coded_height, false))?;
        Ok(Self {
            inner: Box::new(inner),
            width,
            height,
        })
    }
    fn decode(&mut self, packet: &[u8], pts: u64) -> io::Result<Option<(Vec<u8>, u64)>> {
        let Some((pixels, pts)) = self.inner.decode_frame(packet, pts)? else {
            return Ok(None);
        };
        let (width, height) = coded_size(self.width, self.height)?;
        if (width, height) == (self.width, self.height) {
            return Ok(Some((pixels, pts)));
        }
        let pixels = zeroize::Zeroizing::new(pixels);
        let mut visible = Vec::with_capacity(self.width as usize * self.height as usize * 4);
        for row in pixels
            .chunks_exact(width as usize * 4)
            .take(self.height as usize)
        {
            visible.extend_from_slice(&row[..self.width as usize * 4]);
        }
        Ok(Some((visible, pts)))
    }
}

/// A bounded, owned synthetic encode at the actual target, hardware first.
/// This proves decodable Annex B IDR/profile/level output, not browser hardware
/// decode, capture latency, sustainable frame rate, or zero-copy operation.
pub fn probe_h264_encoder(
    config: VideoConfig,
    limits: Option<H264EncodingLimits>,
) -> io::Result<H264EncoderProbe> {
    #[cfg(windows)]
    {
        use std::time::{Duration, Instant};
        let (width, height) = coded_size(config.width, config.height)?;
        let coded = VideoConfig {
            width,
            height,
            ..config
        };
        if let Some(limits) = limits {
            limits.validate_config(coded)?;
        }
        let mut last_error = io::Error::other("H.264 target probe produced no independent IDR");
        for hardware in [true, false] {
            let attempt = || -> io::Result<H264EncoderProbe> {
                let started = Instant::now();
                let mut encoder = crate::MfH264Encoder::with_limits(coded, hardware, limits)?;
                let pixels =
                    zeroize::Zeroizing::new([32, 160, 64, 255].repeat((width * height) as usize));
                for frame in 0..64 {
                    if started.elapsed() >= Duration::from_millis(1500) {
                        break;
                    }
                    let step = encoder.encode_step(
                        &pixels,
                        frame * 90_000 / u64::from(coded.fps),
                        frame == 0,
                    )?;
                    if let Some(packet) = step.output {
                        let mut independent = crate::H264Validator::new_sdr(width, height)?;
                        let unit = independent.validate(&packet.data)?;
                        if !unit.keyframe {
                            return Err(io::Error::other(
                                "probe did not start with an independent IDR",
                            ));
                        }
                        let sps = unit
                            .sps
                            .ok_or_else(|| io::Error::other("probe IDR lacks SPS"))?;
                        H264EncodingLimits {
                            max_level_idc: sps.level_idc,
                            require_constrained_baseline: false,
                        }
                        .validate_config(coded)?;
                        if let Some(limits) = limits {
                            limits.validate_sps(sps)?;
                        }
                        // A fresh software MFT decodes this IDR by itself. Do
                        // not infer browser GPU decoding from this owned probe.
                        let mut decoder = crate::MfH264Decoder::with_config(coded, false)?;
                        let mut decoded = decoder.decode_frame(&packet.data, packet.pts_90khz)?;
                        for _ in 0..8 {
                            if decoded.is_some() {
                                break;
                            }
                            decoded = decoder.drain_frame()?;
                        }
                        let (pixels, decoded_pts) = decoded.ok_or_else(|| {
                            io::Error::other("independent probe IDR produced no decoded image")
                        })?;
                        if decoded_pts != packet.pts_90khz
                            || pixels.len() != (width * height * 4) as usize
                            || !pixels.chunks_exact(4).step_by(137).all(|pixel| {
                                (i32::from(pixel[1]) - 160).abs() <= 20 && pixel[3] == 255
                            })
                        {
                            return Err(io::Error::other(
                                "independent probe IDR pixels or PTS differ",
                            ));
                        }
                        if hardware && !encoder.hardware() {
                            return Err(io::Error::other(
                                "hardware probe produced no hardware output",
                            ));
                        }
                        return Ok(H264EncoderProbe {
                            config,
                            encoded_config: coded,
                            geometry: independent
                                .sps_geometry()
                                .ok_or_else(|| io::Error::other("probe SPS geometry missing"))?,
                            sps,
                            hardware: encoder.hardware(),
                        });
                    }
                }
                Err(io::Error::other(
                    "bounded H.264 target probe produced no output",
                ))
            };
            match attempt() {
                Ok(probe) => return Ok(probe),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
    #[cfg(not(windows))]
    {
        let _ = (config, limits);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "H.264 target probe requires Windows",
        ))
    }
}

/// Cached real encode/decode of an owned synthetic image. No screen capture or
/// device name is used as a substitute for observed hardware output.
pub fn h264_hardware_available() -> bool {
    #[cfg(windows)]
    {
        static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PROBE.get_or_init(|| {
            let probe = || -> io::Result<bool> {
                let mut encoder = crate::MfH264Encoder::new(
                    VideoConfig {
                        width: 320,
                        height: 240,
                        fps: 60,
                        bitrate_kbps: 2_000,
                    },
                    true,
                )?;
                let mut decoder = crate::MfH264Decoder::new(320, 240, true)?;
                let pixels = [32, 160, 64, 255].repeat(320 * 240);
                for frame in 0..6 {
                    if let Some(packet) = encoder.encode(&pixels, frame * 1500, frame == 0)?
                        && decoder.decode(&packet.data, packet.pts_90khz)?.is_some()
                    {
                        return Ok(encoder.hardware() && decoder.hardware());
                    }
                }
                Ok(false)
            };
            probe().unwrap_or(false)
        })
    }
    #[cfg(not(windows))]
    false
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn target_probe_uses_each_target_and_actual_sps_instead_of_a_small_cached_result()
    -> io::Result<()> {
        let limits = H264EncodingLimits {
            max_level_idc: 31,
            require_constrained_baseline: false,
        };
        for (width, height, fps, bitrate_kbps) in [(1280, 720, 30, 4000), (640, 360, 60, 2000)] {
            let probe = probe_h264_encoder(
                VideoConfig {
                    width,
                    height,
                    fps,
                    bitrate_kbps,
                },
                Some(limits),
            )?;
            assert_eq!(probe.encoded_config.width, width);
            assert_eq!(probe.encoded_config.height, height);
            assert_eq!(probe.geometry.coded_width, width.div_ceil(16) * 16);
            assert_eq!(probe.geometry.coded_height, height.div_ceil(16) * 16);
            let [left, right, top, bottom] = probe.geometry.crop;
            assert_eq!(probe.geometry.coded_width - left - right, width);
            assert_eq!(probe.geometry.coded_height - top - bottom, height);
            assert_eq!(
                (
                    probe.config.width,
                    probe.config.height,
                    probe.config.fps,
                    probe.config.bitrate_kbps
                ),
                (width, height, fps, bitrate_kbps)
            );
            assert_eq!(probe.sps.profile_idc, 66);
            assert!(probe.sps.level_idc <= 31);
            eprintln!(
                "target probe {width}x{height}@{fps} {bitrate_kbps}kbps actual_sps={} hardware={}",
                probe.sps.profile_level_id(),
                probe.hardware
            );
        }
        assert!(
            probe_h264_encoder(
                VideoConfig {
                    width: 1920,
                    height: 1080,
                    fps: 60,
                    bitrate_kbps: 4000
                },
                Some(limits)
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn h264_odd_desktop_dimensions_roundtrip_without_changing_visible_geometry() -> io::Result<()> {
        let config = VideoConfig {
            width: 321,
            height: 241,
            fps: 30,
            bitrate_kbps: 2000,
        };
        let mut encoder = VideoEncoder::new(VideoCodec::H264Baseline, config)?;
        let mut decoder = VideoDecoder::new(VideoCodec::H264Baseline, config.width, config.height)?;
        let pixels = [32, 160, 64, 255].repeat((config.width * config.height) as usize);
        let mut observed = false;
        for frame in 0..12 {
            if let Some(packet) = encoder.encode(&pixels, frame * 3000, frame == 0)?
                && let Some((decoded, _)) = decoder.decode(&packet.data, packet.pts_90khz)?
            {
                assert_eq!(decoded.len(), pixels.len());
                assert!(
                    decoded
                        .chunks_exact(4)
                        .step_by(137)
                        .all(|pixel| (i32::from(pixel[1]) - 160).abs() <= 18 && pixel[3] == 255)
                );
                observed = true;
            }
        }
        assert!(observed);
        Ok(())
    }
}
