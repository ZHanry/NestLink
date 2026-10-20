//! Codec choice is made before negotiation. Runtime fallback preserves that
//! codec and reports the backend actually producing frames.
use crate::{EncodedVideo, VideoConfig, Vp8Decoder, Vp8Encoder};
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

pub enum VideoEncoder {
    Vp8(Vp8Encoder),
    #[cfg(windows)]
    H264(H264Encoder),
}
impl VideoEncoder {
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
    inner: crate::MfH264Encoder,
    width: u32,
    height: u32,
}
#[cfg(windows)]
fn coded_size(width: u32, height: u32) -> io::Result<(u32, u32)> {
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
    fn new(mut config: VideoConfig) -> io::Result<Self> {
        let (width, height) = (config.width, config.height);
        (config.width, config.height) = coded_size(width, height)?;
        let inner = crate::MfH264Encoder::new(config, true)
            .or_else(|_| crate::MfH264Encoder::new(config, false))?;
        Ok(Self {
            inner,
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
        if bgra.len() != self.width as usize * self.height as usize * 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid visible BGRA length",
            ));
        }
        let (width, height) = coded_size(self.width, self.height)?;
        if (width, height) == (self.width, self.height) {
            return self.inner.encode(bgra, pts, keyframe);
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
        self.inner.encode(&padded, pts, keyframe)
    }
}
#[cfg(windows)]
pub struct H264Decoder {
    inner: crate::MfH264Decoder,
    width: u32,
    height: u32,
}
#[cfg(windows)]
impl H264Decoder {
    fn new(width: u32, height: u32) -> io::Result<Self> {
        let (coded_width, coded_height) = coded_size(width, height)?;
        let inner = crate::MfH264Decoder::new(coded_width, coded_height, true)
            .or_else(|_| crate::MfH264Decoder::new(coded_width, coded_height, false))?;
        Ok(Self {
            inner,
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
