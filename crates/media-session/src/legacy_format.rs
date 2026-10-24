//! Internal legacy admission, not a signed capability or format negotiation.
//! Rate/bitrate exist only at the configured sender; never invent them from
//! receiver placeholder VideoConfig values or an external Prepare's geometry.
use nestlink_media_codec::{H264SpsInfo, H264Validator, VideoCodec, VideoConfig};
use nestlink_protocol::media_format::{
    BitDepth, Chroma, Codec, Color, FrameRate, Geometry, VideoFormat,
};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacySurface {
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    pub color: Color,
    pub chroma: Chroma,
    pub bit_depth: BitDepth,
}

/// Private fields prevent a caller from relabelling an HEVC/444/10-bit surface
/// as one of the only two existing legacy production codecs.
pub struct LegacyPrepare {
    surface: LegacySurface,
    h264: Option<H264Validator>,
}
impl LegacyPrepare {
    pub fn new(codec: VideoCodec, width: u32, height: u32) -> io::Result<Self> {
        if width == 0
            || height == 0
            || width > 8192
            || height > 8192
            || u64::from(width) * u64::from(height) * 4 > 64 * 1024 * 1024
        {
            return Err(io::Error::other("invalid legacy prepared surface"));
        }
        let (codec, color, h264) = match codec {
            VideoCodec::Vp8 => (Codec::Vp8, Color::LEGACY_VP8_BT601, None),
            VideoCodec::H264Baseline => (
                Codec::H264,
                Color::SDR_BT709_LIMITED,
                Some(H264Validator::new_sdr(width, height)?),
            ),
        };
        Ok(Self {
            surface: LegacySurface {
                codec,
                width,
                height,
                color,
                chroma: Chroma::Yuv420,
                bit_depth: BitDepth::Eight,
            },
            h264,
        })
    }
    /// CPU VideoEncoder/VideoDecoder preserve visible geometry but replicate
    /// odd edges into an even H264 input surface, then crop decoded BGRA back.
    /// External surfaces must use strict new(), since they have no such wrapper.
    pub fn new_cpu_visible(codec: VideoCodec, width: u32, height: u32) -> io::Result<Self> {
        let (encoded_width, encoded_height) = if codec == VideoCodec::H264Baseline {
            (
                width
                    .checked_add(width % 2)
                    .ok_or_else(|| io::Error::other("visible geometry overflow"))?,
                height
                    .checked_add(height % 2)
                    .ok_or_else(|| io::Error::other("visible geometry overflow"))?,
            )
        } else {
            (width, height)
        };
        let mut prepare = Self::new(codec, encoded_width, encoded_height)?;
        prepare.surface.width = width;
        prepare.surface.height = height;
        Ok(prepare)
    }
    pub fn from_wire_cpu_visible(codec: i32, width: u32, height: u32) -> io::Result<Self> {
        Self::new_cpu_visible(Self::wire_codec(codec)?, width, height)
    }
    pub fn from_wire(codec: i32, width: u32, height: u32) -> io::Result<Self> {
        Self::new(Self::wire_codec(codec)?, width, height)
    }
    fn wire_codec(codec: i32) -> io::Result<VideoCodec> {
        match nestlink_protocol::NativeVideoCodec::try_from(codec) {
            Ok(nestlink_protocol::NativeVideoCodec::Vp8) => Ok(VideoCodec::Vp8),
            Ok(nestlink_protocol::NativeVideoCodec::H264Baseline) => Ok(VideoCodec::H264Baseline),
            Err(_) => Err(io::Error::other("unsupported legacy codec")),
        }
    }
    pub fn surface(&self) -> LegacySurface {
        self.surface
    }
    pub fn validate(&mut self, payload: &[u8], keyframe: bool) -> io::Result<Option<H264SpsInfo>> {
        let Some(validator) = &mut self.h264 else {
            return Ok(None);
        };
        // Commit parser state only after all admission checks, including the
        // external keyframe flag, succeed. Rejection cannot poison history.
        let mut next = validator.clone();
        let unit = next.validate(payload)?;
        if unit.keyframe != keyframe {
            return Err(io::Error::other(
                "legacy H264 keyframe flag differs from AU",
            ));
        }
        let info = unit
            .sps
            .ok_or_else(|| io::Error::other("validated AU lacks SPS"))?;
        *validator = next;
        Ok(Some(info))
    }
    /// Sender-only: config is the actual capture/encode target. SPS has already
    /// passed geometry, profile, bounded parameter-set and SDR VUI validation.
    pub fn configured(
        &self,
        config: VideoConfig,
        sps: Option<H264SpsInfo>,
    ) -> io::Result<VideoFormat> {
        if sps != self.h264.as_ref().and_then(H264Validator::sps_info) {
            return Err(io::Error::other(
                "format receipt does not match this validator's actual SPS",
            ));
        }
        if config.width != self.surface.width
            || config.height != self.surface.height
            || !(1..=120).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
        {
            return Err(io::Error::other(
                "legacy configuration differs from prepared surface",
            ));
        }
        let rate = FrameRate::new(config.fps, 1).map_err(io::Error::other)?;
        match self.surface.codec {
            Codec::Vp8 => {
                VideoFormat::legacy_vp8(config.width, config.height, rate, config.bitrate_kbps)
            }
            Codec::H264 => {
                let info = sps.ok_or_else(|| io::Error::other("actual H264 SPS required"))?;
                if info.profile_idc != 66
                    || info.constraints & 3 != 0
                    || (info.level_idc == 11 && info.constraints & 0x10 != 0)
                {
                    return Err(io::Error::other("unsupported actual H264 profile or level"));
                }
                let actual = self
                    .h264
                    .as_ref()
                    .and_then(H264Validator::sps_geometry)
                    .ok_or_else(|| io::Error::other("actual H264 SPS geometry required"))?;
                VideoFormat::h264_observed(
                    info.level_idc,
                    info.constraints,
                    Geometry {
                        coded_width: actual.coded_width,
                        coded_height: actual.coded_height,
                        crop: actual.crop,
                    },
                    // Actual SPS display dimensions of the CPU even copy.
                    // Surface/native metadata keep the original visible size.
                    config.width + config.width % 2,
                    config.height + config.height % 2,
                    rate,
                    config.bitrate_kbps,
                )
            }
            Codec::Hevc => {
                return Err(io::Error::other(
                    "HEVC requires a future atomic format negotiation",
                ));
            }
        }
        .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::{Matrix, Primaries, Range, Transfer};
    fn config() -> VideoConfig {
        VideoConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_kbps: 1000,
        }
    }
    fn idr() -> Vec<u8> {
        idr_color(None)
    }
    fn idr_color(color: Option<(bool, [u8; 3])>) -> Vec<u8> {
        idr_geometry(color, 31, 19, 14, None)
    }
    fn idr_geometry(
        color: Option<(bool, [u8; 3])>,
        level_idc: u8,
        width_mbs: u32,
        height_mbs: u32,
        crop: Option<[u32; 4]>,
    ) -> Vec<u8> {
        // Same bounded progressive Baseline fixture shape as media-codec tests.
        let mut bits = format!("0100001011000000{level_idc:08b}");
        for value in [0u32, 0, 2, 1] {
            ue(&mut bits, value);
        }
        bits.push('0');
        ue(&mut bits, width_mbs);
        ue(&mut bits, height_mbs);
        bits.push_str("11"); // frame-only/direct
        if let Some(crop) = crop {
            bits.push('1');
            for value in crop {
                ue(&mut bits, value);
            }
        } else {
            bits.push('0');
        }
        if let Some((full, values)) = color {
            bits.push_str("1001"); // VUI; no aspect/overscan, video signal present
            bits.push_str("101"); // unspecified video_format
            bits.push(if full { '1' } else { '0' });
            bits.push('1'); // color description present
            for value in values {
                bits.push_str(&format!("{value:08b}"));
            }
            bits.push_str("000000"); // remaining VUI flags absent
        } else {
            bits.push('0');
        }
        bits.push('1'); // RBSP stop
        while !bits.len().is_multiple_of(8) {
            bits.push('0');
        }
        let mut out = vec![0, 0, 0, 1, 0x67];
        for part in bits.as_bytes().chunks(8) {
            let byte = part.iter().fold(0, |v, b| v * 2 + (b - b'0'));
            if out.ends_with(&[0, 0]) && byte <= 3 {
                out.push(3);
            }
            out.push(byte);
        }
        out.extend_from_slice(&[0, 0, 1, 0x68, 0xce, 0x38, 0x80, 0, 0, 1, 0x65, 0xb8, 0x40]);
        out
    }
    fn ue(bits: &mut String, value: u32) {
        let value = format!("{:b}", value + 1);
        bits.push_str(&"0".repeat(value.len() - 1));
        bits.push_str(&value);
    }
    #[test]
    fn actual_crop_and_constraints_survive_sender_receipt_and_rejection() -> io::Result<()> {
        let mut prepare = LegacyPrepare::new(VideoCodec::H264Baseline, 1920, 1080)?;
        // 8160 macroblocks exceed Level 3.1's 3600-macroblock limit.
        assert!(
            prepare
                .validate(&idr_geometry(None, 31, 119, 67, Some([0, 0, 0, 4])), true)
                .is_err()
        );
        let encoded = idr_geometry(None, 40, 119, 67, Some([0, 0, 0, 4]));
        // A forged frame flag must not commit the parsed geometry or SPS.
        assert!(prepare.validate(&encoded, false).is_err());
        assert_eq!(
            prepare.h264.as_ref().and_then(H264Validator::sps_geometry),
            None
        );
        let sps = prepare.validate(&encoded, true)?;
        let target = VideoConfig {
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 1000,
        };
        let format = prepare.configured(target, sps)?;
        assert_eq!(format.h264_constraints, 0xc0);
        assert_eq!(
            format.geometry,
            Geometry {
                coded_width: 1920,
                coded_height: 1088,
                crop: [0, 0, 0, 8]
            }
        );
        // Same displayed size with a different crop origin is a different SPS,
        // and cannot silently replace the current parameter-set history.
        assert!(
            prepare
                .validate(&idr_geometry(None, 40, 119, 67, Some([0, 0, 4, 0])), true)
                .is_err()
        );
        assert_eq!(
            prepare.configured(target, sps)?.digest().ok(),
            format.digest().ok()
        );
        Ok(())
    }
    #[test]
    fn odd_visible_cpu_geometry_does_not_widen_external_or_unknown_codec() -> io::Result<()> {
        let prepare = LegacyPrepare::new_cpu_visible(VideoCodec::H264Baseline, 321, 241)?;
        assert_eq!(
            (prepare.surface().width, prepare.surface().height),
            (321, 241)
        );
        assert!(LegacyPrepare::new(VideoCodec::H264Baseline, 321, 241).is_err());
        assert!(LegacyPrepare::from_wire(1, 321, 241).is_err());
        assert!(LegacyPrepare::from_wire_cpu_visible(2, 321, 241).is_err());
        assert!(LegacyPrepare::new_cpu_visible(VideoCodec::H264Baseline, 0, 241).is_err());
        assert!(LegacyPrepare::new_cpu_visible(VideoCodec::H264Baseline, u32::MAX, 241).is_err());
        // An otherwise64MiB visible image whose even copy exceeds budget must
        // fail before allocation just as the actual codec wrapper does.
        assert!(LegacyPrepare::new_cpu_visible(VideoCodec::H264Baseline, 4095, 4097).is_err());
        Ok(())
    }
    #[test]
    fn actual_sps_and_sender_target_are_checked_before_format_receipt() -> io::Result<()> {
        let mut prepare = LegacyPrepare::new(VideoCodec::H264Baseline, 320, 240)?;
        assert!(prepare.configured(config(), None).is_err());
        assert!(
            prepare
                .configured(
                    config(),
                    Some(H264SpsInfo {
                        profile_idc: 66,
                        constraints: 0xc0,
                        level_idc: 31
                    })
                )
                .is_err()
        );
        let sps = prepare.validate(&idr(), true)?;
        let format = prepare.configured(config(), sps)?;
        assert_eq!(format.level, 31);
        assert_eq!(format.color, Color::SDR_BT709_LIMITED);
        assert!(
            LegacyPrepare::new(VideoCodec::H264Baseline, 640, 480)?
                .validate(&idr(), true)
                .is_err()
        );
        assert!(
            prepare
                .configured(
                    VideoConfig {
                        fps: 121,
                        ..config()
                    },
                    sps
                )
                .is_err()
        );
        assert!(
            prepare
                .configured(
                    VideoConfig {
                        width: 640,
                        ..config()
                    },
                    sps
                )
                .is_err()
        );
        assert!(
            prepare
                .configured(
                    config(),
                    Some(H264SpsInfo {
                        profile_idc: 100,
                        ..sps.ok_or_else(|| io::Error::other("SPS missing"))?
                    })
                )
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn wrong_keyframe_flag_cannot_commit_history_and_reset_requires_idr() -> io::Result<()> {
        let mut prepare = LegacyPrepare::new(VideoCodec::H264Baseline, 320, 240)?;
        assert!(prepare.validate(&idr(), false).is_err());
        assert!(prepare.validate(&[0, 0, 1, 0x41, 0xe0], false).is_err());
        prepare.validate(&idr(), true)?;
        prepare.validate(&[0, 0, 1, 0x41, 0xe0], false)?;
        Ok(())
    }
    #[test]
    fn explicit_color_conflicts_reject_before_decode_and_do_not_poison_history() -> io::Result<()> {
        for color in [(true, [1, 1, 1]), (false, [1, 1, 6]), (false, [9, 16, 9])] {
            let mut prepare = LegacyPrepare::new(VideoCodec::H264Baseline, 320, 240)?;
            assert!(prepare.validate(&idr_color(Some(color)), true).is_err());
            prepare.validate(&idr_color(Some((false, [1, 1, 1]))), true)?;
        }
        Ok(())
    }
    #[test]
    fn vp8_metadata_does_not_invent_709_or_high_depth_support() -> io::Result<()> {
        let prepare = LegacyPrepare::new(VideoCodec::Vp8, 320, 240)?;
        let format = prepare.configured(config(), None)?;
        assert_eq!(format.color.matrix, Matrix::Bt601);
        assert_eq!(format.color.range, Range::Limited);
        assert_eq!(format.color.primaries, Primaries::Unspecified);
        assert_eq!(format.color.transfer, Transfer::Unspecified);
        assert!(LegacyPrepare::from_wire(2, 320, 240).is_err());
        assert!(LegacyPrepare::from_wire(-1, 320, 240).is_err());
        Ok(())
    }
}
