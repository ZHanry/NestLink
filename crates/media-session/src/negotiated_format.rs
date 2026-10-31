//! Conversion only after exact signed format confirmation; no inferred target.
use nestlink_media_codec::{VideoCodec, VideoConfig};
use nestlink_protocol::{
    media_format::{Codec, VideoFormat},
    native_media_format::FormatSelection,
};
use std::io;
pub(crate) fn configured_target(
    selection: &FormatSelection,
    width: u32,
    height: u32,
    cpu_visible: bool,
) -> io::Result<(VideoCodec, VideoConfig)> {
    selection.validate().map_err(io::Error::other)?;
    if cpu_visible && selection.format.codec == Codec::H264 {
        let config = h264_display_config(selection.format, width, height)?;
        return Ok((VideoCodec::H264Baseline, config));
    }
    format_target(selection.format, width, height, cpu_visible)
}
/// Signed CPU output may downscale the selected source without changing that
/// source's logical input space. No crop, aspect change or upscale is inferred.
pub fn h264_display_config(
    format: VideoFormat,
    width: u32,
    height: u32,
) -> io::Result<VideoConfig> {
    software_h264_execution_limits(format)?;
    let padded_width = width
        .checked_add(width & 1)
        .ok_or_else(|| io::Error::other("display width overflow"))?;
    let padded_height = height
        .checked_add(height & 1)
        .ok_or_else(|| io::Error::other("display height overflow"))?;
    let visible = if (format.width, format.height) == (padded_width, padded_height) {
        (width, height)
    } else if format.width <= width
        && format.height <= height
        && u64::from(format.width) * u64::from(height)
            == u64::from(format.height) * u64::from(width)
    {
        (format.width, format.height)
    } else {
        return Err(io::Error::other(
            "signed output is not an uncropped display downscale",
        ));
    };
    let (_, config) = format_target(format, visible.0, visible.1, true)?;
    Ok(config)
}
pub(crate) fn format_target(
    format: VideoFormat,
    width: u32,
    height: u32,
    cpu_visible: bool,
) -> io::Result<(VideoCodec, VideoConfig)> {
    format.validate().map_err(io::Error::other)?;
    let codec = match format.codec {
        Codec::Vp8 => VideoCodec::Vp8,
        Codec::H264 => VideoCodec::H264Baseline,
        _ => return Err(io::Error::other("negotiated codec has no executable path")),
    };
    let (encoded_width, encoded_height) = if codec == VideoCodec::H264Baseline && cpu_visible {
        (
            width
                .checked_add(width & 1)
                .ok_or_else(|| io::Error::other("visible width overflow"))?,
            height
                .checked_add(height & 1)
                .ok_or_else(|| io::Error::other("visible height overflow"))?,
        )
    } else {
        (width, height)
    };
    if format.width != encoded_width
        || format.height != encoded_height
        || format.frame_rate.denominator != 1
        || !(1..=120).contains(&format.frame_rate.numerator)
        || !(64..=100_000).contains(&format.max_kbps)
    {
        return Err(io::Error::other(
            "confirmed format differs from executable visible geometry or timing budget",
        ));
    }
    Ok((
        codec,
        VideoConfig {
            width,
            height,
            fps: format.frame_rate.numerator,
            bitrate_kbps: format.max_kbps,
        },
    ))
}
pub(crate) fn receipt_matches(
    prepare: &crate::LegacyPrepare,
    config: VideoConfig,
    sps: Option<nestlink_media_codec::H264SpsInfo>,
    expected: VideoFormat,
) -> io::Result<()> {
    if prepare.configured(config, sps)? != expected {
        return Err(io::Error::other(
            "actual access unit format differs from confirmed format",
        ));
    }
    Ok(())
}

/// Configure the executable encoder from the exact signed observed target.
/// MF accepts a level and Baseline profile, not arbitrary SPS constraint bits.
/// The resulting AU must still pass exact configured receipt comparison before
/// proposal or delivery; these limits alone never attest to those output bits.
pub fn software_h264_execution_limits(
    format: VideoFormat,
) -> io::Result<nestlink_media_codec::H264EncodingLimits> {
    format.validate().map_err(io::Error::other)?;
    if format.codec != Codec::H264
        || format.frame_rate.denominator != 1
        || !(1..=120).contains(&format.frame_rate.numerator)
        || !(64..=100_000).contains(&format.max_kbps)
    {
        return Err(io::Error::other(
            "signed target has no software H264 execution",
        ));
    }
    let limits = nestlink_media_codec::H264EncodingLimits {
        max_level_idc: format.level,
        require_constrained_baseline: format.h264_constraints & 0x40 != 0,
    };
    limits.validate_config(VideoConfig {
        width: format.width,
        height: format.height,
        fps: format.frame_rate.numerator,
        bitrate_kbps: format.max_kbps,
    })?;
    Ok(limits)
}

/// Convert a signed exact format into a codec owner target, including visible padding.
pub fn h264_execution_target(
    format: VideoFormat,
    visible: VideoConfig,
) -> io::Result<nestlink_media_codec::H264ExecutionTarget> {
    software_h264_execution_limits(format)?;
    let (kind, actual) = format_target(format, visible.width, visible.height, true)?;
    if kind != VideoCodec::H264Baseline
        || actual.fps != visible.fps
        || actual.bitrate_kbps != visible.bitrate_kbps
    {
        return Err(io::Error::other(
            "execution config differs from exact signed target",
        ));
    }
    nestlink_media_codec::H264ExecutionTarget::new(
        visible,
        nestlink_media_codec::H264SpsInfo {
            profile_idc: 66,
            constraints: format.h264_constraints,
            level_idc: format.level,
        },
        nestlink_media_codec::H264Geometry {
            coded_width: format.geometry.coded_width,
            coded_height: format.geometry.coded_height,
            crop: format.geometry.crop,
        },
        format.digest().map_err(io::Error::other)?,
    )
}
pub fn execution_receipt_matches(
    receipt: &nestlink_media_codec::ExecutionReceipt,
    format: VideoFormat,
) -> io::Result<()> {
    receipt.check_current()?;
    if receipt.target() != h264_execution_target(format, receipt.target().config())? {
        return Err(io::Error::other(
            "live execution differs from signed format",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod execution_limits_tests {
    use super::*;
    use nestlink_protocol::media_format::FrameRate;
    fn target(level: u8, constraints: u8) -> io::Result<VideoFormat> {
        VideoFormat::h264_observed(
            level,
            constraints,
            nestlink_protocol::media_format::Geometry::uncropped(320, 240),
            320,
            240,
            FrameRate {
                numerator: 30,
                denominator: 1,
            },
            1000,
        )
        .map_err(io::Error::other)
    }
    #[test]
    fn execution_uses_each_exact_signed_level_and_constrained_requirement() -> io::Result<()> {
        for level in [31, 40, 42] {
            for constraints in [0, 0x40, 0x80, 0xc0] {
                let limits = software_h264_execution_limits(target(level, constraints)?)?;
                assert_eq!(limits.max_level_idc, level);
                assert_eq!(limits.require_constrained_baseline, constraints & 0x40 != 0);
            }
        }
        Ok(())
    }
    #[test]
    fn invalid_constraints_and_insufficient_or_unknown_levels_are_rejected() -> io::Result<()> {
        let base = target(40, 0xc0)?;
        for value in [
            VideoFormat {
                h264_constraints: 0xc1,
                ..base
            },
            VideoFormat {
                level: 11,
                h264_constraints: 0xd0,
                ..base
            },
            VideoFormat { level: 1, ..base },
            VideoFormat { level: 10, ..base },
            VideoFormat {
                frame_rate: FrameRate {
                    numerator: 60,
                    denominator: 2,
                },
                ..base
            },
        ] {
            assert!(software_h264_execution_limits(value).is_err());
        }
        Ok(())
    }
}
