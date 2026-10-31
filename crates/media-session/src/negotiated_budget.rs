//! Select only already signed and actually probed configurations. The caller
//! must retire its old owner and obtain a new exact format ACK before delivery.
use nestlink_protocol::media_format::{Codec, FormatSet, VideoFormat};
use std::io;

pub fn select_h264_budget(
    approved: &FormatSet,
    current: VideoFormat,
    fps: u32,
    kbps: u32,
) -> io::Result<VideoFormat> {
    if !approved.contains(&current) || current.codec != Codec::H264 || fps == 0 || kbps == 0 {
        return Err(io::Error::other(
            "budget selection lacks an exact approved current format",
        ));
    }
    let compatible = |format: &&VideoFormat| {
        format.codec == current.codec
            && format.profile == current.profile
            && format.chroma == current.chroma
            && format.bit_depth == current.bit_depth
            && format.color == current.color
            && format.width == current.width
            && format.height == current.height
            && format.geometry == current.geometry
            && format.frame_rate.denominator == 1
    };
    let key = |format: &&VideoFormat| (format.frame_rate.numerator, format.max_kbps);
    let selected = approved
        .formats()
        .iter()
        .filter(compatible)
        .filter(|format| format.frame_rate.numerator <= fps && format.max_kbps <= kbps)
        .max_by_key(key)
        .or_else(|| {
            approved
                .formats()
                .iter()
                .filter(compatible)
                .min_by_key(|format| (format.max_kbps, format.frame_rate.numerator))
        })
        .copied()
        .ok_or_else(|| io::Error::other("no executable approved budget"))?;
    Ok(selected)
}

/// Select across the finite independently probed resolutions within the same
/// approved source. Recovery uses the original source ceiling, never the last
/// reduced output as a new authority or a new maximum.
pub fn select_h264_display_budget(
    approved: &FormatSet,
    current: VideoFormat,
    source: (u32, u32),
    fps: u32,
    kbps: u32,
) -> io::Result<VideoFormat> {
    if !approved.contains(&current) || fps == 0 || kbps == 0 {
        return Err(io::Error::other(
            "display budget lacks signed current format",
        ));
    }
    crate::h264_display_config(current, source.0, source.1)?;
    let compatible = |format: &&VideoFormat| {
        format.codec == current.codec
            && format.profile == current.profile
            && format.chroma == current.chroma
            && format.bit_depth == current.bit_depth
            && format.color == current.color
            && crate::h264_display_config(**format, source.0, source.1).is_ok()
    };
    let key = |format: &&VideoFormat| {
        (
            u64::from(format.width) * u64::from(format.height),
            format.frame_rate.numerator,
            format.max_kbps,
        )
    };
    approved
        .formats()
        .iter()
        .filter(compatible)
        .filter(|format| format.frame_rate.numerator <= fps && format.max_kbps <= kbps)
        .max_by_key(key)
        .or_else(|| approved.formats().iter().filter(compatible).min_by_key(key))
        .copied()
        .ok_or_else(|| io::Error::other("no approved display budget"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::FrameRate;
    fn format(fps: u32, kbps: u32) -> io::Result<VideoFormat> {
        VideoFormat::legacy_h264(
            31,
            320,
            240,
            FrameRate::new(fps, 1).map_err(io::Error::other)?,
            kbps,
        )
        .map_err(io::Error::other)
    }
    #[test]
    fn step_down_and_recovery_never_invent_or_widen_a_signed_format() -> io::Result<()> {
        let high = format(60, 8000)?;
        let mid = format(45, 6000)?;
        let low = format(30, 4000)?;
        let foreign_geometry = VideoFormat { width: 640, ..high };
        let approved = FormatSet::new(vec![high, mid, low]).map_err(io::Error::other)?;
        assert_eq!(select_h264_budget(&approved, high, 60, 6000)?, mid);
        assert_eq!(select_h264_budget(&approved, mid, 60, 4500)?, low);
        assert_eq!(select_h264_budget(&approved, low, 15, 800)?, low);
        assert_eq!(select_h264_budget(&approved, low, 60, 6500)?, mid);
        assert_eq!(select_h264_budget(&approved, mid, 60, 8000)?, high);
        assert!(select_h264_budget(&approved, foreign_geometry, 60, 8000).is_err());
        let other = FormatSet::new(vec![low]).map_err(io::Error::other)?;
        assert!(select_h264_budget(&other, high, 60, 8000).is_err());
        assert!(select_h264_budget(&approved, high, 0, 8000).is_err());
        Ok(())
    }
    #[test]
    fn resolution_budget_retains_source_aspect_and_recovers_only_to_original_signed_ceiling()
    -> io::Result<()> {
        let high = format(60, 8000)?;
        let mid = format(45, 6000)?;
        let low = VideoFormat::legacy_h264(
            31,
            160,
            120,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        let wrong_aspect = VideoFormat::legacy_h264(
            31,
            160,
            160,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            3000,
        )
        .map_err(io::Error::other)?;
        let oversized = VideoFormat::legacy_h264(
            31,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            3000,
        )
        .map_err(io::Error::other)?;
        let approved = FormatSet::new(vec![high, mid, low, wrong_aspect, oversized])
            .map_err(io::Error::other)?;
        assert_eq!(
            select_h264_display_budget(&approved, high, (320, 240), 60, 6000)?,
            mid
        );
        assert_eq!(
            select_h264_display_budget(&approved, mid, (320, 240), 60, 4500)?,
            low
        );
        assert_eq!(
            select_h264_display_budget(&approved, low, (320, 240), 60, 1000)?,
            low
        );
        assert_eq!(
            select_h264_display_budget(&approved, low, (320, 240), 60, 8000)?,
            high
        );
        assert!(select_h264_display_budget(&approved, wrong_aspect, (320, 240), 60, 8000).is_err());
        assert!(select_h264_display_budget(&approved, oversized, (320, 240), 60, 8000).is_err());
        assert!(crate::h264_display_config(low, 0, 0).is_err());
        assert!(crate::h264_display_config(low, u32::MAX, u32::MAX).is_err());
        Ok(())
    }
}
