//! A finite signed HEVC budget choice. Never change codec, source, depth or color.
use nestlink_protocol::media_format::{Codec, FormatSet, VideoFormat};
use std::io;

pub fn select_hevc_budget(
    approved: &FormatSet,
    current: VideoFormat,
    fps: u32,
    kbps: u32,
) -> io::Result<VideoFormat> {
    if !approved.contains(&current) || current.codec != Codec::Hevc || fps == 0 || kbps == 0 {
        return Err(io::Error::other(
            "HEVC budget lacks an exact signed current target",
        ));
    }
    crate::hevc_contract(current)?;
    let compatible = |format: &&VideoFormat| {
        format.codec == current.codec
            && format.profile == current.profile
            && format.chroma == current.chroma
            && format.bit_depth == current.bit_depth
            && format.color == current.color
            && format.width == current.width
            && format.height == current.height
            && format.geometry == current.geometry
            && format.canonical_version() == current.canonical_version()
            && crate::hevc_contract(**format).is_ok()
    };
    let key = |format: &&VideoFormat| (format.frame_rate.numerator, format.max_kbps);
    approved
        .formats()
        .iter()
        .filter(compatible)
        .filter(|format| format.frame_rate.numerator <= fps && format.max_kbps <= kbps)
        .max_by_key(key)
        .or_else(|| approved.formats().iter().filter(compatible).min_by_key(key))
        .copied()
        .ok_or_else(|| io::Error::other("no executable signed HEVC budget"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::FrameRate;
    fn format(fps: u32, kbps: u32) -> io::Result<VideoFormat> {
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 123;
        VideoFormat::hevc_main8_observed(
            ptl,
            1920,
            1080,
            FrameRate::new(fps, 1).map_err(io::Error::other)?,
            kbps,
        )
        .map_err(io::Error::other)
    }
    #[test]
    fn finite_signed_fallback_recovers_to_original_ceiling_without_inventing_a_middle_target()
    -> io::Result<()> {
        let high = format(60, 8000)?;
        let low = format(30, 4000)?;
        let approved = FormatSet::new(vec![high, low]).map_err(io::Error::other)?;
        assert_eq!(select_hevc_budget(&approved, high, 45, 6000)?, low);
        assert_eq!(select_hevc_budget(&approved, low, 60, 8000)?, high);
        assert_eq!(select_hevc_budget(&approved, high, 1, 1)?, low);
        assert!(select_hevc_budget(&approved, format(45, 6000)?, 60, 8000).is_err());
        assert!(select_hevc_budget(&approved, high, 0, 8000).is_err());
        let single = FormatSet::new(vec![high]).map_err(io::Error::other)?;
        assert_eq!(select_hevc_budget(&single, high, 30, 4000)?, high);
        Ok(())
    }
    #[test]
    fn selection_does_not_use_a_signed_different_monitor_or_a_legacy_codec() -> io::Result<()> {
        let high = format(60, 8000)?;
        let mut other = format(30, 4000)?;
        other.width = 1280;
        other.height = 720;
        other.geometry = nestlink_protocol::media_format::Geometry::uncropped(1280, 720);
        let approved = FormatSet::new(vec![high, other]).map_err(io::Error::other)?;
        assert_eq!(select_hevc_budget(&approved, high, 30, 4000)?, high);
        let h264 = VideoFormat::legacy_h264(
            31,
            320,
            240,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            1000,
        )
        .map_err(io::Error::other)?;
        let legacy = FormatSet::new(vec![h264]).map_err(io::Error::other)?;
        assert!(select_hevc_budget(&legacy, h264, 30, 1000).is_err());
        Ok(())
    }
}
