//! v6 all-intra ordinary frames have ordinary frame pacing. The existing
//! recovery-request interval still applies to cached recovery and other codecs.
use nestlink_media_session::LiveExecutionReceipt;
use nestlink_protocol::media_format::VideoFormat;

pub(super) fn ordinary_rgb444_output(
    format: Option<VideoFormat>, execution: Option<&LiveExecutionReceipt>,
    pts: u64, keyframe: bool, repeated_source: bool, bytes: &[u8],
) -> bool {
    if repeated_source || !keyframe { return false; }
    let (Some(format), Some(LiveExecutionReceipt::Vp9Rgb444(receipt))) = (format, execution) else { return false; };
    nestlink_media_session::vp9_rgb444_execution_receipt_matches(receipt, format).is_ok()
        && receipt.check_encoded(pts, true, bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_media_codec::VideoEncoder;
    use nestlink_protocol::media_format::FrameRate;
    use std::io;

    #[test]
    #[ignore = "requires actual fixed libvpx owner; run explicitly in the GitHub-hosted native media experiment"]
    fn ordinary_rgb444_pacing_requires_exact_live_sealed_output() -> io::Result<()> {
        let format = VideoFormat::vp9_rgb444(64, 32, FrameRate::new(60, 1).map_err(io::Error::other)?, 10_000).map_err(io::Error::other)?;
        let target = nestlink_media_session::vp9_rgb444_execution_target(format)?;
        let mut encoder = VideoEncoder::with_vp9_rgb444_execution_target(target)?;
        let registration: LiveExecutionReceipt = encoder.current_execution()?.ok_or_else(|| io::Error::other("registration missing"))?.into();
        let packet = encoder.encode_step(&[16, 32, 240, 255].repeat(64 * 32), 1500, true)?.output.ok_or_else(|| io::Error::other("actual VP9 output missing"))?;
        let sealed: LiveExecutionReceipt = encoder.execution_receipt().ok_or_else(|| io::Error::other("sealed VP9 output missing"))?.into();
        assert!(ordinary_rgb444_output(Some(format), Some(&sealed), 1500, true, false, &packet.data));
        assert!(!ordinary_rgb444_output(Some(format), Some(&sealed), 1500, true, true, &packet.data));
        assert!(!ordinary_rgb444_output(Some(format), Some(&registration), 1500, true, false, &packet.data));
        assert!(!ordinary_rgb444_output(Some(format), None, 1500, true, false, &packet.data));
        assert!(!ordinary_rgb444_output(None, Some(&sealed), 1500, true, false, &packet.data));
        assert!(!ordinary_rgb444_output(Some(format), Some(&sealed), 1501, true, false, &packet.data));
        assert!(!ordinary_rgb444_output(Some(format), Some(&sealed), 1500, false, false, &packet.data));
        let mut changed = packet.data.clone();
        changed[0] ^= 1;
        assert!(!ordinary_rgb444_output(Some(format), Some(&sealed), 1500, true, false, &changed));
        let h264 = VideoFormat::legacy_h264(31, 64, 32, FrameRate::new(60, 1).map_err(io::Error::other)?, 10_000).map_err(io::Error::other)?;
        assert!(!ordinary_rgb444_output(Some(h264), Some(&sealed), 1500, true, false, &packet.data));
        let other = VideoFormat::vp9_rgb444(64, 32, FrameRate::new(30, 1).map_err(io::Error::other)?, 10_000).map_err(io::Error::other)?;
        assert!(!ordinary_rgb444_output(Some(other), Some(&sealed), 1500, true, false, &packet.data));
        encoder.close()?;
        assert!(!ordinary_rgb444_output(Some(format), Some(&sealed), 1500, true, false, &packet.data));
        Ok(())
    }
}
