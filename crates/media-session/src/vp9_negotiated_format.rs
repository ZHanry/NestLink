//! Separate v6 target conversion. A descriptor is never a native probe or receipt.
use nestlink_media_codec::{SoftwareExecutionTarget, VideoConfig, Vp9Rgb444ExecutionTarget};
use nestlink_protocol::media_format::{Codec, VideoFormat, VP9_RGB444_FORMAT_VERSION};
use std::io;

pub fn vp9_rgb444_execution_target(format: VideoFormat) -> io::Result<Vp9Rgb444ExecutionTarget> {
    format.validate().map_err(io::Error::other)?;
    if format.codec != Codec::Vp9 || format.canonical_version() != VP9_RGB444_FORMAT_VERSION {
        return Err(io::Error::other("signed format is not independent VP9 RGB444"));
    }
    Vp9Rgb444ExecutionTarget::new(VideoConfig {
        width: format.width, height: format.height,
        fps: format.frame_rate.numerator, bitrate_kbps: format.max_kbps,
    }, format.digest().map_err(io::Error::other)?)
}
pub fn vp9_rgb444_execution_receipt_matches(receipt: &nestlink_media_codec::ExecutionReceipt, format: VideoFormat) -> io::Result<()> {
    receipt.check_current()?;
    if receipt.target() != SoftwareExecutionTarget::Vp9Rgb444(vp9_rgb444_execution_target(format)?) {
        return Err(io::Error::other("live VP9 RGB444 execution differs from signed format"));
    }
    Ok(())
}
