//! Native media primitives. Run synchronous codec work on a dedicated media
//! worker; these types neither grant permissions nor validate session epochs.
mod h264;
mod opus;
mod quality;
mod video;
mod vp8;
pub use h264::{H264AccessUnit, H264Validator};
pub use opus::{OpusConfig, OpusDecoder, OpusEncoder};
pub use quality::VideoQuality;
pub use video::{VideoCodec, VideoDecoder, VideoEncoder, h264_hardware_available};
pub use vp8::{EncodedVideo, VideoConfig, Vp8Decoder, Vp8Encoder};
#[cfg(windows)]
mod windows_mf;
#[cfg(windows)]
pub use windows_mf::{MfH264Decoder, MfH264Encoder};
