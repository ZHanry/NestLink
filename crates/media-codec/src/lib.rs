//! Native media primitives. Run synchronous codec work on a dedicated media
//! worker; these types neither grant permissions nor validate session epochs.
mod h264;
mod opus;
mod quality;
mod video;
mod vp8;
pub use h264::{H264AccessUnit, H264EncodingLimits, H264SpsInfo, H264Validator};
pub use opus::{OpusConfig, OpusDecoder, OpusEncoder};
pub use quality::VideoQuality;
pub use video::{
    H264EncoderProbe, VideoCodec, VideoDecoder, VideoEncodeStep, VideoEncoder,
    h264_hardware_available, probe_h264_encoder,
};
pub use vp8::{EncodedVideo, VideoConfig, Vp8Decoder, Vp8Encoder};
#[cfg(windows)]
mod windows_mf;
#[cfg(windows)]
pub use windows_mf::{MfH264Decoder, MfH264Encoder};
#[cfg(windows)]
mod windows_gpu_presenter;
#[cfg(windows)]
pub use windows_gpu_presenter::{
    GpuDecodeStep, GpuDecodedPicture, GpuH264Presenter, GpuVideoSurface, gpu_qpc,
};
#[cfg(not(windows))]
pub fn gpu_qpc() -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows QPC unavailable",
    ))
}

#[cfg(windows)]
mod windows_hevc;
#[cfg(windows)]
pub use windows_hevc::{
    HevcBackendObservation, HevcProbeDecoder, HevcProbeEncoder, HevcProbePacket,
    HevcSyntheticSource,
};
#[cfg(windows)]
mod hevc_probe;
