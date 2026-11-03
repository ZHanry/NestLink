//! Native media primitives. Run synchronous codec work on a dedicated media
//! worker; these types neither grant permissions nor validate session epochs.
mod h264;
mod opus;
mod quality;
mod scale;
mod video;
mod vp8;
pub use h264::{H264AccessUnit, H264EncodingLimits, H264Geometry, H264SpsInfo, H264Validator};
pub use opus::{OpusConfig, OpusDecoder, OpusEncoder};
pub use quality::{ReceiverCondition, VideoQuality};
pub use scale::scale_bgra;
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
    GpuDecodeStep, GpuDecodedPicture, GpuH264Presenter, GpuHevcPresenter, GpuSharedConsumption,
    GpuSharedPresenter, GpuVideoSurface, HevcGpuDecodeStep, HevcGpuSubmissionReceipt,
    SharedGpuSubmissionReceipt, gpu_qpc,
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
    HevcBackendObservation, HevcProbeDecodeStep, HevcProbeDecoder, HevcProbeEncoder,
    HevcProbePacket, HevcProbePicture, HevcSyntheticSource,
};
mod hevc_backend;
mod hevc_main8;
pub use hevc_backend::{HevcEncoderBackend, HevcEncoderSelection};
#[cfg(windows)]
mod hevc_encoder;
mod hevc_probe;
#[cfg(windows)]
mod windows_amf;
pub use hevc_main8::{HevcContract, HevcMain8Admission, HevcMain8Contract};
#[cfg(windows)]
mod windows_hevc_owner;
#[cfg(windows)]
mod windows_shared_output;
#[cfg(windows)]
pub use nestlink_platform_security::local_stream::VerifiedProcessExportTarget;
#[cfg(windows)]
pub use windows_hevc_owner::{
    HevcDecodedOutput, HevcOwnerOutput, MfHevcHardwareDecoder, MfHevcTextureEncoder,
};
#[cfg(windows)]
pub use windows_shared_output::{
    SharedDecodedFrame, SharedFrameDescriptor, SharedRingDescriptor, TransferredSurfaceRing,
};

#[cfg(windows)]
mod hevc_execution;
#[cfg(windows)]
pub use hevc_execution::{
    HardwareHevcExecution, HevcExecutionIdentity, HevcExecutionOutput, HevcExecutionReceipt,
    HevcExecutionTarget, HevcExecutionTicket, HevcTextureSource,
};

#[cfg(windows)]
mod owner_observation;
#[cfg(windows)]
pub use owner_observation::OwnerObservation;
#[cfg(windows)]
mod controller_probe;
#[cfg(windows)]
pub use controller_probe::{
    ControllerProbeBackend, ControllerProbeFixture, ControllerProbeReceipt,
    build_controller_probe_fixture, probe_controller_cpu, probe_controller_gpu,
};

#[cfg(windows)]
mod cpu_direction_probe;
#[cfg(windows)]
pub use cpu_direction_probe::{CpuDirectionProbe, probe_cpu_decode, probe_cpu_encode};

mod execution;
pub use execution::{
    ExecutionDirection, ExecutionIdentity, ExecutionOutput, ExecutionReceipt, ExecutionTicket,
    H264ExecutionTarget, SoftwareH264Execution,
};
#[cfg(windows)]
mod hevc_direction_probe;
#[cfg(windows)]
pub use hevc_direction_probe::{
    HevcDirectionProbe, probe_hevc_direction, probe_hevc_direction_depth,
    probe_hevc_direction_with_encoder, probe_hevc_hdr10_direction,
};
