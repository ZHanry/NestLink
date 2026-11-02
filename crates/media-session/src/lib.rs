//! Authorized native media pipelines. No screen/audio device is opened here.
//! Each sender/receiver owns a dedicated codec thread; software encoding and
//! decoding never execute under the authorization lock or on a Tokio executor.
#![cfg(any(target_os = "windows", target_os = "linux"))]

mod audio;
mod decoded_export;
pub use decoded_export::{DecodedExportLedger, DecodedFrameExport};
mod timing;
pub use timing::{
    AudioCaptureTimeline, MAX_PLAYOUT_LATE, PLAYOUT_DELAY, PlayoutDecision, SessionCaptureClock,
    SessionMediaTiming, SessionPlayoutClock,
};
pub mod external;
mod hevc_negotiated_format;
pub use hevc_negotiated_format::hevc_main8_contract;
mod legacy_format;
mod live_execution;
pub use live_execution::{LiveExecutionIdentity, LiveExecutionReceipt, LiveExecutionTarget};
mod negotiated_budget;
mod negotiated_format;
#[cfg(windows)]
pub use hevc_negotiated_format::{
    hevc_execution_receipt_matches, hevc_execution_target, hevc_submission_receipt_matches,
};
pub use negotiated_budget::{select_h264_budget, select_h264_display_budget};
pub use negotiated_format::{
    execution_receipt_matches, h264_display_config, h264_execution_target,
    software_h264_execution_limits,
};
mod receiver;
mod receiver_qos;
pub use legacy_format::{LegacyPrepare, LegacySurface};
pub use receiver_qos::ReceiverReportTracker;
mod video;
mod worker;
pub use audio::{AudioReceiver, AudioSender, AudioStats, AudioStream};
pub use receiver::{
    DecodedVideo, ExternalVideoCleanup, VideoLayout, VideoPresentation, VideoReceiver,
    VideoReceiverStats,
};
#[cfg(windows)]
pub use receiver::SharedVideoConsumer;
pub use video::{ProducerBudgetObservation, VideoSender, VideoSenderStats, VideoStream};
pub use worker::{ShutdownReport, WorkerMonitor, WorkerStatus};

#[cfg(test)]
mod tests;

pub use nestlink_media_codec::gpu_qpc as native_video_qpc;
