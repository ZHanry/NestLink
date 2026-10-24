//! Authorized native media pipelines. No screen/audio device is opened here.
//! Each sender/receiver owns a dedicated codec thread; software encoding and
//! decoding never execute under the authorization lock or on a Tokio executor.
#![cfg(any(target_os = "windows", target_os = "linux"))]

mod audio;
mod timing;
pub use timing::{
    AudioCaptureTimeline, MAX_PLAYOUT_LATE, PLAYOUT_DELAY, PlayoutDecision, SessionCaptureClock,
    SessionMediaTiming, SessionPlayoutClock,
};
pub mod external;
mod receiver;
mod video;
mod worker;
pub use audio::{AudioReceiver, AudioSender, AudioStats, AudioStream};
pub use receiver::{
    DecodedVideo, ExternalVideoCleanup, VideoLayout, VideoPresentation, VideoReceiver,
    VideoReceiverStats,
};
pub use video::{VideoSender, VideoSenderStats, VideoStream};
pub use worker::{ShutdownReport, WorkerMonitor, WorkerStatus};

#[cfg(test)]
mod tests;

pub use nestlink_media_codec::gpu_qpc as native_video_qpc;
