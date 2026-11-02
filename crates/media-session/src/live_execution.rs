//! Explicit live codec ownership. Variants preserve the original sealed owner;
//! a diagnostic announcement, requested target or IPC UUID cannot create one.
use nestlink_media_codec::{ExecutionDirection, ExecutionReceipt, VideoConfig};
use nestlink_protocol::media_format::VideoFormat;
use std::io;

#[derive(Clone, Debug)]
pub enum LiveExecutionReceipt {
    H264(ExecutionReceipt),
    #[cfg(windows)]
    Hevc(nestlink_media_codec::HevcExecutionReceipt),
}
impl From<ExecutionReceipt> for LiveExecutionReceipt {
    fn from(value: ExecutionReceipt) -> Self {
        Self::H264(value)
    }
}
#[cfg(windows)]
impl From<nestlink_media_codec::HevcExecutionReceipt> for LiveExecutionReceipt {
    fn from(value: nestlink_media_codec::HevcExecutionReceipt) -> Self {
        Self::Hevc(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveExecutionIdentity {
    H264(nestlink_media_codec::ExecutionIdentity),
    #[cfg(windows)]
    Hevc(nestlink_media_codec::HevcExecutionIdentity),
}
impl LiveExecutionIdentity {
    pub fn direction(self) -> ExecutionDirection {
        match self {
            Self::H264(value) => value.direction(),
            #[cfg(windows)]
            Self::Hevc(value) => value.direction(),
        }
    }
    pub fn generation(self) -> u64 {
        match self {
            Self::H264(value) => value.generation(),
            #[cfg(windows)]
            Self::Hevc(value) => value.generation(),
        }
    }
    pub fn resource_id(self) -> [u8; 16] {
        match self {
            Self::H264(value) => value.resource_id(),
            #[cfg(windows)]
            Self::Hevc(value) => value.resource_id(),
        }
    }
    pub fn adapter_luid(self) -> Option<u64> {
        match self {
            Self::H264(value) => value.adapter_luid(),
            #[cfg(windows)]
            Self::Hevc(value) => Some(value.adapter_luid()),
        }
    }
    pub fn driver_version(self) -> Option<u64> {
        match self {
            Self::H264(value) => value.driver_version(),
            #[cfg(windows)]
            Self::Hevc(value) => Some(value.driver_version()),
        }
    }
    pub fn backend(self) -> &'static str {
        match self {
            Self::H264(value) => value.backend(),
            #[cfg(windows)]
            Self::Hevc(value) => value.backend(),
        }
    }
}
#[derive(Clone, Copy)]
pub struct LiveExecutionTarget {
    config: VideoConfig,
    digest: [u8; 32],
}
impl LiveExecutionTarget {
    pub fn config(self) -> VideoConfig {
        self.config
    }
    pub fn format_digest(self) -> [u8; 32] {
        self.digest
    }
}
impl LiveExecutionReceipt {
    pub fn identity(&self) -> io::Result<LiveExecutionIdentity> {
        match self {
            Self::H264(value) => value.identity().map(LiveExecutionIdentity::H264),
            #[cfg(windows)]
            Self::Hevc(value) => value.identity().map(LiveExecutionIdentity::Hevc),
        }
    }
    pub fn target(&self) -> LiveExecutionTarget {
        match self {
            Self::H264(value) => LiveExecutionTarget {
                config: value.target().config(),
                digest: value.target().format_digest(),
            },
            #[cfg(windows)]
            Self::Hevc(value) => LiveExecutionTarget {
                config: value.target().contract().config(),
                digest: value.target().format_digest(),
            },
        }
    }
    pub fn check_current(&self) -> io::Result<()> {
        match self {
            Self::H264(value) => value.check_current(),
            #[cfg(windows)]
            Self::Hevc(value) => value.check_current(),
        }
    }
    pub fn with_current<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        match self {
            Self::H264(value) => value.with_current(operation),
            #[cfg(windows)]
            Self::Hevc(value) => value.with_current(operation),
        }
    }
    pub fn fence(&self) {
        match self {
            Self::H264(value) => value.fence(),
            #[cfg(windows)]
            Self::Hevc(value) => value.fence(),
        }
    }
    pub fn retired_joined(&self) -> bool {
        match self {
            Self::H264(value) => value.retired_joined(),
            #[cfg(windows)]
            Self::Hevc(value) => value.retired_joined(),
        }
    }
    pub fn is_encoded_output(&self) -> bool {
        match self {
            Self::H264(value) => value.is_encoded_output(),
            #[cfg(windows)]
            Self::Hevc(value) => value.is_encoded_output(),
        }
    }
    pub fn check_encoded(&self, pts: u64, keyframe: bool, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::H264(value) => value.check_encoded(pts, keyframe, bytes),
            #[cfg(windows)]
            Self::Hevc(value) => {
                if !keyframe {
                    return Err(io::Error::other(
                        "HEVC Main8 sealed output requires an actual IDR",
                    ));
                }
                value.check_encoded(pts, bytes)
            }
        }
    }
    pub fn check_decoded(&self, pts: u64, pixels: &[u8]) -> io::Result<()> {
        match self {
            Self::H264(value) => value.check_decoded(pts, pixels),
            #[cfg(windows)]
            Self::Hevc(value) => value.check_decoded(pts, pixels),
        }
    }
    pub fn matches_format(&self, format: VideoFormat) -> io::Result<()> {
        match self {
            Self::H264(value) => crate::execution_receipt_matches(value, format),
            #[cfg(windows)]
            Self::Hevc(value) => crate::hevc_execution_receipt_matches(value, format),
        }
    }
}
