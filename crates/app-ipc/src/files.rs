//! Local path selections are dispatched only in the authenticated user daemon.
//! The file command schema is shared with the UI; remote frames never use it.
use nestlink_app_core::{CoreHandle, NativeSessionBinding};
use std::{future::Future, pin::Pin};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol-spec/application-files.rs"
));

pub type FileReplyFuture<'a> = Pin<Box<dyn Future<Output = NativeFileReply> + Send + 'a>>;

pub use nestlink_protocol::file_recovery::{DownloadRecoveryCommand, DownloadRecoveryReply};
pub type RecoveryReplyFuture<'a> = Pin<Box<dyn Future<Output = DownloadRecoveryReply> + Send + 'a>>;

pub trait LocalFileHandler: Send + Sync {
    fn recovery(
        &self,
        _core: CoreHandle,
        _generation: u64,
        _command: DownloadRecoveryCommand,
    ) -> RecoveryReplyFuture<'_> {
        Box::pin(async {
            DownloadRecoveryReply::Refused {
                reason: "Persistent native download recovery is unavailable".into(),
            }
        })
    }

    fn handle(
        &self,
        core: CoreHandle,
        binding: NativeSessionBinding,
        generation: u64,
        command: NativeFileCommand,
    ) -> FileReplyFuture<'_>;
}
