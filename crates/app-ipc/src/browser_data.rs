//! Browser-host local file and clipboard approvals. The shared contract
//! includes OS paths only on the authenticated per-user local IPC channel.
use nestlink_app_core::{BrowserHostBinding, CoreHandle};
use std::{future::Future, pin::Pin};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol-spec/application-browser-data.rs"
));

pub type BrowserHostDataReplyFuture<'a> =
    Pin<Box<dyn Future<Output = BrowserHostDataReply> + Send + 'a>>;

pub trait LocalBrowserHostDataHandler: Send + Sync {
    fn handle(
        &self,
        core: CoreHandle,
        binding: BrowserHostBinding,
        generation: u64,
        command: BrowserHostDataCommand,
    ) -> BrowserHostDataReplyFuture<'_>;
}
