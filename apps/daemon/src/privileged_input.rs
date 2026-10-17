//! Daemon-owned optional input broker. Start requires an explicit local action.
use nestlink_app_core::CoreHandle;
#[cfg(windows)]
use nestlink_app_ipc::privileged_input::PrivilegedInputResult;
use nestlink_app_ipc::privileged_input::{
    LocalPrivilegedInputHandler, PrivilegedInputAction, PrivilegedInputError,
    PrivilegedInputFuture, PrivilegedInputState, PrivilegedInputStatus,
};
use std::{io, sync::Arc};
use tokio::{sync::watch, task::JoinHandle};

pub struct PrivilegedInputTask {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
    failure: Option<io::ErrorKind>,
}
impl PrivilegedInputTask {
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }
    pub async fn join(&mut self) -> io::Result<()> {
        let result = match self.task.as_mut() {
            Some(task) => task
                .await
                .map_err(io::Error::other)
                .and_then(|result| result),
            None => return self.failure.map_or(Ok(()), |kind| Err(kind.into())),
        };
        self.task.take();
        if let Err(error) = &result {
            self.failure = Some(error.kind());
        }
        result
    }
}

#[cfg(windows)]
mod platform;
#[cfg(windows)]
pub use platform::{PrivilegedInput, RenewingBrokerInput};

#[cfg(not(windows))]
pub struct PrivilegedInput;
#[cfg(not(windows))]
impl PrivilegedInput {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
    pub fn spawn_monitor(self: &Arc<Self>, _core: CoreHandle) -> PrivilegedInputTask {
        let (stop, mut receiver) = watch::channel(false);
        PrivilegedInputTask {
            stop,
            failure: None,
            task: Some(tokio::spawn(async move {
                while !*receiver.borrow() && receiver.changed().await.is_ok() {}
                Ok(())
            })),
        }
    }
}
#[cfg(not(windows))]
impl LocalPrivilegedInputHandler for PrivilegedInput {
    fn handle(
        &self,
        _core: CoreHandle,
        _generation: u64,
        action: PrivilegedInputAction,
    ) -> PrivilegedInputFuture<'_> {
        Box::pin(async move {
            match action {
                PrivilegedInputAction::Status | PrivilegedInputAction::Stop => {
                    Ok(PrivilegedInputStatus {
                        state: PrivilegedInputState::Unsupported,
                        cleanup_failed: false,
                    })
                }
                PrivilegedInputAction::Start => Err(PrivilegedInputError::Unsupported),
            }
        })
    }
}
