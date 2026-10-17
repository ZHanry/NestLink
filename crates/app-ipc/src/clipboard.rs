//! Clipboard IPC exposes direction choices and one-shot outcomes only.
//! Clipboard text never crosses into the desktop UI or JSON control channel.
use nestlink_app_core::{
    CoreHandle, NativeClipboardAction, NativeClipboardBinding, NativeClipboardError,
};

use crate::wire::{NativeClipboardRejection, Reply};

pub fn status(core: &CoreHandle) -> Reply {
    Reply::NativeClipboardStatus {
        status: core.native_clipboard_status(),
    }
}

pub async fn set_directions(
    core: &CoreHandle,
    binding: NativeClipboardBinding,
    read: bool,
    write: bool,
) -> Reply {
    match core
        .set_native_clipboard_directions(&binding, read, write)
        .await
    {
        Ok(status) => Reply::NativeClipboardDirectionsSet { status },
        Err(error) => Reply::NativeClipboardRejected {
            reason: rejection(error),
        },
    }
}

pub async fn action(
    core: &CoreHandle,
    binding: NativeClipboardBinding,
    action: NativeClipboardAction,
) -> Reply {
    match core.native_clipboard_action(&binding, action).await {
        Ok(effect) => Reply::NativeClipboardActionResult { effect },
        Err(error) => Reply::NativeClipboardRejected {
            reason: rejection(error),
        },
    }
}

fn rejection(error: NativeClipboardError) -> NativeClipboardRejection {
    match error {
        NativeClipboardError::StaleBinding => NativeClipboardRejection::StaleBinding,
        NativeClipboardError::Unauthorized => NativeClipboardRejection::Unauthorized,
        NativeClipboardError::LocalConsentRequired => {
            NativeClipboardRejection::LocalConsentRequired
        }
        NativeClipboardError::ReestablishSession => NativeClipboardRejection::ReestablishSession,
        NativeClipboardError::PlatformUnavailable(_) => {
            NativeClipboardRejection::PlatformUnavailable
        }
        NativeClipboardError::Transport => NativeClipboardRejection::Transport,
        NativeClipboardError::Stopped => NativeClipboardRejection::Stopped,
        NativeClipboardError::Cleanup => NativeClipboardRejection::Cleanup,
    }
}
