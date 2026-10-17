// Browser-host file and clipboard approvals are a separate local capability
// surface. Paths appear only in this authenticated per-user IPC contract.
use crate::files::{FileDirection, LocalReadRootSelection, LocalWriteRootSelection};
use nestlink_app_core::BrowserHostDataView;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserHostDataCommand {
    SelectReadRoots {
        roots: Vec<LocalReadRootSelection>,
    },
    SelectWriteRoots {
        roots: Vec<LocalWriteRootSelection>,
    },
    RevokeRoot {
        direction: FileDirection,
        root_id: String,
    },
    SetClipboardDirections {
        read: bool,
        write: bool,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserHostDataReply {
    Applied { data: BrowserHostDataView },
    Refused { reason: String },
}
