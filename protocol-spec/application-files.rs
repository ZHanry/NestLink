// Local file selections travel only on authenticated per-user IPC. Remote
// messages contain root IDs and portable relative paths, never these OS paths.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDirection {
    Read,
    Write,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalReadRootSelection {
    pub directory: String,
    pub display_name: String,
    /// Metadata disclosure is an additional explicit local selection.
    pub disclose_directory: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWriteRootSelection {
    pub fresh_directory: String,
    pub display_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeFileCommand {
    SelectHostReadRoots { roots: Vec<LocalReadRootSelection> },
    SelectHostWriteRoots { roots: Vec<LocalWriteRootSelection> },
    RevokeHostRoot { direction: FileDirection, root_id: String },
    ListRoots { direction: FileDirection },
    BrowseBegin { root_id: String, directory: Option<String> },
    BrowseNext { browse_id: String },
    BrowseCancel { browse_id: String },
    Download {
        root_id: String,
        relative_path: String,
        local_directory: String,
        local_name: String,
    },
    Upload {
        root_id: String,
        relative_path: String,
        local_file: String,
    },
    Task { task_id: String },
    Control { task_id: String, action: NativeFileTaskAction },
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFileTaskAction {
    Pause,
    Resume,
    Cancel,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRootView {
    pub root_id: String,
    pub display_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntryView {
    pub relative_path: String,
    pub directory: bool,
    pub size: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTaskView {
    pub task_id: String,
    pub upload: bool,
    pub phase: String,
    pub confirmed_bytes: u64,
    pub total_bytes: Option<u64>,
    /// True only after this task's actual worker has finished.
    pub finished: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeFileReply {
    HostRootsSelected { direction: FileDirection, roots: Vec<FileRootView> },
    HostRootRevoked { direction: FileDirection, root_id: String },
    Roots { direction: FileDirection, roots: Vec<FileRootView> },
    Directory {
        root_id: String,
        directory: String,
        browse_id: String,
        entries: Vec<FileEntryView>,
        complete: bool,
    },
    BrowseCancelled,
    Task { task: FileTaskView },
    ControlAccepted,
    Refused { reason: String },
}
