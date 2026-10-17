//! Android SAF file owners.
//!
//! Picker URIs stay on the Kotlin side. A selected document crosses JNI only
//! as a detached file descriptor; all content reads and writes then happen on
//! the existing Rust-owned upload/download workers.

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use nestlink_app_core::{
    CoreHandle, NativeFileTask, NativeFileTaskAction, NativeFileTaskControl, NativeFileTaskKind,
    NativeFileTaskMonitor, NativeFileTaskPhase, NativeFileTaskStatus, NativeSessionBinding,
};
use nestlink_platform_files::download::{LocalDownloadConsent, LocalDownloadSelection};
use nestlink_protocol::{DirectoryEntryKind, FileRoot};
use nestlink_protocol::{FILE_SIZE_BYTES, FileReadManifest};
use nestlink_remote::{
    files::{FileDestination, FileDestinationFactory, FileReadConsent, FileReadSource},
    upload::FileUploadSourceFactory,
};
use nestlink_sdk::{files::NativeDownloadRequest, upload::NativeUploadRequest};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::SystemTime,
};

const MAX_ANDROID_DOWNLOAD_ARTIFACTS: usize = 8;
const MAX_ANDROID_DOWNLOAD_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ANDROID_DOWNLOAD_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ANDROID_EXPORT_HISTORY: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AndroidFileIdentity {
    pub binding: NativeSessionBinding,
    pub core_generation: u64,
}

pub(crate) trait AndroidExportIdentity: Send + Sync {
    fn current(&self, core: &CoreHandle) -> bool;
}
impl AndroidExportIdentity for AndroidFileIdentity {
    fn current(&self, core: &CoreHandle) -> bool {
        AndroidFileIdentity::current(self, core)
    }
}

impl AndroidFileIdentity {
    pub(crate) fn current(&self, core: &CoreHandle) -> bool {
        core.snapshot().generation == self.core_generation
            && core.native_file_session_binding().as_ref() == Some(&self.binding)
    }
}

#[derive(Default)]
pub(crate) struct AndroidFileTransfers {
    download_area: Option<AndroidPrivateDownloadArea>,
    download_consent: HashMap<String, Arc<LocalDownloadConsent>>,
    download_artifacts: HashMap<String, DownloadArtifact>,
    tasks: HashMap<String, AndroidOwnedTask>,
    upload_consent: HashMap<String, AndroidUploadConsent>,
    exports: HashMap<String, AndroidExportTask>,
    export_order: VecDeque<String>,
    closing: bool,
}

struct AndroidPrivateDownloadArea {
    path: PathBuf,
    directory: Dir,
}

struct DownloadArtifact {
    identity: AndroidFileIdentity,
    area_name: String,
    file_name: String,
    reserved_bytes: u64,
    verified_size: Option<u64>,
}

struct AndroidOwnedTask {
    identity: AndroidFileIdentity,
    monitor: NativeFileTaskMonitor,
    control: NativeFileTaskControl,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AndroidExportStatus {
    pub export_id: String,
    pub phase: String,
    pub owner_stopped: bool,
    pub copied_bytes: u64,
    pub total_bytes: u64,
    pub error: Option<String>,
    pub private_cleanup_complete: bool,
    pub private_cleanup_error: Option<String>,
    pub destination_cleanup_complete: bool,
    pub destination_cleanup_error: Option<String>,
}

struct AndroidExportTask {
    task_id: String,
    identity: AndroidFileIdentity,
    status: Arc<Mutex<AndroidExportStatus>>,
    cancelled: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl AndroidFileTransfers {
    pub(crate) fn set_download_area(&mut self, area: PathBuf) -> Result<(), String> {
        if !area.is_absolute() || area.as_os_str().is_empty() {
            return Err("Android private download area is invalid".to_owned());
        }
        if let Some(current) = self.download_area.as_ref() {
            if current.path == area {
                return Ok(());
            }
            if !self.download_artifacts.is_empty() || !self.tasks.is_empty() {
                return Err(
                    "Android private download area cannot change while artifacts are retained"
                        .to_owned(),
                );
            }
        }
        nestlink_platform_security::private_directory(&area).map_err(|_| {
            "Android private download area is not a protected app directory".to_owned()
        })?;
        let directory = Dir::open_ambient_dir(&area, cap_std::ambient_authority())
            .map_err(|_| "Android private download area cannot be opened".to_owned())?;
        for entry in directory
            .entries()
            .map_err(|_| "Android private download area cannot be enumerated".to_owned())?
        {
            let entry = entry.map_err(|_| {
                "Android private download area contains an unreadable entry".to_owned()
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(suffix) = name.strip_prefix("download-") else {
                continue;
            };
            let Ok(id) = uuid::Uuid::parse_str(suffix) else {
                continue;
            };
            if id.hyphenated().to_string() != suffix {
                continue;
            }
            directory.remove_dir_all(name).map_err(|_| {
                "stale Android private download artifact could not be cleaned".to_owned()
            })?;
        }
        self.download_area = Some(AndroidPrivateDownloadArea {
            path: area,
            directory,
        });
        Ok(())
    }

    pub(crate) fn upload(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        root_id: &str,
        relative_path: &str,
        display_name: &str,
        source: File,
    ) -> Result<NativeFileTask, String> {
        self.check(core, identity)?;
        self.ensure_accepting(identity)?;
        let access = core
            .native_file_access(&identity.binding, identity.core_generation)
            .map_err(|error| error.to_string())?;
        if !access.write {
            return Err("the current session has no file-write permission".to_owned());
        }
        if display_name.is_empty()
            || display_name.len() > 255
            || display_name.contains(['/', '\\', '\0'])
            || display_name.trim() != display_name
        {
            return Err("the selected document name is not portable".to_owned());
        }
        let request = NativeUploadRequest::new(root_id, relative_path)
            .map_err(|_| "invalid remote upload destination".to_owned())?;
        let (selection, owner) = AndroidUploadSelection::new(source, FILE_SIZE_BYTES);
        let task = core
            .native_upload(
                &identity.binding,
                identity.core_generation,
                request,
                selection,
            )
            .map_err(|error| error.to_string())?;
        self.upload_consent.insert(task.task_id().to_owned(), owner);
        self.tasks.insert(
            task.task_id().to_owned(),
            AndroidOwnedTask {
                identity: identity.clone(),
                monitor: task.monitor(),
                control: task.control(),
            },
        );
        Ok(task)
    }

    pub(crate) fn download(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        root_id: &str,
        relative_path: &str,
    ) -> Result<NativeFileTask, String> {
        self.check(core, identity)?;
        self.ensure_accepting(identity)?;
        let access = core
            .native_file_access(&identity.binding, identity.core_generation)
            .map_err(|error| error.to_string())?;
        if !access.read {
            return Err("the current session has no file-read permission".to_owned());
        }
        let area = self
            .download_area
            .as_ref()
            .ok_or_else(|| "Android private download area is unavailable".to_owned())?;
        if self.download_artifacts.len() >= MAX_ANDROID_DOWNLOAD_ARTIFACTS {
            return Err("Android private download artifact limit is full; export or discard a download first".to_owned());
        }
        let reservation = self.available_download_reservation()?;
        let request = NativeDownloadRequest::new(root_id, relative_path)
            .map_err(|_| "invalid remote download selection".to_owned())?;
        // Do not derive an ambient destination from the peer-provided name.
        // The user exports this verified private artifact through SAF later.
        let area_name = format!("download-{}", uuid::Uuid::new_v4());
        let file_name = "verified.bin".to_owned();
        // LocalDownload::prepare atomically creates a fresh private directory.
        // The configured app-private parent exists; each task gets a new child.
        let task_area = area.path.join(&area_name);
        let (selection, owner) = LocalDownloadSelection::new(&task_area, &file_name, reservation)
            .map_err(|error| {
            format!(
                "Android private download storage is unavailable: {:?}",
                error.kind()
            )
        })?;
        let owner = Arc::new(owner);
        let task = core
            .native_download(
                &identity.binding,
                identity.core_generation,
                request,
                OwnedDownloadSelection {
                    selection,
                    _owner: Arc::clone(&owner),
                },
            )
            .map_err(|error| error.to_string())?;
        self.download_consent
            .insert(task.task_id().to_owned(), owner);
        self.tasks.insert(
            task.task_id().to_owned(),
            AndroidOwnedTask {
                identity: identity.clone(),
                monitor: task.monitor(),
                control: task.control(),
            },
        );
        self.download_artifacts.insert(
            task.task_id().to_owned(),
            DownloadArtifact {
                identity: identity.clone(),
                area_name,
                file_name,
                reserved_bytes: reservation,
                verified_size: None,
            },
        );
        Ok(task)
    }

    pub(crate) fn check(
        &self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
    ) -> Result<(), String> {
        if identity.core_generation == 0 || !identity.current(core) {
            return Err("the Android file action belongs to a replaced session".to_owned());
        }
        Ok(())
    }

    pub(crate) fn task_status(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        task_id: &str,
    ) -> Result<NativeFileTaskStatus, String> {
        self.check(core, identity)?;
        let status = match self.tasks.get(task_id) {
            Some(task) if task.identity == *identity => task.monitor.status(),
            Some(_) => return Err("the Android file task belongs to a replaced session".to_owned()),
            None => core
                .native_file_task_status(&identity.binding, identity.core_generation, task_id)
                .map_err(|error| error.to_string())?,
        };
        if status.finished {
            self.download_consent.remove(task_id);
            self.upload_consent.remove(task_id);
            if status.kind == NativeFileTaskKind::Download
                && status.phase == NativeFileTaskPhase::Completed
                && status
                    .download
                    .as_ref()
                    .is_some_and(|download| download.source_verified)
                && let Some(artifact) = self.download_artifacts.get_mut(task_id)
            {
                artifact.verified_size = status
                    .download
                    .as_ref()
                    .and_then(|download| download.manifest.as_ref())
                    .map(|manifest| manifest.size);
                if let Some(size) = artifact.verified_size {
                    artifact.reserved_bytes = size;
                }
            }
        }
        Ok(status)
    }

    pub(crate) fn task_control(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        task_id: &str,
        action: NativeFileTaskAction,
    ) -> Result<(), String> {
        self.check(core, identity)?;
        if action == NativeFileTaskAction::Cancel {
            if let Some(owner) = self.download_consent.get(task_id) {
                owner.revoke();
            }
            if let Some(owner) = self.upload_consent.get(task_id) {
                owner.revoke();
            }
        }
        if let Some(task) = self.tasks.get(task_id) {
            if task.identity != *identity {
                return Err("the Android file task belongs to a replaced session".to_owned());
            }
            match action {
                NativeFileTaskAction::Pause => task
                    .control
                    .pause(&identity.binding, identity.core_generation),
                NativeFileTaskAction::Resume => task
                    .control
                    .resume(&identity.binding, identity.core_generation),
                NativeFileTaskAction::Cancel => task
                    .control
                    .cancel(&identity.binding, identity.core_generation),
            }
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        core.native_file_task_control(&identity.binding, identity.core_generation, task_id, action)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn discard_download(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        task_id: &str,
    ) -> Result<(), String> {
        self.check(core, identity)?;
        if self
            .download_artifacts
            .get(task_id)
            .is_some_and(|artifact| artifact.identity != *identity)
        {
            return Err("the selected download belongs to a replaced session".to_owned());
        }
        let status = self
            .tasks
            .get(task_id)
            .filter(|task| task.identity == *identity)
            .map(|task| task.monitor.status())
            .or_else(|| {
                core.native_file_task_status(&identity.binding, identity.core_generation, task_id)
                    .ok()
            })
            .ok_or_else(|| "the selected Android download task is unavailable".to_owned())?;
        if status.kind != NativeFileTaskKind::Download || !download_owner_stopped(&status) {
            return Err(
                "wait for the Android download worker to stop before discarding it".to_owned(),
            );
        }
        if self.exports.values().any(|export| {
            export.task_id == task_id
                && (export.thread.is_some()
                    || export
                        .status
                        .lock()
                        .map(|status| status.phase == "running")
                        .unwrap_or(true))
        }) {
            return Err(
                "wait for the Android SAF export worker to stop before discarding the download"
                    .to_owned(),
            );
        }
        if self.download_artifacts.contains_key(task_id) {
            self.remove_artifact_area(task_id)?;
        }
        self.download_artifacts.remove(task_id);
        self.download_consent.remove(task_id);
        self.exports.retain(|_, export| export.task_id != task_id);
        self.export_order
            .retain(|export_id| self.exports.contains_key(export_id));
        Ok(())
    }

    pub(crate) fn retire_other_sessions(&mut self, identity: &AndroidFileIdentity) {
        for (task_id, task) in &self.tasks {
            let status = task.monitor.status();
            if task.identity == *identity || task_owner_stopped(&status) {
                continue;
            }
            if let Some(owner) = self.download_consent.get(task_id) {
                owner.revoke();
            }
            if let Some(owner) = self.upload_consent.get(task_id) {
                owner.revoke();
            }
            let _ = task
                .control
                .cancel(&task.identity.binding, task.identity.core_generation);
        }
        for export in self.exports.values() {
            if export.identity != *identity {
                export.cancelled.store(true, Ordering::Release);
            }
        }
        self.reap_finished_exports();
        let retired_tasks = self
            .tasks
            .iter()
            .filter(|(_, task)| {
                task.identity != *identity && task_owner_stopped(&task.monitor.status())
            })
            .map(|(task_id, task)| (task_id.clone(), task.monitor.status()))
            .collect::<Vec<_>>();
        for (task_id, status) in retired_tasks {
            if status.kind == NativeFileTaskKind::Download && download_owner_stopped(&status) {
                let export_still_owns_source = self
                    .exports
                    .values()
                    .any(|export| export.task_id == task_id && export.thread.is_some());
                if !export_still_owns_source
                    && self.download_artifacts.contains_key(&task_id)
                    && self.remove_artifact_area(&task_id).is_ok()
                {
                    self.download_artifacts.remove(&task_id);
                }
            }
        }
    }

    pub(crate) fn shutdown_cleanup(&mut self, core: &CoreHandle) -> Result<bool, String> {
        self.closing = true;
        for owner in self.download_consent.values() {
            owner.revoke();
        }
        for owner in self.upload_consent.values() {
            owner.revoke();
        }
        for task in self.tasks.values() {
            if !task_owner_stopped(&task.monitor.status()) {
                let _ = task
                    .control
                    .cancel(&task.identity.binding, task.identity.core_generation);
            }
        }
        for export in self.exports.values() {
            export.cancelled.store(true, Ordering::Release);
        }
        self.reap_finished_exports();

        if self.exports.values().any(|export| export.thread.is_some())
            || self
                .tasks
                .values()
                .any(|task| !task_owner_stopped(&task.monitor.status()))
        {
            return Ok(false);
        }
        for task_id in self.download_artifacts.keys().cloned().collect::<Vec<_>>() {
            let Some(task) = self.tasks.get(&task_id) else {
                return Err("Android download artifact lost its owning task".to_owned());
            };
            let status = task.monitor.status();
            if status.kind != NativeFileTaskKind::Download || !download_owner_stopped(&status) {
                return Ok(false);
            }
            self.remove_artifact_area(&task_id)?;
            self.download_artifacts.remove(&task_id);
        }
        self.download_consent.clear();
        self.upload_consent.clear();
        self.tasks.clear();
        let _ = core;
        Ok(true)
    }

    fn ensure_accepting(&mut self, identity: &AndroidFileIdentity) -> Result<(), String> {
        if self.closing {
            return Err(
                "Android file owners are closing; finish cleanup before starting another task"
                    .to_owned(),
            );
        }
        self.retire_other_sessions(identity);
        if self
            .tasks
            .values()
            .any(|task| task.identity != *identity && !task_owner_stopped(&task.monitor.status()))
            || self
                .exports
                .values()
                .any(|export| export.identity != *identity && export.thread.is_some())
        {
            return Err(
                "a previous Android file owner is still stopping; no new task can start yet"
                    .to_owned(),
            );
        }
        if self
            .download_artifacts
            .values()
            .any(|artifact| artifact.identity != *identity)
        {
            return Err("a previous session's private download could not be cleaned; retry cleanup before starting another file task".to_owned());
        }
        if self.exports.values().any(|export| export.thread.is_some()) {
            return Err(
                "wait for the Android SAF export worker to stop before starting another file task"
                    .to_owned(),
            );
        }
        self.prune_finished_tasks();
        Ok(())
    }

    fn prune_finished_tasks(&mut self) {
        let expired = self
            .tasks
            .iter()
            .filter(|(task_id, task)| {
                task_owner_stopped(&task.monitor.status())
                    && !self.download_artifacts.contains_key(*task_id)
            })
            .map(|(task_id, _)| task_id.clone())
            .collect::<Vec<_>>();
        for task_id in expired {
            self.tasks.remove(&task_id);
            self.download_consent.remove(&task_id);
            self.upload_consent.remove(&task_id);
        }
    }

    fn available_download_reservation(&self) -> Result<u64, String> {
        let reserved = self
            .download_artifacts
            .values()
            .try_fold(0_u64, |total, artifact| {
                total.checked_add(artifact.reserved_bytes)
            })
            .ok_or_else(|| "Android download reservation overflow".to_owned())?;
        let remaining = MAX_ANDROID_DOWNLOAD_TOTAL_BYTES.saturating_sub(reserved);
        let reservation = remaining.min(MAX_ANDROID_DOWNLOAD_ARTIFACT_BYTES);
        if reservation == 0 {
            return Err(
                "Android private download byte quota is full; export or discard a download first"
                    .to_owned(),
            );
        }
        Ok(reservation)
    }

    fn remove_artifact_area(&self, task_id: &str) -> Result<(), String> {
        let Some(artifact) = self.download_artifacts.get(task_id) else {
            return Ok(());
        };
        let area = self
            .download_area
            .as_ref()
            .ok_or_else(|| "Android private download area is unavailable".to_owned())?;
        match area.directory.remove_dir_all(&artifact.area_name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("verified Android private download cleanup is not confirmed".to_owned()),
        }
    }

    fn reap_finished_exports(&mut self) {
        let finished = self
            .exports
            .iter()
            .filter(|(_, export)| {
                export
                    .thread
                    .as_ref()
                    .is_some_and(thread::JoinHandle::is_finished)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for export_id in finished {
            self.reap_finished_export(&export_id);
        }
    }

    fn reap_finished_export(&mut self, export_id: &str) {
        let (task_id, phase, joined, status) = {
            let Some(export) = self.exports.get_mut(export_id) else {
                return;
            };
            let Some(thread) = export.thread.as_ref() else {
                return;
            };
            if !thread.is_finished() {
                return;
            }
            let Some(thread) = export.thread.take() else {
                return;
            };
            let joined = thread.join().is_ok();
            let phase = export
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .phase
                .clone();
            (
                export.task_id.clone(),
                phase,
                joined,
                Arc::clone(&export.status),
            )
        };
        // A terminal business phase can be published just before the worker
        // returns. Only this retained JoinHandle proves the actual FD owner
        // stopped; UI polling must keep running until this receipt is visible.
        status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owner_stopped = true;
        // A panic may have poisoned the last status publication. The actual
        // owner is joined now, so retain a readable failure receipt rather
        // than leaving subsequent status/discard checks permanently blocked.
        status.clear_poison();
        if !joined {
            let mut status = status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.phase = "failed".to_owned();
            status.error = Some("the SAF export worker exited unexpectedly".to_owned());
            status.destination_cleanup_complete = false;
            status.destination_cleanup_error = Some(
                "the worker stopped before confirming destination cleanup; inspect and remove any partial SAF file".to_owned(),
            );
            return;
        }
        if phase != "completed" {
            return;
        }
        let cleanup = self.remove_artifact_area(&task_id);
        if cleanup.is_ok() {
            self.download_artifacts.remove(&task_id);
        }
        if let Some(export) = self.exports.get(export_id) {
            let mut status = export
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.private_cleanup_complete = cleanup.is_ok();
            status.private_cleanup_error = cleanup.err();
        }
    }

    fn prune_export_history(&mut self) -> Result<(), String> {
        while self.exports.len() >= MAX_ANDROID_EXPORT_HISTORY {
            self.reap_finished_exports();
            let Some(position) = self.export_order.iter().position(|id| {
                self.exports.get(id).is_some_and(|export| {
                    export.thread.is_none()
                        && export
                            .status
                            .lock()
                            .map(|status| status.phase != "running")
                            .unwrap_or(false)
                })
            }) else {
                return Err(
                    "Android export history is full while an export worker is retained".to_owned(),
                );
            };
            if let Some(expired) = self.export_order.remove(position) {
                self.exports.remove(&expired);
            }
        }
        Ok(())
    }

    pub(crate) fn start_export(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        task_id: &str,
        destination: File,
    ) -> Result<AndroidExportStatus, String> {
        let worker_destination = match destination.try_clone() {
            Ok(destination) => destination,
            Err(error) => {
                let cleanup = clear_saf_destination(&destination);
                return Err(export_start_error(
                    format!(
                        "Android SAF destination could not be duplicated ({:?})",
                        error.kind()
                    ),
                    cleanup,
                ));
            }
        };
        match self.start_export_worker(core, identity, task_id, worker_destination) {
            Ok(status) => Ok(status),
            Err(error) => Err(export_start_error(
                error,
                clear_saf_destination(&destination),
            )),
        }
    }

    fn start_export_worker(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        task_id: &str,
        destination: File,
    ) -> Result<AndroidExportStatus, String> {
        self.check(core, identity)?;
        self.ensure_accepting(identity)?;
        self.reap_finished_exports();
        self.prune_export_history()?;
        let task = self
            .tasks
            .get(task_id)
            .filter(|task| task.identity == *identity)
            .map(|task| task.monitor.status())
            .map(Ok)
            .unwrap_or_else(|| {
                core.native_file_task_status(&identity.binding, identity.core_generation, task_id)
            })
            .map_err(|error| error.to_string())?;
        if task.kind != NativeFileTaskKind::Download
            || task.phase != NativeFileTaskPhase::Completed
            || !download_owner_stopped(&task)
            || !task
                .download
                .as_ref()
                .is_some_and(|download| download.source_verified)
        {
            return Err("only a completed, source-verified download can be exported".to_owned());
        }
        let artifact = self
            .download_artifacts
            .get(task_id)
            .ok_or_else(|| "the selected download artifact is unavailable".to_owned())?;
        if artifact.identity != *identity {
            return Err("the selected download belongs to a replaced session".to_owned());
        }
        let manifest = task
            .download
            .as_ref()
            .and_then(|download| download.manifest.as_ref())
            .ok_or_else(|| "the verified download manifest is unavailable".to_owned())?;
        let source_name = artifact.file_name.clone();
        let source_dir = self
            .download_area
            .as_ref()
            .ok_or_else(|| "Android private download area is unavailable".to_owned())?
            .directory
            .open_dir(&artifact.area_name)
            .map_err(|_| "the verified Android download is no longer available".to_owned())?;
        let export_id = uuid::Uuid::new_v4().to_string();
        if self.exports.values().any(|export| {
            export.thread.is_some()
                || export
                    .status
                    .lock()
                    .map(|status| status.phase == "running")
                    .unwrap_or(true)
        }) {
            return Err("another Android SAF export is still active".to_owned());
        }
        let status = Arc::new(Mutex::new(AndroidExportStatus {
            export_id: export_id.clone(),
            phase: "running".to_owned(),
            owner_stopped: false,
            copied_bytes: 0,
            total_bytes: manifest.size,
            error: None,
            private_cleanup_complete: false,
            private_cleanup_error: None,
            destination_cleanup_complete: false,
            destination_cleanup_error: None,
        }));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_status = Arc::clone(&status);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_core = core.clone();
        let worker_identity = identity.clone();
        let expected_hash = manifest.sha256.clone();
        let expected_size = manifest.size;
        let worker = thread::Builder::new()
            .name("nestlink-android-saf-export".to_owned())
            .spawn(move || {
                let result = export_verified_file(
                    source_dir,
                    source_name,
                    destination,
                    expected_size,
                    &expected_hash,
                    AndroidExportSession {
                        core: &worker_core,
                        identity: &worker_identity,
                        cancelled: &worker_cancelled,
                        status: &worker_status,
                    },
                );
                let mut status = worker_status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match result {
                    Ok(()) => {
                        status.phase = "completed".to_owned();
                        status.destination_cleanup_complete = true;
                    }
                    Err(ExportFailure::Cancelled { cleanup_failed }) => {
                        status.phase = "cancelled".to_owned();
                        status.destination_cleanup_complete = !cleanup_failed;
                        if cleanup_failed {
                            status.destination_cleanup_error = Some(
                                "the cancelled SAF destination could not be cleared".to_owned(),
                            );
                        }
                    }
                    Err(ExportFailure::Io { kind, cleanup_failed }) => {
                        status.phase = "failed".to_owned();
                        status.error = Some(format!("export failed ({kind:?})"));
                        status.destination_cleanup_complete = !cleanup_failed;
                        if cleanup_failed {
                            status.destination_cleanup_error = Some(
                                "the failed SAF destination could not be cleared; remove it manually".to_owned(),
                            );
                        }
                    }
                }
            })
            .map_err(|_| "Android SAF export worker could not start".to_owned())?;
        self.exports.insert(
            export_id.clone(),
            AndroidExportTask {
                task_id: task_id.to_owned(),
                identity: identity.clone(),
                status: Arc::clone(&status),
                cancelled,
                thread: Some(worker),
            },
        );
        self.export_order.push_back(export_id.clone());
        Ok(status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    pub(crate) fn export_status(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        export_id: &str,
    ) -> Result<AndroidExportStatus, String> {
        self.check(core, identity)?;
        let export = self
            .exports
            .get(export_id)
            .ok_or_else(|| "the Android SAF export is unavailable".to_owned())?;
        if export.identity != *identity {
            return Err("the Android SAF export belongs to a replaced session".to_owned());
        }
        self.reap_finished_export(export_id);
        let export = self
            .exports
            .get(export_id)
            .ok_or_else(|| "the Android SAF export is unavailable".to_owned())?;
        let status = export
            .status
            .lock()
            .map_err(|_| "Android SAF export status is unavailable".to_owned())?
            .clone();
        Ok(status)
    }

    pub(crate) fn cancel_export(
        &mut self,
        core: &CoreHandle,
        identity: &AndroidFileIdentity,
        export_id: &str,
    ) -> Result<(), String> {
        self.check(core, identity)?;
        let export = self
            .exports
            .get(export_id)
            .ok_or_else(|| "the Android SAF export is unavailable".to_owned())?;
        if export.identity != *identity {
            return Err("the Android SAF export belongs to a replaced session".to_owned());
        }
        export.cancelled.store(true, Ordering::Release);
        Ok(())
    }
}

pub(crate) enum ExportFailure {
    Cancelled {
        cleanup_failed: bool,
    },
    Io {
        kind: io::ErrorKind,
        cleanup_failed: bool,
    },
}

impl ExportFailure {
    fn with_cleanup_failure(self, cleanup_failed: bool) -> Self {
        match self {
            Self::Cancelled { .. } => Self::Cancelled { cleanup_failed },
            Self::Io { kind, .. } => Self::Io {
                kind,
                cleanup_failed,
            },
        }
    }
}

/// The original session and real owner controls remain checked throughout export.
pub(crate) struct AndroidExportSession<'a> {
    pub core: &'a CoreHandle,
    pub identity: &'a dyn AndroidExportIdentity,
    pub cancelled: &'a AtomicBool,
    pub status: &'a Mutex<AndroidExportStatus>,
}

pub(crate) fn export_verified_file(
    source_dir: Dir,
    source_name: String,
    mut destination: File,
    expected_size: u64,
    expected_hash: &[u8],
    session: AndroidExportSession<'_>,
) -> Result<(), ExportFailure> {
    let result = export_verified_file_body(
        &source_dir,
        &source_name,
        &mut destination,
        expected_size,
        expected_hash,
        session,
    );
    if let Err(failure) = result {
        let cleared = destination
            .metadata()
            .is_ok_and(|metadata| metadata.is_file())
            && destination
                .set_len(0)
                .and_then(|()| destination.sync_all())
                .is_ok();
        return Err(failure.with_cleanup_failure(!cleared));
    }
    Ok(())
}

pub(crate) fn clear_saf_destination(destination: &File) -> io::Result<()> {
    let metadata = destination.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SAF destination is not a regular seekable file",
        ));
    }
    destination.set_len(0)?;
    destination.sync_all()
}

pub(crate) fn export_start_error(error: String, cleanup: io::Result<()>) -> String {
    match cleanup {
        Ok(()) => format!("{error}; SAF destination was cleared"),
        Err(_) => format!(
            "{error}; SAF destination cleanup could not be confirmed, remove any partial file manually"
        ),
    }
}

fn export_verified_file_body(
    source_dir: &Dir,
    source_name: &str,
    destination: &mut File,
    expected_size: u64,
    expected_hash: &[u8],
    session: AndroidExportSession<'_>,
) -> Result<(), ExportFailure> {
    let AndroidExportSession {
        core,
        identity,
        cancelled,
        status,
    } = session;
    let mut source_options = OpenOptions::new();
    source_options.read(true).follow(FollowSymlinks::No);
    let mut source = source_dir
        .open_with(source_name, &source_options)
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?;
    let source_metadata = source.metadata().map_err(|error| ExportFailure::Io {
        kind: error.kind(),
        cleanup_failed: false,
    })?;
    let target_metadata = destination.metadata().map_err(|error| ExportFailure::Io {
        kind: error.kind(),
        cleanup_failed: false,
    })?;
    if !source_metadata.is_file()
        || !target_metadata.is_file()
        || source_metadata.len() != expected_size
        || target_metadata.len() != 0
        || expected_hash.len() != 32
    {
        return Err(ExportFailure::Io {
            kind: io::ErrorKind::InvalidInput,
            cleanup_failed: false,
        });
    }
    export_check(core, identity, cancelled)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?;
    let mut write_hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    while copied < expected_size {
        export_check(core, identity, cancelled)?;
        let maximum = (expected_size - copied).min(buffer.len() as u64) as usize;
        let count = source
            .read(&mut buffer[..maximum])
            .map_err(|error| ExportFailure::Io {
                kind: error.kind(),
                cleanup_failed: false,
            })?;
        if count == 0 {
            return Err(ExportFailure::Io {
                kind: io::ErrorKind::UnexpectedEof,
                cleanup_failed: false,
            });
        }
        let mut written = 0;
        while written < count {
            export_check(core, identity, cancelled)?;
            let actual = destination
                .write(&buffer[written..count])
                .map_err(|error| ExportFailure::Io {
                    kind: error.kind(),
                    cleanup_failed: false,
                })?;
            if actual == 0 {
                return Err(ExportFailure::Io {
                    kind: io::ErrorKind::WriteZero,
                    cleanup_failed: false,
                });
            }
            written += actual;
        }
        write_hash.update(&buffer[..count]);
        copied = copied.saturating_add(count as u64);
        status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .copied_bytes = copied;
    }
    export_check(core, identity, cancelled)?;
    if write_hash.finalize().as_slice() != expected_hash {
        return Err(ExportFailure::Io {
            kind: io::ErrorKind::InvalidData,
            cleanup_failed: false,
        });
    }
    destination.sync_all().map_err(|error| ExportFailure::Io {
        kind: error.kind(),
        cleanup_failed: false,
    })?;
    export_check(core, identity, cancelled)?;
    if destination
        .metadata()
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?
        .len()
        != expected_size
    {
        return Err(ExportFailure::Io {
            kind: io::ErrorKind::InvalidData,
            cleanup_failed: false,
        });
    }
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?;
    let mut readback_hash = Sha256::new();
    let mut readback = 0_u64;
    while readback < expected_size {
        export_check(core, identity, cancelled)?;
        let maximum = (expected_size - readback).min(buffer.len() as u64) as usize;
        let count =
            destination
                .read(&mut buffer[..maximum])
                .map_err(|error| ExportFailure::Io {
                    kind: error.kind(),
                    cleanup_failed: false,
                })?;
        if count == 0 {
            return Err(ExportFailure::Io {
                kind: io::ErrorKind::UnexpectedEof,
                cleanup_failed: false,
            });
        }
        readback_hash.update(&buffer[..count]);
        readback = readback.saturating_add(count as u64);
    }
    export_check(core, identity, cancelled)?;
    if readback != expected_size || readback_hash.finalize().as_slice() != expected_hash {
        return Err(ExportFailure::Io {
            kind: io::ErrorKind::InvalidData,
            cleanup_failed: false,
        });
    }
    if destination
        .metadata()
        .map_err(|error| ExportFailure::Io {
            kind: error.kind(),
            cleanup_failed: false,
        })?
        .len()
        != expected_size
    {
        return Err(ExportFailure::Io {
            kind: io::ErrorKind::InvalidData,
            cleanup_failed: false,
        });
    }
    Ok(())
}

fn export_check(
    core: &CoreHandle,
    identity: &dyn AndroidExportIdentity,
    cancelled: &AtomicBool,
) -> Result<(), ExportFailure> {
    if cancelled.load(Ordering::Acquire) || !identity.current(core) {
        return Err(ExportFailure::Cancelled {
            cleanup_failed: false,
        });
    }
    Ok(())
}

fn download_owner_stopped(status: &NativeFileTaskStatus) -> bool {
    if !status.finished || status.kind != NativeFileTaskKind::Download {
        return false;
    }
    let Some(download) = status.download.as_ref() else {
        return true;
    };
    download.actor_finished
        && download.local_stopped
        && download
            .destination
            .as_ref()
            .is_none_or(|worker| worker.finished && worker.destination.file_closed)
}

fn task_owner_stopped(status: &NativeFileTaskStatus) -> bool {
    if !status.finished {
        return false;
    }
    match status.kind {
        NativeFileTaskKind::Download => download_owner_stopped(status),
        NativeFileTaskKind::Upload => status.upload.as_ref().is_none_or(|upload| {
            upload.finished
                && upload.actor_finished
                && upload.remote_closed
                && upload
                    .source
                    .as_ref()
                    .is_none_or(|source| source.finished && source.source_closed)
                && upload.destination.as_ref().is_none_or(|destination| {
                    destination.file_closed && destination.temporary_removed
                })
        }),
    }
}

struct AndroidUploadConsent(Arc<AtomicBool>);
impl AndroidUploadConsent {
    fn new() -> (Self, Self) {
        let active = Arc::new(AtomicBool::new(true));
        (Self(active.clone()), Self(active))
    }
    fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl FileReadConsent for AndroidUploadConsent {
    fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android document grant revoked",
            ))
        }
    }
}

struct AndroidUploadSelection {
    source: Option<File>,
    maximum: u64,
    consent: AndroidUploadConsent,
}
impl AndroidUploadSelection {
    fn new(source: File, maximum: u64) -> (Self, AndroidUploadConsent) {
        let (consent, owner) = AndroidUploadConsent::new();
        (
            Self {
                source: Some(source),
                maximum,
                consent: AndroidUploadConsent(Arc::clone(&consent.0)),
            },
            owner,
        )
    }
}
impl FileUploadSourceFactory for AndroidUploadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(AndroidUploadConsent(Arc::clone(&self.consent.0)))
    }
    fn open(
        mut self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        self.consent.check()?;
        authorized()?;
        let source = self.source.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android source was already opened",
            )
        })?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() > self.maximum || metadata.len() > FILE_SIZE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selected Android document is not a bounded seekable file",
            ));
        }
        let mut source = AndroidUploadSource {
            source,
            consent: self.consent,
            length: metadata.len(),
            modified: metadata.modified().ok(),
            manifest: None,
        };
        source.source.seek(SeekFrom::Start(0))?;
        Ok(Box::new(source))
    }
}

struct AndroidUploadSource {
    source: File,
    consent: AndroidUploadConsent,
    length: u64,
    modified: Option<SystemTime>,
    manifest: Option<FileReadManifest>,
}
impl AndroidUploadSource {
    fn check(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.consent.check()?;
        authorized()
    }
    fn verify_identity(&self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.check(authorized)?;
        let metadata = self.source.metadata()?;
        self.check(authorized)?;
        if !metadata.is_file()
            || metadata.len() != self.length
            || metadata.modified().ok() != self.modified
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "selected Android document changed",
            ));
        }
        Ok(())
    }
    fn digest(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<[u8; 32]> {
        self.verify_identity(authorized)?;
        self.source.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 32 * 1024];
        let mut remaining = self.length;
        while remaining != 0 {
            self.check(authorized)?;
            let maximum = remaining.min(buffer.len() as u64) as usize;
            let count = self.source.read(&mut buffer[..maximum])?;
            self.check(authorized)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "selected Android document ended early",
                ));
            }
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        self.verify_identity(authorized)?;
        Ok(hash.finalize().into())
    }
}
impl FileReadSource for AndroidUploadSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(AndroidUploadConsent(Arc::clone(&self.consent.0)))
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        self.check(authorized)?;
        let sha256 = self.digest(authorized)?;
        self.source.seek(SeekFrom::Start(0))?;
        let manifest = FileReadManifest {
            size: self.length,
            sha256: sha256.to_vec(),
            offset: 0,
        };
        self.manifest = Some(manifest.clone());
        Ok(manifest)
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        self.verify_identity(authorized)?;
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android document has no manifest",
            )
        })?;
        if maximum == 0
            || offset
                .checked_add(maximum as u64)
                .is_none_or(|end| end > manifest.size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Android document range",
            ));
        }
        self.source.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; maximum];
        self.source.read_exact(&mut bytes)?;
        self.verify_identity(authorized)?;
        Ok(bytes)
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.check(authorized)?;
        if self.manifest.as_ref() != Some(original)
            || self.digest(authorized)?.as_slice() != original.sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "selected Android document checksum changed",
            ));
        }
        Ok(())
    }
}

struct OwnedDownloadSelection {
    selection: LocalDownloadSelection,
    _owner: Arc<LocalDownloadConsent>,
}
impl FileDestinationFactory for OwnedDownloadSelection {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.selection.consent()
    }
    fn build(
        self: Box<Self>,
        source: &nestlink_remote::files::FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        let Self { selection, _owner } = *self;
        let destination = Box::new(selection).build(source)?;
        Ok(Box::new(OwnedDownloadDestination {
            destination,
            _owner,
        }))
    }
}

struct OwnedDownloadDestination {
    destination: Box<dyn FileDestination>,
    _owner: Arc<LocalDownloadConsent>,
}
impl FileDestination for OwnedDownloadDestination {
    fn status(&self) -> nestlink_remote::files::FileDestinationStatus {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(authorized)
    }
    fn write(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        chunk: &nestlink_protocol::FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.write(source, chunk, authorized)
    }
    fn resume(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.resume(source, authorized)
    }
    fn finish(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.finish(source, authorized)
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}

pub(crate) fn task_json(task: &NativeFileTaskStatus) -> serde_json::Value {
    let (confirmed_bytes, total_bytes, error) = match task.kind {
        NativeFileTaskKind::Download => {
            let download = task.download.as_ref();
            let confirmed = download
                .and_then(|status| status.destination.as_ref())
                .map(|status| status.destination.confirmed_bytes)
                .unwrap_or(task.confirmed_bytes);
            let total = download
                .and_then(|status| status.manifest.as_ref())
                .map(|manifest| manifest.size)
                .or(task.total_bytes);
            (confirmed, total, task.error.map(|error| error.to_string()))
        }
        NativeFileTaskKind::Upload => {
            let upload = task.upload.as_ref();
            (
                upload
                    .map(|status| status.confirmed_bytes)
                    .unwrap_or(task.confirmed_bytes),
                upload.and_then(|status| status.size).or(task.total_bytes),
                task.error.map(|error| error.to_string()),
            )
        }
    };
    serde_json::json!({
        "task_id": task.task_id,
        "kind": if task.kind == NativeFileTaskKind::Upload { "upload" } else { "download" },
        "phase": match task.phase {
            NativeFileTaskPhase::Queued => "queued",
            NativeFileTaskPhase::Active => "running",
            NativeFileTaskPhase::Paused => "paused",
            NativeFileTaskPhase::Settling => "cancelling",
            NativeFileTaskPhase::Completed => "completed",
            NativeFileTaskPhase::Cancelled => "cancelled",
            NativeFileTaskPhase::Failed => "failed",
        },
        "confirmed_bytes": confirmed_bytes,
        "total_bytes": total_bytes,
        "finished": task.finished,
        "owner_stopped": task_owner_stopped(task),
        "error": error,
    })
}

pub(crate) fn export_json(status: &AndroidExportStatus) -> serde_json::Value {
    serde_json::json!({
        "export_id": status.export_id,
        "phase": status.phase,
        "owner_stopped": status.owner_stopped,
        "copied_bytes": status.copied_bytes,
        "total_bytes": status.total_bytes,
        "error": status.error,
        "private_cleanup_complete": status.private_cleanup_complete,
        "private_cleanup_error": status.private_cleanup_error,
        "destination_cleanup_complete": status.destination_cleanup_complete,
        "destination_cleanup_error": status.destination_cleanup_error,
    })
}

pub(crate) fn roots_json(roots: Vec<FileRoot>) -> serde_json::Value {
    serde_json::json!({
        "roots": roots.into_iter().map(|root| serde_json::json!({
            "root_id": root.root_id,
            "display_name": root.display_name,
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn browse_json(
    page: nestlink_app_core::NativeBrowsePage,
) -> Result<serde_json::Value, String> {
    let directory = page.page.directory;
    let entries = page
        .page
        .entries
        .into_iter()
        .map(|entry| {
            let directory_entry = match DirectoryEntryKind::try_from(entry.kind).map_err(|_| {
                "Android directory response contained an invalid entry type".to_owned()
            })? {
                DirectoryEntryKind::DirectoryEntryFile => false,
                DirectoryEntryKind::DirectoryEntryDirectory => true,
                DirectoryEntryKind::DirectoryEntryUnspecified => {
                    return Err(
                        "Android directory response contained an unspecified entry type".to_owned(),
                    );
                }
            };
            Ok(serde_json::json!({
                "name": entry.name,
                "directory": directory_entry,
                "size": entry.size,
                "modified_unix_ms": entry.modified_unix_ms,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(serde_json::json!({
        "session": page.session,
        "browse_id": page.browse_id,
        "root_id": page.page.root_id,
        "directory": directory,
        "snapshot_id": page.page.snapshot_id,
        "offset": page.page.offset,
        "total_entries": page.page.total_entries,
        "has_more": page.page.has_more,
        "entries": entries,
    }))
}

#[cfg(target_os = "android")]
pub(crate) fn take_detached_fd(fd: jni::sys::jint) -> io::Result<File> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Android picker returned an invalid file descriptor",
        ));
    }
    // SAFETY: ParcelFileDescriptor.detachFd transfers sole ownership of this
    // open descriptor to JNI, and this function wraps it exactly once.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(File::from(owned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    fn transfers_with_export(
        status: Arc<Mutex<AndroidExportStatus>>,
        worker: thread::JoinHandle<()>,
    ) -> AndroidFileTransfers {
        let mut transfers = AndroidFileTransfers::default();
        transfers.exports.insert(
            "export-1".to_owned(),
            AndroidExportTask {
                task_id: "download-1".to_owned(),
                identity: AndroidFileIdentity {
                    binding: NativeSessionBinding {
                        request_id: "request-1".to_owned(),
                        connection_generation: 9,
                    },
                    core_generation: 12,
                },
                status,
                cancelled: Arc::new(AtomicBool::new(false)),
                thread: Some(worker),
            },
        );
        transfers
    }

    fn wait_for_export_reap(transfers: &mut AndroidFileTransfers) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            transfers.reap_finished_exports();
            if transfers
                .exports
                .values()
                .all(|export| export.thread.is_none())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture worker did not finish",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn terminal_export_keeps_the_actual_file_worker_until_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let status = Arc::new(Mutex::new(AndroidExportStatus {
            export_id: "export-1".to_owned(),
            phase: "running".to_owned(),
            ..AndroidExportStatus::default()
        }));
        let owned_file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
        let (published, ready) = mpsc::channel();
        let (release, retained) = mpsc::channel();
        let worker_status = Arc::clone(&status);
        let worker = thread::Builder::new().spawn(move || {
            worker_status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .phase = "completed".to_owned();
            let _ = published.send(());
            let _ = retained.recv_timeout(Duration::from_secs(5));
            drop(owned_file);
        })?;
        let mut transfers = transfers_with_export(Arc::clone(&status), worker);
        ready.recv_timeout(Duration::from_secs(5))?;
        transfers.reap_finished_exports();
        let pending = status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(pending.phase, "completed");
        assert!(!pending.owner_stopped);
        assert!(!pending.private_cleanup_complete);
        assert!(
            transfers
                .exports
                .values()
                .all(|export| export.thread.is_some())
        );
        assert_eq!(export_json(&pending)["owner_stopped"], false);

        release.send(())?;
        wait_for_export_reap(&mut transfers)?;
        let joined = status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert!(joined.owner_stopped);
        assert!(joined.private_cleanup_complete);
        assert_eq!(export_json(&joined)["owner_stopped"], true);
        Ok(())
    }

    #[test]
    fn panicked_export_reaps_the_owner_and_reports_unconfirmed_destination() -> io::Result<()> {
        let status = Arc::new(Mutex::new(AndroidExportStatus {
            export_id: "export-1".to_owned(),
            phase: "running".to_owned(),
            ..AndroidExportStatus::default()
        }));
        let worker_status = Arc::clone(&status);
        let worker = thread::Builder::new().spawn(move || {
            let _status = worker_status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("fixture export owner panicked while publishing status");
        })?;
        let mut transfers = transfers_with_export(Arc::clone(&status), worker);
        wait_for_export_reap(&mut transfers)?;
        let status = status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(status.phase, "failed");
        assert!(status.owner_stopped);
        assert!(!status.destination_cleanup_complete);
        assert!(status.destination_cleanup_error.is_some());
        assert!(!status.private_cleanup_complete);
        assert!(
            transfers
                .exports
                .values()
                .all(|export| !export.status.is_poisoned())
        );
        Ok(())
    }
}
