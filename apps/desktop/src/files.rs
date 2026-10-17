pub(crate) mod recovery;

use crate::picker::Selector;
use eframe::egui;
use nestlink_app_core::NativeSessionBinding;
use nestlink_app_ipc::files::{
    FileDirection, FileEntryView, FileRootView, FileTaskView, LocalReadRootSelection,
    LocalWriteRootSelection, NativeFileCommand, NativeFileReply, NativeFileTaskAction,
};
use nestlink_platform_files::selection::SelectionKind;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum PickerTarget {
    ShareFolder,
    ReceiveParent,
    DownloadParent,
    UploadFile,
}
struct PickerJob {
    session: FileSession,
    target: PickerTarget,
    selector: Selector,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FileSession {
    pub binding: NativeSessionBinding,
    pub generation: u64,
    pub runtime_id: String,
    pub is_host: bool,
    pub read: bool,
    pub write: bool,
}

#[derive(Default)]
pub(crate) struct FilePanel {
    session: Option<FileSession>,
    read_directory: String,
    read_label: String,
    disclose_directory: bool,
    write_directory: String,
    write_label: String,
    read_roots: Vec<FileRootView>,
    write_roots: Vec<FileRootView>,
    selected_read: Option<String>,
    selected_write: Option<String>,
    browse_id: Option<String>,
    browse_directory: String,
    entries: Vec<FileEntryView>,
    browse_complete: bool,
    relative_path: String,
    download_directory: String,
    download_name: String,
    upload_file: String,
    upload_path: String,
    tasks: Vec<FileTaskView>,
    pending: bool,
    pending_since: Option<Instant>,
    next_poll: Option<Instant>,
    message: Option<String>,
    picker: Option<PickerJob>,
}

fn text(english: bool, chinese: &'static str, english_text: &'static str) -> &'static str {
    if english { english_text } else { chinese }
}

impl FilePanel {
    pub(crate) fn reconcile(&mut self, session: Option<FileSession>) {
        if self.session != session {
            *self = Self {
                session,
                ..Self::default()
            };
        }
    }

    pub(crate) fn apply(
        &mut self,
        generation: u64,
        binding: &NativeSessionBinding,
        reply: NativeFileReply,
    ) {
        if !self
            .session
            .as_ref()
            .is_some_and(|session| session.generation == generation && &session.binding == binding)
        {
            return;
        }
        self.pending = false;
        self.pending_since = None;
        self.message = None;
        match reply {
            NativeFileReply::HostRootsSelected { direction, roots }
            | NativeFileReply::Roots { direction, roots } => {
                let (selected, current) = match direction {
                    FileDirection::Read => (&mut self.selected_read, &mut self.read_roots),
                    FileDirection::Write => (&mut self.selected_write, &mut self.write_roots),
                };
                if selected
                    .as_ref()
                    .is_none_or(|id| !roots.iter().any(|root| &root.root_id == id))
                {
                    *selected = roots.first().map(|root| root.root_id.clone());
                }
                *current = roots;
            }
            NativeFileReply::Directory {
                root_id,
                directory,
                browse_id,
                entries,
                complete,
            } => {
                if self.selected_read.as_deref() != Some(root_id.as_str())
                    || self.browse_directory != directory
                {
                    self.message = Some("The directory reply belongs to an older selection".into());
                    return;
                }
                if self
                    .browse_id
                    .as_ref()
                    .is_none_or(|current| current != &browse_id)
                {
                    self.entries.clear();
                }
                self.browse_id = Some(browse_id);
                if self.entries.len() + entries.len()
                    > nestlink_protocol::DIRECTORY_ENTRIES as usize
                {
                    self.message =
                        Some("Directory display capacity reached; end this browse".into());
                    return;
                }
                self.entries.extend(entries);
                self.browse_complete = complete;
            }
            NativeFileReply::BrowseCancelled => {
                self.browse_id = None;
                self.entries.clear();
                self.browse_complete = false;
            }
            NativeFileReply::Task { task } => {
                if let Some(current) = self
                    .tasks
                    .iter_mut()
                    .find(|current| current.task_id == task.task_id)
                {
                    *current = task;
                } else {
                    if self.tasks.len() >= 64 {
                        if let Some(index) = self.tasks.iter().position(|task| task.finished) {
                            self.tasks.remove(index);
                        } else {
                            self.message = Some("File task display capacity reached".into());
                            return;
                        }
                    }
                    self.tasks.push(task);
                }
                self.next_poll = Some(Instant::now() + Duration::from_millis(250));
            }
            NativeFileReply::HostRootRevoked { direction, root_id } => {
                let roots = match direction {
                    FileDirection::Read => &mut self.read_roots,
                    FileDirection::Write => &mut self.write_roots,
                };
                roots.retain(|root| root.root_id != root_id);
            }
            NativeFileReply::ControlAccepted => {
                self.next_poll = Some(Instant::now());
            }
            NativeFileReply::Refused { reason } => self.message = Some(reason),
        }
    }

    pub(crate) fn track_recovered(&mut self, task_id: String) {
        if self.tasks.len() >= 64 {
            if let Some(index) = self.tasks.iter().position(|task| task.finished) {
                self.tasks.remove(index);
            } else {
                self.message =
                    Some("File task display capacity reached; use recovery task facts".into());
                return;
            }
        }
        self.tasks.push(FileTaskView {
            task_id,
            upload: false,
            phase: "queued".into(),
            confirmed_bytes: 0,
            total_bytes: None,
            finished: false,
            error: None,
        });
        self.next_poll = Some(Instant::now());
    }

    pub(crate) fn disconnected(&mut self) {
        self.pending = false;
        self.pending_since = None;
        self.message = Some(
            "File operation acknowledgement was lost; refresh its status before retrying".into(),
        );
    }

    pub(crate) fn poll(&mut self) -> Option<NativeFileCommand> {
        self.poll_picker();
        if self.pending
            || self.session.is_none()
            || self.next_poll.is_none_or(|at| Instant::now() < at)
        {
            return None;
        }
        let task = self.tasks.iter().find(|task| !task.finished)?;
        let command = NativeFileCommand::Task {
            task_id: task.task_id.clone(),
        };
        // Rotate the queried task so one long operation cannot starve others.
        let index = self
            .tasks
            .iter()
            .position(|value| value.task_id == task.task_id)?;
        let task = self.tasks.remove(index);
        self.tasks.push(task);
        self.pending = true;
        self.pending_since = Some(Instant::now());
        self.next_poll = Some(Instant::now() + Duration::from_millis(250));
        Some(command)
    }

    pub(crate) fn session(&self) -> Option<&FileSession> {
        self.session.as_ref()
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui, english: bool) -> Option<NativeFileCommand> {
        self.poll_picker();
        let session = self.session.clone()?;
        if !session.read && !session.write {
            return None;
        }
        let mut command = None;
        egui::CollapsingHeader::new(text(english, "文件", "Files"))
            .id_salt("native-file-panel")
            .show(ui, |ui| {
                if session.is_host {
                    self.host(ui, english, &session, &mut command);
                } else {
                    self.controller(ui, english, &session, &mut command);
                }
                self.task_list(ui, english, &mut command);
                if let Some(message) = &self.message {
                    ui.label(message);
                }
                if self.picker.is_some() {
                    ui.label(text(
                        english,
                        "正在等待系统文件选择器",
                        "Waiting for the system file selector",
                    ));
                    if ui
                        .button(text(english, "取消选择", "Cancel selection"))
                        .clicked()
                    {
                        self.picker = None;
                    }
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
            });
        if command.is_some() {
            self.pending = true;
            self.pending_since = Some(Instant::now());
        }
        command
    }

    fn host(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        session: &FileSession,
        command: &mut Option<NativeFileCommand>,
    ) {
        ui.label(text(
            english,
            "仅共享你在此会话中明确选择的目录。",
            "Share only folders explicitly selected for this session.",
        ));
        if session.read {
            if ui
                .add_enabled(
                    !self.pending,
                    egui::Button::new(text(
                        english,
                        "刷新本机共享目录",
                        "Refresh locally shared folders",
                    )),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::ListRoots {
                    direction: FileDirection::Read,
                });
            }
            ui.label(text(
                english,
                "允许对方下载的本机目录",
                "Local folder available for remote downloads",
            ));
            ui.text_edit_singleline(&mut self.read_directory);
            self.select_button(
                ui,
                english,
                PickerTarget::ShareFolder,
                "选择共享目录",
                "Choose shared folder",
            );
            ui.label(text(
                english,
                "对方看到的目录名称",
                "Folder label shown to the peer",
            ));
            ui.text_edit_singleline(&mut self.read_label);
            ui.checkbox(
                &mut self.disclose_directory,
                text(
                    english,
                    "另行允许浏览目录内容",
                    "Also allow directory browsing",
                ),
            );
            if ui
                .add_enabled(
                    !self.pending && !self.read_directory.is_empty() && !self.read_label.is_empty(),
                    egui::Button::new(text(english, "批准共享此目录", "Approve this folder")),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::SelectHostReadRoots {
                    roots: vec![LocalReadRootSelection {
                        directory: self.read_directory.clone(),
                        display_name: self.read_label.clone(),
                        disclose_directory: self.disclose_directory,
                    }],
                });
            }
            self.shared_roots(ui, english, FileDirection::Read, command);
        }
        if session.write {
            ui.separator();
            if ui
                .add_enabled(
                    !self.pending,
                    egui::Button::new(text(
                        english,
                        "刷新本机接收目录",
                        "Refresh local receiving folders",
                    )),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::ListRoots {
                    direction: FileDirection::Write,
                });
            }
            ui.label(text(
                english,
                "接收上传的新目录（不能是已有目录）",
                "New receiving folder (must not already exist)",
            ));
            ui.text_edit_singleline(&mut self.write_directory);
            self.select_button(
                ui,
                english,
                PickerTarget::ReceiveParent,
                "选择接收位置",
                "Choose receiving location",
            );
            ui.small(text(
                english,
                "在选定位置创建一个新的接收目录。",
                "Create a new receiving folder inside the selected location.",
            ));
            ui.label(text(english, "接收目录名称", "Receiving folder label"));
            ui.text_edit_singleline(&mut self.write_label);
            if ui
                .add_enabled(
                    !self.pending
                        && !self.write_directory.is_empty()
                        && !self.write_label.is_empty(),
                    egui::Button::new(text(
                        english,
                        "批准接收至此目录",
                        "Approve this receiving folder",
                    )),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::SelectHostWriteRoots {
                    roots: vec![LocalWriteRootSelection {
                        fresh_directory: self.write_directory.clone(),
                        display_name: self.write_label.clone(),
                    }],
                });
            }
            self.shared_roots(ui, english, FileDirection::Write, command);
        }
    }

    fn shared_roots(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        direction: FileDirection,
        command: &mut Option<NativeFileCommand>,
    ) {
        let roots = match direction {
            FileDirection::Read => &self.read_roots,
            FileDirection::Write => &self.write_roots,
        };
        for root in roots {
            ui.horizontal(|ui| {
                ui.label(&root.display_name);
                if ui
                    .add_enabled(
                        !self.pending,
                        egui::Button::new(text(english, "撤销此目录", "Revoke folder")),
                    )
                    .clicked()
                {
                    *command = Some(NativeFileCommand::RevokeHostRoot {
                        direction,
                        root_id: root.root_id.clone(),
                    });
                }
            });
        }
    }

    fn controller(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        session: &FileSession,
        command: &mut Option<NativeFileCommand>,
    ) {
        if session.read {
            if ui
                .add_enabled(
                    !self.pending && self.browse_id.is_none(),
                    egui::Button::new(text(english, "获取可下载目录", "Get download folders")),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::ListRoots {
                    direction: FileDirection::Read,
                });
            }
            ui.add_enabled_ui(self.browse_id.is_none(), |ui| {
                let previous = self.selected_read.clone();
                root_choice(
                    ui,
                    "file-read-root",
                    &self.read_roots,
                    &mut self.selected_read,
                    english,
                );
                if self.selected_read != previous {
                    self.entries.clear();
                    self.relative_path.clear();
                    self.download_name.clear();
                    self.browse_directory.clear();
                }
            });
            ui.label(text(
                english,
                "相对浏览目录（留空表示共享根目录）",
                "Relative directory to browse (empty for the shared root)",
            ));
            ui.add_enabled(
                self.browse_id.is_none() && !self.pending,
                egui::TextEdit::singleline(&mut self.browse_directory),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.pending && self.selected_read.is_some() && self.browse_id.is_none(),
                        egui::Button::new(text(english, "浏览", "Browse")),
                    )
                    .clicked()
                    && let Some(root_id) = &self.selected_read
                {
                    self.entries.clear();
                    *command = Some(NativeFileCommand::BrowseBegin {
                        root_id: root_id.clone(),
                        directory: (!self.browse_directory.is_empty())
                            .then(|| self.browse_directory.clone()),
                    });
                }
                if let Some(browse_id) = &self.browse_id {
                    if ui
                        .add_enabled(
                            !self.pending && !self.browse_complete,
                            egui::Button::new(text(english, "下一页", "Next page")),
                        )
                        .clicked()
                    {
                        *command = Some(NativeFileCommand::BrowseNext {
                            browse_id: browse_id.clone(),
                        });
                    }
                    if ui
                        .add_enabled(
                            !self.pending,
                            egui::Button::new(text(english, "结束浏览", "End browse")),
                        )
                        .clicked()
                    {
                        *command = Some(NativeFileCommand::BrowseCancel {
                            browse_id: browse_id.clone(),
                        });
                    }
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("file-directory-entries")
                .max_height(180.0)
                .show(ui, |ui| {
                    for entry in &self.entries {
                        if ui
                            .add_enabled(!entry.directory, egui::Button::new(&entry.relative_path))
                            .clicked()
                        {
                            self.relative_path = entry.relative_path.clone();
                            self.download_name =
                                entry.relative_path.rsplit('/').next().unwrap_or("").into();
                        }
                    }
                });
            ui.label(text(
                english,
                "远端目录内的相对文件路径",
                "Relative file path within the remote folder",
            ));
            ui.text_edit_singleline(&mut self.relative_path);
            ui.label(text(english, "本机新下载目录", "New local download folder"));
            ui.text_edit_singleline(&mut self.download_directory);
            self.select_button(
                ui,
                english,
                PickerTarget::DownloadParent,
                "选择下载位置",
                "Choose download location",
            );
            ui.small(text(
                english,
                "在选定位置创建一个新的下载目录。",
                "Create a new download folder inside the selected location.",
            ));
            ui.label(text(english, "保存文件名", "Save filename"));
            ui.text_edit_singleline(&mut self.download_name);
            if ui
                .add_enabled(
                    !self.pending
                        && self.browse_id.is_none()
                        && self.selected_read.is_some()
                        && !self.relative_path.is_empty()
                        && !self.download_directory.is_empty()
                        && !self.download_name.is_empty(),
                    egui::Button::new(text(english, "下载此文件", "Download file")),
                )
                .clicked()
                && let Some(root_id) = &self.selected_read
            {
                *command = Some(NativeFileCommand::Download {
                    root_id: root_id.clone(),
                    relative_path: self.relative_path.clone(),
                    local_directory: self.download_directory.clone(),
                    local_name: self.download_name.clone(),
                });
            }
        }
        if session.write {
            ui.separator();
            if ui
                .add_enabled(
                    !self.pending,
                    egui::Button::new(text(english, "获取可上传目录", "Get upload folders")),
                )
                .clicked()
            {
                *command = Some(NativeFileCommand::ListRoots {
                    direction: FileDirection::Write,
                });
            }
            root_choice(
                ui,
                "file-write-root",
                &self.write_roots,
                &mut self.selected_write,
                english,
            );
            ui.label(text(english, "本机要上传的文件", "Local file to upload"));
            ui.text_edit_singleline(&mut self.upload_file);
            self.select_button(
                ui,
                english,
                PickerTarget::UploadFile,
                "选择上传文件",
                "Choose upload file",
            );
            ui.label(text(
                english,
                "远端目录内的相对保存路径",
                "Relative destination path within the remote folder",
            ));
            ui.text_edit_singleline(&mut self.upload_path);
            if ui
                .add_enabled(
                    !self.pending
                        && self.selected_write.is_some()
                        && !self.upload_file.is_empty()
                        && !self.upload_path.is_empty(),
                    egui::Button::new(text(english, "上传此文件", "Upload file")),
                )
                .clicked()
                && let Some(root_id) = &self.selected_write
            {
                *command = Some(NativeFileCommand::Upload {
                    root_id: root_id.clone(),
                    relative_path: self.upload_path.clone(),
                    local_file: self.upload_file.clone(),
                });
            }
        }
    }

    fn select_button(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        target: PickerTarget,
        chinese: &'static str,
        english_text: &'static str,
    ) {
        if ui
            .add_enabled(
                !self.pending && self.picker.is_none(),
                egui::Button::new(text(english, chinese, english_text)),
            )
            .clicked()
        {
            let Some(session) = self.session.clone() else {
                return;
            };
            let kind = match target {
                PickerTarget::UploadFile => SelectionKind::File,
                _ => SelectionKind::Folder,
            };
            match Selector::start(kind) {
                Ok(selector) => {
                    self.picker = Some(PickerJob {
                        session,
                        target,
                        selector,
                    })
                }
                Err(_) => {
                    self.message = Some(
                        text(
                            english,
                            "无法打开系统文件选择器，可输入本机路径。",
                            "The system selector is unavailable; enter a local path.",
                        )
                        .into(),
                    )
                }
            }
        }
    }

    fn poll_picker(&mut self) {
        let Some(job) = self.picker.as_mut() else {
            return;
        };
        let Some(result) = job.selector.poll() else {
            return;
        };
        let Some(job) = self.picker.take() else {
            return;
        };
        if self.session.as_ref() != Some(&job.session) {
            return;
        }
        match result {
            Ok(Some(path)) => self.apply_selection(&job.session, job.target, path),
            Ok(None) => {}
            Err(_) => {
                self.message = Some(
                    "System file selection failed or expired; choose again or enter a local path"
                        .into(),
                )
            }
        }
    }

    fn apply_selection(&mut self, session: &FileSession, target: PickerTarget, path: PathBuf) {
        if self.session.as_ref() != Some(session) {
            return;
        }
        let Some(value) = path.to_str() else { return };
        match target {
            PickerTarget::ShareFolder => {
                self.read_directory = value.into();
                if self.read_label.is_empty() {
                    self.read_label = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("Shared folder")
                        .into();
                }
            }
            PickerTarget::ReceiveParent | PickerTarget::DownloadParent => {
                let area = path.join(format!("NestLink-{}", uuid::Uuid::new_v4().simple()));
                let Some(value) = area.to_str() else { return };
                if matches!(target, PickerTarget::ReceiveParent) {
                    self.write_directory = value.into();
                    if self.write_label.is_empty() {
                        self.write_label = "Receiving folder".into();
                    }
                } else {
                    self.download_directory = value.into();
                }
            }
            PickerTarget::UploadFile => {
                self.upload_file = value.into();
                if self.upload_path.is_empty() {
                    self.upload_path = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("")
                        .into();
                }
            }
        }
        self.message = None;
    }

    fn task_list(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        command: &mut Option<NativeFileCommand>,
    ) {
        for task in &self.tasks {
            ui.horizontal_wrapped(|ui| {
                ui.label(text(
                    english,
                    if task.upload { "上传" } else { "下载" },
                    if task.upload { "Upload" } else { "Download" },
                ));
                ui.label(phase(english, &task.phase));
                ui.label(match task.total_bytes {
                    Some(total) => format!("{} / {} B", task.confirmed_bytes, total),
                    None => format!("{} B", task.confirmed_bytes),
                });
                if !task.finished {
                    if !task.upload
                        && ui
                            .add_enabled(
                                !self.pending && task.phase == "running",
                                egui::Button::new(text(english, "暂停", "Pause")),
                            )
                            .clicked()
                    {
                        *command = Some(NativeFileCommand::Control {
                            task_id: task.task_id.clone(),
                            action: NativeFileTaskAction::Pause,
                        });
                    }
                    if !task.upload
                        && ui
                            .add_enabled(
                                !self.pending && task.phase == "paused",
                                egui::Button::new(text(english, "继续", "Resume")),
                            )
                            .clicked()
                    {
                        *command = Some(NativeFileCommand::Control {
                            task_id: task.task_id.clone(),
                            action: NativeFileTaskAction::Resume,
                        });
                    }
                    if ui
                        .add_enabled(
                            !self.pending,
                            egui::Button::new(text(english, "取消", "Cancel")),
                        )
                        .clicked()
                    {
                        *command = Some(NativeFileCommand::Control {
                            task_id: task.task_id.clone(),
                            action: NativeFileTaskAction::Cancel,
                        });
                    }
                }
            });
            if let Some(error) = &task.error {
                ui.small(error);
            }
        }
    }
}

impl super::DesktopApp {
    pub(crate) fn reconcile_transfer_panels(&mut self, snapshot: &nestlink_app_core::Snapshot) {
        let runtime_id = self.bridge.runtime_id();
        self.recovery_panel.reconcile(runtime_id.clone());
        if self.transfer_runtime != runtime_id {
            self.file_panel.reconcile(None);
            self.clipboard_panel.reconcile(None);
            self.file_submission = None;
            self.clipboard_submission = None;
            self.transfer_runtime = runtime_id.clone();
        }
        let session =
            snapshot.native_session.data.as_ref().filter(|session| {
                session.status == nestlink_app_core::NativeSessionStatus::Connected
            });
        let binding = session.map(|session| NativeSessionBinding {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        });
        let request = session.and_then(|session| {
            snapshot
                .selected_request
                .data
                .as_deref()
                .filter(|request| request.id == session.request_id)
                .or_else(|| {
                    snapshot.requests.data.as_ref().and_then(|requests| {
                        requests
                            .iter()
                            .find(|request| request.id == session.request_id)
                    })
                })
        });
        let files =
            runtime_id
                .zip(binding.clone())
                .zip(request)
                .map(|((runtime_id, binding), request)| FileSession {
                    binding,
                    generation: snapshot.generation,
                    runtime_id,
                    is_host: session.is_some_and(|session| session.host_view_authorized),
                    read: request
                        .permissions
                        .contains(&(nestlink_protocol::Permission::FileRead as i32)),
                    write: request
                        .permissions
                        .contains(&(nestlink_protocol::Permission::FileWrite as i32)),
                });
        self.recovery_panel.reconcile_session(files.as_ref());
        let same_file = self.file_panel.session() == files.as_ref();
        self.file_panel.reconcile(files);
        if !same_file {
            self.file_submission = None;
        }
        self.clipboard_panel
            .reconcile(binding.map(|binding| super::clipboard::ClipboardSession {
                binding,
                generation: snapshot.generation,
            }));
    }
    fn send_recovery_command(
        &mut self,
        generation: u64,
        action: nestlink_protocol::file_recovery::DownloadRecoveryCommand,
    ) {
        self.recovery_panel
            .prepare_submission(generation, &action, self.file_panel.session());
        self.recovery_submission = if self.connected {
            self.bridge.submit_tracked(
                generation,
                nestlink_app_ipc::wire::Command::NativeDownloadRecovery { action },
            )
        } else {
            None
        };
        if self.recovery_submission.is_none() {
            self.recovery_panel.disconnected();
        }
    }

    fn send_file_command(&mut self, command: NativeFileCommand) {
        let Some(session) = self.file_panel.session().cloned() else {
            return;
        };
        self.file_submission = if self.connected {
            self.bridge.submit_tracked(
                session.generation,
                nestlink_app_ipc::wire::Command::NativeFiles {
                    binding: session.binding,
                    action: command,
                },
            )
        } else {
            None
        };
        if self.file_submission.is_none() {
            self.file_panel.disconnected();
        }
    }
    fn send_clipboard_command(
        &mut self,
        generation: u64,
        command: nestlink_app_ipc::wire::Command,
    ) {
        self.clipboard_submission = if self.connected {
            self.bridge.submit_tracked(generation, command)
        } else {
            None
        };
        if self.clipboard_submission.is_none() {
            self.clipboard_panel.disconnected();
        }
    }
    pub(crate) fn poll_transfer_panels(&mut self, snapshot: &nestlink_app_core::Snapshot) {
        if self
            .file_panel
            .pending_since
            .is_some_and(|at| at.elapsed() > Duration::from_secs(10))
        {
            self.file_panel.disconnected();
            self.file_submission = None;
        }
        if !self.connected {
            return;
        }
        if let Some(command) = self.recovery_panel.poll() {
            self.send_recovery_command(snapshot.generation, command);
        }
        if let Some(command) = self.file_panel.poll() {
            self.send_file_command(command);
        }
        if let Some(command) = self.clipboard_panel.poll() {
            self.send_clipboard_command(snapshot.generation, command);
        }
    }
    pub(crate) fn transfer_panels(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &nestlink_app_core::Snapshot,
    ) {
        if !self.connected {
            return;
        }
        if let Some(command) = self
            .recovery_panel
            .show(ui, self.english, self.file_panel.session())
        {
            self.send_recovery_command(snapshot.generation, command);
        }
        if let Some(command) = self.file_panel.show(ui, self.english) {
            self.send_file_command(command);
        }
        if let Some(command) = self.clipboard_panel.show(ui, self.english) {
            self.send_clipboard_command(snapshot.generation, command);
        }
    }
}

fn root_choice(
    ui: &mut egui::Ui,
    id: &str,
    roots: &[FileRootView],
    selected: &mut Option<String>,
    english: bool,
) {
    let label = roots
        .iter()
        .find(|root| selected.as_deref() == Some(root.root_id.as_str()))
        .map(|root| root.display_name.as_str())
        .unwrap_or(text(english, "选择共享目录", "Choose shared folder"));
    egui::ComboBox::from_id_salt(id)
        .selected_text(label)
        .show_ui(ui, |ui| {
            for root in roots {
                ui.selectable_value(selected, Some(root.root_id.clone()), &root.display_name);
            }
        });
}

fn phase(english: bool, value: &str) -> &str {
    match value {
        "queued" => text(english, "排队中", "Queued"),
        "running" => text(english, "传输中", "Transferring"),
        "paused" => text(english, "已暂停", "Paused"),
        "cancelling" => text(english, "正在取消", "Cancelling"),
        "completed" => text(english, "已完成", "Completed"),
        "cancelled" => text(english, "已取消", "Cancelled"),
        "failed" => text(english, "失败", "Failed"),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> FileSession {
        FileSession {
            binding: NativeSessionBinding {
                request_id: "00000000-0000-4000-8000-000000000001".into(),
                connection_generation: 7,
            },
            generation: 3,
            runtime_id: "00000000-0000-4000-8000-000000000002".into(),
            is_host: false,
            read: true,
            write: true,
        }
    }
    fn page(root: &str, name: &str, complete: bool) -> NativeFileReply {
        NativeFileReply::Directory {
            root_id: root.into(),
            directory: "docs".into(),
            browse_id: "browse".into(),
            entries: vec![FileEntryView {
                relative_path: format!("docs/{name}"),
                directory: false,
                size: Some(4),
            }],
            complete,
        }
    }

    #[test]
    fn file_panel_rejects_old_request_connection_and_core_replies() {
        let current = session();
        let mut panel = FilePanel::default();
        panel.reconcile(Some(current.clone()));
        panel.selected_read = Some("root".into());
        panel.browse_directory = "docs".into();
        let mut old = current.binding.clone();
        old.request_id = "00000000-0000-4000-8000-000000000003".into();
        panel.apply(current.generation, &old, page("root", "old-request", true));
        old = current.binding.clone();
        old.connection_generation -= 1;
        panel.apply(
            current.generation,
            &old,
            page("root", "old-connection", true),
        );
        panel.apply(
            current.generation - 1,
            &current.binding,
            page("root", "old-core", true),
        );
        panel.apply(
            current.generation,
            &current.binding,
            page("different-root", "old-selection", true),
        );
        assert!(panel.entries.is_empty());
        assert!(panel.browse_id.is_none());
    }

    #[test]
    fn directory_pages_accumulate_and_daemon_restart_clears_selected_paths() {
        let current = session();
        let mut panel = FilePanel::default();
        panel.reconcile(Some(current.clone()));
        panel.selected_read = Some("root".into());
        panel.browse_directory = "docs".into();
        panel.apply(
            current.generation,
            &current.binding,
            page("root", "first.txt", false),
        );
        panel.apply(
            current.generation,
            &current.binding,
            page("root", "second.txt", true),
        );
        assert_eq!(panel.entries.len(), 2);
        assert!(panel.browse_complete);
        panel.upload_file = "private local path".into();
        let mut restarted = current;
        restarted.runtime_id = "00000000-0000-4000-8000-000000000004".into();
        panel.reconcile(Some(restarted));
        assert!(panel.entries.is_empty());
        assert!(panel.upload_file.is_empty());
        assert!(panel.browse_id.is_none());
    }

    #[test]
    fn picker_results_cannot_cross_session_or_daemon_identity() {
        let previous = session();
        let path = std::env::temp_dir().join("private-local-selection.txt");
        for changed in 0..4 {
            let mut current = previous.clone();
            match changed {
                0 => current.binding.request_id = "replacement-request".into(),
                1 => current.binding.connection_generation += 1,
                2 => current.generation += 1,
                _ => current.runtime_id = "replacement-daemon".into(),
            }
            let mut panel = FilePanel::default();
            panel.reconcile(Some(current));
            panel.apply_selection(&previous, PickerTarget::UploadFile, path.clone());
            assert!(panel.upload_file.is_empty());
            assert!(panel.upload_path.is_empty());
        }
        let mut panel = FilePanel::default();
        panel.reconcile(Some(previous.clone()));
        panel.apply_selection(&previous, PickerTarget::UploadFile, path.clone());
        assert_eq!(panel.upload_file, path.to_string_lossy());
        assert_eq!(panel.upload_path, "private-local-selection.txt");
        assert!(!panel.pending); // A choice never submits/authorizes a transfer.
    }
}
