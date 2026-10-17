//! UI-only rendering of daemon-owned restart facts. Every resume is a new click
//! under the current file session; a row or saved progress grants no authority.
use super::{FileSession, text};
use crate::picker::Selector;
use eframe::egui;
use nestlink_platform_files::selection::SelectionKind;
use nestlink_protocol::file_recovery::{
    DownloadRecoveryCommand, DownloadRecoveryReply, DownloadRecoveryView,
};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct RecoveryPanel {
    runtime: Option<String>,
    session: Option<FileSession>,
    resume_session: Option<FileSession>,
    tasks: Vec<DownloadRecoveryView>,
    reserved_bytes: u64,
    pending: Option<Instant>,
    refresh: Option<Instant>,
    message: Option<String>,
    approved: Option<String>,
    export_task: Option<String>,
    export_directory: String,
    export_name: String,
    acknowledge_partial: bool,
    picker: Option<Selector>,
}

impl RecoveryPanel {
    pub(crate) fn reconcile(&mut self, runtime: Option<String>) {
        if self.runtime != runtime {
            *self = Self {
                runtime,
                ..Self::default()
            };
        }
    }
    pub(crate) fn reconcile_session(&mut self, session: Option<&FileSession>) {
        if self.session.as_ref() != session {
            self.session = session.cloned();
            self.approved = None;
            // A return to an equal session value cannot revive an old reply.
            // Local List/Cancel/Export acknowledgements remain session-free.
            if self.resume_session.take().is_some() {
                self.pending = None;
                self.refresh = Some(Instant::now());
            }
        }
    }
    pub(crate) fn prepare_submission(
        &mut self,
        generation: u64,
        command: &DownloadRecoveryCommand,
        session: Option<&FileSession>,
    ) {
        self.reconcile_session(session);
        self.resume_session = match command {
            DownloadRecoveryCommand::Resume {
                request_id,
                connection_generation,
                approve_local_resume: true,
                ..
            } => session
                .filter(|value| {
                    value.generation == generation
                        && value.binding.request_id == *request_id
                        && value.binding.connection_generation == *connection_generation
                        && value.read
                        && !value.is_host
                })
                .cloned(),
            _ => None,
        };
        self.pending = Some(Instant::now());
    }
    pub(crate) fn apply(&mut self, reply: DownloadRecoveryReply) -> Option<String> {
        let resume_session = self.resume_session.take();
        self.pending = None;
        self.refresh = Some(Instant::now() + Duration::from_secs(2));
        match reply {
            DownloadRecoveryReply::Tasks {
                tasks,
                reserved_bytes,
            } => {
                if tasks.len() > nestlink_protocol::file_recovery::DOWNLOAD_RECOVERY_TASKS {
                    self.message = Some("Persistent task display capacity exceeded".into());
                    return None;
                }
                if self.approved.as_ref().is_some_and(|id| {
                    !tasks.iter().any(|task| {
                        &task.task_id == id
                            && task.phase == "waiting_for_approval"
                            && !task.owner_active
                            && !task.temporary_removed
                    })
                }) {
                    self.approved = None;
                }
                if self.export_task.as_ref().is_some_and(|id| {
                    !tasks.iter().any(|task| {
                        &task.task_id == id
                            && !task.owner_active
                            && !task.temporary_removed
                            && task.last_export.is_none()
                    })
                }) {
                    self.export_task = None;
                    self.acknowledge_partial = false;
                }
                self.tasks = tasks;
                self.reserved_bytes = reserved_bytes;
            }
            DownloadRecoveryReply::Resumed { task_id, .. } => {
                if resume_session
                    .as_ref()
                    .is_none_or(|submitted| self.session.as_ref() != Some(submitted))
                {
                    self.message = Some("Recovery acknowledgement belongs to a previous file session. Refresh task facts to see its current state.".into());
                    self.refresh = Some(Instant::now());
                    return None;
                }
                self.message = Some("Recovery was queued under the newly approved session; file verification is still pending".into());
                self.refresh = Some(Instant::now());
                return Some(task_id);
            }
            DownloadRecoveryReply::Refused { reason } => self.message = Some(reason),
        }
        None
    }
    pub(crate) fn disconnected(&mut self) {
        self.resume_session = None;
        self.pending = None;
        self.approved = None;
        self.session = None;
        self.acknowledge_partial = false;
        self.export_task = None;
        self.picker = None;
        self.message =
            Some("Recovery acknowledgement was lost. Refresh task facts before retrying.".into());
        self.refresh = Some(Instant::now() + Duration::from_secs(2));
    }
    pub(crate) fn poll(&mut self) -> Option<DownloadRecoveryCommand> {
        if self
            .pending
            .is_some_and(|at| at.elapsed() > Duration::from_secs(10))
        {
            self.disconnected();
        }
        if let Some(selector) = self.picker.as_mut()
            && let Some(result) = selector.poll()
        {
            self.picker = None;
            match result {
                Ok(Some(path)) => {
                    self.export_directory = path
                        .join(format!(
                            "NestLink-partial-{}",
                            uuid::Uuid::new_v4().simple()
                        ))
                        .to_string_lossy()
                        .into();
                }
                Ok(None) => {}
                Err(_) => {
                    self.message = Some(
                        "System selector failed; choose again or enter a new private folder path"
                            .into(),
                    )
                }
            }
        }
        if self.runtime.is_some()
            && self.pending.is_none()
            && self.refresh.is_none_or(|at| Instant::now() >= at)
        {
            self.pending = Some(Instant::now());
            return Some(DownloadRecoveryCommand::List);
        }
        None
    }
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        session: Option<&FileSession>,
    ) -> Option<DownloadRecoveryCommand> {
        self.reconcile_session(session);
        let mut command = None;
        let can_resume = session.is_some_and(|value| value.read && !value.is_host);
        egui::CollapsingHeader::new(text(english, "中断的下载与本机恢复", "Interrupted downloads and local recovery"))
            .id_salt("native-download-restart-recovery").show(ui, |ui| {
                ui.label(text(english,
                    "两端重新批准文件会话，主机再次选择共享目录后，再同意恢复此任务。",
                    "Approve a new file session on both devices, reselect the shared folder on the host, then approve this task again."));
                ui.label(format!("{} B {}", self.reserved_bytes, text(english, "暂存预算已占用", "of staging budget reserved")));
                if ui.add_enabled(self.pending.is_none(), egui::Button::new(text(english, "刷新任务", "Refresh tasks"))).clicked() {
                    command = Some(DownloadRecoveryCommand::List);
                }
                for task in &self.tasks {
                    ui.separator();
                    ui.label(format!("{} — {} / {} B", task.local_name, task.checkpoint_bytes, task.total_bytes));
                    ui.small(format!("{} · {}", task.remote_path, task.host_device_id));
                    ui.label(match task.phase.as_str() {
                        "waiting_for_approval" => text(english, "等待重新批准", "Waiting for new approval"),
                        "publication_needs_review" => text(english, "发布中断，需核对完整文件与清理", "Publication interrupted; reconcile the complete file and cleanup"),
                        "active" => text(english, "当前进程拥有此任务", "Owned by the current process"),
                        "published" => text(english, "完整文件已保存", "Complete local file saved"),
                        "cancelled" => text(english, "暂存文件已移除", "Staged file removed"),
                        "failed" => text(english, "下载失败，暂存文件已移除", "Download failed; staging was removed"),
                        _ => text(english, "清理仍需处理，预算继续保留", "Cleanup needs attention; reservation is retained"),
                    });
                    if let Some(error) = &task.error { ui.small(error); }
                    if let Some(error) = &task.cleanup_error { ui.small(error); }
                    if let Some(export) = &task.last_export { ui.small(export); }
                    let cleanup_pending = !task.temporary_removed || task.last_export.as_ref().is_some_and(|value| value.contains("cleanup_pending"));
                    if task.owner_active || !cleanup_pending { continue; }
                    let mut approved = self.approved.as_deref() == Some(task.task_id.as_str());
                    if ui.add_enabled(self.pending.is_none() && can_resume && task.phase == "waiting_for_approval", egui::Checkbox::new(&mut approved,
                        text(english, "我同意在当前新会话中恢复此文件", "I approve resuming this file in the current new session"))).changed() {
                        self.approved = approved.then(|| task.task_id.clone());
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(self.pending.is_none() && approved && can_resume && task.phase == "waiting_for_approval",
                            egui::Button::new(text(english, "验证前缀并恢复", "Verify prefix and resume"))).clicked()
                            && let Some(session) = session {
                            command = Some(DownloadRecoveryCommand::Resume { task_id: task.task_id.clone(), request_id: session.binding.request_id.clone(),
                                connection_generation: session.binding.connection_generation, approve_local_resume: true });
                        }
                        if ui.add_enabled(self.pending.is_none(), egui::Button::new(text(english, "核对并清理暂存", "Reconcile and remove staging"))).clicked() {
                            command = Some(DownloadRecoveryCommand::Cancel { task_id: task.task_id.clone() });
                        }
                        if ui.add_enabled(self.pending.is_none() && task.last_export.is_none(), egui::Button::new(text(english, "另存已确认的部分", "Export confirmed partial"))).clicked() {
                            self.export_task = Some(task.task_id.clone());
                            self.export_name = format!("{}.partial", task.local_name);
                            self.acknowledge_partial = false;
                        }
                    });
                }
                if let Some(task_id) = self.export_task.clone() {
                    ui.separator();
                    ui.label(text(english, "导出目标必须是全新目录；这只是未完成的部分文件。", "Choose a new destination folder. This export is an incomplete partial file."));
                    ui.text_edit_singleline(&mut self.export_directory);
                    if ui.add_enabled(self.pending.is_none() && self.picker.is_none(), egui::Button::new(text(english, "选择目标位置", "Choose destination"))).clicked() {
                        match Selector::start(SelectionKind::Folder) {
                            Ok(selector) => self.picker = Some(selector),
                            Err(_) => self.message = Some("System selector unavailable; enter a new local folder path".into()),
                        }
                    }
                    ui.text_edit_singleline(&mut self.export_name);
                    ui.checkbox(&mut self.acknowledge_partial, text(english, "我知道这个部分文件并未完成下载", "I understand this partial file is not a completed download"));
                    if ui.add_enabled(self.pending.is_none() && self.acknowledge_partial && !self.export_directory.is_empty()
                        && self.export_name.ends_with(".partial"), egui::Button::new(text(english, "导出部分文件", "Export partial"))).clicked() {
                        command = Some(DownloadRecoveryCommand::ExportPartial { task_id, fresh_directory: self.export_directory.clone(),
                            local_name: self.export_name.clone(), acknowledge_partial: true });
                        self.export_task = None;
                    }
                }
                if let Some(message) = &self.message { ui.label(message); }
                if self.picker.is_some() {
                    ui.label(text(english, "等待系统文件选择器", "Waiting for the system file selector"));
                    if ui.button(text(english, "取消选择", "Cancel selection")).clicked() { self.picker = None; }
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
                ui.small(text(english, "上传任务重启后须重新发起；没有可恢复的远端上传授权。", "Restarted uploads must be started again; no remote upload authority is retained."));
            });
        if command.is_some() {
            self.pending = Some(Instant::now());
            self.approved = None;
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(generation: u64) -> FileSession {
        FileSession {
            binding: nestlink_app_core::NativeSessionBinding {
                request_id: "00000000-0000-4000-8000-000000000001".into(),
                connection_generation: generation,
            },
            generation,
            runtime_id: "runtime".into(),
            is_host: false,
            read: true,
            write: false,
        }
    }
    fn waiting() -> DownloadRecoveryView {
        DownloadRecoveryView {
            task_id: "00000000-0000-4000-8000-000000000002".into(),
            local_name: "saved".into(),
            remote_path: "source".into(),
            host_device_id: "00000000-0000-4000-8000-000000000003".into(),
            checkpoint_bytes: 3,
            total_bytes: 8,
            phase: "waiting_for_approval".into(),
            owner_active: false,
            published: false,
            temporary_removed: false,
            file_synced: true,
            directory_synced: false,
            error: None,
            cleanup_error: None,
            last_export: None,
        }
    }
    #[test]
    fn automatic_fact_refresh_preserves_one_current_session_approval_and_rebinding_clears_it() {
        let mut panel = RecoveryPanel::default();
        let first = session(9);
        panel.reconcile_session(Some(&first));
        panel.approved = Some(waiting().task_id);
        assert!(
            panel
                .apply(DownloadRecoveryReply::Tasks {
                    tasks: vec![waiting()],
                    reserved_bytes: 8
                })
                .is_none()
        );
        assert_eq!(panel.approved.as_deref(), Some(waiting().task_id.as_str()));
        panel.reconcile_session(Some(&session(10)));
        assert!(panel.approved.is_none());
        panel.approved = Some(waiting().task_id);
        assert!(
            panel
                .apply(DownloadRecoveryReply::Tasks {
                    tasks: vec![],
                    reserved_bytes: 0
                })
                .is_none()
        );
        assert!(panel.approved.is_none());
    }

    fn resume(session: &FileSession) -> DownloadRecoveryCommand {
        DownloadRecoveryCommand::Resume {
            task_id: waiting().task_id,
            request_id: session.binding.request_id.clone(),
            connection_generation: session.binding.connection_generation,
            approve_local_resume: true,
        }
    }

    fn resumed(task_id: &str) -> DownloadRecoveryReply {
        DownloadRecoveryReply::Resumed {
            recovery_id: waiting().task_id,
            task_id: task_id.into(),
        }
    }

    #[test]
    fn late_resume_reply_after_request_or_connection_change_cannot_enter_current_file_tasks() {
        for replace_request in [true, false] {
            let previous = session(9);
            let mut current = previous.clone();
            if replace_request {
                current.binding.request_id = "00000000-0000-4000-8000-000000000004".into();
            } else {
                current.binding.connection_generation += 1;
            }
            assert_eq!(current.generation, previous.generation);
            assert_eq!(current.runtime_id, previous.runtime_id);

            let mut panel = RecoveryPanel::default();
            let mut files = super::super::FilePanel::default();
            panel.reconcile(Some(previous.runtime_id.clone()));
            panel.reconcile_session(Some(&previous));
            files.reconcile(Some(previous.clone()));
            panel.prepare_submission(previous.generation, &resume(&previous), files.session());
            assert!(panel.pending.is_some());

            // notices() reconciles both real panels to the latest snapshot
            // before consuming a response. The outer generation/runtime and
            // submission-ID fences still accept this old response.
            panel.reconcile_session(Some(&current));
            files.reconcile(Some(current.clone()));
            assert!(panel.pending.is_none());
            if let Some(task_id) = panel.apply(resumed("old-live-task")) {
                files.track_recovered(task_id);
            }
            assert!(files.tasks.is_empty());
            assert!(files.poll().is_none());
            assert!(matches!(panel.poll(), Some(DownloadRecoveryCommand::List)));

            // A newly submitted Resume for this exact current session still
            // enters the normal live task polling path.
            panel.prepare_submission(current.generation, &resume(&current), files.session());
            if let Some(task_id) = panel.apply(resumed("new-live-task")) {
                files.track_recovered(task_id);
            }
            assert_eq!(files.tasks.len(), 1);
            assert!(
                matches!(files.poll(), Some(nestlink_app_ipc::files::NativeFileCommand::Task { task_id }) if task_id == "new-live-task")
            );
        }
    }

    #[test]
    fn native_disconnect_or_acknowledgement_loss_cannot_revive_an_old_resume_reply() {
        for daemon_disconnected in [false, true] {
            let current = session(9);
            let mut panel = RecoveryPanel::default();
            let mut files = super::super::FilePanel::default();
            panel.reconcile(Some(current.runtime_id.clone()));
            panel.reconcile_session(Some(&current));
            files.reconcile(Some(current.clone()));
            panel.prepare_submission(current.generation, &resume(&current), files.session());
            if daemon_disconnected {
                panel.disconnected();
            } else {
                panel.reconcile_session(None);
            }
            files.reconcile(None);
            // Even returning to an equal value must not revive the invalidated
            // submission. Real reconnects will usually also get a new binding.
            panel.reconcile_session(Some(&current));
            files.reconcile(Some(current));
            if let Some(task_id) = panel.apply(resumed("lost-live-task")) {
                files.track_recovered(task_id);
            }
            assert!(files.tasks.is_empty());
            assert!(files.poll().is_none());
            assert!(matches!(panel.poll(), Some(DownloadRecoveryCommand::List)));
        }
    }

    #[test]
    fn local_fact_cleanup_and_export_replies_work_across_native_session_loss_and_offline() {
        let commands = [
            DownloadRecoveryCommand::List,
            DownloadRecoveryCommand::Cancel {
                task_id: waiting().task_id,
            },
            DownloadRecoveryCommand::ExportPartial {
                task_id: waiting().task_id,
                fresh_directory: "new-private-export-directory".into(),
                local_name: "saved.partial".into(),
                acknowledge_partial: true,
            },
        ];
        for command in commands {
            let current = session(9);
            let mut panel = RecoveryPanel::default();
            panel.reconcile(Some(current.runtime_id.clone()));
            panel.prepare_submission(current.generation, &command, Some(&current));
            panel.reconcile_session(None);
            assert!(panel.pending.is_some());
            assert!(
                panel
                    .apply(DownloadRecoveryReply::Tasks {
                        tasks: vec![waiting()],
                        reserved_bytes: 8
                    })
                    .is_none()
            );
            assert_eq!(panel.tasks.len(), 1);
            assert_eq!(panel.reserved_bytes, 8);
            assert!(panel.pending.is_none());

            panel.prepare_submission(current.generation, &command, None);
            assert!(
                panel
                    .apply(DownloadRecoveryReply::Tasks {
                        tasks: vec![],
                        reserved_bytes: 0
                    })
                    .is_none()
            );
            assert!(panel.tasks.is_empty());
            assert_eq!(panel.reserved_bytes, 0);
            assert!(panel.session.is_none());
        }
    }

    #[test]
    fn resumed_without_a_current_resume_submission_cannot_create_a_live_task() {
        let current = session(9);
        let mut panel = RecoveryPanel::default();
        panel.reconcile(Some(current.runtime_id.clone()));
        panel.reconcile_session(Some(&current));
        panel.prepare_submission(
            current.generation,
            &DownloadRecoveryCommand::List,
            Some(&current),
        );
        assert!(panel.apply(resumed("unsolicited-live-task")).is_none());
        assert!(matches!(panel.poll(), Some(DownloadRecoveryCommand::List)));
    }
}
