//! Local approval UI for one proved browser-host session.
use crate::picker::Selector;
use eframe::egui;
use nestlink_app_core::{BrowserHostBinding, BrowserHostDataView};
use nestlink_app_ipc::{
    browser_data::{BrowserHostDataCommand, BrowserHostDataReply},
    files::{FileDirection, LocalReadRootSelection, LocalWriteRootSelection},
};
use nestlink_platform_files::selection::SelectionKind;
use std::{io, path::PathBuf};

#[derive(Clone, PartialEq, Eq)]
struct Session {
    binding: BrowserHostBinding,
    generation: u64,
}
#[derive(Clone, Copy)]
enum PickerTarget {
    ReadRoot,
    WriteParent,
}
struct PickerJob {
    session: Session,
    target: PickerTarget,
    selector: Box<dyn FolderPicker>,
    retired: bool,
}
impl PickerJob {
    fn retire(&mut self) {
        self.retired = true;
        self.selector.cancel();
    }
}
trait FolderPicker {
    fn poll(&mut self) -> Option<io::Result<Option<PathBuf>>>;
    fn cancel(&mut self);
}
impl FolderPicker for Selector {
    fn poll(&mut self) -> Option<io::Result<Option<PathBuf>>> {
        Selector::poll(self)
    }
    fn cancel(&mut self) {
        Selector::cancel(self);
    }
}

#[derive(Default)]
pub(crate) struct BrowserDataPanel {
    session: Option<Session>,
    read_directory: String,
    read_label: String,
    disclose_directory: bool,
    write_parent: String,
    write_label: String,
    clipboard_read: bool,
    clipboard_write: bool,
    last_clipboard: Option<(bool, bool)>,
    pending_submission: Option<u64>,
    message: Option<String>,
    picker: Option<PickerJob>,
}

fn text(english: bool, chinese: &'static str, english_text: &'static str) -> &'static str {
    if english { english_text } else { chinese }
}

impl BrowserDataPanel {
    pub(crate) fn reconcile(
        &mut self,
        binding: Option<BrowserHostBinding>,
        generation: u64,
        data: Option<&BrowserHostDataView>,
    ) -> bool {
        let next = binding.map(|binding| Session {
            binding,
            generation,
        });
        let session_changed = self.session != next;
        if session_changed {
            let picker = self.picker.take().map(|mut picker| {
                picker.retire();
                picker
            });
            *self = Self {
                session: next,
                picker,
                ..Self::default()
            };
        }
        if let Some(data) = data {
            let clipboard = (data.local_clipboard_read, data.local_clipboard_write);
            if self.last_clipboard != Some(clipboard) {
                self.clipboard_read = clipboard.0;
                self.clipboard_write = clipboard.1;
                self.last_clipboard = Some(clipboard);
            }
        }
        self.poll_picker();
        session_changed
    }

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        english: bool,
        data: &BrowserHostDataView,
    ) -> Option<BrowserHostDataCommand> {
        let session = self.session.clone()?;
        let mut command = None;
        ui.separator();
        ui.label(
            egui::RichText::new(text(english, "本机数据批准", "Local data approvals")).strong(),
        );
        ui.small(text(english,
            "仅此浏览器会话有效。共享目录默认为空；剪贴板按方向单独批准。",
            "These approvals apply only to this browser session. Shared folders start empty, and clipboard directions are approved separately."));

        if data.permitted_file_read && data.files_available {
            ui.separator();
            ui.label(text(
                english,
                "允许对方读取的目录",
                "Folders the peer may read",
            ));
            for root in &data.read_roots {
                ui.horizontal(|ui| {
                    ui.label(format!("{} · {}", root.display_name, root.root_id));
                    if ui
                        .add_enabled(
                            self.pending_submission.is_none(),
                            egui::Button::new(text(english, "撤销", "Revoke")),
                        )
                        .clicked()
                    {
                        command = Some(BrowserHostDataCommand::RevokeRoot {
                            direction: FileDirection::Read,
                            root_id: root.root_id.clone(),
                        });
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.read_directory);
                if ui
                    .add_enabled(
                        self.pending_submission.is_none() && self.picker.is_none(),
                        egui::Button::new(text(english, "选择目录…", "Choose folder…")),
                    )
                    .clicked()
                {
                    self.start_picker(session.clone(), PickerTarget::ReadRoot);
                }
            });
            ui.horizontal(|ui| {
                ui.label(text(english, "对方看到的名称", "Name shown to peer"));
                ui.text_edit_singleline(&mut self.read_label);
            });
            ui.checkbox(
                &mut self.disclose_directory,
                text(
                    english,
                    "另行允许浏览目录内容",
                    "Also allow browsing the folder",
                ),
            );
            if ui
                .add_enabled(
                    self.pending_submission.is_none()
                        && !self.read_directory.is_empty()
                        && !self.read_label.is_empty(),
                    egui::Button::new(text(english, "批准此目录", "Approve folder")),
                )
                .clicked()
            {
                command = Some(BrowserHostDataCommand::SelectReadRoots {
                    roots: vec![LocalReadRootSelection {
                        directory: self.read_directory.clone(),
                        display_name: self.read_label.clone(),
                        disclose_directory: self.disclose_directory,
                    }],
                });
            }
        }

        if data.permitted_file_write && data.files_available {
            ui.separator();
            ui.label(text(
                english,
                "允许对方上传到的新目录",
                "New folders available for peer uploads",
            ));
            for root in &data.write_roots {
                ui.horizontal(|ui| {
                    ui.label(format!("{} · {}", root.display_name, root.root_id));
                    if ui
                        .add_enabled(
                            self.pending_submission.is_none(),
                            egui::Button::new(text(english, "撤销", "Revoke")),
                        )
                        .clicked()
                    {
                        command = Some(BrowserHostDataCommand::RevokeRoot {
                            direction: FileDirection::Write,
                            root_id: root.root_id.clone(),
                        });
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.write_parent);
                if ui
                    .add_enabled(
                        self.pending_submission.is_none() && self.picker.is_none(),
                        egui::Button::new(text(english, "选择父目录…", "Choose parent…")),
                    )
                    .clicked()
                {
                    self.start_picker(session.clone(), PickerTarget::WriteParent);
                }
            });
            ui.horizontal(|ui| {
                ui.label(text(
                    english,
                    "新目录的显示名称",
                    "Name shown for the new folder",
                ));
                ui.text_edit_singleline(&mut self.write_label);
            });
            ui.small(text(
                english,
                "NestLink 会在所选父目录中创建一个新的唯一接收目录。",
                "NestLink creates a new unique receiving folder inside the selected parent.",
            ));
            if ui
                .add_enabled(
                    self.pending_submission.is_none()
                        && !self.write_parent.is_empty()
                        && !self.write_label.is_empty(),
                    egui::Button::new(text(english, "批准接收目录", "Approve receiving folder")),
                )
                .clicked()
            {
                let fresh = PathBuf::from(&self.write_parent)
                    .join(format!("NestLink-{}", uuid::Uuid::new_v4().simple()));
                if let Some(fresh_directory) = fresh.to_str() {
                    command = Some(BrowserHostDataCommand::SelectWriteRoots {
                        roots: vec![LocalWriteRootSelection {
                            fresh_directory: fresh_directory.to_owned(),
                            display_name: self.write_label.clone(),
                        }],
                    });
                }
            }
        }

        if data.permitted_clipboard_read || data.permitted_clipboard_write {
            ui.separator();
            ui.label(text(
                english,
                "本机剪贴板方向",
                "Local clipboard directions",
            ));
            if !data.clipboard_available {
                ui.small(text(english, "当前桌面会话无法为浏览器会话提供剪贴板授权。", "The current desktop session cannot grant clipboard access to a browser session."));
            } else {
                if data.permitted_clipboard_read {
                    ui.add_enabled_ui(
                        self.pending_submission.is_none()
                            && (!data.clipboard_restart_required || data.local_clipboard_read),
                        |ui| {
                            ui.checkbox(
                                &mut self.clipboard_read,
                                text(
                                    english,
                                    "允许对方读取本机剪贴板",
                                    "Allow the peer to read this clipboard",
                                ),
                            );
                        },
                    );
                }
                if data.permitted_clipboard_write {
                    ui.add_enabled_ui(
                        self.pending_submission.is_none()
                            && (!data.clipboard_restart_required || data.local_clipboard_write),
                        |ui| {
                            ui.checkbox(
                                &mut self.clipboard_write,
                                text(
                                    english,
                                    "允许对方向本机剪贴板写入",
                                    "Allow the peer to write to this clipboard",
                                ),
                            );
                        },
                    );
                }
                if data.clipboard_restart_required {
                    ui.small(text(
                        english,
                        "撤销后不能在此会话重新启用剪贴板方向。",
                        "After revocation, clipboard access requires a new browser session.",
                    ));
                }
                if (self.clipboard_read, self.clipboard_write)
                    != (data.local_clipboard_read, data.local_clipboard_write)
                    && ui
                        .add_enabled(
                            self.pending_submission.is_none(),
                            egui::Button::new(text(
                                english,
                                "应用剪贴板批准",
                                "Apply clipboard approval",
                            )),
                        )
                        .clicked()
                {
                    command = Some(BrowserHostDataCommand::SetClipboardDirections {
                        read: self.clipboard_read,
                        write: self.clipboard_write,
                    });
                }
            }
        }
        if let Some(message) = &self.message {
            ui.small(message);
        }
        if self.pending_submission.is_some() {
            ui.small(text(
                english,
                "正在等待本机守护进程确认…",
                "Waiting for the local daemon…",
            ));
        }
        command
    }

    pub(crate) fn submitted(&mut self, submission_id: u64) {
        self.pending_submission = Some(submission_id);
        self.message = None;
    }

    pub(crate) fn apply_reply(
        &mut self,
        binding: &BrowserHostBinding,
        generation: u64,
        submission_id: u64,
        reply: BrowserHostDataReply,
    ) -> bool {
        let current =
            self.session.as_ref().is_some_and(|session| {
                session.generation == generation && &session.binding == binding
            }) && self.pending_submission == Some(submission_id);
        if !current {
            return false;
        }
        self.pending_submission = None;
        self.message = match reply {
            BrowserHostDataReply::Applied { .. } => {
                Some("Local approval updated for this browser session.".into())
            }
            BrowserHostDataReply::Refused { reason } => Some(reason),
        };
        true
    }

    pub(crate) fn disconnected(&mut self) {
        let picker = self.picker.take().map(|mut picker| {
            picker.retire();
            picker
        });
        *self = Self {
            picker,
            ..Self::default()
        };
    }

    pub(crate) fn rejected(&mut self, submission_id: u64, reason: &str) {
        if self.pending_submission != Some(submission_id) {
            return;
        }
        self.pending_submission = None;
        self.message = Some(reason.to_owned());
    }

    pub(crate) fn rejected_before_submit(&mut self, reason: &str) {
        if self.pending_submission.is_none() {
            self.message = Some(reason.to_owned());
        }
    }

    fn start_picker(&mut self, session: Session, target: PickerTarget) {
        match Selector::start(SelectionKind::Folder) {
            Ok(selector) => {
                self.picker = Some(PickerJob {
                    session,
                    target,
                    selector: Box::new(selector),
                    retired: false,
                })
            }
            Err(_) => {
                self.message =
                    Some("System folder selection is unavailable; enter a local path.".into())
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
        if job.retired || self.session.as_ref() != Some(&job.session) {
            return;
        }
        match result {
            Ok(Some(path)) => {
                if let Some(value) = path.to_str() {
                    match job.target {
                        PickerTarget::ReadRoot => {
                            self.read_directory = value.into();
                            if self.read_label.is_empty() {
                                self.read_label = path
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("Shared folder")
                                    .into();
                            }
                        }
                        PickerTarget::WriteParent => {
                            self.write_parent = value.into();
                            if self.write_label.is_empty() {
                                self.write_label = "Receiving folder".into();
                            }
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(_) => self.message = Some(
                "System folder selection failed or expired; choose again or enter a local path."
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    fn binding(request_id: &str) -> BrowserHostBinding {
        BrowserHostBinding {
            request_id: request_id.into(),
            session_id: format!("session-{request_id}"),
            controller_device_id: "controller".into(),
            host_device_id: "host".into(),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [3; 32],
            connection_generation: 7,
        }
    }

    struct FakePicker {
        cancelled: Arc<AtomicBool>,
        complete: Arc<AtomicBool>,
    }
    impl FolderPicker for FakePicker {
        fn poll(&mut self) -> Option<io::Result<Option<PathBuf>>> {
            self.complete
                .load(Ordering::Acquire)
                .then(|| Ok(Some(PathBuf::from("C:\\stale-picker-result"))))
        }

        fn cancel(&mut self) {
            self.cancelled.store(true, Ordering::Release);
        }
    }

    #[test]
    fn session_change_cancels_but_retains_picker_until_its_terminal_result() {
        let old_binding = binding("old");
        let new_binding = binding("new");
        let cancelled = Arc::new(AtomicBool::new(false));
        let complete = Arc::new(AtomicBool::new(false));
        let mut panel = BrowserDataPanel {
            session: Some(Session {
                binding: old_binding.clone(),
                generation: 3,
            }),
            picker: Some(PickerJob {
                session: Session {
                    binding: old_binding,
                    generation: 3,
                },
                target: PickerTarget::ReadRoot,
                selector: Box::new(FakePicker {
                    cancelled: cancelled.clone(),
                    complete: complete.clone(),
                }),
                retired: false,
            }),
            ..BrowserDataPanel::default()
        };

        panel.reconcile(Some(new_binding.clone()), 4, None);
        assert!(cancelled.load(Ordering::Acquire));
        assert!(panel.picker.is_some(), "old Child owner remains retained");
        assert!(panel.read_directory.is_empty());

        panel.reconcile(Some(new_binding.clone()), 4, None);
        assert!(
            panel.picker.is_some(),
            "a replacement waits for old termination"
        );
        complete.store(true, Ordering::Release);
        panel.reconcile(Some(new_binding), 4, None);
        assert!(panel.picker.is_none());
        assert!(
            panel.read_directory.is_empty(),
            "retired results are discarded"
        );
    }

    #[test]
    fn only_the_receipt_for_the_pending_binding_generation_and_submission_releases_it() {
        let expected = binding("current");
        let mut panel = BrowserDataPanel {
            session: Some(Session {
                binding: expected.clone(),
                generation: 9,
            }),
            pending_submission: Some(24),
            ..BrowserDataPanel::default()
        };

        panel.apply_reply(
            &binding("other"),
            9,
            24,
            BrowserHostDataReply::Refused {
                reason: "wrong binding".into(),
            },
        );
        panel.apply_reply(
            &expected,
            8,
            24,
            BrowserHostDataReply::Refused {
                reason: "wrong generation".into(),
            },
        );
        panel.apply_reply(
            &expected,
            9,
            23,
            BrowserHostDataReply::Refused {
                reason: "wrong submission".into(),
            },
        );
        assert_eq!(panel.pending_submission, Some(24));

        panel.apply_reply(
            &expected,
            9,
            24,
            BrowserHostDataReply::Refused {
                reason: "daemon refused".into(),
            },
        );
        assert_eq!(panel.pending_submission, None);
        assert_eq!(panel.message.as_deref(), Some("daemon refused"));
    }

    #[test]
    fn disconnect_is_the_only_local_event_that_clears_an_unanswered_submission() {
        let mut panel = BrowserDataPanel {
            session: Some(Session {
                binding: binding("current"),
                generation: 9,
            }),
            pending_submission: Some(24),
            ..BrowserDataPanel::default()
        };
        panel.disconnected();
        assert_eq!(panel.pending_submission, None);
        assert!(panel.session.is_none());
    }
}
