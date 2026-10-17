//! Local, explicit clipboard controls for one current native session.
//! This panel never reads clipboard text; actions are one-shot commands only.
use eframe::egui;
use nestlink_app_core::{
    NativeClipboardAction, NativeClipboardBinding, NativeClipboardEffect, NativeClipboardEndpoint,
    NativeClipboardStatus, NativeSessionBinding,
};
use nestlink_app_ipc::wire::{Command, NativeClipboardRejection, Reply};
use std::time::{Duration, Instant};

const STATUS_POLL: Duration = Duration::from_secs(1);
const PENDING_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClipboardSession {
    pub generation: u64,
    pub binding: NativeSessionBinding,
}

enum Pending {
    Status,
    Directions(NativeClipboardBinding),
    Action(NativeClipboardBinding),
}

#[derive(Clone, Debug)]
struct DirectionDraft {
    binding: NativeClipboardBinding,
    read: bool,
    write: bool,
}

#[derive(Default)]
pub(crate) struct ClipboardPanel {
    session: Option<ClipboardSession>,
    status: Option<NativeClipboardStatus>,
    pending: Option<Pending>,
    pending_since: Option<Instant>,
    direction_draft: Option<DirectionDraft>,
    next_poll: Option<Instant>,
    message: Option<&'static str>,
}

impl ClipboardPanel {
    pub(crate) fn reconcile(&mut self, session: Option<ClipboardSession>) {
        if self.session != session {
            *self = Self {
                session,
                ..Self::default()
            };
        }
    }

    /// Polling reports authorization state only. It never accesses OS clipboard data.
    pub(crate) fn poll(&mut self) -> Option<Command> {
        self.session.as_ref()?;
        if self.pending.is_some() {
            if self
                .pending_since
                .is_some_and(|since| since.elapsed() < PENDING_TIMEOUT)
            {
                return None;
            }
            let expired = self.pending.take();
            self.pending_since = None;
            self.next_poll = None;
            match expired {
                Some(Pending::Action(_)) => {
                    self.message = Some("Clipboard result is unknown; it was not retried.");
                }
                Some(Pending::Directions(_)) => {
                    self.direction_draft = None;
                    self.message =
                        Some("Clipboard acknowledgement was lost; refresh before retrying.");
                }
                Some(Pending::Status) | None => {
                    self.message = Some("Clipboard status update timed out; refreshed below.");
                }
            }
        }
        if self.next_poll.is_some_and(|next| Instant::now() < next) {
            return None;
        }
        self.pending = Some(Pending::Status);
        self.pending_since = Some(Instant::now());
        self.next_poll = Some(Instant::now() + STATUS_POLL);
        Some(Command::GetNativeClipboardStatus)
    }

    pub(crate) fn apply_reply(&mut self, generation: u64, reply: Reply) {
        if self
            .session
            .as_ref()
            .is_none_or(|session| session.generation != generation)
        {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        self.pending_since = None;
        if !matches!(&pending, Pending::Status) {
            self.message = None;
        }
        match (pending, reply) {
            (Pending::Status, Reply::NativeClipboardStatus { status }) => {
                self.status = status.filter(|status| self.matches_session(&status.binding));
                self.sync_draft_from_status();
            }
            (Pending::Directions(expected), Reply::NativeClipboardDirectionsSet { status }) => {
                if status.binding == expected && self.matches_session(&status.binding) {
                    self.direction_draft = Some(DirectionDraft {
                        binding: status.binding.clone(),
                        read: status.local_read,
                        write: status.local_write,
                    });
                    self.status = Some(status);
                } else {
                    self.status = None;
                    self.direction_draft = None;
                    self.message = Some("Clipboard session changed; refresh its status.");
                }
            }
            (Pending::Action(expected), Reply::NativeClipboardActionResult { effect }) => {
                if self.matches_session(&expected) {
                    self.message = Some(match effect {
                        NativeClipboardEffect::Applied => "Clipboard action completed.",
                        NativeClipboardEffect::NotApplied => "Clipboard action was not applied.",
                        NativeClipboardEffect::Unknown => {
                            "Clipboard result is unknown; it was not retried."
                        }
                    });
                }
            }
            (_, Reply::NativeClipboardRejected { reason }) => {
                self.message = Some(rejection_message(reason));
                if reason != NativeClipboardRejection::ReestablishSession {
                    self.status = None;
                    self.direction_draft = None;
                }
                self.next_poll = None;
            }
            _ => {
                self.message = Some("Clipboard reply did not match the pending action.");
                self.next_poll = None;
            }
        }
    }

    pub(crate) fn disconnected(&mut self) {
        self.pending = None;
        self.pending_since = None;
        self.status = None;
        self.direction_draft = None;
        self.next_poll = None;
        self.message = Some("Clipboard acknowledgement was lost; refresh before retrying.");
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui, english: bool) -> Option<Command> {
        let session = self.session.clone()?;
        let status = self.status.clone();
        let pending = self.pending.is_some();
        let mut outgoing = None;

        egui::CollapsingHeader::new(label(english, "剪贴板", "Clipboard"))
            .id_salt("native-clipboard-panel")
            .show(ui, |ui| {
                ui.label(label(
                    english,
                    "不会自动读取或同步文本；每次传输都需要你明确点击。",
                    "Text is never read or synced automatically. Click for each transfer.",
                ));
                let Some(status) = status.as_ref() else {
                    ui.label(label(
                        english,
                        "当前会话没有可用的剪贴板许可。",
                        "Clipboard permission is unavailable for this session.",
                    ));
                    return;
                };
                if !binding_matches_session(&session, &status.binding) {
                    ui.label(label(
                        english,
                        "剪贴板状态属于其他会话。",
                        "Clipboard status belongs to another session.",
                    ));
                    return;
                }

                ui.label(match status.endpoint {
                    NativeClipboardEndpoint::Host => {
                        label(english, "本机是被控端", "This device is the host")
                    }
                    NativeClipboardEndpoint::Controller => {
                        label(english, "本机是控制端", "This device is the controller")
                    }
                });
                let draft = self
                    .direction_draft
                    .as_ref()
                    .filter(|draft| draft.binding == status.binding)
                    .cloned()
                    .unwrap_or_else(|| DirectionDraft {
                        binding: status.binding.clone(),
                        read: status.local_read,
                        write: status.local_write,
                    });
                let mut read = draft.read;
                let mut write = draft.write;
                let can_add = !status.ready && !status.session_restart_required;
                let read_changed = ui
                    .add_enabled(
                        !pending && (can_add || (status.ready && read)),
                        egui::Checkbox::new(
                            &mut read,
                            label(
                                english,
                                "允许读取本机剪贴板",
                                "Allow reading this device's clipboard",
                            ),
                        ),
                    )
                    .changed();
                let write_changed = ui
                    .add_enabled(
                        !pending && (can_add || (status.ready && write)),
                        egui::Checkbox::new(
                            &mut write,
                            label(
                                english,
                                "允许写入本机剪贴板",
                                "Allow writing this device's clipboard",
                            ),
                        ),
                    )
                    .changed();
                if read_changed || write_changed {
                    self.direction_draft = Some(DirectionDraft {
                        binding: status.binding.clone(),
                        read,
                        write,
                    });
                }

                let directions_dirty = read != status.local_read || write != status.local_write;
                let adds_direction = (read && !status.local_read) || (write && !status.local_write);
                let can_apply_directions = !pending
                    && directions_dirty
                    && (!status.ready || !adds_direction)
                    && !status.session_restart_required;
                if ui
                    .add_enabled(
                        can_apply_directions,
                        egui::Button::new(label(
                            english,
                            "应用本机剪贴板权限",
                            "Apply local clipboard permissions",
                        )),
                    )
                    .clicked()
                {
                    self.pending = Some(Pending::Directions(status.binding.clone()));
                    self.pending_since = Some(Instant::now());
                    outgoing = Some(Command::SetNativeClipboardDirections {
                        binding: status.binding.clone(),
                        read,
                        write,
                    });
                    return;
                }

                if status.session_restart_required {
                    ui.label(label(
                        english,
                        "新增剪贴板方向需要重新建立本机会话。",
                        "Adding a clipboard direction requires a new native session.",
                    ));
                }
                if pending {
                    ui.spinner();
                }
                let copy_enabled = !pending
                    && status.ready
                    && status.permitted_read
                    && local_allows(status, NativeClipboardAction::CopyRemoteToLocal);
                if ui
                    .add_enabled(
                        copy_enabled,
                        egui::Button::new(label(
                            english,
                            "复制远端剪贴板到本机",
                            "Copy remote clipboard to this device",
                        )),
                    )
                    .clicked()
                {
                    self.pending = Some(Pending::Action(status.binding.clone()));
                    self.pending_since = Some(Instant::now());
                    outgoing = Some(Command::RunNativeClipboardAction {
                        binding: status.binding.clone(),
                        action: NativeClipboardAction::CopyRemoteToLocal,
                    });
                    return;
                }
                let send_enabled = !pending
                    && status.ready
                    && status.permitted_write
                    && local_allows(status, NativeClipboardAction::SendLocalToRemote);
                if ui
                    .add_enabled(
                        send_enabled,
                        egui::Button::new(label(
                            english,
                            "发送本机剪贴板到远端",
                            "Send this device's clipboard to the remote device",
                        )),
                    )
                    .clicked()
                {
                    self.pending = Some(Pending::Action(status.binding.clone()));
                    self.pending_since = Some(Instant::now());
                    outgoing = Some(Command::RunNativeClipboardAction {
                        binding: status.binding.clone(),
                        action: NativeClipboardAction::SendLocalToRemote,
                    });
                }
            });

        if let Some(message) = self.message {
            ui.label(message_for_language(english, message));
        }
        outgoing
    }

    fn matches_session(&self, binding: &NativeClipboardBinding) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| binding_matches_session(session, binding))
    }

    fn sync_draft_from_status(&mut self) {
        let Some(status) = self.status.clone() else {
            self.direction_draft = None;
            return;
        };
        if self
            .direction_draft
            .as_ref()
            .is_none_or(|draft| draft.binding != status.binding)
        {
            self.direction_draft = Some(DirectionDraft {
                binding: status.binding.clone(),
                read: status.local_read,
                write: status.local_write,
            });
        }
    }
}

fn local_allows(status: &NativeClipboardStatus, action: NativeClipboardAction) -> bool {
    let reads_local = matches!(
        (status.endpoint, action),
        (
            NativeClipboardEndpoint::Host,
            NativeClipboardAction::CopyRemoteToLocal
        ) | (
            NativeClipboardEndpoint::Controller,
            NativeClipboardAction::SendLocalToRemote
        )
    );
    if reads_local {
        status.local_read
    } else {
        status.local_write
    }
}

fn binding_matches_session(session: &ClipboardSession, binding: &NativeClipboardBinding) -> bool {
    session.binding.request_id == binding.request_id
        && session.binding.connection_generation == binding.connection_generation
        && session.generation == binding.core_generation
}

fn rejection_message(reason: NativeClipboardRejection) -> &'static str {
    match reason {
        NativeClipboardRejection::StaleBinding => "Clipboard session changed; refresh its status.",
        NativeClipboardRejection::Unauthorized => "This clipboard direction is not permitted.",
        NativeClipboardRejection::LocalConsentRequired => {
            "Select the local clipboard direction before using it."
        }
        NativeClipboardRejection::ReestablishSession => {
            "Adding a clipboard direction requires a new native session."
        }
        NativeClipboardRejection::PlatformUnavailable => {
            "The local clipboard is unavailable on this desktop session."
        }
        NativeClipboardRejection::Transport => "Clipboard transport failed; it was not retried.",
        NativeClipboardRejection::Stopped => "The clipboard session has stopped.",
        NativeClipboardRejection::Cleanup => "Clipboard cleanup was not confirmed.",
    }
}

fn message_for_language(english: bool, message: &'static str) -> &'static str {
    if english {
        message
    } else {
        match message {
            "Clipboard action completed." => "剪贴板操作已完成。",
            "Clipboard action was not applied." => "剪贴板操作未生效。",
            "Clipboard result is unknown; it was not retried." => "剪贴板结果未知；没有自动重试。",
            "Clipboard status update timed out; refreshed below." => {
                "剪贴板状态更新超时；正在下方刷新。"
            }
            "Clipboard acknowledgement was lost; refresh before retrying." => {
                "剪贴板操作确认丢失；请先刷新状态再重试。"
            }
            "Clipboard reply did not match the pending action." => "剪贴板响应与待处理操作不匹配。",
            "Clipboard session changed; refresh its status." => "剪贴板会话已变化，请刷新状态。",
            "This clipboard direction is not permitted." => "当前剪贴板方向未获许可。",
            "Select the local clipboard direction before using it." => "请先选择本机剪贴板方向。",
            "Adding a clipboard direction requires a new native session." => {
                "新增剪贴板方向需要重新建立本机会话。"
            }
            "The local clipboard is unavailable on this desktop session." => {
                "当前桌面会话无法使用本机剪贴板。"
            }
            "Clipboard transport failed; it was not retried." => "剪贴板传输失败；没有自动重试。",
            "The clipboard session has stopped." => "剪贴板会话已停止。",
            "Clipboard cleanup was not confirmed." => "剪贴板清理尚未确认。",
            _ => message,
        }
    }
}

fn label(english: bool, chinese: &'static str, english_text: &'static str) -> &'static str {
    if english { english_text } else { chinese }
}
