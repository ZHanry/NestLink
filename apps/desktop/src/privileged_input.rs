//! Local-only UAC action. Rendering and status polling can never start a broker.
use eframe::egui;
use nestlink_app_core::{Authentication, Snapshot};
use nestlink_app_ipc::{privileged_input::*, wire::Command};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct PrivilegedInputPanel {
    context: Option<(String, u64)>,
    status: Option<PrivilegedInputStatus>,
    error: Option<PrivilegedInputError>,
    pending: bool,
    submission: Option<u64>,
    last_request: Option<Instant>,
}

impl PrivilegedInputPanel {
    pub(crate) fn reconcile(&mut self, runtime: Option<&str>, generation: u64) {
        let context = runtime.map(|runtime| (runtime.to_owned(), generation));
        if context != self.context {
            self.context = context;
            self.status = None;
            self.error = None;
            self.pending = false;
            self.submission = None;
            self.last_request = None;
        }
    }
    pub(crate) fn submitted(&mut self, id: Option<u64>) {
        self.submission = id;
        if id.is_none() {
            self.disconnected();
        }
    }
    pub(crate) fn complete(
        &mut self,
        id: Option<u64>,
        runtime: &str,
        generation: u64,
        result: PrivilegedInputResult,
    ) {
        if id.is_none()
            || id != self.submission
            || self
                .context
                .as_ref()
                .is_none_or(|(expected_runtime, expected_generation)| {
                    expected_runtime != runtime || *expected_generation != generation
                })
        {
            return;
        }
        self.pending = false;
        self.submission = None;
        match result {
            Ok(value) => {
                self.status = Some(value);
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
            }
        }
    }
    pub(crate) fn rejected(&mut self, id: Option<u64>) {
        if id.is_some() && id == self.submission {
            self.pending = false;
            self.submission = None;
            self.status = None;
            self.error = Some(PrivilegedInputError::StaleGeneration);
            self.last_request = None;
        }
    }
    pub(crate) fn disconnected(&mut self) {
        self.context = None;
        self.pending = false;
        self.submission = None;
        self.status = None;
        self.error = Some(PrivilegedInputError::Unavailable);
    }
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        english: bool,
        connected: bool,
    ) -> Option<Command> {
        if !cfg!(windows) {
            return None;
        }
        let t = |zh, en| if english { en } else { zh };
        let mut action = None;
        egui::CollapsingHeader::new(t("管理员窗口输入（可选）", "Input for administrator windows (optional)"))
            .show(ui, |ui| {
                ui.label(t("需要控制已提权的普通应用窗口时，在本机启用输入代理并批准 UAC。每个远控会话仍需本机确认；锁屏和安全桌面会停止输入。", "Enable the local input broker and approve UAC to control elevated application windows. Each session still needs local approval; input stops on lock or the secure desktop."));
                let text = match self.status.map(|value| value.state) {
                    None => t("状态未确认", "Status unconfirmed"),
                    Some(PrivilegedInputState::Unsupported) => t("当前平台不支持", "Unavailable on this platform"),
                    Some(PrivilegedInputState::Disabled) => t("未启用", "Disabled"),
                    Some(PrivilegedInputState::Starting) => t("正在等待本机批准或清理", "Waiting for local approval or cleanup"),
                    Some(PrivilegedInputState::Ready) => t("已启用，等待会话", "Enabled, waiting for a session"),
                    Some(PrivilegedInputState::Active) => t("当前会话已批准输入", "Input approved for this session"),
                    Some(PrivilegedInputState::Failed) => t("代理不可用，请检查可选管理员安装包或本机批准", "Broker unavailable; check the optional administrator package and local approval"),
                };
                ui.label(text);
                ui.small(t("请先结束现有远控再启用。改变显示器布局后需要重新批准。登出或切换控制中心会停用代理。", "End existing remote sessions before enabling. Display layout changes require new approval. Signing out or switching control centers disables the broker."));
                let can_start = self.status.is_some_and(|value| matches!(value.state, PrivilegedInputState::Disabled | PrivilegedInputState::Failed) && !value.cleanup_failed);
                ui.horizontal(|ui| {
                    if ui.add_enabled(connected && !self.pending && snapshot.authentication == Authentication::SignedIn && can_start,
                        egui::Button::new(t("在本机启用并批准 UAC", "Enable locally and approve UAC"))).clicked() { action = Some(PrivilegedInputAction::Start); }
                    if ui.add_enabled(connected && !self.pending && self.status.is_some_and(|value| matches!(value.state, PrivilegedInputState::Starting | PrivilegedInputState::Ready | PrivilegedInputState::Active | PrivilegedInputState::Failed)),
                        egui::Button::new(t("停止输入代理", "Stop input broker"))).clicked() { action = Some(PrivilegedInputAction::Stop); }
                });
                if self.status.is_some_and(|value| value.cleanup_failed) {
                    ui.colored_label(ui.visuals().error_fg_color, t("代理清理尚未确认，无法再次启用。请正常退出并检查本机会话。", "Broker cleanup was not confirmed. Enabling is blocked; exit normally and inspect the local session."));
                }
                if let Some(error) = self.error {
                    let message = match error {
                        PrivilegedInputError::Busy => t("请先停止当前会话并等待清理。", "Stop the current session and wait for cleanup."),
                        PrivilegedInputError::Unauthorized => t("请先连接并登录已批准的控制中心。", "Connect and sign in to an approved control center first."),
                        PrivilegedInputError::StaleGeneration => t("运行状态已改变，请刷新后操作。", "Runtime state changed; refresh before trying again."),
                        PrivilegedInputError::Cleanup => t("清理未确认，请正常退出。", "Cleanup was not confirmed; exit normally."),
                        _ => t("当前无法确认输入代理状态。", "The input broker state could not be confirmed."),
                    };
                    ui.colored_label(ui.visuals().error_fg_color, message);
                }
            });
        if action.is_none()
            && connected
            && !self.pending
            && self
                .last_request
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(2))
        {
            action = Some(PrivilegedInputAction::Status);
        }
        action.map(|action| {
            self.pending = true;
            self.last_request = Some(Instant::now());
            Command::PrivilegedInput { action }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> PrivilegedInputStatus {
        PrivilegedInputStatus {
            state: PrivilegedInputState::Ready,
            cleanup_failed: false,
        }
    }
    #[test]
    fn stale_runtime_or_generation_cannot_show_a_broker_as_enabled() {
        let mut panel = PrivilegedInputPanel::default();
        panel.reconcile(Some("new-runtime"), 9);
        panel.submitted(Some(7));
        panel.complete(Some(7), "old-runtime", 9, Ok(ready()));
        assert!(panel.status.is_none());
        panel.complete(Some(7), "new-runtime", 8, Ok(ready()));
        assert!(panel.status.is_none());
        panel.complete(Some(7), "new-runtime", 9, Ok(ready()));
        assert_eq!(panel.status, Some(ready()));
        panel.reconcile(Some("new-runtime"), 10);
        assert!(panel.status.is_none());
        panel.complete(Some(7), "new-runtime", 9, Ok(ready()));
        assert!(panel.status.is_none());
    }
    #[test]
    fn disconnect_discards_status_and_pending_mutation() {
        let mut panel = PrivilegedInputPanel::default();
        panel.reconcile(Some("runtime"), 1);
        panel.submitted(Some(8));
        panel.disconnected();
        panel.complete(Some(8), "runtime", 1, Ok(ready()));
        assert!(panel.status.is_none());
        assert!(panel.submission.is_none());
    }
    #[test]
    fn ordinary_rendering_never_requests_uac() {
        let context = egui::Context::default();
        let mut panel = PrivilegedInputPanel::default();
        for _ in 0..3 {
            let _ = context.run_ui(egui::RawInput::default(), |ui| {
                let command = panel.show(ui, &Snapshot::default(), true, true);
                assert!(!matches!(
                    command,
                    Some(Command::PrivilegedInput {
                        action: PrivilegedInputAction::Start
                    })
                ));
            });
        }
    }
}
