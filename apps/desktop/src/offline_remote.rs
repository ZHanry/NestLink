//! Presentation of the original daemon's separately consumed offline authority.
use crate::{DesktopApp, RemoteViewportTarget};
use eframe::egui;
use nestlink_app_core::{NativeOfflineView, NativeSessionCleanup, NativeSessionStatus, Snapshot};
use nestlink_protocol::offline::OfflineRemoteOperation;

pub(super) fn target<'a>(
    snapshot: &'a Snapshot,
    target: &RemoteViewportTarget,
) -> Option<&'a NativeOfflineView> {
    snapshot.native_offline.as_ref().filter(|offline| {
        offline.request_id == target.request_id
            && offline.connection_generation == target.connection_generation
    })
}
pub(super) fn viewer_is_current(snapshot: &Snapshot, selected: &RemoteViewportTarget) -> bool {
    target(snapshot, selected).is_some_and(|offline| {
        !offline.is_host
            && offline.status == NativeSessionStatus::Connected
            && !offline.budget.stopped
            && offline.budget.remaining_lifetime_ms > 0
            && offline.budget.remaining_bytes > 0
            && offline.operations.contains(&OfflineRemoteOperation::View)
    })
}
pub(super) fn authority_stopped(snapshot: &Snapshot, selected: &RemoteViewportTarget) -> bool {
    target(snapshot, selected).is_some_and(|offline| {
        offline.budget.stopped
            && matches!(
                offline.status,
                NativeSessionStatus::Stopped | NativeSessionStatus::Failed
            )
            && offline.cleanup == Some(NativeSessionCleanup::Succeeded)
            && offline.failure.is_none()
    })
}

impl DesktopApp {
    pub(super) fn offline_remote_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(offline) = snapshot.native_offline.as_ref() else {
            return;
        };
        egui::ScrollArea::vertical().id_salt("independent-offline-remote").show(ui, |ui| {
            ui.heading(self.t("离线仅直连", "Offline · direct only"));
            ui.label(self.t(
                "此会话使用双方在线批准并已消费的有限离线授权。原进程必须保持运行。",
                "This session uses finite offline authority approved and consumed by both original online processes. Keep those processes running.",
            ));
            ui.label(self.t(
                "中心失联时不能即时收到中心撤销；原期限、累计额度和本机停止持续有效。恢复在线前先结束离线会话。",
                "Central revocations cannot arrive immediately while management is unreachable. The original deadline, cumulative limits and local stop remain effective. End the offline session before returning online.",
            ));
            ui.add_space(10.);
            egui::Grid::new("offline-finite-budget").num_columns(2).spacing([20., 7.]).show(ui, |ui| {
                ui.label(self.t("角色", "Role"));
                ui.label(if offline.is_host { self.t("被控主机", "Host") } else { self.t("控制端", "Controller") }); ui.end_row();
                ui.label(self.t("直连承载", "Direct carrier"));
                ui.label(match offline.transport { nestlink_app_core::NativeOfflineTransport::Quic => "QUIC", nestlink_app_core::NativeOfflineTransport::Tls => "TLS / TCP" }); ui.end_row();
                ui.label(self.t("剩余期限", "Remaining lifetime"));
                ui.label(format!("{} s", offline.budget.remaining_lifetime_ms / 1000)); ui.end_row();
                ui.label(self.t("剩余累计字节", "Remaining cumulative bytes"));
                ui.label(format!("{} B", offline.budget.remaining_bytes)); ui.end_row();
                ui.label(self.t("剩余文件写入字节", "Remaining file write bytes"));
                ui.label(format!("{} B", offline.budget.remaining_file_write_bytes)); ui.end_row();
                ui.label(self.t("已消耗连接尝试", "Connection attempts spent"));
                ui.label(offline.budget.connection_attempts.to_string()); ui.end_row();
                ui.label(self.t("已批准操作", "Approved operations"));
                let operations: Vec<_> = offline.operations.iter().map(|operation| match operation {
                    OfflineRemoteOperation::View => self.t("查看屏幕", "View"),
                    OfflineRemoteOperation::Input => self.t("输入控制", "Input"),
                    OfflineRemoteOperation::Audio => self.t("音频", "Audio"),
                    OfflineRemoteOperation::FileRead => self.t("文件读取", "File read"),
                    OfflineRemoteOperation::FileWrite => self.t("文件写入", "File write"),
                    OfflineRemoteOperation::ClipboardRead => self.t("剪贴板读取", "Clipboard read"),
                    OfflineRemoteOperation::ClipboardWrite => self.t("剪贴板写入", "Clipboard write"),
                }).collect();
                ui.label(operations.join(" · ")); ui.end_row();
            });
            if offline.budget.stopped {
                ui.strong(self.t("原离线授权已终止。重新使用需要双方新的在线批准。", "The original offline authority has ended. New use requires fresh approval by both online endpoints."));
            }
            self.native_session_panel(ui, snapshot);
            if offline.status == NativeSessionStatus::Connected {
                self.transfer_panels(ui, snapshot);
            }
            egui::CollapsingHeader::new(self.t("离线授权标识", "Offline authority identifiers")).show(ui, |ui| {
                ui.monospace(format!("space: {}", offline.space_id));
                ui.monospace(format!("bundle: {}", offline.bundle_id));
                ui.monospace(format!("session: {} / {}", offline.request_id, offline.connection_generation));
            });
        });
    }
}
