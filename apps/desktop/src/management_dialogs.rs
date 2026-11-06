use crate::{DesktopApp, widgets};
use eframe::egui;
use nestlink_app_core::{Action, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::api::{AuditRetentionUpdate, RelayQuotaUpdate};

impl DesktopApp {
    pub(crate) fn management_dialogs(&mut self, context: &egui::Context, snapshot: &Snapshot) {
        if !snapshot.principal.as_ref().is_some_and(|p| p.is_admin) {
            self.workspace.retention_draft = None;
            self.workspace.quota_draft = None;
            return;
        }
        if let Some((revision, mut seconds)) = self.workspace.retention_draft {
            let mut save = false;
            let mut cancel = false;
            let response = egui::Modal::new(egui::Id::new("audit-retention")).frame(widgets::modal_frame(context)).show(context, |ui| {
                ui.set_width(440_f32.min(context.content_rect().width() - 64.));
                ui.heading(self.t("审计保留策略", "Audit retention"));
                ui.label(self.t(
                    "保留期限缩短后，过期历史会按服务器策略清理。",
                    "Shortening retention allows the server to prune expired history.",
                ));
                ui.add_space(18.);
                ui.horizontal(|ui| {
                    ui.label(self.t("保留秒数", "Retention in seconds"));
                    ui.add(egui::DragValue::new(&mut seconds).range(3600..=31_536_000));
                });
                ui.small(format!(
                    "{:.1} {}",
                    seconds as f64 / 86400.,
                    self.t("天", "days")
                ));
                ui.add_space(18.);
                ui.horizontal(|ui| {
                    cancel = ui.button(self.t("取消", "Cancel")).clicked();
                    save = widgets::primary_button(
                        ui,
                        self.t("保存保留策略", "Save retention policy"),
                        self.connected
                            && !self.exiting
                            && snapshot.audit_retention.loading.is_none()
                            && snapshot
                                .audit_retention
                                .data
                                .as_ref()
                                .is_some_and(|v| v.revision == revision),
                    )
                    .clicked();
                });
            });
            self.workspace.retention_draft = if response.should_close() || save || cancel {
                None
            } else {
                Some((revision, seconds))
            };
            if save {
                self.pending_confirmation = Some((
                    self.t(
                        "更改保留期限可能清理已过期的审计记录。",
                        "Changing retention may remove expired audit records.",
                    )
                    .into(),
                    Command::Submit {
                        action: Action::SetAuditRetention {
                            update: AuditRetentionUpdate {
                                expected_revision: revision,
                                retention_seconds: seconds,
                            },
                        },
                    },
                ));
            }
        }
        if let Some(mut draft) = self.workspace.quota_draft {
            let mut save = false;
            let mut cancel = false;
            let response=egui::Modal::new(egui::Id::new("relay-quota")).frame(widgets::modal_frame(context)).show(context,|ui| {
                ui.set_width(460_f32.min(context.content_rect().width()-64.));
                ui.heading(self.t("中继配额", "Relay quotas"));
                ui.label(self.t("配额由控制中心执行，变更可能影响现有连接。", "The control center enforces these quotas. Changes can affect existing connections."));
                ui.add_space(18.);
                egui::Grid::new("relay-quota-form").spacing([22.,16.]).show(ui,|ui| {
                    ui.label(self.t("并发分配上限", "Maximum allocations"));ui.add(egui::DragValue::new(&mut draft.limits.max_allocations).range(0..=128));ui.end_row();
                    ui.label(self.t("账号端点上限", "Maximum endpoints"));ui.add(egui::DragValue::new(&mut draft.limits.max_account_endpoints).range(0..=256));ui.end_row();
                    ui.label(self.t("速率上限（B/s）", "Rate limit (B/s)"));ui.add(egui::DragValue::new(&mut draft.limits.bytes_per_second).range(1..=1_073_741_824));ui.end_row();
                    ui.label(self.t("每次分配流量上限（B）", "Bytes per allocation"));ui.add(egui::DragValue::new(&mut draft.limits.bytes_per_allocation).range(1..=1_099_511_627_776_u64));ui.end_row();
                });
                ui.add_space(18.);
                ui.horizontal(|ui| {
                    cancel=ui.button(self.t("取消", "Cancel")).clicked();
                    save=widgets::primary_button(ui,self.t("保存中继配额", "Save relay quotas"),self.connected && !self.exiting && snapshot.relay_quota.loading.is_none()&&snapshot.relay_quota.data.as_ref().is_some_and(|v|v.revision==draft.revision)).clicked();
                });
            });
            self.workspace.quota_draft = if response.should_close() || save || cancel {
                None
            } else {
                Some(draft)
            };
            if save {
                self.pending_confirmation = Some((
                    self.t(
                        "将使用新的中继配额，可能影响当前连接。",
                        "Apply new relay quotas? Current connections may be affected.",
                    )
                    .into(),
                    Command::Submit {
                        action: Action::SetRelayQuota {
                            update: RelayQuotaUpdate {
                                expected_revision: draft.revision,
                                limits: draft.limits,
                            },
                        },
                    },
                ));
            }
        }
    }
}
