use crate::{DesktopApp, Screen, widgets};
use eframe::egui;
use nestlink_app_core::{Action, OperationStatus, Page, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::api::{NetworkPolicy, PolicyUpdate};

pub(crate) struct PolicyDraft {
    revision: u64,
    forwarding: String,
    path: String,
    ingress: String,
}
impl DesktopApp {
    pub(crate) fn devices_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("设备", "Devices"));
            if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                .clicked()
            {
                self.load(snapshot, Page::Devices);
            }
        });
        ui.label(self.t("设备身份与能力由控制中心返回。登记状态不代表当前在线。", "Device identities and capabilities come from the control center. Enrollment does not indicate online status."));
        ui.add_space(18.);
        if let Some(installation) = &snapshot.installation {
            ui.label(self.t("本机安装身份", "Local installation identity"));
            ui.monospace(&installation.device_id);
            ui.small(format!(
                "SHA-256 {}",
                installation
                    .public_key_sha256
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ));
        }
        egui::CollapsingHeader::new(self.t("登记此设备", "Enroll this device")).default_open(snapshot.devices.data.as_ref().is_some_and(|devices| devices.is_empty())).show(ui,|ui| {
            widgets::field(ui,self.t("设备名称", "Device name"),&mut self.device_name,128);
            ui.small(self.t("Windows/Linux 工作台登记为控制端和主机，并声明 VP8/Opus 能力；其他平台不声明尚未接入的能力。", "Windows/Linux workspaces enroll as controllers and hosts with VP8/Opus; other platforms do not declare capabilities that are not integrated."));
            if ui.add_enabled(!self.device_name.trim().is_empty() && snapshot.devices.loading.is_none(),egui::Button::new(self.t("登记", "Enroll"))).clicked() {
                self.action(snapshot,Action::EnrollLocalDevice {name:self.device_name.trim().into(),platform:local_platform().into(),capabilities:local_capabilities(),path_mode:"direct_preferred".into()});
            }
        });
        ui.add_space(18.);
        widgets::section(ui, &snapshot.devices, self.english);
        self.devices_table(ui, snapshot);
    }
    pub(crate) fn security_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("账号与安全", "Account and security"));
            if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                .clicked()
            {
                self.load(snapshot, Page::AccountSecurity);
            }
        });
        widgets::section(ui, &snapshot.security, self.english);
        if let Some(security) = &snapshot.security.data {
            ui.label(&security.principal.name);
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button(self.t("刷新登录期限", "Refresh login")).clicked() {
                self.action(snapshot, Action::RefreshSession);
            }
            if ui.button(self.t("注销账号", "Sign out")).clicked() {
                self.clear_private_view(ui.ctx());
                self.send(snapshot, Command::Logout);
                self.screen = Screen::Remote;
            }
        });
        if let Some(confirmed) = snapshot.logout_confirmed
            && !confirmed
        {
            ui.label(self.t(
                "本地登录信息已清除，服务器注销未确认。",
                "Local credentials were cleared; server logout was not confirmed.",
            ));
        }
        ui.add_space(20.);
        egui::CollapsingHeader::new(self.t("安全操作", "Security actions")).show(ui, |ui| {
            widgets::secret_field(
                ui,
                self.t("当前密码", "Current password"),
                &mut self.credentials.password,
                "password",
                self.generation,
                1024,
            );
            let ready =
                snapshot.security.loading.is_none() && !self.credentials.password.is_empty();
            widgets::secret_field(
                ui,
                self.t("新密码（至少 12 字节）", "New password (at least 12 bytes)"),
                &mut self.credentials.new_password,
                "new-password",
                self.generation,
                1024,
            );
            if ui
                .add_enabled(
                    ready && self.credentials.new_password.len() >= 12,
                    egui::Button::new(self.t("修改密码并注销", "Change password and sign out")),
                )
                .clicked()
            {
                let action = Action::ChangePassword {
                    current_password: widgets::take_secret(&mut self.credentials.password),
                    new_password: widgets::take_secret(&mut self.credentials.new_password),
                    factor: None,
                };
                self.sensitive.take();
                self.action(snapshot, action);
                widgets::clear_secret_widgets(ui.ctx(), self.generation);
            }
        });
        ui.add_space(18.);
        egui::CollapsingHeader::new(self.t("本次运行的操作", "Operations in this run")).show(
            ui,
            |ui| {
                for result in snapshot.operations.iter().rev().take(16) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!(
                            "#{} · {:?} · {:?}",
                            result.id.get(),
                            result.kind,
                            result.status
                        ));
                        if matches!(
                            result.status,
                            OperationStatus::Queued | OperationStatus::Running
                        ) && ui.small_button(self.t("取消", "Cancel")).clicked()
                        {
                            self.send(
                                snapshot,
                                Command::Cancel {
                                    operation: result.id,
                                },
                            );
                        }
                    });
                }
            },
        );
    }
    pub(crate) fn accounts_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("账号管理", "Accounts"));
            if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                .clicked()
            {
                self.load(snapshot, Page::Accounts);
            }
        });
        widgets::section(ui, &snapshot.accounts, self.english);
        egui::CollapsingHeader::new(self.t("创建普通账号", "Create a standard account")).show(
            ui,
            |ui| {
                widgets::field(
                    ui,
                    self.t("账号名称", "Account name"),
                    &mut self.account_name,
                    128,
                );
                widgets::secret_field(
                    ui,
                    self.t(
                        "初始密码（至少 12 字节）",
                        "Initial password (at least 12 bytes)",
                    ),
                    &mut self.credentials.new_password,
                    "account-password",
                    self.generation,
                    1024,
                );
                if ui
                    .add_enabled(
                        snapshot.accounts.loading.is_none()
                            && !self.account_name.trim().is_empty()
                            && self.credentials.new_password.len() >= 12,
                        egui::Button::new(self.t("创建账号", "Create account")),
                    )
                    .clicked()
                {
                    let username = self.account_name.trim().into();
                    let password = widgets::take_secret(&mut self.credentials.new_password);
                    self.action(snapshot, Action::CreateAccount { username, password });
                    widgets::clear_secret_widgets(ui.ctx(), self.generation);
                }
            },
        );
        ui.add_space(18.);
        self.accounts_table(ui, snapshot);
    }
    pub(crate) fn network_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("网络策略", "Network policy"));
            if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                .clicked()
            {
                self.load(snapshot, Page::Policy);
                self.load(snapshot, Page::RelayQuota);
                self.load(snapshot, Page::RelayUsage);
                self.load(snapshot, Page::PathLimits);
            }
        });
        widgets::section(ui, &snapshot.policy, self.english);
        if let Some(policy) = &snapshot.policy.data {
            if self.policy.is_none() {
                self.policy = Some(PolicyDraft {
                    revision: policy.revision,
                    forwarding: policy.policy.server_forwarding.clone(),
                    path: policy.policy.peer_path_mode.clone(),
                    ingress: policy.policy.public_ingress.clone(),
                });
            }
            let mut save = None;
            let mut reset = false;
            if let Some(draft) = &mut self.policy {
                ui.small(format!("Revision {}", draft.revision));
                if draft.revision != policy.revision {
                    ui.label(if self.english {
                        "The server revision changed. Reload the draft before saving."
                    } else {
                        "服务器版本已变化，请重新加载草稿后保存。"
                    });
                }
                for (id, label, value, choices) in [
                    (
                        "forwarding",
                        if self.english {
                            "Server forwarding"
                        } else {
                            "服务器业务转发"
                        },
                        &mut draft.forwarding,
                        &["deny", "allow"][..],
                    ),
                    (
                        "peer-path",
                        if self.english {
                            "Remote paths"
                        } else {
                            "远控路径"
                        },
                        &mut draft.path,
                        &["direct_only", "direct_preferred", "relay_only"][..],
                    ),
                    (
                        "ingress",
                        if self.english {
                            "Public service ingress"
                        } else {
                            "公网服务入口"
                        },
                        &mut draft.ingress,
                        &["disabled", "enabled"][..],
                    ),
                ] {
                    egui::ComboBox::from_id_salt(id)
                        .selected_text(value.as_str())
                        .width(220.)
                        .show_ui(ui, |ui| {
                            for choice in choices {
                                ui.selectable_value(value, (*choice).into(), *choice);
                            }
                        });
                    ui.small(label);
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            snapshot.policy.loading.is_none() && draft.revision == policy.revision,
                            egui::Button::new(if self.english {
                                "Save policy"
                            } else {
                                "保存策略"
                            }),
                        )
                        .clicked()
                    {
                        save = Some(PolicyUpdate {
                            expected_revision: draft.revision,
                            policy: NetworkPolicy {
                                server_forwarding: draft.forwarding.clone(),
                                peer_path_mode: draft.path.clone(),
                                public_ingress: draft.ingress.clone(),
                            },
                        });
                    }
                    reset = ui
                        .button(if self.english {
                            "Reload draft"
                        } else {
                            "重新加载草稿"
                        })
                        .clicked();
                });
            }
            if reset {
                self.policy = None;
            }
            if let Some(update) = save {
                self.pending_confirmation = Some((
                    self.t(
                        "此策略变更会影响现有授权和业务连接。",
                        "This policy change affects current permits and business connections.",
                    )
                    .into(),
                    Command::Submit {
                        action: Action::SetPolicy { update },
                    },
                ));
                self.policy = None;
            }
        }
        ui.add_space(18.);
        ui.label(
            egui::RichText::new(self.t("中继配额与实际计量", "Relay quota and actual usage"))
                .strong(),
        );
        widgets::section(ui, &snapshot.relay_quota, self.english);
        if let Some(quota) = &snapshot.relay_quota.data {
            ui.label(format!(
                "Revision {} · {} allocations · {} endpoints · {} B/s · {} B/allocation",
                quota.revision,
                quota.limits.max_allocations,
                quota.limits.max_account_endpoints,
                quota.limits.bytes_per_second,
                quota.limits.bytes_per_allocation
            ));
        }
        widgets::section(ui, &snapshot.relay_usage, self.english);
        if let Some(usage) = &snapshot.relay_usage.data {
            ui.label(format!(
                "{} allocations · {} endpoints · {} bytes · {} closed",
                usage.allocations, usage.endpoints, usage.admitted_bytes, usage.closed_allocations
            ));
            ui.small(format!(
                "{} · report {}",
                usage.runtime_id, usage.report_sequence
            ));
        }
        ui.add_space(18.);
        ui.label(egui::RichText::new(self.t("分层路径限制", "Scoped path limits")).strong());
        widgets::section(ui, &snapshot.path_limits, self.english);
        if let Some(limits) = &snapshot.path_limits.data {
            for limit in limits.iter() {
                ui.label(format!(
                    "{} · {} · {}",
                    limit.scope, limit.resource_id, limit.path_mode
                ));
            }
        }
    }
    pub(crate) fn nodes_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("转发节点", "Nodes"));
            if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                .clicked()
            {
                self.load(snapshot, Page::Nodes);
            }
        });
        widgets::section(ui, &snapshot.nodes, self.english);
        if let Some(nodes) = &snapshot.nodes.data {
            if nodes.is_empty() {
                ui.label(self.t("尚无登记节点。", "No nodes are registered."));
            }
            for view in nodes.iter() {
                ui.push_id(&view.node.id, |ui| {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(&view.node.name).strong());
                            ui.label(self.t(
                                if view.revoked {
                                    "已撤销"
                                } else {
                                    "已登记"
                                },
                                if view.revoked {
                                    "Revoked"
                                } else {
                                    "Registered"
                                },
                            ));
                            if ui.button(self.t("查看计量", "Usage")).clicked() {
                                self.action(
                                    snapshot,
                                    Action::LoadNodeUsage {
                                        node_id: view.node.id.clone(),
                                        after_generation: 0,
                                        limit: 50,
                                    },
                                );
                            }
                            if !view.revoked
                                && ui
                                    .add_enabled(
                                        snapshot.nodes.loading.is_none(),
                                        egui::Button::new(self.t("撤销", "Revoke")),
                                    )
                                    .clicked()
                            {
                                self.pending_confirmation = Some((
                                    format!(
                                        "{} {}",
                                        self.t("撤销节点：", "Revoke node:"),
                                        view.node.name
                                    ),
                                    Command::Submit {
                                        action: Action::RevokeNode {
                                            node_id: view.node.id.clone(),
                                        },
                                    },
                                ));
                            }
                        });
                        ui.monospace(&view.node.id);
                        ui.small(format!(
                            "{} connections · {} B/s · generation {}",
                            view.node.max_connections,
                            view.node.bytes_per_second,
                            view.runtime_generation
                        ));
                    });
                });
            }
        }
        widgets::section(ui, &snapshot.node_usage, self.english);
        if let Some(usage) = &snapshot.node_usage.data {
            ui.monospace(&usage.node_id);
            for entry in &usage.entries {
                ui.label(format!(
                    "{} · {} bytes · opened {} · closed {} · report {}",
                    entry.runtime_generation,
                    entry.admitted_bytes,
                    entry.opened_connections,
                    entry.closed_connections,
                    entry.report_sequence
                ));
            }
            if usage.more && ui.button(self.t("继续读取", "Next page")).clicked() {
                self.action(
                    snapshot,
                    Action::LoadNodeUsage {
                        node_id: usage.node_id.clone(),
                        after_generation: usage.next_generation,
                        limit: 50,
                    },
                );
            }
        }
    }
    pub(crate) fn audit_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal(|ui| {
            ui.heading(self.t("审计记录", "Audit"));
            if ui
                .button(self.t("刷新首批", "Refresh first page"))
                .clicked()
            {
                self.action(
                    snapshot,
                    Action::LoadAudit {
                        after_sequence: 0,
                        limit: 50,
                    },
                );
                self.load(snapshot, Page::AuditRetention);
            }
        });
        widgets::section(ui, &snapshot.audit_retention, self.english);
        if let Some(retention) = &snapshot.audit_retention.data {
            ui.small(format!(
                "{} seconds · revision {} · pruned through {}",
                retention.retention_seconds, retention.revision, retention.pruned_through
            ));
        }
        widgets::section(ui, &snapshot.audit, self.english);
        if let Some(page) = &snapshot.audit.data {
            if page.history_pruned {
                ui.label(self.t(
                    "部分历史已按保留策略清理。",
                    "Some history was removed under the retention policy.",
                ));
            }
            if page.entries.is_empty() {
                ui.label(self.t("此页没有审计记录。", "This page has no audit records."));
            }
            for entry in &page.entries {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("#{}", entry.sequence));
                        ui.label(egui::RichText::new(&entry.event).strong());
                        ui.small(format!("{} UTC ms", entry.created_at_unix_ms));
                    });
                    ui.monospace(&entry.resource_id);
                    if let Ok(actor) = serde_json::to_string(&entry.actor) {
                        ui.small(actor);
                    }
                });
            }
            if page.more
                && ui
                    .add_enabled(
                        snapshot.audit.loading.is_none(),
                        egui::Button::new(self.t("读取下一批", "Next page")),
                    )
                    .clicked()
            {
                self.action(
                    snapshot,
                    Action::LoadAudit {
                        after_sequence: page.next_sequence,
                        limit: 50,
                    },
                );
            }
        }
    }
}

pub(super) fn local_platform() -> &'static str {
    if cfg!(target_os = "linux") {
        if std::env::var("XDG_SESSION_TYPE").is_ok_and(|value| value == "wayland")
            || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty())
        {
            "linux-wayland"
        } else {
            "linux-x11"
        }
    } else {
        std::env::consts::OS
    }
}

pub(super) fn local_capabilities() -> Vec<String> {
    if cfg!(any(windows, target_os = "linux")) {
        vec!["controller", "host", "vp8", "opus"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    }
}
