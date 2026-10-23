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
#[derive(Default)]
pub(crate) struct EdgeNamespacePanel {
    node_id: Option<String>,
    draft: Option<EdgeNamespaceDraft>,
    pending: Option<NamespacePending>,
    requires_reload: bool,
    may_initialize: bool,
    error: Option<String>,
}
struct NamespacePending {
    submission: u64,
    generation: u64,
    node_id: String,
    saving: bool,
    completed: bool,
}
impl EdgeNamespacePanel {
    pub(crate) fn completed(
        &mut self,
        submission: Option<u64>,
        result: &nestlink_app_core::OperationResult,
        english: bool,
    ) {
        let Some(pending) = &mut self.pending else {
            return;
        };
        if Some(pending.submission) != submission
            || pending.generation != result.generation
            || result.kind
                != if pending.saving {
                    nestlink_app_core::OperationKind::SetServiceEdgeNamespace
                } else {
                    nestlink_app_core::OperationKind::LoadServiceEdgeNamespace
                }
        {
            return;
        }
        if result.status == OperationStatus::Succeeded {
            pending.completed = true;
        } else {
            self.may_initialize = !pending.saving
                && self.draft.is_none()
                && result
                    .failure
                    .as_ref()
                    .is_some_and(|f| f.status == Some(403));
            self.requires_reload = true;
            self.error = Some(widgets::operation_message(result, english));
            self.pending = None;
        }
    }
    pub(crate) fn disconnected(&mut self) {
        if let Some(submission) = self.pending.as_ref().map(|pending| pending.submission) {
            self.rejected(Some(submission));
        }
    }
    pub(crate) fn rejected(&mut self, submission: Option<u64>) {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| Some(p.submission) == submission)
        {
            self.pending = None;
            self.requires_reload = true;
            self.may_initialize = false;
            self.error = Some("请求未完成，请重新读取配置。 / Request did not complete; reload the configuration.".into());
        }
    }
}
struct EdgeNamespaceDraft {
    revision: u64,
    suffix: String,
    management: String,
    ports: String,
    quic: String,
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
            ui.small(self.t("Windows 桌面端登记为控制端与被控主机；实际可用画面、声音和输入能力在会话建立时确认。", "The Windows client enrolls as a controller and host. Available video, audio and input capabilities are confirmed when a session starts."));
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
                        if !view.revoked
                            && view.node.roles.contains(&2)
                            && snapshot.principal.as_ref().is_some_and(|p| p.is_admin)
                            && ui
                                .button(self.t("公网入口配置", "Public ingress configuration"))
                                .clicked()
                        {
                            self.edge_namespace = EdgeNamespacePanel {
                                node_id: Some(view.node.id.clone()),
                                ..Default::default()
                            };
                            self.submit_edge_namespace(
                                snapshot,
                                Action::LoadServiceEdgeNamespace {
                                    node_id: view.node.id.clone(),
                                },
                                false,
                            );
                        }
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
        self.edge_namespace_panel(ui, snapshot);
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
    fn edge_namespace_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        use nestlink_protocol::service_plane::publication::{
            ServiceEdgeNamespace, ServiceEdgeNamespaceUpdate,
        };
        let Some(node_id) = self.edge_namespace.node_id.clone() else {
            return;
        };
        let allowed = snapshot.principal.as_ref().is_some_and(|p| p.is_admin)
            && snapshot.nodes.data.as_ref().is_some_and(|nodes| {
                nodes
                    .iter()
                    .any(|n| n.node.id == node_id && !n.revoked && n.node.roles.contains(&2))
            });
        if !allowed {
            self.edge_namespace = Default::default();
            return;
        }
        let section = &snapshot.service_edge_namespace;
        if self.edge_namespace.pending.as_ref().is_some_and(|pending| {
            pending.completed
                && pending.generation == snapshot.generation
                && pending.node_id == node_id
        }) && let Some(view) = section.data.as_ref().filter(|view| view.node_id == node_id)
        {
            self.edge_namespace.pending = None;
            self.edge_namespace.requires_reload = false;
            self.edge_namespace.may_initialize = false;
            self.edge_namespace.error = None;
            self.edge_namespace.draft = Some(EdgeNamespaceDraft {
                revision: view.revision,
                suffix: view.config.service_suffix.clone(),
                management: view.config.management_hostname.clone(),
                ports: view
                    .config
                    .public_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                quic: view.config.quic_address.clone(),
            });
        }
        ui.add_space(18.);
        ui.heading(self.t("公网入口", "Public ingress"));
        ui.monospace(&node_id);
        if let Some(pending) = &self.edge_namespace.pending {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(18.));
                ui.label(if pending.saving {
                    self.t("正在保存公网入口…", "Saving public ingress…")
                } else {
                    self.t("正在读取公网入口…", "Loading public ingress…")
                });
            });
        }
        if let Some(error) = &self.edge_namespace.error {
            ui.colored_label(egui::Color32::RED, error);
        }
        if self.edge_namespace.requires_reload
            && self.edge_namespace.pending.is_none()
            && self.edge_namespace.draft.is_some()
        {
            ui.label(self.t(
                "草稿已保留。请明确重新读取配置后再保存。",
                "Your draft is retained. Reload the configuration before saving again.",
            ));
        }
        let busy = self.edge_namespace.pending.is_some();
        if ui
            .add_enabled(!busy, egui::Button::new(self.t("重新读取", "Reload")))
            .clicked()
        {
            self.submit_edge_namespace(
                snapshot,
                Action::LoadServiceEdgeNamespace {
                    node_id: node_id.clone(),
                },
                false,
            );
        }
        let english = self.english;
        if !busy && self.edge_namespace.draft.is_none() && self.edge_namespace.may_initialize {
            ui.label(self.t("未读到可编辑配置。仅在尚未配置时选择首次配置；已有配置会拒绝创建。", "No editable configuration was read. Choose first-time setup only for an unconfigured node; existing configuration prevents creation."));
            if ui.button(self.t("首次配置", "First-time setup")).clicked() {
                self.edge_namespace.draft = Some(EdgeNamespaceDraft {
                    revision: 0,
                    suffix: String::new(),
                    management: String::new(),
                    ports: String::new(),
                    quic: String::new(),
                });
                self.edge_namespace.requires_reload = false;
                self.edge_namespace.may_initialize = false;
            }
        }
        let Some(draft) = &mut self.edge_namespace.draft else {
            return;
        };
        let mut save = false;
        let requires_reload = self.edge_namespace.requires_reload;
        ui.add_enabled_ui(!busy, |ui| {
            ui.label(if english {
                format!("Configuration version {}", draft.revision)
            } else {
                format!("配置版本 {}", draft.revision)
            });
            egui::Grid::new("edge-namespace-fields")
                .num_columns(2)
                .show(ui, |ui| {
                    ui.label(if english {
                        "Service suffix"
                    } else {
                        "服务域名后缀"
                    });
                    ui.text_edit_singleline(&mut draft.suffix);
                    ui.end_row();
                    ui.label(if english {
                        "Management hostname"
                    } else {
                        "管理主机名"
                    });
                    ui.text_edit_singleline(&mut draft.management);
                    ui.end_row();
                    ui.label(if english {
                        "Public ports (ascending, unique)"
                    } else {
                        "公网端口（递增、不重复）"
                    });
                    ui.text_edit_singleline(&mut draft.ports);
                    ui.end_row();
                    ui.label(if english {
                        "QUIC socket address"
                    } else {
                        "QUIC 数字地址与端口"
                    });
                    ui.text_edit_singleline(&mut draft.quic);
                    ui.end_row();
                });
            save = ui
                .add_enabled(
                    !requires_reload,
                    egui::Button::new(if english { "Save" } else { "保存" }),
                )
                .clicked();
        });
        if save {
            let ports = draft
                .ports
                .split(',')
                .map(|p| p.trim().parse::<u16>())
                .collect::<Result<Vec<_>, _>>();
            let config = ports
                .ok()
                .map(|public_ports| ServiceEdgeNamespace {
                    service_suffix: draft.suffix.trim().into(),
                    management_hostname: draft.management.trim().into(),
                    public_ports,
                    quic_address: draft.quic.trim().into(),
                })
                .filter(|config| config.validate().is_ok());
            if let Some(config) = config {
                let update = ServiceEdgeNamespaceUpdate {
                    expected_revision: draft.revision,
                    config,
                };
                self.submit_edge_namespace(
                    snapshot,
                    Action::SetServiceEdgeNamespace { node_id, update },
                    true,
                );
            } else {
                self.edge_namespace.error = Some(if english { "Check domain names, ascending unique ports, and the numeric QUIC socket address." } else { "请检查域名、递增且不重复的端口，以及 QUIC 数字地址与端口。" }.into());
            }
        }
    }
    fn submit_edge_namespace(&mut self, snapshot: &Snapshot, action: Action, saving: bool) {
        self.edge_namespace.requires_reload = true;
        self.edge_namespace.may_initialize = false;
        self.edge_namespace.error = None;
        let submission = self
            .bridge
            .submit_tracked(snapshot.generation, Command::Submit { action });
        if let Some(submission) = submission {
            self.edge_namespace.pending =
                self.edge_namespace
                    .node_id
                    .clone()
                    .map(|node_id| NamespacePending {
                        submission,
                        generation: snapshot.generation,
                        node_id,
                        saving,
                        completed: false,
                    });
        } else {
            self.edge_namespace.pending = None;
            self.edge_namespace.error = Some(
                self.t(
                    "请求未送出，请重新读取配置。",
                    "Request was not sent; reload the configuration.",
                )
                .into(),
            );
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
