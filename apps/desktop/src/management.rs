use crate::{DesktopApp, Screen, widgets};
use eframe::egui;
use nestlink_app_core::{Action, OperationStatus, Page, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::api::{NetworkPolicy, PolicyUpdate};
use zeroize::Zeroize;

pub(crate) struct PolicyDraft {
    revision: u64,
    forwarding: String,
    path: String,
    ingress: String,
}

fn policy_choice(value: &str, english: bool) -> &str {
    match (value, english) {
        ("allow", false) => "允许转发",
        ("allow", true) => "Allow forwarding",
        ("deny", false) => "禁止转发",
        ("deny", true) => "Deny forwarding",
        ("direct_only", false) => "仅直连",
        ("direct_only", true) => "Direct only",
        ("direct_preferred", false) => "优先直连",
        ("direct_preferred", true) => "Prefer direct",
        ("relay_only", false) => "仅中继",
        ("relay_only", true) => "Relay only",
        ("disabled", false) => "已关闭",
        ("disabled", true) => "Disabled",
        ("enabled", false) => "已启用",
        ("enabled", true) => "Enabled",
        _ => value,
    }
}

fn policy_description(id: &str, english: bool) -> &'static str {
    match (id, english) {
        ("forwarding", false) => "控制经服务器转发的业务连接。",
        ("forwarding", true) => "Control business traffic through the server.",
        ("peer-path", false) => "选择已授权会话允许使用的连接路径。",
        ("peer-path", true) => "Choose the paths allowed for authorized sessions.",
        ("ingress", false) => "控制公网服务入口是否可用。",
        _ => "Control whether public service entries are available.",
    }
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
    #[allow(dead_code)]
    pub(crate) fn registered_devices_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
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
        widgets::page_header(
            ui,
            self.t("账号与安全", "Account and security"),
            self.t(
                "管理账号密码、登录状态和登录设备。",
                "Manage your password, sign-in status and login devices.",
            ),
            90.,
            |ui| {
                if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                    .clicked()
                {
                    self.load(snapshot, Page::AccountSecurity);
                }
            },
        );
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(security) = &snapshot.security.data {
                ui.horizontal(|ui| {
                    crate::icons::badge(ui, crate::icons::Icon::Account, 52.);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(&security.principal.name)
                                .size(20.)
                                .strong(),
                        );
                        ui.small(if security.principal.is_admin {
                            self.t("管理员账号", "Administrator account")
                        } else {
                            self.t("普通账号", "Standard account")
                        });
                    });
                });
            }
            widgets::section(ui, &snapshot.security, self.english);
        });
        ui.add_space(16.);
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            widgets::settings_row(
                ui,
                self.t("账号登录", "Account sign-in"),
                self.t(
                    "续期当前登录，或退出此电脑的账号登录。",
                    "Renew this sign-in or sign out on this computer.",
                ),
                220.,
                |ui| {
                    if ui.button(self.t("注销账号", "Sign out")).clicked() {
                        self.clear_private_view(ui.ctx());
                        self.send(snapshot, Command::Logout);
                        self.screen = Screen::Remote;
                    }
                    if ui.button(self.t("刷新登录期限", "Refresh login")).clicked() {
                        self.action(snapshot, Action::RefreshSession);
                    }
                },
            );
            ui.separator();
            widgets::settings_row(
                ui,
                self.t("账号密码", "Account password"),
                self.t(
                    "修改密码后需要重新登录。",
                    "Sign in again after changing your password.",
                ),
                130.,
                |ui| {
                    if ui.button(self.t("修改密码", "Change password")).clicked() {
                        self.workspace.password_open = true;
                    }
                },
            );
            ui.separator();
            widgets::settings_row(
                ui,
                self.t("登录设备", "Login devices"),
                self.t(
                    "查看并单独退出当前账号的 Windows 和 Web 登录。",
                    "Review and revoke this account's Windows and Web logins.",
                ),
                200.,
                |ui| {
                    if ui
                        .button(self.t("管理账号登录设备", "Manage login devices"))
                        .clicked()
                    {
                        self.navigate(Screen::Devices, snapshot);
                    }
                },
            );
            if snapshot.logout_confirmed == Some(false) {
                widgets::notice(
                    ui,
                    self.t(
                        "本地登录信息已清除，服务器注销未确认。",
                        "Local credentials were cleared; server logout was not confirmed.",
                    ),
                );
            }
        });
        if self.workspace.password_open {
            let context = ui.ctx().clone();
            let mut cancel = false;
            let response = egui::Modal::new(egui::Id::new("account-password"))
                .frame(widgets::modal_frame(&context))
                .show(&context, |ui| {
                    ui.set_width(440_f32.min(context.content_rect().width() - 64.));
                    ui.heading(self.t("修改密码", "Change password"));
                    widgets::secret_field(
                        ui,
                        self.t("当前密码", "Current password"),
                        &mut self.credentials.password,
                        "password",
                        self.generation,
                        1024,
                    );
                    let ready = snapshot.security.loading.is_none()
                        && !self.credentials.password.is_empty();
                    widgets::secret_field(
                        ui,
                        self.t("新密码（至少 12 字节）", "New password (at least 12 bytes)"),
                        &mut self.credentials.new_password,
                        "new-password",
                        self.generation,
                        1024,
                    );
                    let (cancel_clicked, save_clicked) = widgets::dialog_actions(
                        ui,
                        self.t("取消", "Cancel"),
                        self.t("修改密码并注销", "Change password and sign out"),
                        ready && self.credentials.new_password.len() >= 12,
                    );
                    cancel = cancel_clicked;
                    if save_clicked {
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
            if cancel || response.should_close() {
                self.workspace.password_open = false;
                self.credentials.password.zeroize();
                self.credentials.new_password.zeroize();
                widgets::clear_secret_widgets(ui.ctx(), self.generation);
            }
        }
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
        widgets::page_header(
            ui,
            self.t("账号管理", "Accounts"),
            self.t(
                "管理控制中心的账号、角色和登录状态。",
                "Manage control-center accounts, roles and access.",
            ),
            200.,
            |ui| {
                if widgets::action_button(
                    ui,
                    self.t("创建账号", "Create account"),
                    snapshot.accounts.loading.is_none(),
                )
                .clicked()
                {
                    self.workspace.account_create_open = true;
                }
                if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                    .clicked()
                {
                    self.load(snapshot, Page::Accounts);
                }
            },
        );
        if self.workspace.account_create_open {
            let context = ui.ctx().clone();
            let mut cancel = false;
            let response = egui::Modal::new(egui::Id::new("account-create"))
                .frame(widgets::modal_frame(&context))
                .show(&context, |ui| {
                    ui.set_width(440_f32.min(context.content_rect().width() - 64.));
                    ui.heading(self.t("创建普通账号", "Create a standard account"));
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
                    let (cancel_clicked, create_clicked) = widgets::dialog_actions(
                        ui,
                        self.t("取消", "Cancel"),
                        self.t("创建账号", "Create account"),
                        snapshot.accounts.loading.is_none()
                            && !self.account_name.trim().is_empty()
                            && self.credentials.new_password.len() >= 12,
                    );
                    cancel = cancel_clicked;
                    if create_clicked {
                        let username = self.account_name.trim().into();
                        let password = widgets::take_secret(&mut self.credentials.new_password);
                        self.action(snapshot, Action::CreateAccount { username, password });
                        self.workspace.account_create_open = false;
                        widgets::clear_secret_widgets(ui.ctx(), self.generation);
                    }
                });
            if cancel || response.should_close() {
                self.workspace.account_create_open = false;
                self.credentials.new_password.zeroize();
                widgets::clear_secret_widgets(ui.ctx(), self.generation);
            }
        }
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            self.accounts_table(ui, snapshot);
        });
        ui.add_space(16.);
        widgets::notice(ui, self.t("账号角色决定控制中心的管理资格，设备和会话权限仍需分别授权。", "Account roles determine control-center administration. Device and session access still require separate authorization."));
        widgets::section(ui, &snapshot.accounts, self.english);
    }
    pub(crate) fn network_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::page_header(
            ui,
            self.t("网络策略与配额", "Policy and quotas"),
            self.t(
                "查看实际资源用量，并管理连接路径与访问策略。",
                "Review actual resource usage and manage connection policies.",
            ),
            230.,
            |ui| {
                if widgets::action_button(
                    ui,
                    self.t("调整中继配额", "Edit relay quotas"),
                    snapshot.relay_quota.data.is_some(),
                )
                .clicked()
                {
                    self.workspace.quota_draft = snapshot.relay_quota.data.as_ref().map(|q| **q);
                }
                if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                    .clicked()
                {
                    for page in [
                        Page::Policy,
                        Page::RelayQuota,
                        Page::RelayUsage,
                        Page::PathLimits,
                    ] {
                        self.load(snapshot, page);
                    }
                }
            },
        );
        if let Some(quota) = &snapshot.relay_quota.data {
            let usage = snapshot.relay_usage.data.as_ref();
            ui.columns(3, |uis| {
                widgets::metric(
                    &mut uis[0],
                    self.t("当前中继分配", "Relay allocations"),
                    &format!(
                        "{} / {}",
                        usage.map_or_else(|| "—".into(), |u| u.allocations.to_string()),
                        quota.limits.max_allocations
                    ),
                    self.t("实际分配 / 允许上限", "Allocated / allowed"),
                );
                widgets::metric(
                    &mut uis[1],
                    self.t("当前端点", "Endpoints"),
                    &format!(
                        "{} / {}",
                        usage.map_or_else(|| "—".into(), |u| u.endpoints.to_string()),
                        quota.limits.max_account_endpoints
                    ),
                    self.t("实际端点 / 允许上限", "Active / allowed"),
                );
                widgets::metric(
                    &mut uis[2],
                    self.t("中继速率上限", "Relay rate limit"),
                    &format!(
                        "{:.1} Mbps",
                        quota.limits.bytes_per_second as f64 * 8. / 1_000_000.
                    ),
                    self.t("服务端配额", "Server quota"),
                );
            });
            if usage.is_none() {
                widgets::notice(
                    ui,
                    self.t(
                        "当前计量尚未读取，请刷新后查看已用数量。",
                        "Usage has not been loaded. Refresh to view measured counters.",
                    ),
                );
            }
        }

        ui.add_space(20.);
        if ui.available_width() >= 950. {
            ui.columns(2, |columns| {
                self.policy_card(&mut columns[0], snapshot);
                self.path_limits_card(&mut columns[1], snapshot);
            });
        } else {
            self.policy_card(ui, snapshot);
            ui.add_space(16.);
            self.path_limits_card(ui, snapshot);
        }
        widgets::section(ui, &snapshot.relay_quota, self.english);
        widgets::section(ui, &snapshot.relay_usage, self.english);
    }
    fn policy_card(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.strong(self.t("全局路径策略", "Global connection policy"));
            ui.add_space(12.);
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
                        ui.horizontal(|ui| {
                            ui.allocate_ui(
                                egui::vec2((ui.available_width() - 202.).max(90.), 54.),
                                |ui| {
                                    ui.strong(label);
                                    ui.small(policy_description(id, self.english));
                                },
                            );
                            egui::ComboBox::from_id_salt(id)
                                .selected_text(policy_choice(value, self.english))
                                .width(180.)
                                .show_ui(ui, |ui| {
                                    for choice in choices {
                                        ui.selectable_value(
                                            value,
                                            (*choice).into(),
                                            policy_choice(choice, self.english),
                                        );
                                    }
                                });
                        });
                        ui.separator();
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                snapshot.policy.loading.is_none()
                                    && draft.revision == policy.revision,
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
            widgets::section(ui, &snapshot.policy, self.english);
        });
    }
    fn path_limits_card(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.strong(self.t("分层路径限制", "Scoped path limits"));
            ui.add_space(12.);
            if let Some(limits) = &snapshot.path_limits.data {
                if limits.is_empty() {
                    ui.label(self.t(
                        "没有单独设置的路径限制。",
                        "No additional scoped path limits.",
                    ));
                }
                for limit in limits.iter() {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(format!("{} · {}", limit.scope, limit.resource_id));
                        ui.label(policy_choice(&limit.path_mode, self.english));
                    });
                    ui.separator();
                }
            }
            widgets::section(ui, &snapshot.path_limits, self.english);
        });
    }
    pub(crate) fn nodes_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::page_header(
            ui,
            self.t(
                "转发节点，连接的另一条路",
                "Relay nodes, another way to connect",
            ),
            self.t(
                "管理公网入口与中继节点，按实际能力提供连接。",
                "Manage public entries and relay nodes using their registered capabilities.",
            ),
            90.,
            |ui| {
                if crate::icons::button(ui, crate::icons::Icon::Refresh, self.t("刷新", "Refresh"))
                    .clicked()
                {
                    self.load(snapshot, Page::Nodes);
                }
            },
        );
        if let Some(nodes) = &snapshot.nodes.data {
            if nodes.is_empty() {
                ui.label(self.t("尚无登记节点。", "No nodes are registered."));
            }
            let count = if ui.available_width() >= 1080. {
                3
            } else if ui.available_width() >= 700. {
                2
            } else {
                1
            };
            for row in nodes.chunks(count) {
                ui.columns(count, |columns| {
                    for (column, view) in columns.iter_mut().zip(row) {
                        self.node_card(column, snapshot, view);
                    }
                });
                ui.add_space(14.);
            }
        }
        ui.add_space(10.);
        widgets::notice(ui, self.t("节点可用不代表会话已经使用中继。连接路径仅在会话完成路径选择后显示。", "Node availability does not mean a session is relayed. The actual path is shown after session path selection."));
        widgets::section(ui, &snapshot.nodes, self.english);
        self.edge_namespace_panel(ui, snapshot);
        if snapshot.node_usage.data.is_some()
            || snapshot.node_usage.loading.is_some()
            || snapshot.node_usage.error.is_some()
        {
            widgets::section(ui, &snapshot.node_usage, self.english);
        }
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
    fn node_card(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        view: &nestlink_protocol::api::NodeView,
    ) {
        ui.push_id(&view.node.id, |ui| {
            widgets::surface(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.set_min_height(250.);
                crate::icons::badge(ui, crate::icons::Icon::Server, 44.);
                ui.add(
                    egui::Label::new(egui::RichText::new(&view.node.name).size(18.).strong())
                        .truncate(),
                )
                .on_hover_text(&view.node.name);
                ui.small(if view.revoked {
                    self.t("已撤销节点", "Revoked node")
                } else {
                    self.t(
                        "已登记 · 可用性由实际连接确认",
                        "Registered · availability checked on connection",
                    )
                });
                ui.small(format!(
                    "{}  ·  {:.1} Mbps",
                    if view.node.roles.contains(&2) {
                        self.t("公网入口", "Public entry")
                    } else {
                        self.t("中继节点", "Relay node")
                    },
                    view.node.bytes_per_second as f64 * 8. / 1_000_000.
                ));
                ui.small(format!(
                    "{} {}",
                    self.t("连接上限", "Connection limit"),
                    view.node.max_connections
                ));
                ui.separator();
                ui.horizontal_wrapped(|ui| {
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
                ui.add(
                    egui::Label::new(egui::RichText::new(&view.node.id).small().monospace())
                        .truncate(),
                )
                .on_hover_text(format!(
                    "{} · generation {}",
                    view.node.id, view.runtime_generation
                ));
            });
        });
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
        widgets::page_header(
            ui,
            self.t("审计记录", "Audit log"),
            self.t(
                "查看账号、授权和配置变更的真实记录。",
                "Review recorded account, authorization and configuration changes.",
            ),
            250.,
            |ui| {
                if let Some(retention) = &snapshot.audit_retention.data
                    && ui.button(self.t("保留策略", "Retention policy")).clicked()
                {
                    self.workspace.retention_draft =
                        Some((retention.revision, retention.retention_seconds));
                }
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
            },
        );
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.workspace.audit_filter)
                    .desired_width(320.)
                    .margin(egui::vec2(10., 8.))
                    .hint_text(if self.english {
                        "Filter this page by event or resource"
                    } else {
                        "筛选本页事件或关联对象…"
                    })
                    .char_limit(128),
            );
            if let Some(retention) = &snapshot.audit_retention.data {
                ui.small(format!(
                    "{} {} {}",
                    self.t("记录保留", "Retain records for"),
                    retention.retention_seconds / 86_400,
                    self.t("天", "days")
                ));
            }
        });
        ui.add_space(12.);
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
            let query = self.workspace.audit_filter.trim().to_lowercase();
            widgets::surface(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::horizontal()
                    .id_salt("audit-table-scroll")
                    .show(ui, |ui| {
                        ui.set_min_width(720.);
                        egui::Grid::new("audit-table")
                            .num_columns(5)
                            .min_col_width(75.)
                            .max_col_width(240.)
                            .spacing([20., 18.])
                            .show(ui, |ui| {
                                for heading in [
                                    self.t("时间（UTC）", "Time (UTC)"),
                                    self.t("事件", "Event"),
                                    self.t("关联对象", "Resource"),
                                    self.t("操作者", "Actor"),
                                    self.t("记录序号", "Sequence"),
                                ] {
                                    ui.strong(heading);
                                }
                                ui.end_row();
                                for entry in page.entries.iter().filter(|entry| {
                                    query.is_empty()
                                        || entry.event.to_lowercase().contains(&query)
                                        || entry.resource_id.to_lowercase().contains(&query)
                                }) {
                                    ui.small(widgets::utc_time(entry.created_at_unix_ms / 1000));
                                    ui.add(egui::Label::new(&entry.event).truncate())
                                        .on_hover_text(&entry.event);
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&entry.resource_id)
                                                .monospace()
                                                .small(),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(&entry.resource_id);
                                    let actor = match &entry.actor {
                                        nestlink_protocol::api::AuditActor::Management {
                                            account_id,
                                            ..
                                        }
                                        | nestlink_protocol::api::AuditActor::Device {
                                            account_id,
                                            ..
                                        }
                                        | nestlink_protocol::api::AuditActor::DeviceCredential {
                                            account_id,
                                            ..
                                        } => account_id.as_str(),
                                        nestlink_protocol::api::AuditActor::Node {
                                            node_id,
                                            ..
                                        } => node_id.as_str(),
                                        nestlink_protocol::api::AuditActor::Legacy => {
                                            self.t("历史记录", "Legacy")
                                        }
                                        nestlink_protocol::api::AuditActor::LocalOperator => {
                                            self.t("本机操作者", "Local operator")
                                        }
                                        nestlink_protocol::api::AuditActor::Unauthenticated => {
                                            self.t("未认证", "Unauthenticated")
                                        }
                                    };
                                    ui.add(egui::Label::new(actor).truncate()).on_hover_text(
                                        serde_json::to_string(&entry.actor).unwrap_or_default(),
                                    );
                                    ui.small(format!("#{}", entry.sequence));
                                    ui.end_row();
                                }
                            });
                    });
            });
            ui.add_space(12.);
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
        widgets::section(ui, &snapshot.audit, self.english);
        widgets::section(ui, &snapshot.audit_retention, self.english);
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
