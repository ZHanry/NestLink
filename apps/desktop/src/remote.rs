use crate::{
    DesktopApp,
    icons::{self, Icon},
    theme, widgets,
};
use eframe::egui;
use nestlink_app_core::{Action, BrowserHostStatus, NativeSessionStatus, Page, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::Permission;
use nestlink_protocol::api::{ApprovalChoice, DeviceView, RemoteView, TrustChoice};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(crate) struct RemoteForm {
    pub selected: Option<String>,
    pub(super) host_device_id: Option<String>,
    pub(super) flow: Option<crate::remote_flow::ConnectionFlow>,
    pub(super) next_inbox_poll: std::time::Instant,
    search: String,
    pub(super) permissions: [bool; 7],
    pub(super) path: String,
    pub(super) trusted: bool,
    approval: Option<ApprovalDraft>,
    host_password: Zeroizing<String>,
    host_password_confirm: Zeroizing<String>,
    host_password_permissions: [bool; 7],
    host_password_paths: [bool; 2],
    host_password_days: u8,
    one_time_password: Zeroizing<String>,
    one_time_password_context: Option<OneTimePasswordContext>,
}
impl Default for RemoteForm {
    fn default() -> Self {
        Self {
            selected: None,
            host_device_id: None,
            flow: None,
            next_inbox_poll: std::time::Instant::now(),
            search: String::new(),
            permissions: [true, false, false, false, false, false, false],
            path: "direct_preferred".into(),
            trusted: false,
            approval: None,
            host_password: Zeroizing::default(),
            host_password_confirm: Zeroizing::default(),
            host_password_permissions: [true, false, false, false, false, false, false],
            host_password_paths: [true, true],
            host_password_days: 1,
            one_time_password: Zeroizing::default(),
            one_time_password_context: None,
        }
    }
}
impl RemoteForm {
    fn reconcile_one_time_password_context(&mut self, snapshot: &Snapshot) {
        let password_context = one_time_password_context(snapshot, self.selected.as_deref());
        if self.one_time_password_context != password_context {
            self.one_time_password = Zeroizing::default();
            self.one_time_password_context = password_context;
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct OneTimePasswordContext {
    request_id: String,
    request_nonce: String,
    policy_revision: u64,
    connection_generation: u64,
    password_revision: u64,
}
impl OneTimePasswordContext {
    fn matches_request(&self, request: &RemoteView) -> bool {
        self.request_id == request.id
            && self.request_nonce == request.nonce
            && self.policy_revision == request.policy_revision
            && self.connection_generation == request.connection_generation
    }
}
struct ApprovalDraft {
    id: String,
    nonce: String,
    policy_revision: u64,
    permissions: [bool; 7],
    paths: Vec<i32>,
}
impl DesktopApp {
    fn remote_device_picker(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let local_id = snapshot
            .installation
            .as_ref()
            .map(|local| local.device_id.as_str());
        let enrolled = snapshot.devices.data.as_ref().is_some_and(|devices| {
            devices
                .iter()
                .any(|view| Some(view.device.id.as_str()) == local_id && !view.revoked)
        });
        ui.add_space(18.);
        egui::Frame::group(ui.style())
            .inner_margin(18)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    icons::badge(ui, Icon::Devices, 42.);
                    ui.vertical(|ui| {
                        ui.strong(self.t("此设备", "This device"));
                        ui.small(self.t(
                            if enrolled {
                                "已登记，可接收授权连接"
                            } else {
                                "登记后可发起或接收远程连接"
                            },
                            if enrolled {
                                "Enrolled · ready for authorized connections"
                            } else {
                                "Enroll to connect or receive requests"
                            },
                        ));
                    });
                    if let Some(id) = local_id
                        && icons::button(ui, Icon::Copy, self.t("复制设备 ID", "Copy device ID"))
                            .clicked()
                    {
                        ui.ctx().copy_text(id.into());
                    }
                    if !enrolled
                        && snapshot.devices.loading.is_none()
                        && icons::button(
                            ui,
                            Icon::Connect,
                            self.t("登记此设备", "Enroll this device"),
                        )
                        .clicked()
                    {
                        self.action(
                            snapshot,
                            Action::EnrollLocalDevice {
                                name: std::env::var("COMPUTERNAME")
                                    .or_else(|_| std::env::var("HOSTNAME"))
                                    .unwrap_or_else(|_| "My computer".into())
                                    .chars()
                                    .take(128)
                                    .collect(),
                                platform: std::env::consts::OS.into(),
                                capabilities: super::management::local_capabilities(),
                                path_mode: "direct_preferred".into(),
                            },
                        );
                    }
                });
            });
        ui.add_space(20.);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(self.t("可连接的设备", "Your computers"))
                    .size(self.tokens.typography.section)
                    .strong(),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.remote.search)
                    .desired_width(220.)
                    .hint_text(if self.english {
                        "Search name or device ID"
                    } else {
                        "搜索设备名称或 ID"
                    })
                    .char_limit(128),
            );
        });
        widgets::section(ui, &snapshot.devices, self.english);
        let query = self.remote.search.trim().to_lowercase();
        let hosts: Vec<_> = snapshot
            .devices
            .data
            .as_deref()
            .filter(|_| snapshot.devices.error.is_none())
            .into_iter()
            .flatten()
            .filter(|view| is_eligible_host(view, local_id))
            .filter(|view| {
                query.is_empty()
                    || view.device.name.to_lowercase().contains(&query)
                    || view.device.id.to_lowercase().contains(&query)
            })
            .collect();
        if hosts.is_empty() && snapshot.devices.loading.is_none() {
            ui.add_space(8.);
            ui.label(self.t(
                if query.is_empty() {
                    "还没有其他被控设备"
                } else {
                    "没有匹配的设备"
                },
                if query.is_empty() {
                    "No other host devices yet"
                } else {
                    "No matching devices"
                },
            ));
            ui.small(self.t(
                "在另一台电脑登录同一服务器并登记设备，再刷新此列表。",
                "Sign in to this server and enroll the other computer, then refresh this list.",
            ));
        }
        egui::ScrollArea::vertical()
            .id_salt("remote-device-picker")
            .max_height(244.)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for view in &hosts {
                    let selected =
                        self.remote.host_device_id.as_deref() == Some(view.device.id.as_str());
                    let fill = if selected {
                        ui.visuals().selection.bg_fill.gamma_multiply(0.09)
                    } else {
                        ui.visuals().window_fill
                    };
                    egui::Frame::group(ui.style())
                        .fill(fill)
                        .inner_margin(14)
                        .show(ui, |ui| {
                            ui.set_min_width((ui.available_width() - 2.).max(0.));
                            ui.horizontal(|ui| {
                                icons::badge(ui, Icon::Monitor, 44.);
                                ui.vertical(|ui| {
                                    ui.set_max_width((ui.available_width() - 110.).max(80.));
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&view.device.name).strong(),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(&view.device.name);
                                    ui.small(format!(
                                        "{} · {}",
                                        view.device.platform,
                                        self.t("已登记", "Enrolled")
                                    ));
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .selectable_label(
                                                selected,
                                                self.t(
                                                    if selected {
                                                        "已选择"
                                                    } else {
                                                        "选择设备"
                                                    },
                                                    if selected { "Selected" } else { "Select" },
                                                ),
                                            )
                                            .clicked()
                                        {
                                            self.remote.host_device_id =
                                                Some(view.device.id.clone());
                                        }
                                    },
                                );
                            });
                        });
                }
            });
        ui.add_space(10.);
        egui::Frame::group(ui.style()).inner_margin(18).show(ui, |ui| {
            let selected = snapshot.devices.data.as_deref().into_iter().flatten().find(|view| self.remote.host_device_id.as_deref() == Some(view.device.id.as_str()));
            ui.strong(selected.map(|view| view.device.name.as_str()).unwrap_or(self.t("选择一台设备开始连接", "Select a device to connect")));
            ui.horizontal_wrapped(|ui| {
                if ui.selectable_label(!self.remote.permissions[1], self.t("仅查看", "View only")).clicked() { self.remote.permissions[1] = false; }
                if ui.selectable_label(self.remote.permissions[1], self.t("远程控制", "Control")).clicked() { self.remote.permissions[1] = true; }
                ui.checkbox(&mut self.remote.trusted, if self.english { "Use trusted-device access" } else { "使用已有受信授权" });
            });
            egui::CollapsingHeader::new(self.t("权限与连接选项", "Permissions and connection options")).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (index, icon) in [(2, Icon::Audio), (3, Icon::Folder), (4, Icon::Folder), (5, Icon::Clipboard), (6, Icon::Clipboard)] {
                        ui.horizontal(|ui| {
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(18., 18.), egui::Sense::hover());
                            icons::paint(ui, icon, rect.center(), 18., ui.visuals().weak_text_color());
                            ui.checkbox(&mut self.remote.permissions[index], widgets::permissions(&[(index + 1) as i32], self.english));
                        });
                    }
                });
                egui::ComboBox::from_id_salt("request-path").selected_text(path_label(&self.remote.path, self.english)).show_ui(ui, |ui| {
                    for path in ["direct_preferred", "relay_only", "direct_only"] {
                        ui.selectable_value(&mut self.remote.path, path.into(), path_label(path, self.english));
                    }
                });
                ui.small(self.t("自动连接会尝试直连和已获授权的中继。公司网络屏蔽 UDP 时可选择中继。", "Automatic mode tries direct and authorized relay paths. Use relay for networks that block UDP."));
            });
            let live = snapshot.native_session.data.as_ref().is_some_and(|session| matches!(session.status, NativeSessionStatus::Establishing | NativeSessionStatus::Connected | NativeSessionStatus::Stopping));
            let ready = enrolled && selected.is_some() && !live && !self.remote.flow.as_ref().is_some_and(|flow| flow.is_busy()) && snapshot.devices.loading.is_none() && snapshot.devices.error.is_none();
            ui.add_space(8.);
            if widgets::primary_button(ui, self.t("连接设备", "Connect to device"), ready).clicked() { self.connect_remote_device(snapshot); }
        });
    }

    pub(crate) fn reconcile_remote_password_context(&mut self, snapshot: &Snapshot) {
        self.remote.reconcile_one_time_password_context(snapshot);
    }

    pub(crate) fn remote_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        reconcile_host_selection(&mut self.remote, snapshot);
        ui.horizontal(|ui| {
            ui.heading(self.t("远程控制", "Remote access"));
            if ui
                .add_enabled(
                    snapshot.devices.loading.is_none() && snapshot.requests.loading.is_none(),
                    egui::Button::new(self.t("刷新", "Refresh")),
                )
                .clicked()
            {
                self.load(snapshot, Page::Devices);
                self.load(snapshot, Page::Requests);
                if let Some(id) = &self.remote.selected {
                    self.action(
                        snapshot,
                        Action::InspectRemote {
                            request_id: id.clone(),
                        },
                    );
                }
            }
        });
        ui.label(self.t(
            "先选择权限并申请访问，由被控设备明确批准。",
            "Choose permissions and request access, then obtain approval from the host device.",
        ));
        let waiting = incoming_requests(snapshot).count();
        if waiting > 0 {
            ui.colored_label(
                ui.visuals().hyperlink_color,
                if self.english {
                    format!("{waiting} incoming request(s) await approval below.")
                } else {
                    format!("有 {waiting} 条访问请求，请在下方查看并批准。")
                },
            );
        }
        self.remote_device_picker(ui, snapshot);
        self.connection_progress(ui, snapshot);
        self.native_session_panel(ui, snapshot);
        self.browser_host_panel(ui, snapshot);
        ui.add_space(20.);
        ui.label(
            egui::RichText::new(self.t(
                "等待本机批准的请求",
                "Requests awaiting this device's approval",
            ))
            .strong()
            .size(self.tokens.typography.section),
        );
        widgets::section(ui, &snapshot.requests, self.english);
        if snapshot.requests.data.is_some() {
            if incoming_requests(snapshot).next().is_none() {
                ui.label(self.t(
                    "当前没有待批准请求。",
                    "There are no requests awaiting approval.",
                ));
            }
            for request in incoming_requests(snapshot) {
                ui.push_id(&request.id, |ui| {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_height(self.tokens.layout.row_height);
                        ui.horizontal_wrapped(|ui| {
                            let name = snapshot
                                .devices
                                .data
                                .as_deref()
                                .into_iter()
                                .flatten()
                                .find(|device| device.device.id == request.controller_device_id)
                                .map(|device| device.device.name.as_str())
                                .unwrap_or(&request.controller_device_id);
                            ui.strong(name);
                            ui.small(self.t("希望连接此设备", "Wants to connect to this device"));
                            if ui.button(self.t("查看并批准", "Review request")).clicked() {
                                if self.remote.selected.as_deref() != Some(request.id.as_str()) {
                                    self.remote.one_time_password = Zeroizing::default();
                                }
                                self.remote.selected = Some(request.id.clone());
                                self.remote.approval = None;
                                self.action(
                                    snapshot,
                                    Action::InspectRemote {
                                        request_id: request.id.clone(),
                                    },
                                );
                            }
                        });
                        ui.small(widgets::permissions(&request.permissions, self.english));
                    });
                });
            }
        }
        ui.add_space(20.);
        widgets::section(ui, &snapshot.selected_request, self.english);
        if let Some(request) = &snapshot.selected_request.data {
            self.request_details(ui, snapshot, request);
        }
        self.transfer_panels(ui, snapshot);
        ui.add_space(20.);
        egui::CollapsingHeader::new(
            self.t("本机访问与网络设置", "Host access and network settings"),
        )
        .show(ui, |ui| {
            self.remote_password_host_panel(ui, snapshot);
            if let Some(command) =
                self.privileged_panel
                    .show(ui, snapshot, self.english, self.connected)
            {
                let submission = self.bridge.submit_tracked(snapshot.generation, command);
                self.privileged_panel.submitted(submission);
            }
            if let Some(command) = self.network_panel.show(ui, snapshot, self.english) {
                self.network_submission = if self.connected {
                    self.bridge.submit_tracked(snapshot.generation, command)
                } else {
                    None
                };
                if self.network_submission.is_none() {
                    self.network_panel
                        .complete(Err(nestlink_app_core::NativeNetworkError::Unavailable));
                }
            }
        });
        ui.add_space(12.);
        ui.small(self.t(
            "仅在访问获准且连接可用时显示远端画面。",
            "The remote screen appears after access is approved and the connection is ready.",
        ));
    }

    fn native_session_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::section(ui, &snapshot.native_session, self.english);
        let Some(session) = snapshot.native_session.data.as_ref() else {
            return;
        };
        ui.add_space(8.);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(self.t("当前会话", "Current session")).strong());
                ui.label(match session.status {
                    NativeSessionStatus::Establishing => self.t("正在建立", "Establishing"),
                    NativeSessionStatus::Connected => self.t("已连接", "Connected"),
                    NativeSessionStatus::Stopping => self.t("正在停止", "Stopping"),
                    NativeSessionStatus::Stopped => self.t("已停止", "Stopped"),
                    NativeSessionStatus::Failed => self.t("建立失败", "Failed"),
                });
            });
            if let Some(path) = session.path {
                ui.label(self.t(
                    if path == 1 { "直连" } else { "中继连接" },
                    if path == 1 {
                        "Direct connection"
                    } else {
                        "Relay connection"
                    },
                ));
            }
            egui::CollapsingHeader::new(self.t("连接诊断", "Connection diagnostics")).show(
                ui,
                |ui| {
                    ui.monospace(&session.request_id);
                    ui.label(format!(
                        "{} {} · {} {}",
                        self.t("连接代次", "Connection generation"),
                        session.connection_generation,
                        self.t("许可序号", "Permit sequence"),
                        session.lease_sequence
                    ));
                    if let Some(path) = session.path {
                        ui.label(if path == 1 {
                            self.t("直连", "Direct")
                        } else if path == 2 {
                            self.t("中继", "Relay")
                        } else {
                            self.t("未知路径", "Unknown path")
                        });
                    }
                    if let Some(reason) = session.stop_reason {
                        ui.label(format!("{}: {reason:?}", self.t("停止原因", "Stop reason")));
                    }
                    if let Some(cleanup) = session.cleanup {
                        ui.label(format!(
                            "{}: {cleanup:?}",
                            self.t("清理结果", "Cleanup result")
                        ));
                    }
                    if let Some(effects) = session.stop_effects {
                        ui.small(format!(
                            "{}: channels={} · inputs={} · queues={} · allocations={}",
                            self.t("停止效果", "Stop effects"),
                            effects.cancel_channels,
                            effects.release_inputs,
                            effects.discard_queues,
                            effects.close_allocations
                        ));
                    }
                },
            );
            self.native_display_panel(ui, snapshot);
            if !session.host_view_authorized
                && matches!(
                    session.status,
                    NativeSessionStatus::Establishing | NativeSessionStatus::Connected
                )
                && ui
                    .add_enabled(
                        self.remote_window_cleanup.is_none(),
                        egui::Button::new(self.t("打开独立远控窗口", "Open remote control window")),
                    )
                    .clicked()
            {
                self.open_remote_viewport(
                    snapshot,
                    crate::RemoteViewportTarget {
                        request_id: session.request_id.clone(),
                        connection_generation: session.connection_generation,
                    },
                );
            }
            match session.status {
                NativeSessionStatus::Establishing => {
                    if let Some(operation) = snapshot.native_session.loading
                        && ui.button(self.t("取消连接", "Cancel connection")).clicked()
                    {
                        self.send(snapshot, Command::Cancel { operation });
                    }
                }
                NativeSessionStatus::Connected => {
                    if ui.button(self.t("停止会话", "Stop session")).clicked() {
                        self.action(
                            snapshot,
                            Action::StopNativeSession {
                                request_id: session.request_id.clone(),
                                connection_generation: session.connection_generation,
                            },
                        );
                    }
                }
                NativeSessionStatus::Stopping
                | NativeSessionStatus::Stopped
                | NativeSessionStatus::Failed => {}
            }
        });
    }

    fn browser_host_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::section(ui, &snapshot.browser_host, self.english);
        let Some(host) = snapshot.browser_host.data.as_ref() else {
            return;
        };
        self.browser_data_panel.reconcile(
            host.binding.clone(),
            snapshot.generation,
            (host.status == BrowserHostStatus::Connected).then_some(&host.data),
        );
        ui.add_space(8.);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(self.t("浏览器查看会话", "Browser viewing session"))
                        .strong(),
                );
                ui.label(match host.status {
                    BrowserHostStatus::Establishing => self.t("正在建立", "Establishing"),
                    BrowserHostStatus::Connected => self.t("已连接", "Connected"),
                    BrowserHostStatus::Stopping => self.t("正在停止", "Stopping"),
                    BrowserHostStatus::Stopped => self.t("已停止", "Stopped"),
                    BrowserHostStatus::Failed => self.t("建立失败", "Failed"),
                });
            });
            ui.monospace(&host.request_id);
            ui.label(format!(
                "{} {} · {} {}",
                self.t("连接代次", "Connection generation"),
                host.connection_generation,
                self.t("许可序号", "Permit sequence"),
                host.lease_sequence
            ));
            if let Some(path) = host.path {
                ui.label(if path == 1 {
                    self.t("直连", "Direct")
                } else if path == 2 {
                    self.t("中继", "Relay")
                } else {
                    self.t("未知路径", "Unknown path")
                });
            }
            if let Some(reason) = host.stop_reason {
                ui.label(format!("{}: {reason:?}", self.t("停止原因", "Stop reason")));
            }
            if let Some(cleanup) = host.cleanup {
                ui.label(format!("{}: {cleanup:?}", self.t("清理结果", "Cleanup result")));
            }
            if let Some(effects) = host.stop_effects {
                ui.small(format!(
                    "{}: channels={} · inputs={} · queues={} · allocations={}",
                    self.t("停止效果", "Stop effects"),
                    effects.cancel_channels,
                    effects.release_inputs,
                    effects.discard_queues,
                    effects.close_allocations
                ));
            }
            self.browser_display_panel(ui, snapshot);
            ui.small(self.t(
                "浏览器宿主支持屏幕查看、文件共享和剪贴板。Windows/Linux 还支持输入和系统音频；Wayland 当前不提供浏览器剪贴板授权。",
                "Browser hosting supports screen viewing, file sharing and clipboard. Windows/Linux also support input and system audio; browser clipboard approval is unavailable on Wayland.",
            ));
            match host.status {
                BrowserHostStatus::Establishing => {
                    if let Some(operation) = snapshot.browser_host.loading
                        && ui.button(self.t("取消连接", "Cancel connection")).clicked()
                    {
                        self.send(snapshot, Command::Cancel { operation });
                    }
                }
                BrowserHostStatus::Connected => {
                    if ui.button(self.t("停止会话", "Stop session")).clicked() {
                        self.action(
                            snapshot,
                            Action::StopBrowserHost {
                                request_id: host.request_id.clone(),
                                connection_generation: host.connection_generation,
                            },
                        );
                    }
                    if let Some(action) = self.browser_data_panel.show(ui, self.english, &host.data)
                        && let Some(binding) = host.binding.clone()
                    {
                        let submission = if self.connected {
                            self.bridge.submit_tracked(
                                snapshot.generation,
                                Command::BrowserHostData {
                                    binding,
                                    action,
                                },
                            )
                        } else { None };
                        if let Some(submission_id) = submission {
                            self.browser_data_submission = Some(submission_id);
                            self.browser_data_panel.submitted(submission_id);
                        } else {
                            self.browser_data_submission = None;
                            self.browser_data_panel.rejected_before_submit(self.t(
                                "本机批准操作未送出，请检查守护进程连接。",
                                "The local approval was not sent. Check the daemon connection.",
                            ));
                        }
                    }
                }
                BrowserHostStatus::Stopping | BrowserHostStatus::Stopped | BrowserHostStatus::Failed => {}
            }
        });
    }
    fn remote_password_host_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        use nestlink_protocol::api::RemotePasswordSettings;

        let local_id = snapshot
            .installation
            .as_ref()
            .map(|installation| installation.device_id.as_str());
        let enrolled_host = local_id.is_some_and(|id| {
            snapshot.devices.data.as_ref().is_some_and(|devices| {
                devices.iter().any(|device| {
                    !device.revoked
                        && device.device.id == id
                        && device
                            .device
                            .capabilities
                            .iter()
                            .any(|capability| capability == "host")
                })
            })
        });
        let current = local_id.and_then(|id| {
            snapshot
                .remote_password
                .data
                .as_deref()
                .filter(|entry| entry.host_device_id == id)
        });
        let mut action = None;
        let mut revoke_confirmation = false;
        let mut configuration_error = None;
        let english = self.english;

        egui::CollapsingHeader::new(self.t("本机一次性密码授权", "One-time password access for this host"))
            .show(ui, |ui| {
                widgets::section(ui, &snapshot.remote_password, english);
                ui.label(self.t(
                    "此密码只用于批准单次访问，不会建立受信关系。设置的权限、路径和截止时间会限制每个请求。",
                    "This password authorizes one access request and never creates device trust. Its permissions, paths and expiry limit each request.",
                ));
                if !enrolled_host {
                    ui.label(self.t(
                        "当前安装尚未登记为 host 设备。请先登记本机 host 能力，再配置一次性密码。",
                        "This installation is not enrolled as a host device. Enroll its host capability before configuring a one-time password.",
                    ));
                    return;
                }
                let Some(local_id) = local_id else {
                    return;
                };
                let loaded = current.is_some() && snapshot.remote_password.error.is_none();
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            snapshot.remote_password.loading.is_none(),
                            egui::Button::new(if loaded {
                                self.t("刷新配置", "Refresh configuration")
                            } else {
                                self.t("读取当前配置", "Load current configuration")
                            }),
                        )
                        .clicked()
                    {
                        action = Some(Action::LoadRemotePassword {
                            host_device_id: local_id.to_owned(),
                        });
                    }
                });
                if let Some(current) = current {
                    let settings = &current.settings;
                    ui.label(format!(
                        "{} {} · {} · {} UTC ms",
                        self.t("版本", "Revision"),
                        settings.revision,
                        if settings.active {
                            self.t("已启用", "Active")
                        } else {
                            self.t("未启用", "Inactive")
                        },
                        settings.expires_at_unix_ms
                    ));
                    if settings.active {
                        ui.label(format!(
                            "{}: {} · {}",
                            self.t("有效范围", "Scope"),
                            widgets::permissions(&settings.permissions, english),
                            remote_paths(&settings.paths, english)
                        ));
                        if ui
                            .add_enabled(
                                snapshot.remote_password.loading.is_none(),
                                egui::Button::new(
                                    egui::RichText::new(self.t(
                                        "撤销密码并关闭其会话",
                                        "Revoke password and close its sessions",
                                    ))
                                    .color(theme::color(if self.dark {
                                        &self.tokens.state.danger_action_text.dark
                                    } else {
                                        &self.tokens.state.danger_action_text.light
                                    })),
                                )
                                .fill(theme::color(if self.dark {
                                    &self.tokens.state.danger_action.dark
                                } else {
                                    &self.tokens.state.danger_action.light
                                })),
                            )
                            .clicked()
                        {
                            revoke_confirmation = true;
                        }
                    }
                } else if snapshot.remote_password.loading.is_none() {
                    ui.small(self.t(
                        "先读取当前配置，确认版本后再设置或轮换。",
                        "Load the current revision before setting or rotating the password.",
                    ));
                }
                let Some(current) = current else {
                    return;
                };
                ui.separator();
                ui.label(self.t("允许的权限（屏幕查看必需）", "Allowed permissions (view is required)"));
                ui.horizontal_wrapped(|ui| {
                    for (index, value) in self.remote.host_password_permissions.iter_mut().enumerate() {
                        ui.checkbox(value, widgets::permissions(&[(index + 1) as i32], english));
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(
                        &mut self.remote.host_password_paths[0],
                        if english { "Direct" } else { "直连" },
                    );
                    ui.checkbox(
                        &mut self.remote.host_password_paths[1],
                        if english { "Relay" } else { "中继" },
                    );
                });
                egui::ComboBox::from_id_salt("host-password-expiry")
                    .selected_text(format!("{} {}", self.remote.host_password_days, self.t("天后到期", "day expiry")))
                    .show_ui(ui, |ui| {
                        for days in [1_u8, 7, 30] {
                            ui.selectable_value(
                                &mut self.remote.host_password_days,
                                days,
                                format!("{} {}", days, if english { "days" } else { "天" }),
                            );
                        }
                    });
                widgets::secret_field(
                    ui,
                    self.t("新密码（12–1024 字节）", "New password (12–1024 bytes)"),
                    &mut self.remote.host_password,
                    "remote-password-host",
                    snapshot.generation,
                    1024,
                );
                widgets::secret_field(
                    ui,
                    self.t("再次输入密码", "Confirm password"),
                    &mut self.remote.host_password_confirm,
                    "remote-password-host-confirm",
                    snapshot.generation,
                    1024,
                );
                let password_len = self.remote.host_password.len();
                let password_valid = (12..=1024).contains(&password_len)
                    && self.remote.host_password.as_str()
                        == self.remote.host_password_confirm.as_str();
                let paths = selected_paths(&self.remote.host_password_paths);
                if password_len > 0 && self.remote.host_password.as_str()
                    != self.remote.host_password_confirm.as_str()
                {
                    ui.small(self.t("两次输入不一致。", "The passwords do not match."));
                }
                if ui
                    .add_enabled(
                        snapshot.remote_password.loading.is_none()
                            && loaded
                            && self.remote.host_password_permissions[0]
                            && !paths.is_empty()
                            && password_valid,
                        egui::Button::new(if current.settings.active {
                            self.t("轮换并立即撤销旧授权", "Rotate and revoke old access now")
                        } else {
                            self.t("启用一次性密码", "Enable one-time password")
                        }),
                    )
                    .clicked()
                {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|duration| u64::try_from(duration.as_millis()).ok());
                    if let Some(expires_at_unix_ms) = now_ms.and_then(|now| {
                        now.checked_add(u64::from(self.remote.host_password_days) * 86_400_000)
                    }) {
                        action = Some(Action::ConfigureRemotePassword {
                            settings: RemotePasswordSettings {
                                expected_revision: current.settings.revision,
                                permissions: selected(&self.remote.host_password_permissions),
                                paths,
                                expires_at_unix_ms,
                            },
                            password: widgets::take_secret(&mut self.remote.host_password),
                        });
                        self.remote.host_password_confirm = Zeroizing::default();
                    } else {
                        configuration_error = Some(self.t("系统时间不可用，未提交。", "System time is unavailable; nothing was submitted."));
                    }
                }
                if let Some(error) = configuration_error {
                    ui.colored_label(egui::Color32::RED, error);
                }
            });

        if let Some(action) = action {
            self.action(snapshot, action);
        }
        if revoke_confirmation && let Some(current) = current {
            self.pending_confirmation = Some((
                self.t(
                    "撤销会关闭所有通过此密码授权的会话。",
                    "Revocation closes every session authorized with this password.",
                )
                .into(),
                nestlink_app_ipc::wire::Command::Submit {
                    action: Action::RevokeRemotePassword {
                        expected_revision: current.settings.revision,
                    },
                },
            ));
        }
    }

    fn remote_password_offer_panel(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        request: &RemoteView,
        busy: bool,
    ) {
        let request_is_current =
            selected_request_is_current(snapshot, self.remote.selected.as_deref(), request);
        let current_context = one_time_password_context(snapshot, self.remote.selected.as_deref());
        let offer_ready = request_is_current
            && current_context.as_ref().is_some_and(|context| {
                self.remote.one_time_password_context.as_ref() == Some(context)
                    && context.matches_request(request)
            });
        let offer = snapshot
            .remote_password_offer
            .data
            .as_deref()
            .filter(|offer| offer_ready && offer.request_id == request.id);
        let mut load_offer = false;
        let mut authorize = None;
        ui.separator();
        ui.label(
            egui::RichText::new(self.t("单次密码授权", "One-time password authorization")).strong(),
        );
        widgets::section(ui, &snapshot.remote_password_offer, self.english);
        ui.label(self.t(
            "可用被控设备的明确密码批准本次请求。此操作不会保存密码或建立受信设备关系。",
            "Use the host's explicit password grant for this request. The password is not saved and no trusted-device relationship is created.",
        ));
        if let Some(offer) = offer {
            let settings = &offer.settings;
            if settings.active {
                ui.label(format!(
                    "{}: revision {} · {} · {} · {} UTC ms",
                    self.t("被控设备允许的范围", "Host-authorized scope"),
                    settings.revision,
                    widgets::permissions(&settings.permissions, self.english),
                    remote_paths(&settings.paths, self.english),
                    settings.expires_at_unix_ms
                ));
                widgets::secret_field(
                    ui,
                    self.t("一次性授权密码", "One-time authorization password"),
                    &mut self.remote.one_time_password,
                    "remote-password-attempt",
                    snapshot.generation,
                    1024,
                );
                let password_len = self.remote.one_time_password.len();
                if ui
                    .add_enabled(
                        !busy && offer_ready && (12..=1024).contains(&password_len),
                        egui::Button::new(self.t("仅批准本次请求", "Authorize this request only")),
                    )
                    .clicked()
                {
                    authorize = Some(Action::AuthorizeRemotePassword {
                        request_id: request.id.clone(),
                        expected_revision: settings.revision,
                        password: widgets::take_secret(&mut self.remote.one_time_password),
                    });
                }
            } else {
                ui.small(self.t(
                    "被控设备当前没有可用的一次性密码配置。",
                    "The host has no active one-time password configuration.",
                ));
            }
        } else {
            ui.small(self.t(
                "读取被控设备当前一次性授权范围后再输入密码。",
                "Load the host's current one-time authorization scope before entering a password.",
            ));
        }
        ui.add_enabled_ui(
            !busy && request_is_current && snapshot.remote_password_offer.loading.is_none(),
            |ui| {
                if ui
                    .button(if offer.is_some() {
                        self.t("刷新授权范围", "Refresh authorization scope")
                    } else {
                        self.t("查看一次性授权范围", "View one-time authorization scope")
                    })
                    .clicked()
                {
                    self.remote.one_time_password = Zeroizing::default();
                    load_offer = true;
                }
            },
        );
        if load_offer {
            self.action(
                snapshot,
                Action::LoadRemotePasswordOffer {
                    request_id: request.id.clone(),
                },
            );
        }
        if let Some(action) = authorize {
            self.action(snapshot, action);
        }
    }

    fn request_details(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot, request: &RemoteView) {
        ui.separator();
        ui.label(egui::RichText::new(self.t("请求详情", "Request details")).strong());
        ui.label(self.t(
            match request.status.as_str() {
                "pending" => "等待批准",
                "approved" => "访问已批准",
                "denied" => "访问已拒绝",
                "revoked" => "访问已撤销",
                _ => "访问已结束",
            },
            match request.status.as_str() {
                "pending" => "Awaiting approval",
                "approved" => "Access approved",
                "denied" => "Access denied",
                "revoked" => "Access revoked",
                _ => "Access ended",
            },
        ));
        ui.label(widgets::permissions(&request.permissions, self.english));
        egui::CollapsingHeader::new(self.t("请求诊断", "Request diagnostics")).show(ui, |ui| {
            ui.monospace(&request.id);
            ui.label(format!(
                "{} → {}",
                request.controller_device_id, request.host_device_id
            ));
            ui.label(format!(
                "{} · policy {} · connection {} · lease {}",
                request.status,
                request.policy_revision,
                request.connection_generation,
                request.lease_sequence
            ));
            ui.label(widgets::permissions(&request.permissions, self.english));
            ui.small(format!("{} UTC ms", request.expires_at_unix_ms));
        });
        let local = snapshot
            .installation
            .as_ref()
            .map(|installation| installation.device_id.as_str());
        let is_host = local == Some(request.host_device_id.as_str());
        let is_controller = local == Some(request.controller_device_id.as_str());
        let request_is_current =
            selected_request_is_current(snapshot, self.remote.selected.as_deref(), request);
        let busy = snapshot.selected_request.loading.is_some()
            || snapshot.requests.loading.is_some()
            || snapshot.native_session.loading.is_some()
            || snapshot.browser_host.loading.is_some();
        if is_controller && request.status == "pending" && request_is_current {
            self.remote_password_offer_panel(ui, snapshot, request, busy);
        }
        if is_host && request.status == "pending" && request_is_current {
            if self.remote.approval.as_ref().is_none_or(|draft| {
                draft.id != request.id
                    || draft.nonce != request.nonce
                    || draft.policy_revision != request.policy_revision
            }) {
                let mut permissions = [false; 7];
                permissions[0] = request.permissions.contains(&1);
                self.remote.approval = Some(ApprovalDraft {
                    id: request.id.clone(),
                    nonce: request.nonce.clone(),
                    policy_revision: request.policy_revision,
                    permissions,
                    paths: request.paths.clone(),
                });
            }
            let mut choice = None;
            if let Some(draft) = &mut self.remote.approval {
                ui.horizontal_wrapped(|ui| {
                    for value in &request.permissions {
                        if let Ok(index) = usize::try_from(*value - 1)
                            && index < 7
                        {
                            ui.checkbox(
                                &mut draft.permissions[index],
                                widgets::permissions(&[*value], self.english),
                            );
                        }
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    for path in &request.paths {
                        let mut enabled = draft.paths.contains(path);
                        if ui
                            .checkbox(
                                &mut enabled,
                                if *path == 1 {
                                    if self.english { "Direct" } else { "直连" }
                                } else if self.english {
                                    "Relay"
                                } else {
                                    "中继"
                                },
                            )
                            .changed()
                        {
                            if enabled {
                                draft.paths.push(*path);
                            } else {
                                draft.paths.retain(|existing| existing != path);
                            }
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !busy && draft.permissions[0] && !draft.paths.is_empty(),
                            egui::Button::new(if self.english {
                                "Approve selected permissions"
                            } else {
                                "批准所选权限"
                            }),
                        )
                        .clicked()
                    {
                        choice = Some(true);
                    }
                    if ui
                        .add_enabled(
                            !busy,
                            egui::Button::new(if self.english { "Deny" } else { "拒绝" }),
                        )
                        .clicked()
                    {
                        choice = Some(false);
                    }
                });
                if let Some(approved) = choice {
                    let action = Action::ApproveRemote {
                        request_id: draft.id.clone(),
                        expected_nonce: draft.nonce.clone(),
                        expected_policy_revision: draft.policy_revision,
                        choice: ApprovalChoice {
                            approved,
                            permissions: if approved {
                                selected(&draft.permissions)
                            } else {
                                Vec::new()
                            },
                            paths: if approved {
                                draft.paths.clone()
                            } else {
                                Vec::new()
                            },
                        },
                    };
                    self.action(snapshot, action);
                }
            }
        }
        if is_controller
            && request.status == "approved"
            && request.lease_sequence == 0
            && !self.remote.flow.as_ref().is_some_and(|flow| flow.is_busy())
            && ui
                .add_enabled(
                    !busy,
                    egui::Button::new(
                        self.t("领取初始会话许可", "Issue the initial session permit"),
                    ),
                )
                .clicked()
        {
            self.action(
                snapshot,
                Action::IssueRemotePermit {
                    request_id: request.id.clone(),
                },
            );
        }
        if is_controller
            && request.status == "approved"
            && request.lease_sequence > 0
            && !self.remote.flow.as_ref().is_some_and(|flow| flow.is_busy())
            && snapshot.native_session.data.as_ref().is_none_or(|session| {
                session.request_id != request.id
                    || !matches!(
                        session.status,
                        NativeSessionStatus::Establishing
                            | NativeSessionStatus::Connected
                            | NativeSessionStatus::Stopping
                    )
            })
            && ui
                .add_enabled(
                    !busy,
                    egui::Button::new(self.t("建立原生会话", "Establish native session")),
                )
                .clicked()
        {
            self.action(
                snapshot,
                Action::StartNativeSession {
                    request_id: request.id.clone(),
                },
            );
        }
        let browser_permissions_supported = browser_permissions_supported(&request.permissions);
        if is_host
            && request.status == "approved"
            && request.lease_sequence > 0
            && snapshot.browser_host.data.as_ref().is_none_or(|host| {
                host.request_id != request.id
                    || !matches!(
                        host.status,
                        BrowserHostStatus::Establishing
                            | BrowserHostStatus::Connected
                            | BrowserHostStatus::Stopping
                    )
            })
            && ui
                .add_enabled(
                    !busy && browser_permissions_supported,
                    egui::Button::new(
                        self.t("启动浏览器查看会话", "Start browser viewing session"),
                    ),
                )
                .clicked()
        {
            self.action(
                snapshot,
                Action::StartBrowserHost {
                    request_id: request.id.clone(),
                },
            );
        }
        if is_host && request.status == "approved" && !browser_permissions_supported {
            ui.small(self.t(
                "此请求包含当前浏览器宿主不支持的权限，无法启动浏览器会话。",
                "This request includes permissions unsupported by the browser host, so a browser session cannot start.",
            ));
        }
        if (is_host || is_controller)
            && !matches!(request.status.as_str(), "revoked" | "denied" | "expired")
            && ui
                .add_enabled(
                    !busy,
                    egui::Button::new(self.t("撤销此访问", "Revoke access")),
                )
                .clicked()
        {
            self.pending_confirmation = Some((
                self.t(
                    "撤销此访问的许可与现有连接。",
                    "Revoke this access permit and its current connections.",
                )
                .into(),
                Command::Submit {
                    action: Action::RevokeRemote {
                        request_id: request.id.clone(),
                    },
                },
            ));
        }
        if is_host && request.lease_sequence > 0 && request.status == "approved" {
            ui.separator();
            if ui
                .button(self.t("查看本机受信设备", "Trusted devices for this host"))
                .clicked()
            {
                self.action(
                    snapshot,
                    Action::LoadTrustedDevices {
                        host_device_id: request.host_device_id.clone(),
                    },
                );
            }
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(self.t(
                        "将此控制端设为受信设备（1 小时）",
                        "Trust this controller for one hour",
                    )),
                )
                .clicked()
            {
                let revision = snapshot
                    .trusted_devices
                    .data
                    .as_ref()
                    .filter(|value| value.host_device_id == request.host_device_id)
                    .and_then(|value| {
                        value.devices.iter().find(|entry| {
                            entry.controller_device_id == request.controller_device_id
                        })
                    })
                    .map_or(0, |entry| entry.revision);
                if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
                    && let Ok(now) = u64::try_from(now.as_millis())
                    && let Some(expires_at_unix_ms) = now.checked_add(3_600_000)
                {
                    self.pending_confirmation=Some((self.t("此控制端在一小时内可按所选权限申请受信访问。", "This controller may request trusted access with these permissions for one hour.").into(),Command::Submit{action:Action::TrustRemote{request_id:request.id.clone(),choice:TrustChoice{expected_revision:revision,expires_at_unix_ms}}}));
                }
            }
        }
        widgets::section(ui, &snapshot.trusted_devices, self.english);
        if let Some(trusted) = &snapshot.trusted_devices.data {
            for entry in &trusted.devices {
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(&entry.controller_device_id);
                    ui.small(format!("revision {} · {}", entry.revision, entry.active));
                    if local == Some(trusted.host_device_id.as_str())
                        && entry.active
                        && ui.button(self.t("撤销受信", "Revoke trust")).clicked()
                    {
                        self.pending_confirmation = Some((
                            self.t(
                                "撤销这台设备的受信权限。",
                                "Revoke this device's trusted access.",
                            )
                            .into(),
                            Command::Submit {
                                action: Action::RevokeDeviceTrust {
                                    host_device_id: trusted.host_device_id.clone(),
                                    controller_device_id: entry.controller_device_id.clone(),
                                    expected_revision: entry.revision,
                                },
                            },
                        ));
                    }
                });
            }
        }
    }
}

fn incoming_requests(snapshot: &Snapshot) -> impl Iterator<Item = &RemoteView> {
    let local = snapshot
        .installation
        .as_ref()
        .map(|installation| installation.device_id.as_str());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| u64::try_from(now.as_millis()).ok())
        .unwrap_or(u64::MAX);
    snapshot
        .requests
        .data
        .as_deref()
        .into_iter()
        .flatten()
        .filter(move |request| {
            Some(request.host_device_id.as_str()) == local
                && request.status == "pending"
                && request.expires_at_unix_ms > now
        })
}

fn path_label(path: &str, english: bool) -> &str {
    match (path, english) {
        ("direct_preferred", false) => "自动连接（直连优先，允许中继）",
        ("relay_only", false) => "仅中继",
        ("direct_only", false) => "仅直连",
        ("direct_preferred", true) => "Automatic (direct and relay)",
        ("relay_only", true) => "Relay only",
        _ => "Direct only",
    }
}

fn is_eligible_host(device: &DeviceView, local_device_id: Option<&str>) -> bool {
    !device.revoked
        && nestlink_protocol::valid_id(&device.device.id)
        && local_device_id != Some(device.device.id.as_str())
        && device
            .device
            .capabilities
            .iter()
            .any(|capability| capability == "host")
}

fn selected_request_is_current(
    snapshot: &Snapshot,
    selected_id: Option<&str>,
    request: &RemoteView,
) -> bool {
    selected_id == Some(request.id.as_str())
        && snapshot.requests.loading.is_none()
        && snapshot.requests.error.is_none()
        && snapshot.selected_request.loading.is_none()
        && snapshot.selected_request.error.is_none()
        && request.status == "pending"
        && snapshot
            .selected_request
            .data
            .as_deref()
            .is_some_and(|current| {
                current.id == request.id
                    && current.nonce == request.nonce
                    && current.policy_revision == request.policy_revision
                    && current.connection_generation == request.connection_generation
                    && current.status == "pending"
            })
}

fn one_time_password_context(
    snapshot: &Snapshot,
    selected_id: Option<&str>,
) -> Option<OneTimePasswordContext> {
    if snapshot.remote_password_offer.loading.is_some()
        || snapshot.remote_password_offer.error.is_some()
    {
        return None;
    }
    let request = snapshot.selected_request.data.as_deref()?;
    if !selected_request_is_current(snapshot, selected_id, request) {
        return None;
    }
    let offer = snapshot.remote_password_offer.data.as_deref()?;
    if offer.request_id != request.id || !offer.settings.active {
        return None;
    }
    Some(OneTimePasswordContext {
        request_id: request.id.clone(),
        request_nonce: request.nonce.clone(),
        policy_revision: request.policy_revision,
        connection_generation: request.connection_generation,
        password_revision: offer.settings.revision,
    })
}

fn reconcile_host_selection(form: &mut RemoteForm, snapshot: &Snapshot) {
    let local_device_id = snapshot
        .installation
        .as_ref()
        .map(|installation| installation.device_id.as_str());
    reconcile_host_id(
        form,
        snapshot.devices.loading.is_some(),
        snapshot.devices.error.is_some(),
        snapshot.devices.data.as_deref().map(Vec::as_slice),
        local_device_id,
    );
}

fn reconcile_host_id(
    form: &mut RemoteForm,
    loading: bool,
    failed: bool,
    devices: Option<&[DeviceView]>,
    local_device_id: Option<&str>,
) {
    if loading {
        return;
    }
    let still_eligible = !failed
        && form.host_device_id.as_deref().is_some_and(|selected_id| {
            devices.is_some_and(|devices| {
                devices.iter().any(|device| {
                    is_eligible_host(device, local_device_id) && device.device.id == selected_id
                })
            })
        });
    if !still_eligible {
        form.host_device_id = None;
    }
}

fn browser_permissions_supported(permissions: &[i32]) -> bool {
    let supports_input_audio = cfg!(any(windows, target_os = "linux"));
    let supports_files = cfg!(any(windows, target_os = "linux"));
    let supports_clipboard = cfg!(windows)
        || (cfg!(target_os = "linux")
            && std::env::var_os("WAYLAND_DISPLAY").is_none()
            && std::env::var_os("DISPLAY").is_some());
    permissions.contains(&(Permission::View as i32))
        && permissions.iter().all(|permission| {
            *permission == Permission::View as i32
                || (supports_input_audio
                    && matches!(
                        Permission::try_from(*permission),
                        Ok(Permission::Input | Permission::Audio)
                    ))
                || (supports_files
                    && matches!(
                        Permission::try_from(*permission),
                        Ok(Permission::FileRead | Permission::FileWrite)
                    ))
                || (supports_clipboard
                    && matches!(
                        Permission::try_from(*permission),
                        Ok(Permission::ClipboardRead | Permission::ClipboardWrite)
                    ))
        })
}

pub(super) fn selected(values: &[bool; 7]) -> Vec<i32> {
    values
        .iter()
        .enumerate()
        .filter_map(|(index, enabled)| enabled.then_some((index + 1) as i32))
        .collect()
}

fn selected_paths(values: &[bool; 2]) -> Vec<i32> {
    values
        .iter()
        .enumerate()
        .filter_map(|(index, enabled)| enabled.then_some((index + 1) as i32))
        .collect()
}

fn remote_paths(paths: &[i32], english: bool) -> String {
    let labels: Vec<_> = paths
        .iter()
        .filter_map(|path| match *path {
            1 => Some(if english { "direct" } else { "直连" }),
            2 => Some(if english { "relay" } else { "中继" }),
            _ => None,
        })
        .collect();
    if labels.is_empty() {
        if english { "none" } else { "无" }.into()
    } else {
        labels.join(if english { ", " } else { "、" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_core::{Failure, FailureKind, RemotePasswordOffer};
    use nestlink_protocol::api::{DeviceDescriptor, RemotePasswordView};
    use std::sync::Arc;

    const HOST_ID: &str = "00000000-0000-4000-8000-000000000001";
    const REQUEST_ID: &str = "00000000-0000-4000-8000-000000000010";

    fn device(id: &str, capabilities: &[&str], revoked: bool) -> DeviceView {
        DeviceView {
            device: DeviceDescriptor {
                id: id.into(),
                name: format!("Device {id}"),
                platform: "windows".into(),
                public_key: String::new(),
                capabilities: capabilities.iter().map(|value| (*value).into()).collect(),
                path_mode: "direct_preferred".into(),
            },
            revoked,
        }
    }

    fn request(status: &str) -> RemoteView {
        RemoteView {
            id: REQUEST_ID.into(),
            controller_device_id: "00000000-0000-4000-8000-000000000002".into(),
            host_device_id: HOST_ID.into(),
            permissions: vec![1],
            paths: vec![1],
            nonce: "request-nonce".into(),
            policy_revision: 4,
            expires_at_unix_ms: 100,
            status: status.into(),
            lease_sequence: 0,
            connection_generation: 7,
            trust_revision: None,
            password_revision: Some(3),
        }
    }

    fn password_offer(request_id: &str, revision: u64, active: bool) -> RemotePasswordOffer {
        RemotePasswordOffer {
            request_id: request_id.into(),
            settings: RemotePasswordView {
                revision,
                permissions: vec![1],
                paths: vec![1],
                expires_at_unix_ms: 200,
                active,
            },
        }
    }

    fn snapshot_with_password_offer(status: &str, offer: RemotePasswordOffer) -> Snapshot {
        let request = request(status);
        let mut snapshot = Snapshot::default();
        snapshot.selected_request.data = Some(Arc::new(request));
        snapshot.remote_password_offer.data = Some(Arc::new(offer));
        snapshot
    }

    #[test]
    fn host_choices_exclude_revoked_and_non_host_devices() {
        let devices = [
            device(HOST_ID, &["view", "host"], false),
            device("00000000-0000-4000-8000-000000000002", &["view"], false),
            device("00000000-0000-4000-8000-000000000003", &["host"], true),
        ];
        let hosts: Vec<_> = devices
            .iter()
            .filter(|device| is_eligible_host(device, None))
            .map(|device| device.device.id.as_str())
            .collect();

        assert_eq!(hosts, [HOST_ID]);
    }

    #[test]
    fn host_selection_is_preserved_while_refresh_is_busy_then_revalidated() {
        let active = device(HOST_ID, &["host"], false);
        let mut form = RemoteForm {
            host_device_id: Some(HOST_ID.into()),
            ..RemoteForm::default()
        };

        reconcile_host_id(&mut form, true, false, Some(&[]), None);
        assert_eq!(form.host_device_id.as_deref(), Some(HOST_ID));

        reconcile_host_id(
            &mut form,
            false,
            false,
            Some(std::slice::from_ref(&active)),
            None,
        );
        assert_eq!(form.host_device_id.as_deref(), Some(HOST_ID));

        let revoked = device(HOST_ID, &["host"], true);
        reconcile_host_id(
            &mut form,
            false,
            false,
            Some(std::slice::from_ref(&revoked)),
            None,
        );
        assert_eq!(form.host_device_id, None);

        form.host_device_id = Some(HOST_ID.into());
        let downgraded = device(HOST_ID, &["view"], false);
        reconcile_host_id(
            &mut form,
            false,
            false,
            Some(std::slice::from_ref(&downgraded)),
            None,
        );
        assert_eq!(form.host_device_id, None);
    }

    #[test]
    fn missing_or_failed_device_list_clears_stale_selection() {
        let mut form = RemoteForm {
            host_device_id: Some(HOST_ID.into()),
            ..RemoteForm::default()
        };

        reconcile_host_id(&mut form, false, false, Some(&[]), None);
        assert_eq!(form.host_device_id, None);

        form.host_device_id = Some(HOST_ID.into());
        reconcile_host_id(&mut form, false, true, None, None);
        assert_eq!(form.host_device_id, None);
    }

    #[test]
    fn local_installation_is_not_an_eligible_remote_host() {
        let local = device(HOST_ID, &["host"], false);
        assert!(is_eligible_host(&local, None));
        assert!(!is_eligible_host(&local, Some(HOST_ID)));

        let mut form = RemoteForm {
            host_device_id: Some(HOST_ID.into()),
            ..RemoteForm::default()
        };
        reconcile_host_id(
            &mut form,
            false,
            false,
            Some(std::slice::from_ref(&local)),
            Some(HOST_ID),
        );
        assert_eq!(form.host_device_id, None);
    }

    #[test]
    fn one_time_password_context_tracks_only_a_current_pending_request_offer() {
        let mut snapshot =
            snapshot_with_password_offer("pending", password_offer(REQUEST_ID, 8, true));
        let selected = one_time_password_context(&snapshot, Some(REQUEST_ID));
        assert_eq!(
            selected,
            Some(OneTimePasswordContext {
                request_id: REQUEST_ID.into(),
                request_nonce: "request-nonce".into(),
                policy_revision: 4,
                connection_generation: 7,
                password_revision: 8,
            })
        );

        snapshot.remote_password_offer.data = Some(Arc::new(password_offer(REQUEST_ID, 9, true)));
        assert_ne!(
            selected,
            one_time_password_context(&snapshot, Some(REQUEST_ID))
        );

        snapshot.selected_request.data = Some(Arc::new(request("approved")));
        assert_eq!(one_time_password_context(&snapshot, Some(REQUEST_ID)), None);

        snapshot.selected_request.data = None;
        assert_eq!(one_time_password_context(&snapshot, Some(REQUEST_ID)), None);

        snapshot.selected_request.data = Some(Arc::new(request("pending")));
        assert_eq!(one_time_password_context(&snapshot, None), None);
        assert_eq!(one_time_password_context(&snapshot, Some(HOST_ID)), None);

        snapshot.remote_password_offer.data = Some(Arc::new(password_offer(
            "00000000-0000-4000-8000-000000000011",
            9,
            true,
        )));
        assert_eq!(one_time_password_context(&snapshot, Some(REQUEST_ID)), None);

        snapshot.remote_password_offer.data = Some(Arc::new(password_offer(REQUEST_ID, 9, false)));
        assert_eq!(one_time_password_context(&snapshot, Some(REQUEST_ID)), None);

        snapshot.remote_password_offer.data = Some(Arc::new(password_offer(REQUEST_ID, 9, true)));
        snapshot.remote_password_offer.error = Some(Failure {
            kind: FailureKind::Invalid,
            status: None,
            code: None,
        });
        assert_eq!(one_time_password_context(&snapshot, Some(REQUEST_ID)), None);
    }

    #[test]
    fn request_or_offer_revision_change_zeroizes_the_password() {
        let mut snapshot =
            snapshot_with_password_offer("pending", password_offer(REQUEST_ID, 8, true));
        let context = one_time_password_context(&snapshot, Some(REQUEST_ID));
        let mut form = RemoteForm {
            selected: Some(REQUEST_ID.into()),
            one_time_password: Zeroizing::new("one-time-secret".into()),
            one_time_password_context: context,
            ..RemoteForm::default()
        };

        form.reconcile_one_time_password_context(&snapshot);
        assert_eq!(form.one_time_password.as_str(), "one-time-secret");

        snapshot.remote_password_offer.data = Some(Arc::new(password_offer(REQUEST_ID, 9, true)));
        form.reconcile_one_time_password_context(&snapshot);
        assert!(form.one_time_password.is_empty());
        assert_eq!(
            form.one_time_password_context
                .as_ref()
                .map(|context| context.password_revision),
            Some(9)
        );

        form.one_time_password = Zeroizing::new("stale-secret".into());
        snapshot.selected_request.data = Some(Arc::new(request("approved")));
        form.reconcile_one_time_password_context(&snapshot);
        assert!(form.one_time_password.is_empty());
        assert!(form.one_time_password_context.is_none());
    }
}
