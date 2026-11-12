//! Native presentation state only. Account, network and session state stays in the daemon.
use crate::{DesktopApp, MessageTone, Screen, widgets};
use eframe::egui::{self, RichText};
use nestlink_app_core::{Page, Snapshot};
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub(crate) struct WorkspaceState {
    pub search_open: bool,
    pub search: String,
    pub help_open: bool,
    pub settings_tab: usize,
    pub remote_session_tool: usize,
    pub devices_view: usize,
    pub selected_login: Option<String>,
    pub account_create_open: bool,
    pub password_open: bool,
    pub exit_open: bool,
    pub audit_filter: String,
    pub retention_draft: Option<(u64, u64)>,
    pub quota_draft: Option<nestlink_protocol::api::RelayQuota>,
    pub preferences: Preferences,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Preferences {
    pub dark: bool,
    pub follow_system: bool,
    pub english: bool,
    pub compact: bool,
    pub reduced_motion: bool,
}

impl WorkspaceState {
    pub(crate) fn read(directory: &std::path::Path) -> Self {
        let preferences =
            nestlink_platform_security::read_private(&directory.join("appearance.json"), 4096)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
        Self {
            preferences,
            ..Self::default()
        }
    }
}

impl DesktopApp {
    pub(crate) fn save_appearance(&mut self) {
        self.workspace.preferences.dark = self.dark;
        self.workspace.preferences.english = self.english;
        let result = serde_json::to_vec(&self.workspace.preferences)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                nestlink_platform_security::replace_private_metadata(
                    &self.directory.join("appearance.json"),
                    &bytes,
                )
                .map(|_| ())
            });
        if result.is_err() {
            self.set_message(
                self.t(
                    "外观已应用，但本机偏好保存失败。",
                    "Appearance applied; local preferences could not be saved.",
                )
                .into(),
                MessageTone::Warning,
            );
        }
    }

    pub(crate) fn workspace_dialogs(&mut self, context: &egui::Context, snapshot: &Snapshot) {
        self.management_dialogs(context, snapshot);
        if snapshot.principal.is_some()
            && context.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::K))
        {
            self.workspace.search_open = true;
        }
        if self.workspace.search_open {
            let mut destination = None;
            let response = egui::Modal::new(egui::Id::new("workspace-search"))
                .frame(widgets::modal_frame(context))
                .show(context, |ui| {
                    ui.set_width(520_f32.min(context.content_rect().width() - 64.));
                    widgets::modal_heading(
                        ui,
                        self.t("搜索设备与功能", "Search devices and actions"),
                        self.english,
                    );
                    let search = ui.add(
                        egui::TextEdit::singleline(&mut self.workspace.search)
                            .desired_width(f32::INFINITY)
                            .hint_text(if self.english {
                                "Device name or page"
                            } else {
                                "输入设备名称或功能名称…"
                            })
                            .char_limit(128),
                    );
                    if search.gained_focus() || self.workspace.search.is_empty() {
                        search.request_focus();
                    }
                    let query = self.workspace.search.to_lowercase();
                    ui.add_space(12.);
                    for (screen, zh, en) in [
                        (Screen::Remote, "远程桌面", "Remote desktop"),
                        (Screen::Services, "内网穿透", "Tunnels"),
                        (Screen::Spaces, "网络空间", "Network spaces"),
                        (Screen::Devices, "设备管理", "Login devices"),
                        (Screen::Security, "账号与安全", "Account security"),
                        (Screen::Server, "设置", "Settings"),
                    ] {
                        if (zh.contains(&query) || en.to_lowercase().contains(&query))
                            && ui.selectable_label(false, self.t(zh, en)).clicked()
                        {
                            destination = Some(screen);
                        }
                    }
                    if let Some(devices) = &snapshot.devices.data {
                        ui.separator();
                        for device in devices
                            .iter()
                            .filter(|d| !d.revoked && d.device.name.to_lowercase().contains(&query))
                            .take(8)
                        {
                            if ui.selectable_label(false, &device.device.name).clicked() {
                                self.remote.host_device_id = Some(device.device.id.clone());
                                destination = Some(Screen::Remote);
                            }
                        }
                    }
                });
            if response.should_close() {
                self.workspace.search_open = false;
            }
            if let Some(screen) = destination {
                self.workspace.search_open = false;
                self.navigate(screen, snapshot);
            }
        }
        if self.workspace.help_open {
            let response=egui::Modal::new(egui::Id::new("workspace-help")).frame(widgets::modal_frame(context)).show(context,|ui|{
                ui.set_width(460_f32.min(context.content_rect().width()-64.));
                widgets::modal_heading(ui, "NestLink", self.english);
                ui.label(format!("{} · Windows",env!("CARGO_PKG_VERSION")));
                ui.add_space(10.);
                ui.label(self.t("远程桌面用于控制与会话文件传输；内网穿透管理本机和其他已授权设备的服务；网络空间管理私有组网和成员授权；设备管理查看账号登录。", "Remote desktop provides control and session file transfer. Tunnels manage local and authorized remote services. Spaces manage private networking and member grants. Devices manages account logins."));
                ui.hyperlink_to(self.t("项目与使用文档", "Project and documentation"),"https://github.com/ZHanry/NestLink");
                ui.add_space(12.);
                if widgets::primary_button(ui,self.t("完成", "Done"),true).clicked(){self.workspace.help_open=false;}
            });
            if response.should_close() {
                self.workspace.help_open = false;
            }
        }
        if self.workspace.exit_open {
            let response = egui::Modal::new(egui::Id::new("workspace-exit"))
                .frame(widgets::modal_frame(context))
                .show(context, |ui| {
                    ui.set_width(420_f32.min(context.content_rect().width() - 64.));
                    widgets::modal_heading(
                        ui,
                        self.t("退出 NestLink？", "Exit NestLink?"),
                        self.english,
                    );
                    ui.label(self.t(
                        "退出会结束本用户的远程会话与本机后台服务。",
                        "Exiting ends this user's remote sessions and local background services.",
                    ));
                    ui.add_space(18.);
                    let (cancel, exit) = widgets::dialog_actions(
                        ui,
                        self.t("取消", "Cancel"),
                        self.t("退出程序", "Exit application"),
                        true,
                    );
                    if cancel || exit {
                        self.workspace.exit_open = false;
                    }
                    if exit {
                        self.exit(snapshot, context);
                    }
                });
            if response.should_close() {
                self.workspace.exit_open = false;
            }
        }
    }

    fn appearance_settings(&mut self, ui: &mut egui::Ui) {
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.strong(self.t("外观", "Appearance"));
            ui.small(self.t(
                "柔和的紫色，让熟悉的工作台焕然一新。",
                "A soft purple appearance for your everyday workspace.",
            ));
            ui.add_space(12.);
            let current = if self.workspace.preferences.follow_system {
                2
            } else {
                usize::from(self.dark)
            };
            ui.horizontal_wrapped(|ui| {
                for (index, zh, en) in [
                    (0, "浅色", "Light"),
                    (1, "深色", "Dark"),
                    (2, "跟随系统", "System"),
                ] {
                    if widgets::theme_choice(ui, self.t(zh, en), index, current == index).clicked()
                    {
                        self.workspace.preferences.follow_system = index == 2;
                        self.dark = if index == 2 {
                            ui.ctx().system_theme() == Some(egui::Theme::Dark)
                        } else {
                            index == 1
                        };
                        self.save_appearance();
                    }
                }
            });
            ui.add_space(12.);
            widgets::settings_row(
                ui,
                self.t("品牌强调色", "Brand accent"),
                self.t(
                    "与原版 NestLink LOGO 一致的品牌紫。",
                    "The purple accent matches the original NestLink logo.",
                ),
                160.,
                |ui| {
                    ui.colored_label(
                        ui.visuals().hyperlink_color,
                        self.t("品牌紫 #7850B2", "Brand purple #7850B2"),
                    );
                },
            );
            ui.separator();
            widgets::settings_row(
                ui,
                self.t("界面密度", "Density"),
                self.t(
                    "在舒适阅读与信息容量间取得平衡。",
                    "Balance comfortable reading and information density.",
                ),
                150.,
                |ui| {
                    let previous = self.workspace.preferences.compact;
                    egui::ComboBox::from_id_salt("appearance-density")
                        .width(110.)
                        .selected_text(self.t(
                            if previous { "紧凑" } else { "舒适" },
                            if previous { "Compact" } else { "Comfortable" },
                        ))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.workspace.preferences.compact,
                                false,
                                if self.english {
                                    "Comfortable"
                                } else {
                                    "舒适"
                                },
                            );
                            ui.selectable_value(
                                &mut self.workspace.preferences.compact,
                                true,
                                if self.english { "Compact" } else { "紧凑" },
                            );
                        });
                    if previous != self.workspace.preferences.compact {
                        self.save_appearance();
                    }
                },
            );
            ui.separator();
            widgets::settings_row(
                ui,
                self.t("减少动态效果", "Reduce motion"),
                self.t(
                    "减少界面切换与展开动画。",
                    "Reduce interface transition and expansion animations.",
                ),
                80.,
                |ui| {
                    let label = if self.english {
                        "Reduce motion"
                    } else {
                        "减少动态效果"
                    };
                    if widgets::toggle(ui, &mut self.workspace.preferences.reduced_motion, label)
                        .changed()
                    {
                        self.save_appearance();
                    }
                },
            );
        });
        ui.add_space(18.);
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.strong(self.t("语言与格式", "Language and format"));
            ui.small(self.t(
                "使用 Windows 系统字体，清晰显示中文与连接信息。",
                "System fonts keep text and connection details clear.",
            ));
            widgets::settings_row(
                ui,
                self.t("显示语言", "Display language"),
                self.t(
                    "在简体中文与 English 之间切换。",
                    "Choose Simplified Chinese or English.",
                ),
                150.,
                |ui| {
                    let previous = self.english;
                    egui::ComboBox::from_id_salt("appearance-language")
                        .width(120.)
                        .selected_text(if self.english {
                            "English"
                        } else {
                            "简体中文"
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.english, false, "简体中文");
                            ui.selectable_value(&mut self.english, true, "English");
                        });
                    if previous != self.english {
                        self.save_appearance();
                    }
                },
            );
            ui.separator();
            widgets::settings_row(
                ui,
                self.t("时间格式", "Time format"),
                self.t(
                    "登录与审计详情显示明确的 UTC 时间。",
                    "Login and audit details show explicit UTC timestamps.",
                ),
                100.,
                |ui| {
                    ui.small("UTC · 24h");
                },
            );
        });
    }

    pub(crate) fn settings_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::page_heading(
            ui,
            self.t("按你的方式，保持连接", "Stay connected, your way"),
            self.t(
                "让 NestLink 更贴合你的日常习惯。",
                "Make NestLink fit your daily routine.",
            ),
        );
        let labels = if self.english {
            [
                "Appearance",
                "General",
                "Control center",
                "Remote permissions",
                "Network",
                "About",
            ]
        } else {
            [
                "外观与语言",
                "常规设置",
                "控制中心",
                "远控与权限",
                "网络与代理",
                "关于 NestLink",
            ]
        };
        let icons = [
            crate::icons::Icon::Theme,
            crate::icons::Icon::Settings,
            crate::icons::Icon::Server,
            crate::icons::Icon::Monitor,
            crate::icons::Icon::Network,
            crate::icons::Icon::Help,
        ];
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(if ui.ctx().content_rect().width() < 1000. { 126. } else { 180. });
                ui.spacing_mut().item_spacing.y = 4.;
                for (index, label) in labels.iter().enumerate() {
                    let selected = self.workspace.settings_tab == index;
                    ui.scope(|ui| {
                        ui.visuals_mut().window_fill = ui.visuals().faint_bg_color;
                        if widgets::nav_button(ui, icons[index], label, selected).clicked() { self.workspace.settings_tab = index; }
                    });
                }
            });
            ui.add_space(12.);
            ui.vertical(|ui| {
                if self.workspace.settings_tab == 0 { self.appearance_settings(ui); return; }
                widgets::surface(ui).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    match self.workspace.settings_tab {
                        1 => {
                            ui.strong(self.t("常规设置", "General"));
                            ui.label(self.t("关闭主窗口后保留托盘入口，已授权会话与本机服务由守护进程继续管理。", "Closing the main window keeps the tray available. The daemon continues managing authorized sessions and local services."));
                            ui.add_space(14.);
                            if ui.button(self.t("打开登录设备管理", "Manage login devices")).clicked() { self.navigate(Screen::Devices, snapshot); }
                            if ui.button(self.t("退出 NestLink", "Exit NestLink")).clicked() { self.workspace.exit_open = true; }
                        }
                        2 => self.connection_page(ui, snapshot),
                        3 => self.remote_host_settings(ui, snapshot),
                        4 => self.local_network_settings(ui, snapshot),
                        _ => {
                            ui.heading("NestLink");
                            ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).color(ui.visuals().hyperlink_color));
                            ui.label(self.t("Windows 桌面端 · 内网穿透与远程桌面", "Windows desktop · Tunnels and remote desktop"));
                            ui.hyperlink_to("GitHub / Releases", "https://github.com/ZHanry/NestLink/releases");
                            if ui.button(self.t("检查当前连接状态", "Refresh connection state")).clicked() { self.load(snapshot, Page::AccountSecurity); }
                        }
                    }
                });
            });
        });
    }
}

impl DesktopApp {
    pub(crate) fn login_brand_panel(&self, ui: &mut egui::Ui) {
        let width = ui.available_width() * 0.5;
        let height = (ui.ctx().content_rect().height() - 140.).clamp(520., 920.);
        widgets::fixed_region(ui, "login-brand-story", egui::vec2(width, height), |ui| {
            let rect = ui.max_rect();
            ui.painter().rect_filled(
                rect,
                19.,
                crate::theme::color(if self.dark {
                    &self.tokens.dark.sidebar
                } else {
                    &self.tokens.light.sidebar
                }),
            );
            let content = rect.shrink(43.);
            let mut story = ui.new_child(egui::UiBuilder::new().max_rect(content));
            story.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(43., 43.), egui::Sense::hover());
                crate::icons::brand(ui, rect);
                ui.add_space(8.);
                ui.label(RichText::new("NestLink").size(25.).strong());
            });
            story.add_space(68.);
            story.label(
                RichText::new(self.t(
                    "熟悉的设备，\n不受距离限制。",
                    "Familiar devices,\nwithout distance.",
                ))
                .size(33.)
                .strong(),
            );
            story.add_space(16.);
            story.label(RichText::new(self.t("连接你的控制中心，让远程桌面、内网服务与协作空间，自然融入每一天。", "Connect your control center. Bring remote desktops, private services and shared spaces into every day.")).color(ui.visuals().weak_text_color()));
            story.add_space(40.);
            story.horizontal(|ui| {
                ui.add_space(((content.width() - 220.) / 2.).max(0.));
                for (index, icon) in [widgets::NavIcon::Devices, widgets::NavIcon::Monitor]
                    .into_iter()
                    .enumerate()
                {
                    if index == 1 {
                        let (logo, _) =
                            ui.allocate_exact_size(egui::vec2(49., 49.), egui::Sense::hover());
                        crate::icons::brand(ui, logo);
                        ui.add_space(10.);
                    }
                    let (tile, _) =
                        ui.allocate_exact_size(egui::vec2(65., 65.), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(tile, 16., ui.visuals().window_fill);
                    crate::icons::paint(ui, icon, tile.center(), 22., ui.visuals().hyperlink_color);
                    ui.add_space(10.);
                }
            });
            let footer = egui::Rect::from_min_max(
                egui::pos2(content.left(), content.bottom() - 36.),
                content.max,
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(footer), |ui| {
                ui.small(self.t(
                    "你的设备，你的空间，你的连接。",
                    "Your devices. Your space. Your connection.",
                ));
                ui.small(format!("{} · Windows", env!("CARGO_PKG_VERSION")));
            });
        });
    }
}
