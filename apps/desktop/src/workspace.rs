//! Native presentation state only. Account, network and session state stays in the daemon.
use crate::{DesktopApp, MessageTone, Screen, theme, widgets};
use eframe::egui::{self, RichText};
use nestlink_app_core::{Page, Snapshot};
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub(crate) struct WorkspaceState {
    pub search_open: bool,
    pub search: String,
    pub help_open: bool,
    pub settings_tab: usize,
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
                    ui.horizontal(|ui| {
                        ui.heading(self.t("搜索设备与功能", "Search devices and actions"));
                        if ui.button("×").clicked() {
                            self.workspace.search_open = false;
                        }
                    });
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
                ui.heading("NestLink");
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
                    ui.heading(self.t("退出 NestLink？", "Exit NestLink?"));
                    ui.label(self.t(
                        "退出会结束本用户的远程会话与本机后台服务。",
                        "Exiting ends this user's remote sessions and local background services.",
                    ));
                    ui.add_space(18.);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(self.t("取消", "Cancel")).clicked() {
                            self.workspace.exit_open = false;
                        }
                        if ui.button(self.t("退出程序", "Exit application")).clicked() {
                            self.workspace.exit_open = false;
                            self.exit(snapshot, context);
                        }
                    });
                });
            if response.should_close() {
                self.workspace.exit_open = false;
            }
        }
    }

    pub(crate) fn settings_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::page_heading(
            ui,
            self.t("设置", "Settings"),
            self.t(
                "外观、语言、控制中心与本机连接设置。",
                "Appearance, language, control center and local connectivity.",
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
                "常规",
                "控制中心",
                "远控与权限",
                "网络与代理",
                "关于 NestLink",
            ]
        };
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(if ui.ctx().content_rect().width()<1000. {126.} else {170.});
                for (index,label) in labels.iter().enumerate() {
                    if ui.add_sized([ui.available_width(),42.],egui::Button::new(*label).selected(self.workspace.settings_tab==index)).clicked() {self.workspace.settings_tab=index;}
                }
            });
            ui.add_space(12.);
            ui.vertical(|ui| {
        widgets::surface(ui).show(ui,|ui|{
            ui.set_min_width(ui.available_width());
            match self.workspace.settings_tab {
                0 => {
                    ui.strong(self.t("外观主题", "Appearance"));
                    ui.label(self.t("选择与 NestLink 品牌一致的淡紫色或深紫色界面。", "Choose NestLink's lilac or deep-purple appearance."));
                    ui.add_space(14.);
                    let current=if self.workspace.preferences.follow_system {2} else {usize::from(self.dark)};
                    ui.horizontal_wrapped(|ui|{
                        for (index,zh,en) in [(0,"淡紫浅色","Lilac light"),(1,"深紫深色","Deep purple"),(2,"跟随系统","System")]{
                            if ui.add_sized([120.,60.],egui::Button::new(self.t(zh,en)).selected(current==index)).clicked(){
                                self.workspace.preferences.follow_system=index==2;
                                self.dark=if index==2 {ui.ctx().system_theme()==Some(egui::Theme::Dark)} else {index==1};
                                theme::apply(ui.ctx(),&self.tokens,self.dark);self.save_appearance();
                            }
                        }
                    });
                    ui.add_space(22.);ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(self.t("界面密度", "Density"));
                        if ui.selectable_label(!self.workspace.preferences.compact,self.t("舒适", "Comfortable")).clicked(){self.workspace.preferences.compact=false;self.save_appearance();}
                        if ui.selectable_label(self.workspace.preferences.compact,self.t("紧凑", "Compact")).clicked(){self.workspace.preferences.compact=true;self.save_appearance();}
                    });
                    ui.horizontal(|ui|{ui.label(self.t("界面语言", "Language"));if ui.selectable_label(!self.english,"简体中文").clicked(){self.english=false;self.save_appearance();}
if ui.selectable_label(self.english,"English").clicked(){self.english=true;self.save_appearance();}});
                }
                1=>{
                    ui.strong(self.t("常规", "General"));
                    ui.label(self.t("关闭主窗口后保留托盘入口，已授权会话与本机服务由守护进程继续管理。", "Closing the main window keeps the tray available. The daemon continues managing authorized sessions and local services."));
                    ui.add_space(14.);
                    if ui.button(self.t("打开登录设备管理", "Manage login devices")).clicked(){self.navigate(Screen::Devices,snapshot);}
                    if ui.button(self.t("退出 NestLink", "Exit NestLink")).clicked(){self.workspace.exit_open=true;}
                }
                2=>{self.connection_page(ui,snapshot);}
                3=>{self.remote_host_settings(ui,snapshot);}
                4=>{self.local_network_settings(ui,snapshot);}
                _=>{
                    ui.heading("NestLink");ui.label(RichText::new(format!("v{}",env!("CARGO_PKG_VERSION"))).color(ui.visuals().hyperlink_color));
                    ui.label(self.t("Windows 桌面端 · 内网穿透与远程桌面", "Windows desktop · Tunnels and remote desktop"));
                    ui.hyperlink_to("GitHub / Releases","https://github.com/ZHanry/NestLink/releases");
                    if ui.button(self.t("检查当前连接状态", "Refresh connection state")).clicked(){self.load(snapshot,Page::AccountSecurity);}
                }
            }
        });
            });
        });
    }
}

impl DesktopApp {
    pub(crate) fn login_brand_panel(&self, ui: &mut egui::Ui) {
        let width = (ui.available_width() * 0.43).min(540.);
        widgets::fixed_region(ui, "login-brand-story", egui::vec2(width, 570.), |ui| {
            egui::Frame::new().fill(ui.visuals().selection.bg_fill.gamma_multiply(0.09)).corner_radius(20).inner_margin(40).show(ui,|ui|{
                ui.set_width((width-80.).max(240.));ui.set_min_height(490.);
                let (rect,_)=ui.allocate_exact_size(egui::vec2(52.,52.),egui::Sense::hover());crate::icons::brand(ui,rect);
                ui.add_space(48.);
                ui.label(RichText::new(self.t("你的设备，\n始终在身边。", "Your devices,\nwithin reach.")).size(32.).strong());
                ui.add_space(20.);
                ui.label(self.t("连接远程桌面，访问内网服务，让工作在设备之间自然衔接。", "Connect remote desktops and private services. Continue your work across devices."));
                ui.add_space(56.);ui.separator();
                ui.small(self.t("每一次连接，都在你的掌控之中。", "Every connection stays in your control."));
            });
        });
    }
}
