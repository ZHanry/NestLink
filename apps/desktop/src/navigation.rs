use crate::{
    DesktopApp, Screen,
    icons::{self, Icon},
    theme, widgets,
};
use eframe::egui::{self, Align, RichText};
use nestlink_app_core::{Action, Page, Snapshot};

impl DesktopApp {
    pub(crate) fn navigate(&mut self, screen: Screen, snapshot: &Snapshot) {
        self.message = None;
        if self.screen == Screen::Spaces && screen != Screen::Spaces {
            self.space_panel.close();
        }
        if snapshot.native_offline.is_some() {
            self.screen = Screen::Remote;
            return;
        }
        self.screen = screen;
        match screen {
            Screen::Remote => {
                self.load(snapshot, Page::Devices);
                self.load(snapshot, Page::Requests);
            }
            Screen::Services => {
                self.load(snapshot, Page::Services);
                self.load(snapshot, Page::Devices);
            }
            Screen::Spaces => {
                for page in [Page::Spaces, Page::Devices, Page::Services] {
                    self.load(snapshot, page);
                }
            }
            Screen::Devices | Screen::Security => self.load(snapshot, Page::AccountSecurity),
            Screen::Accounts => self.load(snapshot, Page::Accounts),
            Screen::Network => {
                for page in [
                    Page::Policy,
                    Page::RelayQuota,
                    Page::RelayUsage,
                    Page::PathLimits,
                ] {
                    self.load(snapshot, page);
                }
            }
            Screen::Nodes => self.load(snapshot, Page::Nodes),
            Screen::Audit => {
                self.load(snapshot, Page::AuditRetention);
                self.action(
                    snapshot,
                    Action::LoadAudit {
                        after_sequence: 0,
                        limit: 50,
                    },
                );
            }
            Screen::Server => {}
        }
    }

    pub(crate) fn navigation(
        &mut self,
        context: &egui::Context,
        parent: &mut egui::Ui,
        snapshot: &Snapshot,
    ) {
        let compact = context.content_rect().width() < 1000.;
        let short = context.content_rect().height() < 700.;
        let palette = if self.dark {
            &self.tokens.dark
        } else {
            &self.tokens.light
        };
        let fill = theme::color(&palette.sidebar);
        let muted = theme::color(&palette.muted);
        let width = if compact {
            self.tokens.layout.sidebar_width_compact
        } else {
            self.tokens.layout.sidebar_width
        };
        egui::Panel::left("navigation")
            .exact_size(width)
            .resizable(false)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(fill)
                    .inner_margin(egui::Margin::symmetric(13, if short { 12 } else { 24 })),
            )
            .show_inside(parent, |ui| {
                ui.spacing_mut().item_spacing.y = if short { 2. } else { 4. };
                egui::Panel::bottom("navigation-footer")
                    .exact_size(if short { 112. } else { 224. })
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(egui::Frame::new())
                    .show_inside(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 3.;
                        let signed_in = snapshot.principal.is_some();
                        if !short && !compact {
                            egui::Frame::new()
                                .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                                .corner_radius(9)
                                .inner_margin(12)
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    // Information rows do not need the normal
                                    // button height, which overflows this footer
                                    // with Windows UI font metrics.
                                    ui.spacing_mut().interact_size.y = 20.;
                                    let verified = self.connected
                                        && snapshot.server.as_ref().is_some_and(|server| {
                                            server.verified_health.is_some()
                                                && server.error.is_none()
                                        });
                                    ui.horizontal(|ui| {
                                        let (rect, _) = ui.allocate_exact_size(
                                            egui::vec2(6., 6.),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().circle_filled(
                                            rect.center(),
                                            3.,
                                            if verified {
                                                theme::color(if self.dark {
                                                    "#82C6A7"
                                                } else {
                                                    "#278361"
                                                })
                                            } else {
                                                muted
                                            },
                                        );
                                        let status = self.t(
                                            if verified {
                                                "控制中心已连接"
                                            } else {
                                                "控制中心未连接"
                                            },
                                            if verified {
                                                "Control center connected"
                                            } else {
                                                "Control center disconnected"
                                            },
                                        );
                                        ui.add(
                                            egui::Label::new(RichText::new(status).small())
                                                .truncate(),
                                        )
                                        .on_hover_text(status);
                                    });
                                    let origin = snapshot
                                        .server
                                        .as_ref()
                                        .map(|server| server.origin.as_str())
                                        .unwrap_or("—");
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(origin).size(10.).color(muted),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(origin);
                                });
                            ui.add_space(9.);
                        }
                        ui.add_enabled_ui(signed_in && self.connected && !self.exiting, |ui| {
                            if widgets::nav_button(
                                ui,
                                Icon::Shield,
                                self.t("账号与安全", "Account and security"),
                                self.screen == Screen::Security,
                            )
                            .clicked()
                            {
                                self.navigate(Screen::Security, snapshot);
                            }
                        });
                        if widgets::nav_button(
                            ui,
                            Icon::Settings,
                            self.t("设置", "Settings"),
                            self.screen == Screen::Server,
                        )
                        .clicked()
                        {
                            self.screen = Screen::Server;
                        }
                        ui.separator();
                        let label = snapshot
                            .principal
                            .as_ref()
                            .map(|p| p.name.as_str())
                            .unwrap_or(self.t("尚未登录", "Sign in"));
                        let account_clicked = if compact || short {
                            widgets::nav_button(ui, Icon::Account, label, false).clicked()
                        } else {
                            let (rect, response) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 46.),
                                egui::Sense::click(),
                            );
                            response.widget_info(|| {
                                egui::WidgetInfo::labeled(
                                    egui::WidgetType::Button,
                                    ui.is_enabled(),
                                    label,
                                )
                            });
                            let center = rect.left_center() + egui::vec2(26., 0.);
                            ui.painter().circle_filled(
                                center,
                                16.,
                                ui.visuals().selection.bg_fill.gamma_multiply(0.16),
                            );
                            let initial: String =
                                label.chars().take(2).flat_map(char::to_uppercase).collect();
                            ui.painter().text(
                                center,
                                egui::Align2::CENTER_CENTER,
                                initial,
                                theme::heading_font(11.),
                                ui.visuals().hyperlink_color,
                            );
                            let painter = ui.painter().with_clip_rect(rect);
                            painter.text(
                                rect.min + egui::vec2(52., 15.),
                                egui::Align2::LEFT_CENTER,
                                label,
                                theme::heading_font(12.),
                                ui.visuals().text_color(),
                            );
                            painter.text(
                                rect.min + egui::vec2(52., 34.),
                                egui::Align2::LEFT_CENTER,
                                self.t(
                                    if snapshot.principal.as_ref().is_some_and(|p| p.is_admin) {
                                        "个人账号 · 管理员"
                                    } else {
                                        "个人账号"
                                    },
                                    if snapshot.principal.as_ref().is_some_and(|p| p.is_admin) {
                                        "Account · Admin"
                                    } else {
                                        "Personal account"
                                    },
                                ),
                                egui::FontId::proportional(10.),
                                muted,
                            );
                            response.on_hover_text(label).clicked()
                        };
                        if account_clicked {
                            if signed_in {
                                self.navigate(Screen::Security, snapshot);
                            } else {
                                self.screen = Screen::Remote;
                            }
                        }
                    });
                ui.horizontal(|ui| {
                    if !compact {
                        ui.add_space(13.);
                    }
                    if compact {
                        ui.add_space(6.);
                    }
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(34., 34.), egui::Sense::hover());
                    icons::brand(ui, rect);
                    if !compact {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("NestLink").font(theme::heading_font(21.)));
                            ui.label(RichText::new("STAY CONNECTED").size(9.).color(muted));
                        });
                    }
                });
                ui.add_space(if short { 12. } else { 36. });
                egui::ScrollArea::vertical()
                    .id_salt("sidebar-navigation")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if !compact {
                            ui.label(
                                RichText::new(self.t("主要功能", "WORKSPACE"))
                                    .small()
                                    .color(muted),
                            );
                        }
                        let signed_in = snapshot.principal.is_some();
                        ui.add_enabled_ui(signed_in && self.connected && !self.exiting, |ui| {
                            for (screen, icon, zh, en) in [
                                (Screen::Remote, Icon::Monitor, "远程桌面", "Remote desktop"),
                                (Screen::Services, Icon::Share, "内网穿透", "Tunnels"),
                                (Screen::Spaces, Icon::Spaces, "网络空间", "Network spaces"),
                                (Screen::Devices, Icon::Devices, "设备管理", "Login devices"),
                            ] {
                                if widgets::nav_button(
                                    ui,
                                    icon,
                                    self.t(zh, en),
                                    self.screen == screen,
                                )
                                .clicked()
                                {
                                    self.navigate(screen, snapshot);
                                }
                            }
                        });
                        ui.add_space(if short { 8. } else { 20. });
                        if !compact {
                            ui.label(
                                RichText::new(self.t("管理控制台", "ADMINISTRATION"))
                                    .small()
                                    .color(muted),
                            );
                        }
                        let admin = self.connected
                            && snapshot.principal.as_ref().is_some_and(|p| p.is_admin)
                            && !self.exiting;
                        ui.add_enabled_ui(admin, |ui| {
                            for (screen, icon, zh, en) in [
                                (Screen::Accounts, Icon::Account, "账号管理", "Accounts"),
                                (
                                    Screen::Network,
                                    Icon::Network,
                                    "网络策略与配额",
                                    "Policy and quotas",
                                ),
                                (Screen::Nodes, Icon::Server, "转发节点", "Relay nodes"),
                                (Screen::Audit, Icon::Audit, "审计记录", "Audit log"),
                            ] {
                                if widgets::nav_button(
                                    ui,
                                    icon,
                                    self.t(zh, en),
                                    self.screen == screen,
                                )
                                .clicked()
                                {
                                    self.navigate(screen, snapshot);
                                }
                            }
                        });
                    });
            });
    }

    pub(crate) fn workspace_toolbar(&mut self, parent: &mut egui::Ui, snapshot: &Snapshot) {
        egui::Panel::top("window-titlebar")
            .exact_size(38.)
            .resizable(false)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(parent.visuals().window_fill)
                    .inner_margin(egui::Margin::symmetric(14, 4)),
            )
            .show_inside(parent, |ui| {
                ui.spacing_mut().interact_size.y = 28.;
                ui.spacing_mut().button_padding = egui::vec2(8., 4.);
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(17., 17.), egui::Sense::hover());
                    icons::brand(ui, rect);
                    let title = ui.add(
                        egui::Label::new(
                            RichText::new("NestLink / Windows")
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        )
                        .sense(egui::Sense::click_and_drag()),
                    );
                    if title.drag_started() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }
                    if title.double_clicked() {
                        let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                        ui.ctx()
                            .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if icons::tool_button(
                            ui,
                            Icon::Close,
                            self.t("关闭主窗口", "Close main window"),
                        )
                        .clicked()
                        {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if icons::tool_button(
                            ui,
                            Icon::Maximize,
                            self.t("最大化 / 还原", "Maximize / restore"),
                        )
                        .clicked()
                        {
                            let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                        }
                        if icons::tool_button(ui, Icon::Minimize, self.t("最小化", "Minimize"))
                            .clicked()
                        {
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
                        ui.separator();
                        if icons::tool_button(
                            ui,
                            Icon::Theme,
                            self.t("切换浅色 / 深色", "Switch appearance"),
                        )
                        .clicked()
                        {
                            self.workspace.preferences.follow_system = false;
                            self.dark = !self.dark;
                            theme::apply(ui.ctx(), &self.tokens, self.dark);
                            self.save_appearance();
                        }
                        if icons::tool_button(
                            ui,
                            Icon::Help,
                            self.t("帮助与关于", "Help and about"),
                        )
                        .clicked()
                        {
                            self.workspace.help_open = true;
                        }
                        if snapshot.principal.is_some() {
                            if icons::tool_button(
                                ui,
                                Icon::Bell,
                                self.t("连接请求", "Connection requests"),
                            )
                            .clicked()
                            {
                                self.navigate(Screen::Remote, snapshot);
                                self.show_remote_requests();
                            }
                            if ui
                                .button(if ui.available_width() > 350. {
                                    self.t(
                                        "搜索设备与功能  Ctrl K",
                                        "Search devices / actions  Ctrl K",
                                    )
                                } else {
                                    self.t("搜索", "Search")
                                })
                                .clicked()
                            {
                                self.workspace.search_open = true;
                            }
                        }
                        let drag = ui.interact(
                            ui.available_rect_before_wrap(),
                            ui.id().with("titlebar-drag"),
                            egui::Sense::click_and_drag(),
                        );
                        if drag.drag_started() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
                        }
                        if drag.double_clicked() {
                            let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                        }
                    });
                });
            });
    }
}
