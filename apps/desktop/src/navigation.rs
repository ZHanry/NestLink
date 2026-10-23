use crate::{DesktopApp, Screen, theme, widgets};
use eframe::egui::{self, Align, RichText};
use nestlink_app_core::{Action, Page, Snapshot};

impl DesktopApp {
    pub(crate) fn navigate(&mut self, screen: Screen, snapshot: &Snapshot) {
        self.message = None;
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
            Screen::Devices => self.load(snapshot, Page::Devices),
            Screen::Security => self.load(snapshot, Page::AccountSecurity),
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
        let palette = if self.dark {
            &self.tokens.dark
        } else {
            &self.tokens.light
        };
        let fill = theme::color(&palette.surface);
        let border = theme::color(&palette.border);
        let muted = theme::color(&palette.muted);
        let compact = context.content_rect().width() < 1000.;
        let width = if compact {
            76.
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
                    .inner_margin(10)
                    .stroke(egui::Stroke::new(1., border)),
            )
            .show_inside(parent, |ui| {
                egui::Panel::bottom("navigation-footer")
                    .exact_size(if compact { 224. } else { 214. })
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(egui::Frame::new())
                    .show_inside(ui, |ui| {
                        ui.separator();
                        if let Some(principal) = &snapshot.principal {
                            let name = principal.name.clone();
                            if widgets::nav_button(
                                ui,
                                widgets::NavIcon::Account,
                                self.t("账号", "Account"),
                                self.screen == Screen::Security,
                            )
                            .on_hover_text(name)
                            .clicked()
                            {
                                self.navigate(Screen::Security, snapshot);
                            }
                        }
                        if widgets::nav_button(
                            ui,
                            widgets::NavIcon::Settings,
                            self.t("设置", "Settings"),
                            self.screen == Screen::Server,
                        )
                        .clicked()
                        {
                            self.screen = Screen::Server;
                        }
                        ui.add_enabled_ui(!self.exiting, |ui| {
                            ui.menu_button(self.t("更多", "More"), |ui| {
                                if self.connected
                                    && snapshot.principal.as_ref().is_some_and(|p| p.is_admin)
                                {
                                    ui.strong(self.t("管理控制中心", "Administration"));
                                    for (screen, zh, en) in [
                                        (Screen::Accounts, "账号管理", "Accounts"),
                                        (Screen::Network, "网络策略与配额", "Policy and quotas"),
                                        (Screen::Nodes, "转发节点", "Relay nodes"),
                                        (Screen::Audit, "审计记录", "Audit log"),
                                    ] {
                                        if ui
                                            .selectable_label(self.screen == screen, self.t(zh, en))
                                            .clicked()
                                        {
                                            self.navigate(screen, snapshot);
                                            ui.close();
                                        }
                                    }
                                    ui.separator();
                                }
                                if ui
                                    .button(if self.english {
                                        "切换为中文"
                                    } else {
                                        "Switch to English"
                                    })
                                    .clicked()
                                {
                                    self.english = !self.english;
                                    ui.close();
                                }
                                if ui
                                    .button(self.t(
                                        if self.dark {
                                            "使用浅色外观"
                                        } else {
                                            "使用深色外观"
                                        },
                                        if self.dark {
                                            "Use light theme"
                                        } else {
                                            "Use dark theme"
                                        },
                                    ))
                                    .clicked()
                                {
                                    self.dark = !self.dark;
                                    theme::apply(context, &self.tokens, self.dark);
                                    ui.close();
                                }
                                ui.separator();
                                if ui
                                    .button(self.t("退出 NestLink", "Exit NestLink"))
                                    .clicked()
                                {
                                    self.exit(snapshot, context);
                                    ui.close();
                                }
                            });
                        });
                        ui.add_space(8.);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                    .size(if compact { 10. } else { 12. })
                                    .color(muted),
                            )
                            .truncate(),
                        );
                    });
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 70.),
                    egui::Layout::top_down(Align::Min),
                    |ui| {
                        if compact {
                            ui.horizontal(|ui| {
                                ui.add_space(10.);
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(32., 32.),
                                    egui::Sense::hover(),
                                );
                                crate::icons::brand(ui, rect);
                            });
                        } else {
                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(32., 32.),
                                    egui::Sense::hover(),
                                );
                                crate::icons::brand(ui, rect);
                                ui.label(RichText::new("NestLink").size(23.).strong());
                            });
                            ui.add_space(4.);
                            ui.label(
                                RichText::new(
                                    self.t("内网穿透 + 远程桌面", "Tunnels + remote desktop"),
                                )
                                .small()
                                .color(muted),
                            );
                        }
                    },
                );
                let signed_in = snapshot.principal.is_some();
                ui.add_enabled_ui(signed_in && self.connected && !self.exiting, |ui| {
                    for (screen, icon, zh, en) in [
                        (
                            Screen::Remote,
                            widgets::NavIcon::Monitor,
                            "远程桌面",
                            "Desktop",
                        ),
                        (
                            Screen::Services,
                            widgets::NavIcon::Share,
                            "内网穿透",
                            "Tunnels",
                        ),
                    ] {
                        if widgets::nav_button(ui, icon, self.t(zh, en), self.screen == screen)
                            .clicked()
                        {
                            self.navigate(screen, snapshot);
                        }
                    }
                    ui.add_space(18.);
                    ui.separator();
                    if widgets::nav_button(
                        ui,
                        widgets::NavIcon::Devices,
                        self.t("设备管理", "Devices"),
                        self.screen == Screen::Devices,
                    )
                    .clicked()
                    {
                        self.navigate(Screen::Devices, snapshot);
                    }
                });
            });
    }

    pub(crate) fn workspace_toolbar(&self, parent: &mut egui::Ui, snapshot: &Snapshot) {
        let (zh, en) = match self.screen {
            Screen::Remote => ("远程桌面", "Remote desktop"),
            Screen::Services => ("内网穿透", "Intranet tunnels"),
            Screen::Devices => ("设备管理", "Devices"),
            Screen::Security => ("账号与安全", "Account and security"),
            Screen::Accounts => ("账号管理", "Accounts"),
            Screen::Network => ("网络策略与配额", "Policy and quotas"),
            Screen::Nodes => ("转发节点", "Relay nodes"),
            Screen::Audit => ("审计记录", "Audit log"),
            Screen::Server => ("设置", "Settings"),
        };
        egui::Panel::top("workspace-toolbar")
            .exact_size(60.)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(24, 10))
                    .fill(parent.visuals().window_fill),
            )
            .show_inside(parent, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(self.t(zh, en)).size(18.).strong());
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let origin = snapshot
                            .server
                            .as_ref()
                            .map(|s| s.origin.as_str())
                            .unwrap_or(self.t("尚未连接服务器", "No server connected"));
                        let width = ui.available_width().min(300.);
                        ui.allocate_ui_with_layout(
                            egui::vec2(width, 36.),
                            egui::Layout::top_down(Align::Max),
                            |ui| {
                                ui.add(egui::Label::new(RichText::new(origin).small()).truncate())
                                    .on_hover_text(origin);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(self.t(
                                            if snapshot.server.as_ref().is_some_and(|server| {
                                                server.verified_health.is_some()
                                            }) {
                                                "控制中心已验证"
                                            } else {
                                                "等待验证控制中心"
                                            },
                                            if snapshot.server.as_ref().is_some_and(|server| {
                                                server.verified_health.is_some()
                                            }) {
                                                "Control center verified"
                                            } else {
                                                "Awaiting server verification"
                                            },
                                        ))
                                        .small()
                                        .color(ui.visuals().weak_text_color()),
                                    )
                                    .truncate(),
                                );
                            },
                        );
                    });
                });
            });
    }
}
