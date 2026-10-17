use crate::{DesktopApp, Screen, theme, widgets};
use eframe::egui::{self, Align, Color32, RichText};
use nestlink_app_core::{Action, Page, Snapshot};

impl DesktopApp {
    pub(crate) fn navigate(&mut self, screen: Screen, snapshot: &Snapshot) {
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
        let fill = theme::color(&palette.sidebar);
        let border = theme::color(&palette.border);
        let muted = theme::color(&palette.muted);
        let primary = theme::color(&palette.primary);
        let width = if context.content_rect().width() < 900. {
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
                    .inner_margin(16)
                    .stroke(egui::Stroke::new(1., border)),
            )
            .show_inside(parent, |ui| {
                egui::Panel::bottom("navigation-footer")
                    .exact_size(if snapshot.principal.is_some() {
                        208.
                    } else {
                        160.
                    })
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(egui::Frame::new())
                    .show_inside(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 6.;
                        ui.add_space(4.);
                        if widgets::nav_button(
                            ui,
                            widgets::NavIcon::Settings,
                            self.t("服务器连接", "Server connection"),
                            self.screen == Screen::Server,
                        )
                        .clicked()
                        {
                            self.screen = Screen::Server;
                        }
                        if let Some(principal) = &snapshot.principal {
                            let name = principal.name.clone();
                            if widgets::nav_button(
                                ui,
                                widgets::NavIcon::Account,
                                &name,
                                self.screen == Screen::Security,
                            )
                            .clicked()
                            {
                                self.navigate(Screen::Security, snapshot);
                            }
                        }
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui
                                .button(if self.english { "中文" } else { "English" })
                                .clicked()
                            {
                                self.english = !self.english;
                            }
                            if ui
                                .button(self.t(
                                    if self.dark {
                                        "浅色外观"
                                    } else {
                                        "深色外观"
                                    },
                                    if self.dark { "Light" } else { "Dark" },
                                ))
                                .clicked()
                            {
                                self.dark = !self.dark;
                                theme::apply(context, &self.tokens, self.dark);
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                    .small()
                                    .color(muted),
                            );
                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                if ui.small_button(self.t("退出", "Exit")).clicked() {
                                    self.exit(snapshot, context);
                                }
                            });
                        });
                    });
                ui.spacing_mut().scroll.floating = false;
                egui::ScrollArea::vertical()
                    .id_salt("navigation-menu")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(6.);
                        ui.horizontal(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(32., 32.), egui::Sense::hover());
                            ui.painter().rect_filled(rect, 8., primary);
                            let p = |x, y| rect.min + egui::vec2(x, y);
                            ui.painter()
                                .line_segment([p(10., 23.), p(10., 9.)], (2.4, Color32::WHITE));
                            ui.painter()
                                .line_segment([p(10., 9.), p(22., 23.)], (2.4, Color32::WHITE));
                            ui.painter()
                                .line_segment([p(22., 23.), p(22., 9.)], (2.4, Color32::WHITE));
                            ui.label(RichText::new("NestLink").size(22.).strong());
                        });
                        ui.add_space(28.);
                        let signed_in = snapshot.principal.is_some();
                        ui.add_enabled_ui(signed_in && self.connected && !self.exiting, |ui| {
                            for (screen, icon, zh, en) in [
                                (
                                    Screen::Remote,
                                    widgets::NavIcon::Monitor,
                                    "远程控制",
                                    "Remote control",
                                ),
                                (
                                    Screen::Services,
                                    widgets::NavIcon::Share,
                                    "服务发布",
                                    "Services",
                                ),
                                (
                                    Screen::Devices,
                                    widgets::NavIcon::Devices,
                                    "我的设备",
                                    "My devices",
                                ),
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
                            if snapshot.principal.as_ref().is_some_and(|p| p.is_admin) {
                                ui.add_space(22.);
                                ui.label(
                                    RichText::new(self.t("管理", "Administration"))
                                        .small()
                                        .color(muted),
                                );
                                ui.add_space(5.);
                                for (screen, icon, zh, en) in [
                                    (
                                        Screen::Accounts,
                                        widgets::NavIcon::Account,
                                        "账号管理",
                                        "Accounts",
                                    ),
                                    (
                                        Screen::Network,
                                        widgets::NavIcon::Network,
                                        "网络策略",
                                        "Network policy",
                                    ),
                                    (
                                        Screen::Nodes,
                                        widgets::NavIcon::Share,
                                        "转发节点",
                                        "Relay nodes",
                                    ),
                                    (
                                        Screen::Audit,
                                        widgets::NavIcon::List,
                                        "审计记录",
                                        "Audit log",
                                    ),
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
                            }
                        });
                    });
            });
    }

    pub(crate) fn workspace_toolbar(&self, parent: &mut egui::Ui, snapshot: &Snapshot) {
        let (zh, en) = match self.screen {
            Screen::Remote => ("远程控制", "Remote control"),
            Screen::Services => ("服务发布", "Service publishing"),
            Screen::Devices => ("我的设备", "My devices"),
            Screen::Security => ("账号与安全", "Account and security"),
            Screen::Accounts => ("账号管理", "Accounts"),
            Screen::Network => ("网络策略", "Network policy"),
            Screen::Nodes => ("转发节点", "Relay nodes"),
            Screen::Audit => ("审计记录", "Audit log"),
            Screen::Server => ("服务器连接", "Server connection"),
        };
        egui::Panel::top("workspace-toolbar")
            .frame(
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(28, 14))
                    .fill(parent.visuals().window_fill),
            )
            .show_inside(parent, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(self.t(zh, en)).strong());
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let origin = snapshot
                            .server
                            .as_ref()
                            .map(|s| s.origin.as_str())
                            .unwrap_or(self.t("尚未连接服务器", "No server connected"));
                        ui.add(
                            egui::Label::new(
                                RichText::new(origin)
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(origin);
                    });
                });
            });
    }
}
