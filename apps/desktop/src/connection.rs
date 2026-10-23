use crate::{DesktopApp, MessageTone, Screen, widgets};
use eframe::egui::{self, RichText};
use nestlink_app_core::{Action, ApprovedServer, Authentication, Snapshot};
use nestlink_app_ipc::wire::Command;

impl DesktopApp {
    pub(crate) fn connection_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(32.);
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - 460.) / 2.).max(0.));
            ui.vertical(|ui| {
                ui.set_max_width(460.);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(32., 32.), egui::Sense::hover());
                    crate::icons::brand(ui, rect);
                    ui.heading(self.t("连接控制中心", "Connect your control center"));
                });
                ui.add_space(8.);
                ui.label(
                    RichText::new(self.t(
                        "同一控制中心，管理远程桌面与内网穿透。",
                        "One control center for remote desktop and intranet tunnels.",
                    ))
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(28.);
                egui::Frame::new().fill(ui.visuals().window_fill)
                    .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                    .inner_margin(24)
                    .corner_radius(8)
                    .show(ui, |ui| {
                        ui.set_width((ui.available_width()).min(412.));
                        ui.label(self.t("服务器地址", "Server address"));
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.trust.origin)
                                .hint_text("https://control.example.com")
                                .desired_width(f32::INFINITY)
                                .margin(egui::vec2(12., 10.))
                                .char_limit(512),
                        );
                        ui.add_space(10.);
                        let verifying = snapshot.authentication == Authentication::VerifyingServer;
                        let ready =
                            self.connected && !self.trust.origin.trim().is_empty() && !verifying;
                        let enter = response.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter));
                        if widgets::primary_button(
                            ui,
                            self.t(
                                if verifying {
                                    "正在连接…"
                                } else {
                                    "连接服务器"
                                },
                                if verifying {
                                    "Connecting…"
                                } else {
                                    "Connect to server"
                                },
                            ),
                            ready,
                        )
                        .clicked()
                            || (enter && ready)
                        {
                            self.clear_private_view(ui.ctx());
                            self.send(
                                snapshot,
                                Command::Connect {
                                    server: ApprovedServer::from_origin(
                                        self.trust.origin.trim().into(),
                                        self.trust.loopback,
                                    ),
                                },
                            );
                            self.screen = Screen::Remote;
                        }
                        let status_width = ui.available_width();
                        widgets::fixed_region(ui, "server-verification-status", egui::vec2(status_width, 34.), |ui| {
                            if verifying {
                                ui.horizontal(|ui| { ui.spinner(); ui.small(self.t("正在验证服务器…", "Verifying the control center…")); });
                            } else {
                                ui.small(self.t("连接前会验证服务器身份。", "The server identity is verified before sign-in."));
                            }
                        });
                        ui.add_space(12.);
                        egui::CollapsingHeader::new(self.t("本地开发设置", "Local development"))
                            .show(ui, |ui| {
                                ui.checkbox(
                                    &mut self.trust.loopback,
                                    if self.english {
                                        "Allow HTTP for a local loopback server"
                                    } else {
                                        "允许本机回环服务器使用 HTTP"
                                    },
                                );
                            });
                    });
                ui.add_space(18.);
                ui.small(self.t(
                    "使用控制中心的 HTTPS 地址。自建服务器的连接设置位于下方。",
                    "Use the HTTPS address of your control center. Local connection settings are below.",
                ));
                if let Some(server) = &snapshot.server {
                    if let Some(error) = &server.error {
                        ui.add_space(12.);
                        ui.colored_label(
                            ui.visuals().error_fg_color,
                            widgets::failure(error, self.english),
                        );
                    }
                    if server.verified_health.is_some()
                        && ui
                            .button(self.t("返回工作台", "Back to workspace"))
                            .clicked()
                    {
                        self.screen = Screen::Remote;
                    }
                }
            });
        });
    }

    pub(crate) fn local_network_settings(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(24.);
        ui.separator();
        ui.heading(self.t("本机连接设置", "Local connection settings"));
        if cfg!(windows) {
            ui.label(self.t(
                "媒体连接默认优先使用物理网卡，无需在远程控制时选择网络路径。",
                "Media connections prefer a physical interface by default. No network selection is needed for remote control.",
            ));
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
    }

    pub(crate) fn sign_in_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(32.);
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - 460.) / 2.).max(0.));
            ui.vertical(|ui| {
                ui.set_max_width(460.);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(32., 32.), egui::Sense::hover());
                    crate::icons::brand(ui, rect);
                    ui.heading(self.t("登录 NestLink", "Sign in to NestLink"));
                });
                ui.add_space(8.);
                ui.label(
                    RichText::new(self.t(
                        "连接你的 Windows 电脑，访问内网服务。",
                        "Connect to your Windows computers and intranet services.",
                    ))
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(28.);
                egui::Frame::new().fill(ui.visuals().window_fill)
                    .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                    .inner_margin(24)
                    .corner_radius(8)
                    .show(ui, |ui| {
                        ui.set_width((ui.available_width()).min(412.));
                        if let Some(server) = &snapshot.server {
                            ui.small(self.t("当前控制中心", "Current control center"));
                            ui.add(egui::Label::new(egui::RichText::new(&server.origin).strong()).truncate()).on_hover_text(&server.origin);
                            ui.add_space(12.);
                        }
                        widgets::field(
                            ui,
                            self.t("账号", "Account"),
                            &mut self.credentials.username,
                            128,
                        );
                        ui.add_space(6.);
                        widgets::secret_field(
                            ui,
                            self.t("密码", "Password"),
                            &mut self.credentials.password,
                            "password",
                            self.generation,
                            1024,
                        );
                        ui.add_space(14.);
                        ui.checkbox(
                            &mut self.credentials.remember_login,
                            if self.english {
                                "Keep me signed in on this device"
                            } else {
                                "在此设备保持登录"
                            },
                        );
                        let signing_in = snapshot.authentication == Authentication::SigningIn;
                        let ready = self.connected
                            && !signing_in
                            && !self.credentials.username.trim().is_empty()
                            && !self.credentials.password.is_empty();
                        let enter = ui.input(|input| input.key_pressed(egui::Key::Enter));
                        if widgets::primary_button(
                            ui,
                            self.t(
                                if signing_in {
                                    "正在登录…"
                                } else {
                                    "登录"
                                },
                                if signing_in {
                                    "Signing in…"
                                } else {
                                    "Sign in"
                                },
                            ),
                            ready,
                        )
                        .clicked()
                            || (enter && ready)
                        {
                            let preference = self.directory.join("remember-login.json");
                            if nestlink_platform_security::replace_private_metadata(&preference,
                                if self.credentials.remember_login { b"true" } else { b"false" }).is_err() {
                                self.set_message(self.t("无法保存登录设置，请检查本机数据目录。", "Could not save the sign-in setting. Check the local data directory.").into(), MessageTone::Danger);
                                return;
                            }
                            let action = Action::SignIn {
                                username: self.credentials.username.trim().into(),
                                password: widgets::take_secret(&mut self.credentials.password),
                                factor: None,
                            };
                            widgets::clear_secret_widgets(ui.ctx(), self.generation);
                            self.action(snapshot, action);
                        }
                        let status_width = ui.available_width();
                        widgets::fixed_region(ui, "sign-in-status", egui::vec2(status_width, 56.), |ui| {
                            if signing_in {
                                ui.horizontal(|ui| { ui.spinner(); ui.label(self.t("正在验证账号…", "Verifying your account…")); });
                            }
                            if let Some(error) = &snapshot.authentication_error {
                                egui::ScrollArea::vertical().id_salt("sign-in-error").max_height(56.).show(ui, |ui| {
                                    ui.colored_label(ui.visuals().error_fg_color, widgets::failure(error, self.english));
                                });
                            }
                        });
                    });
                ui.add_space(16.);
                if ui
                    .button(self.t("连接其他服务器", "Connect to another server"))
                    .clicked()
                {
                    self.credentials.clear();
                    self.screen = Screen::Server;
                    self.set_message(
                        self.t("请输入新的服务器地址。", "Enter the new server address.")
                            .into(),
                        MessageTone::Neutral,
                    );
                }
            });
        });
    }
}
