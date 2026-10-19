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
                ui.heading(self.t("连接你的设备，从这里开始", "Your devices, within reach"));
                ui.add_space(8.);
                ui.label(
                    RichText::new(self.t(
                        "输入控制中心地址，连接后即可登录。",
                        "Enter your control center address to continue to sign in.",
                    ))
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(28.);
                egui::Frame::group(ui.style())
                    .inner_margin(24)
                    .corner_radius(12)
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
                        if verifying {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    self.t(
                                        "正在建立安全连接…",
                                        "Establishing a secure connection…",
                                    ),
                                );
                            });
                        }
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
                    "通过 HTTPS 自动读取服务器配置，连接信息仅用于当前会话。",
                    "Server configuration is discovered over HTTPS for this session.",
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

    pub(crate) fn sign_in_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(32.);
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - 460.) / 2.).max(0.));
            ui.vertical(|ui| {
                ui.set_max_width(460.);
                ui.heading(self.t("欢迎使用 NestLink", "Welcome to NestLink"));
                ui.add_space(8.);
                ui.label(
                    RichText::new(self.t(
                        "登录后，远程控制和服务发布尽在一处。",
                        "Sign in to manage remote access and published services.",
                    ))
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(28.);
                egui::Frame::group(ui.style())
                    .inner_margin(24)
                    .corner_radius(12)
                    .show(ui, |ui| {
                        ui.set_width((ui.available_width()).min(412.));
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
                        if signing_in {
                            ui.spinner();
                        }
                        if let Some(error) = &snapshot.authentication_error {
                            ui.colored_label(
                                ui.visuals().error_fg_color,
                                widgets::failure(error, self.english),
                            );
                        }
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
