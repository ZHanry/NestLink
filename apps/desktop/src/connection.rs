use crate::{DesktopApp, MessageTone, Screen, widgets};
use eframe::egui::{self, RichText};
use nestlink_app_core::{Action, ApprovedServer, Authentication, Snapshot};
use nestlink_app_ipc::wire::Command;

impl DesktopApp {
    pub(crate) fn connection_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(0.);
        ui.horizontal_top(|ui| {
            if ui.available_width()>900. { self.login_brand_panel(ui); }
            ui.add_space(((ui.available_width() - 330.) / 2.).max(0.));
            ui.vertical(|ui| {
                ui.set_width(330.);
                ui.add_space(((ui.ctx().content_rect().height() - 620.) / 2.).max(0.));
                ui.label(RichText::new("WELCOME BACK").size(10.).color(ui.visuals().hyperlink_color));
                ui.add_space(12.);
                ui.horizontal(|ui| {
                    ui.heading(self.t("连接你的控制中心", "Connect your control center"));
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
                egui::Frame::new().inner_margin(0)
                    .show(ui, |ui| {
                        ui.set_width(330.);
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
                    "使用控制中心的 HTTPS 地址。登录后可在设置中调整网络连接。",
                    "Use your control center's HTTPS address. Network options are available in Settings after sign-in.",
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
        egui::CollapsingHeader::new(self.t("连接诊断", "Connection diagnostics"))
            .show(ui, |ui| self.connection_diagnostics(ui, snapshot));
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

    fn connection_diagnostics(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let verified = snapshot
            .server
            .as_ref()
            .is_some_and(|server| server.error.is_none() && server.verified_health.is_some());
        let signed_in = verified
            && snapshot.authentication == Authentication::SignedIn
            && snapshot.principal.is_some();
        let enrolled = signed_in
            && snapshot.installation.as_ref().is_some_and(|local| {
                snapshot.devices.error.is_none()
                    && snapshot.devices.loading.is_none()
                    && snapshot.devices.data.as_ref().is_some_and(|devices| {
                        devices
                            .iter()
                            .any(|view| view.device.id == local.device_id && !view.revoked)
                    })
            });
        for (title, value) in [
            (
                self.t("控制中心", "Control center"),
                self.t(
                    if verified {
                        "身份已验证"
                    } else {
                        "等待连接并验证"
                    },
                    if verified {
                        "Identity verified"
                    } else {
                        "Connect and verify"
                    },
                ),
            ),
            (
                self.t("账号", "Account"),
                self.t(
                    if signed_in {
                        "已登录"
                    } else {
                        "等待登录"
                    },
                    if signed_in {
                        "Signed in"
                    } else {
                        "Sign in required"
                    },
                ),
            ),
            (
                self.t("此设备", "This device"),
                self.t(
                    if enrolled {
                        "服务器列表中已登记"
                    } else {
                        "尚未确认登记，请读取设备列表"
                    },
                    if enrolled {
                        "Enrolled in the server device list"
                    } else {
                        "Enrollment unconfirmed; read the device list"
                    },
                ),
            ),
        ] {
            ui.horizontal_wrapped(|ui| {
                ui.strong(title);
                ui.label(value);
            });
        }
        if let Some(error) = &snapshot.devices.error {
            ui.colored_label(
                ui.visuals().error_fg_color,
                widgets::failure(error, self.english),
            );
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    verified && !signed_in,
                    egui::Button::new(self.t("继续登录", "Continue to sign in")),
                )
                .clicked()
            {
                self.screen = Screen::Remote;
            }
            if ui
                .add_enabled(
                    signed_in && snapshot.devices.loading.is_none(),
                    egui::Button::new(self.t("读取当前设备状态", "Read current device status")),
                )
                .clicked()
            {
                self.load(snapshot, nestlink_app_core::Page::Devices);
            }
        });
        ui.small(self.t("这里显示最近一次实际读取的结果。登记、配置保存和服务连通分别确认；连接结果在开始实际会话后显示。", "These are the last actual readback results. Enrollment, saved configuration and reachability are confirmed separately; connection results appear after starting a real session."));
        egui::CollapsingHeader::new(self.t("查看连接检查", "Connection checks")).show(ui, |ui| {
            ui.label(self.t(
                if snapshot.native_network.use_deployment_stun { "STUN：已允许当前设备使用部署地址；可达性需在实际会话中确认。" } else { "STUN：当前设备未启用部署地址发现。" },
                if snapshot.native_network.use_deployment_stun { "STUN: deployment discovery is allowed on this device; reachability is confirmed during an actual session." } else { "STUN: deployment discovery is disabled on this device." },
            ));
            ui.label(if snapshot.native_network.space_path.is_some() {
                self.t("空间路径：本机已保存仅直连批准。直连失败时停止。", "Space path: direct-only consent is saved locally. A failed direct connection stops.")
            } else if snapshot.native_network.route_set.is_some() {
                self.t("空间路径：本机已保存指定双中继批准；节点和会话仍需各自授权及实际可达。", "Space path: consent for the specified two relays is saved locally. Nodes and sessions still require their own authorization and actual reachability.")
            } else {
                self.t("连接路径：使用部署和本次会话策略。是否允许中继还取决于双方设备批准。", "Connection path: follows deployment and session policy. Relay use also requires both devices' consent.")
            });
            if let Some(durable) = snapshot.native_network_durable {
                ui.label(self.t(if durable { "本机配置：已确认保存。" } else { "本机配置：已应用，持久保存尚未确认。" }, if durable { "Local configuration: persistence confirmed." } else { "Local configuration: applied; persistence unconfirmed." }));
            }
            if let Some(session) = snapshot.native_session.data.as_ref().filter(|session| session.status == nestlink_app_core::NativeSessionStatus::Connected) {
                ui.label(match session.path {
                    Some(1) => self.t("当前远控：实际直连已建立。", "Current remote session: a direct connection is established."),
                    Some(2) => self.t("当前远控：实际中继连接已建立。", "Current remote session: a relayed connection is established."),
                    _ => self.t("当前远控：已连接，路径类型尚未确认。", "Current remote session: connected; path type unconfirmed."),
                });
            } else {
                ui.label(self.t("当前远控：尚无已连接会话。", "Current remote session: no connected session."));
            }
            ui.small(self.t("浏览器远控使用 WebRTC。TURN、中继、公网入口和本机服务目标分别在实际连接或发布时检查；未检查的项目没有通过状态。可先从设备发起一次已批准的远控，再查看连接诊断。", "Browser remote access uses WebRTC. TURN, relays, public ingress and local service targets are checked when actually connecting or publishing. Unchecked items have no passing status. Start an approved session from Devices, then inspect connection diagnostics."));
        });
        let mode_id = ui.make_persistent_id("setup-purpose");
        let mut mode = ui
            .ctx()
            .data_mut(|data| data.get_temp::<u8>(mode_id))
            .unwrap_or(0);
        ui.add_space(12.);
        ui.horizontal_wrapped(|ui| {
            for (value, zh, en) in [
                (0, "远程桌面", "Remote desktop"),
                (1, "私有服务", "Private services"),
                (2, "公网发布", "Public publishing"),
                (3, "空间与虚拟网络", "Spaces and virtual networks"),
            ] {
                ui.selectable_value(&mut mode, value, self.t(zh, en));
            }
        });
        ui.ctx().data_mut(|data| data.insert_temp(mode_id, mode));
        match mode {
            0 => {
                ui.label(self.t("先在双方登记设备，再选择目标发起远控。画面、输入、文件和剪贴板按本次批准的权限开放；默认远控无需虚拟网卡。", "Enroll both devices, then choose the target and request a session. Screen, input, files and clipboard use the permissions approved for that session. Ordinary remote access needs no virtual adapter."));
                if ui
                    .add_enabled(
                        signed_in,
                        egui::Button::new(self.t("打开远程桌面", "Open remote desktop")),
                    )
                    .clicked()
                {
                    self.navigate(Screen::Remote, snapshot);
                }
            }
            1 => {
                ui.label(self.t("在服务中选择私有范围，确认固定目标、允许访问的设备和本机同意。访问端通过本地代理或获准的私有 Web 入口连接；加入空间不会自动授权本机端口。", "Choose private exposure in Services and confirm the fixed target, permitted devices and local consent. Connect through a local proxy or approved private web entry. Space membership alone does not authorize local ports."));
                if ui
                    .add_enabled(
                        signed_in,
                        egui::Button::new(self.t("配置私有服务", "Configure private services")),
                    )
                    .clicked()
                {
                    self.navigate(Screen::Services, snapshot);
                }
            }
            2 => {
                ui.label(self.t("在服务中显式选择公网范围，再读取节点和入口状态并批准发布。只有实际发布就绪后才能使用公网地址；保存配置不会开启公网访问。", "Explicitly choose public exposure in Services, read the node and entry status, then approve publishing. Use the public address after actual publication is ready. Saving configuration does not enable public access."));
                if ui
                    .add_enabled(
                        signed_in,
                        egui::Button::new(self.t("配置公网服务", "Configure public services")),
                    )
                    .clicked()
                {
                    self.navigate(Screen::Services, snapshot);
                }
            }
            _ => {
                ui.label(self.t("打开网络空间，创建或加入空间、登记设备，并为已批准的远控选择空间路径。地址与名称、子网和 WireGuard 在控制中心管理。系统虚拟网卡和转发需要在运行设备上另行批准并启用。", "Open Network spaces to create or join a space, enroll a device, and select a space path for an approved remote session. Manage addresses, names, subnets and WireGuard in the control center. Approve and enable system adapters and forwarding separately on the runtime device."));
                if ui
                    .add_enabled(
                        signed_in,
                        egui::Button::new(self.t("打开网络空间", "Open network spaces")),
                    )
                    .clicked()
                {
                    self.navigate(Screen::Spaces, snapshot);
                }
                if signed_in {
                    if let Some(server) = &snapshot.server {
                        ui.hyperlink_to(
                            self.t("打开控制中心", "Open control center"),
                            &server.origin,
                        );
                    }
                } else {
                    ui.small(self.t("登录后可创建空间或接受邀请。成员角色和网络访问权限分别检查。", "Sign in to create a space or accept an invitation. Membership roles and network access permissions are checked separately."));
                }
            }
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    signed_in,
                    egui::Button::new(self.t("登记与管理设备", "Enroll and manage devices")),
                )
                .clicked()
            {
                self.navigate(Screen::Devices, snapshot);
            }
            if ui
                .add_enabled(
                    self.network_diagnostics.has_observations(),
                    egui::Button::new(self.t("复制连接诊断", "Copy connection diagnostics")),
                )
                .clicked()
                && let Ok(report) = serde_json::to_string_pretty(&self.network_diagnostics.export())
            {
                ui.ctx().copy_text(report);
            }
        });
    }

    pub(crate) fn sign_in_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(0.);
        ui.horizontal_top(|ui| {
            if ui.available_width()>900. { self.login_brand_panel(ui); }
            ui.add_space(((ui.available_width() - 330.) / 2.).max(0.));
            ui.vertical(|ui| {
                ui.set_width(330.);
                ui.add_space(((ui.ctx().content_rect().height() - 620.) / 2.).max(0.));
                ui.label(RichText::new("WELCOME BACK").size(10.).color(ui.visuals().hyperlink_color));
                ui.add_space(12.);
                ui.horizontal(|ui| {
                    ui.heading(self.t("连接你的控制中心", "Connect your control center"));
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
                egui::Frame::new().inner_margin(0)
                    .show(ui, |ui| {
                        ui.set_width(330.);
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
