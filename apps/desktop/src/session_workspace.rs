//! Remote viewport presentation. Session authority and native resource ownership stay unchanged.
use crate::{
    DesktopApp, NativeSessionStatus, RemoteViewportAction, cleanup_phase, icons, theme, widgets,
};
use eframe::egui;
use nestlink_app_core::Snapshot;
use std::time::Duration;

impl DesktopApp {
    pub(crate) fn remote_viewport_contents(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
    ) -> RemoteViewportAction {
        let fullscreen = ui.input(|input| input.viewport().fullscreen.unwrap_or(false));
        let mut fullscreen_change = ui.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::F11) {
                Some(!fullscreen)
            } else if fullscreen && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                Some(false)
            } else {
                None
            }
        });
        let target = self.remote_viewport_target.clone();
        let session = target.as_ref().and_then(|target| {
            snapshot.native_session.data.as_ref().filter(|session| {
                session.request_id == target.request_id
                    && session.connection_generation == target.connection_generation
            })
        });
        let mut action = RemoteViewportAction::None;
        egui::Panel::top("session-toolbar")
            .exact_size(62.)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().window_fill)
                    .inner_margin(egui::Margin::symmetric(20, 10)),
            )
            .show_inside(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 6.;
                ui.horizontal_centered(|ui| {
                    let identity_width = (ui.available_width() - 380.).max(80.);
                    widgets::fixed_region(
                        ui,
                        "session-identity",
                        egui::vec2(identity_width, 42.),
                        |ui| {
                            ui.horizontal(|ui| {
                                icons::badge(ui, icons::Icon::Monitor, 38.);
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 3.;
                                    let name = target
                                        .as_ref()
                                        .and_then(|target| {
                                            snapshot
                                                .selected_request
                                                .data
                                                .as_ref()
                                                .filter(|request| request.id == target.request_id)
                                        })
                                        .and_then(|request| {
                                            snapshot.devices.data.as_deref()?.iter().find(
                                                |device| device.device.id == request.host_device_id,
                                            )
                                        })
                                        .map(|device| device.device.name.as_str())
                                        .unwrap_or(if snapshot.native_offline.is_some() {
                                            self.t("离线仅直连", "Offline · direct only")
                                        } else {
                                            self.t("远程桌面", "Remote desktop")
                                        });
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(name)
                                                .font(theme::heading_font(15.)),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(name);
                                    let status = if self.remote_window_cleanup.is_some() {
                                        self.t("正在断开", "Disconnecting")
                                    } else {
                                        match session.map(|session| session.status) {
                                            Some(NativeSessionStatus::Connected) => {
                                                self.t("会话进行中", "Session active")
                                            }
                                            Some(NativeSessionStatus::Establishing) => {
                                                self.t("正在连接", "Connecting")
                                            }
                                            Some(NativeSessionStatus::Stopping) => {
                                                self.t("正在断开", "Disconnecting")
                                            }
                                            Some(NativeSessionStatus::Stopped) => {
                                                self.t("会话已结束", "Session ended")
                                            }
                                            Some(NativeSessionStatus::Failed) => {
                                                self.t("会话失败", "Session failed")
                                            }
                                            None => {
                                                self.t("等待会话状态", "Waiting for session state")
                                            }
                                        }
                                    };
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(status)
                                                .small()
                                                .color(ui.visuals().hyperlink_color),
                                        )
                                        .truncate(),
                                    );
                                });
                            });
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let palette = if self.dark {
                            &self.tokens.dark
                        } else {
                            &self.tokens.light
                        };
                        let background = if self.dark {
                            &self.tokens.state.danger_soft.dark
                        } else {
                            &self.tokens.state.danger_soft.light
                        };
                        if ui
                            .add_enabled(
                                self.remote_window_cleanup.is_none(),
                                egui::Button::new(
                                    egui::RichText::new(self.t("断开", "Disconnect"))
                                        .color(theme::color(&palette.danger)),
                                )
                                .fill(theme::color(background))
                                .stroke(egui::Stroke::NONE)
                                .min_size(egui::vec2(82., 32.)),
                            )
                            .clicked()
                        {
                            action = RemoteViewportAction::Close;
                        }
                        if icons::tool_button(
                            ui,
                            icons::Icon::Maximize,
                            if fullscreen {
                                self.t("退出全屏 (Esc)", "Exit fullscreen (Esc)")
                            } else {
                                self.t("全屏 (F11)", "Fullscreen (F11)")
                            },
                        )
                        .clicked()
                        {
                            fullscreen_change = Some(!fullscreen);
                        }
                        ui.add_enabled_ui(self.remote_window_cleanup.is_none(), |ui| {
                            for (icon, label, tool) in [
                                (
                                    icons::Icon::Settings,
                                    self.t("会话设置", "Session settings"),
                                    0,
                                ),
                                (
                                    icons::Icon::Keyboard,
                                    self.t("键鼠控制", "Keyboard and mouse"),
                                    4,
                                ),
                                (icons::Icon::Files, self.t("会话文件", "Session files"), 1),
                                (
                                    icons::Icon::Clipboard,
                                    self.t("会话剪贴板", "Session clipboard"),
                                    2,
                                ),
                                (icons::Icon::Audio, self.t("会话音频", "Session audio"), 5),
                                (
                                    icons::Icon::Monitor,
                                    self.t("选择显示器", "Choose display"),
                                    3,
                                ),
                            ] {
                                if icons::tool_button(ui, icon, label).clicked() {
                                    self.release_native_control();
                                    self.remote_tools_open = !(self.remote_tools_open
                                        && self.workspace.remote_session_tool == tool);
                                    self.workspace.remote_session_tool = tool;
                                }
                            }
                        });
                    });
                });
            });
        if let Some(fullscreen) = fullscreen_change {
            self.release_native_control();
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(fullscreen));
        }
        egui::Panel::bottom("session-control-dock")
            .exact_size(58.)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().window_fill)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_top(|ui| {
                    let message_width = (ui.available_width() - if self.remote_window_cleanup.is_some() { 244. } else { 0. }).max(100.);
                    widgets::fixed_region(
                        ui,
                        "session-state",
                        egui::vec2(message_width, 42.),
                        |ui| {
                            if let Some(cleanup) = &self.remote_window_cleanup {
                                let message = cleanup.error.as_deref().unwrap_or(if cleanup.offline {
                                    self.t("正在终止原离线授权并清理资源…", "Ending the original offline authority and cleaning up…")
                                } else {
                                    self.t("正在结束会话并撤销访问…", "Ending the session and revoking access…")
                                });
                                ui.add(egui::Label::new(message).truncate())
                                    .on_hover_text(message);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!(
                                            "{} {} / {} {}",
                                            self.t("本地清理", "Local cleanup"),
                                            cleanup_phase(cleanup.stop_status, self.english),
                                            if cleanup.offline { self.t("本机授权终止", "Local authority stop") } else { self.t("访问撤销", "Revocation") },
                                            cleanup_phase(cleanup.revoke_status, self.english)
                                        ))
                                        .small(),
                                    )
                                    .truncate(),
                                );
                            } else {
                                ui.strong(match session.map(|session| session.status) {
                                    Some(NativeSessionStatus::Establishing) => {
                                        if session.is_some_and(|session| session.is_recovering()) {
                                            self.t("正在恢复连接", "Recovering connection")
                                        } else {
                                            self.t("正在建立连接", "Establishing connection")
                                        }
                                    }
                                    Some(NativeSessionStatus::Connected) => {
                                        self.t("已连接", "Connected")
                                    }
                                    Some(NativeSessionStatus::Stopping) => {
                                        self.t("正在断开", "Disconnecting")
                                    }
                                    Some(NativeSessionStatus::Stopped) => {
                                        self.t("会话已结束", "Session ended")
                                    }
                                    Some(NativeSessionStatus::Failed) => {
                                        self.t("会话失败", "Session failed")
                                    }
                                    None => self.t("会话状态不可用", "Session state unavailable"),
                                });
                                ui.small(match session.and_then(|session| session.path) {
                                    Some(1) => self.t(
                                        "实际连接路径：直连",
                                        "Observed connection path: direct",
                                    ),
                                    Some(2) => self
                                        .t("实际连接路径：中继", "Observed connection path: relay"),
                                    _ => {
                                        self.t("连接路径尚未确认", "Connection path not confirmed")
                                    }
                                });
                            }
                        },
                    );
                    if let Some(cleanup) = &self.remote_window_cleanup
                        && ui
                            .add_enabled(
                                cleanup.error.is_some() && self.connected,
                                egui::Button::new(self.t("重试清理", "Retry cleanup"))
                                    .min_size(egui::vec2(228., 40.)),
                            )
                            .clicked()
                    {
                        action = RemoteViewportAction::Retry;
                    }
                });
            });

        if self.remote_tools_open && self.remote_window_cleanup.is_none() {
            self.session_inspector(ui, snapshot);
        }
        self.video_panel(ui, snapshot);
        action
    }

    fn session_inspector(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let tools_width = (ui.available_width() * 0.32).clamp(260., 360.);
        egui::Panel::right("remote-session-tools").exact_size(tools_width).resizable(false)
            .frame(egui::Frame::new().fill(ui.visuals().window_fill).inner_margin(16.))
            .show_inside(ui, |ui| {
                let title = match self.workspace.remote_session_tool {
                    1 => self.t("文件传输", "File transfer"),
                    2 => self.t("剪贴板", "Clipboard"),
                    3 => self.t("显示器", "Displays"),
                    4 => self.t("键鼠控制", "Keyboard and mouse"),
                    5 => self.t("音频", "Audio"),
                    _ => self.t("会话设置", "Session settings"),
                };
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 48.).max(1.);
                    ui.add_sized([width, 32.], egui::Label::new(egui::RichText::new(title).font(theme::heading_font(16.))).truncate());
                    if icons::tool_button(ui, icons::Icon::Close, self.t("收起会话面板", "Close session panel")).clicked() { self.remote_tools_open = false; }
                });
                ui.separator();
                egui::ScrollArea::vertical().id_salt(("remote-tools-scroll", self.workspace.remote_session_tool)).show(ui, |ui| {
                    match self.workspace.remote_session_tool {
                        1 => {
                            if self.file_panel.session().is_none_or(|session| !session.read && !session.write) {
                                ui.label(self.t("本次会话未授权文件传输，或文件通道尚未就绪。", "File transfer is not authorized or the file channel is not ready for this session."));
                            }
                            self.session_files_panel(ui, snapshot);
                        }
                        2 => {
                            ui.small(self.t("仅在本次会话获得剪贴板授权且通道就绪时可用。", "Available when this session authorizes clipboard access and its channel is ready."));
                            self.session_clipboard_panel(ui, snapshot);
                        }
                        3 => self.native_display_panel(ui, snapshot),
                        4 => {
                            ui.label(self.t("使用画面上方的键鼠按钮开始或暂停控制。", "Use the keyboard and mouse button above the screen to start or pause control."));
                            ui.add_space(8.);
                            ui.small(self.t("需要本次会话已授权，且画面和输入通道均已就绪。失去焦点时会释放按键。", "The session must authorize input, with video and the input channel ready. Losing focus releases held inputs."));
                        }
                        5 => {
                            let authorized = self.remote_viewport_target.as_ref().and_then(|target| snapshot.selected_request.data.as_ref().filter(|request| request.id == target.request_id))
                                .map(|request| request.permissions.contains(&(nestlink_protocol::Permission::Audio as i32)));
                            ui.label(match authorized {
                                Some(true) => self.t("已授权 · 使用本机系统音频设备", "Authorized · uses local system audio devices"),
                                Some(false) => self.t("未授权，重新申请时可选择音频", "Not authorized; request Audio for a new session"),
                                None => self.t("本次会话没有音频授权状态", "Audio authorization is unavailable for this session"),
                            });
                        }
                        _ => {
                            self.native_display_panel(ui, snapshot);
                            ui.add_space(12.);
                            ui.collapsing(self.t("连接诊断", "Connection diagnostics"), |ui| self.session_diagnostics(ui));
                        }
                    }
                });
            });
    }

    fn session_diagnostics(&mut self, ui: &mut egui::Ui) {
        #[cfg(windows)]
        if self.gpu_video.active() {
            ui.label(format!(
                "GPU blit: {} · submitted: {} · QPC {:?} · scanout unverified",
                self.gpu_video.converted_count,
                self.gpu_video.submitted_count,
                self.gpu_video.last_submitted_qpc
            ));
        }
        #[cfg(windows)]
        if self.gpu_video.has_diagnostics() {
            ui.small(self.t(
                "原生 GPU 接收端诊断；扫描输出未验证",
                "Native GPU receiver diagnostics; scanout unverified",
            ));
            if ui
                .button(self.t("复制脱敏诊断", "Copy redacted diagnostics"))
                .clicked()
                && let Some(report) = self.gpu_video.diagnostics_export()
                && let Ok(text) = serde_json::to_string_pretty(&report)
            {
                ui.ctx().copy_text(text);
            }
        }
        if let Some(observed) = &self.video_observation {
            ui.strong(self.t("连接与性能", "Connection and performance"));
            ui.label(format!(
                "{}: {}",
                self.t("实际编码", "Actual codec"),
                match observed.codec {
                    1 => "H.264 Baseline",
                    2 => "HEVC Main8",
                    3 => "HEVC Main10",
                    4 => "VP9 RGB444",
                    _ => "VP8",
                }
            ));
            ui.label(format!(
                "{}: {}",
                self.t("实际解码", "Actual decoder"),
                if observed.hardware {
                    self.t("硬件", "Hardware")
                } else {
                    self.t("软件", "Software")
                }
            ));
            let fps = observed
                .fps
                .filter(|_| observed.latest.elapsed() < Duration::from_secs(2))
                .map(|fps| format!("{fps:.1} fps"))
                .unwrap_or_else(|| self.t("未观测", "Not observed").into());
            ui.label(format!(
                "{}: {fps}",
                self.t("画面上传帧率", "Texture upload rate")
            ));
            ui.label(format!("{} × {}", observed.layout.1, observed.layout.2));
            ui.small(self.t("解码后经 CPU 像素上传呈现；此帧率不代表端到端输入时延。", "Decoded CPU pixels are uploaded for display. This rate does not measure input-to-picture latency."));
            if ui
                .button(self.t("复制脱敏诊断", "Copy redacted diagnostics"))
                .clicked()
            {
                let report = serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "codec": match observed.codec { 1 => "h264-baseline", 2 => "hevc-main8", 3 => "hevc-main10", 4 => "vp9-rgb444", _ => "vp8" }, "hardware_decode_observed": observed.hardware,
                                        "texture_upload_fps": observed.fps.filter(|_| observed.latest.elapsed() < Duration::from_secs(2)), "sample_age_ms": observed.latest.elapsed().as_millis(), "width": observed.layout.1, "height": observed.layout.2,
                                        "presentation": "cpu-bgra-texture-upload", "network_rtt_ms": null, "end_to_end_latency_ms": null});
                if let Ok(text) = serde_json::to_string_pretty(&report) {
                    ui.ctx().copy_text(text);
                }
            }
            ui.separator();
        }
    }
}
