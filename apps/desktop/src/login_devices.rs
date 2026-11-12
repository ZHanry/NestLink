use crate::{
    DesktopApp,
    icons::{self, Icon},
    widgets,
};
use eframe::egui::{self, RichText};
use nestlink_app_core::{Action, Page, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::api::LoginSessionView;

fn device_name(session: &LoginSessionView) -> &str {
    session
        .device_name
        .as_deref()
        .filter(|v| !v.is_empty())
        .or(session.client.as_deref().filter(|v| !v.is_empty()))
        .unwrap_or("未命名登录 / Unnamed login")
}
fn activity(time: Option<u64>, english: bool) -> String {
    let Some(time) = time else {
        return if english { "Not recorded" } else { "未记录" }.into();
    };
    format!("{} UTC", widgets::utc_time(time))
}

impl DesktopApp {
    pub(crate) fn login_devices_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        widgets::page_heading(
            ui,
            self.t("设备管理", "Login devices"),
            self.t(
                "管理当前账号已登录的设备和浏览器会话。",
                "Manage devices and browsers signed in to your account.",
            ),
        );
        ui.horizontal(|ui| {
            if icons::button(ui, Icon::Refresh, self.t("刷新登录设备", "Refresh logins")).clicked()
            {
                self.load(snapshot, Page::AccountSecurity);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .selectable_label(self.workspace.devices_view == 1, self.t("列表", "List"))
                    .clicked()
                {
                    self.workspace.devices_view = 1;
                }
                if ui
                    .selectable_label(self.workspace.devices_view == 0, self.t("卡片", "Cards"))
                    .clicked()
                {
                    self.workspace.devices_view = 0;
                }
            });
        });
        widgets::section(ui, &snapshot.security, self.english);
        let Some(security) = &snapshot.security.data else {
            return;
        };
        if !security.session_management_available {
            widgets::notice(ui,self.t("当前控制中心尚不支持登录设备管理。请将服务器升级到 0.8.1 RC 后刷新。", "This control center does not support login-device management yet. Upgrade the server to 0.8.1 RC and refresh."));
            return;
        }
        widgets::surface(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                icons::badge(ui, Icon::Account, 38.);
                ui.vertical(|ui| {
                    ui.strong(format!(
                        "{} {}",
                        security.principal.name,
                        self.t("的登录设备", "— signed-in devices")
                    ));
                    ui.small(format!(
                        "{} {}",
                        security.sessions.len(),
                        self.t(
                            "条有效登录记录（最多显示 100 条）",
                            "active login records (up to 100 shown)"
                        )
                    ));
                });
            });
        });
        ui.add_space(18.);
        if self.workspace.devices_view == 0 {
            let columns: usize = if ui.available_width() > 1000. {
                3
            } else if ui.available_width() > 620. {
                2
            } else {
                1
            };
            let columns = columns.min(security.sessions.len().max(1));
            for chunk in security.sessions.chunks(columns) {
                ui.columns(columns, |uis| {
                    for (index, session) in chunk.iter().enumerate() {
                        widgets::surface(&uis[index]).show(&mut uis[index], |ui| {
                            ui.set_min_width(ui.available_width());
                            self.login_device_card(ui, snapshot, session);
                        });
                    }
                });
                ui.add_space(12.);
            }
        } else {
            widgets::surface(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                for session in &security.sessions {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(device_name(session));
                        ui.label(session.client.as_deref().unwrap_or("—"));
                        ui.small(activity(session.last_active_at, self.english));
                        if session.current {
                            ui.label(
                                RichText::new(self.t("当前设备", "This device"))
                                    .color(ui.visuals().hyperlink_color),
                            );
                        }
                        if ui.button(self.t("登录详情", "Details")).clicked() {
                            self.workspace.selected_login = Some(session.session_id.clone());
                        }
                        self.login_signout_button(ui, snapshot, session);
                    });
                    ui.separator();
                }
            });
        }
        ui.add_space(12.);
        widgets::notice(ui,self.t("退出设备会结束它的账号登录及依赖该登录的远程授权。设备身份和空间成员关系分别保留，在「网络空间」管理组网成员。", "Signing out ends that login and remote authority depending on it. Device identities and space membership remain separately managed in Network spaces."));
        if let Some(session) = security
            .sessions
            .iter()
            .find(|s| Some(&s.session_id) == self.workspace.selected_login.as_ref())
        {
            let context = ui.ctx().clone();
            let response = egui::Modal::new(egui::Id::new("login-device-details"))
                .frame(widgets::modal_frame(&context))
                .show(&context, |ui| {
                    ui.set_width(420_f32.min(context.content_rect().width() - 64.));
                    widgets::modal_heading(
                        ui,
                        self.t("登录设备详情", "Login device details"),
                        self.english,
                    );
                    ui.strong(device_name(session));
                    ui.label(format!(
                        "{} · {}",
                        session.platform.as_deref().unwrap_or("—"),
                        session.client.as_deref().unwrap_or("—")
                    ));
                    ui.label(format!(
                        "{}: {}",
                        self.t("登录时间", "Signed in"),
                        activity(session.created_at, self.english)
                    ));
                    ui.label(format!(
                        "{}: {}",
                        self.t("最近活动", "Last account activity"),
                        activity(session.last_active_at, self.english)
                    ));
                    ui.label(self.t("会话标识", "Session identifier"));
                    ui.monospace(&session.session_id);
                    if widgets::primary_button(ui, self.t("完成", "Done"), true).clicked() {
                        self.workspace.selected_login = None;
                    }
                });
            if response.should_close() {
                self.workspace.selected_login = None;
            }
        }
    }

    fn login_device_card(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        session: &LoginSessionView,
    ) {
        // Identity, facts and actions have separate budgets. A current-session
        // badge or a long device name cannot move another card's action row.
        widgets::fixed_region(
            ui,
            ("login-card", &session.session_id),
            egui::vec2(ui.available_width(), 188.),
            |ui| {
                let card = ui.max_rect();
                widgets::fixed_region(ui, "identity", egui::vec2(card.width(), 48.), |ui| {
                    ui.horizontal(|ui| {
                        icons::badge(
                            ui,
                            if session
                                .client
                                .as_deref()
                                .is_some_and(|v| v.starts_with("Web"))
                            {
                                Icon::Network
                            } else {
                                Icon::Monitor
                            },
                            40.,
                        );
                        ui.vertical(|ui| {
                            ui.add(
                                egui::Label::new(RichText::new(device_name(session)).strong())
                                    .truncate(),
                            )
                            .on_hover_text(device_name(session));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "{} · {}",
                                        session.platform.as_deref().unwrap_or("—"),
                                        session.client.as_deref().unwrap_or("—")
                                    ))
                                    .small()
                                    .weak(),
                                )
                                .truncate(),
                            );
                        });
                    });
                });
                for (label, value) in [
                    (
                        self.t("登录时间", "Signed in"),
                        activity(session.created_at, self.english),
                    ),
                    (
                        self.t("最近活动", "Last activity"),
                        activity(session.last_active_at, self.english),
                    ),
                ] {
                    widgets::fixed_region(ui, label, egui::vec2(card.width(), 20.), |ui| {
                        // A facts row contains text only. The global button
                        // height would center its labels below this row's clip.
                        ui.spacing_mut().interact_size.y = 20.;
                        ui.horizontal(|ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(76., 20.),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.small(RichText::new(label).weak());
                                },
                            );
                            ui.add(egui::Label::new(RichText::new(&value).small()).truncate())
                                .on_hover_text(&value);
                        });
                    });
                }
                let footer = egui::Rect::from_min_max(
                    egui::pos2(card.left(), card.bottom() - 52.),
                    card.max,
                );
                ui.scope_builder(egui::UiBuilder::new().max_rect(footer), |ui| {
                    ui.separator();
                    ui.horizontal(|ui| {
                        if session.current {
                            ui.colored_label(
                                ui.visuals().hyperlink_color,
                                RichText::new(self.t("当前设备", "This device")).small(),
                            );
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            self.login_signout_button(ui, snapshot, session);
                            if ui.button(self.t("登录详情", "Details")).clicked() {
                                self.workspace.selected_login = Some(session.session_id.clone());
                            }
                        });
                    });
                });
            },
        );
    }
    fn login_signout_button(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        session: &LoginSessionView,
    ) {
        let text = self.t(
            if session.current {
                "退出登录"
            } else {
                "退出此设备"
            },
            if session.current {
                "Sign out"
            } else {
                "Sign out device"
            },
        );
        if ui
            .add_enabled(
                snapshot.security.loading.is_none(),
                egui::Button::new(RichText::new(text).color(ui.visuals().error_fg_color)),
            )
            .clicked()
        {
            self.pending_confirmation = Some((
                format!(
                    "{} {}?",
                    self.t("退出登录：", "Sign out:"),
                    device_name(session)
                ),
                if session.current {
                    Command::Logout
                } else {
                    Command::Submit {
                        action: Action::RevokeLoginSession {
                            session_id: session.session_id.clone(),
                        },
                    }
                },
            ));
        }
    }
}
