//! Independent host indicator: stays visible while the main window is in the tray.
use crate::{DesktopApp, MessageTone, Screen, theme, tray, widgets};
use eframe::egui;
use nestlink_app_core::{Action, BrowserHostStatus, NativeSessionStatus, Snapshot};
use nestlink_app_ipc::wire::Command;
use nestlink_protocol::api::{ApprovalChoice, RemoteView};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

#[derive(Clone, PartialEq, Eq)]
struct NoticeKey {
    id: String,
    connection: u64,
    browser: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Request,
    Preparing,
    Screen,
    Sharing,
    Stopping,
}
#[derive(Clone)]
struct Notice {
    key: NoticeKey,
    phase: Phase,
    request: Option<RemoteView>,
    path: Option<i32>,
    peer: String,
}
#[derive(Clone, Copy)]
enum Choice {
    Review,
    Reject,
    Disconnect,
}
struct Event {
    generation: u64,
    key: NoticeKey,
    choice: Choice,
}

pub(super) struct HostNoticeState {
    key: Option<NoticeKey>,
    sharing_since: Option<Instant>,
    sender: mpsc::SyncSender<Event>,
    events: mpsc::Receiver<Event>,
}
impl Default for HostNoticeState {
    fn default() -> Self {
        let (sender, events) = mpsc::sync_channel(8);
        Self {
            key: None,
            sharing_since: None,
            sender,
            events,
        }
    }
}

fn request<'a>(snapshot: &'a Snapshot, id: &str) -> Option<&'a RemoteView> {
    snapshot
        .requests
        .data
        .as_deref()
        .into_iter()
        .flatten()
        .chain(snapshot.selected_request.data.as_deref())
        .find(|request| request.id == id)
}

fn current_notice(snapshot: &Snapshot) -> Option<Notice> {
    let local = &snapshot.installation.as_ref()?.device_id;
    let active = if let Some(host) = snapshot.browser_host.data.as_deref()
        && matches!(
            host.status,
            BrowserHostStatus::Establishing
                | BrowserHostStatus::Connected
                | BrowserHostStatus::Stopping
        ) {
        Some((
            NoticeKey {
                id: host.request_id.clone(),
                connection: host.connection_generation,
                browser: true,
            },
            match host.status {
                BrowserHostStatus::Connected => Phase::Sharing,
                BrowserHostStatus::Stopping => Phase::Stopping,
                _ if host.displays.approval_required => Phase::Screen,
                _ => Phase::Preparing,
            },
            host.path,
        ))
    } else if let Some(host) = snapshot.native_session.data.as_deref()
        && (host.host_view_authorized
            || request(snapshot, &host.request_id)
                .is_some_and(|request| &request.host_device_id == local))
        && matches!(
            host.status,
            NativeSessionStatus::Establishing
                | NativeSessionStatus::Connected
                | NativeSessionStatus::Stopping
        )
    {
        Some((
            NoticeKey {
                id: host.request_id.clone(),
                connection: host.connection_generation,
                browser: false,
            },
            match host.status {
                NativeSessionStatus::Connected => Phase::Sharing,
                NativeSessionStatus::Stopping => Phase::Stopping,
                _ => Phase::Preparing,
            },
            host.path,
        ))
    } else {
        None
    };
    let (key, phase, path) = active.or_else(|| {
        crate::remote::incoming_requests(snapshot)
            .next()
            .map(|request| {
                (
                    NoticeKey {
                        id: request.id.clone(),
                        connection: request.connection_generation,
                        browser: false,
                    },
                    Phase::Request,
                    None,
                )
            })
    })?;
    let request = request(snapshot, &key.id).cloned();
    let peer = request
        .as_ref()
        .and_then(|request| {
            snapshot
                .devices
                .data
                .as_deref()
                .into_iter()
                .flatten()
                .find(|device| device.device.id == request.controller_device_id)
                .map(|device| device.device.name.clone())
                .or_else(|| Some(request.controller_device_id.chars().take(8).collect()))
        })
        .unwrap_or_default();
    Some(Notice {
        key,
        phase,
        request,
        path,
        peer,
    })
}

impl DesktopApp {
    pub(super) fn update_host_notice(
        &mut self,
        context: &egui::Context,
        frame: &eframe::Frame,
        snapshot: &Snapshot,
    ) {
        let id = egui::ViewportId::from_hash_of("nestlink-host-notice");
        let Some(notice) = current_notice(snapshot) else {
            if self.host_notice.key.take().is_some() {
                context.send_viewport_cmd_to(id, egui::ViewportCommand::Close);
            }
            self.host_notice.sharing_since = None;
            return;
        };
        let fresh = self.host_notice.key.as_ref() != Some(&notice.key);
        if fresh {
            self.host_notice.key = Some(notice.key.clone());
            self.host_notice.sharing_since = None;
        }
        if notice.phase == Phase::Sharing && self.host_notice.sharing_since.is_none() {
            self.host_notice.sharing_since = Some(Instant::now());
        }
        let events: Vec<_> = self.host_notice.events.try_iter().collect();
        for event in events {
            if event.generation != snapshot.generation || event.key != notice.key {
                continue;
            }
            match event.choice {
                Choice::Review => {
                    self.hidden = false;
                    tray::restore(context);
                    self.screen = Screen::Remote;
                    self.remote.selected = Some(notice.key.id.clone());
                    self.action(
                        snapshot,
                        Action::InspectRemote {
                            request_id: notice.key.id.clone(),
                        },
                    );
                }
                Choice::Reject if notice.phase == Phase::Request => {
                    if let Some(request) = &notice.request {
                        self.action(
                            snapshot,
                            Action::ApproveRemote {
                                request_id: request.id.clone(),
                                expected_nonce: request.nonce.clone(),
                                expected_policy_revision: request.policy_revision,
                                choice: ApprovalChoice {
                                    approved: false,
                                    permissions: Vec::new(),
                                    paths: Vec::new(),
                                },
                            },
                        );
                    }
                }
                Choice::Disconnect
                    if notice.phase != Phase::Request && notice.phase != Phase::Stopping =>
                {
                    let loading = if notice.key.browser {
                        snapshot.browser_host.loading
                    } else {
                        snapshot.native_session.loading
                    };
                    if let Some(operation) = loading {
                        self.send(snapshot, Command::Cancel { operation });
                    } else {
                        self.action(
                            snapshot,
                            if notice.key.browser {
                                Action::StopBrowserHost {
                                    request_id: notice.key.id.clone(),
                                    connection_generation: notice.key.connection,
                                }
                            } else {
                                Action::StopNativeSession {
                                    request_id: notice.key.id.clone(),
                                    connection_generation: notice.key.connection,
                                }
                            },
                        );
                    }
                    self.set_message(
                        self.t(
                            "已请求断开，正在释放远控权限。",
                            "Disconnect requested. Releasing remote access.",
                        )
                        .into(),
                        MessageTone::Warning,
                    );
                }
                _ => {}
            }
        }
        let mut builder = egui::ViewportBuilder::default()
            .with_title(self.t("NestLink 共享提示", "NestLink sharing"))
            .with_inner_size([368., 320.])
            .with_resizable(false)
            .with_decorations(false)
            .with_close_button(false)
            .with_minimize_button(false)
            .with_maximize_button(false)
            .with_window_level(egui::WindowLevel::AlwaysOnTop)
            .with_taskbar(false)
            .with_active(false);
        if fresh {
            if let Some(window) = frame.winit_window()
                && let Some(monitor) = window.current_monitor()
            {
                let scale = window.scale_factor();
                let origin = monitor.position().to_logical::<f32>(scale);
                let size = monitor.size().to_logical::<f32>(scale);
                builder = builder.with_position([
                    origin.x + (size.width - 384.).max(16.),
                    origin.y + (size.height - 400.).max(16.),
                ]);
            } else {
                let size = context.input(|input| {
                    input
                        .viewport()
                        .monitor_size
                        .unwrap_or(egui::vec2(1200., 800.))
                });
                builder =
                    builder.with_position([(size.x - 384.).max(16.), (size.y - 400.).max(16.)]);
            }
        }
        let english = self.english;
        let elapsed = self
            .host_notice
            .sharing_since
            .map_or(0, |started| started.elapsed().as_secs());
        let generation = snapshot.generation;
        let sender = self.host_notice.sender.clone();
        let root = context.clone();
        context.show_viewport_deferred(id, builder, move |popup, _class| {
            if popup.input(|input| input.viewport().close_requested()) {
                popup.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            let choice = notice_ui(popup, &notice, english, elapsed);
            if let Some(choice) = choice {
                let _ = sender.try_send(Event {
                    generation,
                    key: notice.key.clone(),
                    choice,
                });
                root.request_repaint_of(egui::ViewportId::ROOT);
            }
            popup.request_repaint_after(Duration::from_secs(1));
        });
    }
}

fn notice_ui(
    context: &egui::Context,
    notice: &Notice,
    english: bool,
    elapsed: u64,
) -> Option<Choice> {
    let t = |zh, en| if english { en } else { zh };
    let mut choice = None;
    let mut parent = egui::Ui::new(
        context.clone(),
        egui::Id::new("host-notice-root"),
        egui::UiBuilder::new()
            .layer_id(egui::LayerId::background())
            .max_rect(context.content_rect()),
    );
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(context.global_style().visuals.panel_fill)
                .inner_margin(18.)
                .stroke(egui::Stroke::new(
                    1.,
                    context
                        .global_style()
                        .visuals
                        .widgets
                        .noninteractive
                        .bg_stroke
                        .color,
                )),
        )
        .show_inside(&mut parent, |ui| {
            ui.horizontal(|ui| {
                let (dot, _) = ui.allocate_exact_size(egui::vec2(10., 10.), egui::Sense::hover());
                ui.painter().circle_filled(
                    dot.center(),
                    4.,
                    if notice.phase == Phase::Sharing {
                        theme::color("#316B4A")
                    } else {
                        theme::color("#966313")
                    },
                );
                ui.strong(match notice.phase {
                    Phase::Request => t("有设备请求连接", "Incoming connection"),
                    Phase::Preparing => t("正在准备远程连接", "Preparing remote access"),
                    Phase::Screen => t("请选择共享屏幕", "Choose a screen to share"),
                    Phase::Sharing => t("此电脑正在共享", "This computer is being shared"),
                    Phase::Stopping => t("正在断开连接", "Disconnecting"),
                });
            });
            ui.add_space(12.);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(if notice.peer.is_empty() {
                        t("已授权的远端设备", "Authorized remote device")
                    } else {
                        &notice.peer
                    })
                    .size(19.)
                    .strong(),
                )
                .truncate(),
            );
            let permissions = notice
                .request
                .as_ref()
                .map(|request| widgets::permissions(&request.permissions, english))
                .unwrap_or_else(|| {
                    t(
                        "权限以本机批准范围为准",
                        "Access follows your local approval",
                    )
                    .into()
                });
            ui.label(permissions);
            ui.add_space(4.);
            ui.small(match notice.phase {
                Phase::Request => t(
                    "查看权限后批准，也可以直接拒绝。",
                    "Review the requested access or deny it.",
                ),
                Phase::Screen => t(
                    "批准屏幕后才会发送画面。",
                    "Video starts only after you approve a screen.",
                ),
                _ => t(
                    "可随时断开，主窗口收起后提示仍保留。",
                    "Disconnect at any time, even with the main window hidden.",
                ),
            });
            if notice.phase == Phase::Sharing {
                let path = match notice.path {
                    Some(1) => t("直连", "Direct"),
                    Some(2) => t("中继", "Relay"),
                    _ => t("已连接", "Connected"),
                };
                ui.small(format!(
                    "{path}    {:02}:{:02}:{:02}",
                    elapsed / 3600,
                    elapsed / 60 % 60,
                    elapsed % 60
                ));
            }
            ui.add_space(12.);
            ui.horizontal(|ui| {
                if ui
                    .button(if notice.phase == Phase::Request {
                        t("查看并批准", "Review access")
                    } else {
                        t("查看会话", "Show session")
                    })
                    .clicked()
                {
                    choice = Some(Choice::Review);
                }
                let label = if notice.phase == Phase::Request {
                    t("拒绝", "Deny")
                } else {
                    t("断开连接", "Disconnect")
                };
                if ui
                    .add_enabled(
                        notice.phase != Phase::Stopping,
                        egui::Button::new(egui::RichText::new(label).color(egui::Color32::WHITE))
                            .fill(theme::color("#B42336")),
                    )
                    .on_hover_text(t("立即停止此设备的访问", "Stop this device's access"))
                    .clicked()
                {
                    choice = Some(if notice.phase == Phase::Request {
                        Choice::Reject
                    } else {
                        Choice::Disconnect
                    });
                }
            });
        });
    choice
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_core::{BrowserHostView, Section};
    use std::sync::Arc;

    #[test]
    fn browser_host_notice_survives_without_request_metadata_and_disappears_after_stop() {
        let mut snapshot = Snapshot {
            installation: Some(nestlink_app_core::InstallationView {
                device_id: "local".into(),
                public_key_sha256: [0; 32],
            }),
            browser_host: Section {
                data: Some(Arc::new(BrowserHostView {
                    request_id: "session".into(),
                    connection_generation: 2,
                    lease_sequence: 1,
                    status: BrowserHostStatus::Connected,
                    host_view_authorized: true,
                    binding: None,
                    displays: Default::default(),
                    data: Default::default(),
                    path: Some(1),
                    stop_reason: None,
                    stop_effects: None,
                    cleanup: None,
                    failure: None,
                })),
                ..Default::default()
            },
            ..Default::default()
        };
        let notice = current_notice(&snapshot).unwrap_or_else(|| panic!("host notice missing"));
        assert!(notice.phase == Phase::Sharing && notice.key.browser);
        let mut host = snapshot
            .browser_host
            .data
            .as_deref()
            .cloned()
            .unwrap_or_else(|| panic!("host missing"));
        host.status = BrowserHostStatus::Stopped;
        snapshot.browser_host.data = Some(Arc::new(host));
        assert!(current_notice(&snapshot).is_none());
    }
}
