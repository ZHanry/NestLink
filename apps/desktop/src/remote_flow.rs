//! The controller's explicit Connect action continues through approval and proof.
use crate::{
    DesktopApp, RemoteViewportTarget,
    icons::{self, Icon},
    widgets,
};
use eframe::egui;
use nestlink_app_core::{
    Action, Authentication, NativeSessionStatus, OperationKind, OperationResult, OperationStatus,
    Page, PublicOutput, RemoteAccess, Snapshot,
};
use nestlink_app_ipc::wire::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Requesting,
    Approval,
    Permit,
    Connecting,
    Connected,
    Ended,
    Failed,
}

pub(crate) struct ConnectionFlow {
    stage: Stage,
    request: Option<String>,
    submission: Option<u64>,
    deadline: Instant,
    next_poll: Instant,
    error: Option<String>,
    opened: bool,
}
impl ConnectionFlow {
    fn active(&self) -> bool {
        !matches!(self.stage, Stage::Failed | Stage::Connected | Stage::Ended)
    }
    pub(super) fn is_busy(&self) -> bool {
        self.active()
    }
}

impl DesktopApp {
    pub(crate) fn remote_flow_rejected(&mut self, submission: Option<u64>, message: &str) {
        if let Some(flow) = &mut self.remote.flow
            && submission.is_some()
            && flow.submission == submission
        {
            flow.submission = None;
            flow.stage = Stage::Failed;
            flow.error = Some(message.into());
        }
    }

    pub(crate) fn connect_remote_device(&mut self, snapshot: &Snapshot) {
        if self
            .remote
            .flow
            .as_ref()
            .is_some_and(ConnectionFlow::active)
        {
            return;
        }
        let Some(host_device_id) = self.remote.host_device_id.clone() else {
            return;
        };
        let submission = self.bridge.submit_tracked(
            snapshot.generation,
            Command::Submit {
                action: Action::RequestRemote {
                    host_device_id,
                    permissions: super::remote::selected(&self.remote.permissions),
                    path_mode: self.remote.path.clone(),
                    access: if self.remote.trusted {
                        RemoteAccess::TrustedDevice
                    } else {
                        RemoteAccess::LocalApproval
                    },
                },
            },
        );
        self.remote.flow = Some(ConnectionFlow {
            stage: if submission.is_some() {
                Stage::Requesting
            } else {
                Stage::Failed
            },
            request: None,
            submission,
            deadline: Instant::now() + Duration::from_secs(120),
            next_poll: Instant::now(),
            error: submission.is_none().then(|| {
                self.t(
                    "请求未送出，请检查本机服务后重试。",
                    "Request was not sent. Check the local service and retry.",
                )
                .into()
            }),
            opened: false,
        });
    }

    pub(crate) fn remote_flow_completed(
        &mut self,
        submission: Option<u64>,
        result: &OperationResult,
    ) -> bool {
        let Some(flow) = &mut self.remote.flow else {
            return false;
        };
        if submission.is_none() || flow.submission != submission {
            return false;
        }
        flow.submission = None;
        if result.status != OperationStatus::Succeeded {
            flow.stage = Stage::Failed;
            flow.error = Some(widgets::operation_message(result, self.english));
            return true;
        }
        match result.kind {
            OperationKind::RequestRemote => {
                if let PublicOutput::Created { id } = &result.output {
                    flow.request = Some(id.clone());
                    self.remote.selected = Some(id.clone());
                    flow.stage = Stage::Approval;
                } else {
                    flow.stage = Stage::Failed;
                }
            }
            OperationKind::IssueRemotePermit => flow.stage = Stage::Approval,
            OperationKind::StartNativeSession => flow.stage = Stage::Connected,
            _ => {}
        }
        true
    }

    pub(crate) fn advance_remote_flow(&mut self, snapshot: &Snapshot) {
        if !self.connected || snapshot.authentication != Authentication::SignedIn {
            return;
        }
        let now = Instant::now();
        // Incoming requests continue to refresh while the window is in the tray.
        if now >= self.remote.next_inbox_poll && snapshot.requests.loading.is_none() {
            self.remote.next_inbox_poll = now + Duration::from_secs(3);
            self.load(snapshot, Page::Requests);
        }
        let Some(flow) = &mut self.remote.flow else {
            return;
        };
        if flow.stage == Stage::Connected
            && let Some(session) = snapshot
                .native_session
                .data
                .as_ref()
                .filter(|session| Some(session.request_id.as_str()) == flow.request.as_deref())
            && matches!(
                session.status,
                NativeSessionStatus::Stopped | NativeSessionStatus::Failed
            )
        {
            flow.stage = if session.status == NativeSessionStatus::Failed {
                Stage::Failed
            } else {
                Stage::Ended
            };
            flow.error = session
                .failure
                .as_ref()
                .map(|error| widgets::failure(error, self.english));
        }
        if flow.stage == Stage::Connected
            && !flow.opened
            && let Some(session) = snapshot.native_session.data.as_ref().filter(|session| {
                Some(session.request_id.as_str()) == flow.request.as_deref()
                    && session.status == NativeSessionStatus::Connected
            })
        {
            flow.opened = true;
            let target = RemoteViewportTarget {
                request_id: session.request_id.clone(),
                connection_generation: session.connection_generation,
            };
            self.open_remote_viewport(snapshot, target);
            return;
        }
        if !flow.active() {
            return;
        }
        if now >= flow.deadline {
            flow.stage = Stage::Failed;
            flow.error = Some(if self.english { "Connection timed out. Keep the host signed in and check its relay configuration, then request access again." } else { "连接超时。请确认被控端已登录、服务器中继可用，再重新申请连接。" }.into());
            let request = flow.request.clone();
            if let Some(operation) = snapshot.native_session.loading {
                self.send(snapshot, Command::Cancel { operation });
            }
            if let Some(request_id) = request {
                self.action(snapshot, Action::RevokeRemote { request_id });
            }
            return;
        }
        if flow.submission.is_some() {
            return;
        }
        let Some(id) = flow.request.clone() else {
            return;
        };
        let current = snapshot
            .selected_request
            .data
            .as_deref()
            .filter(|request| request.id == id);
        let action = match current {
            Some(request)
                if matches!(request.status.as_str(), "denied" | "revoked" | "expired") =>
            {
                flow.stage = Stage::Failed;
                flow.error = Some(
                    if self.english {
                        "Access was denied, revoked or expired. Request access again."
                    } else {
                        "访问已拒绝、撤销或过期，请重新申请。"
                    }
                    .into(),
                );
                None
            }
            Some(request) if request.status == "approved" && request.lease_sequence == 0 => {
                flow.stage = Stage::Permit;
                Some(Action::IssueRemotePermit { request_id: id })
            }
            Some(request) if request.status == "approved" && request.lease_sequence > 0 => {
                flow.stage = Stage::Connecting;
                Some(Action::StartNativeSession { request_id: id })
            }
            _ if now >= flow.next_poll && snapshot.selected_request.loading.is_none() => {
                flow.next_poll = now + Duration::from_secs(1);
                Some(Action::InspectRemote { request_id: id })
            }
            _ => None,
        };
        if let Some(action) = action {
            flow.submission = self
                .bridge
                .submit_tracked(snapshot.generation, Command::Submit { action });
            if flow.submission.is_none() {
                flow.stage = Stage::Failed;
                flow.error = Some(
                    if self.english {
                        "Connection could not continue. Check the local service and retry."
                    } else {
                        "连接操作未送出，请检查本机服务并重试。"
                    }
                    .into(),
                );
            }
        }
    }

    pub(crate) fn connection_can_cancel(&self) -> bool {
        self.remote
            .flow
            .as_ref()
            .is_some_and(|flow| flow.active() && flow.request.is_some())
    }

    pub(crate) fn cancel_remote_connection(&mut self, snapshot: &Snapshot) {
        if let Some(request_id) = self
            .remote
            .flow
            .as_ref()
            .and_then(|flow| flow.request.clone())
        {
            if let Some(operation) = snapshot.native_session.loading {
                self.send(snapshot, Command::Cancel { operation });
            }
            self.action(snapshot, Action::RevokeRemote { request_id });
            self.remote.flow = None;
        }
    }

    pub(crate) fn connection_progress(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(flow) = &self.remote.flow else {
            return;
        };
        let stage = flow.stage;
        let active = flow.active();
        let error = flow.error.clone();
        ui.add_space(12.);
        egui::Frame::group(ui.style()).inner_margin(18).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if active { ui.spinner(); }
                ui.strong(self.t(match stage {
                    Stage::Requesting => "正在申请访问", Stage::Approval => "等待被控端批准", Stage::Permit => "正在获取会话许可",
                    Stage::Connecting => "正在连接设备", Stage::Connected => "会话已建立", Stage::Ended => "会话已结束", Stage::Failed => "连接未完成",
                }, match stage {
                    Stage::Requesting => "Requesting access", Stage::Approval => "Waiting for host approval", Stage::Permit => "Authorizing session",
                    Stage::Connecting => "Connecting to device", Stage::Connected => "Session established", Stage::Ended => "Session ended", Stage::Failed => "Connection incomplete",
                }));
            });
            ui.horizontal_wrapped(|ui| {
                for (index, (zh, en)) in [("申请访问", "Request"), ("授权", "Approval"), ("建立连接", "Connect"), ("远程画面", "Screen")].into_iter().enumerate() {
                    let reached = match stage { Stage::Requesting => 0, Stage::Approval | Stage::Permit => 1, Stage::Connecting => 2, Stage::Connected | Stage::Ended => 3, Stage::Failed => 0 };
                    ui.label(egui::RichText::new(self.t(zh, en)).color(if index <= reached { ui.visuals().hyperlink_color } else { ui.visuals().weak_text_color() }));
                    if index < 3 { ui.small("/"); }
                }
            });
            if stage == Stage::Approval {
                ui.small(self.t("请在被控端批准，或在连接详情中使用该设备已设置的访问密码。获准后自动连接。", "Approve on the host or use its configured access password in connection details. Connection continues automatically."));
            }
            if let Some(error) = error { ui.colored_label(ui.visuals().error_fg_color, error); }
            if stage == Stage::Connected && snapshot.native_session.data.as_ref().is_some_and(|session| session.status == NativeSessionStatus::Connected && !session.host_view_authorized)
                && icons::button(ui, Icon::Monitor, self.t("打开远程画面", "Open remote screen")).clicked()
                && let Some(session) = snapshot.native_session.data.as_ref()
            {
                self.open_remote_viewport(snapshot, RemoteViewportTarget { request_id: session.request_id.clone(), connection_generation: session.connection_generation });
            }
        });
    }
}
