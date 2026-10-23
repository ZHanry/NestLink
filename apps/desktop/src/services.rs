use crate::picker::Selector;
use crate::{DesktopApp, widgets};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use eframe::egui;
use nestlink_app_core::{
    Action, LocalHttpsBackendConfig, LocalServiceHostPreview, LocalServiceHostStatus, Page,
    Snapshot,
};
use nestlink_app_ipc::wire::Command;
use nestlink_platform_files::selection::SelectionKind;
use nestlink_protocol::api::*;
use std::{fs::File, io::Read, path::Path};

const MAX_CA_BUNDLE_FILE_BYTES: usize = 192 * 1024;

#[derive(Default)]
pub(crate) struct ServicePanel {
    generation: u64,
    draft: Option<Draft>,
    draft_baseline: Option<String>,
    discard_confirmation: bool,
    error: Option<String>,
    revoke: Option<ServiceView>,
    local_target: Option<LocalTargetDraft>,
    local_preview: Option<LocalServiceHostPreview>,
    preview_created_at: Option<std::time::Instant>,
    preview_backend_tls: Option<LocalHttpsBackendConfig>,
    preview_submission: Option<u64>,
    stop_submission: Option<u64>,
    status_message: Option<String>,
    ca_selector: Option<Selector>,
}

struct LocalTargetDraft {
    service_id: String,
    protocol: String,
    address: String,
    https_server_name: String,
    https_ca_certificates_der: Vec<Vec<u8>>,
    https_ca_file_name: Option<String>,
    tls_error: Option<String>,
}
impl LocalTargetDraft {
    fn https_backend(&self) -> Result<Option<LocalHttpsBackendConfig>, ()> {
        if self.protocol != "https" {
            return Ok(None);
        }
        if self.tls_error.is_some() {
            return Err(());
        }
        let config = LocalHttpsBackendConfig {
            server_name: self.https_server_name.clone(),
            ca_certificates_der: self.https_ca_certificates_der.clone(),
        };
        if config.server_name.is_empty()
            || config.server_name.len() > 253
            || config.server_name.trim() != config.server_name
            || config.server_name.chars().any(char::is_control)
            || !(1..=8).contains(&config.ca_certificates_der.len())
            || config
                .ca_certificates_der
                .iter()
                .any(|certificate| !(1..=16_384).contains(&certificate.len()))
        {
            return Err(());
        }
        Ok(Some(config))
    }
}

struct Draft {
    id: String,
    revision: Option<u64>,
    name: String,
    host: String,
    edge: String,
    protocol: usize,
    ingress: String,
    sources: String,
    limits: ServiceLimits,
    saved_definition: Option<ServiceDefinition>,
}
impl Draft {
    fn fingerprint(&self) -> String {
        format!(
            "{:?}",
            (
                &self.name,
                &self.host,
                &self.edge,
                self.protocol,
                &self.ingress,
                &self.sources,
                self.limits
            )
        )
    }

    fn new(snapshot: &Snapshot) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            revision: None,
            name: String::new(),
            host: snapshot
                .installation
                .as_ref()
                .map(|v| v.device_id.clone())
                .unwrap_or_default(),
            edge: String::new(),
            protocol: 2,
            ingress: "29100".into(),
            sources: String::new(),
            limits: ServiceLimits {
                maximum_connections: 8,
                bytes_per_second: 1_048_576,
                maximum_bytes: 1_073_741_824,
                idle_timeout_seconds: 60,
            },
            saved_definition: None,
        }
    }
    fn edit(view: &ServiceView) -> Self {
        let (protocol, ingress) = match &view.definition.requested_ingress {
            ServiceIngress::Http { hostname } => (0, hostname.clone()),
            ServiceIngress::Https { hostname } => (1, hostname.clone()),
            ServiceIngress::Tcp { port } => (2, port.to_string()),
            ServiceIngress::Udp { port } => (3, port.to_string()),
        };
        Self {
            id: view.id.clone(),
            revision: Some(view.revision),
            name: view.definition.name.clone(),
            host: view.definition.host_device_id.clone(),
            edge: view.definition.edge_node_id.clone(),
            protocol,
            ingress,
            sources: view
                .definition
                .allowed_sources
                .iter()
                .map(|v| format!("{}/{}", v.address, v.prefix))
                .collect::<Vec<_>>()
                .join("\n"),
            limits: view.definition.limits,
            saved_definition: Some(view.definition.clone()),
        }
    }
    fn definition(&self) -> Result<ServiceDefinition, ()> {
        let requested_ingress = match self.protocol {
            0 => ServiceIngress::Http {
                hostname: self.ingress.clone(),
            },
            1 => ServiceIngress::Https {
                hostname: self.ingress.clone(),
            },
            2 => ServiceIngress::Tcp {
                port: self.ingress.parse().map_err(|_| ())?,
            },
            3 => ServiceIngress::Udp {
                port: self.ingress.parse().map_err(|_| ())?,
            },
            _ => return Err(()),
        };
        let mut allowed_sources = Vec::new();
        for line in self
            .sources
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if allowed_sources.len() == 32 {
                return Err(());
            }
            let (address, prefix) = line.split_once('/').ok_or(())?;
            allowed_sources.push(ServiceSourceNetwork {
                address: address.into(),
                prefix: prefix.parse().map_err(|_| ())?,
            });
        }
        let definition = ServiceDefinition {
            name: self.name.clone(),
            host_device_id: self.host.clone(),
            edge_node_id: self.edge.clone(),
            requested_ingress,
            allowed_sources,
            limits: self.limits,
        };
        definition.validate().map_err(|_| ())?;
        Ok(definition)
    }
    fn reconcile(&mut self, snapshot: &Snapshot) {
        let Ok(definition) = self.definition() else {
            return;
        };
        let selected = snapshot.selected_service.data.iter().map(AsRef::as_ref);
        let page = snapshot
            .services
            .data
            .iter()
            .flat_map(|page| page.services.iter());
        // A committed create/update may precede a failed list refresh. Adopt
        // only the same record and exact definition; concurrent edits must
        // still surface their revision conflict instead of overwriting input.
        if let Some(view) = selected
            .chain(page)
            .filter(|view| {
                view.id == self.id
                    && view.approval != ServiceApprovalState::Revoked
                    && self
                        .revision
                        .is_none_or(|revision| view.revision >= revision)
                    && view.definition == definition
            })
            .max_by_key(|view| view.revision)
        {
            self.revision = Some(view.revision);
            self.saved_definition = Some(view.definition.clone());
        }
    }
    fn unchanged(&self) -> bool {
        self.definition().ok().as_ref() == self.saved_definition.as_ref()
            && self.saved_definition.is_some()
    }
    fn action(&self) -> Result<Action, ()> {
        let definition = self.definition()?;
        Ok(match self.revision {
            Some(revision) => Action::UpdateService {
                service_id: self.id.clone(),
                update: ServiceUpdate {
                    expected_revision: revision,
                    definition,
                },
            },
            None => Action::CreateService {
                create: ServiceCreate {
                    id: self.id.clone(),
                    definition,
                },
            },
        })
    }
}

impl DesktopApp {
    pub(crate) fn services_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let mut panel = std::mem::take(&mut self.service_panel);
        let command = panel.ui(ui, snapshot, self.english);
        self.service_panel = panel;
        if let Some(command) = command {
            let requested_backend_tls = match &command {
                Command::PreviewLocalServiceHost { backend_tls, .. } => backend_tls.clone(),
                _ => None,
            };
            let kind = match &command {
                Command::PreviewLocalServiceHost { .. } => Some(TrackedCommand::Preview),
                Command::StopLocalServiceHost => Some(TrackedCommand::Stop),
                _ => None,
            };
            if let Some(kind) = kind {
                if self.connected
                    && let Some(submission_id) =
                        self.bridge.submit_tracked(snapshot.generation, command)
                {
                    self.service_panel
                        .track_submission(kind, submission_id, requested_backend_tls);
                } else {
                    self.message = Some(if self.english {
                        "The service command was not sent. Check the daemon connection and try again.".into()
                    } else {
                        "本机服务操作未送出，请检查守护进程连接后重试。".into()
                    });
                }
            } else {
                self.send(snapshot, command);
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TrackedCommand {
    Preview,
    Stop,
}

impl ServicePanel {
    pub(crate) fn track_submission(
        &mut self,
        kind: TrackedCommand,
        submission_id: u64,
        backend_tls: Option<LocalHttpsBackendConfig>,
    ) {
        match kind {
            TrackedCommand::Preview => {
                self.preview_submission = Some(submission_id);
                self.local_preview = None;
                self.preview_created_at = None;
                self.preview_backend_tls = backend_tls;
                self.status_message = None;
            }
            TrackedCommand::Stop => {
                self.stop_submission = Some(submission_id);
                self.status_message = None;
            }
        }
    }

    pub(crate) fn preview_reply(
        &mut self,
        submission_id: u64,
        preview: LocalServiceHostPreview,
        english: bool,
    ) {
        if self.preview_submission == Some(submission_id) {
            self.preview_submission = None;
            let tls_matches = match &self.preview_backend_tls {
                Some(config) => {
                    preview.backend_tls_server_name.as_deref() == Some(config.server_name.as_str())
                        && preview
                            .backend_tls_sha256
                            .as_deref()
                            .is_some_and(valid_fingerprint)
                }
                None => {
                    preview.backend_tls_server_name.is_none()
                        && preview.backend_tls_sha256.is_none()
                }
            };
            if tls_matches {
                self.local_preview = Some(preview);
                self.preview_created_at = Some(std::time::Instant::now());
                self.status_message = None;
            } else {
                self.local_preview = None;
                self.preview_created_at = None;
                self.preview_backend_tls = None;
                self.status_message = Some(if english {
                    "The local HTTPS trust preview does not match the selected settings. Preview again.".into()
                } else {
                    "本机 HTTPS 信任预览与所选配置不匹配，请重新预览。".into()
                });
            }
        }
    }

    pub(crate) fn stop_reply(&mut self, submission_id: u64, accepted: bool, english: bool) {
        if self.stop_submission == Some(submission_id) {
            self.stop_submission = None;
            self.status_message = Some(if accepted {
                if english {
                    "Stop requested. The daemon will report Stopped only after cleanup finishes."
                        .into()
                } else {
                    "已请求停止；守护进程完成清理后才会显示“已停止”。".into()
                }
            } else if english {
                "There is no local service host to stop.".into()
            } else {
                "当前没有运行中的本机服务可停止。".into()
            });
        }
    }

    pub(crate) fn rejected(&mut self, submission_id: u64, english: bool) -> bool {
        if self.preview_submission == Some(submission_id) {
            self.preview_submission = None;
            self.local_preview = None;
            self.preview_created_at = None;
            self.preview_backend_tls = None;
            self.status_message = Some(if english {
                "The local target preview expired or was rejected. Check service state and preview again.".into()
            } else {
                "本机目标预览已失效，请检查服务状态后重试。".into()
            });
            true
        } else if self.stop_submission == Some(submission_id) {
            self.stop_submission = None;
            self.status_message = Some(if english {
                "The stop request was rejected. Check daemon state.".into()
            } else {
                "停止请求未被接受，请检查守护进程状态。".into()
            });
            true
        } else {
            false
        }
    }

    pub(crate) fn disconnected(&mut self, english: bool) {
        self.preview_submission = None;
        self.stop_submission = None;
        self.local_preview = None;
        self.preview_created_at = None;
        self.preview_backend_tls = None;
        self.ca_selector = None;
        self.status_message = Some(if english {
            "The daemon disconnected; local target status cannot be confirmed.".into()
        } else {
            "守护进程断开，本机目标状态无法确认。".into()
        });
    }

    fn invalidate_preview(&mut self) {
        self.preview_submission = None;
        self.local_preview = None;
        self.preview_created_at = None;
        self.preview_backend_tls = None;
    }

    fn poll_ca_selector(&mut self, english: bool) {
        let Some(result) = self.ca_selector.as_mut().and_then(Selector::poll) else {
            return;
        };
        self.ca_selector = None;
        match result {
            Ok(Some(path)) => match read_ca_bundle(&path) {
                Ok(certificates) => {
                    let file_name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .filter(|name| !name.is_empty())
                        .unwrap_or(if english { "CA bundle" } else { "CA 证书" })
                        .to_owned();
                    if let Some(target) = &mut self.local_target {
                        target.https_ca_certificates_der = certificates;
                        target.https_ca_file_name = Some(file_name);
                        target.tls_error = None;
                    }
                    self.invalidate_preview();
                }
                Err(()) => {
                    if let Some(target) = &mut self.local_target {
                        target.tls_error = Some(if english {
                            "Choose a DER certificate or a PEM bundle with 1–8 certificates; each certificate must be at most 16 KiB and the file at most 192 KiB.".into()
                        } else {
                            "请选择 DER 证书或含 1–8 张证书的 PEM 文件；每张不超过 16 KiB，文件不超过 192 KiB。".into()
                        });
                    }
                    self.invalidate_preview();
                }
            },
            Ok(None) => {}
            Err(_) => {
                if let Some(target) = &mut self.local_target {
                    target.tls_error = Some(if english {
                        "The certificate file could not be read.".into()
                    } else {
                        "无法读取证书文件。".into()
                    });
                }
                self.invalidate_preview();
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot, english: bool) -> Option<Command> {
        if self.generation != snapshot.generation {
            *self = Self {
                generation: snapshot.generation,
                ..Self::default()
            };
        }
        if let Some(draft) = &mut self.draft {
            draft.reconcile(snapshot);
        }
        self.poll_ca_selector(english);
        if self.local_preview.as_ref().is_some_and(|preview| {
            let target_matches = self.local_target.as_ref().is_some_and(|target| {
                target.service_id == preview.service.id
                    && target.protocol == preview.protocol
                    && target.address == preview.address
            });
            let tls_matches = self
                .local_target
                .as_ref()
                .and_then(|target| target.https_backend().ok())
                .is_some_and(|tls| {
                    tls == self.preview_backend_tls
                        && match &tls {
                            Some(config) => {
                                preview.backend_tls_server_name.as_deref()
                                    == Some(config.server_name.as_str())
                                    && preview
                                        .backend_tls_sha256
                                        .as_deref()
                                        .is_some_and(valid_fingerprint)
                            }
                            None => {
                                preview.backend_tls_server_name.is_none()
                                    && preview.backend_tls_sha256.is_none()
                            }
                        }
                });
            let selected_matches = snapshot
                .selected_service
                .data
                .as_ref()
                .is_some_and(|service| {
                    service.id == preview.service.id
                        && service.revision == preview.service.revision
                        && service.definition_sha256 == preview.service.definition_sha256
                });
            !target_matches
                || !tls_matches
                || !selected_matches
                || self.preview_created_at.is_none_or(|created| {
                    created.elapsed() >= std::time::Duration::from_millis(preview.lifetime_ms)
                })
        }) {
            self.local_preview = None;
            self.preview_created_at = None;
            self.preview_backend_tls = None;
        }
        let t = |zh, en| if english { en } else { zh };
        let mut command = None;
        let busy =
            snapshot.services.loading.is_some() || snapshot.selected_service.loading.is_some();
        ui.horizontal(|ui| {
            ui.heading(t("隧道入口", "Tunnel entries"));
            if ui
                .add_enabled(!busy, egui::Button::new(t("刷新", "Refresh")))
                .clicked()
            {
                command = Some(Command::Submit {
                    action: Action::Load {
                        page: Page::Services,
                    },
                });
            }
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(
                        egui::RichText::new(t("新建隧道", "New tunnel"))
                            .color(ui.visuals().selection.stroke.color),
                    )
                    .fill(ui.visuals().selection.bg_fill),
                )
                .clicked()
            {
                self.draft_baseline = Some(Draft::new(snapshot).fingerprint());
                self.draft = Some(Draft::new(snapshot));
                self.error = None;
            }
        });
        ui.label(t(
            "把内网服务发布到访问入口。支持 TCP、UDP、HTTP 和 HTTPS。",
            "Publish an intranet service through an access entry. TCP, UDP, HTTP and HTTPS are supported.",
        ));
        widgets::section(ui, &snapshot.services, english);
        widgets::section(ui, &snapshot.selected_service, english);
        if let Some(page) = &snapshot.services.data {
            if page.services.is_empty() {
                ui.add_space(16.);
                egui::Frame::new().fill(ui.visuals().window_fill).inner_margin(24).corner_radius(8)
                    .stroke(ui.visuals().widgets.noninteractive.bg_stroke).show(ui, |ui| {
                        ui.heading(t("创建第一个内网入口", "Create your first tunnel"));
                        ui.label(t("先选择 Windows 主机、协议和访问入口，再在目标电脑上确认本机服务地址。", "Choose a Windows host, protocol and access entry, then confirm the local service address on the host."));
                        ui.small(t("只有节点确认发布后，才显示入口已发布。", "An entry is shown as published only after the node confirms it."));
                    });
            } else {
                egui::ScrollArea::horizontal()
                    .id_salt("tunnel-directory-scroll")
                    .show(ui, |ui| {
                        ui.set_min_width(560.);
                        egui::Grid::new("service-directory")
                            .min_col_width(72.)
                            .max_col_width(220.)
                            .num_columns(4)
                            .striped(true)
                            .spacing([20., 14.])
                            .show(ui, |ui| {
                                for label in [
                                    t("隧道 / 目标设备", "Tunnel / host"),
                                    t("访问入口", "Access entry"),
                                    t("状态", "Status"),
                                    t("操作", "Actions"),
                                ] {
                                    ui.strong(label);
                                }
                                ui.end_row();
                                for view in &page.services {
                                    ui.vertical(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&view.definition.name).strong(),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&view.definition.name);
                                        let host = snapshot
                                            .devices
                                            .data
                                            .as_deref()
                                            .into_iter()
                                            .flatten()
                                            .find(|device| {
                                                device.device.id == view.definition.host_device_id
                                            })
                                            .map(|device| device.device.name.as_str())
                                            .unwrap_or(&view.definition.host_device_id);
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(host)
                                                    .small()
                                                    .color(ui.visuals().weak_text_color()),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(host);
                                    });
                                    ui.label(ingress_label(&view.definition.requested_ingress));
                                    ui.vertical(|ui| {
                                        ui.label(match view.publication {
                                            ServicePublicationStatus::NotPublished => {
                                                t("未发布", "Not published")
                                            }
                                            ServicePublicationStatus::Published => {
                                                t("已发布", "Published")
                                            }
                                            ServicePublicationStatus::Stopping => {
                                                t("正在停止", "Stopping")
                                            }
                                        });
                                        ui.small(match view.approval {
                                            ServiceApprovalState::Pending => t(
                                                "等待本机目标批准",
                                                "Awaiting local target approval",
                                            ),
                                            ServiceApprovalState::ApprovedTarget => {
                                                t("目标已批准", "Target approved")
                                            }
                                            ServiceApprovalState::Invalidated => {
                                                t("目标批准已失效", "Target approval invalidated")
                                            }
                                            ServiceApprovalState::Revoked => t("已撤销", "Revoked"),
                                        });
                                    });
                                    ui.push_id(&view.id, |ui| {
                                        ui.menu_button(t("操作", "Actions"), |ui| {
                                            let live = !busy
                                                && view.approval != ServiceApprovalState::Revoked;
                                            if ui
                                                .add_enabled(
                                                    live,
                                                    egui::Button::new(t("编辑", "Edit")),
                                                )
                                                .clicked()
                                            {
                                                self.draft_baseline =
                                                    Some(Draft::edit(view).fingerprint());
                                                self.draft = Some(Draft::edit(view));
                                                self.error = None;
                                                ui.close();
                                            }
                                            if ui
                                                .add_enabled(
                                                    live,
                                                    egui::Button::new(t("撤销", "Revoke")),
                                                )
                                                .clicked()
                                            {
                                                self.revoke = Some(view.clone());
                                                ui.close();
                                            }
                                            let local_device = snapshot
                                                .installation
                                                .as_ref()
                                                .is_some_and(|installation| {
                                                    installation.device_id
                                                        == view.definition.host_device_id
                                                });
                                            if local_device
                                                && matches!(
                                                    &view.definition.requested_ingress,
                                                    ServiceIngress::Tcp { .. }
                                                        | ServiceIngress::Udp { .. }
                                                        | ServiceIngress::Http { .. }
                                                        | ServiceIngress::Https { .. }
                                                )
                                                && ui
                                                    .add_enabled(
                                                        live,
                                                        egui::Button::new(t(
                                                            "本机批准…",
                                                            "Approve on this device…",
                                                        )),
                                                    )
                                                    .clicked()
                                            {
                                                let (protocol, address) =
                                                    match &view.definition.requested_ingress {
                                                        ServiceIngress::Tcp { port } => {
                                                            ("tcp", format!("127.0.0.1:{port}"))
                                                        }
                                                        ServiceIngress::Udp { port } => {
                                                            ("udp", format!("127.0.0.1:{port}"))
                                                        }
                                                        ServiceIngress::Http { .. } => {
                                                            ("http", "127.0.0.1:80".into())
                                                        }
                                                        ServiceIngress::Https { .. } => {
                                                            ("https", "127.0.0.1:443".into())
                                                        }
                                                    };
                                                self.local_target = Some(LocalTargetDraft {
                                                    service_id: view.id.clone(),
                                                    protocol: protocol.into(),
                                                    address,
                                                    https_server_name: String::new(),
                                                    https_ca_certificates_der: Vec::new(),
                                                    https_ca_file_name: None,
                                                    tls_error: None,
                                                });
                                                self.invalidate_preview();
                                                self.status_message = None;
                                                ui.close();
                                                command = Some(Command::Submit {
                                                    action: Action::InspectService {
                                                        service_id: view.id.clone(),
                                                    },
                                                });
                                            }
                                        });
                                    });
                                    ui.end_row();
                                }
                            });
                    });
                ui.add_space(12.);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new(t("第一页", "First page")))
                        .clicked()
                    {
                        command = Some(Command::Submit {
                            action: Action::Load {
                                page: Page::Services,
                            },
                        });
                    }
                    if ui
                        .add_enabled(
                            !busy && page.more,
                            egui::Button::new(t("下一页", "Next page")),
                        )
                        .clicked()
                    {
                        command = Some(Command::Submit {
                            action: Action::LoadServicesPage {
                                after_id: page.next_id.clone(),
                                limit: 50,
                            },
                        });
                    }
                });
            }
        }
        if let Some(host) = &snapshot.local_service_host {
            ui.add_space(12.);
            ui.separator();
            ui.heading(t("本机隧道运行状态", "Local tunnel runtime"));
            ui.label(format!(
                "{} · {} · {}:{} · {} {}",
                host.service_name,
                host.service_id,
                host.protocol,
                host.address,
                t("服务版本", "service revision"),
                host.approved_revision.map_or_else(
                    || host.approved_from_revision.to_string(),
                    |revision| revision.to_string()
                ),
            ));
            ui.label(match host.status {
                LocalServiceHostStatus::Starting => t("正在启动", "Starting"),
                LocalServiceHostStatus::Running => t("运行中", "Running"),
                LocalServiceHostStatus::Stopping => {
                    t("正在停止并等待清理", "Stopping; waiting for cleanup")
                }
                LocalServiceHostStatus::Stopped => t("本机已停止", "Stopped locally"),
                LocalServiceHostStatus::Failed => t(
                    "停止或启动失败，请检查清理状态",
                    "Start or cleanup failed; inspect cleanup status",
                ),
            });
            if host.status == LocalServiceHostStatus::Stopped {
                ui.small(t(
                    "本机连接已清理，公网入口的移除状态仍由节点确认。",
                    "Local connections are closed; the node confirms public entry removal separately.",
                ));
            }
            if host.cleanup_failed {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    t(
                        "守护进程未能确认完整清理。",
                        "The daemon could not confirm complete cleanup.",
                    ),
                );
            }
            if let Some(failure) = &host.failure {
                ui.small(format!("{}: {failure:?}", t("错误", "Failure")));
            }
            if matches!(
                host.status,
                LocalServiceHostStatus::Starting | LocalServiceHostStatus::Running
            ) && ui
                .add_enabled(
                    self.stop_submission.is_none(),
                    egui::Button::new(t("立即停止", "Stop now")),
                )
                .clicked()
            {
                command = Some(Command::StopLocalServiceHost);
            }
        }
        let mut target_inputs_changed = false;
        let mut close_target = false;
        if let Some(target) = &mut self.local_target {
            let context = ui.ctx().clone();
            egui::Modal::new(egui::Id::new("local-service-target")).show(&context, |ui| {
            ui.set_width((context.content_rect().width() - 48.).clamp(280., 620.));
            close_target = ui.button(t("关闭目标批准", "Close target approval")).clicked();
            egui::ScrollArea::vertical().id_salt("local-target-scroll")
                .max_height(context.content_rect().height() * 0.65).show(ui, |ui| {
            ui.add_space(14.);
            ui.separator();
            ui.heading(t(
                "在本机批准服务目标",
                "Approve a service target on this device",
            ));
            let selected = snapshot
                .selected_service
                .data
                .as_ref()
                .filter(|service| service.id == target.service_id);
            if let Some(service) = selected {
                if !supports_local_protocol(&service.definition.requested_ingress, &target.protocol)
                {
                    target.protocol =
                        default_local_protocol(&service.definition.requested_ingress).into();
                    target.https_server_name.clear();
                    target.https_ca_certificates_der.clear();
                    target.https_ca_file_name = None;
                    target.tls_error = None;
                    target_inputs_changed = true;
                }
                ui.label(format!("{} · {}", service.definition.name, service.id));
                ui.label(t(
                    "以下地址由本机用户选择；服务端响应不能指定或重解析该地址。",
                    "The local user chooses this address. Server responses cannot select or resolve it.",
                ));
                let old_protocol = target.protocol.clone();
                egui::ComboBox::from_id_salt("local-service-target-protocol")
                    .selected_text(target.protocol.as_str())
                    .show_ui(ui, |ui| match &service.definition.requested_ingress {
                        ServiceIngress::Tcp { .. } => {
                            ui.selectable_value(&mut target.protocol, "tcp".into(), "tcp");
                        }
                        ServiceIngress::Udp { .. } => {
                            ui.selectable_value(&mut target.protocol, "udp".into(), "udp");
                        }
                        ServiceIngress::Http { .. } | ServiceIngress::Https { .. } => {
                            ui.selectable_value(&mut target.protocol, "http".into(), "http");
                            ui.selectable_value(&mut target.protocol, "https".into(), "https");
                        }
                    });
                target_inputs_changed |= target.protocol != old_protocol;
                if target.protocol != old_protocol {
                    target.tls_error = None;
                }
                ui.horizontal(|ui| {
                    ui.label(t("目标地址", "Target address"));
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut target.address)
                            .desired_width(260.)
                            .char_limit(64),
                    );
                    target_inputs_changed |= response.changed();
                });
                if target.protocol == "https" {
                    ui.horizontal(|ui| {
                        ui.label(t("HTTPS 服务器名称", "HTTPS server name"));
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut target.https_server_name)
                                .desired_width(260.)
                                .char_limit(253),
                        );
                        if response.changed() {
                            target.tls_error = None;
                        }
                        target_inputs_changed |= response.changed();
                    });
                    ui.horizontal(|ui| {
                        let choose = ui.add_enabled(
                            self.ca_selector.is_none(),
                            egui::Button::new(t(
                                "选择本机 CA 证书…",
                                "Choose local CA certificate…",
                            )),
                        );
                        if choose.clicked() {
                            target_inputs_changed = true;
                            target.tls_error = None;
                            match Selector::start(SelectionKind::File) {
                                Ok(selector) => self.ca_selector = Some(selector),
                                Err(_) => {
                                    target.tls_error = Some(if english {
                                        "Local certificate selection is unavailable.".into()
                                    } else {
                                        "本机证书选择器不可用。".into()
                                    });
                                }
                            }
                        }
                        ui.label(
                            target
                                .https_ca_file_name
                                .as_deref()
                                .unwrap_or(t("尚未选择证书", "No certificate selected")),
                        );
                        if self.ca_selector.is_some() {
                            ui.spinner();
                        }
                    });
                    ui.small(t(
                        "仅接受本机 DER 证书或 PEM 证书包（1–8 张）；证书只通过认证本机 IPC 发送给守护进程。",
                        "Accepts only a local DER certificate or PEM bundle (1–8 certificates); certificates travel only over authenticated local IPC to the daemon.",
                    ));
                    if let Some(error) = &target.tls_error {
                        ui.colored_label(ui.visuals().error_fg_color, error);
                    } else if target.https_ca_certificates_der.is_empty() {
                        ui.label(t(
                            "需要选择本机信任的 CA 证书，并填写后端 TLS 服务器名称。",
                            "Choose a locally trusted CA certificate and enter the backend TLS server name.",
                        ));
                    } else if target.https_backend().is_err() {
                        ui.label(t(
                            "请填写有效的服务器名称并检查本机 CA 证书。",
                            "Enter a valid server name and check the local CA certificate.",
                        ));
                    }
                }
                let host_active = snapshot.local_service_host.as_ref().is_some_and(|host| {
                    matches!(
                        host.status,
                        LocalServiceHostStatus::Starting
                            | LocalServiceHostStatus::Running
                            | LocalServiceHostStatus::Stopping
                    ) || host.cleanup_failed
                });
                let backend_tls = target.https_backend();
                if ui
                    .add_enabled(
                        !busy
                            && !host_active
                            && self.preview_submission.is_none()
                            && self.ca_selector.is_none()
                            && backend_tls.is_ok(),
                        egui::Button::new(t("预览本机批准内容", "Preview local approval")),
                    )
                    .clicked()
                {
                    match backend_tls {
                        Ok(backend_tls) => {
                            command = Some(Command::PreviewLocalServiceHost {
                                service_id: service.id.clone(),
                                service_revision: service.revision,
                                definition_sha256: service.definition_sha256.clone(),
                                expected_snapshot_revision: snapshot.revision,
                                protocol: target.protocol.clone(),
                                address: target.address.clone(),
                                backend_tls,
                            });
                        }
                        Err(()) => {
                            target.tls_error = Some(t(
                                "HTTPS 需要有效的服务器名称和 1–8 张有效大小的本机 CA 证书。",
                                "HTTPS requires a valid server name and 1–8 local CA certificates within the size limits.",
                            ).into());
                        }
                    }
                }
                if self.preview_submission.is_some() {
                    ui.label(t("正在生成短时预览…", "Creating a short-lived preview…"));
                }
                if !target_inputs_changed && let Some(preview) = &self.local_preview {
                    ui.separator();
                    ui.strong(t("请核对完整服务版本 N 和本机目标，然后显式确认启动。", "Review the complete service revision N and local target, then explicitly confirm start."));
                    ui.monospace(format!(
                        "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
                        t("协议", "Protocol"),
                        preview.protocol,
                        t("规范化目标地址", "Canonical target address"),
                        preview.address,
                        t("服务 ID", "Service ID"),
                        preview.service.id,
                        t("完整服务版本 N", "Full service revision N"),
                        preview.service.revision,
                        t("服务定义摘要", "Service definition digest"),
                        preview.service.definition_sha256,
                    ));
                    if let (Some(server_name), Some(fingerprint)) = (
                        preview.backend_tls_server_name.as_deref(),
                        preview.backend_tls_sha256.as_deref(),
                    ) {
                        ui.monospace(format!(
                            "{}: {}\n{}: {}",
                            t("后端 TLS 名称", "Backend TLS name"),
                            server_name,
                            t(
                                "本机 HTTPS 信任绑定 SHA-256",
                                "Local HTTPS trust binding SHA-256"
                            ),
                            fingerprint,
                        ));
                    }
                    ui.label(t("完整服务视图", "Complete service view"));
                    ui.monospace(format!("{:#?}", preview.service));
                    let remaining = self.preview_created_at.map_or(0, |created| {
                        preview
                            .lifetime_ms
                            .saturating_sub(created.elapsed().as_millis() as u64)
                            / 1000
                    });
                    ui.label(format!(
                        "{}: {remaining} s",
                        t("预览有效期剩余", "Preview expires in")
                    ));
                    if ui
                        .add_enabled(
                            remaining > 0
                                && self.preview_submission.is_none()
                                && self.ca_selector.is_none()
                                && !target_inputs_changed,
                            egui::Button::new(t(
                                "确认并启动本机服务",
                                "Confirm and start local service",
                            )),
                        )
                        .clicked()
                    {
                        command = Some(Command::StartLocalServiceHost {
                            preview_nonce: preview.nonce.clone(),
                        });
                    }
                }
            } else if snapshot.selected_service.loading.is_some() {
                ui.label(t("正在读取服务版本…", "Loading the service revision…"));
            } else {
                ui.label(t(
                    "先从服务列表选择一个由本机托管的服务。",
                    "Choose a supported service hosted by this device from the service list first.",
                ));
            }
            });
            });
        }
        if close_target {
            self.local_target = None;
            self.invalidate_preview();
        }
        if target_inputs_changed {
            self.invalidate_preview();
        }
        if let Some(message) = &self.status_message {
            ui.label(message);
        }
        if let Some(view) = self.revoke.clone() {
            let context = ui.ctx().clone();
            egui::Modal::new(egui::Id::new("revoke-service")).show(&context, |ui| {
            ui.set_width(420.);
            let id = view.id.clone();
            let revision = view.revision;
            ui.separator();
            ui.label(format!(
                "{} {}",
                t("撤销此服务：", "Revoke this service:"),
                view.definition.name
            ));
            ui.label(t("该服务的目标批准将失效，恢复使用需要重新配置和批准。", "Its target approval will be invalidated. Reusing it requires a new configuration and approval."));
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new(t("确认撤销", "Confirm revoke")))
                    .clicked()
                {
                    command = Some(Command::Submit {
                        action: Action::RevokeService {
                            service_id: id,
                            expected_revision: revision,
                        },
                    });
                    self.revoke = None;
                }
                if ui.button(t("取消", "Cancel")).clicked() {
                    self.revoke = None;
                }
            });
            });
        }
        if let Some(draft) = &mut self.draft {
            let context = ui.ctx().clone();
            let mut close = false;
            egui::Modal::new(egui::Id::new("service-editor")).show(&context, |ui| {
            ui.set_width((context.content_rect().width() - 48.).clamp(280., 620.));
            ui.heading(t("入口配置", "Ingress configuration"));
            egui::ScrollArea::vertical().id_salt("service-editor-scroll")
                .max_height(context.content_rect().height() * 0.6).show(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
            widgets::field(ui, t("服务名称", "Service name"), &mut draft.name, 128);
            widgets::field(ui, t("主机设备 ID", "Host device ID"), &mut draft.host, 36);
            widgets::field(ui, t("边缘节点 ID", "Edge node ID"), &mut draft.edge, 36);
            ui.small(t("节点 ID 由管理员提供。目标地址只在主机本机批准时选择。", "Your administrator supplies the node ID. The target address is chosen locally on the host."));
            egui::ComboBox::from_id_salt("service-protocol")
                .selected_text(["HTTP", "HTTPS", "TCP", "UDP"][draft.protocol])
                .show_ui(ui, |ui| {
                    for (index, label) in ["HTTP", "HTTPS", "TCP", "UDP"].iter().enumerate() {
                        ui.selectable_value(&mut draft.protocol, index, *label);
                    }
                });
            widgets::field(
                ui,
                if draft.protocol < 2 {
                    t("入口域名", "Ingress hostname")
                } else {
                    t("入口端口", "Ingress port")
                },
                &mut draft.ingress,
                253,
            );
            ui.label(t(
                "访问来源（CIDR，每行一项；留空拒绝所有访问）",
                "Visitor networks (one CIDR per line; empty denies all visitors)",
            ));
            ui.add(
                egui::TextEdit::multiline(&mut draft.sources)
                    .char_limit(2048)
                    .desired_rows(3),
            );
            egui::Grid::new("service-limits")
                .num_columns(2)
                .show(ui, |ui| {
                    ui.label(t("最大连接数", "Maximum connections"));
                    ui.add(
                        egui::DragValue::new(&mut draft.limits.maximum_connections).range(1..=128),
                    );
                    ui.end_row();
                    ui.label(t("速率上限（字节/秒）", "Rate limit (bytes/second)"));
                    ui.add(
                        egui::DragValue::new(&mut draft.limits.bytes_per_second)
                            .range(1..=1_073_741_824u64),
                    );
                    ui.end_row();
                    ui.label(t("累计流量上限（字节）", "Total traffic limit (bytes)"));
                    ui.add(
                        egui::DragValue::new(&mut draft.limits.maximum_bytes)
                            .range(1..=1_099_511_627_776u64),
                    );
                    ui.end_row();
                    ui.label(t("空闲超时（秒）", "Idle timeout (seconds)"));
                    ui.add(
                        egui::DragValue::new(&mut draft.limits.idle_timeout_seconds).range(1..=300),
                    );
                    ui.end_row();
                });
            ui.label(t("修改配置会使原目标批准失效。保存配置后，入口仍需等待主机批准和发布就绪。", "Changing a configuration invalidates its previous target approval. Saving still requires host approval and publication readiness."));
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy && !draft.unchanged(), egui::Button::new(t("保存配置", "Save configuration"))).clicked() {
                    match draft.action() {
                        Ok(next) => { command = Some(Command::Submit { action: next }); self.error = None; }
                        Err(()) => self.error = Some(t("请检查设备和节点 ID、域名或端口，以及规范的 CIDR 网络地址。", "Check device and node IDs, the hostname or port, and canonical CIDR network addresses.").into()),
                    }
                }
                if ui.button(t("关闭编辑", "Close editor")).clicked() { close = true; }
            });
            });
            });
            });
            if close || context.input(|i| i.key_pressed(egui::Key::Escape)) {
                let dirty = !draft.unchanged()
                    && self.draft_baseline.as_ref() != Some(&draft.fingerprint());
                if dirty {
                    self.discard_confirmation = true;
                } else {
                    self.draft = None;
                    self.error = None;
                }
            }
        }
        if self.discard_confirmation {
            let mut discard = false;
            let mut keep = false;
            egui::Modal::new(egui::Id::new("discard-service-draft")).show(ui.ctx(), |ui| {
                ui.heading(t("放弃未保存的修改？", "Discard unsaved changes?"));
                keep = ui.button(t("继续编辑", "Keep editing")).clicked();
                discard = ui.button(t("放弃修改", "Discard changes")).clicked();
            });
            if discard {
                self.draft = None;
                self.error = None;
            }
            if discard || keep {
                self.discard_confirmation = false;
            }
        }
        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        if matches!(
            command.as_ref(),
            Some(Command::StartLocalServiceHost { .. })
        ) {
            self.invalidate_preview();
        }
        command
    }
}

fn valid_fingerprint(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|digest| digest.len() == 32)
}

fn read_ca_bundle(path: &Path) -> Result<Vec<Vec<u8>>, ()> {
    let file = File::open(path).map_err(|_| ())?;
    if file.metadata().map_err(|_| ())?.len() > MAX_CA_BUNDLE_FILE_BYTES as u64 {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BUNDLE_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > MAX_CA_BUNDLE_FILE_BYTES {
        return Err(());
    }
    parse_ca_bundle(bytes)
}

fn parse_ca_bundle(bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, ()> {
    if bytes.is_empty() || bytes.len() > MAX_CA_BUNDLE_FILE_BYTES {
        return Err(());
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return if bytes.len() <= 16_384 {
            Ok(vec![bytes])
        } else {
            Err(())
        };
    };
    if text.contains("-----BEGIN ") && !text.contains(BEGIN) {
        return Err(());
    }
    if !text.contains(BEGIN) {
        return if bytes.len() <= 16_384 {
            Ok(vec![bytes])
        } else {
            Err(())
        };
    }

    let mut lines = text.lines().map(str::trim);
    let mut certificates = Vec::new();
    loop {
        while lines.clone().next().is_some_and(|line| line.is_empty()) {
            lines.next();
        }
        let Some(begin) = lines.next() else {
            break;
        };
        if begin != BEGIN || certificates.len() == 8 {
            return Err(());
        }
        let mut encoded = String::new();
        let mut found_end = false;
        for line in lines.by_ref() {
            if line == END {
                found_end = true;
                break;
            }
            if line.is_empty()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return Err(());
            }
            encoded.push_str(line);
            if encoded.len() > 22_000 {
                return Err(());
            }
        }
        if !found_end {
            return Err(());
        }
        let certificate = BASE64_STANDARD.decode(encoded).map_err(|_| ())?;
        if !(1..=16_384).contains(&certificate.len()) {
            return Err(());
        }
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        Err(())
    } else {
        Ok(certificates)
    }
}

fn ingress_label(ingress: &ServiceIngress) -> String {
    match ingress {
        ServiceIngress::Http { hostname } => format!("http://{hostname}"),
        ServiceIngress::Https { hostname } => format!("https://{hostname}"),
        ServiceIngress::Tcp { port } => format!("TCP {port}"),
        ServiceIngress::Udp { port } => format!("UDP {port}"),
    }
}

fn supports_local_protocol(ingress: &ServiceIngress, protocol: &str) -> bool {
    match ingress {
        ServiceIngress::Http { .. } | ServiceIngress::Https { .. } => {
            matches!(protocol, "http" | "https")
        }
        ServiceIngress::Tcp { .. } => protocol == "tcp",
        ServiceIngress::Udp { .. } => protocol == "udp",
    }
}

fn default_local_protocol(ingress: &ServiceIngress) -> &'static str {
    match ingress {
        ServiceIngress::Http { .. } => "http",
        ServiceIngress::Https { .. } => "https",
        ServiceIngress::Tcp { .. } => "tcp",
        ServiceIngress::Udp { .. } => "udp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ca_reader_accepts_bounded_der_and_pem_bundles() {
        assert_eq!(parse_ca_bundle(vec![1, 2, 3]), Ok(vec![vec![1, 2, 3]]));
        assert_eq!(
            parse_ca_bundle(
                b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n".to_vec(),
            ),
            Ok(vec![vec![1, 2, 3], vec![4, 5, 6]]),
        );
    }

    #[test]
    fn local_ca_reader_rejects_malformed_and_unbounded_bundles() {
        assert!(
            parse_ca_bundle(
                b"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----".to_vec(),
            )
            .is_err()
        );
        assert!(parse_ca_bundle(vec![0; 16_385]).is_err());
        assert!(parse_ca_bundle(vec![0; MAX_CA_BUNDLE_FILE_BYTES + 1]).is_err());
    }
}
