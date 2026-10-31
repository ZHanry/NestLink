use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::*;
use nestlink_sdk::{Sdk, SdkError};
use nestlink_web::{
    i18n::{sdk_error, text as t},
    localized_format,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
mod exposure;
mod private_web;

#[derive(Clone)]
struct Editor {
    id: String,
    revision: Option<u64>,
    name: String,
    host: String,
    edge: String,
    protocol: String,
    ingress: String,
    sources: String,
    connections: String,
    rate: String,
    bytes: String,
    idle: String,
    saved: Option<ServiceDefinition>,
}
impl Editor {
    fn fingerprint(&self) -> String {
        format!(
            "{:?}",
            (
                &self.name,
                &self.host,
                &self.edge,
                &self.protocol,
                &self.ingress,
                &self.sources,
                &self.connections,
                &self.rate,
                &self.bytes,
                &self.idle
            )
        )
    }

    fn new() -> Self {
        Self {
            id: nestlink_auth::random_id(),
            revision: None,
            name: String::new(),
            host: String::new(),
            edge: String::new(),
            protocol: "tcp".into(),
            ingress: "29100".into(),
            sources: String::new(),
            connections: "8".into(),
            rate: "1048576".into(),
            bytes: "1073741824".into(),
            idle: "60".into(),
            saved: None,
        }
    }
    fn from_view(view: &ServiceView) -> Self {
        let (protocol, ingress) = match &view.definition.requested_ingress {
            ServiceIngress::Http { hostname } => ("http", hostname.clone()),
            ServiceIngress::Https { hostname } => ("https", hostname.clone()),
            ServiceIngress::Tcp { port } => ("tcp", port.to_string()),
            ServiceIngress::Udp { port } => ("udp", port.to_string()),
        };
        Self {
            id: view.id.clone(),
            revision: Some(view.revision),
            name: view.definition.name.clone(),
            host: view.definition.host_device_id.clone(),
            edge: view.definition.edge_node_id.clone(),
            protocol: protocol.into(),
            ingress,
            sources: view
                .definition
                .allowed_sources
                .iter()
                .map(|v| format!("{}/{}", v.address, v.prefix))
                .collect::<Vec<_>>()
                .join("\n"),
            connections: view.definition.limits.maximum_connections.to_string(),
            rate: view.definition.limits.bytes_per_second.to_string(),
            bytes: view.definition.limits.maximum_bytes.to_string(),
            idle: view.definition.limits.idle_timeout_seconds.to_string(),
            saved: Some(view.definition.clone()),
        }
    }
    fn definition(&self) -> Result<ServiceDefinition, &'static str> {
        let invalid = t(
            "请检查主机和节点 ID、域名或端口、规范 CIDR 网络地址及配额。",
            "Check host and node IDs, domain or port, canonical CIDR networks, and quotas.",
        );
        if !nestlink_protocol::valid_id(&self.host) {
            return Err(t(
                "主机设备：请选择有效设备。",
                "Host device: select a valid device.",
            ));
        }
        if !self.edge.is_empty() && !nestlink_protocol::valid_id(&self.edge) {
            return Err(t(
                "边缘节点：请选择有效节点。",
                "Edge node: select a valid node.",
            ));
        }
        let port_error = t("入口端口：请输入 1–65535。", "Ingress port: enter 1–65535.");
        let quota_error = t(
            "服务配额：请检查连接数、速率、累计字节数和超时。",
            "Service limits: check connections, rate, total bytes and timeout.",
        );
        let cidr_error = t(
            "访问来源：每行必须是规范 CIDR 网络地址。",
            "Allowed sources: each line must be a canonical CIDR network.",
        );
        let requested_ingress = match self.protocol.as_str() {
            "http" => ServiceIngress::Http {
                hostname: self.ingress.clone(),
            },
            "https" => ServiceIngress::Https {
                hostname: self.ingress.clone(),
            },
            "tcp" => ServiceIngress::Tcp {
                port: self
                    .ingress
                    .parse::<u16>()
                    .ok()
                    .filter(|v| *v != 0)
                    .ok_or(port_error)?,
            },
            "udp" => ServiceIngress::Udp {
                port: self
                    .ingress
                    .parse::<u16>()
                    .ok()
                    .filter(|v| *v != 0)
                    .ok_or(port_error)?,
            },
            _ => return Err(invalid),
        };
        let mut allowed_sources = Vec::new();
        for line in self
            .sources
            .lines()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            if allowed_sources.len() == 32 {
                return Err(invalid);
            }
            let (address, prefix) = line.split_once('/').ok_or(cidr_error)?;
            allowed_sources.push(ServiceSourceNetwork {
                address: address.into(),
                prefix: prefix.parse().map_err(|_| cidr_error)?,
            });
        }
        let definition = ServiceDefinition {
            name: self.name.clone(),
            host_device_id: self.host.clone(),
            edge_node_id: self.edge.clone(),
            requested_ingress,
            allowed_sources,
            limits: ServiceLimits {
                maximum_connections: self.connections.parse().map_err(|_| quota_error)?,
                bytes_per_second: self.rate.parse().map_err(|_| quota_error)?,
                maximum_bytes: self.bytes.parse().map_err(|_| quota_error)?,
                idle_timeout_seconds: self.idle.parse().map_err(|_| quota_error)?,
            },
        };
        definition.validate().map_err(|_| invalid)?;
        Ok(definition)
    }
    fn reconcile(&mut self, view: &ServiceView) {
        if view.id == self.id
            && view.approval != ServiceApprovalState::Revoked
            && self
                .revision
                .is_none_or(|revision| revision <= view.revision)
            && self
                .definition()
                .is_ok_and(|definition| definition == view.definition)
        {
            self.revision = Some(view.revision);
            self.saved = Some(view.definition.clone());
        }
    }
    fn unchanged(&self) -> bool {
        self.saved.is_some() && self.definition().ok().as_ref() == self.saved.as_ref()
    }
}

enum Command {
    List(Option<String>),
    Save {
        id: String,
        revision: Option<u64>,
        definition: ServiceDefinition,
    },
    Revoke {
        id: String,
        revision: u64,
    },
    StopPublication {
        id: String,
        revision: u64,
    },
}
enum Outcome {
    Page(ServicePage, Vec<(String, String)>, Vec<(String, String)>),
    Committed {
        view: Box<ServiceView>,
        page: Result<ServicePage, SdkError>,
    },
    PublicationStopped {
        page: Result<ServicePage, SdkError>,
    },
}
async fn execute(sdk: &Sdk, command: Command) -> Result<Outcome, SdkError> {
    let view = match command {
        Command::List(after) => {
            let page = sdk.services(after.as_deref(), 50).await?;
            let hosts = sdk
                .devices()
                .await?
                .into_iter()
                .filter(|v| !v.revoked && v.device.capabilities.iter().any(|c| c == "host"))
                .map(|v| (v.device.id, v.device.name))
                .collect();
            let nodes = sdk
                .nodes()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|v| !v.revoked)
                .map(|v| (v.node.id, v.node.name))
                .collect();
            return Ok(Outcome::Page(page, hosts, nodes));
        }
        Command::StopPublication { id, revision } => {
            sdk.stop_service_publication(&id, revision).await?;
            return Ok(Outcome::PublicationStopped {
                page: sdk.services(None, 50).await,
            });
        }
        Command::Save {
            id,
            revision,
            definition,
        } => match revision {
            None => {
                sdk.create_service(&ServiceCreate { id, definition })
                    .await?
            }
            Some(expected_revision) => {
                sdk.update_service(
                    &id,
                    &ServiceUpdate {
                        expected_revision,
                        definition,
                    },
                )
                .await?
            }
        },
        Command::Revoke { id, revision } => sdk.revoke_service(&id, revision).await?,
    };
    Ok(Outcome::Committed {
        view: Box::new(view),
        page: sdk.services(None, 50).await,
    })
}
fn authentication_lost(error: &SdkError) -> bool {
    matches!(error, SdkError::SignIn)
        || matches!(error, SdkError::Api(status, _) if status.as_u16() == 401)
}

#[component]
pub(super) fn ServicesPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    refresh: RwSignal<u64>,
    active: Signal<bool>,
    auth_failure: Callback<SdkHandle>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
) -> impl IntoView {
    let page = RwSignal::new(None::<ServicePage>);
    let hosts = RwSignal::new(Vec::<(String, String)>::new());
    let edges = RwSignal::new(Vec::<(String, String)>::new());
    let editor = RwSignal::new(None::<Editor>);
    let confirmation = RwSignal::new(None::<ServiceView>);
    let discard = RwSignal::new(false);
    let baseline = RwSignal::new(String::new());
    let editor_close = Callback::new(move |()| {
        if editor.with_untracked(|v| {
            v.as_ref()
                .is_some_and(|v| !v.unchanged() && v.fingerprint() != baseline.get_untracked())
        }) {
            discard.set(true);
        } else {
            editor.set(None);
        }
    });
    let busy = RwSignal::new(false);
    let alive = Arc::new(AtomicBool::new(true));
    let owner = alive.clone();
    on_cleanup(move || owner.store(false, Ordering::Release));
    let submit = Callback::new(move |command: Command| {
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        let write = !matches!(&command, Command::List(_));
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let result = {
                let sdk = sdk.lock().await;
                // Waiting for another SDK operation must not dispatch an old
                // page's action after navigation, logout or account replacement.
                if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                    return;
                }
                execute(&sdk, command).await
            };
            if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                return;
            }
            match result {
                Ok(Outcome::Page(value, host_options, edge_options)) => {
                    hosts.set(host_options);
                    edges.set(edge_options);
                    editor.update(|draft| {
                        if let Some(draft) = draft {
                            for view in &value.services {
                                draft.reconcile(view);
                            }
                        }
                    });
                    page.set(Some(value));
                }
                Ok(Outcome::Committed {
                    view,
                    page: refreshed,
                }) => {
                    editor.update(|draft| {
                        if view.approval == ServiceApprovalState::Revoked {
                            if draft.as_ref().is_some_and(|draft| draft.id == view.id) {
                                *draft = None;
                            }
                        } else if let Some(draft) = draft {
                            draft.reconcile(&view);
                        }
                    });
                    notice.set(
                        if view.approval == ServiceApprovalState::Revoked {
                            t("服务配置已撤销。", "Service configuration revoked.")
                        } else {
                            t("配置已保存，入口仍需主机批准和发布就绪。", "Configuration saved. Ingress still requires host approval and a ready publication.")
                        }
                        .into(),
                    );
                    match refreshed {
                        Ok(value) => page.set(Some(value)),
                        Err(problem) if authentication_lost(&problem) => {
                            auth_failure.run(sdk);
                            return;
                        }
                        Err(problem) => {
                            let problem = sdk_error(&problem);
                            error.set(nestlink_web::localized_detail!("操作已提交，但目录刷新失败：{}。请刷新目录。", "The operation was submitted, but the catalog refresh failed: {}. Refresh the catalog.", problem));
                        }
                    }
                }
                Ok(Outcome::PublicationStopped { page: refreshed }) => {
                    notice.set(
                        t(
                            "停止已请求；边缘节点正在清理现有连接。",
                            "Stop requested. The edge is draining existing connections.",
                        )
                        .into(),
                    );
                    match refreshed {
                        Ok(value) => page.set(Some(value)),
                        Err(problem) if authentication_lost(&problem) => {
                            auth_failure.run(sdk);
                            return;
                        }
                        Err(problem) => {
                            let problem = sdk_error(&problem);
                            error.set(nestlink_web::localized_detail!("停止已提交，但目录刷新失败：{}。请刷新目录。", "Stop was submitted, but the catalog refresh failed: {}. Refresh the catalog.", problem));
                        }
                    }
                }
                Err(problem) if authentication_lost(&problem) => {
                    auth_failure.run(sdk);
                    return;
                }
                Err(problem) => {
                    let known =
                        matches!(&problem, SdkError::Api(status, _) if status.is_client_error());
                    let problem = sdk_error(&problem);
                    error.set(if write && !known {
                        nestlink_web::localized_detail!("未能确认保存或撤销结果：{}。请先刷新；创建草稿保留相同 ID，核实后可重试。", "Could not confirm the save or revocation result: {}. Refresh first; new drafts retain the same ID so you can check before retrying.", problem)
                    } else { problem.to_string() });
                }
            }
            busy.set(false);
        });
    });
    let loaded_refresh = StoredValue::new(None::<u64>);
    Effect::new(move |_| {
        if !active.get() {
            return;
        }
        let requested = refresh.get();
        if !busy.get() && loaded_refresh.get_value() != Some(requested) {
            loaded_refresh.set_value(Some(requested));
            submit.run(Command::List(None));
        }
    });
    let save = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if let Some(value) = editor.get_untracked() {
            match value.definition() {
                Ok(definition) => submit.run(Command::Save {
                    id: value.id,
                    revision: value.revision,
                    definition,
                }),
                Err(problem) => error.set(problem.into()),
            }
        }
    };
    view! {
        <div class="tunnel-workspace">
            <section class="tunnel-directory" aria-label=move || t("服务目录", "Service catalog")>
                <div class="section-heading tunnel-heading"><div><h2>{move || t("我的穿透服务", "My tunnels")}</h2><p>{move || t("查看入口、主机授权和发布状态。", "Review ingress, host approval, and publication status.")}</p></div>
                    <button class="primary" type="button" disabled=move || busy.get() on:click=move |_| { baseline.set(Editor::new().fingerprint()); editor.set(Some(Editor::new())); confirmation.set(None); }>{move || t("新建服务", "New service")}</button>
                </div>
                <div class="tunnel-records" aria-busy=move || busy.get().to_string()>
                    {move || page.get().map(|value| if value.services.is_empty() {
                        view! { <div class="empty-state"><super::WorkspaceIcon kind=super::Section::Services /><h3>{move || t("让内网服务拥有访问入口", "Give an internal service an ingress")}</h3><p>{move || t("新建服务，选择主机、协议和入口，再到主机确认内网目标。", "Create a service, choose its host, protocol, and ingress, then approve the internal target on the host.")}</p></div> }.into_any()
                    } else {
                        value.services.into_iter().map(|service| {
                            let edit = service.clone();
                            let revoke = service.clone();
                            let status = approval_label(service.approval);
                            let publication_status = publication_label(service.publication);
                            let ingress = ingress_label(&service.definition.requested_ingress);
                            let revoked = service.approval == ServiceApprovalState::Revoked;
                            let stop_publication = StoredValue::new((service.id.clone(), service.revision));
                            view! { <article class="tunnel-record">
                                <header class="tunnel-record-head"><super::WorkspaceIcon kind=super::Section::Services /><h3 title=service.definition.name.clone()>{service.definition.name.clone()}</h3><span class="status-label">{publication_status}</span></header>
                                <div class="tunnel-route"><div><span>{move || t("配置入口", "Configured ingress")}</span><code>{ingress}</code></div><span class="route-connector" aria-hidden="true"></span><div><span>{move || t("目标主机", "Target host")}</span><code>{service.definition.host_device_id.clone()}</code></div></div>
                                <footer class="tunnel-record-foot"><p>{status} <small>{move || t("配置版本 ", "Configuration revision ")}{service.revision}</small></p><div class="tunnel-actions">
                                <Show when=move || service.publication != ServicePublicationStatus::NotPublished>
                                    <button class="danger" type="button" disabled=move || busy.get() on:click=move |_| { let (id, revision) = stop_publication.get_value(); submit.run(Command::StopPublication { id, revision }); }>{move || t("停止发布", "Stop publication")}</button>
                                </Show>
                                <button class="secondary" type="button" disabled=move || busy.get() || revoked on:click=move |_| { baseline.set(Editor::from_view(&edit).fingerprint()); editor.set(Some(Editor::from_view(&edit))); confirmation.set(None); }>{move || t("编辑配置", "Edit configuration")}</button>
                                <button class="danger" type="button" disabled=move || busy.get() || revoked on:click=move |_| confirmation.set(Some(revoke.clone()))>{move || t("撤销", "Revoke")}</button>
                                </div></footer>
                            </article> }
                        }).collect_view().into_any()
                    })}
                </div>
                <div class="audit-pagination">
                    <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| submit.run(Command::List(None))>{move || t("第一页", "First page")}</button>
                    <button class="secondary" type="button" disabled=move || busy.get() || !page.with(|page| page.as_ref().is_some_and(|page| page.more)) on:click=move |_| {
                        let after = page.with_untracked(|page| page.as_ref().and_then(|page| page.next_id.clone()));
                        submit.run(Command::List(after));
                    }>{move || t("下一页", "Next page")}</button>
                </div>
                <Show when=move || confirmation.with(Option::is_some)>
                    <super::TaskDialog open=Signal::derive(move || confirmation.with(Option::is_some))
                        label=Signal::derive(move || t("撤销此服务？", "Revoke this service?").to_owned())
                        on_close=Callback::new(move |()| confirmation.set(None))>
                    <div class="policy-form">
                        <h3>{move || t("撤销此服务？", "Revoke this service?")}</h3><p>{move || confirmation.with(|v| v.as_ref().map(|v| v.definition.name.clone()).unwrap_or_default())}</p>
                        <p>{move || t("目标批准将失效，恢复使用需要重新配置和批准。", "Target approval will expire. Reconfigure and approve the service before using it again.")}</p>
                        <button class="danger" type="button" disabled=move || busy.get() on:click=move |_| {
                            if let Some(view) = confirmation.get_untracked() { submit.run(Command::Revoke { id: view.id, revision: view.revision }); confirmation.set(None); }
                        }>{move || t("确认撤销", "Confirm revocation")}</button>
                        <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| confirmation.set(None)>{move || t("取消", "Cancel")}</button>
                    </div>
                    </super::TaskDialog>
                </Show>
            </section>
            <exposure::ServiceExposurePanel api page session_revision auth_failure />
            <private_web::PrivateWebPanel api session_revision auth_failure active />
            <aside class="tunnel-guide" aria-label=move || t("发布流程", "Publishing steps")>
                <h2>{move || t("从内网到访问入口", "From internal service to ingress")}</h2>
                <ol><li><strong>{move || t("配置入口", "Configure ingress")}</strong><p>{move || t("选择已登记的主机、边缘节点和协议。", "Choose a registered host, edge node, and protocol.")}</p></li><li><strong>{move || t("主机确认目标", "Approve the target")}</strong><p>{move || t("在 Windows 客户端选择内网地址并批准。", "Choose and approve the internal address in the Windows client.")}</p></li><li><strong>{move || t("核对发布状态", "Check publication")}</strong><p>{move || t("以服务返回的发布状态为准；保存配置不等于已发布。", "Use the service's reported publication status. Saving a configuration does not publish it.")}</p></li></ol>
                <p class="muted">{move || t("修改配置后，原目标批准会失效。", "Changing a configuration invalidates its previous target approval.")}</p>
                <Show when=move || editor.with(Option::is_some)>
                    <super::TaskDialog open=Signal::derive(move || editor.with(Option::is_some))
                        label=Signal::derive(move || t("入口配置", "Ingress configuration").to_owned()) on_close=editor_close>
                    <form class="service-editor" on:submit=save>
                        <header class="dialog-head"><h2>{move || editor.with(|value| if value.as_ref().is_some_and(|value| value.revision.is_some()) { t("编辑穿透服务", "Edit tunnel") } else { t("新建穿透服务", "New tunnel") })}</h2><p>{move || t("保存后，请在主机确认内网目标。", "After saving, approve the internal target on the host.")}</p></header>
                        <div class="service-editor-body">
                        <fieldset class="service-fields" disabled=move || busy.get()>
                            <section class="form-section"><h3>{move || t("服务与主机", "Service and host")}</h3>
                            {field(editor, Field::Name, "服务名称", "Service name", 128)}
                            <label>{move || t("主机设备（输入名称搜索）", "Host device (search by name)")}
                                <input list="service-host-options" required=true prop:value=move || editor.with(|v| v.as_ref().map(|v| v.host.clone()).unwrap_or_default()) on:input=move |event| editor.update(|v| if let Some(v) = v { v.host = event_target_value(&event); }) />
                            </label>
                            <datalist id="service-host-options"><For each=move || hosts.get() key=|v| v.0.clone() children=move |(id,name)| view! { <option value=id>{name}</option> } /></datalist>
                            <label>{move || t("公网边缘节点（私有服务可留空）", "Public edge node (leave empty for private services)")}
                                <input list="service-edge-options" prop:value=move || editor.with(|v| v.as_ref().map(|v| v.edge.clone()).unwrap_or_default()) on:input=move |event| editor.update(|v| if let Some(v) = v { v.edge = event_target_value(&event); }) />
                            </label>
                            <datalist id="service-edge-options"><For each=move || edges.get() key=|v| v.0.clone() children=move |(id,name)| view! { <option value=id>{name}</option> } /></datalist>
                            </section>
                            <section class="form-section"><h3>{move || t("访问入口", "Ingress and access")}</h3>
                            <label>{move || t("协议", "Protocol")}<select prop:value=move || editor.with(|v| v.as_ref().map(|v| v.protocol.clone()).unwrap_or_default()) on:change=move |event| editor.update(|v| if let Some(v) = v { v.protocol = event_target_value(&event); })>
                                <option value="http">"HTTP"</option><option value="https">"HTTPS"</option><option value="tcp">"TCP"</option><option value="udp">"UDP"</option>
                            </select></label>
                            {field(editor, Field::Ingress, "入口域名或端口", "Ingress domain or port", 253)}
                            <label>{move || t("访问来源（CIDR，每行一项；留空拒绝所有访问）", "Allowed sources (one CIDR per line; leave empty to deny all access)")}
                                <textarea rows="3" maxlength="2048" prop:value=move || editor.with(|v| v.as_ref().map(|v| v.sources.clone()).unwrap_or_default()) on:input=move |event| editor.update(|v| if let Some(v) = v { v.sources = event_target_value(&event); })></textarea>
                            </label>
                            </section>
                            <section class="form-section"><h3>{move || t("资源限制", "Resource limits")}</h3><div class="form-columns">
                            {field(editor, Field::Connections, "最大连接数", "Maximum connections", 3)}
                            {field(editor, Field::Rate, "速率上限（字节/秒）", "Rate limit (bytes/second)", 10)}
                            {field(editor, Field::Bytes, "累计流量上限（字节）", "Total traffic limit (bytes)", 13)}
                            {field(editor, Field::Idle, "空闲超时（秒）", "Idle timeout (seconds)", 3)}
                            </div>
                            <p class="muted">{move || editor.with(|v| v.as_ref().map(|v| {
                                let rate = v.rate.parse::<u64>().unwrap_or_default();
                                let bytes = v.bytes.parse::<u64>().unwrap_or_default();
                                localized_format!("速率约 {:.3} MiB/s；累计流量约 {:.3} GiB（1 MiB = 1048576 字节；1 GiB = 1073741824 字节）。", "Rate: {:.3} MiB/s; total: {:.3} GiB (1 MiB = 1048576 bytes; 1 GiB = 1073741824 bytes).", rate as f64 / 1048576., bytes as f64 / 1073741824.)
                            }).unwrap_or_default())}</p>
                            </section>
                        </fieldset>
                        </div>
                        <footer class="dialog-actions"><p class="form-error" aria-live="polite">{move || editor.with(|value| value.as_ref().and_then(|value| value.definition().err()).unwrap_or(""))}</p><div>
                            <button class="primary" type="submit" disabled=move || busy.get() || editor.with(|v| v.as_ref().is_none_or(Editor::unchanged))>{move || t("保存配置", "Save configuration")}</button>
                            <button class="secondary" type="button" on:click=move |_| editor_close.run(())>{move || t("关闭编辑", "Close editor")}</button>
                        </div></footer>
                    </form>
                    </super::TaskDialog>
                </Show>
            </aside>
            <super::TaskDialog open=Signal::derive(move || discard.get())
                label=Signal::derive(move || t("放弃修改？", "Discard changes?").to_owned())
                on_close=Callback::new(move |()| discard.set(false))>
                <h2>{move || t("放弃未保存的修改？", "Discard unsaved changes?")}</h2>
                <button class="secondary" type="button" on:click=move |_| discard.set(false)>{move || t("继续编辑", "Keep editing")}</button>
                <button class="danger" type="button" on:click=move |_| { editor.set(None); discard.set(false); }>{move || t("放弃修改", "Discard changes")}</button>
            </super::TaskDialog>
        </div>
    }
}

#[derive(Clone, Copy)]
enum Field {
    Name,

    Ingress,
    Connections,
    Rate,
    Bytes,
    Idle,
}
impl Field {
    fn value(self, editor: &mut Editor) -> &mut String {
        match self {
            Self::Name => &mut editor.name,

            Self::Ingress => &mut editor.ingress,
            Self::Connections => &mut editor.connections,
            Self::Rate => &mut editor.rate,
            Self::Bytes => &mut editor.bytes,
            Self::Idle => &mut editor.idle,
        }
    }
}
fn field(
    editor: RwSignal<Option<Editor>>,
    field: Field,
    label: &'static str,
    english_label: &'static str,
    maximum: u16,
) -> impl IntoView {
    let bounds = match field {
        Field::Connections => Some((1_u64, 128_u64)),
        Field::Rate => Some((1, 1_073_741_824)),
        Field::Bytes => Some((1, 1_099_511_627_776)),
        Field::Idle => Some((1, 300)),
        _ => None,
    };
    let invalid = move || {
        editor.with(|value| {
            value.as_ref().is_some_and(|value| {
                bounds.is_some_and(|(min, max)| {
                    field
                        .value(&mut value.clone())
                        .parse::<u64>()
                        .map_or(true, |number| number < min || number > max)
                })
            })
        })
    };
    view! { <label>{move || t(label, english_label)}<input type=match field { Field::Connections | Field::Rate | Field::Bytes | Field::Idle => "number", _ => "text" } min=bounds.map(|v| v.0) max=bounds.map(|v| v.1) step="1" aria-invalid=move || invalid().to_string() maxlength=maximum autocomplete="off" required=true
    prop:value=move || editor.with(|editor| editor.as_ref().map(|value| field.value(&mut value.clone()).clone()).unwrap_or_default())
    on:input=move |event| editor.update(|editor| if let Some(editor) = editor { *field.value(editor) = event_target_value(&event); }) />
    <span class="form-error">{move || if invalid() { bounds.map(|(min,max)| localized_format!("请输入 {}–{} 的整数。", "Enter an integer from {} to {}.", min, max)).unwrap_or_default() } else { String::new() }}</span>
    </label> }
}
fn approval_label(state: ServiceApprovalState) -> &'static str {
    match state {
        ServiceApprovalState::Pending => t("等待本机目标批准", "Waiting for local target approval"),
        ServiceApprovalState::ApprovedTarget => t("目标已批准", "Target approved"),
        ServiceApprovalState::Invalidated => t("目标批准已失效", "Target approval invalidated"),
        ServiceApprovalState::Revoked => t("已撤销", "Revoked"),
    }
}
fn publication_label(state: ServicePublicationStatus) -> &'static str {
    match state {
        ServicePublicationStatus::NotPublished => t("未发布", "Not published"),
        ServicePublicationStatus::Published => t("已发布", "Published"),
        ServicePublicationStatus::Stopping => t("正在停止", "Stopping"),
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
