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
        let requested_ingress = match self.protocol.as_str() {
            "http" => ServiceIngress::Http {
                hostname: self.ingress.clone(),
            },
            "https" => ServiceIngress::Https {
                hostname: self.ingress.clone(),
            },
            "tcp" => ServiceIngress::Tcp {
                port: self.ingress.parse().map_err(|_| invalid)?,
            },
            "udp" => ServiceIngress::Udp {
                port: self.ingress.parse().map_err(|_| invalid)?,
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
            let (address, prefix) = line.split_once('/').ok_or(invalid)?;
            allowed_sources.push(ServiceSourceNetwork {
                address: address.into(),
                prefix: prefix.parse().map_err(|_| invalid)?,
            });
        }
        let definition = ServiceDefinition {
            name: self.name.clone(),
            host_device_id: self.host.clone(),
            edge_node_id: self.edge.clone(),
            requested_ingress,
            allowed_sources,
            limits: ServiceLimits {
                maximum_connections: self.connections.parse().map_err(|_| invalid)?,
                bytes_per_second: self.rate.parse().map_err(|_| invalid)?,
                maximum_bytes: self.bytes.parse().map_err(|_| invalid)?,
                idle_timeout_seconds: self.idle.parse().map_err(|_| invalid)?,
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
    Page(ServicePage),
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
        Command::List(after) => return sdk.services(after.as_deref(), 50).await.map(Outcome::Page),
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
    auth_failure: Callback<SdkHandle>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
) -> impl IntoView {
    let page = RwSignal::new(None::<ServicePage>);
    let editor = RwSignal::new(None::<Editor>);
    let confirmation = RwSignal::new(None::<ServiceView>);
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
                Ok(Outcome::Page(value)) => {
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
                            error.set(localized_format!("操作已提交，但目录刷新失败：{problem}。请刷新目录。", "The operation was submitted, but the catalog refresh failed: {problem}. Refresh the catalog."));
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
                            error.set(localized_format!("停止已提交，但目录刷新失败：{problem}。请刷新目录。", "Stop was submitted, but the catalog refresh failed: {problem}. Refresh the catalog."));
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
                        localized_format!("未能确认保存或撤销结果：{problem}。请先刷新；创建草稿保留相同 ID，核实后可重试。", "Could not confirm the save or revocation result: {problem}. Refresh first; new drafts retain the same ID so you can check before retrying.")
                    } else { problem.to_string() });
                }
            }
            busy.set(false);
        });
    });
    let loaded_refresh = StoredValue::new(None::<u64>);
    Effect::new(move |_| {
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
        <div class="content-grid">
            <section class="list-pane" aria-label=move || t("服务目录", "Service catalog")>
                <div class="section-heading"><div><h2>{move || t("服务目录", "Service catalog")}</h2><p>{move || t("保存入口配置，由主机上的用户单独批准目标。", "Save ingress configuration here. The user on the host separately approves the target.")}</p></div>
                    <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| { editor.set(Some(Editor::new())); confirmation.set(None); }>{move || t("新建服务", "New service")}</button>
                </div>
                <div class="records" aria-live="polite">
                    {move || page.get().map(|value| if value.services.is_empty() {
                        view! { <p class="empty-state">{move || t("尚无服务。创建配置以选择主机、入口和访问来源。", "No services yet. Create a configuration to choose a host, ingress, and allowed sources.")}</p> }.into_any()
                    } else {
                        value.services.into_iter().map(|service| {
                            let edit = service.clone();
                            let revoke = service.clone();
                            let status = approval_label(service.approval);
                            let publication_status = publication_label(service.publication);
                            let ingress = ingress_label(&service.definition.requested_ingress);
                            let revoked = service.approval == ServiceApprovalState::Revoked;
                            let stop_publication = StoredValue::new((service.id.clone(), service.revision));
                            view! { <article class="policy-form">
                                <div class="section-heading"><div><h3>{service.definition.name.clone()}</h3><p>{ingress}</p></div><span class="record-status">{publication_status}</span></div>
                                <p>{status} {move || t(" · 版本 ", " · Revision ")} {service.revision}</p>
                                <p class="muted">{move || t("主机 ", "Host ")} <code>{service.definition.host_device_id.clone()}</code></p>
                                <Show when=move || service.publication != ServicePublicationStatus::NotPublished>
                                    <button class="danger" type="button" disabled=move || busy.get() on:click=move |_| { let (id, revision) = stop_publication.get_value(); submit.run(Command::StopPublication { id, revision }); }>{move || t("停止发布", "Stop publication")}</button>
                                </Show>
                                <button class="secondary" type="button" disabled=move || busy.get() || revoked on:click=move |_| { editor.set(Some(Editor::from_view(&edit))); confirmation.set(None); }>{move || t("编辑配置", "Edit configuration")}</button>
                                <button class="danger" type="button" disabled=move || busy.get() || revoked on:click=move |_| confirmation.set(Some(revoke.clone()))>{move || t("撤销", "Revoke")}</button>
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
                    <div class="policy-form" role="alert">
                        <h3>{move || t("撤销此服务？", "Revoke this service?")}</h3><p>{move || confirmation.with(|v| v.as_ref().map(|v| v.definition.name.clone()).unwrap_or_default())}</p>
                        <p>{move || t("目标批准将失效，恢复使用需要重新配置和批准。", "Target approval will expire. Reconfigure and approve the service before using it again.")}</p>
                        <button class="danger" type="button" disabled=move || busy.get() on:click=move |_| {
                            if let Some(view) = confirmation.get_untracked() { submit.run(Command::Revoke { id: view.id, revision: view.revision }); confirmation.set(None); }
                        }>{move || t("确认撤销", "Confirm revocation")}</button>
                        <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| confirmation.set(None)>{move || t("取消", "Cancel")}</button>
                    </div>
                </Show>
            </section>
            <aside class="detail-pane" aria-label=move || t("入口配置", "Ingress configuration")>
                <Show when=move || editor.with(Option::is_some) fallback=|| view! { <h2>{move || t("选择或创建服务", "Select or create a service")}</h2><p>{move || t("目标地址只在主机本机批准时选择。", "Target addresses are chosen only during local approval on the host.")}</p> }>
                    <form class="policy-form" on:submit=save>
                        <h2>{move || t("入口配置", "Ingress configuration")}</h2><p>{move || t("修改配置会使原目标批准失效。", "Changing the configuration invalidates the previous target approval.")}</p>
                        <fieldset class="service-fields" disabled=move || busy.get()>
                            {field(editor, Field::Name, "服务名称", "Service name", 128)}
                            {field(editor, Field::Host, "主机设备 ID", "Host device ID", 36)}
                            {field(editor, Field::Edge, "边缘节点 ID", "Edge node ID", 36)}
                            <label>{move || t("协议", "Protocol")}<select prop:value=move || editor.with(|v| v.as_ref().map(|v| v.protocol.clone()).unwrap_or_default()) on:change=move |event| editor.update(|v| if let Some(v) = v { v.protocol = event_target_value(&event); })>
                                <option value="http">"HTTP"</option><option value="https">"HTTPS"</option><option value="tcp">"TCP"</option><option value="udp">"UDP"</option>
                            </select></label>
                            {field(editor, Field::Ingress, "入口域名或端口", "Ingress domain or port", 253)}
                            <label>{move || t("访问来源（CIDR，每行一项；留空拒绝所有访问）", "Allowed sources (one CIDR per line; leave empty to deny all access)")}
                                <textarea rows="3" maxlength="2048" prop:value=move || editor.with(|v| v.as_ref().map(|v| v.sources.clone()).unwrap_or_default()) on:input=move |event| editor.update(|v| if let Some(v) = v { v.sources = event_target_value(&event); })></textarea>
                            </label>
                            {field(editor, Field::Connections, "最大连接数", "Maximum connections", 3)}
                            {field(editor, Field::Rate, "速率上限（字节/秒）", "Rate limit (bytes/second)", 10)}
                            {field(editor, Field::Bytes, "累计流量上限（字节）", "Total traffic limit (bytes)", 13)}
                            {field(editor, Field::Idle, "空闲超时（秒）", "Idle timeout (seconds)", 3)}
                            <button class="primary" type="submit" disabled=move || busy.get() || editor.with(|v| v.as_ref().is_none_or(Editor::unchanged))>{move || t("保存配置", "Save configuration")}</button>
                            <button class="secondary" type="button" on:click=move |_| editor.set(None)>{move || t("关闭编辑", "Close editor")}</button>
                        </fieldset>
                    </form>
                </Show>
            </aside>
        </div>
    }
}

#[derive(Clone, Copy)]
enum Field {
    Name,
    Host,
    Edge,
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
            Self::Host => &mut editor.host,
            Self::Edge => &mut editor.edge,
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
    view! { <label>{move || t(label, english_label)}<input maxlength=maximum autocomplete="off" required=true
    prop:value=move || editor.with(|editor| editor.as_ref().map(|value| field.value(&mut value.clone()).clone()).unwrap_or_default())
    on:input=move |event| editor.update(|editor| if let Some(editor) = editor { *field.value(editor) = event_target_value(&event); }) /></label> }
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
