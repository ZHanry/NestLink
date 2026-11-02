//! Read-only onboarding through the existing pinned SDK and production pages.
use super::{Api, SdkHandle, Section, UiCopy};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::ServicePublicationStatus;
use nestlink_sdk::{Sdk, SdkError};
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Remote,
    Private,
    Public,
    Network,
}

impl Purpose {
    fn parse(value: &str) -> Self {
        match value {
            "private" => Self::Private,
            "public" => Self::Public,
            "network" => Self::Network,
            _ => Self::Remote,
        }
    }
}

#[derive(Clone)]
struct Check {
    title: UiCopy,
    detail: UiCopy,
    failed: bool,
}

impl Check {
    fn result(title: UiCopy, result: Result<UiCopy, SdkError>) -> Result<Self, SdkError> {
        match result {
            Err(error) if matches!(&error, SdkError::SignIn)
                || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401) => Err(error),
            Err(error) => Ok(Self { title, detail: sdk_error(&error).to_string().into(), failed: true }),
            Ok(detail) => Ok(Self { title, detail, failed: false }),
        }
    }
}

async fn read_checks(sdk: &Sdk, purpose: Purpose) -> Result<Vec<Check>, SdkError> {
    // Re-read the account before any optional administrator-only operation.
    // The cached principal alone cannot prove the role is still current.
    let account = sdk.me().await?;
    if sdk.principal().is_none_or(|p| p.account_id != account.principal.account_id) {
        return Err(SdkError::Trust);
    }
    let mut checks = vec![Check {
        title: UiCopy::new("管理连接与账号", "Management connection and account"),
        detail: UiCopy::new("已通过核验的服务器读取当前账号。", "Current account read through the verified server."),
        failed: false,
    }];
    checks.push(Check::result(UiCopy::new("设备登记", "Device enrollment"), sdk.devices().await.map(|devices| {
        let enrolled = devices.iter().filter(|view| !view.revoked).count();
        UiCopy::new(format!("服务器返回 {enrolled} 台未撤销设备；在线和可达状态需在实际会话中确认。"), format!("The server returned {enrolled} non-revoked devices; availability and reachability require an actual session."))
    }))?);
    if purpose == Purpose::Remote || purpose == Purpose::Network {
        checks.push(Check::result(UiCopy::new("原生 STUN 配置", "Native STUN configuration"), sdk.native_discovery_config().await.map(|config| {
            let count = config.stun_servers.len();
            UiCopy::new(format!("部署返回 {count} 个地址；此读取未测试 UDP 可达性，也未更改本机批准。"), format!("The deployment returned {count} endpoints. This read does not test UDP reachability or change local consent."))
        }))?);
    }
    if purpose == Purpose::Private || purpose == Purpose::Public {
        checks.push(Check::result(UiCopy::new("服务发布记录", "Service publication records"), sdk.services(None, 50).await.map(|page| {
            let count = page.services.len();
            let published = page.services.iter().filter(|service| service.publication == ServicePublicationStatus::Published).count();
            UiCopy::new(format!("本页 {count} 项服务中，服务器记录 {published} 项已发布；更多记录：{}。这不是外网或本机目标可达性检查。", if page.more { "有" } else { "无" }), format!("The server records {published} published services among {count} on this page; more records: {}. This does not check public ingress or local target reachability.", if page.more { "yes" } else { "no" }))
        }))?);
    }
    if account.principal.is_admin && purpose != Purpose::Private {
        checks.push(Check::result(UiCopy::new("部署策略", "Deployment policy"), sdk.policy().await.map(|view| {
            let policy = view.policy;
            UiCopy::new(format!("版本 {}：转发 {}，远控路径 {}，公网入口 {}。保存的策略仍需本次业务和双方设备批准。", view.revision, policy.server_forwarding, policy.peer_path_mode, policy.public_ingress), format!("Revision {}: forwarding {}, remote paths {}, public ingress {}. Saved policy still requires session and device approvals.", view.revision, policy.server_forwarding, policy.peer_path_mode, policy.public_ingress))
        }))?);
    }
    Ok(checks)
}

#[component]
pub(super) fn SetupPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    load: Callback<String>,
) -> impl IntoView {
    let purpose = RwSignal::new(Purpose::Remote);
    let reports = RwSignal::new(Vec::<Check>::new());
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let revision = RwSignal::new(0_u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    Effect::new(move |_| {
        let _ = session_revision.get();
        revision.update(|value| *value = value.saturating_add(1));
        reports.set(Vec::new());
        problem.set(String::new());
        busy.set(false);
    });
    let read = Callback::new(move |()| {
        if busy.get_untracked() { return; }
        let Some(sdk) = api.get_value() else { return; };
        let request = revision.get_untracked().saturating_add(1);
        revision.set(request);
        let session = session_revision.get_untracked();
        let mode = purpose.get_untracked();
        busy.set(true);
        reports.set(Vec::new());
        problem.set(String::new());
        let alive = alive.clone();
        spawn_local(async move {
            let client = sdk.lock().await;
            let result = read_checks(&client, mode).await;
            drop(client);
            if !alive.load(Ordering::Acquire) || session_revision.try_get_untracked() != Some(session)
                || revision.try_get_untracked() != Some(request) { return; }
            busy.set(false);
            match result {
                Ok(values) => reports.set(values),
                Err(SdkError::SignIn) => auth_failure.run(sdk),
                Err(SdkError::Api(status, _)) if status.as_u16() == 401 => auth_failure.run(sdk),
                Err(error) => problem.set(sdk_error(&error).to_string()),
            }
        });
    });
    view! {
        <details class="setup-guide" aria-label=move || t("配置向导", "Setup guide")>
            <summary>{move || t("配置向导与实际状态", "Setup guide and actual state")}</summary>
            <section class="form-stack" aria-busy=move || busy.get().to_string()>
                <p class="muted">{move || t("选择用途，再读取当前状态。这里使用已验证的管理连接；读取配置不会启用中继、虚拟网卡或公网发布。", "Choose a purpose, then read current state. Checks use the verified management connection. Reading configuration does not enable relays, virtual adapters or public publishing.")}</p>
                <label for="setup-purpose">{move || t("用途", "Purpose")}</label>
                <select id="setup-purpose" disabled=move || busy.get() on:change=move |event| {
                    purpose.set(Purpose::parse(&event_target_value(&event)));
                    revision.update(|value| *value = value.saturating_add(1));
                    reports.set(Vec::new());
                    problem.set(String::new());
                }>
                    <option value="remote">{move || t("远程桌面", "Remote desktop")}</option>
                    <option value="private">{move || t("私有服务", "Private services")}</option>
                    <option value="public">{move || t("公网发布", "Public publishing")}</option>
                    <option value="network">{move || t("空间与虚拟网络", "Spaces and virtual networks")}</option>
                </select>
                <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| read.run(())>{move || if busy.get() { t("正在读取…", "Reading…") } else { t("读取当前状态", "Read current state") }}</button>
                <p role="alert" hidden=move || problem.get().is_empty()>{move || problem.get()}</p>
                <ul aria-label=move || t("实际读取结果", "Actual readback results")>
                    {move || reports.get().into_iter().map(|check| view! { <li><strong>{check.title.current()}</strong><p class:danger=check.failed>{check.detail.current()}</p></li> }).collect_view()}
                </ul>
                <p class="muted">{move || t("结果来自最近一次读取，不代表持续健康。尚未测试的连通性保持未知；保存、主机批准、建立连接和公网可达分别确认。", "Results reflect the last read, not continuous health. Untested reachability remains unknown. Saving, host approval, connection establishment and public reachability are confirmed separately.")}</p>
                {move || match purpose.get() {
                    Purpose::Remote => view! {
                        <p>{move || t("先登记双方设备并批准本次权限。浏览器使用 WebRTC：实际会话才会检查 ICE、STUN 和获准的 TURN；原生客户端也可在本机设置中选择仅直连或批准指定中继。默认远控无需虚拟网卡。", "Enroll both devices and approve this session's permissions. The browser uses WebRTC; ICE, STUN and authorized TURN are checked during an actual session. Native clients can choose direct-only paths or approve specified relays in local settings. Ordinary remote access needs no virtual adapter.")}</p>
                        <button class="secondary" type="button" on:click=move |_| load.run(Section::Desktop.key().to_owned())>{move || t("选择远控设备", "Choose remote device")}</button>
                    }.into_any(),
                    Purpose::Private | Purpose::Public => view! {
                        <p>{move || if purpose.get() == Purpose::Private { t("在服务中明确选择私有范围、允许的设备和固定目标，再到主机批准。私有 Web 入口还需独立 HTTPS origin；空间成员资格不会授予本机端口权限。", "Choose private exposure, permitted devices and a fixed target in Services, then approve on the host. Private web entry requires a separate HTTPS origin. Space membership does not grant local port access.") } else { t("显式选择公网范围和入口，在主机批准固定目标，再核对实际发布状态。域名、TLS 和公网入口可达必须在部署后确认。", "Explicitly choose public exposure and ingress, approve the fixed target on the host, then check actual publication state. Domain, TLS and public reachability must be confirmed after deployment.") }}</p>
                        <button class="secondary" type="button" on:click=move |_| load.run(Section::Services.key().to_owned())>{move || t("打开服务配置", "Open service configuration")}</button>
                    }.into_any(),
                    Purpose::Network => view! {
                        <p>{move || t("在账号与安全中管理自己的空间和邀请；网络管理员在网络与节点配置成员、地址、名称、子网和 WireGuard。系统 TUN 和转发需要运行设备另行批准并启用。浏览器只管理配置，不安装虚拟网卡。", "Manage your spaces and invitations in Account and security. Network administrators configure membership, addresses, names, subnets and WireGuard in Network and nodes. System TUN and forwarding require separate consent and activation on the runtime device. The browser manages configuration and does not install virtual adapters.")}</p>
                        <button class="secondary" type="button" on:click=move |_| load.run(Section::Security.key().to_owned())>{move || t("打开我的空间", "Open my spaces")}</button>
                    }.into_any(),
                }}
            </section>
        </details>
    }
}
