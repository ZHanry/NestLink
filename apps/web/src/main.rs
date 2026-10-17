use std::rc::Rc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(target_arch = "wasm32")]
use leptos::mount::mount_to_body;
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::{NetworkPolicy, PolicyUpdate, Principal, RemoteView};
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use nestlink_web::{
    i18n::{self, text as t},
    localized_format,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
mod remote_panel;
#[cfg(target_arch = "wasm32")]
use nestlink_web::{browser_clipboard, browser_files, browser_rpc};

mod account_security_panel;
mod service_quota_panel;
mod services_panel;

#[derive(Clone, PartialEq, Eq)]
struct RemoteTarget {
    id: String,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Trust,
    SignIn,
    Workspace,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Devices,
    Services,
    Quotas,
    Requests,
    Network,
    Security,
    Accounts,
    Audit,
}

impl Section {
    fn title(self) -> &'static str {
        match self {
            Self::Devices => t("设备", "Devices"),
            Self::Services => t("服务发布", "Service publishing"),
            Self::Quotas => t("服务配额", "Service quotas"),
            Self::Requests => t("访问请求", "Access requests"),
            Self::Network => t("网络与节点", "Network and nodes"),
            Self::Security => t("账号与安全", "Account and security"),
            Self::Accounts => t("账号", "Account"),
            Self::Audit => t("审计记录", "Audit log"),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Devices => "devices",
            Self::Services => "services",
            Self::Quotas => "quotas",
            Self::Requests => "requests",
            Self::Network => "network",
            Self::Security => "security",
            Self::Accounts => "accounts",
            Self::Audit => "audit",
        }
    }

    fn from_key(value: &str) -> Self {
        match value {
            "requests" => Self::Requests,
            "services" => Self::Services,
            "quotas" => Self::Quotas,
            "network" => Self::Network,
            "security" => Self::Security,
            "accounts" => Self::Accounts,
            "audit" => Self::Audit,
            _ => Self::Devices,
        }
    }
}

#[derive(Clone, PartialEq)]
struct Record {
    id: String,
    key: String,
    title: String,
    detail: UiCopy,
    status: UiCopy,
    kind: &'static str,
    connectable: bool,
}

#[derive(Clone, PartialEq)]
struct PanelData {
    rows: Vec<Record>,
    empty: UiCopy,
}

/// Cached local labels retain both languages. Changing language only reads
/// these facts; it never refreshes management state or replaces the SDK.
#[derive(Clone, Default, PartialEq)]
struct UiCopy {
    chinese: String,
    english: String,
}

impl UiCopy {
    fn new(chinese: impl Into<String>, english: impl Into<String>) -> Self {
        Self {
            chinese: chinese.into(),
            english: english.into(),
        }
    }

    fn current(&self) -> String {
        if i18n::english() {
            self.english.clone()
        } else {
            self.chinese.clone()
        }
    }
}

impl From<String> for UiCopy {
    fn from(value: String) -> Self {
        Self::new(value.clone(), value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AuditPageInfo {
    next_sequence: u64,
    high_watermark: u64,
    pruned_through: u64,
    history_pruned: bool,
    more: bool,
}

type Api = StoredValue<Option<Rc<futures_util::lock::Mutex<Sdk>>>, LocalStorage>;
type SdkHandle = Rc<futures_util::lock::Mutex<Sdk>>;

struct UiError {
    message: String,
    requires_sign_in: bool,
}

impl From<SdkError> for UiError {
    fn from(problem: SdkError) -> Self {
        let requires_sign_in = match &problem {
            SdkError::SignIn => true,
            SdkError::Api(status, _) => is_auth_status(status.as_u16()),
            _ => false,
        };
        Self {
            message: i18n::sdk_error(&problem).into(),
            requires_sign_in,
        }
    }
}

fn is_auth_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

#[cfg(test)]
mod tests {
    use super::is_auth_status;

    #[test]
    fn only_unauthorized_and_forbidden_statuses_end_the_ui_session() {
        assert!(is_auth_status(401));
        assert!(is_auth_status(403));
        assert!(!is_auth_status(400));
        assert!(!is_auth_status(500));
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start_app() {
    mount_to_body(move || {
        view! { <App /> }
    });
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

#[component]
fn App() -> impl IntoView {
    i18n::initialize();
    #[cfg(target_arch = "wasm32")]
    let origin = web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default();
    #[cfg(not(target_arch = "wasm32"))]
    let origin = String::new();
    let screen = RwSignal::new(Screen::Trust);
    let section = RwSignal::new(Section::Devices);
    let api: Api = StoredValue::new_local(None);
    let principal = RwSignal::new(None::<Principal>);
    let rows = RwSignal::new(Vec::<Record>::new());
    let audit_page = RwSignal::new(None::<AuditPageInfo>);
    let empty_text = RwSignal::new(UiCopy::new(
        "尚无设备。设备注册由已批准的 NestLink 客户端发起。",
        "No devices yet. Register devices from an approved NestLink client.",
    ));
    let selected = RwSignal::new(None::<Record>);
    let policy_revision = RwSignal::new(0_u64);
    let forwarding = RwSignal::new("deny".to_owned());
    let peer_path = RwSignal::new("direct_only".to_owned());
    let ingress = RwSignal::new("disabled".to_owned());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let deployment_id = RwSignal::new(String::new());
    let issuer_key = RwSignal::new(String::new());
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let factor = RwSignal::new(String::new());
    let account_name = RwSignal::new(String::new());
    let account_password = RwSignal::new(String::new());
    let load_revision = RwSignal::new(0_u64);
    let session_revision = RwSignal::new(0_u64);
    let remote_target = RwSignal::new(None::<RemoteTarget>);

    let clear_workspace = Callback::new(move |_: ()| {
        remote_target.set(None);
        principal.set(None);
        rows.set(Vec::new());
        audit_page.set(None);
        empty_text.set(UiCopy::new(
            "尚无设备。设备注册由已批准的 NestLink 客户端发起。",
            "No devices yet. Register devices from an approved NestLink client.",
        ));
        selected.set(None);
        section.set(Section::Devices);
        policy_revision.set(0);
        forwarding.set("deny".to_owned());
        peer_path.set("direct_only".to_owned());
        ingress.set("disabled".to_owned());
        username.set(String::new());
        password.set(String::new());
        factor.set(String::new());
        account_name.set(String::new());
        account_password.set(String::new());
        session_revision.set(session_revision.get_untracked().saturating_add(1));
        load_revision.set(load_revision.get_untracked().saturating_add(1));
    });

    let auth_failure = Callback::new({
        move |sdk: SdkHandle| {
            clear_workspace.run(());
            screen.set(Screen::SignIn);
            error.set(
                t(
                    "当前会话已失效或账号权限已变化，请重新登录。",
                    "Your session ended or account permissions changed. Sign in again.",
                )
                .into(),
            );
            notice.set(String::new());
            busy.set(true);
            spawn_local(async move {
                if let Err(problem) = sdk.lock().await.logout().await {
                    let problem = i18n::sdk_error(&problem);
                    notice.set(localized_format!(
                        "服务器未确认旧会话已撤销：{problem}",
                        "The server did not confirm revocation of the previous session: {problem}"
                    ));
                }
                busy.set(false);
            });
        }
    });

    let password_changed = Callback::new(move |()| {
        clear_workspace.run(());
        screen.set(Screen::SignIn);
        error.set(String::new());
        notice.set(
            t(
                "密码已修改，请使用新密码重新登录。",
                "Password changed. Sign in with your new password.",
            )
            .into(),
        );
    });

    let load = Callback::new({
        move |key: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(sdk) = api.get_value() else {
                clear_workspace.run(());
                screen.set(Screen::SignIn);
                error.set(
                    t(
                        "会话已结束，请重新验证服务器并登录。",
                        "Your session ended. Verify the server and sign in again.",
                    )
                    .into(),
                );
                return;
            };
            let current = Section::from_key(&key);
            section.set(current);
            selected.set(None);
            error.set(String::new());
            notice.set(String::new());
            let revision = load_revision.get_untracked().saturating_add(1);
            load_revision.set(revision);
            let session = session_revision.get_untracked();
            if matches!(
                current,
                Section::Services | Section::Quotas | Section::Security
            ) {
                rows.set(Vec::new());
                audit_page.set(None);
                return;
            }
            busy.set(true);
            let auth_sdk = sdk.clone();
            spawn_local(async move {
                let result = load_records(sdk, current, 0).await;
                if load_revision.get_untracked() != revision
                    || session_revision.get_untracked() != session
                    || screen.get_untracked() != Screen::Workspace
                {
                    return;
                }
                match result {
                    Ok((data, policy, audit)) => {
                        rows.set(data.rows);
                        empty_text.set(data.empty);
                        audit_page.set(audit);
                        if let Some((revision, value)) = policy {
                            policy_revision.set(revision);
                            forwarding.set(value.server_forwarding);
                            peer_path.set(value.peer_path_mode);
                            ingress.set(value.public_ingress);
                        }
                        if rows.with(Vec::is_empty) {
                            selected.set(None);
                        }
                    }
                    Err(problem) if problem.requires_sign_in => {
                        auth_failure.run(auth_sdk);
                        return;
                    }
                    Err(problem) => error.set(problem.message),
                }
                busy.set(false);
            });
        }
    });

    let load_more_auth_failure = auth_failure;
    let load_more_clear_workspace = clear_workspace;
    let load_more_audit = Callback::new(move |_| {
        if busy.get_untracked() || section.get_untracked() != Section::Audit {
            return;
        }
        let Some(page) = audit_page.get_untracked().filter(|page| page.more) else {
            return;
        };
        let Some(sdk) = api.get_value() else {
            load_more_clear_workspace.run(());
            screen.set(Screen::SignIn);
            error.set(
                t(
                    "会话已结束，请重新登录。",
                    "Your session ended. Sign in again.",
                )
                .into(),
            );
            return;
        };
        let revision = load_revision.get_untracked().saturating_add(1);
        load_revision.set(revision);
        let session = session_revision.get_untracked();
        busy.set(true);
        error.set(String::new());
        let auth_sdk = sdk.clone();
        let auth_failure = load_more_auth_failure;
        spawn_local(async move {
            let result = load_records(sdk, Section::Audit, page.next_sequence).await;
            if load_revision.get_untracked() != revision
                || session_revision.get_untracked() != session
                || screen.get_untracked() != Screen::Workspace
                || section.get_untracked() != Section::Audit
            {
                return;
            }
            match result {
                Ok((data, _, next_page)) => {
                    rows.update(|items| items.extend(data.rows));
                    let next_page = next_page.map(|mut next| {
                        next.history_pruned |= page.history_pruned;
                        next.pruned_through = next.pruned_through.max(page.pruned_through);
                        next
                    });
                    audit_page.set(next_page);
                    if let Some(page) = next_page.filter(|page| page.history_pruned) {
                        notice.set(localized_format!("更早的部分审计记录已按保留策略清理（序号至 {}）。", "Earlier audit records were removed under the retention policy (through sequence {}).",
                            page.pruned_through
                        ));
                    }
                }
                Err(problem) if problem.requires_sign_in => {
                    auth_failure.run(auth_sdk);
                    return;
                }
                Err(problem) => error.set(localized_format!(
                    "读取更早审计记录失败：{}",
                    "Could not load earlier audit records: {}",
                    problem.message
                )),
            }
            busy.set(false);
        });
    });

    let verify_origin = origin.clone();
    let display_origin = StoredValue::new_local(origin);
    let verify_server = UnsyncCallback::new(move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        error.set(String::new());
        notice.set(String::new());
        let session = session_revision.get_untracked().saturating_add(1);
        session_revision.set(session);
        load_revision.set(load_revision.get_untracked().saturating_add(1));
        api.set_value(None);
        busy.set(true);
        let deployment = deployment_id.get_untracked().trim().to_owned();
        let key_text = issuer_key.get_untracked().trim().to_owned();
        let server_origin = verify_origin.clone();
        spawn_local(async move {
            let result = URL_SAFE_NO_PAD
                .decode(key_text)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    t(
                        "签发公钥必须是 32 字节的 Base64URL 编码。",
                        "The issuer public key must be 32 bytes encoded as Base64URL.",
                    )
                    .to_owned()
                })
                .and_then(|permit_issuer| {
                    if deployment.is_empty() {
                        Err(t(
                            "请填写管理员提供的部署 ID。",
                            "Enter the deployment ID supplied by your administrator.",
                        )
                        .to_owned())
                    } else {
                        Ok(DeploymentTrust {
                            deployment_id: deployment,
                            permit_issuer,
                        })
                    }
                });
            match result {
                Ok(trust) => match Sdk::connect(&server_origin, trust, false).await {
                    Ok(sdk) => {
                        if session_revision.get_untracked() != session {
                            return;
                        }
                        api.set_value(Some(Rc::new(futures_util::lock::Mutex::new(sdk))));
                        screen.set(Screen::SignIn);
                        notice.set(t("服务器身份与部署信息已匹配；本次仅保存在内存中。", "Server identity matches the approved deployment. It is retained in memory for this session.").into());
                    }
                    Err(problem) => {
                        let problem = i18n::sdk_error(&problem);
                        error.set(localized_format!(
                            "服务器验证失败：{problem}",
                            "Server verification failed: {problem}"
                        ));
                    }
                },
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let sign_in = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        error.set(String::new());
        notice.set(String::new());
        busy.set(true);
        let user = username.get_untracked().trim().to_owned();
        let pass = password.get_untracked();
        let one_time = factor.get_untracked().trim().to_owned();
        let session = session_revision.get_untracked();
        password.set(String::new());
        factor.set(String::new());
        let Some(sdk) = api.get_value() else {
            busy.set(false);
            error.set(
                t(
                    "服务器连接已过期，请重新验证。",
                    "The server connection expired. Verify it again.",
                )
                .into(),
            );
            return;
        };
        spawn_local(async move {
            let result = async {
                let mut sdk = sdk.lock().await;
                sdk.login(
                    user,
                    nestlink_auth::Secret::from_text(pass),
                    (!one_time.is_empty()).then(|| nestlink_auth::Secret::from_text(one_time)),
                )
                .await
                .map_err(UiError::from)?;
                match sdk.me().await {
                    Ok(user) => Ok(user.principal),
                    Err(problem) => {
                        let problem = UiError::from(problem);
                        if let Err(cleanup) = sdk.logout().await {
                            let cleanup = i18n::sdk_error(&cleanup);
                            return Err(UiError {
                                message: localized_format!("{}；服务器未确认刚建立的登录会话已撤销：{cleanup}", "{}; the server did not confirm revocation of the newly created session: {cleanup}",
                                    problem.message
                                ),
                                requires_sign_in: problem.requires_sign_in,
                            });
                        }
                        Err(problem)
                    }
                }
            }
            .await;
            if session_revision.get_untracked() != session {
                return;
            }
            match result {
                Ok(user) => {
                    principal.set(Some(user));
                    screen.set(Screen::Workspace);
                    busy.set(false);
                    load.run(Section::Devices.key().to_owned());
                }
                Err(problem) => {
                    error.set(localized_format!(
                        "登录失败：{}",
                        "Sign-in failed: {}",
                        problem.message
                    ));
                    busy.set(false);
                }
            }
        });
    };

    let sign_out = {
        move |_| {
            if busy.get_untracked() {
                return;
            }
            clear_workspace.run(());
            screen.set(Screen::Trust);
            busy.set(true);
            error.set(String::new());
            if let Some(sdk) = api.get_value() {
                spawn_local(async move {
                    if let Err(problem) = sdk.lock().await.logout().await {
                        let problem = i18n::sdk_error(&problem);
                        error.set(localized_format!(
                            "服务器未确认退出：{problem}",
                            "The server did not confirm sign-out: {problem}"
                        ));
                    }
                    api.set_value(None);
                    busy.set(false);
                });
            } else {
                busy.set(false);
            }
        }
    };

    let change_server = {
        move |_| {
            if busy.get_untracked() {
                return;
            }
            busy.set(true);
            error.set(String::new());
            notice.set(String::new());
            let finish = move |logout_problem: Option<String>| {
                api.set_value(None);
                clear_workspace.run(());
                deployment_id.set(String::new());
                issuer_key.set(String::new());
                screen.set(Screen::Trust);
                if let Some(problem) = logout_problem {
                    error.set(localized_format!("切换服务器前未能确认旧会话已撤销：{problem}", "Could not confirm revocation of the old session before changing servers: {problem}"));
                }
                busy.set(false);
            };
            if let Some(sdk) = api.get_value() {
                spawn_local(async move {
                    let result = sdk.lock().await.logout().await;
                    finish(
                        result
                            .err()
                            .map(|problem| i18n::sdk_error(&problem).to_owned()),
                    );
                });
            } else {
                finish(None);
            }
        }
    };

    let revoke_auth_failure = auth_failure;
    let revoke_clear_workspace = clear_workspace;
    let revoke_selected = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(item) = selected.get_untracked() else {
            return;
        };
        let Some(sdk) = api.get_value() else {
            revoke_clear_workspace.run(());
            screen.set(Screen::SignIn);
            error.set(
                t(
                    "会话已结束，请重新登录。",
                    "Your session ended. Sign in again.",
                )
                .into(),
            );
            return;
        };
        let accepted = confirm_revoke();
        if !accepted {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let item_kind = item.kind;
        let item_id = item.id;
        let current_key = section.get_untracked().key().to_owned();
        let auth_sdk = sdk.clone();
        spawn_local(async move {
            let result = match item_kind {
                "device" => sdk.lock().await.revoke_device(&item_id).await,
                "node" => sdk.lock().await.revoke_node(&item_id).await,
                "account" => sdk.lock().await.disable_account(&item_id).await,
                _ => {
                    busy.set(false);
                    return;
                }
            };
            match result {
                Ok(()) => notice.set(
                    t(
                        "撤销已提交并获服务端确认。",
                        "Revocation was submitted and confirmed by the server.",
                    )
                    .into(),
                ),
                Err(problem) => {
                    let problem = UiError::from(problem);
                    if problem.requires_sign_in {
                        revoke_auth_failure.run(auth_sdk);
                        return;
                    }
                    error.set(localized_format!(
                        "撤销未完成：{}",
                        "Revocation did not complete: {}",
                        problem.message
                    ));
                }
            }
            busy.set(false);
            load.run(current_key);
        });
    };

    let policy_auth_failure = auth_failure;
    let policy_clear_workspace = clear_workspace;
    let save_policy = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            policy_clear_workspace.run(());
            screen.set(Screen::SignIn);
            error.set(
                t(
                    "会话已结束，请重新登录。",
                    "Your session ended. Sign in again.",
                )
                .into(),
            );
            return;
        };
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        let update = PolicyUpdate {
            expected_revision: policy_revision.get_untracked(),
            policy: NetworkPolicy {
                server_forwarding: forwarding.get_untracked(),
                peer_path_mode: peer_path.get_untracked(),
                public_ingress: ingress.get_untracked(),
            },
        };
        if update.policy.server_forwarding == "deny"
            && (update.policy.peer_path_mode != "direct_only"
                || update.policy.public_ingress != "disabled")
        {
            error.set(t("禁止服务器转发时，路径必须设为“仅直连”，公网入口必须关闭。", "When server forwarding is denied, select Direct only and disable public ingress.").into());
            busy.set(false);
            return;
        }
        let auth_sdk = sdk.clone();
        spawn_local(async move {
            match sdk.lock().await.set_policy(update).await {
                Ok(revision) => {
                    notice.set(localized_format!("策略已保存为版本 {revision}。节点仍按各自的应用版本显示状态。", "Policy revision {revision} was saved. Each node still reports the revision it has applied."
                    ));
                    busy.set(false);
                    load.run(Section::Network.key().to_owned());
                }
                Err(problem) => {
                    let problem = UiError::from(problem);
                    if problem.requires_sign_in {
                        policy_auth_failure.run(auth_sdk);
                        return;
                    }
                    error.set(localized_format!(
                        "策略未保存：{}",
                        "Policy was not saved: {}",
                        problem.message
                    ));
                    busy.set(false);
                }
            }
        });
    };

    let account_auth_failure = auth_failure;
    let account_clear_workspace = clear_workspace;
    let create_account = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            account_clear_workspace.run(());
            screen.set(Screen::SignIn);
            error.set(
                t(
                    "会话已结束，请重新登录。",
                    "Your session ended. Sign in again.",
                )
                .into(),
            );
            return;
        };
        let name = account_name.get_untracked().trim().to_owned();
        let pass = account_password.get_untracked();
        account_password.set(String::new());
        busy.set(true);
        error.set(String::new());
        let auth_sdk = sdk.clone();
        spawn_local(async move {
            match sdk
                .lock()
                .await
                .create_account(name, nestlink_auth::Secret::from_text(pass))
                .await
            {
                Ok(_) => {
                    account_name.set(String::new());
                    notice.set(t("账号已创建。", "Account created.").into());
                    busy.set(false);
                    load.run(Section::Accounts.key().to_owned());
                }
                Err(problem) => {
                    let problem = UiError::from(problem);
                    if problem.requires_sign_in {
                        account_auth_failure.run(auth_sdk);
                        return;
                    }
                    error.set(localized_format!(
                        "账号未创建：{}",
                        "Account was not created: {}",
                        problem.message
                    ));
                    busy.set(false);
                }
            }
        });
    };

    view! {
        <LanguageSelector />
        <Show when=move || screen.get() == Screen::Trust>
            <main class="entry-shell">
                <Brand />
                <section class="entry-panel" aria-labelledby="trust-title">
                    <p class="entry-kicker">{move || t("连接到你的 NestLink 部署", "Connect to your NestLink deployment")}</p>
                    <h1 id="trust-title">{move || t("先核验服务器", "Verify your server")}</h1>
                    <p class="muted">{move || t("请从管理员处独立取得部署 ID 和策略签发公钥。浏览器不会仅凭服务器自报信息建立信任。", "Obtain the deployment ID and issuer public key independently from your administrator. Server claims alone do not establish trust.")}</p>
                    <form on:submit=move |event| verify_server.run(event) class="form-stack">
                        <label for="deployment">{move || t("部署 ID", "Deployment ID")}</label>
                        <input id="deployment" autocomplete="off" spellcheck="false" prop:value=move || deployment_id.get() on:input=move |event| deployment_id.set(event_target_value(&event)) />
                        <label for="issuer">{move || t("策略签发公钥（Base64URL）", "Policy issuer public key (Base64URL)")}</label>
                        <textarea id="issuer" rows="2" autocomplete="off" spellcheck="false" prop:value=move || issuer_key.get() on:input=move |event| issuer_key.set(event_target_value(&event))></textarea>
                        <p class="origin-note">{move || t("当前服务器：", "Current server: ")} <code>{move || display_origin.get_value()}</code></p>
                        <button class="primary" type="submit" disabled=move || busy.get()>
                            {move || if busy.get() { t("正在验证…", "Verifying…") } else { t("验证并继续", "Verify and continue") }}
                        </button>
                    </form>
                </section>
                <Feedback error notice />
            </main>
        </Show>

        <Show when=move || screen.get() == Screen::SignIn>
            <main class="entry-shell">
                <Brand />
                <section class="entry-panel" aria-labelledby="signin-title">
                    <p class="entry-kicker">{move || t("服务器身份已核验", "Server identity verified")}</p>
                    <h1 id="signin-title">{move || t("登录 NestLink", "Sign in to NestLink")}</h1>
                    <form on:submit=sign_in class="form-stack">
                        <label for="username">{move || t("账号", "Account")}</label>
                        <input id="username" autocomplete="username" prop:value=move || username.get() on:input=move |event| username.set(event_target_value(&event)) />
                        <label for="password">{move || t("密码", "Password")}</label>
                        <input id="password" type="password" autocomplete="current-password" prop:value=move || password.get() on:input=move |event| password.set(event_target_value(&event)) />
                        <label for="factor">{move || t("TOTP 或恢复码（如已启用）", "TOTP or recovery code (if enabled)")}</label>
                        <input id="factor" type="password" inputmode="text" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" prop:value=move || factor.get() on:input=move |event| factor.set(event_target_value(&event)) />
                        <button class="primary" type="submit" disabled=move || busy.get()>
                            {move || if busy.get() { t("正在登录…", "Signing in…") } else { t("登录", "Sign in") }}
                        </button>
                    </form>
                    <button class="text-button" type="button" disabled=move || busy.get() on:click=change_server>
                        {move || t("更换服务器", "Change server")}
                    </button>
                </section>
                <Feedback error notice />
            </main>
        </Show>

        <Show when=move || screen.get() == Screen::Workspace>
            {move || {
                let user = principal.get();
                let is_admin = user.as_ref().is_some_and(|value| value.is_admin);
                view! {
                    <div class="workspace">
                        <aside class="sidebar">
                            <Brand />
                            <nav aria-label=move || t("主导航", "Main navigation")>
                                <p class="nav-label">{move || t("管理", "Manage")}</p>
                                <NavButton section current=Section::Devices load busy />
                                <NavButton section current=Section::Requests load busy />
                                <NavButton section current=Section::Services load busy />
                                {if is_admin {
                                    view! {
                                        <NavButton section current=Section::Quotas load busy />
                                        <NavButton section current=Section::Network load busy />
                                        <NavButton section current=Section::Accounts load busy />
                                        <NavButton section current=Section::Audit load busy />
                                    }.into_any()
                                } else { ().into_any() }}
                            </nav>
                            <div class="sidebar-foot">
                                <span class="user-name">{user.as_ref().map(|v| v.name.clone()).unwrap_or_default()}</span>
                                <span class="user-role">{move || if is_admin { t("管理员", "Administrator") } else { t("账号", "Account") }}</span>
                                <button class="text-button" type="button" aria-current=move || (section.get() == Section::Security).then_some("page") disabled=move || busy.get() on:click=move |_| load.run(Section::Security.key().to_owned())>{move || t("账号与安全", "Account and security")}</button>
                                <button class="text-button" type="button" on:click=sign_out disabled=move || busy.get()>{move || t("退出登录", "Sign out")}</button>
                            </div>
                        </aside>
                        <main class="content">
                            <header class="page-head">
                                <div>
                                    <p class="origin-note">{move || t("当前部署：", "Current deployment: ")} <code>{move || display_origin.get_value()}</code></p>
                                    <h1>{move || section.get().title()}</h1>
                                </div>
                                <button class="secondary" type="button" on:click=move |_| load.run(section.get_untracked().key().to_owned()) disabled=move || busy.get()>
                                    {move || if busy.get() { t("正在更新…", "Updating…") } else { t("刷新", "Refresh") }}
                                </button>
                            </header>
                            <Feedback error notice />
                            <Show when=move || section.get() == Section::Services>
                                <services_panel::ServicesPanel api session_revision refresh=load_revision auth_failure error notice />
                            </Show>
                            <Show when=move || section.get() == Section::Quotas>
                                <service_quota_panel::ServiceQuotaPanel api session_revision refresh=load_revision auth_failure error notice />
                            </Show>
                            <Show when=move || section.get() == Section::Security>
                                <account_security_panel::AccountSecurityPanel api session_revision refresh=load_revision auth_failure password_changed error notice />
                            </Show>
                            <Show when=move || !matches!(section.get(), Section::Services | Section::Quotas | Section::Security)>
                            <div class="content-grid">
                                <section class="list-pane" aria-label=move || t("当前列表", "Current list")>
                                    {move || (section.get() == Section::Network).then(|| view! {
                                        <form class="policy-form" on:submit=save_policy>
                                            <div class="section-heading">
                                                <div><h2>{move || t("转发策略", "Forwarding policy")}</h2><p>{move || t("版本 ", "Revision ")} {move || policy_revision.get()}</p></div>
                                                <button class="secondary" type="submit" disabled=move || busy.get()>{move || t("保存策略", "Save policy")}</button>
                                            </div>
                                            <label for="forwarding">{move || t("服务器转发", "Server forwarding")}</label>
                                            <select id="forwarding" disabled=move || busy.get() prop:value=move || forwarding.get() on:change=move |event| forwarding.set(event_target_value(&event))>
                                                <option value="deny">{move || t("禁止用户业务转发", "Deny user traffic forwarding")}</option>
                                                <option value="allow">{move || t("允许符合授权的转发", "Allow authorized forwarding")}</option>
                                            </select>
                                            <label for="peer-path">{move || t("远控路径", "Remote access path")}</label>
                                            <select id="peer-path" disabled=move || busy.get() prop:value=move || peer_path.get() on:change=move |event| peer_path.set(event_target_value(&event))>
                                                <option value="direct_only">{move || t("仅直连", "Direct only")}</option>
                                                <option value="direct_preferred">{move || t("直连优先，可中继", "Prefer direct, allow relay")}</option>
                                                <option value="relay_only">{move || t("仅中继", "Relay only")}</option>
                                            </select>
                                            <label for="ingress">{move || t("公网服务入口", "Public service ingress")}</label>
                                            <select id="ingress" disabled=move || busy.get() prop:value=move || ingress.get() on:change=move |event| ingress.set(event_target_value(&event))>
                                                <option value="disabled">{move || t("关闭", "Disabled")}</option>
                                                <option value="enabled">{move || t("启用", "Enabled")}</option>
                                            </select>
                                            <p class="muted">{move || t("提交后立即拒绝新违规请求；在线节点按撤销事件或当前租约边界停止。", "New requests that violate this policy are rejected immediately. Online nodes stop on revocation or when their current lease ends.")}</p>
                                        </form>
                                    })}
                                    {move || (section.get() == Section::Accounts && is_admin).then(|| view! {
                                        <form class="inline-create" on:submit=create_account>
                                            <div><h2>{move || t("创建账号", "Create account")}</h2><p>{move || t("新账号默认不具备管理员权限。", "New accounts do not have administrator permissions by default.")}</p></div>
                                            <label for="new-account">{move || t("账号名", "Account name")}</label>
                                            <input id="new-account" autocomplete="off" disabled=move || busy.get() prop:value=move || account_name.get() on:input=move |event| account_name.set(event_target_value(&event)) />
                                            <label for="new-account-password">{move || t("初始密码", "Initial password")}</label>
                                            <input id="new-account-password" type="password" autocomplete="new-password" disabled=move || busy.get() prop:value=move || account_password.get() on:input=move |event| account_password.set(event_target_value(&event)) />
                                            <button class="secondary" type="submit" disabled=move || busy.get()>{move || t("创建账号", "Create account")}</button>
                                        </form>
                                    })}
                                    <div class="section-heading list-heading">
                                        <div><h2>{move || list_heading(section.get())}</h2><p>{move || localized_format!("{} 项", "{} items", rows.with(Vec::len))}</p></div>
                                    </div>
                                    <div class="records" aria-live="polite">
                                        {move || rows.with(|items| {
                                            if items.is_empty() {
                                                view! { <p class="empty-state">{move || empty_text.get().current()}</p> }.into_any()
                                            } else {
                                                items.iter().map(|item| {
                                                    let row = item.clone();
                                                    let detail = item.detail.clone();
                                                    let status = item.status.clone();
                                                    let active = selected.with(|row| row.as_ref().is_some_and(|v| v.key == item.key));
                                                    view! {
                                                         <button class=if active { "record selected" } else { "record" } type="button" aria-pressed=active disabled=move || busy.get() on:click=move |_| selected.set(Some(row.clone()))>
                                                            <span class="record-main"><strong>{item.title.clone()}</strong><small>{move || detail.current()}</small></span>
                                                            <span class="record-status">{move || status.current()}</span>
                                                        </button>
                                                    }
                                                }).collect_view().into_any()
                                            }
                                        })}
                                    </div>
                                    {move || (section.get() == Section::Audit).then(|| view! {
                                        <div class="audit-pagination" aria-live="polite">
                                            {move || audit_page.get().map(|page| {
                                                let status = if page.history_pruned {
                                                    localized_format!("保留策略已清理到序号 {}；当前最新序号 {}。", "Retention removed records through sequence {}; the latest sequence is {}.", page.pruned_through, page.high_watermark)
                                                } else {
                                                    localized_format!("当前最新审计序号 {}。", "Latest audit sequence: {}.", page.high_watermark)
                                                };
                                                view! { <p class="muted">{status}</p> }
                                            })}
                                            {move || audit_page.get().is_some_and(|page| page.more).then(|| view! {
                                                <button class="secondary" type="button" on:click=move |_| load_more_audit.run(()) disabled=move || busy.get()>
                                                    {move || if busy.get() { t("正在读取…", "Loading…") } else { t("加载更早记录", "Load earlier records") }}
                                                </button>
                                            })}
                                        </div>
                                    })}
                                </section>
                                <aside class="detail-pane" aria-label=move || t("所选项目详情", "Selected item details") aria-live="polite" aria-atomic="true">
                                    {move || if let Some(item) = selected.get() {
                                        let revocable = matches!(item.kind, "device" | "node" | "account");
                                        let detail = item.detail.clone();
                                        let status = item.status.clone();
                                        view! {
                                            <p class="entry-kicker">{move || t("详情", "Details")}</p>
                                            <h2>{item.title.clone()}</h2>
                                            <p class="record-status detail-status">{move || status.current()}</p>
                                            <dl>
                                                <dt>{move || t("说明", "Description")}</dt><dd>{move || detail.current()}</dd>
                                                <dt>{move || t("资源 ID", "Resource ID")}</dt><dd><code>{item.id.clone()}</code></dd>
                                            </dl>
                                            {item.connectable.then(|| {
                                                let host = RemoteTarget { id: item.id.clone(), name: item.title.clone() };
                                                view! {
                                                    <button class="primary" type="button" disabled=move || busy.get() on:click=move |_| remote_target.set(Some(host.clone()))>{move || t("浏览器连接", "Connect in browser")}</button>
                                                }
                                            })}
                                            {revocable.then(|| view! {
                                                <button class="danger" type="button" on:click=revoke_selected disabled=move || busy.get()>{move || t("撤销授权", "Revoke access")}</button>
                                            })}
                                        }.into_any()
                                    } else {
                                        view! { <div class="detail-empty"><BrandMark small=true /><h2>{move || t("选择一项查看详情", "Select an item for details")}</h2><p>{move || t("这里显示服务器返回的当前状态。", "Current state returned by the server appears here.")}</p></div> }.into_any()
                                    }}
                                </aside>
                            </div>
                            </Show>
                        </main>
                    </div>
                }
            }}
        </Show>
        {remote_panel_view(api, remote_target, session_revision)}
    }
}

fn remote_panel_view(
    api: Api,
    target: RwSignal<Option<RemoteTarget>>,
    session_revision: RwSignal<u64>,
) -> AnyView {
    #[cfg(target_arch = "wasm32")]
    {
        view! { <remote_panel::RemotePanel api target session_revision /> }.into_any()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (api, target, session_revision);
        ().into_any()
    }
}

fn confirm_revoke() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| {
                window
                    .confirm_with_message(t(
                        "撤销此对象的当前授权？现有连接会停止。",
                        "Revoke current access for this item? Existing connections will stop.",
                    ))
                    .ok()
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_arch = "wasm32"))]
    false
}

#[component]
fn LanguageSelector() -> impl IntoView {
    view! {
        <div class="language-selector" role="group" aria-label=move || t("显示语言", "Display language")>
            <button class="text-button" type="button" lang="zh-CN"
                aria-pressed=move || (!i18n::english()).to_string()
                on:click=move |_| i18n::set_english(false)>
                "简体中文"
            </button>
            <button class="text-button" type="button" lang="en"
                aria-pressed=move || i18n::english().to_string()
                on:click=move |_| i18n::set_english(true)>
                "English"
            </button>
        </div>
    }
}

#[component]
fn Brand() -> impl IntoView {
    view! {
        <div class="brand" aria-label="NestLink">
            <BrandMark />
            <span>NestLink</span>
        </div>
    }
}

#[component]
fn BrandMark(#[prop(optional)] small: bool) -> impl IntoView {
    view! {
        <svg class=if small { "brand-mark small" } else { "brand-mark" } viewBox="0 0 512 512" aria-hidden="true" focusable="false">
            <rect x="8" y="8" width="496" height="496" rx="116" fill="#7955CF" />
            <polyline points="154,342 154,196 200,150" fill="none" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" stroke-linejoin="round" />
            <polyline points="358,170 358,316 312,362" fill="none" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" stroke-linejoin="round" />
            <line x1="190" y1="190" x2="322" y2="322" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" />
        </svg>
    }
}

#[component]
fn Feedback(error: RwSignal<String>, notice: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="feedback" aria-live="polite">
            <Show when=move || !error.get().is_empty()>
                <p class="error-message" role="alert">{move || error.get()}</p>
            </Show>
            <Show when=move || !notice.get().is_empty()>
                <p class="notice-message">{move || notice.get()}</p>
            </Show>
        </div>
    }
}

#[component]
fn NavButton(
    section: RwSignal<Section>,
    current: Section,
    load: Callback<String>,
    busy: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class=move || if section.get() == current { "nav-item active" } else { "nav-item" }
            aria-current=move || (section.get() == current).then_some("page")
            disabled=move || busy.get()
            on:click=move |_| load.run(current.key().to_owned())
        >
            <span class="nav-marker" aria-hidden="true"></span>{move || current.title()}
        </button>
    }
}

async fn load_records(
    sdk: SdkHandle,
    section: Section,
    audit_after_sequence: u64,
) -> Result<
    (
        PanelData,
        Option<(u64, NetworkPolicy)>,
        Option<AuditPageInfo>,
    ),
    UiError,
> {
    let mut policy = None;
    let mut audit_page = None;
    let data = match section {
        Section::Services | Section::Quotas | Section::Security => PanelData {
            rows: Vec::new(),
            empty: UiCopy::default(),
        },
        Section::Devices => {
            let result = sdk.lock().await.devices().await.map_err(UiError::from)?;
            PanelData {
                rows: result
                    .into_iter()
                    .map(|view| Record {
                        connectable: !view.revoked
                            && view
                                .device
                                .capabilities
                                .iter()
                                .any(|capability| capability == "host"),
                        id: view.device.id.clone(),
                        key: view.device.id.clone(),
                        title: view.device.name,
                        detail: UiCopy::new(
                            format!(
                                "{} / {} 能力 / 路径 {}",
                                view.device.platform,
                                view.device.capabilities.len(),
                                view.device.path_mode
                            ),
                            format!(
                                "{} / {} capabilities / path {}",
                                view.device.platform,
                                view.device.capabilities.len(),
                                view.device.path_mode
                            ),
                        ),
                        status: if view.revoked {
                            UiCopy::new("已撤销", "Revoked")
                        } else {
                            UiCopy::new("可用", "Available")
                        },
                        kind: "device",
                    })
                    .collect(),
                empty: UiCopy::new(
                    "尚无登记设备。请从设备端完成注册与本机批准。",
                    "No registered devices. Complete registration and local approval on the device.",
                ),
            }
        }
        Section::Requests => {
            let result: Vec<RemoteView> = sdk
                .lock()
                .await
                .pending_remote()
                .await
                .map_err(UiError::from)?;
            PanelData {
                rows: result
                    .into_iter()
                    .map(|request| Record {
                        id: request.id.clone(),
                        key: request.id.clone(),
                        title: format!(
                            "{} → {}",
                            short_id(&request.controller_device_id),
                            short_id(&request.host_device_id)
                        ),
                        detail: UiCopy::new(
                            format!(
                                "{} / 策略版本 {} / 连接代次 {}",
                                permission_summary(&request.permissions, false),
                                request.policy_revision,
                                request.connection_generation
                            ),
                            format!(
                                "{} / policy revision {} / connection generation {}",
                                permission_summary(&request.permissions, true),
                                request.policy_revision,
                                request.connection_generation
                            ),
                        ),
                        status: remote_status(&request.status),
                        kind: "request",
                        connectable: false,
                    })
                    .collect(),
                empty: UiCopy::new(
                    "当前没有远控请求。需要设备密钥签名的批准，应在被控设备上完成。",
                    "No remote access requests. Approval signed with the host device key must be completed on that device.",
                ),
            }
        }
        Section::Network => {
            let result = sdk.lock().await.nodes().await.map_err(UiError::from)?;
            let current_policy = sdk.lock().await.policy().await.map_err(UiError::from)?;
            policy = Some((current_policy.revision, current_policy.policy));
            PanelData {
                rows: result
                    .into_iter()
                    .map(|view| Record {
                        id: view.node.id.clone(),
                        key: view.node.id.clone(),
                        title: view.node.name,
                        detail: UiCopy::new(
                            format!(
                                "{} 个连接上限 / {} B/s",
                                view.node.max_connections, view.node.bytes_per_second
                            ),
                            format!(
                                "Up to {} connections / {} B/s",
                                view.node.max_connections, view.node.bytes_per_second
                            ),
                        ),
                        status: if view.revoked {
                            UiCopy::new("已撤销", "Revoked")
                        } else if view.runtime_id.is_some() {
                            UiCopy::new("在线", "Online")
                        } else {
                            UiCopy::new("等待节点", "Waiting for node")
                        },
                        kind: "node",
                        connectable: false,
                    })
                    .collect(),
                empty: UiCopy::new(
                    "尚未登记数据节点。节点注册和端点绑定需由受管节点完成。",
                    "No data nodes registered. Managed nodes complete their own registration and endpoint binding.",
                ),
            }
        }
        Section::Accounts => {
            let result = sdk.lock().await.accounts().await.map_err(UiError::from)?;
            PanelData {
                rows: result
                    .into_iter()
                    .map(|account| Record {
                        id: account.id.clone(),
                        key: account.id.clone(),
                        title: account.name,
                        detail: UiCopy::new(
                            format!(
                                "{} / TOTP {}",
                                if account.is_admin {
                                    "管理员"
                                } else {
                                    "普通账号"
                                },
                                if account.totp_enabled {
                                    "已启用"
                                } else {
                                    "未启用"
                                }
                            ),
                            format!(
                                "{} / TOTP {}",
                                if account.is_admin {
                                    "Administrator"
                                } else {
                                    "Standard account"
                                },
                                if account.totp_enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }
                            ),
                        ),
                        status: if account.disabled {
                            UiCopy::new("已停用", "Deactivated")
                        } else {
                            UiCopy::new("可登录", "Sign-in enabled")
                        },
                        kind: "account",
                        connectable: false,
                    })
                    .collect(),
                empty: UiCopy::new("没有可显示的账号。", "No accounts to display."),
            }
        }
        Section::Audit => {
            let result = sdk
                .lock()
                .await
                .audit_page(audit_after_sequence, 50)
                .await
                .map_err(UiError::from)?;
            audit_page = Some(AuditPageInfo {
                next_sequence: result.next_sequence,
                high_watermark: result.high_watermark,
                pruned_through: result.pruned_through,
                history_pruned: result.history_pruned,
                more: result.more,
            });
            PanelData {
                rows: result
                    .entries
                    .into_iter()
                    .map(|entry| Record {
                        id: entry.resource_id,
                        key: entry.sequence.to_string(),
                        title: entry.event,
                        detail: UiCopy::new(
                            format!(
                                "{} / 安全代次 {} / 序号 {}",
                                actor_summary(&entry.actor, false),
                                entry.security_epoch,
                                entry.sequence
                            ),
                            format!(
                                "{} / security epoch {} / sequence {}",
                                actor_summary(&entry.actor, true),
                                entry.security_epoch,
                                entry.sequence
                            ),
                        ),
                        status: format_time(entry.created_at_unix_ms),
                        kind: "audit",
                        connectable: false,
                    })
                    .collect(),
                empty: UiCopy::new(
                    "当前保留窗口内没有审计记录。",
                    "No audit records in the current retention window.",
                ),
            }
        }
    };
    Ok((data, policy, audit_page))
}

fn list_heading(section: Section) -> &'static str {
    match section {
        Section::Devices => t("已登记设备", "Registered devices"),
        Section::Services => t("服务目录", "Service catalog"),
        Section::Quotas => t("服务配额", "Service quotas"),
        Section::Requests => t("近期请求", "Recent requests"),
        Section::Network => t("数据节点", "Data nodes"),
        Section::Security => t("账号与安全", "Account and security"),
        Section::Accounts => t("账号目录", "Accounts"),
        Section::Audit => t("最近事件", "Recent events"),
    }
}

fn short_id(value: &str) -> String {
    value.get(..8).unwrap_or(value).to_owned()
}

fn copy_language(english: bool, chinese: &'static str, english_text: &'static str) -> &'static str {
    if english { english_text } else { chinese }
}

fn permission_summary(values: &[i32], english: bool) -> String {
    values
        .iter()
        .map(|value| match value {
            1 => copy_language(english, "观看画面", "View screen"),
            2 => copy_language(english, "控制输入", "Control input"),
            3 => copy_language(english, "音频", "Audio"),
            4 => copy_language(english, "读取文件", "Read files"),
            5 => copy_language(english, "写入文件", "Write files"),
            6 => copy_language(english, "读取剪贴板", "Read clipboard"),
            7 => copy_language(english, "写入剪贴板", "Write clipboard"),
            _ => copy_language(english, "其他权限", "Other permission"),
        })
        .collect::<Vec<_>>()
        .join(if english { ", " } else { "、" })
}

fn actor_summary(actor: &nestlink_protocol::api::AuditActor, english: bool) -> String {
    match actor {
        nestlink_protocol::api::AuditActor::Legacy => {
            copy_language(english, "历史记录", "Historical record").into()
        }
        nestlink_protocol::api::AuditActor::LocalOperator => {
            copy_language(english, "本机操作员", "Local operator").into()
        }
        nestlink_protocol::api::AuditActor::Unauthenticated => {
            copy_language(english, "未认证请求", "Unauthenticated request").into()
        }
        nestlink_protocol::api::AuditActor::Management { account_id, .. } => {
            format!(
                "{} {}",
                copy_language(english, "管理账号", "Management account"),
                short_id(account_id)
            )
        }
        nestlink_protocol::api::AuditActor::Device { device_id, .. } => {
            format!(
                "{} {}",
                copy_language(english, "设备", "Device"),
                short_id(device_id)
            )
        }
        nestlink_protocol::api::AuditActor::DeviceCredential { device_id, .. } => {
            format!(
                "{} {}",
                copy_language(english, "设备凭据", "Device credential"),
                short_id(device_id)
            )
        }
        nestlink_protocol::api::AuditActor::Node { node_id, .. } => {
            format!(
                "{} {}",
                copy_language(english, "节点", "Node"),
                short_id(node_id)
            )
        }
    }
}

fn format_time(unix_ms: u64) -> UiCopy {
    UiCopy::new(
        format!("Unix 毫秒 {unix_ms}"),
        format!("Unix milliseconds {unix_ms}"),
    )
}

fn remote_status(status: &str) -> UiCopy {
    match status {
        "pending" => UiCopy::new("等待批准", "Pending approval"),
        "approved" => UiCopy::new("已批准", "Approved"),
        "rejected" | "denied" => UiCopy::new("已拒绝", "Denied"),
        "revoked" => UiCopy::new("已撤销", "Revoked"),
        "closed" => UiCopy::new("已结束", "Closed"),
        "expired" => UiCopy::new("已到期", "Expired"),
        _ => status.to_owned().into(),
    }
}
