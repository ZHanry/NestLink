use std::rc::Rc;

#[cfg(target_arch = "wasm32")]
use leptos::mount::mount_to_body;
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::{NetworkPolicy, PolicyUpdate, Principal, RemoteView};
use nestlink_sdk::{Sdk, SdkError};
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
    Restoring,
    Trust,
    SignIn,
    Workspace,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Desktop,
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
            Self::Desktop => t("远程桌面", "Remote desktop"),
            Self::Devices => t("设备管理", "Devices"),
            Self::Services => t("内网穿透", "Tunnels"),
            Self::Quotas => t("服务配额", "Service quotas"),
            Self::Requests => t("连接记录", "Access requests"),
            Self::Network => t("网络与节点", "Network and nodes"),
            Self::Security => t("账号与安全", "Account and security"),
            Self::Accounts => t("账号", "Account"),
            Self::Audit => t("审计记录", "Audit log"),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
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
            "desktop" => Self::Desktop,
            "devices" => Self::Devices,
            "requests" => Self::Requests,
            "services" => Self::Services,
            "quotas" => Self::Quotas,
            "network" => Self::Network,
            "security" => Self::Security,
            "accounts" => Self::Accounts,
            "audit" => Self::Audit,
            _ => Self::Desktop,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Desktop => t(
                "选择设备，在浏览器中打开远程桌面。",
                "Choose a device and open its desktop in your browser.",
            ),
            Self::Services => t(
                "将内网服务发布到指定入口，管理访问来源与运行状态。",
                "Publish an internal service through an assigned ingress and manage its access.",
            ),
            Self::Devices => t(
                "管理已登记设备和授权。新增被控主机请使用 Windows 客户端。",
                "Manage registered devices and access. Add a host from the Windows client.",
            ),
            Self::Requests => t(
                "查看远程访问请求及其授权状态。",
                "Review remote access requests and their authorization.",
            ),
            Self::Quotas => t(
                "按账号、设备、节点和服务查看用量并设置限制。",
                "Review and limit usage by account, device, node, or service.",
            ),
            Self::Network => t(
                "管理数据节点、连接路径和服务发布策略。",
                "Manage data nodes, connection paths, and publishing policy.",
            ),
            Self::Security => t(
                "管理当前账号的密码和登录期限。",
                "Manage your password and sign-in expiry.",
            ),
            Self::Accounts => t("管理账号及其访问权限。", "Manage accounts and access."),
            Self::Audit => t(
                "查看服务器保留的操作记录。",
                "Review operations retained by the server.",
            ),
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
    status == 401
}

#[cfg(test)]
mod tests {
    use super::is_auth_status;

    #[test]
    fn permission_denial_keeps_other_sessions_and_the_current_login() {
        assert!(is_auth_status(401));
        assert!(!is_auth_status(403));
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
    let screen = RwSignal::new(Screen::Restoring);
    let section = RwSignal::new(Section::Desktop);
    let api: Api = StoredValue::new_local(None);
    let principal = RwSignal::new(None::<Principal>);
    // Token renewal changes expiry, not workspace identity. Keep forms and
    // pointer targets mounted while the same signed-in account is refreshed.
    let workspace_user = Memo::new(move |_| {
        principal.with(|user| {
            user.as_ref()
                .map(|user| (user.account_id.clone(), user.name.clone(), user.is_admin))
        })
    });
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

    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let remember_login = RwSignal::new(false);

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
        section.set(Section::Desktop);
        policy_revision.set(0);
        forwarding.set("deny".to_owned());
        peer_path.set("direct_only".to_owned());
        ingress.set("disabled".to_owned());
        username.set(String::new());
        password.set(String::new());

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
                    notice.set(nestlink_web::localized_detail!(
                        "服务器未确认旧会话已撤销：{}",
                        "The server did not confirm revocation of the previous session: {}",
                        problem
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

    // Every page owns its own SDK and rotating refresh token. Background
    // renewal never reads another tab's cookies as its session identity.
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let revision = session_revision.get();
        if screen.get() != Screen::Workspace {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        spawn_local(async move {
            loop {
                gloo_timers::future::TimeoutFuture::new(15_000).await;
                if session_revision.try_get_untracked() != Some(revision)
                    || screen.try_get_untracked() != Some(Screen::Workspace)
                {
                    break;
                }
                let mut client = sdk.lock().await;
                if session_revision.try_get_untracked() != Some(revision) {
                    break;
                }
                let now = (js_sys::Date::now() / 1000.0) as u64;
                let due = client
                    .principal()
                    .is_some_and(|user| user.access_expires <= now.saturating_add(60));
                if !due {
                    continue;
                }
                let result = client.refresh().await;
                let user = client.principal().cloned();
                drop(client);
                if session_revision.try_get_untracked() != Some(revision) {
                    break;
                }
                if result.is_ok() {
                    let _ = principal.try_set(user);
                } else if user.is_none() {
                    auth_failure.run(sdk.clone());
                    break;
                }
            }
        });
    });

    let load = Callback::new({
        move |key: String| {
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
            let navigating = current != section.get_untracked();
            busy.set(false);
            section.set(current);
            #[cfg(target_arch = "wasm32")]
            if let Some(storage) =
                web_sys::window().and_then(|window| window.session_storage().ok().flatten())
            {
                let _ = storage.set_item("nestlink.management-section", current.key());
            }
            if navigating {
                selected.set(None);
                rows.set(Vec::new());
                audit_page.set(None);
                error.set(String::new());
                notice.set(String::new());
            }
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
                        selected.update(|chosen| {
                            if let Some(previous) = chosen.as_ref() {
                                *chosen = data
                                    .rows
                                    .iter()
                                    .find(|row| row.key == previous.key)
                                    .cloned();
                            }
                        });
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
                    rows.update(|items| {
                        items.extend(data.rows);
                        if items.len() > 500 {
                            items.drain(..items.len() - 500);
                        }
                    });
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
                Err(problem) => error.set(nestlink_web::localized_detail!(
                    "读取更早审计记录失败：{}",
                    "Could not load earlier audit records: {}",
                    problem.message
                )),
            }
            busy.set(false);
        });
    });

    #[cfg(target_arch = "wasm32")]
    {
        let restore_origin = origin.clone();
        spawn_local(async move {
            let saved = browser_session_selector(None);
            if let Some(saved) = saved {
                match Sdk::connect_origin(&restore_origin, false).await {
                    Ok(mut sdk) => match sdk.restore_browser_session(saved).await {
                        Ok(()) => {
                            principal.set(sdk.principal().cloned());
                            api.set_value(Some(Rc::new(futures_util::lock::Mutex::new(sdk))));
                            screen.set(Screen::Workspace);
                            let page = web_sys::window()
                                .and_then(|window| window.session_storage().ok().flatten())
                                .and_then(|storage| {
                                    storage
                                        .get_item("nestlink.management-section")
                                        .ok()
                                        .flatten()
                                })
                                .map(|key| Section::from_key(&key))
                                .unwrap_or(Section::Desktop);
                            load.run(page.key().to_owned());
                            return;
                        }
                        Err(problem) => error.set(i18n::sdk_error(&problem).into()),
                    },
                    Err(problem) => error.set(i18n::sdk_error(&problem).into()),
                }
            }
            screen.set(Screen::Trust);
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    screen.set(Screen::Trust);
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
        let server_origin = verify_origin.clone();
        spawn_local(async move {
            match Sdk::connect_origin(&server_origin, false).await {
                Ok(mut sdk) => {
                    #[cfg(target_arch = "wasm32")]
                    if let Some(saved) = browser_session_selector(None) {
                        match sdk.restore_browser_session(saved).await {
                            Ok(()) => {
                                if session_revision.get_untracked() != session {
                                    return;
                                }
                                principal.set(sdk.principal().cloned());
                                api.set_value(Some(Rc::new(futures_util::lock::Mutex::new(sdk))));
                                screen.set(Screen::Workspace);
                                busy.set(false);
                                load.run(Section::Desktop.key().to_owned());
                                return;
                            }
                            Err(problem)
                                if matches!(problem, SdkError::SignIn)
                                    || matches!(&problem, SdkError::Api(status, _) if status.as_u16() == 401) =>
                            {
                                browser_session_selector(Some(None));
                            }
                            Err(problem) => {
                                error.set(i18n::sdk_error(&problem).into());
                                busy.set(false);
                                return;
                            }
                        }
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    let _ = &mut sdk;
                    if session_revision.get_untracked() != session {
                        return;
                    }
                    api.set_value(Some(Rc::new(futures_util::lock::Mutex::new(sdk))));
                    screen.set(Screen::SignIn);
                    notice.set(t("服务器已连接。", "Connected to server.").into());
                }
                Err(problem) => error.set(i18n::sdk_error(&problem).to_string()),
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

        let session = session_revision.get_untracked();
        password.set(String::new());

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
                    None,
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
                                message: {
                                    let detail = nestlink_web::localized_detail!("服务器未确认刚建立的登录会话已撤销：{}", "The server did not confirm revocation of the newly created session: {}", cleanup);
                                    i18n::join_feedback(&[problem.message, detail], "; ")
                                },
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
                    #[cfg(target_arch = "wasm32")]
                    {
                        browser_session_selector(Some(Some(user.session_id.clone())));
                        if let Some(storage) = web_sys::window()
                            .and_then(|window| window.local_storage().ok().flatten())
                        {
                            if remember_login.get_untracked() {
                                let _ = storage
                                    .set_item("nestlink.remembered-session", &user.session_id);
                            } else {
                                let _ = storage.remove_item("nestlink.remembered-session");
                            }
                        }
                    }
                    principal.set(Some(user));
                    screen.set(Screen::Workspace);
                    busy.set(false);
                    load.run(Section::Desktop.key().to_owned());
                }
                Err(problem) => {
                    error.set(nestlink_web::localized_detail!(
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
            #[cfg(target_arch = "wasm32")]
            browser_session_selector(Some(None));
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
                        error.set(nestlink_web::localized_detail!(
                            "服务器未确认退出：{}",
                            "The server did not confirm sign-out: {}",
                            problem
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

                screen.set(Screen::Trust);
                if let Some(problem) = logout_problem {
                    error.set(nestlink_web::localized_detail!("切换服务器前未能确认旧会话已撤销：{}", "Could not confirm revocation of the old session before changing servers: {}", problem));
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
                    error.set(nestlink_web::localized_detail!(
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
                    error.set(nestlink_web::localized_detail!(
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
                    error.set(nestlink_web::localized_detail!(
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
        <div class="app-topbar"><span>{move || t("内网穿透 + 远程桌面", "Tunnels + remote desktop")}</span><LanguageSelector /></div>
        <Show when=move || screen.get() == Screen::Restoring><main class="entry-shell"><Brand /><section class="entry-panel"><h1>{move || t("正在恢复登录…", "Restoring your session…")}</h1><p class="muted">{move || t("正在核对服务器和管理会话。", "Verifying the server and management session.")}</p></section></main></Show>
            <Show when=move || screen.get() == Screen::Trust>
            <main class="entry-shell">
                <Brand />
                <section class="entry-panel" aria-labelledby="trust-title">
                    <div class="entry-symbol"><WorkspaceIcon kind=Section::Network /></div>
                    <h1 id="trust-title">{move || t("连接服务器", "Connect to server")}</h1>
                    <p class="muted">{move || t("通过 HTTPS 自动读取当前服务器配置，连接后即可登录。", "Discover this server over HTTPS, then sign in with your account.")}</p>
                    <form on:submit=move |event| verify_server.run(event) class="form-stack">
                        <p class="origin-note">{move || t("当前服务器：", "Current server: ")} <code>{move || display_origin.get_value()}</code></p>
                        <button class="primary" type="submit" disabled=move || busy.get()>
                            {move || if busy.get() { t("正在验证…", "Verifying…") } else { t("连接并继续", "Connect and continue") }}
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
                    <p class="origin-note"><code>{move || display_origin.get_value()}</code></p>
                    <form on:submit=sign_in class="form-stack">
                        <label for="username">{move || t("账号", "Account")}</label>
                        <input id="username" autocomplete="username" prop:value=move || username.get() on:input=move |event| username.set(event_target_value(&event)) />
                        <label for="password">{move || t("密码", "Password")}</label>
                        <input id="password" type="password" autocomplete="current-password" prop:value=move || password.get() on:input=move |event| password.set(event_target_value(&event)) />

                        <label class="checkbox-row"><input type="checkbox" prop:checked=move || remember_login.get() on:change=move |event| remember_login.set(event_target_checked(&event)) />{move || t("在此浏览器保持登录（新标签页和重启时恢复此账号）", "Keep this account signed in across new tabs and browser restarts")}</label>
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
                let user = workspace_user.get();
                let is_admin = user.as_ref().is_some_and(|value| value.2);
                view! {
                    <div class="workspace">
                        <aside class="sidebar">
                            <Brand />
                            <nav aria-label=move || t("主导航", "Main navigation")>
                                <p class="nav-label">{move || t("工作区", "Workspace")}</p>
                                <NavButton section current=Section::Desktop load busy />
                                <NavButton section current=Section::Services load busy />
                                <p class="nav-label nav-group">{move || t("资源", "Resources")}</p>
                                <NavButton section current=Section::Devices load busy />
                                <NavButton section current=Section::Requests load busy />
                                {if is_admin {
                                    view! {
                                        <p class="nav-label nav-group">{move || t("管理", "Administration")}</p>
                                        <NavButton section current=Section::Quotas load busy />
                                        <NavButton section current=Section::Network load busy />
                                        <NavButton section current=Section::Accounts load busy />
                                        <NavButton section current=Section::Audit load busy />
                                    }.into_any()
                                } else { ().into_any() }}
                            </nav>
                            <div class="sidebar-foot">
                                <span class="user-name">{user.as_ref().map(|v| v.1.clone()).unwrap_or_default()}</span>
                                <span class="user-role">{move || if is_admin { t("管理员", "Administrator") } else { t("账号", "Account") }}</span>
                                <button class="text-button" type="button" aria-current=move || (section.get() == Section::Security).then_some("page") disabled=move || busy.get() on:click=move |_| load.run(Section::Security.key().to_owned())>{move || t("账号与安全", "Account and security")}</button>
                                <button class="text-button" type="button" on:click=sign_out disabled=move || busy.get()>{move || t("退出登录", "Sign out")}</button>
                            </div>
                        </aside>
                        <main class="content">
                            <header class="page-head">
                                <div>
                                    <h1>{move || section.get().title()}</h1>
                                    <p>{move || section.get().description()}</p>
                                </div>
                                <button class="secondary refresh-button" type="button" on:click=move |_| load.run(section.get_untracked().key().to_owned()) disabled=move || busy.get()>
                                    {move || if busy.get() { t("正在更新…", "Updating…") } else { t("刷新", "Refresh") }}
                                </button>
                            </header>
                            <Feedback error notice />
                            <Show when=move || section.get() == Section::Desktop>
                                <DesktopWorkspace rows selected busy remote_target />
                            </Show>
                            <div hidden=move || section.get() != Section::Services>
                                <services_panel::ServicesPanel api session_revision refresh=load_revision active=Signal::derive(move || section.get() == Section::Services) auth_failure error notice />
                            </div>
                            <div hidden=move || section.get() != Section::Quotas>
                                <service_quota_panel::ServiceQuotaPanel api session_revision refresh=load_revision active=Signal::derive(move || section.get() == Section::Quotas) auth_failure error notice />
                            </div>
                            <Show when=move || section.get() == Section::Security>
                                <account_security_panel::AccountSecurityPanel api session_revision refresh=load_revision auth_failure password_changed error notice />
                            </Show>
                            <Show when=move || !matches!(section.get(), Section::Desktop | Section::Services | Section::Quotas | Section::Security)>
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
                                        <Show when=move || rows.with(Vec::is_empty)><p class="empty-state">{move || empty_text.get().current()}</p></Show>
                                        <For each=move || rows.get() key=|item| item.key.clone() children=move |item| {
                                            let row = item.clone();
                                            let active_key = item.key.clone();
                                            let pressed_key = item.key.clone();
                                            let detail = item.detail.clone();
                                            let status = item.status.clone();
                                            view! {
                                                <button class=move || if selected.with(|chosen| chosen.as_ref().is_some_and(|v| v.key == active_key)) { "record selected" } else { "record" }
                                                    type="button" aria-pressed=move || selected.with(|chosen| chosen.as_ref().is_some_and(|v| v.key == pressed_key))
                                                    on:click=move |_| selected.set(Some(row.clone()))>
                                                    <span class="record-main"><strong>{item.title}</strong><small>{move || detail.current()}</small></span>
                                                    <span class="record-status">{move || status.current()}</span>
                                                </button>
                                            }
                                        } />
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
                                                    <button class="primary" type="button" disabled=move || busy.get() on:click=move |_| remote_target.set(Some(host.clone()))>{move || t("进入桌面", "Enter desktop")}</button>
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
                            <footer class="deployment-foot"><span>{move || t("当前服务器", "Current server")}</span><code>{move || display_origin.get_value()}</code></footer>
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
            <rect x="8" y="8" width="496" height="496" rx="116" fill="#7850B2" />
            <polyline points="154,342 154,196 200,150" fill="none" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" stroke-linejoin="round" />
            <polyline points="358,170 358,316 312,362" fill="none" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" stroke-linejoin="round" />
            <line x1="190" y1="190" x2="322" y2="322" stroke="#FFFFFF" stroke-width="44" stroke-linecap="round" />
        </svg>
    }
}

#[component]
fn WorkspaceIcon(kind: Section) -> impl IntoView {
    let path = match kind {
        Section::Desktop => "M3 4h18v12H3z M8 21h8 M12 16v5",
        Section::Services => "M3 5h6v6H3z M15 13h6v6h-6z M9 8h7v5 M5 11v7h10",
        Section::Devices => "M3 3h13v10H3z M7 17h5 M10 13v4 M18 9h4v12h-8v-8",
        Section::Requests => "M5 5h14v16H5z M9 2v6 M15 2v6 M8 12h8 M8 16h5",
        Section::Quotas => "M4 20V10h4v10 M10 20V4h4v16 M16 20v-7h4v7",
        Section::Network => "M8 2h8v6H8z M2 16h8v6H2z M14 16h8v6h-8z M12 8v5 M6 16v-3h12v3",
        Section::Security => "M12 2l8 3v6c0 5-4 9-8 11-4-2-8-6-8-11V5z M8 12l3 3 5-6",
        Section::Accounts => "M8 3h8v8H8z M4 22v-5l4-3h8l4 3v5",
        Section::Audit => "M5 2h10l4 4v16H5z M14 2v5h5 M8 11h8 M8 15h8 M8 19h5",
    };
    view! { <svg class="workspace-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d=path /></svg> }
}

#[component]
fn DesktopWorkspace(
    rows: RwSignal<Vec<Record>>,
    selected: RwSignal<Option<Record>>,
    busy: RwSignal<bool>,
    remote_target: RwSignal<Option<RemoteTarget>>,
) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let hosts = Memo::new(move |_| {
        let query = query.get().trim().to_lowercase();
        rows.with(|rows| {
            rows.iter()
                .filter(|row| {
                    row.connectable
                        && (query.is_empty()
                            || row.title.to_lowercase().contains(&query)
                            || row.id.to_lowercase().contains(&query))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    view! {
        <div class="desktop-workspace" class:has-selection=move || selected.with(Option::is_some)>
            <section class="desktop-directory" aria-label=move || t("可连接设备", "Remote devices")>
                <header class="directory-head">
                    <h2>{move || t("我的设备", "My devices")}</h2>
                    <span class="directory-count">{move || hosts.with(Vec::len)}</span>
                    <label class="device-search" for="device-search"><span class="visually-hidden">{move || t("搜索设备名或 ID", "Search device name or ID")}</span><input id="device-search" type="search" placeholder=move || t("搜索设备名或 ID", "Search device name or ID") autocomplete="off" prop:value=move || query.get() on:input=move |event| query.set(event_target_value(&event)) /></label>
                </header>
                <div class="device-records records" aria-busy=move || busy.get().to_string()>
                    <Show when=move || hosts.with(Vec::is_empty)>
                        <div class="empty-state"><WorkspaceIcon kind=Section::Desktop /><h3>{move || if busy.get() { t("正在读取设备", "Loading devices") } else if !query.get().is_empty() { t("没有匹配的设备", "No matching devices") } else { t("还没有被控主机", "No remote hosts yet") }}</h3><p>{move || if !query.get().is_empty() { t("更换名称或设备 ID 后重试。", "Try another name or device ID.") } else { t("在 Windows 客户端登录并完成本机接入后，设备会显示在这里。", "Sign in and enroll the host in the Windows client. It will appear here.") }}</p></div>
                    </Show>
                    <For each=move || hosts.get() key=|item| item.key.clone() children=move |item| {
                        let row = item.clone();
                        let active_key = item.key.clone();
                        let pressed_key = item.key.clone();
                        let status = item.status.clone();
                        view! {
                            <button class=move || if selected.with(|chosen| chosen.as_ref().is_some_and(|v| v.key == active_key)) { "record device-record selected" } else { "record device-record" } type="button" aria-pressed=move || selected.with(|chosen| chosen.as_ref().is_some_and(|v| v.key == pressed_key)) on:click=move |_| selected.set(Some(row.clone()))>
                                <span class="device-symbol"><WorkspaceIcon kind=Section::Desktop /></span><span class="record-main"><strong title=item.title.clone()>{item.title}</strong><small>{move || status.current()}</small></span>
                            </button>
                        }
                    } />
                </div>
                <p class="directory-note">{move || t("登记状态不代表当前在线。连接时会核验主机是否就绪。", "Registration does not confirm availability. The host is checked when you connect.")}</p>
            </section>
            <section class="desktop-detail detail-pane" aria-label=move || t("连接工作区", "Connection workspace")>
                {move || if let Some(item) = selected.get() {
                    let host = RemoteTarget { id: item.id.clone(), name: item.title.clone() };
                    let status = item.status.clone();
                    let detail = item.detail.clone();
                    view! {
                        <header class="desktop-detail-head"><button class="text-button back-to-devices" type="button" on:click=move |_| selected.set(None)>{move || t("返回设备", "Back to devices")}</button><h2 title=item.title.clone()>{item.title}</h2><p>{move || status.current()}</p></header>
                        <div class="desktop-detail-body">
                            <div class="desktop-preview"><WorkspaceIcon kind=Section::Desktop /><h3>{move || t("准备打开远程桌面", "Ready to open the remote desktop")}</h3><p>{move || t("选择本次访问权限，发起连接后由主机确认。连接建立后在这里查看画面并操作。", "Choose access for this session, then request the host's approval. View and control the desktop once connected.")}</p></div>
                            <dl class="device-facts"><dt>{move || t("设备 ID", "Device ID")}</dt><dd><code>{item.id}</code></dd><dt>{move || t("设备信息", "Device details")}</dt><dd>{move || detail.current()}</dd></dl>
                            <p class="connection-note">{move || t("优先建立设备间的直接连接。实际路径将在连接后显示。", "A direct device-to-device connection is preferred. The actual path appears after verification.")}</p>
                        </div>
                        <footer class="desktop-detail-actions"><span>{move || t("访问权限仅用于本次连接", "Access applies to this connection")}</span><button class="primary" type="button" disabled=move || busy.get() on:click=move |_| remote_target.set(Some(host.clone()))>{move || t("进入桌面", "Enter desktop")}</button></footer>
                    }.into_any()
                } else {
                    view! {
                        <header class="desktop-detail-head"><h2>{move || t("远程连接", "Remote connection")}</h2><p>{move || t("连接前由你选择设备和权限", "Choose the device and access before connecting")}</p></header>
                        <div class="desktop-detail-body"><div class="desktop-preview"><WorkspaceIcon kind=Section::Desktop /><h3>{move || t("你的下一次连接，从这里开始", "Your next connection starts here")}</h3><p>{move || t("从左侧选择 Windows 主机，打开远程桌面。文件和剪贴板可在会话操作中心按需使用。", "Select a Windows host to open its desktop. Files and clipboard are available in the session's control center when authorized.")}</p></div></div>
                        <footer class="desktop-detail-actions"><span>{move || t("先选择一台设备", "Select a device first")}</span><button class="primary" type="button" disabled=true>{move || t("进入桌面", "Enter desktop")}</button></footer>
                    }.into_any()
                }}
            </section>
        </div>
    }
}

#[component]
fn Feedback(error: RwSignal<String>, notice: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="feedback" aria-live="polite">
            <Show when=move || !error.get().is_empty()>
                <p class="error-message" role="alert">{move || i18n::feedback_text(&error.get())} <button type="button" on:click=move |_| error.set(String::new())>{move || t("关闭", "Dismiss")}</button></p>
            </Show>
            <Show when=move || !notice.get().is_empty()>
                <p class="notice-message">{move || i18n::feedback_text(&notice.get())} <button type="button" on:click=move |_| notice.set(String::new())>{move || t("关闭", "Dismiss")}</button></p>
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
    let _ = busy;
    view! {
        <button
            type="button"
            class=move || if section.get() == current { "nav-item active" } else { "nav-item" }
            aria-current=move || (section.get() == current).then_some("page")
            on:click=move |_| load.run(current.key().to_owned())
        >
            <WorkspaceIcon kind=current /><span>{move || current.title()}</span>
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
        Section::Desktop | Section::Devices => {
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
                            UiCopy::new("已登记，在线状态未知", "Registered; availability unknown")
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
                        detail: if account.is_admin {
                            UiCopy::new("管理员", "Administrator")
                        } else {
                            UiCopy::new("普通账号", "Standard account")
                        },
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
        Section::Desktop => t("可连接设备", "Remote devices"),
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

#[component]
fn TaskDialog(
    open: Signal<bool>,
    label: Signal<String>,
    on_close: Callback<()>,
    children: Children,
) -> impl IntoView {
    let dialog = NodeRef::<leptos::html::Dialog>::new();
    Effect::new(move |_| {
        let requested = open.get();
        #[cfg(target_arch = "wasm32")]
        if let Some(element) = dialog.get() {
            if requested && !element.open() {
                let _ = element.show_modal();
            } else if !requested && element.open() {
                element.close();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = requested;
    });
    view! {
        <dialog class="task-dialog" node_ref=dialog aria-label=move || label.get()
            on:cancel=move |event: leptos::ev::Event| { event.prevent_default(); on_close.run(()); }>
            {children()}
        </dialog>
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_session_selector(update: Option<Option<String>>) -> Option<String> {
    let window = web_sys::window()?;
    let storage = window.session_storage().ok()??;
    if let Some(value) = update {
        if let Some(value) = value {
            let _ = storage.set_item("nestlink.management-session", &value);
        } else {
            let _ = storage.remove_item("nestlink.management-session");
            if let Ok(Some(local)) = window.local_storage() {
                let _ = local.remove_item("nestlink.remembered-session");
            }
        }
    }
    let selected = storage
        .get_item("nestlink.management-session")
        .ok()
        .flatten()
        .or_else(|| {
            window
                .local_storage()
                .ok()
                .flatten()
                .and_then(|local| local.get_item("nestlink.remembered-session").ok().flatten())
        })
        .filter(|id| nestlink_protocol::valid_id(id));
    if let Some(selected) = &selected {
        let _ = storage.set_item("nestlink.management-session", selected);
    }
    selected
}
