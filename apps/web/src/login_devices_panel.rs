//! Account sign-ins are distinct from registered remote-control hosts.
use super::{Api, SdkHandle, TaskDialog, format_time};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::LoginSessionView;
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[component]
pub(super) fn LoginDevicesPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    refresh: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    sign_out: Callback<()>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
) -> impl IntoView {
    let sessions = RwSignal::new(Vec::<LoginSessionView>::new());
    let available = RwSignal::new(false);
    let loaded = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let pending = RwSignal::new(None::<LoginSessionView>);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || {
        cleanup.store(false, Ordering::Release);
    });
    let submit = Callback::new(move |id: Option<String>| {
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        pending.set(None);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let writes = id.is_some();
            let result = {
                let client = sdk.lock().await;
                if !alive.load(Ordering::Acquire)
                    || session_revision.try_get_untracked() != Some(session)
                {
                    return;
                }
                let revoked = if let Some(id) = id {
                    client.revoke_login_session(&id).await
                } else {
                    Ok(())
                };
                match revoked {
                    Ok(()) => client.me().await,
                    Err(problem) => Err(problem),
                }
            };
            if session_revision.try_get_untracked() != Some(session) {
                return;
            }
            if matches!(&result, Err(SdkError::SignIn))
                || matches!(&result, Err(SdkError::Api(status, _)) if status.as_u16() == 401)
            {
                auth_failure.run(sdk);
                return;
            }
            if !alive.load(Ordering::Acquire) {
                return;
            }
            busy.set(false);
            match result {
                Ok(value) => {
                    sessions.set(value.sessions);
                    available.set(value.session_management_available);
                    loaded.set(true);
                    if writes {
                        notice.set(
                            t(
                                "已退出所选设备的账号登录。",
                                "The selected device has been signed out.",
                            )
                            .into(),
                        );
                    }
                }
                Err(problem) => {
                    let detail = sdk_error(&problem);
                    error.set(if writes {
                        nestlink_web::localized_detail!("无法确认退出结果：{}。请先刷新登录设备，再决定是否重试。", "Sign-out could not be confirmed: {}. Refresh login devices before retrying.", detail)
                    } else { detail.into() });
                }
            }
        });
    });
    let requested_refresh = StoredValue::new(None::<u64>);
    Effect::new(move |_| {
        let revision = refresh.get();
        if requested_refresh.get_value() != Some(revision) && !busy.get() {
            requested_refresh.set_value(Some(revision));
            submit.run(None);
        }
    });
    view! {
        <section class="login-devices" aria-label=move || t("账号登录设备", "Account login devices") aria-busy=move || busy.get().to_string()>
            <div class="account-summary"><super::WorkspaceIcon kind=super::Section::Devices />
                <div><h2>{move || t("我的登录设备", "My signed-in devices")}</h2><p>{move || t("查看当前账号的 Windows 与浏览器登录，按需退出其他设备。", "Review this account's Windows and browser sign-ins, and sign out other devices.")}</p></div>
                <span class="status-label">{move || nestlink_web::localized_format!("{} 条登录记录", "{} sign-ins", sessions.with(Vec::len))}</span>
            </div>
            <Show when=move || loaded.get() && !available.get()><p class="info-callout">{move || t("当前服务器尚未提供登录设备管理，请先升级控制中心。", "This server does not provide login device management yet. Upgrade the control center first.")}</p></Show>
            <Show when=move || loaded.get() && available.get() && sessions.with(Vec::is_empty)><p class="empty-state">{move || t("没有可显示的有效登录记录，请刷新状态。", "No active sign-ins to display. Refresh the current state.")}</p></Show>
            <div class="login-device-grid">
                {move || sessions.get().into_iter().map(|session| {
                    let target = session.clone();
                    let title = session.device_name.as_deref().filter(|v| !v.is_empty())
                        .or(session.client.as_deref()).unwrap_or(t("未命名登录", "Unnamed sign-in")).to_owned();
                    let created = session.created_at.map(|time| format_time(time.saturating_mul(1000)));
                    let active = session.last_active_at.map(|time| format_time(time.saturating_mul(1000)));
                    view! {
                        <article class="login-device-card" data-login-session=session.session_id>
                            <div class="device-symbol"><super::WorkspaceIcon kind=super::Section::Devices /></div>
                            <h3>{title}</h3><p class="muted">{session.platform.unwrap_or_default()} " · " {session.client.unwrap_or_default()}</p>
                            {session.current.then(|| view! { <span class="current-device">{move || t("当前设备", "This device")}</span> })}
                            <dl><dt>{move || t("登录时间", "Signed in")}</dt><dd>{move || created.as_ref().map(|v| v.current()).unwrap_or_else(|| t("未记录", "Not recorded").into())}</dd>
                                <dt>{move || t("最近活动", "Last active")}</dt><dd>{move || active.as_ref().map(|v| v.current()).unwrap_or_else(|| t("未记录", "Not recorded").into())}</dd></dl>
                            <button class="danger-soft" type="button" disabled=move || busy.get() || !available.get() on:click=move |_| pending.set(Some(target.clone()))>{move || t("退出此设备", "Sign out device")}</button>
                        </article>
                    }
                }).collect_view()}
            </div>
            <p class="info-callout">{move || t("退出登录会结束该设备的账号会话及依赖此登录的远程授权。主机身份与空间成员关系在各自页面管理。", "Signing out ends the account session and remote access that depends on it. Manage host identities and space membership in their respective pages.")}</p>
            <Show when=move || pending.with(Option::is_some)>
                <TaskDialog open=Signal::derive(move || pending.with(Option::is_some)) label=Signal::derive(move || t("退出设备登录", "Sign out device").to_owned()) on_close=Callback::new(move |()| pending.set(None))>
                    <h2>{move || t("退出这台设备？", "Sign out this device?")}</h2>
                    <p>{move || pending.with(|value| value.as_ref().and_then(|value| value.device_name.clone()).unwrap_or_default())}</p>
                    <p class="muted">{move || t("该设备需要重新登录才能继续使用账号服务。", "This device will need to sign in again to use account services.")}</p>
                    <div class="confirmation-actions"><button class="secondary" type="button" on:click=move |_| pending.set(None)>{move || t("取消", "Cancel")}</button>
                        <button class="danger" type="button" disabled=move || busy.get() on:click=move |_| {
                            if let Some(value) = pending.get_untracked() {
                                if value.current { pending.set(None); sign_out.run(()); }
                                else { submit.run(Some(value.session_id)); }
                            }
                        }>{move || t("确认退出", "Confirm sign-out")}</button></div>
                </TaskDialog>
            </Show>
        </section>
    }
}
