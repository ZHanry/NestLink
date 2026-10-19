//! Account self-service uses the same SDK and authenticated session as the
//! workspace. Credentials and one-time material never enter persisted state.
use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_auth::Secret;
use nestlink_protocol::api::MeResponse;
use nestlink_sdk::{Sdk, SdkError};
use nestlink_web::{
    i18n::{sdk_error, text as t},
    localized_format,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

enum Command {
    Load,
    RefreshLogin,
    ChangePassword {
        current: Secret,
        replacement: Secret,
    },
}

impl Command {
    fn reauthenticates(&self) -> bool {
        matches!(self, Self::ChangePassword { .. })
    }
}

enum Outcome {
    Status(MeResponse),
    PasswordChanged,
}

async fn execute(sdk: &mut Sdk, command: Command) -> Result<Outcome, SdkError> {
    match command {
        Command::Load => sdk.me().await.map(Outcome::Status),
        Command::RefreshLogin => {
            sdk.refresh().await?;
            sdk.me().await.map(Outcome::Status)
        }
        Command::ChangePassword {
            current,
            replacement,
        } => {
            sdk.change_password(current, replacement, None).await?;
            Ok(Outcome::PasswordChanged)
        }
    }
}

fn authentication_lost(problem: &SdkError) -> bool {
    matches!(problem, SdkError::SignIn)
        || matches!(problem, SdkError::Api(status, _) if status.as_u16() == 401)
}

fn take_secret(field: RwSignal<Zeroizing<String>>) -> Secret {
    let mut value = String::new();
    field.update(|secret| value = std::mem::take(&mut **secret));
    Secret::from_text(value)
}

#[component]
pub(super) fn AccountSecurityPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    refresh: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    password_changed: Callback<()>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
) -> impl IntoView {
    let status = RwSignal::new(None::<u64>);
    let password = RwSignal::new(Zeroizing::new(String::new()));
    let replacement = RwSignal::new(Zeroizing::new(String::new()));
    let confirmation = RwSignal::new(Zeroizing::new(String::new()));
    let busy = RwSignal::new(false);
    let alive = Arc::new(AtomicBool::new(true));
    let owner = alive.clone();
    on_cleanup(move || {
        owner.store(false, Ordering::Release);
        for field in [password, replacement, confirmation] {
            let _ = field.try_update(|value| *value = Zeroizing::new(String::new()));
        }
    });

    let submit = Callback::new(move |command: Command| {
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        let reauthenticates = command.reauthenticates();
        let writes = !matches!(command, Command::Load);
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let (result, ended) = {
                let mut client = sdk.lock().await;
                if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                    return;
                }
                let result = execute(&mut client, command).await;
                let ended = match &result {
                    // A wrong current password uses the same
                    // 401 response as an expired login. Check the actual login
                    // before discarding a still-valid workspace session.
                    Err(problem) if reauthenticates && authentication_lost(problem) => client
                        .me()
                        .await
                        .is_err_and(|problem| authentication_lost(&problem)),
                    Err(problem) => authentication_lost(problem),
                    _ => false,
                };
                (result, ended)
            };
            if session_revision.get_untracked() != session {
                return;
            }
            // A committed password change ends the account session even if
            // the user navigated away while its HTTP response was in flight.
            if matches!(&result, Ok(Outcome::PasswordChanged)) {
                password_changed.run(());
                return;
            }
            if ended {
                auth_failure.run(sdk);
                return;
            }
            if !alive.load(Ordering::Acquire) {
                return;
            }
            match result {
                Ok(Outcome::Status(value)) => {
                    status.set(Some(value.principal.access_expires));
                }
                Ok(Outcome::PasswordChanged) => unreachable!(),
                Err(problem) => {
                    let rejected =
                        matches!(&problem, SdkError::Api(status, _) if status.is_client_error());
                    let problem = sdk_error(&problem);
                    error.set(if writes && !rejected {
                        nestlink_web::localized_detail!("无法确认安全操作结果：{}。请先刷新状态；不要自动重试。", "The security operation could not be confirmed: {}. Refresh its status before retrying.", problem)
                    } else {
                        problem.to_string()
                    });
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
            submit.run(Command::Load);
        }
    });

    view! {
        <div class="content-grid">
            <section class="list-pane" aria-label=move || t("账号与安全", "Account and security")>
                <div class="section-heading"><div>
                    <h2>{move || t("账号与安全", "Account and security")}</h2>
                    <p>{move || if status.get().is_some() { t("使用账号和密码登录。", "Sign in with your account and password.") } else { t("正在读取账号状态…", "Loading account status…") }}</p>
                </div>
                    <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| submit.run(Command::RefreshLogin)>{move || t("刷新登录期限", "Refresh login")}</button>
                </div>
                <form class="policy-form form-stack" on:submit=move |event| {
                    event.prevent_default();
                    if !replacement.with(|value| (12..=1024).contains(&value.len()))
                        || !replacement.with(|value| confirmation.with(|confirmed| value.as_str() == confirmed.as_str())) {
                        error.set(t("新密码需为 12–1024 个 UTF-8 字节，且两次输入一致。", "The new password must contain 12–1024 UTF-8 bytes and match its confirmation.").into());
                        return;
                    }
                    confirmation.set(Zeroizing::new(String::new()));
                    submit.run(Command::ChangePassword { current: take_secret(password), replacement: take_secret(replacement) });
                }>
                    <h3>{move || t("修改密码", "Change password")}</h3>
                    <SecretField id="security-password" chinese="当前密码" english="Current password" value=password busy maximum=1024 />
                    <SecretField id="security-new-password" chinese="新密码（至少 12 字节）" english="New password (at least 12 bytes)" value=replacement busy maximum=1024 />
                    <SecretField id="security-confirm-password" chinese="再次输入新密码" english="Confirm new password" value=confirmation busy maximum=1024 />
                    <p class="muted">{move || t("修改成功会撤销现有登录，请使用新密码重新登录。", "Changing the password revokes existing logins. Sign in again with the new password.")}</p>
                    <button class="danger" type="submit" disabled=move || busy.get() || password.with(|value| value.is_empty()) || !replacement.with(|value| (12..=1024).contains(&value.len())) || !replacement.with(|value| confirmation.with(|confirmed| value.as_str() == confirmed.as_str()))>{move || t("修改密码并注销", "Change password and sign out")}</button>
                </form>
            </section>

        </div>
    }
}

#[component]
fn SecretField(
    id: &'static str,
    chinese: &'static str,
    english: &'static str,
    value: RwSignal<Zeroizing<String>>,
    busy: RwSignal<bool>,
    maximum: usize,
) -> impl IntoView {
    view! {
        <label for=id>{move || t(chinese, english)}</label>
        <input id=id type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength=maximum disabled=move || busy.get() prop:value=move || value.with(|value| value.to_string()) on:input=move |event| {
            let next = Zeroizing::new(event_target_value(&event));
            if next.len() <= maximum {
                value.set(next);
            }
        } />
    }
}
