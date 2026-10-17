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
    BeginTotp {
        password: Secret,
        factor: Option<Secret>,
    },
    ConfirmTotp {
        code: Secret,
    },
    ResetRecovery {
        password: Secret,
        factor: Secret,
    },
    ChangePassword {
        current: Secret,
        replacement: Secret,
        factor: Option<Secret>,
    },
}

impl Command {
    fn reauthenticates(&self) -> bool {
        matches!(
            self,
            Self::BeginTotp { .. }
                | Self::ConfirmTotp { .. }
                | Self::ResetRecovery { .. }
                | Self::ChangePassword { .. }
        )
    }
}

enum Material {
    TotpSeed(Secret),
    RecoveryCodes(Vec<Secret>),
}

enum Outcome {
    Status(MeResponse),
    Material {
        value: Material,
        status: Result<MeResponse, SdkError>,
    },
    PasswordChanged,
}

async fn execute(sdk: &mut Sdk, command: Command) -> Result<Outcome, SdkError> {
    let value = match command {
        Command::Load => return sdk.me().await.map(Outcome::Status),
        Command::RefreshLogin => {
            sdk.refresh().await?;
            return sdk.me().await.map(Outcome::Status);
        }
        Command::BeginTotp { password, factor } => {
            Material::TotpSeed(sdk.begin_totp(password, factor).await?)
        }
        Command::ConfirmTotp { code } => Material::RecoveryCodes(sdk.confirm_totp(code).await?),
        Command::ResetRecovery { password, factor } => {
            Material::RecoveryCodes(sdk.reset_recovery(password, factor).await?)
        }
        Command::ChangePassword {
            current,
            replacement,
            factor,
        } => {
            sdk.change_password(current, replacement, factor).await?;
            return Ok(Outcome::PasswordChanged);
        }
    };
    Ok(Outcome::Material {
        value,
        status: sdk.me().await,
    })
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

fn take_optional(field: RwSignal<Zeroizing<String>>) -> Option<Secret> {
    let value = take_secret(field);
    (!value.expose().is_empty()).then_some(value)
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
    let status = RwSignal::new(None::<(bool, u64)>);
    let password = RwSignal::new(Zeroizing::new(String::new()));
    let factor = RwSignal::new(Zeroizing::new(String::new()));
    let code = RwSignal::new(Zeroizing::new(String::new()));
    let replacement = RwSignal::new(Zeroizing::new(String::new()));
    let confirmation = RwSignal::new(Zeroizing::new(String::new()));
    let material = RwSignal::new(None::<Material>);
    let busy = RwSignal::new(false);
    let alive = Arc::new(AtomicBool::new(true));
    let owner = alive.clone();
    on_cleanup(move || {
        owner.store(false, Ordering::Release);
        let _ = material.try_update(|value| *value = None);
        for field in [password, factor, code, replacement, confirmation] {
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
        if reauthenticates {
            material.set(None);
        }
        spawn_local(async move {
            let (result, ended) = {
                let mut client = sdk.lock().await;
                if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                    return;
                }
                let result = execute(&mut client, command).await;
                let ended = match &result {
                    // A wrong password, TOTP or recovery code uses the same
                    // 401 response as an expired login. Check the actual login
                    // before discarding a still-valid workspace session.
                    Err(problem) if reauthenticates && authentication_lost(problem) => client
                        .me()
                        .await
                        .is_err_and(|problem| authentication_lost(&problem)),
                    Err(problem) => authentication_lost(problem),
                    Ok(Outcome::Material {
                        status: Err(problem),
                        ..
                    }) => authentication_lost(problem),
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
                    status.set(Some((value.totp_enabled, value.principal.access_expires)));
                }
                Ok(Outcome::Material {
                    value,
                    status: refreshed,
                }) => {
                    material.set(Some(value));
                    match refreshed {
                        Ok(value) => {
                            status.set(Some((value.totp_enabled, value.principal.access_expires)))
                        }
                        Err(problem) => {
                            let problem = sdk_error(&problem);
                            error.set(localized_format!(
                                "安全操作已完成，但状态刷新失败：{problem}。请先保存显示的一次性信息，再刷新。",
                                "The security operation completed, but its status could not be refreshed: {problem}. Save the one-time information before refreshing."
                            ));
                        }
                    }
                }
                Ok(Outcome::PasswordChanged) => unreachable!(),
                Err(problem) => {
                    let rejected =
                        matches!(&problem, SdkError::Api(status, _) if status.is_client_error());
                    let problem = sdk_error(&problem);
                    error.set(if writes && !rejected {
                        localized_format!(
                            "无法确认安全操作结果：{problem}。请先刷新状态；不要自动重试。",
                            "The security operation could not be confirmed: {problem}. Refresh its status before retrying."
                        )
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
                    <p>{move || status.get().map(|(enabled, _)| if enabled { t("TOTP 已启用", "TOTP enabled") } else { t("TOTP 未启用", "TOTP not enabled") }).unwrap_or_else(|| t("正在读取账号安全状态…", "Loading account security…"))}</p>
                </div>
                    <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| submit.run(Command::RefreshLogin)>{move || t("刷新登录期限", "Refresh login")}</button>
                </div>
                <p class="muted">{move || t("安全操作需要重新核验当前密码，以及已启用的 TOTP 或恢复码。", "Security changes require your current password and an enabled TOTP or recovery code.")}</p>
                <div class="policy-form">
                    <SecretField id="security-password" chinese="当前密码" english="Current password" value=password busy maximum=1024 />
                    <SecretField id="security-factor" chinese="TOTP 或恢复码（如已启用）" english="TOTP or recovery code (if enabled)" value=factor busy maximum=128 />
                    <div class="section-heading">
                        <button class="secondary" type="button" disabled=move || busy.get() || password.with(|value| value.is_empty()) on:click=move |_| submit.run(Command::BeginTotp { password: take_secret(password), factor: take_optional(factor) })>{move || t("开始设置 TOTP", "Set up TOTP")}</button>
                        <button class="secondary" type="button" disabled=move || busy.get() || status.get().is_none_or(|(enabled, _)| !enabled) || password.with(|value| value.is_empty()) || factor.with(|value| value.is_empty()) on:click=move |_| submit.run(Command::ResetRecovery { password: take_secret(password), factor: take_secret(factor) })>{move || t("重新生成恢复码", "Replace recovery codes")}</button>
                    </div>
                    <form class="form-stack" on:submit=move |event| {
                        event.prevent_default();
                        if code.with(|value| value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())) {
                            submit.run(Command::ConfirmTotp { code: take_secret(code) });
                        }
                    }>
                        <SecretField id="security-totp-code" chinese="认证器的六位验证码" english="Six-digit authenticator code" value=code busy maximum=6 />
                        <button class="primary" type="submit" disabled=move || busy.get() || !code.with(|value| value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit()))>{move || t("确认启用 TOTP", "Confirm TOTP")}</button>
                    </form>
                </div>
                <form class="policy-form form-stack" on:submit=move |event| {
                    event.prevent_default();
                    if !replacement.with(|value| (12..=1024).contains(&value.len()))
                        || !replacement.with(|value| confirmation.with(|confirmed| value.as_str() == confirmed.as_str())) {
                        error.set(t("新密码需为 12–1024 个 UTF-8 字节，且两次输入一致。", "The new password must contain 12–1024 UTF-8 bytes and match its confirmation.").into());
                        return;
                    }
                    confirmation.set(Zeroizing::new(String::new()));
                    submit.run(Command::ChangePassword { current: take_secret(password), replacement: take_secret(replacement), factor: take_optional(factor) });
                }>
                    <h3>{move || t("修改密码", "Change password")}</h3>
                    <SecretField id="security-new-password" chinese="新密码（至少 12 字节）" english="New password (at least 12 bytes)" value=replacement busy maximum=1024 />
                    <SecretField id="security-confirm-password" chinese="再次输入新密码" english="Confirm new password" value=confirmation busy maximum=1024 />
                    <p class="muted">{move || t("修改成功会撤销现有登录，请使用新密码重新登录。", "Changing the password revokes existing logins. Sign in again with the new password.")}</p>
                    <button class="danger" type="submit" disabled=move || busy.get() || password.with(|value| value.is_empty()) || !replacement.with(|value| (12..=1024).contains(&value.len())) || !replacement.with(|value| confirmation.with(|confirmed| value.as_str() == confirmed.as_str()))>{move || t("修改密码并注销", "Change password and sign out")}</button>
                </form>
            </section>
            <aside class="detail-pane" aria-label=move || t("一次性安全信息", "One-time security information")>
                <h2>{move || t("一次性安全信息", "One-time security information")}</h2>
                <p>{move || t("请安全保存。切换页面、账号或服务器后立即清除；关闭后无法再次读取。", "Save this securely. It is cleared when leaving this page or changing account or server, and cannot be retrieved after dismissal.")}</p>
                {move || material.with(|value| match value {
                    Some(Material::TotpSeed(seed)) => view! {
                        <p>{move || t("在认证器中手动输入此密钥，再填写六位验证码确认启用。", "Enter this key in your authenticator, then confirm with its six-digit code.")}</p>
                        <p><code>{seed.expose().to_owned()}</code></p>
                        <p class="muted">"TOTP · SHA1 · 6 digits · 30 seconds"</p>
                    }.into_any(),
                    Some(Material::RecoveryCodes(codes)) => view! {
                        <p>{move || t("每个恢复码只能使用一次。新恢复码会替代以前的恢复码。", "Each recovery code can be used once. These codes replace all previous recovery codes.")}</p>
                        <ul>{codes.iter().map(|code| view! { <li><code>{code.expose().to_owned()}</code></li> }).collect_view()}</ul>
                    }.into_any(),
                    None => view! { <p class="muted">{move || t("完成 TOTP 设置或生成恢复码后，在此显示一次。", "Your TOTP setup key or new recovery codes will appear here once.")}</p> }.into_any(),
                })}
                <button class="secondary" type="button" disabled=move || material.with(Option::is_none) on:click=move |_| material.set(None)>{move || t("我已保存，清除显示", "Saved; clear display")}</button>
            </aside>
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
