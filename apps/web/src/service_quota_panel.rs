use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::{
    service_plane::{
        ServiceQuotaLimitUpdate, ServiceQuotaScope, ServiceQuotaUsageQuery, ServiceQuotaUsageView,
    },
    valid_id,
};
use nestlink_sdk::{Sdk, SdkError};
use nestlink_web::{i18n::text as t, localized_format};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
enum Command {
    Load {
        scope: ServiceQuotaScope,
        scope_key: String,
    },
    Save {
        scope: ServiceQuotaScope,
        scope_key: String,
        expected_revision: u64,
        limit_bytes: u64,
    },
}

impl Command {
    fn scope_and_key(&self) -> (ServiceQuotaScope, &str) {
        match self {
            Self::Load { scope, scope_key }
            | Self::Save {
                scope, scope_key, ..
            } => (*scope, scope_key),
        }
    }

    fn is_write(&self) -> bool {
        matches!(self, Self::Save { .. })
    }
}

async fn execute(sdk: &Sdk, command: Command) -> Result<ServiceQuotaUsageView, SdkError> {
    match command {
        Command::Load { scope, scope_key } => {
            sdk.service_quota_usage(ServiceQuotaUsageQuery { scope, scope_key })
                .await
        }
        Command::Save {
            scope,
            scope_key,
            expected_revision,
            limit_bytes,
        } => {
            sdk.set_service_quota_limit(ServiceQuotaLimitUpdate {
                scope,
                scope_key,
                expected_revision,
                limit_bytes,
            })
            .await
        }
    }
}

fn parse_scope(value: &str) -> Option<ServiceQuotaScope> {
    match value {
        "account" => Some(ServiceQuotaScope::Account),
        "device" => Some(ServiceQuotaScope::Device),
        "node" => Some(ServiceQuotaScope::Node),
        "resource" => Some(ServiceQuotaScope::Resource),
        _ => None,
    }
}

fn authentication_lost(error: &SdkError) -> bool {
    matches!(error, SdkError::SignIn)
        || matches!(error, SdkError::Api(status, _) if status.as_u16() == 401)
}

#[component]
pub(super) fn ServiceQuotaPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    refresh: RwSignal<u64>,
    active: Signal<bool>,
    auth_failure: Callback<SdkHandle>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
) -> impl IntoView {
    let scope = RwSignal::new("account".to_owned());
    let scope_key = RwSignal::new(String::new());
    let limit_bytes = RwSignal::new(String::new());
    let usage = RwSignal::new(None::<ServiceQuotaUsageView>);
    let stale = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let alive = Arc::new(AtomicBool::new(true));
    let owner = alive.clone();
    on_cleanup(move || owner.store(false, Ordering::Release));

    let submit = Callback::new(move |command: Command| {
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            error.set(
                t(
                    "会话已结束，请重新登录。",
                    "Your session ended. Sign in again.",
                )
                .into(),
            );
            return;
        };
        let (requested_scope, requested_key) = command.scope_and_key();
        let requested_key = requested_key.to_owned();
        let write = command.is_write();
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let result = {
                let sdk = sdk.lock().await;
                if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                    return;
                }
                execute(&sdk, command).await
            };
            if !alive.load(Ordering::Acquire) || session_revision.get_untracked() != session {
                return;
            }
            let still_selected = parse_scope(&scope.get_untracked()) == Some(requested_scope)
                && scope_key.get_untracked().trim() == requested_key;
            match result {
                Ok(view) if still_selected => {
                    let dirty = usage.with_untracked(|old| {
                        old.as_ref().is_some_and(|old| {
                            limit_bytes.get_untracked() != old.limit_bytes.to_string()
                        })
                    });
                    if write || !dirty {
                        limit_bytes.set(view.limit_bytes.to_string());
                    }
                    stale.set(false);
                    usage.set(Some(view));
                    notice.set(
                        if write {
                            t("服务配额已保存。", "Service quota saved.")
                        } else {
                            t(
                                "配额和实际计量已刷新。",
                                "Quota and actual usage refreshed.",
                            )
                        }
                        .into(),
                    );
                }
                Ok(_) => {}
                Err(problem) if authentication_lost(&problem) => {
                    auth_failure.run(sdk);
                    return;
                }
                Err(problem) => {
                    if write {
                        // A transport failure can arrive after the transaction
                        // committed. Do not leave an old revision looking current.
                        stale.set(true);
                        error.set(localized_format!(
                            "未能确认配额更新结果：{}。请重新读取当前修订后再操作。",
                            "Could not confirm the quota update: {}. Read the current revision before trying again.",
                            nestlink_web::i18n::sdk_error(&problem)
                        ));
                    } else {
                        error.set(nestlink_web::i18n::sdk_error(&problem).into());
                    }
                }
            }
            busy.set(false);
        });
    });

    let load_selected = move || {
        let Some(scope) = parse_scope(&scope.get_untracked()) else {
            error.set(t("请选择配额范围。", "Choose a quota scope.").into());
            return;
        };
        let scope_key = scope_key.get_untracked().trim().to_owned();
        if !valid_id(&scope_key) {
            error.set(
                t(
                    "请输入完整且有效的范围 ID。",
                    "Enter a complete, valid scope ID.",
                )
                .into(),
            );
            return;
        }
        submit.run(Command::Load { scope, scope_key });
    };

    let loaded_refresh = StoredValue::new(None::<u64>);
    Effect::new(move |_| {
        if !active.get() {
            return;
        }
        let requested = refresh.get();
        if loaded_refresh.get_value() != Some(requested) {
            loaded_refresh.set_value(Some(requested));
            if let Some(scope) = parse_scope(&scope.get_untracked()) {
                let scope_key = scope_key.get_untracked().trim().to_owned();
                if valid_id(&scope_key) {
                    submit.run(Command::Load { scope, scope_key });
                }
            }
        }
    });

    let save = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        let Some(current) = usage.get_untracked() else {
            error.set(t("请先读取当前配额。", "Read the current quota first.").into());
            return;
        };
        let next = match limit_bytes.get_untracked().parse::<u64>() {
            Ok(value) if value <= i64::MAX as u64 => value,
            _ => {
                error.set(
                    t(
                        "配额必须是不超过 2^63−1 的非负整数。",
                        "Quota must be a non-negative integer no greater than 2^63−1.",
                    )
                    .into(),
                );
                return;
            }
        };
        if parse_scope(&scope.get_untracked()) != Some(current.scope)
            || scope_key.get_untracked().trim() != current.scope_key
        {
            usage.set(None);
            error.set(
                t(
                    "范围已变化，请重新读取配额。",
                    "The scope changed. Read its quota again.",
                )
                .into(),
            );
            return;
        }
        if next == current.limit_bytes {
            error.set(
                t(
                    "新配额与当前值相同。",
                    "The new quota matches the current value.",
                )
                .into(),
            );
            return;
        }
        submit.run(Command::Save {
            scope: current.scope,
            scope_key: current.scope_key,
            expected_revision: current.limit_revision,
            limit_bytes: next,
        });
    };

    let can_save = move || {
        !busy.get()
            && !stale.get()
            && usage.with(|value| {
                value.as_ref().is_some_and(|value| {
                    parse_scope(&scope.get()) == Some(value.scope)
                        && scope_key.get().trim() == value.scope_key
                        && limit_bytes
                            .get()
                            .parse::<u64>()
                            .is_ok_and(|next| next <= i64::MAX as u64 && next != value.limit_bytes)
                })
            })
    };

    view! {
        <div class="content-grid">
            <section class="list-pane" aria-label=move || t("服务配额", "Service quotas")>
                <form class="policy-form" on:submit=move |event| { event.prevent_default(); load_selected(); }>
                    <div class="section-heading">
                        <div>
                            <h2>{move || t("服务配额与实际用量", "Service quota and actual usage")}</h2>
                            <p>{move || t("配额限制同时按账号、主机设备、节点和单项服务累计。", "Aggregate service limits apply by account, host device, node, and individual service.")}</p>
                        </div>
                        <button class="secondary" type="submit" disabled=move || busy.get()>
                            {move || if busy.get() { t("正在读取…", "Reading…") } else { t("读取范围", "Read scope") }}
                        </button>
                    </div>
                    <label for="service-quota-scope">{move || t("配额范围", "Quota scope")}</label>
                    <select id="service-quota-scope" disabled=move || busy.get() prop:value=move || scope.get() on:change=move |event| {
                        scope.set(event_target_value(&event));
                        stale.set(true);
                        limit_bytes.set(String::new());
                        error.set(String::new());
                        notice.set(String::new());
                    }>
                        <option value="account">{move || t("账号", "Account")}</option>
                        <option value="device">{move || t("主机设备", "Host device")}</option>
                        <option value="node">{move || t("数据节点", "Data node")}</option>
                        <option value="resource">{move || t("单项服务", "Service resource")}</option>
                    </select>
                    <label for="service-quota-key">{move || t("范围 ID", "Scope ID")}</label>
                    <input id="service-quota-key" maxlength="36" autocomplete="off" required=true disabled=move || busy.get()
                        prop:value=move || scope_key.get()
                        on:input=move |event| {
                            scope_key.set(event_target_value(&event));
                            stale.set(true);
                            limit_bytes.set(String::new());
                            error.set(String::new());
                            notice.set(String::new());
                        } />
                    <p class="muted">{move || t("请使用对应账号、设备、节点或服务的完整 UUID。无已计量流量的范围仍可设置限制。", "Use the full UUID of the account, device, node, or service. A scope with no recorded traffic can still receive a limit.")}</p>
                </form>
                <Show when=move || usage.with(Option::is_some)>
                            <article class="policy-form">
                                <div class="section-heading">
                                    <div><h2>{move || t("当前计量", "Current usage")}</h2><p>{move || t("配额修订 ", "Quota revision ")} {move || usage.with(|v| v.as_ref().map(|v| v.limit_revision).unwrap_or_default())}</p></div>
                                </div>
                                <p>{move || localized_format!("已确认用量：{} 字节", "Confirmed spent: {} bytes", usage.with(|v| v.as_ref().map(|v| v.spent_bytes).unwrap_or_default()))}</p>
                                <p>{move || localized_format!("未结清授权：{} 字节", "Outstanding grants: {} bytes", usage.with(|v| v.as_ref().map(|v| v.outstanding_bytes).unwrap_or_default()))}</p>
                                <p>{move || localized_format!("活动授权数：{}", "Active grants: {}", usage.with(|v| v.as_ref().map(|v| v.active_grants).unwrap_or_default()))}</p>
                                <Show when=move || usage.with(|v| v.as_ref().is_some_and(|v| v.reconciliation_required))><p class="quota-warning" role="status">{move || t("恢复后的用量尚待外部对账。", "Restored usage requires external reconciliation.")}</p></Show>
                                <Show when=move || stale.get()><p role="status">{move || t("当前为上次读取的数据，请刷新后再保存。", "Showing last known data. Refresh before saving.")}</p></Show>
                                <form class="service-fields" on:submit=save>
                                    <label for="service-quota-limit">{move || t("新累计流量上限（字节）", "New cumulative traffic limit (bytes)")}</label>
                                    <input id="service-quota-limit" type="number" min="0" max="9223372036854775807" step="1" required=true disabled=move || busy.get()
                                        prop:value=move || limit_bytes.get()
                                        on:input=move |event| limit_bytes.set(event_target_value(&event)) />
                                    <p class="muted">{move || limit_bytes.get().parse::<u64>().ok().map(|bytes| localized_format!("约 {:.3} GiB（1 GiB = 1073741824 字节）。", "Approximately {:.3} GiB (1 GiB = 1073741824 bytes).", bytes as f64 / 1073741824.)).unwrap_or_default()}</p>
                                    <p class="muted">{move || t("保存会递增当前范围的修订；并发修改会被拒绝，必须刷新后重试。", "Saving advances this scope's revision. Concurrent changes are rejected; refresh before retrying.")}</p>
                                    <button class="primary" type="submit" disabled=move || !can_save()>
                                        {move || if busy.get() { t("正在保存…", "Saving…") } else { t("保存服务配额", "Save service quota") }}
                                    </button>
                                </form>
                            </article>
                </Show>
            </section>
            <aside class="detail-pane" aria-label=move || t("配额说明", "Quota details")>
                <h2>{move || t("配额说明", "Quota details")}</h2>
                <p>{move || t("系统按实际确认字节和仍有效的授权预算分别显示用量。账号、设备、节点和服务资源限制共同生效。", "The server reports confirmed bytes separately from still-active grant budgets. Account, device, node, and service-resource limits apply together.")}</p>
                <p>{move || t("修改上限不会清除已计量用量，也不会提前释放活动授权。", "Changing a limit does not erase recorded usage or release active grants early.")}</p>
            </aside>
        </div>
    }
}
