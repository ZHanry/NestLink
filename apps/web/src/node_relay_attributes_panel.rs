use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::api::{NodeRelayAttributes, NodeRelayAttributesUpdate};
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[component]
pub(super) fn NodeRelayAttributesPanel(
    api: Api,
    node_id: String,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let node = StoredValue::new(node_id);
    let region = RwSignal::new(String::new());
    let cost = RwSignal::new(String::new());
    let revision = RwSignal::new(None::<u64>);
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    let request = Callback::new(move |save: bool| {
        if busy.get_untracked() {
            return;
        }
        let update = if save {
            let Some(expected_revision) = revision.get_untracked() else {
                return;
            };
            let region = region.get_untracked().trim().to_owned();
            let cost = cost.get_untracked();
            let cost_weight = if cost.trim().is_empty() {
                None
            } else {
                match cost.trim().parse::<u32>() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        problem.set(t("费用权重须为 0–1000000 的整数，留空表示未知。", "Cost weight must be an integer from 0 to 1000000; blank means unknown.").into());
                        return;
                    }
                }
            };
            let attributes = NodeRelayAttributes {
                region: (!region.is_empty()).then_some(region),
                cost_weight,
            };
            if attributes.validate().is_err() {
                problem.set(t("地区须为 1–32 位小写字母、数字或连字符；费用权重须为 0–1000000，均可留空。", "Region must contain 1–32 lowercase letters, digits or hyphens; cost weight must be 0–1000000. Either may be blank.").into());
                return;
            }
            Some(NodeRelayAttributesUpdate {
                expected_revision,
                attributes,
            })
        } else {
            None
        };
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let id = node.get_value();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        spawn_local(async move {
            let active = || {
                alive.load(Ordering::Acquire)
                    && session_revision.try_get_untracked() == Some(session)
            };
            let result = {
                let client = sdk.lock().await;
                if !active() {
                    return;
                }
                if let Some(update) = update {
                    client.set_node_relay_attributes(&id, update).await
                } else {
                    client.node_relay_attributes(&id).await
                }
            };
            if !active() {
                return;
            }
            busy.set(false);
            match result {
                Ok(view) if view.node_id == id && view.attributes.validate().is_ok() => {
                    region.set(view.attributes.region.unwrap_or_default());
                    cost.set(
                        view.attributes
                            .cost_weight
                            .map(|value| value.to_string())
                            .unwrap_or_default(),
                    );
                    revision.set(Some(view.revision));
                    message.set(
                        if save {
                            t("节点属性已保存。", "Relay attributes saved.")
                        } else {
                            t("已读取当前节点属性。", "Current relay attributes loaded.")
                        }
                        .into(),
                    );
                }
                Ok(_) => {
                    revision.set(None);
                    problem.set(t("服务器返回了不匹配的节点属性，请重新读取。", "The returned relay attributes do not match this node. Read them again.").into());
                }
                Err(error) => {
                    revision.set(None);
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401)
                    {
                        auth_failure.run(sdk);
                        return;
                    }
                    problem.set(format!("{} {}", sdk_error(&error), t("仅管理员可配置未撤销的中继节点。请重新读取后再保存。", "Only an administrator can configure an active relay node. Read the current values before saving again.")));
                }
            }
        });
    });
    Effect::new(move |_| {
        let _ = session_revision.get();
        revision.set(None);
        region.set(String::new());
        cost.set(String::new());
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
        request.run(false);
    });
    view! {
        <section class="form-stack" aria-label=move || t("中继节点属性", "Relay attributes") aria-busy=move || busy.get().to_string()>
            <h3>{move || t("中继节点属性", "Relay attributes")}</h3>
            <p class="muted">{move || t("地区和相对费用权重仅供选择参考，不代表价格、账单、硬性费用上限或转发权限。留空表示未知；零表示明确配置的零权重。", "Region and relative cost weight are selection hints, not a price, bill, spending limit or forwarding permission. Blank means unknown; zero is an explicitly configured zero weight.")}</p>
            <p>{move || revision.get().map(|value| format!("revision {value}")).unwrap_or_else(|| t("尚未读取当前版本", "Current revision not loaded").into())}</p>
            <label>{move || t("地区（可留空）", "Region (optional)")}<input data-node-relay-field="region" maxlength="32" placeholder=move || t("未知", "Unknown") prop:value=move || region.get() disabled=move || busy.get() on:input=move |event| region.set(event_target_value(&event)) /></label>
            <label>{move || t("相对费用权重（可留空）", "Relative cost weight (optional)")}<input data-node-relay-field="cost" type="number" min="0" max="1000000" step="1" placeholder=move || t("未知", "Unknown") prop:value=move || cost.get() disabled=move || busy.get() on:input=move |event| cost.set(event_target_value(&event)) /></label>
            <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| request.run(false)>{move || t("读取当前属性", "Read current attributes")}</button>
            <button type="button" class="primary" disabled=move || busy.get() || revision.get().is_none() on:click=move |_| request.run(true)>{move || t("保存节点属性", "Save relay attributes")}</button>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            <p role="status">{move || message.get()}</p>
        </section>
    }
}
