use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::service_plane::publication::{
    ServiceEdgeNamespace, ServiceEdgeNamespaceUpdate,
};
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
struct Draft {
    suffix: String,
    management: String,
    ports: String,
    quic: String,
}
impl Draft {
    fn config(&self) -> Result<ServiceEdgeNamespace, &'static str> {
        let ports = self
            .ports
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| t("公网端口必须是数字。", "Public ports must be numeric."))?;
        let config = ServiceEdgeNamespace {
            service_suffix: self.suffix.clone(),
            management_hostname: self.management.clone(),
            public_ports: ports,
            quic_address: self.quic.clone(),
        };
        config.validate().map_err(|_| t("请检查规范域名、数字 QUIC 地址及端口。端口须升序且不重复，范围 1024–65535，排除 28743–29055；管理域名不能位于服务域名后缀内。", "Check canonical domains, numeric QUIC address and ports. Ports must be ascending and unique, within 1024–65535, excluding 28743–29055. The management hostname must be outside the service suffix."))?;
        Ok(config)
    }
}

#[component]
pub(super) fn EdgeNamespacePanel(
    api: Api,
    node_id: String,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let node_id = StoredValue::new(node_id);
    let draft = RwSignal::new(Draft::default());
    let revision = RwSignal::new(None::<u64>);
    let known_namespace = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let eligible = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let blocked = RwSignal::new(false);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    let request = Callback::new(move |save: bool| {
        if busy.get_untracked() {
            return;
        }
        let update = if save {
            if !eligible.get_untracked() || blocked.get_untracked() {
                return;
            }
            let Some(expected_revision) = revision.get_untracked() else {
                return;
            };
            match draft.get_untracked().config() {
                Ok(config) => Some(ServiceEdgeNamespaceUpdate {
                    expected_revision,
                    config,
                }),
                Err(error) => {
                    problem.set(error.into());
                    return;
                }
            }
        } else {
            None
        };
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let id = node_id.get_value();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        spawn_local(async move {
            let result = {
                let client = sdk.lock().await;
                if !alive.load(Ordering::Acquire)
                    || session_revision.try_get_untracked() != Some(session)
                {
                    return;
                }
                // Check live eligibility for both reads and writes; the server remains authoritative.
                match client.nodes().await {
                    Ok(nodes)
                        if nodes.iter().any(|v| {
                            v.node.id == id && !v.revoked && v.node.roles.contains(&2)
                        }) =>
                    {
                        if !alive.load(Ordering::Acquire)
                            || session_revision.try_get_untracked() != Some(session)
                        {
                            return;
                        }
                        eligible.set(true);
                        if let Some(update) = update {
                            client.set_service_edge_namespace(&id, &update).await
                        } else {
                            client.service_edge_namespace(&id).await
                        }
                    }
                    Ok(_) => {
                        if alive.load(Ordering::Acquire)
                            && session_revision.try_get_untracked() == Some(session)
                        {
                            eligible.set(false);
                            revision.set(None);
                            busy.set(false);
                            problem.set(
                                t(
                                    "仅未撤销的边缘节点可以配置公网入口。",
                                    "Only active edge nodes can configure public ingress.",
                                )
                                .into(),
                            );
                        }
                        return;
                    }
                    Err(error) => Err(error),
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
            match result {
                Ok(view) => {
                    known_namespace.set(true);
                    eligible.set(true);
                    revision.set(Some(view.revision));
                    blocked.set(false);
                    draft.set(Draft {
                        suffix: view.config.service_suffix,
                        management: view.config.management_hostname,
                        ports: view
                            .config
                            .public_ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                        quic: view.config.quic_address,
                    });
                    message.set(
                        if save {
                            t(
                                "公网入口配置已保存。",
                                "Public ingress configuration saved.",
                            )
                        } else {
                            t("已读取当前配置。", "Current configuration loaded.")
                        }
                        .into(),
                    );
                }
                Err(error) => {
                    // A conflict proves a namespace exists, even after a first-create attempt.
                    if matches!(&error, SdkError::Api(status, _) if status.as_u16() == 409) {
                        known_namespace.set(true);
                    }
                    // A failed read never becomes an empty successful configuration.
                    if !save {
                        revision.set(None);
                    }
                    blocked.set(save);
                    problem.set(format!("{} {}", sdk_error(&error), t("草稿已保留。保存前请重新读取；仅确认尚未初始化时选择首次配置。", "Draft retained. Read again before saving; choose first configuration only when the namespace has not been initialized.")));
                }
            }
            busy.set(false);
        });
    });
    Effect::new(move |_| {
        let _ = session_revision.get();
        busy.set(false);
        eligible.set(false);
        revision.set(None);
        blocked.set(false);
        known_namespace.set(false);
        draft.set(Draft::default());
        request.run(false);
    });
    view! {
        <section class="policy-form form-stack" aria-label=move || t("服务公网入口", "Public service ingress") aria-busy=move || busy.get().to_string()>
            <h3>{move || t("服务公网入口", "Public service ingress")}</h3>
            <p class="muted">{move || revision.get().map(|v| format!("{} {v}", t("配置版本", "Configuration revision"))).unwrap_or_else(|| t("尚未读取配置版本", "No configuration revision loaded").into())}</p>
            <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| request.run(false)>{move || if busy.get() { t("正在处理…", "Working…") } else { t("重新读取（替换草稿）", "Read again (replace draft)") }}</button>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            <p role="status">{move || message.get()}</p>
            <Show when=move || eligible.get()>
                <Show when=move || revision.get().is_none() && !known_namespace.get()>
                    <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| { revision.set(Some(0)); blocked.set(false); message.set(t("首次配置将以版本 0 创建；已有配置会被服务器拒绝。", "First configuration uses revision 0; the server rejects it if configuration already exists.").into()); }>{move || t("确认首次配置（版本 0）", "Initialize first configuration (revision 0)")}</button>
                </Show>
                <label>{move || t("服务域名后缀", "Service domain suffix")}<input disabled=move || busy.get() prop:value=move || draft.get().suffix on:input=move |e| draft.update(|d| d.suffix = event_target_value(&e)) /></label>
                <label>{move || t("管理域名", "Management hostname")}<input disabled=move || busy.get() prop:value=move || draft.get().management on:input=move |e| draft.update(|d| d.management = event_target_value(&e)) /></label>
                <label>{move || t("公网端口（升序，逗号分隔）", "Public ports (ascending, comma separated)")}<input disabled=move || busy.get() prop:value=move || draft.get().ports on:input=move |e| draft.update(|d| d.ports = event_target_value(&e)) /></label>
                <label>{move || t("QUIC 数字地址（IP:端口）", "Numeric QUIC address (IP:port)")}<input disabled=move || busy.get() prop:value=move || draft.get().quic on:input=move |e| draft.update(|d| d.quic = event_target_value(&e)) /></label>
                <button class="primary" type="button" disabled=move || busy.get() || revision.get().is_none() || blocked.get() on:click=move |_| request.run(true)>{move || t("保存公网入口", "Save public ingress")}</button>
            </Show>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::Draft;

    fn draft() -> Draft {
        Draft {
            suffix: "services.example.test".into(),
            management: "manage.example.test".into(),
            ports: "1024, 29100\n65535".into(),
            quic: "[2001:db8::1]:29100".into(),
        }
    }

    #[test]
    fn editor_fields_preserve_canonical_protocol_configuration() {
        let Ok(config) = draft().config() else {
            panic!("valid editor fields must produce a configuration");
        };
        assert_eq!(config.public_ports, vec![1024, 29100, 65535]);
        assert_eq!(config.service_suffix, "services.example.test");
        assert_eq!(config.management_hostname, "manage.example.test");
        assert_eq!(config.quic_address, "[2001:db8::1]:29100");
    }

    #[test]
    fn editor_does_not_silently_sort_or_repair_invalid_public_ports() {
        for ports in [
            "",
            "http",
            "65536",
            "1023",
            "28743",
            "29055",
            "29100,29100",
            "29101,29100",
        ] {
            let mut value = draft();
            value.ports = ports.into();
            assert!(value.config().is_err(), "accepted ports {ports:?}");
            assert_eq!(value.ports, ports, "validation changed the user's draft");
        }
    }

    #[test]
    fn editor_rejects_management_overlap_and_nonnumeric_or_noncanonical_quic() {
        for hostname in ["services.example.test", "admin.services.example.test"] {
            let mut value = draft();
            value.management = hostname.into();
            assert!(
                value.config().is_err(),
                "accepted management hostname {hostname}"
            );
        }
        for address in [
            "edge.example.test:29100",
            "0.0.0.0:29100",
            "192.0.2.1:0",
            "[2001:0db8::1]:29100",
        ] {
            let mut value = draft();
            value.quic = address.into();
            assert!(value.config().is_err(), "accepted QUIC address {address}");
        }
    }
}
