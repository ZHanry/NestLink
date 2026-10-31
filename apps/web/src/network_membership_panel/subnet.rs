//! Explicit management of immutable subnet mappings. Local gateway consent and
//! the original packet business remain independent of this publication UI.
use super::topology::{expiry, now_ms, prefixes};
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    network::{NetworkVerification, verify_network_grant},
    subnet::{SubnetGatewayState, verify_subnet_mapping},
};
use nestlink_protocol::{
    NodeRole,
    network::IpPrefix,
    network_topology::BootIncarnation,
    subnet::{SUBNET_MAPPING_VERSION, SubnetMappingClaims, management::*},
};
use std::collections::BTreeSet;

#[derive(Clone)]
struct Gateway {
    id: String,
    name: String,
    key: [u8; 32],
    incarnation: BootIncarnation,
    lease_end: u64,
}

#[derive(Clone, Copy)]
enum Action {
    Load,
    Read,
    Issue,
    Revoke,
}

enum Reply {
    Loaded(NetworkPolicyView, Vec<Gateway>, bool),
    Mapping(NetworkPolicyView, Box<SubnetMappingClaims>),
    Revoked(NetworkPolicyView),
}

fn single_prefix(text: &str) -> Result<IpPrefix, SdkError> {
    let values = prefixes(text).map_err(|_| SdkError::Invalid)?;
    if values.len() != 1 {
        return Err(SdkError::Invalid);
    }
    Ok(values[0])
}

/// The authority is pinned to the previously loaded deployment policy. The
/// gateway key and boot come from an independent authenticated node listing.
fn verified_claims(
    view: &SubnetMappingView,
    snapshot: &NetworkPolicyView,
    expected_space: &str,
    expected_id: &str,
    gateway: &Gateway,
) -> Result<SubnetMappingClaims, SdkError> {
    if view.policy.space_id != expected_space
        || view.policy.deployment_id != snapshot.deployment_id
        || view.policy.policy_epoch != snapshot.policy_epoch
        || view.policy.authority_public_key != snapshot.authority_public_key
        || view.gateway.node_id != gateway.id
        || view.gateway.public_key != gateway.key
        || view.gateway.incarnation != gateway.incarnation
        || view.gateway.lease_expires_at_ms > gateway.lease_end
    {
        return Err(SdkError::Invalid);
    }
    let authority: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&snapshot.authority_public_key)
        .map_err(|_| SdkError::Invalid)?
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &authority,
        deployment_id: &snapshot.deployment_id,
        space_id: expected_space,
        policy_epoch: snapshot.policy_epoch,
        now_ms: now_ms().max(view.policy.observed_at_unix_ms),
        revoked_grant_ids: &revoked,
    };
    let export = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&view.route_export)?,
        &context,
    )?;
    let verified = verify_subnet_mapping(
        &view.mapping,
        &context,
        export,
        &SubnetGatewayState {
            node_id: &gateway.id,
            public_key: &gateway.key,
            incarnation: &gateway.incarnation,
            mapping_revision: view.gateway.mapping_revision,
            lease_expires_at_ms: gateway.lease_end.min(view.gateway.lease_expires_at_ms),
        },
    )?;
    if verified.claims().scope.grant_id != expected_id {
        return Err(SdkError::Invalid);
    }
    Ok(verified.claims().clone())
}

#[component]
pub(super) fn SubnetMappingPanel(
    api: Api,
    space: RwSignal<String>,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let policy = RwSignal::new(None::<NetworkPolicyView>);
    let gateways = RwSignal::new(Vec::<Gateway>::new());
    let manager = RwSignal::new(false);
    let selected = RwSignal::new(String::new());
    let mapping_id = RwSignal::new(nestlink_auth::random_id());
    let export_id = RwSignal::new(String::new());
    let original = RwSignal::new(String::new());
    let alias = RwSignal::new(String::new());
    let minutes = RwSignal::new("5".to_owned());
    let approved = RwSignal::new(false);
    let current = RwSignal::new(None::<SubnetMappingClaims>);
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let clock = RwSignal::new(now_ms());
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    #[cfg(target_arch = "wasm32")]
    {
        let alive = alive.clone();
        spawn_local(async move {
            while alive.load(Ordering::Acquire) {
                gloo_timers::future::TimeoutFuture::new(1000).await;
                if alive.load(Ordering::Acquire) {
                    clock.set(now_ms());
                }
            }
        });
    }
    let edited = Callback::new(move |()| {
        approved.set(false);
        message.set(String::new());
    });
    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked().trim().to_owned();
        let id = mapping_id.get_untracked().trim().to_owned();
        let snapshot = policy.get_untracked().filter(|p| p.space_id == space_id);
        if !nestlink_protocol::valid_id(&space_id)
            || (!matches!(action, Action::Load)
                && (snapshot.is_none() || !nestlink_protocol::valid_id(&id)))
        {
            problem.set(
                t(
                    "请先读取有效空间，并填写映射编号。",
                    "Load a valid space and enter a mapping ID first.",
                )
                .into(),
            );
            return;
        }
        let draft_gateway = selected.get_untracked();
        let draft_export = export_id.get_untracked().trim().to_owned();
        let draft_prefixes = single_prefix(&original.get_untracked())
            .and_then(|original| Ok((original, single_prefix(&alias.get_untracked())?)));
        let intended_prefixes = draft_prefixes.as_ref().ok().copied();
        let end = minutes
            .get_untracked()
            .parse::<u64>()
            .ok()
            .filter(|value| (1..=15).contains(value))
            .and_then(|value| {
                snapshot
                    .as_ref()?
                    .observed_at_unix_ms
                    .checked_add(value * 60_000)
            });
        let old = current.get_untracked().filter(|c| c.scope.grant_id == id);
        if matches!(action, Action::Issue)
            && (!manager.get_untracked()
                || !approved.get_untracked()
                || !nestlink_protocol::valid_id(&draft_export)
                || !gateways
                    .get_untracked()
                    .iter()
                    .any(|g| g.id == draft_gateway && g.lease_end > now_ms())
                || draft_prefixes.is_err()
                || end.is_none_or(|end| end <= now_ms())
                || old.is_some())
        {
            problem.set(t("请选择当前网关、填写原导出授权与两个规范 CIDR，读取新快照后确认发布。已有映射须用新编号重新签发。", "Select a live gateway, enter the original export and two canonical CIDRs, then confirm publication after loading a fresh snapshot. Reissuing requires a new mapping ID.").into());
            return;
        }
        if matches!(action, Action::Revoke) && (!manager.get_untracked() || old.is_none()) {
            problem.set(
                t(
                    "请先读取要撤销的映射。",
                    "Read the mapping to revoke first.",
                )
                .into(),
            );
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let operation = generation.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        approved.set(false);
        spawn_local(async move {
            let active = || {
                alive.load(Ordering::Acquire)
                    && session_revision.try_get_untracked() == Some(session)
                    && generation.try_get_untracked() == Some(operation)
                    && space
                        .try_get_untracked()
                        .is_some_and(|s| s.trim() == space_id)
            };
            let result: Result<Reply, SdkError> = async {
                let client = sdk.lock().await;
                if !active() {
                    return Err(SdkError::Invalid);
                }
                if matches!(action, Action::Load) {
                    let view = client.network_policy(&space_id).await?;
                    if !active() {
                        return Err(SdkError::Invalid);
                    }
                    let details = client.space_details(&space_id).await?;
                    if view.deployment_id != client.health().deployment_id
                        || details.space.space_id != space_id
                        || details.space.deployment_id != view.deployment_id
                        || details.space.archived
                    {
                        return Err(SdkError::Invalid);
                    }
                    if !active() {
                        return Err(SdkError::Invalid);
                    }
                    let choices = client
                        .nodes()
                        .await?
                        .into_iter()
                        .filter(|node| {
                            !node.revoked && node.node.roles.contains(&(NodeRole::NodeRelay as i32))
                        })
                        .filter_map(|node| {
                            Some(Gateway {
                                id: node.node.id,
                                name: node.node.name,
                                key: URL_SAFE_NO_PAD
                                    .decode(node.node.public_key)
                                    .ok()?
                                    .try_into()
                                    .ok()?,
                                incarnation: BootIncarnation {
                                    runtime_id: node.runtime_id?,
                                    runtime_generation: node.runtime_generation,
                                },
                                lease_end: node
                                    .last_issued_at_unix_ms
                                    .checked_add(nestlink_protocol::NODE_LEASE_MS)?,
                            })
                        })
                        .collect();
                    return Ok(Reply::Loaded(
                        view,
                        choices,
                        matches!(details.space.role, SpaceRole::Owner | SpaceRole::Admin),
                    ));
                }
                let snapshot = snapshot.as_ref().ok_or(SdkError::Invalid)?;
                if matches!(action, Action::Revoke) {
                    let old = old.as_ref().ok_or(SdkError::Invalid)?;
                    let view = client
                        .revoke_subnet_mapping(
                            &space_id,
                            &id,
                            &SubnetMappingRevoke {
                                expected_revision: snapshot.revision,
                                expected_mapping_revision: old.mapping_revision,
                            },
                        )
                        .await?;
                    if view.space_id != space_id
                        || view.deployment_id != snapshot.deployment_id
                        || view.authority_public_key != snapshot.authority_public_key
                        || view.policy_epoch != snapshot.policy_epoch
                    {
                        return Err(SdkError::Invalid);
                    }
                    return Ok(Reply::Revoked(view));
                }
                let view = if matches!(action, Action::Issue) {
                    let node = gateways
                        .get_untracked()
                        .into_iter()
                        .find(|g| g.id == draft_gateway)
                        .ok_or(SdkError::Invalid)?;
                    let (original, alias) = draft_prefixes?;
                    client
                        .issue_subnet_mapping(
                            &space_id,
                            &SubnetMappingRequest {
                                mapping_version: SUBNET_MAPPING_VERSION,
                                grant_id: id.clone(),
                                gateway_node_id: node.id,
                                route_export_grant_id: draft_export.clone(),
                                expected_revision: snapshot.revision,
                                expected_policy_epoch: snapshot.policy_epoch,
                                expected_gateway_incarnation: node.incarnation,
                                original,
                                alias,
                                expires_at_ms: end.ok_or(SdkError::Invalid)?,
                            },
                        )
                        .await?
                } else {
                    client.subnet_mapping(&space_id, &id).await?
                };
                if !active() {
                    return Err(SdkError::Invalid);
                }
                // Reread the actual accepted boot after the response; an old
                // same-name node or delayed response cannot approve a reboot.
                let node = client
                    .nodes()
                    .await?
                    .into_iter()
                    .find(|node| {
                        node.node.id == view.gateway.node_id
                            && !node.revoked
                            && node.node.roles.contains(&(NodeRole::NodeRelay as i32))
                    })
                    .ok_or(SdkError::Invalid)?;
                let gateway = Gateway {
                    id: node.node.id,
                    name: node.node.name,
                    key: URL_SAFE_NO_PAD
                        .decode(node.node.public_key)
                        .map_err(|_| SdkError::Invalid)?
                        .try_into()
                        .map_err(|_| SdkError::Invalid)?,
                    incarnation: BootIncarnation {
                        runtime_id: node.runtime_id.ok_or(SdkError::Invalid)?,
                        runtime_generation: node.runtime_generation,
                    },
                    lease_end: node
                        .last_issued_at_unix_ms
                        .checked_add(nestlink_protocol::NODE_LEASE_MS)
                        .ok_or(SdkError::Invalid)?,
                };
                let claims = verified_claims(&view, snapshot, &space_id, &id, &gateway)?;
                if matches!(action, Action::Issue)
                    && (claims.gateway_node_id != draft_gateway
                        || Some((claims.original, claims.alias)) != intended_prefixes
                        || view.route_export.grant_id != draft_export
                        || claims.scope.expires_at_ms > end.ok_or(SdkError::Invalid)?)
                {
                    return Err(SdkError::Invalid);
                }
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let latest = client.network_policy(&space_id).await?;
                if latest.space_id != view.policy.space_id
                    || latest.deployment_id != view.policy.deployment_id
                    || latest.policy_epoch != view.policy.policy_epoch
                    || latest.revision != view.policy.revision
                    || latest.authority_public_key != view.policy.authority_public_key
                {
                    return Err(SdkError::Invalid);
                }
                Ok(Reply::Mapping(latest, Box::new(claims)))
            }
            .await;
            if !active() {
                return;
            }
            busy.set(false);
            match result {
                Ok(Reply::Loaded(view, choices, can_manage)) => {
                    policy.set(Some(view));
                    gateways.set(choices);
                    manager.set(can_manage);
                    current.set(None);
                    message.set(t("已读取当前空间及网关；请选择映射或填写发布草稿。", "Current space and gateways loaded. Read a mapping or prepare a publication.").into());
                }
                Ok(Reply::Mapping(view, claims)) => {
                    policy.set(Some(view));
                    current.set(Some(*claims));
                    message.set(t("映射管理授权有效；网关本机批准与原始业务授权须分别完成。", "Mapping management authority is valid. Gateway local consent and original business approval are separate requirements.").into());
                }
                Ok(Reply::Revoked(view)) => {
                    policy.set(Some(view));
                    current.set(None);
                    message.set(
                        t(
                            "映射已撤销；原编号不能复活。",
                            "Mapping revoked. Its original ID cannot be revived.",
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    policy.set(None);
                    current.set(None);
                    gateways.set(Vec::new());
                    manager.set(false);
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401)
                    {
                        auth_failure.run(sdk);
                        return;
                    }
                    problem.set(format!(
                        "{} {}",
                        sdk_error(&error),
                        t(
                            "草稿已保留；请重新读取空间与映射后再提交。",
                            "Draft retained. Reload the space and mapping before submitting again."
                        )
                    ));
                }
            }
        });
    });
    Effect::new(move |_| {
        let _ = session_revision.get();
        let _ = space.get();
        generation.update(|value| *value = value.wrapping_add(1));
        policy.set(None);
        gateways.set(Vec::new());
        manager.set(false);
        current.set(None);
        selected.set(String::new());
        mapping_id.set(nestlink_auth::random_id());
        export_id.set(String::new());
        original.set(String::new());
        alias.set(String::new());
        minutes.set("5".into());
        approved.set(false);
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
    });
    view! {
        <section class="policy-form form-stack" aria-label=move || t("子网映射", "Subnet mappings") aria-busy=move || busy.get().to_string()>
            <h2>{move || t("子网映射", "Subnet mappings")}</h2>
            <p class="muted">{move || t("为重叠站点发布明确的原网段与别名。网关必须已持有同时覆盖两个网段的独立导出授权；IPv6 当前仅支持保持原前缀。", "Publish an exact original and alias prefix for overlapping sites. The gateway needs an independent route export covering both prefixes. IPv6 currently preserves its original prefix.")}</p>
            <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| request.run(Action::Load)>{move || t("读取空间与网关", "Read space and gateways")}</button>
            <label>{move || t("映射编号", "Mapping ID")}<input maxlength="36" disabled=move || busy.get() prop:value=move || mapping_id.get() on:input=move |e| { mapping_id.set(event_target_value(&e)); current.set(None); edited.run(()); } /></label>
            <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| { mapping_id.set(nestlink_auth::random_id()); current.set(None); edited.run(()); }>{move || t("生成新的映射编号", "Generate a new mapping ID")}</button>
            <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::Read)>{move || t("读取并核验映射", "Read and verify mapping")}</button>
            <p role="status">{move || message.get()}</p>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            {move || current.get().map(|claims| view! {
                <p>{format!("{} · {} · {}/{} → {}/{} · {} {} · {} {}", claims.scope.grant_id, claims.gateway_node_id,
                    claims.original.network, claims.original.prefix_len, claims.alias.network, claims.alias.prefix_len,
                    t("修订", "Revision"), claims.mapping_revision, t("到期", "Expires"), expiry(claims.scope.expires_at_ms))}</p>
                <p class="muted">{move || if clock.get() >= claims.scope.expires_at_ms { t("映射已过期，请重新读取状态。", "Mapping expired. Read its status again.") } else { t("管理授权已保存；本页未配置本机网卡、路由或转发。", "Management authority saved. This page has not configured a local adapter, route or forwarding.") }}</p>
            })}
            <button type="button" class="secondary" disabled=move || busy.get() || !manager.get() || current.get().is_none() on:click=move |_| request.run(Action::Revoke)>{move || t("撤销此映射", "Revoke this mapping")}</button>
            <Show when=move || manager.get()>
                <label>{move || t("网关", "Gateway")}<select disabled=move || busy.get() prop:value=move || selected.get() on:change=move |e| { selected.set(event_target_value(&e)); edited.run(()); }>
                    <option value="">{move || t("选择有当前租约的网关", "Choose a gateway with a current lease")}</option>
                    {move || gateways.get().into_iter().map(|g| view! { <option value=g.id.clone()>{format!("{} · {} · {} {}", g.name, g.id, t("租约到期", "Lease ends"), expiry(g.lease_end))}</option> }).collect_view()}
                </select></label>
                <label>{move || t("原导出授权编号", "Original route export ID")}<input maxlength="36" disabled=move || busy.get() prop:value=move || export_id.get() on:input=move |e| { export_id.set(event_target_value(&e)); edited.run(()); } /></label>
                <label>{move || t("原网段 CIDR", "Original prefix CIDR")}<input maxlength="49" disabled=move || busy.get() prop:value=move || original.get() on:input=move |e| { original.set(event_target_value(&e)); edited.run(()); } /></label>
                <label>{move || t("别名网段 CIDR", "Alias prefix CIDR")}<input maxlength="49" disabled=move || busy.get() prop:value=move || alias.get() on:input=move |e| { alias.set(event_target_value(&e)); edited.run(()); } /></label>
                <label>{move || t("请求有效期（1–15分钟，从读取空间时算起）", "Requested lifetime (1–15 minutes from the space read)")}<input type="number" min="1" max="15" disabled=move || busy.get() prop:value=move || minutes.get() on:input=move |e| { minutes.set(event_target_value(&e)); edited.run(()); } /></label>
                <p class="muted">{move || t("实际期限取映射、原导出与网关当前租约的交集。修改草稿后须重新确认；更新已有映射请使用新编号。", "The actual deadline is limited by the mapping, original export and current gateway lease. Confirm again after editing. Use a new ID to replace an existing mapping.")}</p>
                <label><input type="checkbox" disabled=move || busy.get() prop:checked=move || approved.get() on:change=move |e| approved.set(event_target_checked(&e)) />{move || t("确认发布上述精确映射的管理授权", "Confirm publication authority for this exact mapping")}</label>
                <button type="button" class="primary" disabled=move || busy.get() || !approved.get() || current.get().is_some() on:click=move |_| request.run(Action::Issue)>{move || t("签发新映射", "Issue new mapping")}</button>
            </Show>
        </section>
    }
}
