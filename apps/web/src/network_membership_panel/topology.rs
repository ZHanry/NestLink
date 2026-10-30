//! Administrative publication setup uses the existing SDK and server revisions.
//! Saved publication rights and short-lived observations are separate UI facts.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    network::{NetworkVerification, verify_network_grant},
    network_topology::verify_topology_update,
};
use nestlink_protocol::{
    NodeRole,
    api::{NetworkRouteExportRequest, NetworkTopologyPublisherRequest, NetworkTopologyQuery},
    network::{GrantClaims, IpPrefix, MAX_PREFIXES, PeerId, RouteExportClaims},
    network_topology::{
        MAX_NEIGHBORS, TopologyAdvertisement, TopologyPublisherClaims, TopologySync,
    },
};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Clone)]
struct NodeChoice {
    id: String,
    name: String,
    key: [u8; 32],
    runtime: String,
    generation: u64,
    lease_end: u64,
}

#[derive(Clone, Copy)]
enum Action {
    Load,
    ReadPublisher,
    SavePublisher,
    RevokePublisher,
    ReadExport,
    SaveExport,
    RevokeExport,
    Observe,
}

enum Reply {
    Loaded(NetworkPolicyView, Vec<NodeChoice>),
    Publisher(TopologyPublisherClaims),
    PublisherRevoked,
    Export(NetworkPolicyView, RouteExportClaims),
    ExportRevoked(NetworkPolicyView),
    Observed(Option<TopologyAdvertisement>, u64),
}

fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_millis() as u64)
            .unwrap_or_default()
    }
}

fn prefixes(text: &str) -> Result<Vec<IpPrefix>, &'static str> {
    let invalid = || {
        t(
            "每行填写一个规范 CIDR，最多32项；不允许默认路由、主机位、回环、多播或重复网段。",
            "Enter one canonical CIDR per line, up to 32. Default routes, host bits, loopback, multicast and duplicates are rejected.",
        )
    };
    let mut result = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (address, length) = line.split_once('/').ok_or_else(invalid)?;
        let prefix = IpPrefix {
            network: address.parse::<IpAddr>().map_err(|_| invalid())?,
            prefix_len: length.parse::<u8>().map_err(|_| invalid())?,
        };
        prefix.validate().map_err(|_| invalid())?;
        if result.contains(&prefix) || result.len() >= MAX_PREFIXES {
            return Err(invalid());
        }
        result.push(prefix);
    }
    if result.is_empty() {
        return Err(invalid());
    }
    result.sort_by_key(|prefix| (prefix.network, prefix.prefix_len));
    Ok(result)
}

fn prefix_text(values: &[IpPrefix]) -> String {
    values
        .iter()
        .map(|value| format!("{}/{}", value.network, value.prefix_len))
        .collect::<Vec<_>>()
        .join(", ")
}

fn expiry(value: u64) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(value as f64))
            .to_iso_string()
            .as_string()
            .unwrap_or_else(|| value.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        value.to_string()
    }
}

#[component]
pub(super) fn NetworkTopologyPanel(
    api: Api,
    space: RwSignal<String>,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let policy = RwSignal::new(None::<NetworkPolicyView>);
    let nodes = RwSignal::new(Vec::<NodeChoice>::new());
    let selected = RwSignal::new(String::new());
    let neighbors = RwSignal::new(Vec::<String>::new());
    let minutes = RwSignal::new("10".to_owned());
    let publisher_id = RwSignal::new(nestlink_auth::random_id());
    let export_id = RwSignal::new(nestlink_auth::random_id());
    let cidrs = RwSignal::new(String::new());
    let include_export = RwSignal::new(false);
    let publisher = RwSignal::new(None::<TopologyPublisherClaims>);
    let export = RwSignal::new(None::<RouteExportClaims>);
    let observation = RwSignal::new(None::<TopologyAdvertisement>);
    let observed_at = RwSignal::new(None::<u64>);
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let clock = RwSignal::new(now_ms());
    let generation = RwSignal::new(0_u64);
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
                    let _ = clock.try_set(now_ms());
                }
            }
        });
    }

    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked().trim().to_owned();
        let node_id = selected.get_untracked();
        let node = nodes
            .get_untracked()
            .into_iter()
            .find(|node| node.id == node_id);
        let snapshot = policy
            .get_untracked()
            .filter(|view| view.space_id == space_id);
        let chosen_neighbors = neighbors.get_untracked();
        let chosen_export = export.get_untracked();
        let use_export = include_export.get_untracked();
        let publisher_draft_id = publisher_id.get_untracked();
        let export_draft_id = export_id.get_untracked().trim().to_owned();
        let parse_result = prefixes(&cidrs.get_untracked());
        if !nestlink_protocol::valid_id(&space_id)
            || (!matches!(action, Action::Load) && (node.is_none() || snapshot.is_none()))
        {
            problem.set(
                t(
                    "请填写有效空间编号，读取空间与中继后选择节点。",
                    "Enter a valid space ID, load space and relays, then select a node.",
                )
                .into(),
            );
            return;
        }
        let saving = matches!(action, Action::SavePublisher | Action::SaveExport);
        let mut end = minutes
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
        if matches!(action, Action::SavePublisher) && use_export {
            end = end
                .zip(chosen_export.as_ref())
                .map(|(end, grant)| end.min(grant.scope.expires_at_ms));
        }
        if saving && end.is_none_or(|end| end <= now_ms()) {
            problem.set(t("有效期须为1–15分钟；起点为最近读取空间的服务器时间。请重新读取过期快照。", "Lifetime must be 1–15 minutes from the last server space read. Reload an expired snapshot.").into());
            return;
        }
        if matches!(action, Action::SaveExport) && parse_result.is_err() {
            problem.set(parse_result.err().unwrap_or_default().into());
            return;
        }
        if matches!(
            action,
            Action::SaveExport | Action::ReadExport | Action::RevokeExport
        ) && !nestlink_protocol::valid_id(&export_draft_id)
        {
            problem.set(
                t(
                    "请输入有效的导出授权编号。",
                    "Enter a valid export grant ID.",
                )
                .into(),
            );
            return;
        }
        if matches!(action, Action::SavePublisher) {
            let choices = nodes.get_untracked();
            if chosen_neighbors.len() > MAX_NEIGHBORS
                || chosen_neighbors
                    .iter()
                    .any(|id| id == &node_id || !choices.iter().any(|node| &node.id == id))
                || (use_export
                    && chosen_export.as_ref().is_none_or(|grant| {
                        grant.scope.grant_id != export_draft_id
                            || grant.scope.expires_at_ms <= now_ms()
                    }))
            {
                problem.set(t("请检查相邻节点，并先读取所引用的导出授权；发布授权不得晚于导出授权到期。", "Check neighbors and read the referenced export first. Publisher expiry must not exceed export expiry.").into());
                return;
            }
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
        spawn_local(async move {
            let active = || {
                alive.load(Ordering::Acquire)
                    && session_revision.try_get_untracked() == Some(session)
                    && generation.try_get_untracked() == Some(operation)
            };
            let result: Result<Reply, SdkError> = async {
                let client = sdk.lock().await;
                if !active() {
                    return Err(SdkError::Invalid);
                }
                if matches!(action, Action::Load) {
                    let view = client.network_policy(&space_id).await?;
                    if view.deployment_id != client.health().deployment_id {
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
                            Some(NodeChoice {
                                id: node.node.id,
                                name: node.node.name,
                                key: URL_SAFE_NO_PAD
                                    .decode(node.node.public_key)
                                    .ok()?
                                    .try_into()
                                    .ok()?,
                                runtime: node.runtime_id?,
                                generation: node.runtime_generation,
                                lease_end: node
                                    .last_issued_at_unix_ms
                                    .checked_add(nestlink_protocol::NODE_LEASE_MS)?,
                            })
                        })
                        .collect();
                    return Ok(Reply::Loaded(view, choices));
                }
                let snapshot = snapshot.as_ref().ok_or(SdkError::Invalid)?;
                let node = node.as_ref().ok_or(SdkError::Invalid)?;
                let authority: [u8; 32] = URL_SAFE_NO_PAD
                    .decode(&snapshot.authority_public_key)
                    .map_err(|_| SdkError::Invalid)?
                    .try_into()
                    .map_err(|_| SdkError::Invalid)?;
                match action {
                    Action::SavePublisher | Action::ReadPublisher => {
                        let signed = if matches!(action, Action::SavePublisher) {
                            client
                                .issue_network_topology_publisher(
                                    &space_id,
                                    &node_id,
                                    NetworkTopologyPublisherRequest {
                                        publisher_id: publisher_draft_id.clone(),
                                        expected_policy_epoch: snapshot.policy_epoch,
                                        allowed_node_ids: chosen_neighbors,
                                        route_export_grant_ids: if use_export {
                                            vec![export_draft_id]
                                        } else {
                                            Vec::new()
                                        },
                                        expires_at_ms: end.ok_or(SdkError::Invalid)?,
                                    },
                                )
                                .await?
                        } else {
                            client
                                .network_topology_publisher(&space_id, &node_id)
                                .await?
                        };
                        signed.validate()?;
                        let claims = TopologyPublisherClaims::decode_canonical(&signed.claims)?;
                        if claims.node_id != node_id
                            || claims.public_key != node.key
                            || claims.scope.space_id != space_id
                            || claims.scope.deployment_id != snapshot.deployment_id
                            || claims.scope.policy_epoch != snapshot.policy_epoch
                            || claims.incarnation.runtime_id != node.runtime
                            || claims.incarnation.runtime_generation != node.generation
                            || (matches!(action, Action::SavePublisher)
                                && claims.scope.grant_id != publisher_draft_id)
                        {
                            return Err(SdkError::Invalid);
                        }
                        Ok(Reply::Publisher(claims))
                    }
                    Action::RevokePublisher => {
                        client
                            .revoke_network_topology_publisher(&space_id, &node_id)
                            .await?;
                        Ok(Reply::PublisherRevoked)
                    }
                    Action::SaveExport | Action::ReadExport => {
                        let view = if matches!(action, Action::SaveExport) {
                            client
                                .issue_network_route_export(
                                    &space_id,
                                    &node_id,
                                    NetworkRouteExportRequest {
                                        grant_id: export_draft_id.clone(),
                                        expected_revision: snapshot.revision,
                                        expected_policy_epoch: snapshot.policy_epoch,
                                        prefixes: parse_result.map_err(|_| SdkError::Invalid)?,
                                        expires_at_ms: end.ok_or(SdkError::Invalid)?,
                                    },
                                )
                                .await?
                        } else {
                            client
                                .network_route_export(&space_id, &export_draft_id)
                                .await?
                        };
                        let signed = nestlink_sdk::network_management::decode_network_grant(&view)?;
                        let revoked = BTreeSet::new();
                        let verified = verify_network_grant(
                            &signed,
                            &NetworkVerification {
                                authority_key: &authority,
                                deployment_id: &snapshot.deployment_id,
                                space_id: &space_id,
                                policy_epoch: snapshot.policy_epoch,
                                now_ms: now_ms(),
                                revoked_grant_ids: &revoked,
                            },
                        )?;
                        let GrantClaims::RouteExport(claims) = verified.claims() else {
                            return Err(SdkError::Invalid);
                        };
                        if claims.gateway != PeerId::from_public_key(&node.key)
                            || claims.scope.grant_id != export_draft_id
                        {
                            return Err(SdkError::Invalid);
                        }
                        let claims = claims.clone();
                        if !active() {
                            return Err(SdkError::Invalid);
                        }
                        let current = client.network_policy(&space_id).await?;
                        if current.policy_epoch != claims.scope.policy_epoch
                            || current.authority_public_key != snapshot.authority_public_key
                        {
                            return Err(SdkError::Invalid);
                        }
                        Ok(Reply::Export(current, claims))
                    }
                    Action::RevokeExport => Ok(Reply::ExportRevoked(
                        client
                            .revoke_network_route_export(
                                &space_id,
                                &export_draft_id,
                                snapshot.revision,
                            )
                            .await?,
                    )),
                    Action::Observe => {
                        let nonce = nestlink_auth::random_bytes::<32>();
                        let signed = client
                            .network_topology_update(
                                &space_id,
                                NetworkTopologyQuery {
                                    after_cursor: None,
                                    nonce,
                                },
                            )
                            .await?;
                        let revoked = BTreeSet::new();
                        let verified = verify_topology_update(
                            &signed,
                            &NetworkVerification {
                                authority_key: &authority,
                                deployment_id: &snapshot.deployment_id,
                                space_id: &space_id,
                                policy_epoch: snapshot.policy_epoch,
                                now_ms: now_ms(),
                                revoked_grant_ids: &revoked,
                            },
                            &nonce,
                        )?;
                        let TopologySync::Full { advertisements, .. } = &verified.claims().sync
                        else {
                            return Err(SdkError::Invalid);
                        };
                        let mut found = None;
                        for advertisement in advertisements {
                            let value =
                                TopologyAdvertisement::decode_canonical(&advertisement.claims)?;
                            if value.report.node_id == node_id
                                && value.report.peer == PeerId::from_public_key(&node.key)
                                && value.report.incarnation.runtime_id == node.runtime
                                && value.report.incarnation.runtime_generation == node.generation
                            {
                                found = Some(value);
                            }
                        }
                        Ok(Reply::Observed(found, verified.claims().issued_at_ms))
                    }
                    Action::Load => Err(SdkError::Invalid),
                }
            }
            .await;
            if !active() {
                return;
            }
            busy.set(false);
            clock.set(now_ms());
            match result {
                Ok(Reply::Loaded(view, choices)) if view.space_id == space_id => {
                    let previous = nodes
                        .get_untracked()
                        .into_iter()
                        .find(|node| node.id == node_id);
                    let current = choices.iter().find(|node| node.id == node_id);
                    if previous.as_ref().zip(current).is_none_or(|(old, new)| {
                        old.key != new.key
                            || old.runtime != new.runtime
                            || old.generation != new.generation
                    }) || publisher.get_untracked().is_some_and(|grant| {
                        grant.scope.policy_epoch != view.policy_epoch
                            || grant.scope.deployment_id != view.deployment_id
                    }) || export.get_untracked().is_some_and(|grant| {
                        grant.scope.policy_epoch != view.policy_epoch
                            || grant.scope.deployment_id != view.deployment_id
                    }) {
                        publisher.set(None);
                        export.set(None);
                        include_export.set(false);
                    }
                    observation.set(None);
                    observed_at.set(None);
                    policy.set(Some(view));
                    nodes.set(choices);
                    message.set(t("已读取空间与中继。仅有当前控制租约的节点可以保存授权。", "Space and relays loaded. Saving requires a current node control lease.").into());
                }
                Ok(Reply::Publisher(claims)) => {
                    publisher.set(Some(claims));
                    observation.set(None);
                    observed_at.set(None);
                    publisher_id.set(nestlink_auth::random_id());
                    message.set(t("服务器已保存发布授权。请单独读取节点观测以确认发布。", "Publisher authorization is saved on the server. Read node observations separately to confirm publication.").into());
                }
                Ok(Reply::PublisherRevoked) => {
                    publisher.set(None);
                    observation.set(None);
                    observed_at.set(None);
                    message.set(
                        t(
                            "服务器已撤销该节点在此空间的发布授权。",
                            "The server revoked this node's publisher authorization in this space.",
                        )
                        .into(),
                    );
                }
                Ok(Reply::Export(view, claims)) if view.space_id == space_id => {
                    policy.set(Some(view));
                    export.set(Some(claims));
                    message.set(t("导出授权已由服务器确认；只有明确引用它的发布授权才能发布这些网段。", "Export authorization is confirmed by the server. A publisher must explicitly reference it to publish these prefixes.").into());
                }
                Ok(Reply::ExportRevoked(view)) if view.space_id == space_id => {
                    policy.set(Some(view));
                    export.set(None);
                    include_export.set(false);
                    publisher.set(None);
                    observation.set(None);
                    observed_at.set(None);
                    message.set(t("已撤销导出授权及引用它的发布授权，请重新读取节点状态。", "Export authorization and its dependent publishers are revoked. Read node state again.").into());
                }
                Ok(Reply::Observed(value, at)) => {
                    observation.set(value);
                    observed_at.set(Some(at));
                    message.set(
                        t(
                            "已读取服务器当前拓扑观测。",
                            "Current server topology observations loaded.",
                        )
                        .into(),
                    );
                }
                Ok(_) => {
                    policy.set(None);
                    problem.set(
                        t(
                            "服务器返回的空间不匹配，请重新读取。",
                            "The returned space does not match. Reload it.",
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401)
                    {
                        auth_failure.run(sdk);
                        return;
                    }
                    policy.set(None);
                    observation.set(None);
                    observed_at.set(None);
                    problem.set(format!("{} {}", sdk_error(&error), t("草稿及授权编号已保留。保存结果未确认时，先重新读取空间和相同授权，勿直接新建。", "Drafts and grant IDs are retained. If a save is unconfirmed, reload the space and the same authorization before creating another.")));
                }
            }
        });
    });

    Effect::new(move |_| {
        let _ = (space.get(), session_revision.get());
        generation.update(|value| *value = value.wrapping_add(1));
        policy.set(None);
        nodes.set(Vec::new());
        selected.set(String::new());
        neighbors.set(Vec::new());
        publisher.set(None);
        export.set(None);
        observation.set(None);
        observed_at.set(None);
        publisher_id.set(nestlink_auth::random_id());
        export_id.set(nestlink_auth::random_id());
        cidrs.set(String::new());
        include_export.set(false);
        minutes.set("10".into());
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
    });

    view! {
        <section class="policy-form form-stack" aria-label=move || t("空间中继发布", "Space relay publication") aria-busy=move || busy.get().to_string()>
            <h2>{move || t("空间中继发布", "Space relay publication")}</h2>
            <p class="muted">{move || t("为上方空间明确授权中继发布相邻关系与指定网段。保存授权后，节点还需通过实际探测发布观测；网络访问仍按独立权限执行。", "Authorize relay neighbors and exact prefixes for the space above. After saving, the node must publish observations from actual probes. Network access follows its separate permissions.")}</p>
            <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| request.run(Action::Load)>{move || t("读取空间与中继", "Read space and relays")}</button>
            <p>{move || policy.get().map(|view| format!("revision {} · epoch {}", view.revision, view.policy_epoch)).unwrap_or_else(|| t("请先读取当前空间", "Read the current space first").into())}</p>
            <label>{move || t("发布节点", "Publishing node")}<select data-topology-field="node" prop:value=move || selected.get() disabled=move || busy.get() || policy.get().is_none() on:change=move |event| {
                generation.update(|value| *value = value.wrapping_add(1));
                selected.set(event_target_value(&event)); neighbors.set(Vec::new()); publisher.set(None); export.set(None);
                publisher_id.set(nestlink_auth::random_id()); export_id.set(nestlink_auth::random_id()); cidrs.set(String::new());
                include_export.set(false); observation.set(None); observed_at.set(None); message.set(String::new());
            }>
                <option value="">{move || t("选择已登记中继", "Choose a registered relay")}</option>
                {move || nodes.get().into_iter().map(|node| view! { <option value=node.id>{node.name} {if node.lease_end <= clock.get() { t(" · 最近读取的租约已过期，请刷新", " · last-read lease expired; reload") } else { "" }}</option> }).collect_view()}
            </select></label>
            <Show when=move || !selected.get().is_empty()>
                <fieldset disabled=move || busy.get()>
                    <legend>{move || t("允许探测的相邻节点（最多16个）", "Neighbors allowed for probing (up to 16)")}</legend>
                    {move || nodes.get().into_iter().filter(|node| node.id != selected.get()).map(|node| {
                        let checked_id = node.id.clone(); let change_id = node.id;
                        view! { <label><input type="checkbox" data-topology-field="neighbor" prop:checked=move || neighbors.get().contains(&checked_id) on:change=move |event| {
                            let checked = event_target_checked(&event);
                            neighbors.update(|values| { values.retain(|id| id != &change_id); if checked { values.push(change_id.clone()); } });
                        } />{node.name}</label> }
                    }).collect_view()}
                </fieldset>
                <label>{move || t("有效分钟数（1–15，自最近读取空间的服务器时间起）", "Lifetime in minutes (1–15, from the last server space read)")}<input data-topology-field="minutes" type="number" min="1" max="15" step="1" prop:value=move || minutes.get() disabled=move || busy.get() on:input=move |event| minutes.set(event_target_value(&event)) /></label>
                <h3>{move || t("精确网段导出授权", "Exact prefix export authorization")}</h3>
                <label>{move || t("导出授权编号（可填写已有编号以读取或撤销）", "Export grant ID (enter an existing ID to read or revoke)")}<input data-topology-field="export-id" maxlength="36" prop:value=move || export_id.get() disabled=move || busy.get() on:input=move |event| { export_id.set(event_target_value(&event)); export.set(None); include_export.set(false); } /></label>
                <label>{move || t("获准发布的 CIDR，每行一个", "CIDRs authorized for publication, one per line")}<textarea data-topology-field="prefixes" rows="4" maxlength="2048" placeholder="192.168.20.0/24" prop:value=move || cidrs.get() disabled=move || busy.get() on:input=move |event| cidrs.set(event_target_value(&event))></textarea></label>
                <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| { export_id.set(nestlink_auth::random_id()); export.set(None); include_export.set(false); }>{move || t("新建导出授权编号", "New export grant ID")}</button>
                <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::ReadExport)>{move || t("读取此导出授权", "Read export authorization")}</button>
                <button type="button" class="primary" disabled=move || busy.get() || policy.get().is_none() || export.get().is_some() on:click=move |_| request.run(Action::SaveExport)>{move || t("保存新的精确网段授权", "Save new exact prefix authorization")}</button>
                <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() || !nestlink_protocol::valid_id(&export_id.get()) on:click=move |_| request.run(Action::RevokeExport)>{move || t("撤销此编号的导出及其发布授权", "Revoke this export grant ID and dependent publishers")}</button>
                <p>{move || export.get().map(|grant| format!("{} · {} · {} {}{}", if policy.get().is_some() { t("服务器已保存", "Saved on server") } else { t("上次服务器确认；当前状态未确认", "Previously confirmed; current state unconfirmed") }, prefix_text(&grant.prefixes), t("到期", "expires"), expiry(grant.scope.expires_at_ms), if grant.scope.expires_at_ms <= clock.get() { t(" · 已过期", " · expired") } else { "" })).unwrap_or_else(|| t("尚未读取导出授权", "Export authorization not loaded").into())}</p>
                <label><input data-topology-field="include-export" type="checkbox" prop:checked=move || include_export.get() disabled=move || busy.get() || export.get().is_none() on:change=move |event| include_export.set(event_target_checked(&event)) />{move || t("在此次发布授权中引用上面已读取的精确网段", "Reference the loaded exact prefixes in this publisher authorization")}</label>
                <p class="muted">{move || t("引用导出授权时，发布授权在两者较早的到期时间结束。", "When an export is referenced, publisher authorization ends at the earlier expiry.")}</p>
                <h3>{move || t("节点发布授权", "Node publisher authorization")}</h3>
                <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::ReadPublisher)>{move || t("读取已保存的发布授权", "Read saved publisher authorization")}</button>
                <button type="button" class="primary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::SavePublisher)>{move || t("按当前相邻节点及网段保存或替换发布授权", "Save or replace publisher authorization with the current neighbors and prefixes")}</button>
                <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::RevokePublisher)>{move || t("撤销此节点当前的发布授权", "Revoke this node's current publisher authorization")}</button>
                <p>{move || publisher.get().map(|grant| format!("{} · {} · runtime {} · {} {}{}", if policy.get().is_some() { t("服务器已保存", "Saved on server") } else { t("上次服务器确认；当前状态未确认", "Previously confirmed; current state unconfirmed") }, grant.scope.grant_id, grant.incarnation.runtime_generation, t("到期", "expires"), expiry(grant.scope.expires_at_ms), if grant.scope.expires_at_ms <= clock.get() { t(" · 已过期", " · expired") } else { "" })).unwrap_or_else(|| t("尚未读取发布授权", "Publisher authorization not loaded").into())}</p>
                <p>{move || publisher.get().map(|grant| {
                    let choices = nodes.get();
                    let names = grant.allowed_neighbors.iter().map(|peer| choices.iter().find(|node| PeerId::from_public_key(&node.key) == *peer).map(|node| node.name.clone()).unwrap_or_else(|| t("未在当前节点列表中", "Not in the current node list").into())).collect::<Vec<_>>().join(", ");
                    format!("{}: {} · {}: {}", t("已保存的相邻节点", "Saved neighbors"), names, t("已保存的网段", "Saved prefixes"), prefix_text(&grant.allowed_prefixes))
                }).unwrap_or_default()}</p>
                <button type="button" class="secondary" disabled=move || busy.get() || policy.get().is_none() on:click=move |_| request.run(Action::Observe)>{move || t("读取节点当前发布观测", "Read current node publication observations")}</button>
                <p role="status">{move || {
                    let Some(at) = observed_at.get() else { return t("尚未确认节点发布；保存授权不等于已生效。", "Node publication has not been confirmed; saving authorization does not prove it is active.").to_owned(); };
                    observation.get().map(|value| format!("{} · {} {} · {} {} · {} {} · {} {} · {} {}", if value.expires_at_ms > clock.get() { t("服务器已观测当前节点发布", "Server observed the current node publication") } else { t("此观测已过期，请重新读取", "This observation expired; read it again") }, t("序列", "sequence"), value.report.sequence, t("相邻节点", "neighbors"), value.report.neighbors.iter().filter(|neighbor| neighbor.up).count(), t("网段", "prefixes"), prefix_text(&value.report.prefixes), t("观测时间", "observed"), expiry(at), t("到期", "expires"), expiry(value.expires_at_ms))).unwrap_or_else(|| format!("{} · {}", t("服务器尚无当前节点的发布观测", "The server has no publication observation for the current node"), expiry(at)))
                }}</p>
            </Show>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            <p role="status">{move || message.get()}</p>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_drafts_preserve_exact_networks_and_reject_widening_or_duplicates() {
        let Ok(values) = prefixes("192.168.20.0/24\nfd12:3456::/64") else {
            panic!("canonical prefixes were rejected");
        };
        assert_eq!(values.len(), 2);
        assert_eq!(prefix_text(&values), "192.168.20.0/24, fd12:3456::/64");
        for value in [
            "",
            "0.0.0.0/0",
            "::/0",
            "192.168.20.1/24",
            "fd12:3456::1/64",
            "127.0.0.0/8",
            "224.0.0.0/4",
            "192.168.20.0/24\n192.168.20.0/24",
        ] {
            assert!(
                prefixes(value).is_err(),
                "accepted invalid prefix draft: {value}"
            );
        }
    }

    #[test]
    fn prefix_drafts_bound_the_complete_export_set() {
        let allowed = (0..MAX_PREFIXES)
            .map(|index| format!("10.0.{index}.0/24"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(prefixes(&allowed).is_ok());
        assert!(prefixes(&format!("{allowed}\n10.1.0.0/24")).is_err());
    }
}
