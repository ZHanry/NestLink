//! Account-owned standard-client management. Browser state never creates a
//! private key, consumes a packet start, or configures an operating-system port.
use super::topology::{expiry, now_ms};
use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nestlink_identity::{
    network::{NetworkVerification, verify_network_grant},
    subnet::{SubnetGatewayState, verify_subnet_mapping},
    wireguard::{WireGuardPortalState, verify_wireguard_client_binding},
};
use nestlink_protocol::{
    network::{GrantClaims, NetworkAccessClaims},
    network_access::NetworkAccessView,
    spaces::SpaceView,
    subnet::SubnetMappingClaims,
    wireguard::{WIREGUARD_BINDING_VERSION, WireGuardClientBindingClaims, management::*},
};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Clone)]
struct Prepared {
    business: NetworkAccessClaims,
    access_digest: [u8; 32],
    mapping: SubnetMappingClaims,
    installation: String,
    address: Ipv4Addr,
    lease_end: u64,
}
#[derive(Clone)]
struct Binding {
    claims: WireGuardClientBindingClaims,
    digest: [u8; 32],
    total: u64,
    committed: u64,
}
#[derive(Clone, Copy)]
enum Action {
    Load,
    Preview,
    Read,
    Issue,
    Revoke,
}
enum Reply {
    Loaded(SpaceView),
    Prepared(SpaceView, Box<Prepared>),
    Bound(SpaceView, Box<Binding>),
    Revoked(SpaceView),
}
fn same_policy(policy: &NetworkPolicyView, space: &SpaceView) -> bool {
    policy.space_id == space.space_id
        && policy.deployment_id == space.deployment_id
        && policy.authority_public_key == space.authority_public_key
        && policy.policy_epoch == space.policy_epoch
        && policy.revision == space.revision
}
fn public_key(value: &str) -> Result<[u8; 32], SdkError> {
    let key: [u8; 32] = STANDARD
        .decode(value)
        .map_err(|_| SdkError::Invalid)?
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    if key == [0; 32] || STANDARD.encode(key) != value {
        return Err(SdkError::Invalid);
    }
    Ok(key)
}
fn prepared(
    view: &NetworkAccessView,
    space: &SpaceView,
    id: &str,
    account: &str,
) -> Result<Prepared, SdkError> {
    let now = now_ms();
    let observed = view.address_directory.space.observed_at_unix_ms;
    let directory_space = &view.address_directory.space;
    if directory_space.space_id != space.space_id
        || directory_space.deployment_id != space.deployment_id
        || directory_space.policy_epoch != space.policy_epoch
        || directory_space.authority_public_key != space.authority_public_key
        || now < observed
        || now - observed >= 5000
    {
        return Err(SdkError::Invalid);
    }
    let authority: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&space.authority_public_key)
        .map_err(|_| SdkError::Invalid)?
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &authority,
        deployment_id: &space.deployment_id,
        space_id: &space.space_id,
        policy_epoch: space.policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let access = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&view.access)?,
        &context,
    )?;
    let GrantClaims::NetworkAccess(business) = access.claims() else {
        return Err(SdkError::Invalid);
    };
    let member_grant = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&view.source_membership)?,
        &context,
    )?;
    let GrantClaims::Membership(member) = member_grant.claims() else {
        return Err(SdkError::Invalid);
    };
    let source = view
        .address_directory
        .addresses
        .first()
        .ok_or(SdkError::Invalid)?;
    if business.scope.grant_id != id
        || member.peer != business.source
        || member.installation_id != source.installation_id
        || member.membership_epoch != source.membership_epoch
        || URL_SAFE_NO_PAD.encode(member.public_key) != source.public_key
        || source.account_id != account
    {
        return Err(SdkError::Invalid);
    }
    let mut selected = None;
    for mapping in &view.subnet_mappings {
        if mapping.gateway.public_key != member.public_key {
            continue;
        }
        if selected.is_some() || !same_policy(&mapping.policy, space) {
            return Err(SdkError::Invalid);
        }
        let export = verify_network_grant(
            &nestlink_sdk::network_management::decode_network_grant(&mapping.route_export)?,
            &context,
        )?;
        let gateway = SubnetGatewayState {
            node_id: &mapping.gateway.node_id,
            public_key: &mapping.gateway.public_key,
            incarnation: &mapping.gateway.incarnation,
            mapping_revision: mapping.gateway.mapping_revision,
            lease_expires_at_ms: mapping.gateway.lease_expires_at_ms,
        };
        let mapping_verified = verify_subnet_mapping(&mapping.mapping, &context, export, &gateway)?;
        let claims = mapping_verified.claims();
        let IpAddr::V4(address) = claims.alias.network else {
            return Err(SdkError::Invalid);
        };
        if claims.original != claims.alias
            || claims.alias.prefix_len != 32
            || business.source_prefixes.as_slice() != [claims.alias]
            || business.scope.expires_at_ms > claims.scope.expires_at_ms
        {
            return Err(SdkError::Invalid);
        }
        selected = Some(Prepared {
            business: business.clone(),
            access_digest: access.digest(),
            mapping: claims.clone(),
            installation: source.installation_id.clone(),
            address,
            lease_end: mapping.gateway.lease_expires_at_ms,
        });
    }
    selected.ok_or(SdkError::Invalid)
}
fn verified_binding(
    view: &WireGuardClientBindingView,
    space: &SpaceView,
    id: &str,
    account: &str,
) -> Result<Binding, SdkError> {
    if !same_policy(&view.policy, space) {
        return Err(SdkError::Invalid);
    }
    let raw = WireGuardClientBindingClaims::decode_canonical(&view.binding.claims)?;
    let original = prepared(&view.packet_access, space, &raw.access_grant_id, account)?;
    let authority: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&space.authority_public_key)
        .map_err(|_| SdkError::Invalid)?
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &authority,
        deployment_id: &space.deployment_id,
        space_id: &space.space_id,
        policy_epoch: space.policy_epoch,
        now_ms: now_ms(),
        revoked_grant_ids: &revoked,
    };
    let access = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&view.packet_access.access)?,
        &context,
    )?;
    let portal = WireGuardPortalState {
        node_id: &original.mapping.gateway_node_id,
        public_key: &original.mapping.gateway_public_key,
        incarnation: &original.mapping.gateway_incarnation,
        lease_expires_at_ms: original.lease_end,
        client_revision: raw.client_revision,
    };
    let verified = verify_wireguard_client_binding(&view.binding, &context, access, &portal)?;
    let claims = verified.claims();
    if claims.scope.grant_id != id
        || claims.account_id != account
        || claims.installation_id != original.installation
        || claims.client_address != original.address
        || claims.committed_bytes > view.committed_bytes
        || view.committed_bytes > view.total_byte_ceiling
    {
        return Err(SdkError::Invalid);
    }
    Ok(Binding {
        claims: claims.clone(),
        digest: verified.digest(),
        total: view.total_byte_ceiling,
        committed: view.committed_bytes,
    })
}

#[component]
pub(super) fn WireGuardClientPanel(
    api: Api,
    space: RwSignal<String>,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let policy = RwSignal::new(None::<SpaceView>);
    let preview = RwSignal::new(None::<Prepared>);
    let current = RwSignal::new(None::<Binding>);
    let access_id = RwSignal::new(String::new());
    let binding_id = RwSignal::new(nestlink_auth::random_id());
    let client_id = RwSignal::new(nestlink_auth::random_id());
    let key = RwSignal::new(String::new());
    let ceiling = RwSignal::new(String::new());
    let approved = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    let edited = Callback::new(move |()| {
        approved.set(false);
        message.set(String::new());
    });
    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked().trim().to_owned();
        let binding_id = binding_id.get_untracked().trim().to_owned();
        let access_id = access_id.get_untracked().trim().to_owned();
        let draft_client = client_id.get_untracked().trim().to_owned();
        let draft_key = public_key(key.get_untracked().trim()).ok();
        let draft_ceiling = ceiling
            .get_untracked()
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0 && *v <= i64::MAX as u64);
        let old = current.get_untracked();
        let snapshot = policy.get_untracked().filter(|p| p.space_id == space_id);
        let expected = preview.get_untracked();
        if !nestlink_protocol::valid_id(&space_id)
            || (!matches!(action, Action::Load) && snapshot.is_none())
            || (matches!(action, Action::Preview | Action::Issue)
                && !nestlink_protocol::valid_id(&access_id))
            || (matches!(action, Action::Read | Action::Issue | Action::Revoke)
                && !nestlink_protocol::valid_id(&binding_id))
            || (matches!(action, Action::Issue)
                && (!approved.get_untracked()
                    || expected.is_none()
                    || draft_key.is_none()
                    || draft_ceiling.is_none()
                    || !nestlink_protocol::valid_id(&draft_client)))
            || (matches!(action, Action::Revoke)
                && (!approved.get_untracked()
                    || old
                        .as_ref()
                        .is_none_or(|b| b.claims.scope.grant_id != binding_id)))
        {
            problem.set(t("请先读取空间和原业务，并明确确认当前客户端草稿。","Load the space and original business, then explicitly confirm the exact client draft.").into());
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let operation = generation.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        approved.set(false);
        problem.set(String::new());
        message.set(String::new());
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
                let latest = client.space_details(&space_id).await?.space;
                if !active()
                    || latest.archived
                    || latest.space_id != space_id
                    || latest.deployment_id != client.health().deployment_id
                {
                    return Err(SdkError::Invalid);
                }
                if matches!(action, Action::Load) {
                    return Ok(Reply::Loaded(latest));
                }
                let snapshot = snapshot.as_ref().ok_or(SdkError::Invalid)?;
                if snapshot.authority_public_key != latest.authority_public_key
                    || snapshot.deployment_id != latest.deployment_id
                    || snapshot.policy_epoch != latest.policy_epoch
                    || snapshot.revision != latest.revision
                {
                    return Err(SdkError::Invalid);
                }
                let account = &client.principal().ok_or(SdkError::SignIn)?.account_id;
                if matches!(action, Action::Revoke) {
                    let old = old.as_ref().ok_or(SdkError::Invalid)?;
                    let view = client
                        .revoke_wireguard_client(
                            &space_id,
                            &binding_id,
                            &WireGuardClientRevoke {
                                expected_revision: latest.revision,
                                expected_client_revision: old.claims.client_revision,
                            },
                        )
                        .await?;
                    if !active() {
                        return Err(SdkError::Invalid);
                    }
                    let after = client.space_details(&space_id).await?.space;
                    if !same_policy(&view, &after)
                        || after.authority_public_key != snapshot.authority_public_key
                        || after.policy_epoch != snapshot.policy_epoch
                    {
                        return Err(SdkError::Invalid);
                    }
                    return Ok(Reply::Revoked(after));
                }
                let requested = if matches!(action, Action::Preview | Action::Issue) {
                    let view = client.network_access(&space_id, &access_id).await?;
                    if !active() {
                        return Err(SdkError::Invalid);
                    }
                    Some(prepared(&view, &latest, &access_id, account)?)
                } else {
                    None
                };
                if matches!(action, Action::Preview) {
                    return Ok(Reply::Prepared(
                        latest,
                        Box::new(requested.ok_or(SdkError::Invalid)?),
                    ));
                }
                let view = if matches!(action, Action::Issue) {
                    let original = requested.as_ref().ok_or(SdkError::Invalid)?;
                    if expected.as_ref().is_none_or(|p| {
                        p.access_digest != original.access_digest || p.mapping != original.mapping
                    }) {
                        return Err(SdkError::Invalid);
                    }
                    let request = WireGuardClientBindingRequest {
                        binding_version: WIREGUARD_BINDING_VERSION,
                        grant_id: binding_id.clone(),
                        client_id: draft_client.clone(),
                        expected_client_revision: old
                            .as_ref()
                            .filter(|b| b.claims.client_id == draft_client)
                            .map_or(0, |b| b.claims.client_revision),
                        expected_revision: latest.revision,
                        expected_policy_epoch: latest.policy_epoch,
                        installation_id: original.installation.clone(),
                        portal_node_id: original.mapping.gateway_node_id.clone(),
                        expected_portal_incarnation: original.mapping.gateway_incarnation.clone(),
                        access_grant_id: access_id.clone(),
                        client_public_key: draft_key.ok_or(SdkError::Invalid)?,
                        client_address: original.address,
                        total_byte_ceiling: draft_ceiling.ok_or(SdkError::Invalid)?,
                        expires_at_ms: original.business.scope.expires_at_ms,
                    };
                    client
                        .issue_wireguard_client_binding(&space_id, &request)
                        .await?
                } else {
                    client
                        .wireguard_client_binding(&space_id, &binding_id)
                        .await?
                };
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let after = client.space_details(&space_id).await?.space;
                if !active()
                    || after.authority_public_key != snapshot.authority_public_key
                    || after.policy_epoch != snapshot.policy_epoch
                {
                    return Err(SdkError::Invalid);
                }
                let binding = verified_binding(&view, &after, &binding_id, account)?;
                if matches!(action, Action::Issue)
                    && (binding.claims.client_id != draft_client
                        || Some(binding.claims.client_public_key) != draft_key
                        || binding.claims.access_grant_id != access_id
                        || Some(binding.total) != draft_ceiling)
                {
                    return Err(SdkError::Invalid);
                }
                Ok(Reply::Bound(after, Box::new(binding)))
            }
            .await;
            if !active() {
                return;
            }
            busy.set(false);
            match result {
                Ok(Reply::Loaded(view)) => {
                    policy.set(Some(view));
                    preview.set(None);
                    current.set(None);
                    message.set(t("空间已读取。请核验已由目标设备批准的原业务。","Space loaded. Verify the original business approved by the target device.").into());
                }
                Ok(Reply::Prepared(view, prepared)) => {
                    policy.set(Some(view));
                    ceiling.set(prepared.business.byte_limit.to_string());
                    preview.set(Some(*prepared));
                    message.set(t("原业务和客户端专用地址已核验。填写客户端公钥后确认。","Original business and dedicated client address verified. Enter the client public key and confirm.").into());
                }
                Ok(Reply::Bound(view, binding)) => {
                    policy.set(Some(view));
                    client_id.set(binding.claims.client_id.clone());
                    key.set(STANDARD.encode(binding.claims.client_public_key));
                    ceiling.set(binding.total.to_string());
                    access_id.set(binding.claims.access_grant_id.clone());
                    current.set(Some(*binding));
                    message.set(t("客户端授权已核验。网关应用仍需本机批准后才启用隧道。","Client authority verified. The gateway application still needs local approval before enabling its tunnel.").into());
                }
                Ok(Reply::Revoked(view)) => {
                    policy.set(Some(view));
                    preview.set(None);
                    current.set(None);
                    message.set(
                        t(
                            "客户端已撤销，原密钥和业务不能恢复。",
                            "Client revoked. Its original key and business cannot resume.",
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    policy.set(None);
                    preview.set(None);
                    current.set(None);
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error,SdkError::Api(status,_)if status.as_u16()==401)
                    {
                        auth_failure.run(sdk);
                        return;
                    }
                    problem.set(format!(
                        "{} {}",
                        sdk_error(&error),
                        t(
                            "草稿已保留，请重新读取空间和业务。",
                            "Draft retained. Reload the space and business."
                        )
                    ));
                }
            }
        });
    });
    Effect::new(move |_| {
        let _ = space.get();
        let _ = session_revision.get();
        generation.update(|v| *v = v.wrapping_add(1));
        policy.set(None);
        preview.set(None);
        current.set(None);
        access_id.set(String::new());
        binding_id.set(nestlink_auth::random_id());
        client_id.set(nestlink_auth::random_id());
        key.set(String::new());
        ceiling.set(String::new());
        approved.set(false);
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
    });
    view! {
        <section class="policy-form form-stack" aria-label=move||t("WireGuard 客户端","WireGuard clients") aria-busy=move||busy.get().to_string()>
            <h2>{move||t("WireGuard 客户端","WireGuard clients")}</h2>
            <p class="muted">{move||t("连接标准 WireGuard 客户端。目标设备须先批准具体地址、端口和总额度；每个客户端使用独立密钥与专用地址。","Connect a standard WireGuard client. The target device first approves exact addresses, ports and the total budget. Each client uses its own key and dedicated address.")}</p>
            <button type="button" class="secondary" disabled=move||busy.get() on:click=move |_|request.run(Action::Load)>{move||t("读取客户端空间","Read client space")}</button>
            <label>{move||t("原业务编号","Original business ID")}<input data-wg-field="access" maxlength="36" disabled=move||busy.get() prop:value=move||access_id.get() on:input=move|e|{access_id.set(event_target_value(&e));preview.set(None);edited.run(());}/></label>
            <button type="button" class="secondary" disabled=move||busy.get()||policy.get().is_none() on:click=move |_|request.run(Action::Preview)>{move||t("核验客户端原业务","Verify client business")}</button>
            {move||preview.get().map(|p|view!{<p>{format!("{} · {} · {} {} · {} {}",p.mapping.gateway_node_id,p.address,t("字节预算","Byte budget"),p.business.byte_limit,t("到期","Expires"),expiry(p.business.scope.expires_at_ms))}</p>})}
            <label>{move||t("客户端编号","Client ID")}<input data-wg-field="client" maxlength="36" disabled=move||busy.get() prop:value=move||client_id.get() on:input=move|e|{client_id.set(event_target_value(&e));edited.run(());}/></label>
            <label>{move||t("授权编号","Binding ID")}<input data-wg-field="binding" maxlength="36" disabled=move||busy.get() prop:value=move||binding_id.get() on:input=move|e|{binding_id.set(event_target_value(&e));current.set(None);edited.run(());}/></label>
            <button type="button" class="secondary" disabled=move||busy.get()||policy.get().is_none() on:click=move |_|request.run(Action::Read)>{move||t("读取客户端授权","Read client binding")}</button>
            <button type="button" class="secondary" disabled=move||busy.get() on:click=move |_|{binding_id.set(nestlink_auth::random_id());edited.run(());}>{move||t("生成新授权编号","Generate new binding ID")}</button>
            <label>{move||t("客户端公钥","Client public key")}<input data-wg-field="key" maxlength="44" autocomplete="off" disabled=move||busy.get() prop:value=move||key.get() on:input=move|e|{key.set(event_target_value(&e));edited.run(());}/></label>
            <label>{move||t("此客户端累计字节上限","Client cumulative byte ceiling")}<input data-wg-field="ceiling" type="number" min="1" disabled=move||busy.get() prop:value=move||ceiling.get() on:input=move|e|{ceiling.set(event_target_value(&e));edited.run(());}/></label>
            <p class="muted">{move||t("轮换密钥会继续扣除同一累计额度；每次使用新的已批准业务和专用地址。私钥仅在本机客户端保管，配置和二维码由网关应用受保护地导出。","Key rotation continues charging the same cumulative ceiling. Each rotation needs a new approved business and dedicated address. Keep private keys in the local client; export configuration and QR codes securely from the gateway application.")}</p>
            {move||current.get().map(|b|view!{<p>{format!("{} · {} {} · {}/{} bytes · {} {}",b.claims.client_id,t("修订","Revision"),b.claims.client_revision,b.committed,b.total,t("到期","Expires"),expiry(b.claims.scope.expires_at_ms))}</p><p class="muted">{format!("{}: {} · {}: {}",t("授权核验值","Binding digest"),URL_SAFE_NO_PAD.encode(b.digest),t("原业务核验值","Business digest"),URL_SAFE_NO_PAD.encode(b.claims.access_digest))}</p>})}
            <label><input data-wg-field="approval" type="checkbox" disabled=move||busy.get() prop:checked=move||approved.get() on:change=move|e|approved.set(event_target_checked(&e))/>{move||t("确认上述精确客户端、原业务、密钥和累计上限","Confirm this exact client, original business, key and cumulative ceiling")}</label>
            <button type="button" class="primary" disabled=move||busy.get()||!approved.get()||preview.get().is_none() on:click=move |_|request.run(Action::Issue)>{move||t("批准客户端密钥绑定","Approve client key binding")}</button>
            <button type="button" class="secondary" disabled=move||busy.get()||!approved.get()||current.get().is_none() on:click=move |_|request.run(Action::Revoke)>{move||t("撤销当前客户端","Revoke current client")}</button>
            <p role="status">{move||message.get()}</p>
            <Show when=move||!problem.get().is_empty()><p role="alert">{move||problem.get()}</p></Show>
        </section>
    }
}
