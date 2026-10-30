use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::{
    api::{NetworkMemberRequest, NetworkMemberView, NetworkPolicyView, NetworkRevokeMemberRequest},
    network::SpaceRole,
};
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy)]
enum Command {
    ReadPolicy,
    Initialize,
    ReadMember,
    Add,
    Update,
    Revoke,
}

enum Reply {
    Policy(NetworkPolicyView, Vec<(String, String)>),
    Member(NetworkMemberView),
}

fn role(value: &str) -> Option<SpaceRole> {
    Some(match value {
        "owner" => SpaceRole::Owner,
        "admin" => SpaceRole::Admin,
        "member" => SpaceRole::Member,
        "guest" => SpaceRole::Guest,
        _ => return None,
    })
}

fn role_name(value: SpaceRole) -> &'static str {
    match value {
        SpaceRole::Owner => "owner",
        SpaceRole::Admin => "admin",
        SpaceRole::Member => "member",
        SpaceRole::Guest => "guest",
    }
}

/// Administrative enrollment uses registered device keys at the server. No
/// credential bytes are retained in UI state or treated as business access.
#[component]
pub(super) fn NetworkMembershipPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let space = RwSignal::new(String::new());
    let installation = RwSignal::new(String::new());
    let selected_role = RwSignal::new("member".to_owned());
    let role_dirty = RwSignal::new(false);
    let policy = RwSignal::new(None::<NetworkPolicyView>);
    let member = RwSignal::new(None::<NetworkMemberView>);
    let devices = RwSignal::new(Vec::<(String, String)>::new());
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));

    let request = Callback::new(move |command: Command| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked();
        let installation_id = installation.get_untracked();
        let is_policy = matches!(command, Command::ReadPolicy | Command::Initialize);
        if !nestlink_protocol::valid_id(&space_id)
            || (!is_policy && !nestlink_protocol::valid_id(&installation_id))
        {
            problem.set(t("请输入有效的空间编号，并选择已登记设备。", "Enter a valid space ID and choose a registered device.").into());
            return;
        }
        let current_policy = policy.get_untracked().filter(|p| p.space_id == space_id);
        let current_member = member.get_untracked().filter(|m| {
            m.policy.space_id == space_id && m.installation_id == installation_id
        });
        let Some(chosen_role) = role(&selected_role.get_untracked()) else {
            return;
        };
        let mutation = matches!(command, Command::Add | Command::Update | Command::Revoke);
        if mutation && current_policy.is_none() {
            problem.set(t("请先读取当前空间。", "Read the current space first.").into());
            return;
        }
        if matches!(command, Command::Update | Command::Revoke) && current_member.is_none() {
            problem.set(t("请先读取所选设备的成员状态。", "Read the selected device's membership first.").into());
            return;
        }
        if mutation && !devices.get_untracked().iter().any(|(id, _)| id == &installation_id) {
            problem.set(t("请重新读取设备列表。", "Read the device list again.").into());
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        spawn_local(async move {
            let result: Result<Reply, SdkError> = async {
                let client = sdk.lock().await;
                if !alive.load(Ordering::Acquire)
                    || session_revision.try_get_untracked() != Some(session)
                {
                    return Err(SdkError::Invalid);
                }
                if is_policy {
                    let view = match command {
                        Command::Initialize => client.configure_network_authority(&space_id, 0).await?,
                        _ => client.network_policy(&space_id).await?,
                    };
                    // A logout while the policy call was pending must prevent
                    // the second request from running under a later session.
                    if !alive.load(Ordering::Acquire)
                        || session_revision.try_get_untracked() != Some(session)
                    {
                        return Err(SdkError::Invalid);
                    }
                    let choices = client.devices().await?.into_iter()
                        .filter(|d| !d.revoked)
                        .map(|d| (d.device.id, d.device.name))
                        .collect();
                    return Ok(Reply::Policy(view, choices));
                }
                let view = match command {
                    Command::ReadMember => client.network_member(&space_id, &installation_id).await?,
                    Command::Add | Command::Update => {
                        let snapshot = current_policy.as_ref().ok_or(SdkError::Invalid)?;
                        let epoch = if matches!(command, Command::Add) {
                            0 // Explicit first enrollment; existing membership must conflict.
                        } else {
                            current_member.as_ref().ok_or(SdkError::Invalid)?.membership_epoch
                        };
                        client.set_network_member(&space_id, &installation_id, NetworkMemberRequest {
                            expected_policy_revision: snapshot.revision,
                            expected_membership_epoch: epoch,
                            role: chosen_role,
                        }).await?
                    }
                    Command::Revoke => {
                        client.revoke_network_member(&space_id, &installation_id, NetworkRevokeMemberRequest {
                            expected_policy_revision: current_policy.as_ref().ok_or(SdkError::Invalid)?.revision,
                            expected_membership_epoch: current_member.as_ref().ok_or(SdkError::Invalid)?.membership_epoch,
                        }).await?
                    }
                    _ => return Err(SdkError::Invalid),
                };
                Ok(Reply::Member(view))
            }.await;
            if !alive.load(Ordering::Acquire)
                || session_revision.try_get_untracked() != Some(session)
            {
                return;
            }
            busy.set(false);
            match result {
                Ok(Reply::Policy(view, choices)) if view.space_id == space_id => {
                    policy.set(Some(view));
                    member.set(None);
                    devices.set(choices);
                    message.set(t("已读取空间及可选设备。", "Space and available devices loaded.").into());
                }
                Ok(Reply::Member(view)) if view.policy.space_id == space_id && view.installation_id == installation_id => {
                    policy.set(Some(view.policy.clone()));
                    // A read refreshes the CAS snapshot after a conflict. It
                    // must not replace the role the user is trying to save.
                    if !matches!(command, Command::ReadMember) || !role_dirty.get_untracked() {
                        selected_role.set(role_name(view.role).into());
                        role_dirty.set(false);
                    }
                    member.set(Some(view));
                    message.set(t("已读取服务器确认的成员状态。", "Server-confirmed membership loaded.").into());
                }
                Ok(_) => {
                    policy.set(None);
                    member.set(None);
                    devices.set(Vec::new());
                    problem.set(t("服务器返回的空间或设备不匹配，请重新读取。", "The returned space or device does not match. Read again.").into());
                }
                Err(error) => {
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401)
                    {
                        auth_failure.run(sdk);
                        return;
                    }
                    // Neither a failed read nor an ambiguous mutation result
                    // supplies a revision for a second write. Retain the draft.
                    policy.set(None);
                    member.set(None);
                    problem.set(format!("{} {}", sdk_error(&error), t("草稿已保留。请先重新读取空间与成员状态。", "Draft retained. Read the space and membership again first.")));
                }
            }
        });
    });
    Effect::new(move |_| {
        let _ = session_revision.get();
        space.set(String::new());
        installation.set(String::new());
        selected_role.set("member".into());
        role_dirty.set(false);
        policy.set(None);
        member.set(None);
        devices.set(Vec::new());
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
    });

    view! {
        <section class="policy-form form-stack" aria-label=move || t("空间成员", "Space membership") aria-busy=move || busy.get().to_string()>
            <h2>{move || t("空间成员", "Space membership")}</h2>
            <p class="muted">{move || t("将已登记设备加入指定空间。远控、文件及服务访问仍需单独批准。", "Enroll registered devices in a space. Remote desktop, files, and services each require separate approval.")}</p>
            <label>{move || t("空间编号", "Space ID")}<input maxlength="36" disabled=move || busy.get() prop:value=move || space.get() on:input=move |e| {
                space.set(event_target_value(&e)); selected_role.set("member".into()); role_dirty.set(false); policy.set(None); member.set(None); devices.set(Vec::new()); message.set(String::new());
            } /></label>
            <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| request.run(Command::ReadPolicy)>{move || t("读取空间及设备", "Read space and devices")}</button>
            <button class="secondary" type="button" disabled=move || busy.get() || policy.get().is_some() on:click=move |_| request.run(Command::Initialize)>{move || t("首次初始化此编号（已有空间会拒绝）", "Initialize this ID (existing spaces are rejected)")}</button>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            <p role="status">{move || message.get()}</p>
            <Show when=move || policy.get().is_some()>
                <label>{move || t("已登记设备", "Registered device")}<select disabled=move || busy.get() prop:value=move || installation.get() on:change=move |e| {
                    installation.set(event_target_value(&e)); selected_role.set("member".into()); role_dirty.set(false); member.set(None); message.set(String::new());
                }>
                    <option value="">{move || t("选择设备", "Choose a device")}</option>
                    {move || devices.get().into_iter().map(|(id, name)| view! { <option value=id>{name}</option> }).collect_view()}
                </select></label>
                <button class="secondary" type="button" disabled=move || busy.get() || installation.get().is_empty() on:click=move |_| request.run(Command::ReadMember)>{move || t("读取成员状态", "Read membership")}</button>
                <p>{move || member.get().map(|m| if m.active { t("当前为有效成员", "Membership is active") } else { t("成员已移除", "Membership is revoked") }).unwrap_or(t("尚未读取此设备的成员状态", "Membership has not been read for this device"))}</p>
                <label>{move || t("成员角色", "Member role")}<select disabled=move || busy.get() prop:value=move || selected_role.get() on:change=move |e| {
                    selected_role.set(event_target_value(&e)); role_dirty.set(true);
                }>
                    <option value="owner">{move || t("所有者", "Owner")}</option>
                    <option value="admin">{move || t("空间管理员", "Space administrator")}</option>
                    <option value="member">{move || t("成员", "Member")}</option>
                    <option value="guest">{move || t("访客", "Guest")}</option>
                </select></label>
                <button class="primary" type="button" disabled=move || busy.get() || member.get().is_some() || installation.get().is_empty() on:click=move |_| request.run(Command::Add)>{move || t("首次加入此设备（已加入会拒绝）", "Enroll device for the first time (existing membership is rejected)")}</button>
                <button class="primary" type="button" disabled=move || busy.get() || member.get().is_none() on:click=move |_| request.run(Command::Update)>{move || t("保存角色或重新加入", "Save role or re-enroll")}</button>
                <button class="secondary" type="button" disabled=move || busy.get() || !member.get().is_some_and(|m| m.active) on:click=move |_| request.run(Command::Revoke)>{move || t("移除此设备", "Remove device")}</button>
            </Show>
        </section>
    }
}
