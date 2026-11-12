//! Account-visible space management with server revisions and one-use invitations.
use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::{network::SpaceRole, spaces::*};
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
mod service_publication;
use service_publication::SpaceServicesPanel;

#[derive(Clone)]
enum Command {
    List,
    Read(String),
    Create,
    Archive,
    UpdateMember,
    RemoveMember,
    JoinDevice,
    RemoveDevice(String, u64),
    Invite,
    RevokeInvitation(String),
    Accept,
    Audit,
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

fn invitation_parts(link: &str) -> Option<(String, String, String)> {
    let (_, fragment) = link.trim().split_once("#space-invite=")?;
    let parts: Vec<_> = fragment.split('.').collect();
    if parts.len() != 3
        || !nestlink_protocol::valid_id(parts[0])
        || !nestlink_protocol::valid_id(parts[1])
        || parts[2].len() != 43
        || !parts[2]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    Some((parts[0].into(), parts[1].into(), parts[2].into()))
}

fn origin() -> String {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        return window.location().origin().unwrap_or_default();
    }
    String::new()
}

fn take_invitation_link() -> String {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        let location = window.location();
        let value = location.href().unwrap_or_default();
        if invitation_parts(&value).is_some() {
            if let (Ok(history), Ok(path), Ok(search)) =
                (window.history(), location.pathname(), location.search())
            {
                let _ = history.replace_state_with_url(
                    &wasm_bindgen::JsValue::NULL,
                    "",
                    Some(&format!("{path}{search}")),
                );
            }
            return value;
        }
    }
    String::new()
}

pub(super) fn invitation_pending() -> bool {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        return window
            .location()
            .href()
            .ok()
            .is_some_and(|link| invitation_parts(&link).is_some());
    }
    false
}

#[component]
pub(super) fn SpacesPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    is_admin: bool,
) -> impl IntoView {
    let tab = RwSignal::new(0_u8);
    let dialog = RwSignal::new(0_u8);
    let spaces = RwSignal::new(Vec::<SpaceView>::new());
    let details = RwSignal::new(None::<SpaceDetails>);
    let devices = RwSignal::new(Vec::<(String, String)>::new());
    let audit = RwSignal::new(Vec::<SpaceAuditEntry>::new());
    let name = RwSignal::new(String::new());
    let account = RwSignal::new(String::new());
    let selected_role = RwSignal::new("member".to_owned());
    let installation = RwSignal::new(String::new());
    let invitation_target = RwSignal::new(String::new());
    let invitation_minutes = RwSignal::new("60".to_owned());
    let incoming_link = RwSignal::new(String::new());
    let issued_link = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let close_dialog = Callback::new(move |()| {
        if !busy.get_untracked() {
            dialog.set(0);
            name.set(String::new());
            incoming_link.set(String::new());
            problem.set(String::new());
        }
    });
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));

    let request = Callback::new(move |command: Command| {
        if busy.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let current = details.get_untracked();
        let draft_name = name.get_untracked();
        let chosen_account = account.get_untracked();
        let chosen_role = role(&selected_role.get_untracked());
        let chosen_device = installation.get_untracked();
        let target = invitation_target.get_untracked();
        let minutes = invitation_minutes
            .get_untracked()
            .parse::<u64>()
            .ok()
            .filter(|minutes| (1..=1440).contains(minutes));
        let incoming = invitation_parts(&incoming_link.get_untracked());
        let session = session_revision.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        issued_link.set(String::new());
        spawn_local(async move {
            let result = async {
                let client = sdk.lock().await;
                let active = || {
                    alive.load(Ordering::Acquire)
                        && session_revision.try_get_untracked() == Some(session)
                };
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let mut issued = None;
                let mut audit_rows = None;
                let selected = match &command {
                    Command::List => None,
                    Command::Read(id) => Some(id.clone()),
                    Command::Create => Some(
                        client
                            .create_space(SpaceCreateRequest { name: draft_name })
                            .await?
                            .space_id,
                    ),
                    Command::Accept => {
                        let (space, invitation, token) = incoming.ok_or(SdkError::Invalid)?;
                        Some(
                            client
                                .accept_space_invitation(
                                    &space,
                                    &invitation,
                                    SpaceInvitationAcceptance { token },
                                )
                                .await?
                                .space_id,
                        )
                    }
                    _ => {
                        let current = current.as_ref().ok_or(SdkError::Invalid)?;
                        let space = &current.space;
                        let revision = SpaceRevisionRequest {
                            expected_revision: space.revision,
                        };
                        match &command {
                            Command::Archive => {
                                client.archive_space(&space.space_id, revision).await?;
                            }
                            Command::UpdateMember | Command::RemoveMember => {
                                let member = current
                                    .members
                                    .iter()
                                    .find(|member| member.account_id == chosen_account)
                                    .ok_or(SdkError::Invalid)?;
                                if matches!(&command, Command::UpdateMember) {
                                    client
                                        .update_space_member(
                                            &space.space_id,
                                            &chosen_account,
                                            SpaceMemberUpdate {
                                                expected_revision: space.revision,
                                                expected_member_epoch: member.member_epoch,
                                                role: chosen_role.ok_or(SdkError::Invalid)?,
                                            },
                                        )
                                        .await?;
                                } else {
                                    client
                                        .remove_space_member(
                                            &space.space_id,
                                            &chosen_account,
                                            SpaceMemberRemoval {
                                                expected_revision: space.revision,
                                                expected_member_epoch: member.member_epoch,
                                            },
                                        )
                                        .await?;
                                }
                            }
                            Command::JoinDevice => {
                                let epoch = current
                                    .devices
                                    .iter()
                                    .find(|device| device.installation_id == chosen_device)
                                    .map_or(0, |device| device.membership_epoch);
                                client
                                    .join_space_device(
                                        &space.space_id,
                                        SpaceDeviceJoin {
                                            expected_revision: space.revision,
                                            expected_membership_epoch: epoch,
                                            installation_id: chosen_device,
                                        },
                                    )
                                    .await?;
                            }
                            Command::RemoveDevice(id, epoch) => {
                                client
                                    .remove_space_device(
                                        &space.space_id,
                                        id,
                                        SpaceDeviceRemoval {
                                            expected_revision: space.revision,
                                            expected_membership_epoch: *epoch,
                                        },
                                    )
                                    .await?;
                            }
                            Command::Invite => {
                                let fresh = client.space_details(&space.space_id).await?;
                                if !active() {
                                    return Err(SdkError::Invalid);
                                }
                                if fresh.space.revision != space.revision {
                                    return Err(SdkError::Invalid);
                                }
                                let now = fresh.space.observed_at_unix_ms;
                                let end = now
                                    .checked_add(minutes.ok_or(SdkError::Invalid)? * 60_000)
                                    .ok_or(SdkError::Invalid)?;
                                issued = Some(
                                    client
                                        .invite_to_space(
                                            &space.space_id,
                                            SpaceInvitationRequest {
                                                expected_revision: space.revision,
                                                role: chosen_role.ok_or(SdkError::Invalid)?,
                                                target_account_id: if target.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(target.trim().into())
                                                },
                                                expires_at_unix_ms: end,
                                            },
                                        )
                                        .await?,
                                );
                            }
                            Command::RevokeInvitation(id) => {
                                client
                                    .revoke_space_invitation(&space.space_id, id, revision)
                                    .await?;
                            }
                            Command::Audit => {
                                audit_rows = Some(client.space_audit(&space.space_id).await?);
                            }
                            _ => return Err(SdkError::Invalid),
                        }
                        Some(space.space_id.clone())
                    }
                };
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let listing = client.spaces().await?;
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let selected = if let Some(id) = selected {
                    Some(client.space_details(&id).await?)
                } else {
                    None
                };
                if !active() {
                    return Err(SdkError::Invalid);
                }
                let choices = client
                    .devices()
                    .await?
                    .into_iter()
                    .filter(|device| !device.revoked)
                    .map(|device| (device.device.id, device.device.name))
                    .collect::<Vec<_>>();
                Ok((listing, selected, choices, issued, audit_rows))
            }
            .await;
            if !alive.load(Ordering::Acquire)
                || session_revision.try_get_untracked() != Some(session)
            {
                return;
            }
            busy.set(false);
            match result {
                Ok((listing, selected, choices, issued, audit_rows)) => {
                    spaces.set(listing);
                    details.set(selected);
                    devices.set(choices);
                    if let Some(rows) = audit_rows {
                        audit.set(rows);
                    } else {
                        audit.set(Vec::new());
                    }
                    if let Some(issued) = issued {
                        issued_link.set(format!(
                            "{}/#space-invite={}.{}.{}",
                            origin(),
                            issued.space.space_id,
                            issued.invitation.invitation_id,
                            issued.token
                        ));
                    }
                    if matches!(command, Command::Accept | Command::Create) {
                        dialog.set(0);
                    }
                    if matches!(command, Command::Accept) {
                        incoming_link.set(String::new());
                    }
                    if matches!(command, Command::Create) {
                        name.set(String::new());
                    }
                    message.set(
                        t(
                            "已读取服务器确认的空间状态。",
                            "Server-confirmed space state loaded.",
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
                    details.set(None);
                    audit.set(Vec::new());
                    problem.set(format!(
                        "{} {}",
                        sdk_error(&error),
                        t(
                            "草稿已保留，请重新读取空间后再修改。",
                            "Draft retained. Read the space again before changing it."
                        )
                    ));
                }
            }
        });
    });

    Effect::new(move |_| {
        let _ = session_revision.get();
        spaces.set(Vec::new());
        details.set(None);
        devices.set(Vec::new());
        audit.set(Vec::new());
        name.set(String::new());
        account.set(String::new());
        selected_role.set("member".into());
        installation.set(String::new());
        invitation_target.set(String::new());
        invitation_minutes.set("60".into());
        incoming_link.set(take_invitation_link());
        issued_link.set(String::new());
        dialog.set(if incoming_link.get_untracked().is_empty() {
            0
        } else {
            2
        });
        tab.set(0);
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
        request.run(Command::List);
    });

    view! {
            <section class="spaces-workspace" aria-label=move || t("网络空间", "Network spaces") aria-busy=move || busy.get().to_string()>
                <div class="space-toolbar"><p class="info-callout">{move || t("管理多设备的私有组网、空间成员与服务访问权限。账号登录设备请在「设备管理」查看。", "Manage private networks, people and service access. Find account sign-ins under Login devices.")}</p><button class="secondary" type="button" data-space-action="join" on:click=move |_| dialog.set(2)>{move || t("加入空间", "Join space")}</button><Show when=move || is_admin><button class="secondary" type="button" data-space-action="network" on:click=move |_| tab.set(2)>{move || t("受管网络", "Managed networks")}</button></Show><button class="primary" type="button" data-space-action="create" on:click=move |_| dialog.set(1)>{move || t("新建空间", "New space")}</button></div>
                <Show when=move || !problem.get().is_empty()><p role="alert" class="error-message">{move || problem.get()}</p></Show>
                <p role="status">{move || message.get()}</p>
                <div class="space-layout"><aside class="space-list">
                    <button type="button" class="text-button" disabled=move || busy.get() on:click=move |_| request.run(Command::List)>{move || t("读取我的空间", "Read my spaces")}</button>
                    {move || spaces.get().into_iter().map(|space| {
                        let id = space.space_id.clone();
                        let active_id = space.space_id;
                        view! { <button type="button" class="space-card" class:active=move || details.with(|current| current.as_ref().is_some_and(|current| current.space.space_id == active_id)) disabled=move || busy.get() on:click=move |_| request.run(Command::Read(id.clone()))><super::WorkspaceIcon kind=super::Section::Spaces /><strong>{space.name}</strong><small>" · "{role_name(space.role)}{if space.archived { " · archived" } else { "" }}</small></button> }
                    }).collect_view()}
                    <Show when=move || spaces.with(Vec::is_empty)><p class="muted">{move || t("创建空间或接受邀请，开始连接你的设备。", "Create a space or accept an invitation to connect your devices.")}</p></Show>
                </aside><div class="space-detail">
                    <Show when=move || details.get().is_some() fallback=move || view! { <div class="empty-state"><super::WorkspaceIcon kind=super::Section::Spaces /><h2>{move || t("你的空间，从这里开始", "Your space starts here")}</h2><p>{move || t("从左侧选择空间，查看设备、成员与授权。", "Choose a space to review its devices, people and access.")}</p></div> }>
                        <header class="space-detail-head"><div class="device-symbol"><super::WorkspaceIcon kind=super::Section::Spaces /></div><div><h2>{move || details.with(|current| current.as_ref().map(|current| current.space.name.clone()).unwrap_or_default())}</h2><p class="muted">{move || details.with(|current| current.as_ref().map(|current| format!("{} · revision {}", role_name(current.space.role), current.space.revision)).unwrap_or_default())}</p></div></header>
                        <div class="workspace-tabs space-tabs" role="tablist" aria-label=move || t("空间页面", "Space pages")>
                            {[(0_u8,"空间设备","Devices"),(1,"空间成员","Members"),(2,"受管网络","Managed networks"),(3,"服务授权","Service access")].into_iter().map(|(value,zh,en)| view! { <button type="button" role="tab" class="nav-item" class:active=move || tab.get()==value aria-selected=move || (tab.get()==value).to_string() data-space-tab=value on:click=move |_| tab.set(value)>{move || t(zh,en)}</button> }).collect_view()}
                        </div>
                        <div class="space-tab-body form-stack" role="tabpanel" hidden=move || tab.get()!=0>                <label>{move || t("已登记设备", "Registered device")}<select data-space-field="device" prop:value=move || installation.get() disabled=move || busy.get() on:change=move |event| installation.set(event_target_value(&event))>
                        <option value="">{move || t("选择设备", "Choose a device")}</option>
                        {move || devices.get().into_iter().map(|(id, name)| view! { <option value=id>{name}</option> }).collect_view()}
                    </select></label>
                    <button type="button" class="primary" disabled=move || busy.get() || installation.get().is_empty() || details.get().is_none_or(|details| details.space.archived) on:click=move |_| request.run(Command::JoinDevice)>{move || t("加入或重新加入此设备", "Join or rejoin device")}</button>
                    {move || details.get().into_iter().flat_map(|details| details.devices).map(|device| {
                        let id = device.installation_id;
                        let epoch = device.membership_epoch;
                        view! { <div><span>{device.name} " · " {role_name(device.role)} {if device.active { " · active" } else { " · revoked" }}</span><button type="button" class="secondary" disabled=move || busy.get() || !device.active on:click=move |_| request.run(Command::RemoveDevice(id.clone(), epoch))>{move || t("移除设备", "Remove device")}</button></div> }
                    }).collect_view()}
    </div>
                        <div class="space-tab-body form-stack" role="tabpanel" hidden=move || tab.get()!=1>
                            <Show when=move || details.get().is_some_and(|current| !matches!(current.space.role, SpaceRole::Owner | SpaceRole::Admin))><p class="muted">{move || t("成员角色由空间所有者或管理员管理。", "Space owners and administrators manage member roles.")}</p>{move || details.get().into_iter().flat_map(|current| current.members).map(|member| view! { <div class="space-row"><strong>{member.name}</strong><span>{role_name(member.role)}</span></div> }).collect_view()}</Show>                <Show when=move || details.get().is_some_and(|details| matches!(details.space.role, SpaceRole::Owner | SpaceRole::Admin) && !details.space.archived)>
                        <label>{move || t("空间成员", "Space member")}<select data-space-field="account" prop:value=move || account.get() disabled=move || busy.get() on:change=move |event| account.set(event_target_value(&event))>
                            <option value="">{move || t("选择成员", "Choose a member")}</option>
                            {move || details.get().into_iter().flat_map(|details| details.members).map(|member| view! { <option value=member.account_id>{member.name} " · " {role_name(member.role)} {if member.active { "" } else { " · revoked" }}</option> }).collect_view()}
                        </select></label>
                        <label>{move || t("成员或邀请角色", "Member or invitation role")}<select data-space-field="role" prop:value=move || selected_role.get() disabled=move || busy.get() on:change=move |event| selected_role.set(event_target_value(&event))>
                            <option value="member">"member"</option><option value="guest">"guest"</option>


                                            <Show when=move || details.get().is_some_and(|details| details.space.role == SpaceRole::Owner)><option value="admin">"admin"</option><option value="owner">{move || t("转让所有权（仅已有成员）", "Transfer ownership (existing member only)")}</option></Show>
                        </select></label>
                        <button type="button" class="primary" disabled=move || busy.get() || account.get().is_empty() on:click=move |_| request.run(Command::UpdateMember)>{move || t("保存角色或转让所有权", "Save role or transfer ownership")}</button>
                        <button type="button" class="secondary" disabled=move || busy.get() || account.get().is_empty() on:click=move |_| request.run(Command::RemoveMember)>{move || t("移除成员及其空间设备", "Remove member and their space devices")}</button>
                        <label>{move || t("邀请限定账号编号（可选）", "Invitation account ID (optional)")}<input data-space-field="target" maxlength="36" prop:value=move || invitation_target.get() disabled=move || busy.get() on:input=move |event| invitation_target.set(event_target_value(&event)) /></label>
                        <label>{move || t("邀请有效分钟数（1–1440）", "Invitation lifetime in minutes (1–1440)")}<input data-space-field="lifetime" type="number" min="1" max="1440" prop:value=move || invitation_minutes.get() disabled=move || busy.get() on:input=move |event| invitation_minutes.set(event_target_value(&event)) /></label>
                        <button type="button" class="primary" disabled=move || busy.get() || selected_role.get() == "owner" on:click=move |_| request.run(Command::Invite)>{move || t("生成一次性邀请", "Create one-use invitation")}</button>
                        {move || details.get().into_iter().flat_map(|details| details.invitations).map(|invitation| {
                            let id = invitation.invitation_id.clone();
                            view! { <div><span>{invitation.invitation_id} " · " {role_name(invitation.role)} {if invitation.consumed { " · consumed" } else if invitation.revoked { " · revoked" } else { "" }}</span><button type="button" class="secondary" disabled=move || busy.get() || invitation.revoked || invitation.consumed on:click=move |_| request.run(Command::RevokeInvitation(id.clone()))>{move || t("撤销邀请", "Revoke invitation")}</button></div> }
                        }).collect_view()}
                    </Show>
                    <Show when=move || details.get().is_some_and(|details| details.space.role == SpaceRole::Owner && !details.space.archived)>
                        <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| request.run(Command::Archive)>{move || t("归档空间并撤销全部设备和邀请", "Archive space and revoke all devices and invitations")}</button>
                    </Show>
                    <Show when=move || details.get().is_some_and(|details| matches!(details.space.role, SpaceRole::Owner | SpaceRole::Admin))>
                        <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| request.run(Command::Audit)>{move || t("读取最近100条空间审计", "Read latest 100 space audit entries")}</button>
                        {move || audit.get().into_iter().map(|entry| view! { <p>{entry.sequence} " · " {entry.action} " · " {entry.actor_account_id} " · " {entry.target_id}</p> }).collect_view()}
                    </Show>

                        </div>
                        <div class="space-tab-body" role="tabpanel" hidden=move || tab.get()!=3><SpaceServicesPanel api session_revision auth_failure details /></div>
                    </Show>
                        <div class="space-tab-body" role="tabpanel" hidden=move || tab.get()!=2>
                            <Show when=move || is_admin fallback=move || view! { <p class="info-callout">{move || t("受管网络配置由控制中心管理员管理。", "Control center administrators manage network configuration.")}</p> }><details class="managed-network"><summary>{move || t("受管网络与高级配置", "Managed networks and advanced configuration")}</summary><super::network_membership_panel::NetworkMembershipPanel api session_revision auth_failure /></details></Show>
                        </div>
                </div></div>
                <Show when=move || dialog.get()!=0>
                    <super::TaskDialog open=Signal::derive(move || dialog.get()!=0) label=Signal::derive(move || if dialog.get()==1 { t("创建空间","Create space") } else { t("加入空间","Join space") }.to_owned()) on_close=close_dialog>
                        <form class="space-dialog-form" on:submit=move |event: leptos::ev::SubmitEvent| {
                            event.prevent_default();
                            if dialog.get_untracked()==1 && !name.get_untracked().trim().is_empty() {
                                request.run(Command::Create);
                            } else if dialog.get_untracked()==2 && invitation_parts(&incoming_link.get_untracked()).is_some() {
                                request.run(Command::Accept);
                            }
                        }>
                            <header class="dialog-head"><h2>{move || if dialog.get()==1 { t("创建空间","Create space") } else { t("加入空间","Join space") }}</h2></header>
                            <div class="dialog-body form-stack">
                                <label hidden=move || dialog.get()!=1>{move || t("新空间名称", "New space name")}<input data-space-field="name" maxlength="80" prop:value=move || name.get() disabled=move || busy.get() on:input=move |event| name.set(event_target_value(&event)) /></label>
                                <label hidden=move || dialog.get()!=2>{move || t("一次性邀请链接", "One-use invitation link")}<input data-space-field="incoming" type="password" autocomplete="off" prop:value=move || incoming_link.get() disabled=move || busy.get() on:input=move |event| incoming_link.set(event_target_value(&event)) /></label>
                                <p class="form-error" role="alert">{move || problem.get()}</p>
                            </div>
                            <footer class="confirmation-actions">
                                <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| close_dialog.run(())>{move || t("取消", "Cancel")}</button>
                                <button type="submit" class="primary" disabled=move || busy.get() || if dialog.get()==1 { name.get().trim().is_empty() } else { invitation_parts(&incoming_link.get()).is_none() }>{move || if busy.get() { t("正在提交…", "Submitting…") } else if dialog.get()==1 { t("创建空间", "Create space") } else { t("接受邀请加入空间", "Accept invitation") }}</button>
                            </footer>
                        </form>
                    </super::TaskDialog>
                </Show>
                            <Show when=move || !issued_link.get().is_empty()>
                    <label>{move || t("请复制并妥善交付此链接；关闭面板后无法再次读取。", "Copy and deliver this link securely. It cannot be read again after closing this panel.")}<input data-space-field="issued" readonly autocomplete="off" prop:value=move || issued_link.get() /></label>
                    <button type="button" class="secondary" on:click=move |_| {
                        #[cfg(target_arch = "wasm32")]
                        if let Some(window) = web_sys::window() {
                            let session = session_revision.get_untracked();
                            let operation = window.navigator().clipboard().write_text(&issued_link.get_untracked());
                            spawn_local(async move {
                                if wasm_bindgen_futures::JsFuture::from(operation).await.is_err()
                                    && session_revision.try_get_untracked() == Some(session) {
                                    let _ = problem.try_set(t("复制失败，请手动复制链接。", "Copy failed. Copy the link manually.").into());
                                }
                            });
                        }
                    }>{move || t("复制邀请链接", "Copy invitation link")}</button>
                    <button type="button" class="secondary" on:click=move |_| issued_link.set(String::new())>{move || t("清除此链接", "Clear link")}</button>
                </Show>

            </section>
        }
}
