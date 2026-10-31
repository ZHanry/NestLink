//! Address/name management uses the existing authenticated space SDK. A
//! directory record grants neither traffic access nor local system settings.
use super::*;
use nestlink_protocol::spaces::{SpaceDeviceView, addressing::*};

#[derive(Clone, Copy)]
enum Action {
    Load,
    Issue,
    Reserve,
    Rename,
    Revoke,
}

fn manager(directory: &SpaceAddressDirectory) -> bool {
    !directory.space.archived && matches!(directory.space.role, SpaceRole::Owner | SpaceRole::Admin)
}

#[component]
pub(super) fn SpaceAddressPanel(
    api: Api,
    space: RwSignal<String>,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let directory = RwSignal::new(None::<SpaceAddressDirectory>);
    let devices = RwSignal::new(Vec::<SpaceDeviceView>::new());
    let selected = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let ipv4 = RwSignal::new(String::new());
    let ipv6 = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));

    let choose = Callback::new(move |id: String| {
        let record = directory.get_untracked().and_then(|directory| {
            directory
                .addresses
                .into_iter()
                .find(|record| record.installation_id == id)
        });
        name.set(record.as_ref().map(|r| r.name.clone()).unwrap_or_default());
        ipv4.set(record.as_ref().map(|r| r.ipv4.clone()).unwrap_or_default());
        ipv6.set(record.as_ref().map(|r| r.ipv6.clone()).unwrap_or_default());
        selected.set(id);
        message.set(String::new());
    });

    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked().trim().to_owned();
        if !nestlink_protocol::valid_id(&space_id) {
            problem.set(t("请先填写有效的空间编号。", "Enter a valid space ID first.").into());
            return;
        }
        let snapshot = directory
            .get_untracked()
            .filter(|d| d.space.space_id == space_id);
        let installation = selected.get_untracked();
        let record = snapshot
            .as_ref()
            .and_then(|d| {
                d.addresses
                    .iter()
                    .find(|r| r.installation_id == installation)
            })
            .cloned();
        let device = devices
            .get_untracked()
            .into_iter()
            .find(|d| d.installation_id == installation && d.active);
        if !matches!(action, Action::Load)
            && (snapshot.as_ref().is_none_or(|d| !manager(d))
                || !nestlink_protocol::valid_id(&installation)
                || (matches!(action, Action::Issue) && device.is_none())
                || (!matches!(action, Action::Issue) && record.is_none()))
        {
            problem.set(t("请重新读取目录并选择设备；只有空间所有者或管理员可以修改。", "Reload the directory and select a device. Only space owners and administrators can change it.").into());
            return;
        }
        let draft_name = name.get_untracked().trim().to_owned();
        let draft_v4 = ipv4.get_untracked().trim().to_owned();
        let draft_v6 = ipv6.get_untracked().trim().to_owned();
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
                    && space
                        .try_get_untracked()
                        .is_some_and(|s| s.trim() == space_id)
            };
            let result: Result<(SpaceAddressDirectory, Option<Vec<SpaceDeviceView>>), SdkError> =
                async {
                    let client = sdk.lock().await;
                    if !active() {
                        return Err(SdkError::Invalid);
                    }
                    if matches!(action, Action::Load) {
                        let loaded = client.space_address_directory(&space_id).await?;
                        if !active() {
                            return Err(SdkError::Invalid);
                        }
                        let details = client.space_details(&space_id).await?;
                        if details.space.space_id != space_id
                            || loaded.space.deployment_id != client.health().deployment_id
                            || details.space.policy_epoch != loaded.space.policy_epoch
                        {
                            return Err(SdkError::Invalid);
                        }
                        return Ok((loaded, Some(details.devices)));
                    }
                    let snapshot = snapshot.as_ref().ok_or(SdkError::Invalid)?;
                    let epoch = record.as_ref().map_or(0, |r| r.address_epoch);
                    let loaded = match action {
                        Action::Issue => {
                            client
                                .issue_space_address(
                                    &space_id,
                                    SpaceAddressIssue {
                                        expected_revision: snapshot.revision,
                                        expected_address_epoch: epoch,
                                        expected_membership_epoch: device
                                            .as_ref()
                                            .ok_or(SdkError::Invalid)?
                                            .membership_epoch,
                                        installation_id: installation,
                                        name: draft_name,
                                    },
                                )
                                .await?
                        }
                        Action::Reserve => {
                            client
                                .reserve_space_address(
                                    &space_id,
                                    &installation,
                                    SpaceAddressReservation {
                                        expected_revision: snapshot.revision,
                                        expected_address_epoch: epoch,
                                        ipv4: draft_v4,
                                        ipv6: draft_v6,
                                    },
                                )
                                .await?
                        }
                        Action::Rename => {
                            client
                                .rename_space_address(
                                    &space_id,
                                    &installation,
                                    SpaceAddressRename {
                                        expected_revision: snapshot.revision,
                                        expected_address_epoch: epoch,
                                        name: draft_name,
                                    },
                                )
                                .await?
                        }
                        Action::Revoke => {
                            client
                                .revoke_space_address(
                                    &space_id,
                                    &installation,
                                    SpaceAddressRevocation {
                                        expected_revision: snapshot.revision,
                                        expected_address_epoch: epoch,
                                    },
                                )
                                .await?
                        }
                        Action::Load => return Err(SdkError::Invalid),
                    };
                    Ok((loaded, None))
                }
                .await;
            if !active() {
                return;
            }
            busy.set(false);
            match result {
                Ok((loaded, choices)) if loaded.space.space_id == space_id => {
                    if let Some(choices) = choices {
                        devices.set(choices);
                    }
                    directory.set(Some(loaded));
                    message.set(
                        t(
                            "已读取服务器确认的目录。",
                            "Server-confirmed directory loaded.",
                        )
                        .into(),
                    );
                }
                Ok(_) => {
                    directory.set(None);
                    devices.set(Vec::new());
                    problem.set(
                        t(
                            "返回的空间不匹配，请重新读取。",
                            "The returned space does not match. Reload the directory.",
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
                    directory.set(None);
                    devices.set(Vec::new());
                    problem.set(format!(
                        "{} {}",
                        sdk_error(&error),
                        t(
                            "草稿已保留，请重新读取目录后再修改。",
                            "Draft retained. Reload the directory before changing it."
                        )
                    ));
                }
            }
        });
    });
    Effect::new(move |_| {
        let _ = (space.get(), session_revision.get());
        generation.update(|g| *g = g.wrapping_add(1));
        directory.set(None);
        devices.set(Vec::new());
        selected.set(String::new());
        name.set(String::new());
        ipv4.set(String::new());
        ipv6.set(String::new());
        busy.set(false);
        problem.set(String::new());
        message.set(String::new());
    });

    view! {
        <section class="policy-form form-stack" aria-label=move || t("空间地址与名称", "Space addresses and names") aria-busy=move || busy.get().to_string()>
            <h3>{move || t("空间地址与名称", "Space addresses and names")}</h3>
            <p class="muted">{move || t("管理稳定的双栈地址和设备名称。记录不授予端口或远控权限；此页显示目录，尚未配置本机网卡或 DNS。", "Manage stable dual-stack addresses and device names. Records grant no port or remote desktop access. This directory does not configure a local adapter or DNS.")}</p>
            <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| request.run(Action::Load)>{move || t("读取地址目录", "Read address directory")}</button>
            <p role="status">{move || message.get()}</p>
            <Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            {move || directory.get().map(|d| view! {
                <p>{format!("{} · IPv4 {} · IPv6 {}", d.suffix, d.ipv4_pool, d.ipv6_pool)}</p>
                <div class="table-wrap"><table><thead><tr>
                    <th>{t("设备", "Device")}</th><th>{t("账户与身份代次", "Account and identity epochs")}</th><th>{t("名称", "Name")}</th><th>IPv4 / IPv6</th><th>{t("状态", "Status")}</th>
                </tr></thead><tbody>{d.addresses.into_iter().map(|r| {
                    let id = r.installation_id.clone();
                    view! { <tr><td><button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| choose.run(id.clone())>{r.installation_id}</button></td>
                        <td>{r.account_id}<p class="muted">{format!("{} {} / {} {} / {} {}", t("账户代次", "Account epoch"), r.account_member_epoch, t("成员代次", "Membership epoch"), r.membership_epoch, t("地址代次", "Address epoch"), r.address_epoch)}</p></td>
                        <td>{r.fqdn}</td><td>{format!("{} / {}", r.ipv4, r.ipv6)}</td>
                        <td>{if r.revoked { t("已撤销", "Revoked") } else if r.active { t("目录有效", "Active record") } else { t("身份已失效", "Identity inactive") }}<p class="muted">{if r.reserved { t("指定地址保留", "Reserved addresses") } else { t("自动分配", "Automatically assigned") }}</p></td></tr> }
                }).collect_view()}</tbody></table></div>
            })}
            <Show when=move || directory.get().as_ref().is_some_and(manager)>
                <p class="muted">{move || t("签发或重新分配使用当前空间设备的身份；保存名称、保留地址和撤销作用于所选目录记录。历史记录的账户与身份代次见上表。", "Assigning or reassigning uses the current space device identity. Saving a name, reserving addresses and revoking affect the selected directory record. Historical record accounts and identity epochs are shown above.")}</p>
                <label>{move || t("当前空间设备", "Current space device")}<select disabled=move || busy.get() prop:value=move || selected.get() on:change=move |e| choose.run(event_target_value(&e))>
                    <option value="">{move || t("选择设备，或选择表格中的历史记录", "Select a device or a historical record above")}</option>
                    {move || {
                        let id = selected.get();
                        (!id.is_empty() && !devices.get().iter().any(|d| d.active && d.installation_id == id)).then(|| view! {
                            <option value=id.clone()>{format!("{} · {}", t("历史目录记录", "Historical directory record"), id)}</option>
                        })
                    }}
                    {move || devices.get().into_iter().filter(|d| d.active).map(|d| {
                        let label = format!("{} · {} · {}", d.name, d.account_id, d.installation_id);
                        view! { <option value=d.installation_id>{label}</option> }
                    }).collect_view()}
                </select></label>
                <label>{move || t("设备名称（单个 DNS 标签）", "Device name (one DNS label)")}<input maxlength="63" disabled=move || busy.get() prop:value=move || name.get() on:input=move |e| name.set(event_target_value(&e)) /></label>
                <button type="button" class="primary" disabled=move || busy.get() || selected.get().is_empty() on:click=move |_| request.run(Action::Issue)>{move || t("分配或明确重新分配", "Assign or explicitly reassign")}</button>
                <button type="button" class="secondary" disabled=move || busy.get() || selected.get().is_empty() on:click=move |_| request.run(Action::Rename)>{move || t("保存名称", "Save name")}</button>
                <label>IPv4<input maxlength="15" disabled=move || busy.get() prop:value=move || ipv4.get() on:input=move |e| ipv4.set(event_target_value(&e)) /></label>
                <label>IPv6<input maxlength="45" disabled=move || busy.get() prop:value=move || ipv6.get() on:input=move |e| ipv6.set(event_target_value(&e)) /></label>
                <button type="button" class="secondary" disabled=move || busy.get() || selected.get().is_empty() on:click=move |_| request.run(Action::Reserve)>{move || t("保留指定双栈地址", "Reserve these dual-stack addresses")}</button>
                <button type="button" class="secondary" disabled=move || busy.get() || selected.get().is_empty() on:click=move |_| request.run(Action::Revoke)>{move || t("撤销地址与名称", "Revoke addresses and name")}</button>
            </Show>
        </section>
    }
}
