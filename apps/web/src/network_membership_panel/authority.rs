//! Explicit deployment-administrator lifecycle controls. Public key readback
//! describes server state and never replaces the operator's local trust pin.
use super::*;
use nestlink_protocol::api::{NetworkAuthorityChangeRequest, NetworkAuthorityView};

#[derive(Clone, Copy)]
enum Action {
    Read,
    Rotate,
    Advance,
    Revoke,
}

#[component]
pub(super) fn NetworkAuthorityControls(
    api: Api,
    space: RwSignal<String>,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    changed: Callback<()>,
) -> impl IntoView {
    let state = RwSignal::new(None::<NetworkAuthorityView>);
    let busy = RwSignal::new(false);
    let confirm_revoke = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    Effect::new(move |_| {
        let _ = (space.get(), session_revision.get());
        generation.update(|value| *value = value.wrapping_add(1));
        state.set(None);
        busy.set(false);
        confirm_revoke.set(false);
        problem.set(String::new());
        message.set(String::new());
    });
    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() {
            return;
        }
        let space_id = space.get_untracked();
        if !nestlink_protocol::valid_id(&space_id) {
            problem.set(t("请先填写有效的空间编号。", "Enter a valid space ID first.").into());
            return;
        }
        let snapshot = state.get_untracked().filter(|value| value.policy.space_id == space_id);
        let mutation = !matches!(action, Action::Read);
        if mutation && snapshot.as_ref().is_none_or(|value| value.revoked) {
            problem.set(t("请先读取有效的空间授权状态。", "Read the active space authority first.").into());
            return;
        }
        if matches!(action, Action::Revoke) && !confirm_revoke.get_untracked() {
            return;
        }
        let Some(sdk) = api.get_value() else {
            return;
        };
        let session = session_revision.get_untracked();
        let captured = generation.get_untracked();
        let alive = alive.clone();
        busy.set(true);
        problem.set(String::new());
        message.set(String::new());
        spawn_local(async move {
            let current = || alive.load(Ordering::Acquire)
                && session_revision.try_get_untracked() == Some(session)
                && generation.try_get_untracked() == Some(captured);
            let result: Result<NetworkAuthorityView, SdkError> = async {
                let client = sdk.lock().await;
                if !current() {
                    return Err(SdkError::Invalid);
                }
                if mutation {
                    let snapshot = snapshot.as_ref().ok_or(SdkError::Invalid)?;
                    let expected = NetworkAuthorityChangeRequest {
                        expected_revision: snapshot.policy.revision,
                        expected_policy_epoch: snapshot.policy.policy_epoch,
                    };
                    match action {
                        Action::Rotate => {
                            client.rotate_network_authority(&space_id, expected).await?;
                        }
                        Action::Advance => {
                            client.advance_network_policy_epoch(&space_id, expected).await?;
                        }
                        Action::Revoke => {
                            client.revoke_network_authority(&space_id, expected).await?;
                        }
                        Action::Read => return Err(SdkError::Invalid),
                    }
                    // Do not issue a second HTTP request after a logout, input
                    // change, or component replacement while mutation awaited.
                    if !current() {
                        return Err(SdkError::Invalid);
                    }
                }
                client.network_authority_state(&space_id).await
            }.await;
            if !current() {
                return;
            }
            busy.set(false);
            confirm_revoke.set(false);
            match result {
                Ok(value) if value.policy.space_id == space_id => {
                    state.set(Some(value));
                    if mutation {
                        changed.run(());
                    }
                    message.set(t("已读取服务器确认的授权状态。", "Server-confirmed authority loaded.").into());
                }
                Ok(_) => {
                    state.set(None);
                    if mutation {
                        changed.run(());
                    }
                    problem.set(t("返回的空间不匹配，请重新读取。", "Returned space does not match. Read again.").into());
                }
                Err(error) => {
                    state.set(None);
                    if mutation {
                        changed.run(());
                    }
                    if matches!(&error, SdkError::SignIn)
                        || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401) {
                        auth_failure.run(sdk);
                        return;
                    }
                    problem.set(format!("{} {}", sdk_error(&error), t(
                        "请重新读取授权状态后再操作。", "Read authority state again before another change."
                    )));
                }
            }
        });
    });
    let active = move || state.get().is_some_and(|value| !value.revoked);
    view! {
        <section class="policy-form form-stack" aria-label=move ||t("空间授权生命周期", "Space authority lifecycle") aria-busy=move ||busy.get().to_string()>
            <h3>{move ||t("空间授权生命周期", "Space authority lifecycle")}</h3>
            <p class="muted">{move ||t("由部署管理员管理上方空间编号的网络授权。轮换或推进策略代次会停止旧网络授权；客户端信任的空间公钥须由本地管理员单独核对和安装。", "Deployment administrators manage network authority for the space ID above. Rotation or advancing the policy epoch stops older network grants. A local administrator must separately verify and install a trusted space public key.")}</p>
            <button class="secondary" type="button" disabled=move ||busy.get() on:click=move |_|request.run(Action::Read)>{move ||t("读取空间授权状态", "Read authority state")}</button>
            <Show when=move ||!problem.get().is_empty()><p role="alert">{move ||problem.get()}</p></Show>
            <p role="status">{move ||message.get()}</p>
            {move ||state.get().map(|value|view! {
                <dl>
                    <dt>{move ||t("空间编号", "Space ID")}</dt><dd>{value.policy.space_id}</dd>
                    <dt>{move ||t("授权修订", "Authority revision")}</dt><dd data-network-authority="revision">{value.policy.revision}</dd>
                    <dt>{move ||t("策略代次", "Policy epoch")}</dt><dd data-network-authority="epoch">{value.policy.policy_epoch}</dd>
                    <dt>{move ||t("密钥代次", "Signing generation")}</dt><dd data-network-authority="generation">{value.signing_generation}</dd>
                    <dt>{move ||t("服务器空间公钥", "Server space public key")}</dt><dd data-network-authority="key"><code>{value.policy.authority_public_key}</code></dd>
                    <dt>{move ||t("状态", "State")}</dt><dd data-network-authority="state">{if value.revoked {t("已永久撤销", "Permanently revoked")} else {t("有效", "Active")}}</dd>
                </dl>
            })}
            <button class="secondary" type="button" disabled=move ||busy.get() ||!active() on:click=move |_|request.run(Action::Rotate)>{move ||t("轮换空间签名密钥", "Rotate space signing key")}</button>
            <button class="secondary" type="button" disabled=move ||busy.get() ||!active() on:click=move |_|request.run(Action::Advance)>{move ||t("推进策略代次", "Advance policy epoch")}</button>
            <label><input type="checkbox" prop:checked=move ||confirm_revoke.get() disabled=move ||busy.get() ||!active() on:change=move |event|confirm_revoke.set(event_target_checked(&event)) />{move ||t("确认永久停止此空间的网络授权，不能重新启用", "Confirm permanent revocation of this space network authority; it cannot be re-enabled")}</label>
            <button class="secondary" type="button" disabled=move ||busy.get() ||!active() ||!confirm_revoke.get() on:click=move |_|request.run(Action::Revoke)>{move ||t("永久撤销空间网络授权", "Permanently revoke space authority")}</button>
        </section>
    }
}
