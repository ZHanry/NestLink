//! Explicit service exposure and consumer rights retain the original quota.
use super::*;
use nestlink_protocol::services::private::*;

enum Action { Read, Save, Allow, Revoke(String) }
enum Request {
    Read,
    Save(ServiceExposureUpdate),
    Allow(PrivateServiceAclUpdate),
    Revoke(String, u64),
}

fn mode(value: &str) -> Option<ServiceAccessMode> {
    Some(match value { "private" => ServiceAccessMode::Private, "public" => ServiceAccessMode::Public,
        "both" => ServiceAccessMode::Both, _ => return None })
}
fn mode_name(value: ServiceAccessMode) -> &'static str {
    match value { ServiceAccessMode::Private => "private", ServiceAccessMode::Public => "public", ServiceAccessMode::Both => "both" }
}
fn subject_label(subject: &PrivateServiceSubject) -> String {
    match subject {
        PrivateServiceSubject::Account { account_id } => format!("{}: {account_id}", t("账号", "Account")),
        PrivateServiceSubject::Installation { installation_id } => format!("{}: {installation_id}", t("设备", "Device")),
    }
}

#[component]
pub(super) fn ServiceExposurePanel(
    api: Api, page: RwSignal<Option<ServicePage>>, session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
) -> impl IntoView {
    let selected = RwSignal::new(String::new());
    let policy = RwSignal::new(None::<PrivateServicePolicyView>);
    let loaded = RwSignal::new(false);
    let space = RwSignal::new(String::new());
    let exposure_mode = RwSignal::new("public".to_owned());
    let private_bytes = RwSignal::new("0".to_owned());
    let public_bytes = RwSignal::new(String::new());
    let subject_kind = RwSignal::new("installation".to_owned());
    let subject_id = RwSignal::new(String::new());
    let minutes = RwSignal::new("60".to_owned());
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    Effect::new(move |_| {
        let _ = (selected.get(), session_revision.get(), page.get());
        generation.update(|g| *g = g.wrapping_add(1));
        policy.set(None); loaded.set(false); busy.set(false);
        space.set(String::new()); private_bytes.set("0".into()); public_bytes.set(String::new());
        exposure_mode.set("public".into()); subject_id.set(String::new());
        problem.set(String::new()); message.set(String::new());
    });
    let request = Callback::new(move |action: Action| {
        if busy.get_untracked() { return; }
        let id = selected.get_untracked();
        let service = page.get_untracked().and_then(|p| p.services.into_iter().find(|s| s.id == id));
        let Some(service) = service.filter(|s| s.approval == ServiceApprovalState::ApprovedTarget && s.target_sha256.is_some()) else {
            problem.set(t("请选择已由主机批准目标的服务。", "Select a service whose target the host has approved.").into());
            return;
        };
        let snapshot = policy.get_untracked();
        let invalid = || t("请先读取状态，并检查空间、访问模式、分配额度和消费者有效期。", "Read the current state and check the space, access mode, quotas and consumer expiry.").to_owned();
        let command: Option<Request> = match action {
            Action::Read => Some(Request::Read),
            Action::Save if loaded.get_untracked() => (|| {
                let mode=mode(&exposure_mode.get_untracked())?;
                let space_id=space.get_untracked().trim().to_owned();
                let private_maximum_bytes=private_bytes.get_untracked().parse::<u64>().ok()?;
                let public_maximum_bytes=public_bytes.get_untracked().parse::<u64>().ok()?;
                if !nestlink_protocol::valid_id(&space_id)
                    || private_maximum_bytes.checked_add(public_maximum_bytes)? > service.definition.limits.maximum_bytes
                    || (mode.private_enabled() && private_maximum_bytes == 0)
                    || (mode.public_enabled() && public_maximum_bytes == 0)
                    || (!mode.private_enabled() && private_maximum_bytes != 0)
                    || (!mode.public_enabled() && public_maximum_bytes != 0) { return None; }
                Some(Request::Save(ServiceExposureUpdate { expected_revision:snapshot.as_ref().map_or(0,|p|p.exposure.revision),
                    expected_service_revision:service.revision, space_id, mode, private_maximum_bytes, public_maximum_bytes }))
            })(),
            Action::Allow => (|| {
                let current=snapshot.as_ref().filter(|p|p.exposure.mode.private_enabled())?;
                let id=subject_id.get_untracked().trim().to_owned();
                if !nestlink_protocol::valid_id(&id) { return None; }
                let subject=match subject_kind.get_untracked().as_str() {
                    "account" => PrivateServiceSubject::Account { account_id:id },
                    "installation" => PrivateServiceSubject::Installation { installation_id:id }, _=>return None };
                let duration=minutes.get_untracked().parse::<u64>().ok().filter(|m|(1..=10_080).contains(m))?;
                let now=js_sys::Date::now();
                if !now.is_finite() || now < 0.0 || now > i64::MAX as f64 { return None; }
                Some(Request::Allow(PrivateServiceAclUpdate { expected_exposure_revision:current.exposure.revision,
                    subject, expires_at_unix_ms:(now as u64).checked_add(duration.checked_mul(60_000)?)? }))
            })(),
            Action::Revoke(rule) => snapshot.as_ref().filter(|p|p.rules.iter().any(|r|r.rule_id==rule&&!r.revoked))
                .map(|p|Request::Revoke(rule,p.exposure.revision)),
            _ => None,
        };
        let Some(command)=command else { problem.set(invalid()); return; };
        let Some(sdk)=api.get_value() else { return; };
        let session=session_revision.get_untracked();
        let operation=generation.get_untracked();
        let alive=alive.clone();
        let mutation=!matches!(command,Request::Read);
        busy.set(true); problem.set(String::new()); message.set(String::new());
        spawn_local(async move {
            let current=|| alive.load(Ordering::Acquire)
                && session_revision.try_get_untracked()==Some(session)
                && generation.try_get_untracked()==Some(operation)
                && selected.try_get_untracked().as_deref()==Some(id.as_str());
            let result: Result<Option<PrivateServicePolicyView>,SdkError>=async {
                let sdk=sdk.lock().await;
                if !current() { return Err(SdkError::Invalid); }
                match command {
                    Request::Read => match sdk.service_exposure(&id).await? {
                        None=>Ok(None), Some(_)=>sdk.private_service_policy(&id).await.map(Some),
                    },
                    Request::Save(update) => { sdk.set_service_exposure(&id,update).await?; sdk.private_service_policy(&id).await.map(Some) },
                    Request::Allow(update) => sdk.grant_private_service(&id,update).await.map(Some),
                    Request::Revoke(rule,revision) => sdk.revoke_private_service(&id,&rule,revision).await.map(Some),
                }
            }.await;
            if !current() { return; }
            busy.set(false);
            match result {
                Ok(value) => {
                    if let Some(value)=&value {
                        space.set(value.exposure.space_id.clone()); exposure_mode.set(mode_name(value.exposure.mode).into());
                        private_bytes.set(value.exposure.private_maximum_bytes.to_string());
                        public_bytes.set(value.exposure.public_maximum_bytes.to_string());
                    } else { public_bytes.set(service.definition.limits.maximum_bytes.to_string()); }
                    policy.set(value); loaded.set(true);
                    message.set(if mutation { t("访问设置已更新。现有访问按当前授权重新校验。", "Access settings updated. Existing access is checked against the current authorization.") }
                        else { t("已读取当前设置。", "Current settings loaded.") }.into());
                },
                Err(error) => {
                    policy.set(None); loaded.set(false);
                    if authentication_lost(&error) { auth_failure.run(sdk); return; }
                    problem.set(format!("{} {}",sdk_error(&error),t("请重新读取当前设置再操作；已提交的更改可能已经生效。", "Read current settings before another operation; a submitted change may already have taken effect.")));
                },
            }
        });
    });
    view! {
        <section class="policy-form form-stack" aria-label=move||t("服务访问范围与消费者", "Service exposure and consumers") aria-busy=move||busy.get().to_string()>
            <h2>{move||t("服务访问范围与消费者", "Service exposure and consumers")}</h2>
            <p class="muted">{move||t("为主机已批准的服务选择私有、公网或两种访问方式。私有与公网额度共同受原服务累计额度限制；空间成员仍需明确的消费者授权。", "Choose private, public or both for a host-approved service. Private and public reservations share its original total quota. Space members still need explicit consumer authorization.")}</p>
            <label>{move||t("服务", "Service")}<select disabled=move||busy.get() prop:value=move||selected.get() on:change=move|e|selected.set(event_target_value(&e))>
                <option value="">{move||t("选择已批准的服务", "Choose an approved service")}</option>
                <For each=move||page.get().map(|p|p.services.into_iter().filter(|s|s.approval==ServiceApprovalState::ApprovedTarget&&s.target_sha256.is_some()).collect::<Vec<_>>()).unwrap_or_default()
                    key=|s|s.id.clone() children=move|s|view!{<option value=s.id>{s.definition.name}</option>} />
            </select></label>
            <button class="secondary" type="button" disabled=move||busy.get()||selected.get().is_empty() on:click=move|_|request.run(Action::Read)>{move||t("读取访问设置", "Read access settings")}</button>
            <Show when=move||!problem.get().is_empty()><p role="alert">{move||problem.get()}</p></Show><p role="status">{move||message.get()}</p>
            <Show when=move||loaded.get()>
                <label>{move||t("空间编号", "Space ID")}<input maxlength="36" disabled=move||busy.get() prop:value=move||space.get() on:input=move|e|space.set(event_target_value(&e)) /></label>
                <label>{move||t("访问方式", "Access mode")}<select disabled=move||busy.get() prop:value=move||exposure_mode.get() on:change=move|e|exposure_mode.set(event_target_value(&e))>
                    <option value="private">{move||t("仅私有访问", "Private only")}</option><option value="public">{move||t("仅公网入口", "Public only")}</option><option value="both">{move||t("私有与公网", "Private and public")}</option>
                </select></label>
                <label>{move||t("私有额度（字节）", "Private quota (bytes)")}<input type="number" min="0" step="1" disabled=move||busy.get() prop:value=move||private_bytes.get() on:input=move|e|private_bytes.set(event_target_value(&e)) /></label>
                <label>{move||t("公网额度（字节）", "Public quota (bytes)")}<input type="number" min="0" step="1" disabled=move||busy.get() prop:value=move||public_bytes.get() on:input=move|e|public_bytes.set(event_target_value(&e)) /></label>
                <p class="muted">{move||t("两项之和不得超过原服务总额度。未启用的访问方式填 0。更改访问设置会使先前的私有授权失效。", "Their sum must not exceed the original service quota. Enter 0 for a disabled mode. Changing exposure invalidates previous private authorization.")}</p>
                <button type="button" class="primary" disabled=move||busy.get() on:click=move|_|request.run(Action::Save)>{move||t("保存访问范围", "Save exposure")}</button>
            </Show>
            <Show when=move||policy.get().is_some_and(|p|p.exposure.mode.private_enabled())>
                <h3>{move||t("授权私有消费者", "Authorize private consumers")}</h3>
                <label>{move||t("消费者类型", "Consumer type")}<select disabled=move||busy.get() prop:value=move||subject_kind.get() on:change=move|e|subject_kind.set(event_target_value(&e))>
                    <option value="installation">{move||t("指定设备", "Specific device")}</option><option value="account">{move||t("指定账号", "Specific account")}</option>
                </select></label>
                <label>{move||t("消费者编号", "Consumer ID")}<input maxlength="36" disabled=move||busy.get() prop:value=move||subject_id.get() on:input=move|e|subject_id.set(event_target_value(&e)) /></label>
                <label>{move||t("有效分钟数（1–10080）", "Validity in minutes (1–10080)")}<input type="number" min="1" max="10080" step="1" disabled=move||busy.get() prop:value=move||minutes.get() on:input=move|e|minutes.set(event_target_value(&e)) /></label>
                <button type="button" class="primary" disabled=move||busy.get() on:click=move|_|request.run(Action::Allow)>{move||t("授权消费者", "Authorize consumer")}</button>
                <For each=move||policy.get().map(|p|p.rules).unwrap_or_default() key=|r|r.rule_id.clone() children=move|rule|{
                    let id=StoredValue::new(rule.rule_id.clone()); let revoked=rule.revoked;
                    let expiry=js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(rule.expires_at_unix_ms as f64)).to_iso_string().as_string().unwrap_or_default();
                    view!{<article class="policy-form"><p>{subject_label(&rule.subject)}</p><p>{move||t("到期时间：", "Expires: ")}{expiry}</p>
                        <Show when=move||revoked><p>{move||t("已撤销", "Revoked")}</p></Show>
                        <button class="danger" type="button" disabled=move||busy.get()||revoked on:click=move|_|request.run(Action::Revoke(id.get_value()))>{move||t("撤销该消费者", "Revoke consumer")}</button></article>}
                } />
            </Show>
        </section>
    }
}
