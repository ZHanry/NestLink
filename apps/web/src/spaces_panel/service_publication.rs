use super::{Api,SdkHandle};
use leptos::{prelude::*,task::spawn_local};
use nestlink_protocol::{api::{ServiceApprovalState,ServiceView},network::SpaceRole,spaces::{*,service_publication::*}};
use nestlink_sdk::SdkError;
use nestlink_web::i18n::{sdk_error,text as t};
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};

#[derive(Clone)]
enum Command {Read,Bind,RevokeBinding(String),Grant,RevokeRule(String,String)}

fn protocol(value: SpaceServiceProtocol) -> &'static str {
    match value {SpaceServiceProtocol::Http=>"HTTP",SpaceServiceProtocol::Https=>"HTTPS",SpaceServiceProtocol::Tcp=>"TCP",SpaceServiceProtocol::Udp=>"UDP"}
}

fn subject(value: &SpaceServiceSubject) -> String {
    match value {SpaceServiceSubject::Account {account_id}=>format!("account · {account_id}"),SpaceServiceSubject::Device {installation_id}=>format!("device · {installation_id}")}
}

#[component]
pub(super) fn SpaceServicesPanel(api: Api,session_revision: RwSignal<u64>,auth_failure: Callback<SdkHandle>,details: RwSignal<Option<SpaceDetails>>) -> impl IntoView {
    let policy=RwSignal::new(None::<SpaceServicePolicyView>);
    let owned=RwSignal::new(Vec::<ServiceView>::new());
    let own_service=RwSignal::new(String::new());
    let selected=RwSignal::new(String::new());
    let kind=RwSignal::new("account".to_owned());
    let minutes=RwSignal::new("60".to_owned());
    let busy=RwSignal::new(false);
    let problem=RwSignal::new(String::new());
    let message=RwSignal::new(String::new());
    let last=RwSignal::new((0u64,String::new()));
    let alive=Arc::new(AtomicBool::new(true));
    let cleanup=alive.clone();
    on_cleanup(move ||cleanup.store(false,Ordering::Release));
    let request=Callback::new(move |command:Command| {
        if busy.get_untracked() {return;}
        let Some(sdk)=api.get_value() else {return;};
        let Some(space)=details.get_untracked().map(|details|details.space) else {return;};
        let current=policy.get_untracked();
        let own=owned.get_untracked().into_iter().find(|service|service.id==own_service.get_untracked());
        let bound=current.as_ref().and_then(|policy|policy.bindings.iter().find(|bound|bound.service_id==selected.get_untracked())).cloned();
        let by_device=kind.get_untracked()=="device";
        let lifetime=minutes.get_untracked().parse::<u64>().ok().filter(|minutes|(1..=10080).contains(minutes));
        let session=session_revision.get_untracked();
        let alive=alive.clone();
        busy.set(true); problem.set(String::new()); message.set(String::new());
        spawn_local(async move {
            let active=||alive.load(Ordering::Acquire) && session_revision.try_get_untracked()==Some(session)
                && details.try_get_untracked().flatten().is_some_and(|details|details.space.space_id==space.space_id);
            let result=async {
                let client=sdk.lock().await;
                if !active() {return Err(SdkError::Invalid);}
                match &command {
                    Command::Read=>{},
                    Command::Bind=>{
                        let own=own.as_ref().ok_or(SdkError::Invalid)?;
                        let current=current.as_ref().ok_or(SdkError::Invalid)?;
                        client.bind_space_service(&space.space_id,&own.id,SpaceServiceBindingRequest {expected_revision:current.space.revision,expected_service_revision:own.revision}).await?;
                    },
                    Command::RevokeBinding(service)=>{
                        let current=current.as_ref().ok_or(SdkError::Invalid)?;
                        client.revoke_space_service(&space.space_id,service,SpaceRevisionRequest {expected_revision:current.space.revision}).await?;
                    },
                    Command::Grant=>{
                        let current=current.as_ref().ok_or(SdkError::Invalid)?;
                        let bound=bound.as_ref().ok_or(SdkError::Invalid)?;
                        let subject=if by_device {SpaceServiceSubject::Device {installation_id:bound.host_device_id.clone()}} else {SpaceServiceSubject::Account {account_id:bound.account_id.clone()}};
                        let end=lifetime.and_then(|minutes|minutes.checked_mul(60_000)).and_then(|duration|current.space.observed_at_unix_ms.checked_add(duration)).ok_or(SdkError::Invalid)?;
                        client.grant_space_service_rule(&space.space_id,&bound.service_id,SpaceServiceRuleRequest {expected_revision:current.space.revision,expected_binding_epoch:bound.binding_epoch,subject,protocol:bound.protocol,port:bound.port,operation:SpaceServiceOperation::Publish,expires_at_unix_ms:end}).await?;
                    },
                    Command::RevokeRule(service,rule)=>{
                        let current=current.as_ref().ok_or(SdkError::Invalid)?;
                        client.revoke_space_service_rule(&space.space_id,service,rule,SpaceRevisionRequest {expected_revision:current.space.revision}).await?;
                    },
                }
                if !active() {return Err(SdkError::Invalid);}
                let current=client.space_service_policy(&space.space_id).await?;
                let page=client.services(None,100).await?;
                let mut services=page.services;
                if page.more {
                    let page=client.services(page.next_id.as_deref(),100).await?;
                    if page.more {return Err(SdkError::Invalid);}
                    services.extend(page.services);
                }
                Ok((current,services))
            }.await;
            if !active() {return;}
            busy.set(false);
            match result {
                Ok((current,services))=>{
                    let confirmed=current.space.clone();
                    details.update(|details|if let Some(details)=details {if details.space.space_id==confirmed.space_id {details.space=confirmed;}});
                    policy.set(Some(current)); owned.set(services);
                    message.set(t("服务发布规则已由服务器确认。","Service publication rules confirmed by the server.").into());
                },
                Err(error)=>{
                    if matches!(&error,SdkError::SignIn) || matches!(&error,SdkError::Api(status,_) if status.as_u16()==401) {auth_failure.run(sdk);return;}
                    policy.set(None);
                    problem.set(format!("{} {}",sdk_error(&error),t("请重新读取规则后再修改。","Read the rules again before making changes.")));
                },
            }
        });
    });
    Effect::new(move |_| {
        let identity=(session_revision.get(),details.get().map(|details|details.space.space_id).unwrap_or_default());
        if last.get_untracked()!=identity {
            last.set(identity); policy.set(None);owned.set(Vec::new());own_service.set(String::new());selected.set(String::new());
            kind.set("account".into());minutes.set("60".into());problem.set(String::new());message.set(String::new());busy.set(false);
        }
    });
    let management=move ||details.get().is_some_and(|details|matches!(details.space.role,SpaceRole::Owner|SpaceRole::Admin)&&!details.space.archived);
    view! {
        <section class="form-stack" aria-label=move ||t("服务发布授权","Service publication rights") aria-busy=move ||busy.get().to_string()>
            <h3>{move ||t("服务发布授权","Service publication rights")}</h3>
            <p class="muted">{move ||t("服务所有者先绑定已获本机批准的目标，空间管理员再明确授权发布。公共入口仍接受服务原有来源范围内的访客；空间角色不自动放行远控、本机端口或原始 IP。","The service owner first binds an independently approved target, then a space administrator explicitly allows publication. Public ingress keeps its existing visitor source restrictions. Space roles do not grant desktop control, local ports, or raw IP access.")}</p>
            <button type="button" class="secondary" disabled=move ||busy.get() on:click=move |_|request.run(Command::Read)>{move ||t("读取服务发布规则","Read publication rules")}</button>
            <Show when=move ||!problem.get().is_empty()><p role="alert">{move ||problem.get()}</p></Show>
            <p role="status">{move ||message.get()}</p>
            <Show when=move ||policy.get().is_some() && details.get().is_some_and(|details|!details.space.archived)>
                <label>{move ||t("我的已批准服务（宿主须已加入此空间）","My approved service (host must already belong to this space)")}<select data-space-service-field="owned" prop:value=move ||own_service.get() disabled=move ||busy.get() on:change=move |event|own_service.set(event_target_value(&event))>
                    <option value="">{move ||t("选择已批准服务","Choose an approved service")}</option>
                    {move ||owned.get().into_iter().filter(|service|service.approval==ServiceApprovalState::ApprovedTarget).map(|service|view!{<option value=service.id>{service.definition.name}</option>}).collect_view()}
                </select></label>
                <button type="button" class="secondary" disabled=move ||busy.get() ||own_service.get().is_empty() on:click=move |_|request.run(Command::Bind)>{move ||t("绑定并重置为等待授权","Bind and reset to awaiting permission")}</button>
                <Show when=management>
                    <label>{move ||t("待授权绑定","Bound service to authorize")}<select data-space-service-field="binding" prop:value=move ||selected.get() disabled=move ||busy.get() on:change=move |event|selected.set(event_target_value(&event))>
                        <option value="">{move ||t("选择空间服务","Choose a bound service")}</option>
                        {move ||policy.get().into_iter().flat_map(|policy|policy.bindings).filter(|bound|!bound.revoked).map(|bound|view!{<option value=bound.service_id.clone()>{protocol(bound.protocol)}" · "{bound.port}" · "{bound.service_id}</option>}).collect_view()}
                    </select></label>
                    <label>{move ||t("授权对象","Publication subject")}<select data-space-service-field="subject" prop:value=move ||kind.get() disabled=move ||busy.get() on:change=move |event|kind.set(event_target_value(&event))><option value="account">{move ||t("该服务所有者账号","This service owner account")}</option><option value="device">{move ||t("该服务的精确宿主设备","This service's exact host device")}</option></select></label>
                    <label>{move ||t("发布授权有效分钟数（1–10080）","Publication lifetime in minutes (1–10080)")}<input data-space-service-field="lifetime" type="number" min="1" max="10080" prop:value=move ||minutes.get() disabled=move ||busy.get() on:input=move |event|minutes.set(event_target_value(&event)) /></label>
                    <button type="button" class="primary" disabled=move ||busy.get() ||selected.get().is_empty() on:click=move |_|request.run(Command::Grant)>{move ||t("明确授权此协议和端口发布","Allow publication on this protocol and port")}</button>
                </Show>
            </Show>
            {move ||policy.get().into_iter().flat_map(|policy|policy.bindings).map(|bound|{
                let service=bound.service_id.clone();let service_for_rules=service.clone();let revoked=bound.revoked;
                view!{<div class="form-stack"><p>{bound.service_id}" · "{protocol(bound.protocol)}"/"{bound.port}" · publish · "{if revoked {"revoked"} else {"bound"}}</p>
                    <button type="button" class="secondary" disabled=move ||busy.get() ||revoked ||details.get().is_none_or(|details|details.space.archived) on:click=move |_|request.run(Command::RevokeBinding(service.clone()))>{move ||t("撤销绑定并停止发布","Revoke binding and stop publication")}</button>
                    {bound.rules.into_iter().map(|rule|{
                        let service=service_for_rules.clone();let id=rule.rule_id.clone();let revoked=rule.revoked;
                        view!{<div><span>{subject(&rule.subject)}" · "{protocol(rule.protocol)}"/"{rule.port}" · publish · "{rule.expires_at_unix_ms}{if rule.active {" · active"} else {" · inactive"}}{if revoked {" · revoked"} else {""}}</span>
                            <Show when=management><button type="button" class="secondary" disabled=move ||busy.get() ||revoked on:click=move |_|request.run(Command::RevokeRule(service.clone(),id.clone()))>{move ||t("撤销规则并停止发布","Revoke rule and stop publication")}</button></Show>
                        </div>}
                    }).collect_view()}
                </div>}
            }).collect_view()}
        </section>
    }
}
