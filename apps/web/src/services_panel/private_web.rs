//! Private consumer selection and explicit handoff to the original native owner.
//! A downloaded request grants no authority and contains no login/key/hop secret.
use super::{Api, SdkHandle};
use leptos::{prelude::*, task::spawn_local};
use nestlink_protocol::{api::ServiceIngress, services::private::PrivateServicePage};
use nestlink_sdk::{SdkError, services::web_launch::PrivateWebLaunchRequest};
use nestlink_web::i18n::{sdk_error, text as t};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

enum Read { Installations, Directory(Option<String>) }

#[component]
pub(super) fn PrivateWebPanel(
    api: Api,
    session_revision: RwSignal<u64>,
    auth_failure: Callback<SdkHandle>,
    active: Signal<bool>,
) -> impl IntoView {
    let installations = RwSignal::new(Vec::<(String, String)>::new());
    let installation = RwSignal::new(String::new());
    let page = RwSignal::new(None::<PrivateServicePage>);
    let service = RwSignal::new(String::new());
    let management = RwSignal::new(String::new());
    let origin = RwSignal::new(String::new());
    let maximum = RwSignal::new("1048576".to_owned());
    let lifetime = RwSignal::new("300".to_owned());
    let prepared = RwSignal::new(None::<PrivateWebLaunchRequest>);
    let launch_input = RwSignal::new(String::new());
    let launch = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let problem = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let generation = RwSignal::new(0u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup = alive.clone();
    on_cleanup(move || cleanup.store(false, Ordering::Release));
    Effect::new(move |_| {
        let _ = session_revision.get();
        installations.set(Vec::new()); installation.set(String::new());
    });
    Effect::new(move |_| {
        let _ = (session_revision.get(), installation.get(), active.get());
        generation.update(|value| *value = value.wrapping_add(1));
        page.set(None); service.set(String::new()); management.set(String::new());
        busy.set(false); problem.set(String::new()); notice.set(String::new());
    });
    Effect::new(move |_| {
        let _ = (session_revision.get(), installation.get(), service.get(), origin.get(), maximum.get(), lifetime.get(), active.get());
        prepared.set(None); launch_input.set(String::new()); launch.set(None);
    });
    let read = Callback::new(move |command: Read| {
        if busy.get_untracked() || !active.get_untracked() { return; }
        let Some(sdk) = api.get_value() else { return; };
        let selected = installation.get_untracked();
        if !matches!(command, Read::Installations) && !nestlink_protocol::valid_id(&selected) {
            problem.set(t("请选择实际运行网关的原生设备。", "Choose the native installation that will run the gateway.").into()); return;
        }
        let revision = session_revision.get_untracked(); let epoch = generation.get_untracked();
        let alive = alive.clone(); busy.set(true); problem.set(String::new());
        prepared.set(None); launch.set(None); launch_input.set(String::new());
        spawn_local(async move {
            let current = || alive.load(Ordering::Acquire) && active.try_get_untracked() == Some(true)
                && session_revision.try_get_untracked() == Some(revision) && generation.try_get_untracked() == Some(epoch);
            let result = async {
                let client = sdk.lock().await;
                if !current() { return Err(SdkError::Invalid); }
                match command {
                    Read::Installations => {
                        let devices = client.devices().await?.into_iter().filter(|device| !device.revoked).map(|device| (device.device.id, device.device.name)).collect();
                        Ok((Some(devices), None, client.management_origin().to_owned()))
                    }
                    Read::Directory(after) => Ok((None, Some(client.private_services(&selected, after.as_deref(), 50).await?), client.management_origin().to_owned())),
                }
            }.await;
            if !current() { return; }
            busy.set(false);
            match result {
                Ok((devices, directory, manager)) => {
                    management.set(manager);
                    if let Some(devices) = devices { installations.set(devices); }
                    if let Some(directory) = directory { page.set(Some(directory)); service.set(String::new()); }
                }
                Err(error) if matches!(&error, SdkError::SignIn) || matches!(&error, SdkError::Api(status, _) if status.as_u16() == 401) => auth_failure.run(sdk),
                Err(error) => { page.set(None); problem.set(sdk_error(&error).to_string()); }
            }
        });
    });
    let export = move |_| {
        if !active.get_untracked() || busy.get_untracked() { return; }
        let result = (|| -> Result<PrivateWebLaunchRequest, ()> {
            let entry = page.get_untracked().and_then(|page| page.entries.into_iter().find(|entry| entry.service.id == service.get_untracked())).ok_or(())?;
            let request = PrivateWebLaunchRequest { schema_version: 1, management_origin: management.get_untracked(), gateway_installation_id: installation.get_untracked(), service_id: entry.service.id.clone(), space_id: entry.exposure.space_id.clone(), expected_service_revision: entry.service.revision, expected_exposure_revision: entry.exposure.revision, target_sha256: entry.exposure.target_sha256, origin: origin.get_untracked(), maximum_bytes: maximum.get_untracked().parse().map_err(|_| ())?, lifetime_seconds: lifetime.get_untracked().parse().map_err(|_| ())? };
            request.validate(&management.get_untracked()).map_err(|_| ())?;
            if !request.checks_entry(&installation.get_untracked(), &entry) { return Err(()); }
            save_request(&request)?; Ok(request)
        })();
        match result {
            Ok(request) => { prepared.set(Some(request)); problem.set(String::new()); notice.set(t("启动请求已下载。在选定原生网关设备上运行下方命令；配置文件不会创建安装、空间成员或访问授权。", "Launch request downloaded. Run the command below on the selected native gateway. The file creates no installation, space membership, or access rights.").into()); }
            Err(()) => problem.set(t("请选择当前就绪的 HTTP/HTTPS 私有服务，检查独立 HTTPS origin、额度和 1–3600 秒寿命，再下载。服务 UUID 必须是 origin 的第一个 DNS 标签；禁止与管理站共享最后两个 DNS 标签。", "Choose a ready private HTTP/HTTPS service and check its isolated HTTPS origin, quota, and 1–3600 second lifetime. The service UUID must be the first DNS label; do not share the management site's final two labels.").into()),
        }
    };
    let validate_launch = move |_| {
        if !active.get_untracked() || busy.get_untracked() { return; }
        let checked = prepared.get_untracked().and_then(|request| request.checked_launch_url(launch_input.get_untracked().trim()).ok());
        launch_input.set(String::new());
        if let Some(checked) = checked { launch.set(Some(checked)); problem.set(String::new()); }
        else { launch.set(None); problem.set(t("链接不是本次所选服务的单次 fragment URL。只粘贴 daemon 在 HTTPS 就绪后输出文件中的 launch_url；不要粘贴 route bootstrap。", "This is not the selected service's one-use fragment URL. Paste only launch_url from the daemon's file created after HTTPS readiness; never paste the route bootstrap.").into()); }
    };
    view! {
        <section class="policy-form form-stack" aria-label=move || t("访问私有 Web 服务", "Access private Web services") aria-busy=move || busy.get().to_string()>
            <h2>{move || t("访问私有 Web 服务", "Access private Web services")}</h2>
            <p>{move || t("选择已加入空间且获私有 ACL 授权的原生网关安装。浏览器通过该安装的独立 HTTPS origin 访问；每个请求仍由原私有 lease、目标批准和共享配额控制。", "Choose a native gateway installation already enrolled in the space and allowed by the private ACL. The browser uses its isolated HTTPS origin; each request retains the original private lease, target approval, and shared quota.")}</p>
            <button class="secondary" type="button" disabled=move || busy.get() on:click=move |_| read.run(Read::Installations)>{move || t("读取我的设备", "Read my installations")}</button>
            <label>{move || t("实际运行网关的原生设备", "Native installation running the gateway")}<select data-private-web-field="installation" disabled=move || busy.get() prop:value=move || installation.get() on:change=move |event| installation.set(event_target_value(&event))><option value="">{move || t("选择设备", "Choose an installation")}</option>{move || installations.get().into_iter().map(|(id,name)| view!{<option value=id>{name}</option>}).collect_view()}</select></label>
            <button class="secondary" type="button" disabled=move || busy.get() || installation.get().is_empty() on:click=move |_| read.run(Read::Directory(None))>{move || t("读取此设备的私有目录", "Read this installation's private directory")}</button>
            <label>{move || t("当前授权服务", "Currently authorized service")}<select data-private-web-field="service" disabled=move || busy.get() prop:value=move || service.get() on:change=move |event| {service.set(event_target_value(&event));origin.set(String::new());}><option value="">{move || t("选择服务", "Choose a service")}</option>{move || page.get().into_iter().flat_map(|page| page.entries).map(|entry| {let label=format!("{} · {} · {:?}",entry.service.definition.name,entry.exposure.space_id,entry.availability);view!{<option value=entry.service.id>{label}</option>}}).collect_view()}</select></label>
            <button class="secondary" type="button" disabled=move || busy.get() || page.get().is_none_or(|page| !page.more) on:click=move |_| read.run(Read::Directory(page.get_untracked().and_then(|page| page.next_id)))>{move || t("下一页", "Next page")}</button>
            {move || page.get().into_iter().flat_map(|page| page.entries).find(|entry| entry.service.id==service.get()).map(|entry| {
                let web=matches!(&entry.service.definition.requested_ingress,ServiceIngress::Http{..}|ServiceIngress::Https{..});
                view!{<p>{if web {t("HTTP/HTTPS：可准备隔离 Web 网关。", "HTTP/HTTPS: prepare an isolated Web gateway.")} else {t("TCP/UDP：请使用原生 private-service-proxy、本机映射或专用协议客户端；浏览器网页无法承载任意 TCP/UDP。", "TCP/UDP: use native private-service-proxy, a local mapping, or a protocol client. A browser page cannot carry arbitrary TCP/UDP.")}}</p>}
            })}
            <label>{move || t("独立服务 HTTPS origin", "Isolated service HTTPS origin")}<input data-private-web-field="origin" maxlength="2048" autocomplete="off" spellcheck="false" prop:value=move || origin.get() on:input=move |event| origin.set(event_target_value(&event)) /></label>
            <p class="muted">{move || format!("https://{}.private.example.net",service.get())}</p>
            <label>{move || t("每次连接最大字节数", "Maximum bytes per connection")}<input data-private-web-field="maximum" type="number" min="1" step="1" prop:value=move || maximum.get() on:input=move |event| maximum.set(event_target_value(&event)) /></label>
            <label>{move || t("固定 owner 寿命（秒，含 Caddy 准备等待）", "Fixed owner lifetime in seconds, including Caddy setup")}<input data-private-web-field="lifetime" type="number" min="1" max="3600" step="1" prop:value=move || lifetime.get() on:input=move |event| lifetime.set(event_target_value(&event)) /></label>
            <button class="primary" type="button" disabled=move || busy.get() || service.get().is_empty() on:click=export>{move || t("下载私有 Web 启动请求", "Download private Web launch request")}</button>
            <p role="status">{move || notice.get()}</p><Show when=move || !problem.get().is_empty()><p role="alert">{move || problem.get()}</p></Show>
            <Show when=move || prepared.get().is_some()>
                <p>{move || t("在选定设备的安装所有者私有目录保存请求，停止该安装的原 runtime，然后运行：", "Save the request in the selected installation owner's private directory, stop its existing runtime, then run:")}</p>
                <code>"nestlink-daemon private-web-gateway --state-dir <existing-installation> --request <private-request.json> --bootstrap <new-private-route.json> --launch-output <new-private-launch.json>"</code>
                <p>{move || t("将 route JSON 安装到严格 SNI/Host 的独立 Caddy HTTPS server。daemon 仅在该 HTTPS origin 到达原 owner 后创建 launch 文件；从中复制 launch_url，在 60 秒内粘贴到下方。", "Install the route JSON in the dedicated strict-SNI/Host Caddy HTTPS server. The daemon creates the launch file only after this HTTPS origin reaches the original owner. Copy only launch_url and paste it below within 60 seconds.")}</p>
                <label>{move || t("单次 launch_url", "One-use launch_url")}<input type="password" maxlength="4096" autocomplete="off" spellcheck="false" prop:value=move || launch_input.get() on:input=move |event| {launch.set(None);launch_input.set(event_target_value(&event));} /></label>
                <button class="secondary" type="button" on:click=validate_launch>{move || t("核对所选服务链接", "Check the selected service link")}</button>
            </Show>
            <Show when=move || launch.get().is_some()><a class="primary" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" href=move || launch.get().unwrap_or_default()>{move || t("打开所选私有 Web 服务", "Open the selected private Web service")}</a></Show>
            <p class="muted">{move || t("当前需要手动配置 Caddy 和复制单次链接，不提供远程网关委托。只支持服务端 Cookie 登录；HTTP 后端的 Secure 应用 Cookie 必须改用已批准且校验证书的 HTTPS 后端。JS 可读 Cookie、Basic/Bearer、第三方资源和 Service Worker 尚不支持。退出应用时 POST /.nestlink/logout；撤销 ACL、到期或停止 owner 会关闭原连接。", "This flow requires manual Caddy setup and one-use link transfer; it provides no remote gateway delegation. Server-side cookie login is supported. Secure application cookies require an approved HTTPS backend with certificate verification. JavaScript-readable cookies, Basic/Bearer auth, third-party resources, and service workers are unsupported. POST /.nestlink/logout to sign out; ACL revocation, expiry, or owner stop closes original connections.")}</p>
        </section>
    }
}

#[cfg(target_arch = "wasm32")]
fn save_request(request: &PrivateWebLaunchRequest) -> Result<(), ()> {
    use wasm_bindgen::JsCast;
    let content = serde_json::to_string_pretty(request).map_err(|_| ())?;
    let parts = js_sys::Array::new(); parts.push(&content.into());
    let blob = web_sys::Blob::new_with_str_sequence(&parts).map_err(|_| ())?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(|_| ())?;
    let result = (|| {
        let document = web_sys::window().and_then(|window| window.document()).ok_or(())?;
        let anchor = document.create_element("a").map_err(|_| ())?.dyn_into::<web_sys::HtmlAnchorElement>().map_err(|_| ())?;
        anchor.set_href(&url); anchor.set_download("NestLink-private-web-request.json"); anchor.click(); Ok(())
    })();
    spawn_local(async move { gloo_timers::future::TimeoutFuture::new(10_000).await; let _ = web_sys::Url::revoke_object_url(&url); });
    result
}
#[cfg(not(target_arch = "wasm32"))]
fn save_request(_request: &PrivateWebLaunchRequest) -> Result<(), ()> { Err(()) }
