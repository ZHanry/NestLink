//! The page owns authorization, media and stop cleanup for a persistent browser
//! installation. Access methods retain their explicit authorization boundaries.
use crate::{Api, RemoteTarget, SdkHandle};
use gloo_timers::future::TimeoutFuture;
use leptos::{prelude::*, task::spawn_local};
use nestlink_auth::Secret;
use nestlink_protocol::webrtc_data::WebRtcDataChannel;
use nestlink_protocol::{
    Permission,
    api::{RemotePasswordView, RemoteRequest, RemoteView},
};
use nestlink_sdk::DeviceIdentity;
use nestlink_web::browser_clipboard::BrowserClipboard;
use nestlink_web::browser_data::{LocalDataApproval, LocalDataConsent};
use nestlink_web::browser_files::BrowserFiles;
use nestlink_web::browser_identity::{self, BrowserIdentityError};
use nestlink_web::browser_input::{BrowserInputCapture, BrowserInputLayout};
use nestlink_web::browser_peer::{
    BrowserPeer, PeerCancellation, PeerDisplaySnapshot, PeerError, PeerPathMode, SelectedPath,
    network_event_requires_ice_restart,
};
use nestlink_web::browser_rpc::BrowserRpc;
use nestlink_web::{
    i18n::{self, text as t},
    localized_format,
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{Event, EventTarget, HtmlTextAreaElement, HtmlVideoElement, MediaStream};
use zeroize::Zeroizing;

mod data_panel;
use data_panel::RemoteDataPanel;
mod display_selector;
use display_selector::RemoteDisplaySelector;

thread_local! {
    // A stopped page cannot discard a browser disk owner whose cleanup failed.
    // Keep the original run until all actual startup/data owners have stopped,
    // clipboard Promises have settled, and the server confirms revocation.
    static RETAINED_RUNS: RefCell<Vec<Rc<RemoteRun>>> = const { RefCell::new(Vec::new()) };
}
fn retained_count() -> usize {
    RETAINED_RUNS.with(|runs| runs.borrow().len())
}
fn release_clean_run(run: &RemoteRun) {
    if !run.has_pending_cleanup() {
        RETAINED_RUNS.with(|runs| runs.borrow_mut().retain(|item| item.id != run.id));
    }
}

#[derive(Clone, Copy)]
struct RequestedPermissions {
    audio: bool,
    input: bool,
    file_read: bool,
    file_write: bool,
    clipboard_read: bool,
    clipboard_write: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AccessMethod {
    LocalApproval,
    TrustedDevice,
    Password,
}

impl AccessMethod {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "local_approval" => Some(Self::LocalApproval),
            "trusted_device" => Some(Self::TrustedDevice),
            "password" => Some(Self::Password),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PasswordOffer {
    request_id: String,
    request_nonce: String,
    policy_revision: u64,
    connection_generation: u64,
    password_revision: u64,
    permissions: Vec<i32>,
    paths: Vec<i32>,
    expires_at_unix_ms: u64,
}

impl PasswordOffer {
    fn new(request: &RemoteView, settings: &RemotePasswordView) -> Self {
        Self {
            request_id: request.id.clone(),
            request_nonce: request.nonce.clone(),
            policy_revision: request.policy_revision,
            connection_generation: request.connection_generation,
            password_revision: settings.revision,
            permissions: settings.permissions.clone(),
            paths: settings.paths.clone(),
            expires_at_unix_ms: settings.expires_at_unix_ms,
        }
    }
}

struct PasswordSubmission {
    offer: PasswordOffer,
    password: Secret,
}

#[derive(Clone, Copy)]
struct SessionUi {
    status: RwSignal<String>,
    picture: RwSignal<bool>,
    generation: RwSignal<u64>,
    revision: u64,
    data_ready: RwSignal<bool>,
    displays: RwSignal<Option<PeerDisplaySnapshot>>,
    display_switching: RwSignal<bool>,
    password_offer: RwSignal<Option<PasswordOffer>>,
}
impl SessionUi {
    fn status(self, message: impl Into<String>) {
        let _ = self.status.try_set(message.into());
    }
    fn picture(self, value: bool) {
        let _ = self.picture.try_set(value);
    }
}

struct RemoteRun {
    sdk: SdkHandle,
    id: String,
    cancelled: Cell<bool>,
    run_finished: Cell<bool>,
    cleanup_busy: Cell<bool>,
    peer: RefCell<Option<PeerCancellation>>,
    request_created: Cell<bool>,
    display_request: Cell<Option<u32>>,
    input_paused: Rc<Cell<bool>>,
    stream: MediaStream,
    video: HtmlVideoElement,
    files: RefCell<Option<BrowserFiles>>,
    clipboard: RefCell<Option<BrowserClipboard>>,
    data_consent: [LocalDataApproval; 4],
    password_submission: RefCell<Option<PasswordSubmission>>,
}

impl RemoteRun {
    fn cancel(&self) {
        self.cancelled.set(true);
        self.display_request.set(None);
        self.password_submission.borrow_mut().take();
        self.input_paused.set(true);
        for approval in &self.data_consent {
            approval.revoke();
        }
        if let Some(clipboard) = self.clipboard.borrow().as_ref() {
            clipboard.clear();
        }
        if let Some(peer) = self.peer.borrow().as_ref() {
            peer.cancel();
        }
        for track in self.stream.get_tracks().iter() {
            if let Ok(track) = track.dyn_into::<web_sys::MediaStreamTrack>() {
                track.stop();
            }
        }
        if self.video.src_object().as_ref() == Some(&self.stream) {
            let _ = self.video.pause();
            self.video.set_src_object(None);
        }
    }

    fn consent(
        self: &Rc<Self>,
        kind: WebRtcDataChannel,
        task_cancel: Rc<Cell<bool>>,
    ) -> LocalDataConsent {
        let owner = self.clone();
        let approval = data_index(kind)
            .map(|index| owner.data_consent[index].consent())
            .unwrap_or_else(|| Rc::new(|| false));
        Rc::new(move || !task_cancel.get() && owner.check().is_ok() && approval())
    }
    fn set_data_consent(&self, kind: WebRtcDataChannel, allowed: bool) {
        if let Some(index) = data_index(kind) {
            let approval = &self.data_consent[index];
            if allowed && self.check().is_ok() {
                approval.approve();
            } else {
                approval.revoke();
            }
        }
        if kind == WebRtcDataChannel::ClipboardRead
            && !allowed
            && let Some(clipboard) = self.clipboard.borrow().as_ref()
        {
            clipboard.clear();
        }
    }
    fn has_pending_files(&self) -> bool {
        self.files
            .borrow()
            .as_ref()
            .is_some_and(BrowserFiles::has_pending)
    }
    fn has_pending_cleanup(&self) -> bool {
        !self.run_finished.get()
            || self.cleanup_busy.get()
            || self.has_pending_files()
            || self
                .clipboard
                .borrow()
                .as_ref()
                .is_some_and(BrowserClipboard::has_unsettled_operation)
            || self.request_created.get()
    }

    fn check(&self) -> Result<(), String> {
        if self.cancelled.get()
            || self
                .peer
                .borrow()
                .as_ref()
                .is_some_and(PeerCancellation::is_cancelled)
        {
            return Err(t(
                "连接已停止，或授权已经到期。",
                "The connection stopped or its authorization expired.",
            )
            .into());
        }
        Ok(())
    }

    async fn cleanup(&self) -> Vec<String> {
        self.cancel();
        if !self.run_finished.get() {
            return vec![t("上一连接仍在停止实际操作，请稍后重试清理。", "Operations from the previous connection are still stopping. Retry cleanup shortly.").into()];
        }
        if self.cleanup_busy.replace(true) {
            return vec![
                t(
                    "上一连接正在清理，请等待当前清理结束。",
                    "The previous connection is being cleaned up. Wait for cleanup to finish.",
                )
                .into(),
            ];
        }
        let mut problems = Vec::new();
        let files = self.files.borrow().clone();
        if let Some(files) = files
            && let Err(problem) = files.cleanup().await
        {
            problems.push(localized_format!(
                "浏览器暂存文件尚未清理：{problem} 请点击重试清理。",
                "Temporary browser files remain: {problem}. Click Retry cleanup."
            ));
        }
        if self.request_created.replace(false)
            && let Err(problem) = self.sdk.lock().await.revoke_remote(&self.id).await
        {
            self.request_created.set(true);
            problems.push(localized_format!(
                "服务器未确认会话撤销：{problem}",
                "The server did not confirm session revocation: {problem}"
            ));
        }
        if self
            .clipboard
            .borrow()
            .as_ref()
            .is_some_and(BrowserClipboard::has_unsettled_operation)
        {
            problems.push(
                t("本机剪贴板操作尚未结束，结果可能稍后生效。请等待浏览器操作结束后点击“重试清理”；清理完成前不能开始新连接。", "A local clipboard operation is still running and may take effect later. Wait for it to finish, then click Retry cleanup. New connections remain blocked until cleanup completes.")
                    .into(),
            );
        }
        self.cleanup_busy.set(false);
        problems
    }
}

fn data_index(kind: WebRtcDataChannel) -> Option<usize> {
    match kind {
        WebRtcDataChannel::FileRead => Some(0),
        WebRtcDataChannel::FileWrite => Some(1),
        WebRtcDataChannel::ClipboardRead => Some(2),
        WebRtcDataChannel::ClipboardWrite => Some(3),
        _ => None,
    }
}

fn password_paths(paths: &[i32]) -> String {
    paths
        .iter()
        .map(|path| match path {
            1 => t("直连", "Direct"),
            2 => t("中继", "Relay"),
            _ => t("未知", "Unknown"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn fullscreen_call(target: &wasm_bindgen::JsValue, method: &str) -> Result<js_sys::Promise, ()> {
    js_sys::Reflect::get(target, &method.into())
        .map_err(|_| ())?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| ())?
        .call0(target)
        .map_err(|_| ())?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| ())
}

fn remote_is_fullscreen(document: &web_sys::Document) -> bool {
    document
        .fullscreen_element()
        .is_some_and(|element| element.id() == "remote-session")
}

fn change_remote_fullscreen() -> Result<js_sys::Promise, ()> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or(())?;
    if remote_is_fullscreen(&document) {
        fullscreen_call(document.as_ref(), "exitFullscreen")
    } else {
        let element = document.get_element_by_id("remote-session").ok_or(())?;
        // Invoke during the click's trusted activation, before the first await.
        fullscreen_call(element.as_ref(), "requestFullscreen")
    }
}

fn exit_remote_fullscreen() {
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    if remote_is_fullscreen(&document)
        && let Ok(promise) = fullscreen_call(document.as_ref(), "exitFullscreen")
    {
        spawn_local(async move {
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
        });
    }
}

struct FullscreenObserver {
    document: web_sys::Document,
    changed: Closure<dyn FnMut(Event)>,
}

impl FullscreenObserver {
    fn attach(state: RwSignal<bool>) -> Option<Self> {
        let document = web_sys::window()?.document()?;
        state.set(remote_is_fullscreen(&document));
        let observed = document.clone();
        let changed = Closure::<dyn FnMut(Event)>::new(move |_| {
            let _ = state.try_set(remote_is_fullscreen(&observed));
        });
        document
            .add_event_listener_with_callback("fullscreenchange", changed.as_ref().unchecked_ref())
            .ok()?;
        Some(Self { document, changed })
    }
}

impl Drop for FullscreenObserver {
    fn drop(&mut self) {
        let _ = self.document.remove_event_listener_with_callback(
            "fullscreenchange",
            self.changed.as_ref().unchecked_ref(),
        );
    }
}

#[component]
pub fn RemotePanel(
    api: Api,
    target: RwSignal<Option<RemoteTarget>>,
    session_revision: RwSignal<u64>,
) -> impl IntoView {
    let audio = RwSignal::new(false);
    let input_control = RwSignal::new(false);
    let file_read = RwSignal::new(false);
    let file_write = RwSignal::new(false);
    let clipboard_read = RwSignal::new(false);
    let clipboard_write = RwSignal::new(false);
    let path_mode = RwSignal::new("direct_only".to_owned());
    let access_method = RwSignal::new("local_approval".to_owned());
    let password_offer = RwSignal::new(None::<PasswordOffer>);
    let remote_password = RwSignal::new(Zeroizing::new(String::new()));
    let fullscreen = RwSignal::new(false);
    let active = RwSignal::new(false);
    let picture = RwSignal::new(false);
    let data_ready = RwSignal::new(false);
    let displays = RwSignal::new(None::<PeerDisplaySnapshot>);
    let display_switching = RwSignal::new(false);
    let pending_cleanup = RwSignal::new(retained_count());
    let status = RwSignal::new(
        t(
            "选择需要的权限，然后在被控设备批准本次访问。",
            "Choose permissions, then approve this request on the remote device.",
        )
        .to_owned(),
    );
    let problem = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let owner: StoredValue<Option<Rc<RemoteRun>>, LocalStorage> = StoredValue::new_local(None);
    let reset = move || {
        generation.update(|value| *value = value.saturating_add(1));
        if let Some(run) = owner.get_value() {
            run.cancel();
        }
        owner.set_value(None);
        active.set(false);
        picture.set(false);
        data_ready.set(false);
        displays.set(None);
        display_switching.set(false);
        password_offer.set(None);
        remote_password.set(Zeroizing::new(String::new()));
        exit_remote_fullscreen();
    };

    Effect::new(move |_| {
        session_revision.track();
        target.track();
        untrack(|| {
            reset();
            audio.set(false);
            input_control.set(false);
            file_read.set(false);
            file_write.set(false);
            clipboard_read.set(false);
            clipboard_write.set(false);
            path_mode.set("direct_only".into());
            access_method.set("local_approval".into());
            problem.set(String::new());
            status.set(
                t(
                    "选择需要的权限，然后在被控设备批准本次访问。",
                    "Choose permissions, then approve this request on the remote device.",
                )
                .into(),
            );
        });
    });
    let fullscreen_observer: StoredValue<Option<FullscreenObserver>, LocalStorage> =
        StoredValue::new_local(FullscreenObserver::attach(fullscreen));
    on_cleanup(move || {
        reset();
        let _ = fullscreen_observer.try_update_value(|observer| *observer = None);
    });

    let start = move |_| {
        if active.get_untracked() {
            return;
        }
        if retained_count() != 0 {
            pending_cleanup.set(retained_count());
            problem.set(
                t("上一连接仍有操作或清理未完成（可能包括浏览器剪贴板操作）。请等待操作结束，或点击重试清理。", "The previous connection still has operations or cleanup pending, which may include browser clipboard operations. Wait or click Retry cleanup.")
                    .into(),
            );
            return;
        }
        let Some(host) = target.get_untracked() else {
            return;
        };
        let Some(sdk) = api.get_value() else {
            problem.set(t("请先登录。", "Sign in first.").into());
            return;
        };
        let Some(requested_access) = AccessMethod::parse(&access_method.get_untracked()) else {
            problem.set(t("请选择有效的授权方式。", "Choose a valid access method.").into());
            return;
        };
        let video = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("remote-view-video"))
            .and_then(|element| element.dyn_into::<HtmlVideoElement>().ok());
        let Some(video) = video else {
            problem.set(
                t(
                    "浏览器画面容器不可用。",
                    "The browser video element is unavailable.",
                )
                .into(),
            );
            return;
        };
        let Ok(stream) = MediaStream::new() else {
            problem.set(
                t(
                    "浏览器媒体能力不可用。",
                    "Browser media capabilities are unavailable.",
                )
                .into(),
            );
            return;
        };
        video.set_src_object(Some(&stream));
        let run = Rc::new(RemoteRun {
            sdk,
            id: nestlink_auth::random_id(),
            cancelled: Cell::new(false),
            run_finished: Cell::new(false),
            cleanup_busy: Cell::new(false),
            peer: RefCell::new(None),
            request_created: Cell::new(false),
            display_request: Cell::new(None),
            input_paused: Rc::new(Cell::new(true)),
            stream,
            video,
            files: RefCell::new(None),
            clipboard: RefCell::new(None),
            data_consent: std::array::from_fn(|_| LocalDataApproval::default()),
            password_submission: RefCell::new(None),
        });
        RETAINED_RUNS.with(|runs| runs.borrow_mut().push(run.clone()));
        pending_cleanup.set(retained_count());
        let revision = generation.get_untracked().saturating_add(1);
        generation.set(revision);
        owner.set_value(Some(run.clone()));
        active.set(true);
        picture.set(false);
        problem.set(String::new());
        let requested = RequestedPermissions {
            audio: audio.get_untracked(),
            input: input_control.get_untracked(),
            file_read: file_read.get_untracked(),
            file_write: file_write.get_untracked(),
            clipboard_read: clipboard_read.get_untracked(),
            clipboard_write: clipboard_write.get_untracked(),
        };
        let requested_path = path_mode.get_untracked();
        status.set(
            t(
                "正在读取并核验此浏览器的控制设备身份…",
                "Loading and verifying this browser's controller device…",
            )
            .into(),
        );
        spawn_local(async move {
            let result = run_session(
                run.clone(),
                host,
                requested,
                requested_path,
                requested_access,
                SessionUi {
                    status,
                    picture,
                    generation,
                    revision,
                    data_ready,
                    displays,
                    display_switching,
                    password_offer,
                },
            )
            .await;
            run.run_finished.set(true);
            let was_cancelled = run.cancelled.get();
            run.cancel();
            if generation.try_get_untracked() == Some(revision) {
                let _ = picture.try_set(false);
                let _ = data_ready.try_set(false);
                let _ = displays.try_set(None);
                let _ = display_switching.try_set(false);
                let _ = password_offer.try_set(None);
                let _ = remote_password.try_set(Zeroizing::new(String::new()));
                let _ = status.try_set(t("连接已停止。", "Connection stopped.").into());
                if !was_cancelled && let Err(error) = result {
                    let _ = problem.try_set(error);
                }
            }
            let cleanup = run.cleanup().await;
            release_clean_run(&run);
            let _ = pending_cleanup.try_set(retained_count());
            if generation.try_get_untracked() == Some(revision) {
                let _ = active.try_set(false);
                if !run.has_pending_cleanup() {
                    let _ = owner.try_set_value(None);
                }
                if !cleanup.is_empty() {
                    let _ = problem.try_update(|message| {
                        if !message.is_empty() {
                            message.push(' ');
                        }
                        message.push_str(&cleanup.join(" "));
                    });
                }
            }
        });
    };

    let stop = move |_| {
        if let Some(run) = owner.get_value() {
            run.cancel();
        }
        picture.set(false);
        data_ready.set(false);
        password_offer.set(None);
        remote_password.set(Zeroizing::new(String::new()));
        status.set(
            t(
                "画面已停止，正在清理授权…",
                "Video stopped. Revoking access…",
            )
            .into(),
        );
    };
    let retry_cleanup = move |_| {
        let runs = RETAINED_RUNS.with(|runs| runs.borrow().clone());
        if active.get_untracked() {
            return;
        }
        spawn_local(async move {
            let mut problems = Vec::new();
            for run in runs {
                problems.extend(run.cleanup().await);
                release_clean_run(&run);
            }
            let _ = pending_cleanup.try_set(retained_count());
            let _ = problem.try_set(problems.join(" "));
        });
    };
    let close = move |_| {
        reset();
        target.set(None);
    };
    let play = move |_| {
        if let Some(run) = owner.get_value()
            && run.check().is_ok()
        {
            let video = run.video.clone();
            if let Ok(promise) = video.play() {
                spawn_local(async move {
                    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                });
            }
        }
    };
    let submit_password = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        if !active.get_untracked() {
            return;
        }
        let Some(offer) = password_offer.get_untracked() else {
            return;
        };
        let Some(run) = owner.get_value() else {
            return;
        };
        if run.check().is_err() || run.password_submission.borrow().is_some() {
            return;
        }
        if !remote_password.with(|value| (1..=1024).contains(&value.len())) {
            problem.set(
                t(
                    "请输入不超过 1024 个 UTF-8 字节的远控密码。",
                    "Enter a remote access password of at most 1024 UTF-8 bytes.",
                )
                .into(),
            );
            return;
        }
        let mut password = String::new();
        remote_password.update(|value| password = std::mem::take(&mut **value));
        *run.password_submission.borrow_mut() = Some(PasswordSubmission {
            offer,
            password: Secret::from_text(password),
        });
        password_offer.set(None);
        problem.set(String::new());
        status.set(
            t(
                "正在核验本次请求的密码授权…",
                "Verifying password authorization for this request…",
            )
            .into(),
        );
    };
    let toggle_fullscreen = move |_| {
        let revision = generation.get_untracked();
        match change_remote_fullscreen() {
            Ok(promise) => {
                spawn_local(async move {
                    let result = wasm_bindgen_futures::JsFuture::from(promise).await;
                    if generation.try_get_untracked() != Some(revision) {
                        exit_remote_fullscreen();
                    } else if result.is_err() {
                        let _ = problem.try_set(t("浏览器未允许切换全屏。请使用工具栏按钮重试。", "The browser did not allow fullscreen. Retry using the toolbar button.").into());
                    }
                })
            }
            Err(()) => problem.set(
                t(
                    "此浏览器无法使用全屏模式。",
                    "Fullscreen is unavailable in this browser.",
                )
                .into(),
            ),
        }
    };

    let select_display = Callback::new(move |source: u32| {
        if !active.get_untracked() || display_switching.get_untracked() {
            return;
        }
        let Some(snapshot) = displays.get_untracked() else {
            return;
        };
        if snapshot.pending_source.is_some()
            || snapshot
                .selected
                .as_ref()
                .is_some_and(|item| item.source == source)
            || !snapshot.displays.iter().any(|item| item.source == source)
        {
            return;
        }
        if let Some(run) = owner.get_value()
            && run.check().is_ok()
            && run.display_request.get().is_none()
        {
            run.display_request.set(Some(source));
            run.input_paused.set(true);
            display_switching.set(true);
            picture.set(false);
            status.set(t("正在切换显示器…", "Switching displays…").into());
        }
    });

    view! {
        <Show when=move || target.get().is_some()>
            <section id="remote-session" class="remote-session" role="dialog" aria-modal="true" aria-labelledby="remote-session-title">
                <header class="remote-toolbar">
                    <div><h2 id="remote-session-title">{move || target.get().map(|host| host.name).unwrap_or_default()}</h2>
                        <p aria-live="polite">{move || status.get()}</p></div>
                    <div class="remote-actions">
                        <Show when=move || pending_cleanup.get() != 0 && !active.get()>
                            <button class="secondary" type="button" on:click=retry_cleanup>{move || t("重试清理", "Retry cleanup")}</button>
                        </Show>
                        <button class="secondary" type="button" on:click=toggle_fullscreen>{move || if fullscreen.get() { t("退出全屏", "Exit fullscreen") } else { t("全屏", "Fullscreen") }}</button>
                        <button class="secondary" type="button" on:click=play disabled=move || !active.get()>{move || t("播放画面与声音", "Play video and audio")}</button>
                        <button class="danger" type="button" on:click=stop disabled=move || !active.get()>{move || t("停止连接", "Stop connection")}</button>
                        <button class="secondary" type="button" on:click=close>{move || t("关闭", "Close")}</button>
                    </div>
                </header>
                <RemoteDisplaySelector snapshot=displays switching=display_switching active select=select_display />
                <div class="remote-stage">
                    <video id="remote-view-video" autoplay playsinline class=move || if picture.get() { "remote-video visible" } else { "remote-video" } aria-label=move || t("远程屏幕", "Remote screen") />
                    <Show when=move || input_control.get() && active.get()>
                        <textarea id="remote-input-text" class="remote-input-text" disabled=move || display_switching.get() || !data_ready.get() aria-label=move || t("发送到远程设备的文本", "Text to send to the remote device") placeholder=move || t("点击后输入文本或使用输入法", "Click to type text or use your input method") rows="1"></textarea>
                    </Show>
                    <Show when=move || !picture.get()>
                        <div class="remote-wait" aria-live="polite"><p>{move || status.get()}</p></div>
                    </Show>
                </div>
                <RemoteDataPanel owner=owner ready=data_ready />
                <Show when=move || password_offer.get().is_some() && active.get()>
                    <form class="policy-form" on:submit=submit_password>
                        <h3>{move || t("用密码授权本次访问", "Authorize this request with a password")}</h3>
                        {move || password_offer.get().map(|offer| view! {
                            <p>{localized_format!("主机密码配置版本 {}", "Host password revision {}", offer.password_revision)}</p>
                            <p>{localized_format!("允许权限：{}", "Allowed permissions: {}", super::permission_summary(&offer.permissions, i18n::english()))}</p>
                            <p>{localized_format!("允许路径：{}", "Allowed paths: {}", password_paths(&offer.paths))}</p>
                            <p class="muted">{localized_format!("本次请求：{}", "This request: {}", offer.request_id)}</p>
                        })}
                        <label for="remote-access-password">{move || t("远控密码", "Remote access password")}</label>
                        <input id="remote-access-password" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="1024" prop:value=move || remote_password.with(|value| value.to_string()) on:input=move |event| {
                            let value = Zeroizing::new(event_target_value(&event));
                            if value.len() <= 1024 { remote_password.set(value); }
                        } />
                        <button class="primary" type="submit" disabled=move || remote_password.with(|value| value.is_empty())>{move || t("仅授权本次请求", "Authorize this request only")}</button>
                    </form>
                </Show>
                <footer class="remote-footer">
                    <div class="remote-permissions">
                        <span>{move || t("请求查看画面", "Request screen viewing")}</span>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || audio.get() on:change=move |event| audio.set(event_target_checked(&event)) />{move || t("同时请求声音", "Also request audio")}</label>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || input_control.get() on:change=move |event| input_control.set(event_target_checked(&event)) />{move || t("请求键盘和鼠标控制", "Request keyboard and mouse control")}</label>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || file_read.get() on:change=move |event| file_read.set(event_target_checked(&event)) />{move || t("请求文件下载", "Request file downloads")}</label>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || file_write.get() on:change=move |event| file_write.set(event_target_checked(&event)) />{move || t("请求文件上传", "Request file uploads")}</label>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || clipboard_read.get() on:change=move |event| clipboard_read.set(event_target_checked(&event)) />{move || t("请求接收设备剪贴板", "Request remote clipboard access")}</label>
                        <label><input type="checkbox" disabled=move || active.get() prop:checked=move || clipboard_write.get() on:change=move |event| clipboard_write.set(event_target_checked(&event)) />{move || t("请求发送本机剪贴板", "Request sending the local clipboard")}</label>
                        <label>{move || t("连接方式 ", "Connection mode ")}<select disabled=move || active.get() prop:value=move || path_mode.get() on:change=move |event| path_mode.set(event_target_value(&event))>
                            <option value="direct_only">{move || t("仅直连", "Direct only")}</option>
                            <option value="direct_preferred">{move || t("直连优先，允许中继", "Prefer direct, allow relay")}</option>
                            <option value="relay_only">{move || t("仅中继", "Relay only")}</option>
                        </select></label>
                        <label>{move || t("授权方式 ", "Access method ")}<select disabled=move || active.get() prop:value=move || access_method.get() on:change=move |event| access_method.set(event_target_value(&event))>
                            <option value="local_approval">{move || t("在被控设备批准", "Approve on the host")}</option>
                            <option value="trusted_device">{move || t("使用已有受信设备授权", "Use existing trusted-device approval")}</option>
                            <option value="password">{move || t("使用本次密码授权", "Authorize this request with a password")}</option>
                        </select></label>
                    </div>
                    <button class="primary" type="button" on:click=start disabled=move || active.get()>{move || t("请求连接", "Request connection")}</button>
                </footer>
                <Show when=move || !problem.get().is_empty()><p class="error-message remote-error" role="alert">{move || problem.get()}</p></Show>
            </section>
        </Show>
    }
}

async fn managed_request<T, F>(_run: &RemoteRun, future: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, nestlink_sdk::SdkError>>,
{
    // SDK requests are themselves bounded. Keep their result after user stop
    // so a registration or request racing stop can still be revoked.
    future
        .await
        .map_err(|problem| i18n::sdk_error(&problem).into())
}

async fn run_session(
    run: Rc<RemoteRun>,
    host: RemoteTarget,
    requested: RequestedPermissions,
    path_mode: String,
    access_method: AccessMethod,
    ui: SessionUi,
) -> Result<(), String> {
    let mode = PeerPathMode::parse(&path_mode).map_err(|problem| i18n::peer_error(&problem))?;
    let identity = {
        let mut sdk = run.sdk.lock().await;
        browser_identity::load_or_register(&mut sdk)
            .await
            .map_err(|problem| -> String { match problem {
                BrowserIdentityError::Management(problem) => i18n::sdk_error(&problem).into(),
                BrowserIdentityError::Storage => t(
                    "此浏览器无法提供受保护的持久身份存储。",
                    "This browser cannot provide protected persistent identity storage.",
                )
                .into(),
                BrowserIdentityError::Corrupt => t(
                    "保存的浏览器身份无法核验。请保留本机记录并检查设备管理页。",
                    "The saved browser identity could not be verified. Keep the local record and check device management.",
                )
                .into(),
                BrowserIdentityError::Revoked => t(
                    "此浏览器控制设备已被撤销。请先检查设备管理页，再重置本机身份。",
                    "This browser controller device was revoked. Review device management before resetting its local identity.",
                )
                .into(),
                BrowserIdentityError::Mismatch => t(
                    "本机保存的浏览器密钥与已登记设备不匹配。",
                    "The saved browser key does not match the enrolled device.",
                )
                .into(),
            } })?
    };
    run.check()?;
    let mut permissions = vec![Permission::View as i32];
    if requested.audio {
        permissions.push(Permission::Audio as i32);
    }
    if requested.input {
        permissions.push(Permission::Input as i32);
    }
    for (needed, permission) in [
        (requested.file_read, Permission::FileRead),
        (requested.file_write, Permission::FileWrite),
        (requested.clipboard_read, Permission::ClipboardRead),
        (requested.clipboard_write, Permission::ClipboardWrite),
    ] {
        if needed {
            permissions.push(permission as i32);
        }
    }
    run.request_created.set(true);
    let creation = async {
        let request = RemoteRequest {
            id: run.id.clone(),
            controller_device_id: identity.device_id.clone(),
            host_device_id: host.id,
            permissions,
            path_mode,
        };
        let sdk = run.sdk.lock().await;
        match access_method {
            AccessMethod::TrustedDevice => sdk.create_trusted_remote(request).await,
            AccessMethod::LocalApproval | AccessMethod::Password => {
                sdk.create_remote(request).await
            }
        }
    }
    .await;
    let view = match creation {
        Ok(view) => view,
        Err(problem) => {
            // These management responses are issued before the create
            // transaction commits. Retaining a nonexistent request would make
            // its later DELETE fail with 403 and block every replacement run.
            // A transport/parse failure, 5xx or conflicting ID can still hide
            // a committed resource, so their cleanup ownership is retained.
            if matches!(&problem, nestlink_sdk::SdkError::Api(status, _) if matches!(status.as_u16(), 400 | 401 | 403 | 429))
            {
                run.request_created.set(false);
            }
            return Err(i18n::sdk_error(&problem).into());
        }
    };
    run.check()?;
    if access_method == AccessMethod::Password {
        authorize_password(&run, &identity, &view, ui).await?;
    }
    ui.status(t(
        "等待被控设备批准本次访问权限…",
        "Waiting for the remote device to approve this request…",
    ));
    let approval_deadline = performance_ms()? + 60_000.0;
    loop {
        run.check()?;
        if performance_ms()? >= approval_deadline {
            return Err(t(
                "本次请求等待批准超时，请重新请求。",
                "Approval timed out. Submit a new request.",
            )
            .into());
        }
        let view =
            managed_request(&run, async { run.sdk.lock().await.remote(&run.id).await }).await?;
        run.check()?;
        match view.status.as_str() {
            "approved" => break,
            "pending" => TimeoutFuture::new(400).await,
            _ => {
                return Err(t(
                    "被控设备未批准本次请求，或请求已撤销。",
                    "The remote device did not approve this request, or the request was revoked.",
                )
                .into());
            }
        }
    }
    let permit =
        managed_request(&run, async { run.sdk.lock().await.permit(&run.id).await }).await?;
    run.check()?;
    let mut peer = BrowserPeer::new_managed_persistent(run.sdk.clone(), permit, identity, mode)
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    *run.peer.borrow_mut() = Some(peer.cancellation());
    run.check()?;
    let track_run = run.clone();
    peer.on_remote_track(move |track| {
        if track_run.check().is_err() {
            track.stop();
            return;
        }
        track_run.stream.add_track(&track);
    });
    let network = NetworkObserver::attach().map_err(|problem| i18n::peer_error(&problem))?;
    ui.status(t(
        "权限已批准，正在与设备协商连接…",
        "Access approved. Negotiating the connection…",
    ));
    peer.create_and_publish_offer(12_000)
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    receive_answer(&run, &mut peer).await?;
    let mut path = peer
        .wait_for_verified_path(10_000)
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    ui.status(t(
        "正在核验双方设备身份…",
        "Verifying both device identities…",
    ));
    peer.complete_endpoint_proof()
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    ui.status(t(
        "正在读取本机批准的显示器…",
        "Loading displays approved on the remote device…",
    ));
    let catalog = peer
        .wait_for_display_catalog(5_000)
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    let initial_source = catalog
        .displays
        .first()
        .map(|item| item.source)
        .ok_or_else(|| i18n::peer_error(&PeerError::SignalRejected))?;
    let _ = ui.displays.try_set(Some(catalog));
    let _ = ui.display_switching.try_set(true);
    peer.select_display(initial_source)
        .map_err(|problem| i18n::peer_error(&problem))?;
    let initial_display = peer
        .wait_for_display_selection(5_000)
        .await
        .map_err(|problem| i18n::peer_error(&problem))?;
    let mut selected_display = initial_display
        .selected
        .clone()
        .ok_or_else(|| i18n::peer_error(&PeerError::SignalRejected))?;
    let _ = ui.displays.try_set(Some(initial_display));
    let _ = ui.display_switching.try_set(false);
    let rpc = BrowserRpc::new(
        peer.data_channels()
            .map_err(|problem| i18n::peer_error(&problem))?,
        peer.connection_generation(),
    )
    .map_err(|problem| problem.to_string())?;
    *run.files.borrow_mut() = Some(BrowserFiles::new(rpc.clone()));
    *run.clipboard.borrow_mut() = Some(BrowserClipboard::new(rpc));
    let _ = ui.data_ready.try_set(true);
    let mut input_capture = attach_input_capture(&run, &peer, requested.input)?;
    ui.status(path_status(path, false));
    let mut observed_network = network.generation.get();
    let mut last_control_check = performance_ms()?;
    let mut last_media_time = run.video.current_time();
    loop {
        run.check()?;
        if ui.generation.try_get_untracked() != Some(ui.revision) {
            return Err(t("连接页面已更换。", "The connection page changed.").into());
        }
        if let Some(source) = run.display_request.take() {
            // Drop first: release all old keys/buttons and unregister event
            // listeners before the ordered Select can reach the host.
            drop(input_capture.take());
            if !peer
                .select_display(source)
                .map_err(|problem| i18n::peer_error(&problem))?
            {
                input_capture = attach_input_capture(&run, &peer, requested.input)?;
                let _ = ui.display_switching.try_set(false);
            }
        }
        let snapshot = peer
            .display_snapshot()
            .map_err(|problem| i18n::peer_error(&problem))?
            .ok_or_else(|| i18n::peer_error(&PeerError::SignalRejected))?;
        if snapshot.pending_source.is_some() {
            ui.picture(false);
            let _ = ui.display_switching.try_set(true);
        } else if let Some(selection) = snapshot.selected.as_ref()
            && selection != &selected_display
        {
            input_capture = attach_input_capture(&run, &peer, requested.input)?;
            selected_display = selection.clone();
            last_media_time = run.video.current_time();
            ui.picture(false);
            let _ = ui.display_switching.try_set(false);
            ui.status(t(
                "显示器已切换，正在等待新画面…",
                "Display switched. Waiting for the new picture…",
            ));
        }
        if ui.displays.try_get_untracked().flatten().as_ref() != Some(&snapshot) {
            let _ = ui.displays.try_set(Some(snapshot));
        }
        peer.renew_from_host()
            .await
            .map_err(|problem| i18n::peer_error(&problem))?;
        peer.maintain_turn()
            .await
            .map_err(|problem| i18n::peer_error(&problem))?;
        let current_network = network.generation.get();
        if current_network != observed_network {
            // Consume only the generation used to create this offer. A newer
            // online/offline event during signaling or path verification must
            // remain pending and trigger one follow-up restart.
            observed_network = current_network;
            ui.picture(false);
            ui.status(t(
                "网络已变化，正在重新协商连接…",
                "The network changed. Negotiating a new connection…",
            ));
            peer.restart_ice_and_publish_offer(10_000)
                .await
                .map_err(|problem| i18n::peer_error(&problem))?;
            receive_answer(&run, &mut peer).await?;
            let verified_path = peer
                .wait_for_verified_path_or_network_change(10_000, || {
                    network.generation.get() != current_network
                })
                .await
                .map_err(|problem| i18n::peer_error(&problem))?;
            let Some(verified_path) = verified_path else {
                // The just-answered offer was built for an older route. Keep
                // tracks paused and let the next loop issue a fresh restart.
                continue;
            };
            path = verified_path;
            last_media_time = run.video.current_time();
        }
        let now = performance_ms()?;
        if now - last_control_check >= 1_000.0 {
            peer.check_control_status()
                .await
                .map_err(|problem| i18n::peer_error(&problem))?;
            last_control_check = now;
        }
        let media_time = run.video.current_time();
        if !ui.display_switching.try_get_untracked().unwrap_or(true)
            && media_time > last_media_time
            && run.video.ready_state() >= 2
            && run.video.video_width() > 0
        {
            ui.picture(true);
            ui.status(path_status(path, true));
            last_media_time = media_time;
        }
        TimeoutFuture::new(150).await;
    }
}

async fn authorize_password(
    run: &RemoteRun,
    identity: &DeviceIdentity,
    request: &RemoteView,
    ui: SessionUi,
) -> Result<(), String> {
    let settings = managed_request(run, async {
        run.sdk.lock().await.remote_password_offer(&run.id).await
    })
    .await?;
    run.check()?;
    if request.status != "pending"
        || !settings.active
        || !request
            .permissions
            .iter()
            .all(|permission| settings.permissions.contains(permission))
    {
        return Err(t(
            "主机密码授权未启用，或不允许本次请求的权限。请重新选择权限并创建请求。",
            "The host's password authorization is inactive or does not cover the requested permissions. Choose permissions and create a new request.",
        )
        .into());
    }
    let offer = PasswordOffer::new(request, &settings);
    let _ = ui.password_offer.try_set(Some(offer.clone()));
    ui.status(t(
        "核对主机允许的权限和路径，然后输入远控密码授权本次请求。",
        "Review the host's allowed permissions and paths, then enter its remote access password for this request.",
    ));
    let deadline = performance_ms()? + 60_000.0;
    let submitted = loop {
        run.check()?;
        if ui.generation.try_get_untracked() != Some(ui.revision) {
            return Err(t("连接页面已更换。", "The connection page changed.").into());
        }
        if performance_ms()? >= deadline {
            return Err(t(
                "本次密码授权等待超时，请重新请求。",
                "Password authorization timed out. Submit a new request.",
            )
            .into());
        }
        if let Some(submitted) = run.password_submission.borrow_mut().take() {
            break submitted;
        }
        TimeoutFuture::new(100).await;
    };
    let _ = ui.password_offer.try_set(None);
    if submitted.offer != offer {
        return Err(t(
            "密码不再对应当前请求，请重新请求。",
            "The password no longer belongs to the current request. Submit a new request.",
        )
        .into());
    }
    // Never submit a credential captured for an older nonce, policy, connection
    // generation or host configuration revision. The signed SDK request and
    // server CAS then enforce the same boundary through the final transaction.
    let (current, current_settings) = managed_request(run, async {
        let sdk = run.sdk.lock().await;
        let current = sdk.remote(&run.id).await?;
        let settings = sdk.remote_password_offer(&run.id).await?;
        Ok((current, settings))
    })
    .await?;
    run.check()?;
    if current.status != "pending"
        || !current_settings.active
        || PasswordOffer::new(&current, &current_settings) != offer
    {
        return Err(t(
            "本次请求或主机密码配置已变化，密码未提交。请重新请求。",
            "The request or host password configuration changed. The password was not submitted. Create a new request.",
        )
        .into());
    }
    let approved = managed_request(run, async {
        run.sdk
            .lock()
            .await
            .authorize_remote_password(
                identity,
                &current,
                offer.password_revision,
                submitted.password,
            )
            .await
    })
    .await?;
    run.check()?;
    if approved.id != run.id || approved.status != "approved" {
        return Err(t(
            "服务器未确认本次密码授权。",
            "The server did not confirm password authorization for this request.",
        )
        .into());
    }
    Ok(())
}

fn attach_input_capture(
    run: &RemoteRun,
    peer: &BrowserPeer,
    requested: bool,
) -> Result<Option<BrowserInputCapture>, String> {
    if !requested {
        return Ok(None);
    }
    let layout = peer
        .input_layout()
        .map_err(|problem| i18n::peer_error(&problem))?
        .ok_or_else(|| {
            t(
                "被控设备没有发布获准的输入布局。",
                "The remote device has not published an approved input layout.",
            )
            .to_owned()
        })?;
    let text = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("remote-input-text"))
        .and_then(|element| element.dyn_into::<HtmlTextAreaElement>().ok())
        .ok_or_else(|| {
            t(
                "远程文本输入区不可用。",
                "The remote text input field is unavailable.",
            )
            .to_owned()
        })?;
    let input_layout = BrowserInputLayout {
        left: layout.left,
        top: layout.top,
        width: layout.width,
        height: layout.height,
    };
    let sender = peer
        .input_sender()
        .map_err(|problem| i18n::peer_error(&problem))?;
    let paused = run.input_paused.clone();
    let capture =
        BrowserInputCapture::attach(run.video.clone(), text, input_layout, move |event| {
            if !paused.get()
                || matches!(
                    &event,
                    nestlink_web::browser_input::BrowserInputEvent::ReleaseAll
                )
            {
                let _ = sender.send(event);
            }
        })
        .map_err(str::to_owned)?;
    run.input_paused.set(false);
    Ok(Some(capture))
}

async fn receive_answer(run: &RemoteRun, peer: &mut BrowserPeer) -> Result<(), String> {
    loop {
        run.check()?;
        peer.renew_from_host()
            .await
            .map_err(|problem| i18n::peer_error(&problem))?;
        match peer.receive_and_apply_answer_with_timeout(1_000).await {
            Ok(()) => return Ok(()),
            Err(PeerError::AnswerRequired) => {
                peer.renew_from_host()
                    .await
                    .map_err(|problem| i18n::peer_error(&problem))?;
                TimeoutFuture::new(50).await;
            }
            Err(problem) => return Err(i18n::peer_error(&problem)),
        }
    }
}

fn path_status(path: SelectedPath, picture: bool) -> &'static str {
    match (path, picture) {
        (SelectedPath::Direct, true) => t(
            "已连接，正在接收远程画面（直连）。",
            "Connected directly. Receiving the remote screen.",
        ),
        (SelectedPath::Relay, true) => t(
            "已连接，正在接收远程画面（中继）。",
            "Connected through a relay. Receiving the remote screen.",
        ),
        (SelectedPath::Mixed, true) => t(
            "已连接，正在接收远程画面。",
            "Connected. Receiving the remote screen.",
        ),
        _ => t(
            "连接已验证，正在等待远程画面。浏览器若阻止播放，请点击播放。",
            "Connection verified. Waiting for the remote screen. Click Play if the browser blocks playback.",
        ),
    }
}

fn performance_ms() -> Result<f64, String> {
    let value = web_sys::window()
        .and_then(|window| window.performance())
        .ok_or_else(|| t("浏览器时钟不可用。", "The browser clock is unavailable.").to_owned())?
        .now();
    if !value.is_finite() || value < 0.0 {
        return Err(t("浏览器时钟不可用。", "The browser clock is unavailable.").into());
    }
    Ok(value)
}

struct NetworkObserver {
    generation: Rc<Cell<u64>>,
    targets: Vec<(EventTarget, &'static str)>,
    handler: Closure<dyn FnMut(Event)>,
}

impl NetworkObserver {
    fn attach() -> Result<Self, PeerError> {
        let window = web_sys::window().ok_or(PeerError::BrowserUnavailable)?;
        let generation = Rc::new(Cell::new(0_u64));
        let changes = generation.clone();
        let handler = Closure::wrap(Box::new(move |event: Event| {
            if network_event_requires_ice_restart(event.type_().as_str()) {
                changes.set(changes.get().saturating_add(1));
            }
        }) as Box<dyn FnMut(Event)>);
        let mut observer = Self {
            generation,
            targets: Vec::new(),
            handler,
        };
        observer.listen(window.clone().into(), "online")?;
        observer.listen(window.clone().into(), "offline")?;
        // Network Information is optional; online/offline remain available in
        // Firefox. Capability detection avoids assuming a Chromium-only API.
        let navigator = js_sys::Reflect::get(window.as_ref(), &"navigator".into())
            .map_err(|_| PeerError::BrowserUnavailable)?;
        if let Ok(connection) = js_sys::Reflect::get(&navigator, &"connection".into())
            && let Ok(target) = connection.dyn_into::<EventTarget>()
        {
            observer.listen(target, "change")?;
        }
        Ok(observer)
    }

    fn listen(&mut self, target: EventTarget, event: &'static str) -> Result<(), PeerError> {
        target
            .add_event_listener_with_callback(event, self.handler.as_ref().unchecked_ref())
            .map_err(|_| PeerError::BrowserUnavailable)?;
        self.targets.push((target, event));
        Ok(())
    }
}

impl Drop for NetworkObserver {
    fn drop(&mut self) {
        for (target, event) in &self.targets {
            let _ = target
                .remove_event_listener_with_callback(event, self.handler.as_ref().unchecked_ref());
        }
    }
}
