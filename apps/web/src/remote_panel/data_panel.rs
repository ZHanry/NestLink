//! Local approval and controls for the four remote data directions.
//! Clipboard contents are deliberately owned only by BrowserClipboard.
use super::RemoteRun;
use crate::{
    browser_clipboard::ClipboardWaiter,
    browser_files::{BrowserFileArtifact, BrowserFileProgress, FilePhase, FileProgress},
    browser_rpc::BrowserRpcError,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use nestlink_protocol::{
    DirectoryEntry, DirectoryEntryKind, FileRoot, webrtc_data::WebRtcDataChannel,
};
use nestlink_web::{i18n::text as t, localized_format};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::JsCast;
use web_sys::{Event, File, HtmlInputElement};

type RunOwner = StoredValue<Option<Rc<RemoteRun>>, LocalStorage>;
type TaskToken = Rc<Cell<bool>>;

#[derive(Clone, Copy)]
struct ActionUi {
    owner: RunOwner,
    ready: RwSignal<bool>,
    approved: RwSignal<[bool; 4]>,
    message: RwSignal<String>,
}

#[derive(Clone, Default)]
struct Tasks(Rc<RefCell<Vec<(WebRtcDataChannel, TaskToken)>>>);

impl Tasks {
    fn begin(&self, kind: WebRtcDataChannel) -> TaskToken {
        let token = Rc::new(Cell::new(false));
        self.0.borrow_mut().push((kind, token.clone()));
        token
    }

    fn finish(&self, token: &TaskToken) {
        self.0
            .borrow_mut()
            .retain(|(_, active)| !Rc::ptr_eq(active, token));
    }

    fn cancel(&self, kind: WebRtcDataChannel) {
        for (task_kind, token) in self.0.borrow().iter() {
            if *task_kind == kind {
                token.set(true);
            }
        }
    }

    fn cancel_all(&self) {
        for (_, token) in self.0.borrow().iter() {
            token.set(true);
        }
    }
}

#[component]
pub(super) fn RemoteDataPanel(owner: RunOwner, ready: RwSignal<bool>) -> impl IntoView {
    let approved = RwSignal::new([false; 4]);
    let available = RwSignal::new([false; 4]);
    let roots_read = RwSignal::new(Vec::<FileRoot>::new());
    let roots_write = RwSignal::new(Vec::<FileRoot>::new());
    let selected_read_root = RwSignal::new(String::new());
    let selected_write_root = RwSignal::new(String::new());
    let read_directory = RwSignal::new(String::new());
    let read_entries = RwSignal::new(Vec::<DirectoryEntry>::new());
    let download_path = RwSignal::new(String::new());
    let upload_file: StoredValue<Option<File>, LocalStorage> = StoredValue::new_local(None);
    let upload_file_selected = RwSignal::new(false);
    let upload_path = RwSignal::new(String::new());
    let artifacts = RwSignal::new(Vec::<BrowserFileArtifact>::new());
    let read_progress = RwSignal::new(None::<BrowserFileProgress>);
    let write_progress = RwSignal::new(None::<BrowserFileProgress>);
    let read_busy = RwSignal::new(false);
    let write_busy = RwSignal::new(false);
    let clipboard_busy = RwSignal::new(false);
    let pending_clipboard = RwSignal::new(false);
    let discarding = RwSignal::new(Vec::<String>::new());
    let message = RwSignal::new(String::new());
    let tasks = Tasks::default();
    let ui = ActionUi {
        owner,
        ready,
        approved,
        message,
    };

    // ready changes once per session. Revoke local approvals on every stop and
    // refresh retained artifact metadata while cleanup remains available.
    let effect_tasks = tasks.clone();
    Effect::new(move |_| {
        let live = ready.get();
        let run = owner.get_value();
        if let Some(run) = run.as_ref() {
            for kind in [
                WebRtcDataChannel::FileRead,
                WebRtcDataChannel::FileWrite,
                WebRtcDataChannel::ClipboardRead,
                WebRtcDataChannel::ClipboardWrite,
            ] {
                run.set_data_consent(kind, false);
            }
            if let Some(clipboard) = run.clipboard.borrow().as_ref() {
                clipboard.clear();
            }
            if let Some(files) = run.files.borrow().as_ref() {
                artifacts.set(files.artifacts());
            }
        }
        effect_tasks.cancel_all();
        approved.set([false; 4]);
        pending_clipboard.set(false);
        available.set(if live {
            run.as_ref().map(available_directions).unwrap_or([false; 4])
        } else {
            [false; 4]
        });
    });

    let cleanup_tasks = StoredValue::new_local(tasks.clone());
    on_cleanup(move || {
        cleanup_tasks.get_value().cancel_all();
        if let Some(run) = owner.get_value() {
            for kind in [
                WebRtcDataChannel::FileRead,
                WebRtcDataChannel::FileWrite,
                WebRtcDataChannel::ClipboardRead,
                WebRtcDataChannel::ClipboardWrite,
            ] {
                run.set_data_consent(kind, false);
            }
            if let Some(clipboard) = run.clipboard.borrow().as_ref() {
                clipboard.clear();
            }
        }
    });

    let read_roots_tasks = tasks.clone();
    let load_read_roots = move |_| {
        start_roots(
            ui,
            read_roots_tasks.clone(),
            read_busy,
            roots_read,
            selected_read_root,
            read_entries,
            false,
        );
    };
    let write_roots_tasks = tasks.clone();
    let load_write_roots = move |_| {
        start_roots(
            ui,
            write_roots_tasks.clone(),
            write_busy,
            roots_write,
            selected_write_root,
            read_entries,
            true,
        );
    };
    let browse_current_tasks = tasks.clone();
    let browse_current = move |_| {
        let root_id = selected_read_root.get_untracked();
        if !root_id.is_empty() {
            start_browse(
                ui,
                browse_current_tasks.clone(),
                read_busy,
                read_entries,
                read_directory,
                root_id,
                read_directory.get_untracked(),
            );
        }
    };
    let browse_parent_tasks = tasks.clone();
    let browse_parent = move |_| {
        let root_id = selected_read_root.get_untracked();
        let current = read_directory.get_untracked();
        if !root_id.is_empty() {
            let parent = current
                .rsplit_once('/')
                .map(|(path, _)| path.to_owned())
                .unwrap_or_default();
            start_browse(
                ui,
                browse_parent_tasks.clone(),
                read_busy,
                read_entries,
                read_directory,
                root_id,
                parent,
            );
        }
    };

    let download_tasks = tasks.clone();
    let download = move |_| {
        let path = download_path.get_untracked();
        let root_id = selected_read_root.get_untracked();
        start_download(
            ui,
            download_tasks.clone(),
            read_busy,
            read_progress,
            artifacts,
            root_id,
            path,
        );
    };
    let upload_change = move |event: Event| {
        let input = event
            .target()
            .and_then(|target| target.dyn_into::<HtmlInputElement>().ok());
        let file = input
            .and_then(|input| input.files())
            .and_then(|files| files.get(0));
        if let Some(file) = file {
            upload_path.set(file.name());
            upload_file.set_value(Some(file));
            upload_file_selected.set(true);
        } else {
            upload_file.set_value(None);
            upload_file_selected.set(false);
            upload_path.set(String::new());
        }
    };
    let upload_tasks = tasks.clone();
    let upload = move |_| {
        let selected = upload_file.get_value();
        let path = upload_path.get_untracked();
        let root_id = selected_write_root.get_untracked();
        if let Some(file) = selected {
            start_upload(
                ui,
                upload_tasks.clone(),
                write_busy,
                write_progress,
                file,
                root_id,
                path,
            );
        } else {
            let _ = message.try_set(
                t(
                    "请先选择要上传的本机文件。",
                    "Choose a local file to upload first.",
                )
                .into(),
            );
        }
    };

    let receive_tasks = tasks.clone();
    let receive_clipboard = move |_| {
        if !ready.get_untracked() || !approved.get_untracked()[2] || clipboard_busy.get_untracked()
        {
            return;
        }
        let Some(run) = owner.get_value() else {
            return;
        };
        let Some(clipboard) = run.clipboard.borrow().clone() else {
            return;
        };
        let task_set = receive_tasks.clone();
        let token = task_set.begin(WebRtcDataChannel::ClipboardRead);
        clipboard_busy.set(true);
        message.set(
            t(
                "正在安全接收设备剪贴板；内容只会进入私有暂存。",
                "Receiving the device clipboard into private temporary storage.",
            )
            .into(),
        );
        let consent = run.consent(WebRtcDataChannel::ClipboardRead, token.clone());
        let waiting = match clipboard.receive_remote(consent) {
            Ok(waiting) => waiting,
            Err(error) => {
                task_set.finish(&token);
                clipboard_busy.set(false);
                message.set(error.to_string());
                return;
            }
        };
        spawn_local(async move {
            let result = await_clipboard(waiting).await;
            if !token.get() {
                match result {
                    Ok(()) => {
                        let _ = pending_clipboard.try_set(clipboard.has_pending());
                        let _ = message.try_set(
                            t("远端剪贴板已暂存；点击“复制到本机”后才会写入本机剪贴板。", "Remote clipboard received. Click Copy locally to write it to your clipboard.").into(),
                        );
                    }
                    Err(error) => {
                        let _ = pending_clipboard.try_set(false);
                        let _ = message.try_set(error.to_string());
                    }
                }
            }
            let _ = clipboard_busy.try_set(false);
            task_set.finish(&token);
        });
    };
    let copy_tasks = tasks.clone();
    let copy_clipboard = move |_| {
        if !ready.get_untracked() || !approved.get_untracked()[2] || clipboard_busy.get_untracked()
        {
            return;
        }
        let Some(run) = owner.get_value() else {
            return;
        };
        let Some(clipboard) = run.clipboard.borrow().clone() else {
            return;
        };
        let task_set = copy_tasks.clone();
        let token = task_set.begin(WebRtcDataChannel::ClipboardRead);
        let consent = run.consent(WebRtcDataChannel::ClipboardRead, token.clone());
        // Keep this method in the click stack so the browser user activation is live.
        let waiting = match clipboard.copy_remote(consent) {
            Ok(waiting) => waiting,
            Err(error) => {
                task_set.finish(&token);
                message.set(error.to_string());
                return;
            }
        };
        pending_clipboard.set(false);
        clipboard_busy.set(true);
        message.set(
            t(
                "正在将暂存文本写入本机剪贴板…",
                "Copying the received text to your clipboard…",
            )
            .into(),
        );
        spawn_local(async move {
            let result = await_clipboard(waiting).await;
            let _ = clipboard_busy.try_set(false);
            if !token.get() {
                let _ = message.try_set(
                    result
                        .map(|_| t("已复制到本机剪贴板。", "Copied to your clipboard.").into())
                        .unwrap_or_else(|error| error.to_string()),
                );
            }
            task_set.finish(&token);
        });
    };
    let send_tasks = tasks.clone();
    let send_clipboard = move |_| {
        if !ready.get_untracked() || !approved.get_untracked()[3] || clipboard_busy.get_untracked()
        {
            return;
        }
        let Some(run) = owner.get_value() else {
            return;
        };
        let Some(clipboard) = run.clipboard.borrow().clone() else {
            return;
        };
        let task_set = send_tasks.clone();
        let token = task_set.begin(WebRtcDataChannel::ClipboardWrite);
        let consent = run.consent(WebRtcDataChannel::ClipboardWrite, token.clone());
        // readText must also be invoked synchronously during this click.
        let waiting = match clipboard.send_local(consent) {
            Ok(waiting) => waiting,
            Err(error) => {
                task_set.finish(&token);
                message.set(error.to_string());
                return;
            }
        };
        clipboard_busy.set(true);
        message.set(t("正在安全发送本机剪贴板…", "Sending your local clipboard…").into());
        spawn_local(async move {
            let result = await_clipboard(waiting).await;
            let _ = clipboard_busy.try_set(false);
            if !token.get() {
                let _ = message.try_set(
                    result
                        .map(|_| t("本机剪贴板已发送。", "Local clipboard sent.").into())
                        .unwrap_or_else(|error| error.to_string()),
                );
            }
            task_set.finish(&token);
        });
    };

    let refresh_artifacts = move |_| {
        if let Some(run) = owner.get_value()
            && let Some(files) = run.files.borrow().as_ref()
        {
            artifacts.set(files.artifacts());
        }
    };
    let file_read_approval_tasks = tasks.clone();
    let file_write_approval_tasks = tasks.clone();
    let clipboard_read_approval_tasks = tasks.clone();
    let clipboard_write_approval_tasks = tasks.clone();
    let entry_tasks = StoredValue::new_local(tasks.clone());
    let collapse_tasks = tasks.clone();

    view! {
        <details class="remote-data-panel" on:toggle=move |event: Event| {
            let open = event.target().and_then(|target|
                js_sys::Reflect::get(target.as_ref(), &"open".into()).ok())
                .and_then(|value| value.as_bool());
            if open == Some(false) {
                collapse_tasks.cancel_all();
                approved.set([false; 4]);
                pending_clipboard.set(false);
                if let Some(run) = owner.get_value() {
                    for kind in [WebRtcDataChannel::FileRead, WebRtcDataChannel::FileWrite,
                        WebRtcDataChannel::ClipboardRead, WebRtcDataChannel::ClipboardWrite] {
                        run.set_data_consent(kind, false);
                    }
                }
            }
        }>
            <summary>{move || t("文件与剪贴板（本机默认不批准）", "Files and clipboard (local approval required)")}</summary>
            <div class="remote-data-content">
                <p class="remote-data-note">{move || t("连接就绪后，每个方向还需在本机单独批准。停止连接或关闭此面板会撤销本机批准。", "When connected, approve each direction locally. Stopping the connection or closing this panel revokes local approval.")}</p>
                <fieldset class="remote-data-approvals">
                    <legend>{move || t("本机操作授权", "Local approval")}</legend>
                    <label><input type="checkbox" disabled=move || !ready.get() || !available.get()[0] prop:checked=move || approved.get()[0] on:change=move |event| apply_approval(ui, available, pending_clipboard, file_read_approval_tasks.clone(), 0, WebRtcDataChannel::FileRead, event_target_checked(&event)) />{move || t("允许本机接收远端文件", "Allow receiving remote files")}</label>
                    <label><input type="checkbox" disabled=move || !ready.get() || !available.get()[1] prop:checked=move || approved.get()[1] on:change=move |event| apply_approval(ui, available, pending_clipboard, file_write_approval_tasks.clone(), 1, WebRtcDataChannel::FileWrite, event_target_checked(&event)) />{move || t("允许本机发送文件到远端", "Allow sending local files")}</label>
                    <label><input type="checkbox" disabled=move || !ready.get() || !available.get()[2] prop:checked=move || approved.get()[2] on:change=move |event| apply_approval(ui, available, pending_clipboard, clipboard_read_approval_tasks.clone(), 2, WebRtcDataChannel::ClipboardRead, event_target_checked(&event)) />{move || t("允许接收远端剪贴板", "Allow receiving the remote clipboard")}</label>
                    <label><input type="checkbox" disabled=move || !ready.get() || !available.get()[3] prop:checked=move || approved.get()[3] on:change=move |event| apply_approval(ui, available, pending_clipboard, clipboard_write_approval_tasks.clone(), 3, WebRtcDataChannel::ClipboardWrite, event_target_checked(&event)) />{move || t("允许发送本机剪贴板", "Allow sending the local clipboard")}</label>
                    <span class="remote-data-state" aria-live="polite">{move || if ready.get() { t("连接已验证", "Connection verified") } else { t("等待连接就绪", "Waiting for connection") }}</span>
                </fieldset>

                <section class="remote-data-section" aria-labelledby="remote-files-title">
                    <h3 id="remote-files-title">{move || t("接收远端文件", "Receive remote files")}</h3>
                    <div class="remote-data-actions">
                        <button class="secondary" type="button" disabled=move || !ready.get() || !approved.get()[0] || read_busy.get() on:click=load_read_roots>{move || t("加载可访问位置", "Load accessible locations")}</button>
                        <label class="remote-data-field">{move || t("远端位置", "Remote location")}
                            <select disabled=move || !approved.get()[0] || read_busy.get() prop:value=move || selected_read_root.get() on:change=move |event| {
                                let root = event_target_value(&event);
                                selected_read_root.set(root);
                                read_directory.set(String::new());
                                read_entries.set(Vec::new());
                            }>
                                <option value="">{move || t("选择被控设备位置", "Choose a location on the remote device")}</option>
                                <For each=move || roots_read.get() key=|root| root.root_id.clone() children=move |root| {
                                    view! { <option value=root.root_id.clone()>{root.display_name.clone()}</option> }
                                } />
                            </select>
                        </label>
                        <button class="secondary" type="button" disabled=move || !approved.get()[0] || selected_read_root.get().is_empty() || read_busy.get() on:click=browse_current>{move || t("浏览目录", "Browse folder")}</button>
                        <button class="secondary" type="button" disabled=move || !approved.get()[0] || selected_read_root.get().is_empty() || read_directory.get().is_empty() || read_busy.get() on:click=browse_parent>{move || t("上一级", "Parent folder")}</button>
                    </div>
                    <p class="remote-data-path">{move || t("当前目录：", "Current folder: ")}<code>{move || if read_directory.get().is_empty() { "/".to_owned() } else { format!("/{}", read_directory.get()) }}</code></p>
                    <ul class="remote-directory-list" aria-label=move || t("远端目录内容", "Remote folder contents")>
                        <For each=move || read_entries.get() key=|entry| entry.name.clone() children=move |entry| {
                            let is_directory = entry.kind == DirectoryEntryKind::DirectoryEntryDirectory as i32;
                            let entry_name = entry.name.clone();
                            let row_name = entry.name.clone();
                            let size = entry.size;
                            let row_tasks = entry_tasks.get_value();
                            view! {
                                <li>
                                    <button class="remote-file-entry" type="button" disabled=move || !approved.get()[0] || read_busy.get() on:click=move |_| {
                                        let current = read_directory.get_untracked();
                                        let path = if current.is_empty() { entry_name.clone() } else { format!("{current}/{entry_name}") };
                                        if is_directory {
                                            let root = selected_read_root.get_untracked();
                                            start_browse(ui, row_tasks.clone(), read_busy,
                                                read_entries, read_directory, root, path);
                                        } else {
                                            download_path.set(path);
                                        }
                                    }>
                                        <span>{if is_directory { format!("▸ {row_name}") } else { row_name }}</span>
                                        <small>{move || if is_directory { t("文件夹", "Folder").to_owned() } else { size.map(format_bytes).unwrap_or_else(|| t("文件", "File").into()) }}</small>
                                    </button>
                                </li>
                            }
                        } />
                    </ul>
                    <div class="remote-data-actions">
                        <label class="remote-data-field">{move || t("远端相对文件路径", "Relative remote file path")}
                            <input type="text" autocomplete="off" spellcheck="false" placeholder=move || t("例如：文档/报告.pdf", "For example: Documents/report.pdf") prop:value=move || download_path.get() on:input=move |event| download_path.set(event_target_value(&event)) />
                        </label>
                        <button class="primary" type="button" disabled=move || !ready.get() || !approved.get()[0] || read_busy.get() || selected_read_root.get().is_empty() || download_path.get().trim().is_empty() on:click=download>{move || t("安全接收文件", "Receive file")}</button>
                    </div>
                    <Progress progress=read_progress busy=read_busy />
                </section>

                <section class="remote-data-section" aria-labelledby="remote-upload-title">
                    <h3 id="remote-upload-title">{move || t("发送本机文件", "Send local files")}</h3>
                    <div class="remote-data-actions">
                        <button class="secondary" type="button" disabled=move || !ready.get() || !approved.get()[1] || write_busy.get() on:click=load_write_roots>{move || t("加载远端接收位置", "Load remote upload locations")}</button>
                        <label class="remote-data-field">{move || t("远端接收位置", "Remote upload location")}
                            <select disabled=move || !approved.get()[1] || write_busy.get() prop:value=move || selected_write_root.get() on:change=move |event| selected_write_root.set(event_target_value(&event))>
                                <option value="">{move || t("选择被控设备位置", "Choose a location on the remote device")}</option>
                                <For each=move || roots_write.get() key=|root| root.root_id.clone() children=move |root| {
                                    view! { <option value=root.root_id.clone()>{root.display_name.clone()}</option> }
                                } />
                            </select>
                        </label>
                        <label class="remote-data-field">{move || t("选择本机文件", "Choose local file")}
                            <input type="file" disabled=move || !ready.get() || !approved.get()[1] || write_busy.get() on:change=upload_change />
                        </label>
                        <label class="remote-data-field">{move || t("远端相对保存路径", "Relative remote destination path")}
                            <input type="text" autocomplete="off" spellcheck="false" placeholder=move || t("例如：上传/文件.txt", "For example: Uploads/file.txt") prop:value=move || upload_path.get() on:input=move |event| upload_path.set(event_target_value(&event)) />
                        </label>
                        <button class="primary" type="button" disabled=move || !ready.get() || !approved.get()[1] || write_busy.get() || selected_write_root.get().is_empty() || !upload_file_selected.get() || upload_path.get().trim().is_empty() on:click=upload>{move || t("发送文件", "Send file")}</button>
                    </div>
                    <Progress progress=write_progress busy=write_busy />
                </section>

                <section class="remote-data-section" aria-labelledby="remote-artifacts-title">
                    <div class="remote-data-heading"><h3 id="remote-artifacts-title">{move || t("本机暂存文件", "Temporary local files")}</h3><button class="secondary" type="button" on:click=refresh_artifacts>{move || t("刷新", "Refresh")}</button></div>
                    <p class="remote-data-note">{move || t("接收的文件先保存在浏览器私有暂存区。保存会打开浏览器下载；删除会清理暂存副本。连接停止后也可以重试删除。", "Received files are held in private browser storage. Save starts a browser download; Delete removes the temporary copy. You can retry deletion after disconnecting.")}</p>
                    <Show when=move || artifacts.get().is_empty()>
                        <p class="remote-data-empty">{move || t("没有待处理的暂存文件。", "No temporary files to manage.")}</p>
                    </Show>
                    <ul class="remote-artifact-list">
                        <For each=move || artifacts.get() key=|artifact| artifact.id.clone() children=move |artifact| {
                            let artifact_id = artifact.id.clone();
                            let id_for_save = StoredValue::new(artifact.id.clone());
                            let id_for_delete = artifact.id.clone();
                            let id_for_disabled = artifact.id.clone();
                            let id_for_label = artifact.id.clone();
                            let filename = artifact.filename.clone();
                            let size = artifact.size;
                            let verified = artifact.verified;
                            view! {
                                <li class="remote-artifact">
                                    <div class="remote-artifact-info"><strong>{filename}</strong>
                                        <small>{format!("{} · {}", format_bytes(size), if verified { t("已校验", "Verified") } else { t("需要清理", "Cleanup required") })}</small></div>
                                    <div class="remote-data-actions">
                                        <Show when=move || verified>
                                            <button class="secondary" type="button" on:click=move |_| {
                                                if let Some(run) = owner.get_value()
                                                    && let Some(files) = run.files.borrow().as_ref() {
                                                    match files.save(&id_for_save.get_value()) {
                                                        Ok(()) => message.set(t("已交由浏览器保存暂存文件。", "The browser has been asked to save the temporary file.").into()),
                                                        Err(error) => message.set(error.to_string()),
                                                    }
                                                }
                                            } >{move || t("保存到本机", "Save locally")}</button>
                                        </Show>
                                        <button class="danger" type="button" disabled=move || discarding.get().iter().any(|id| id == &id_for_disabled) on:click=move |_| {
                                            if discarding.get_untracked().iter().any(|id| id == &artifact_id) { return; }
                                            let Some(run) = owner.get_value() else { return; };
                                            let Some(files) = run.files.borrow().clone() else { return; };
                                            let id = id_for_delete.clone();
                                            discarding.update(|ids| if !ids.contains(&id) { ids.push(id.clone()); });
                                            spawn_local(async move {
                                                let result = files.discard(id.clone()).await;
                                                let _ = discarding.try_update(|ids| ids.retain(|value| value != &id));
                                                let _ = artifacts.try_set(files.artifacts());
                                                let _ = message.try_set(result.map(|_| t("暂存文件已删除。", "Temporary file deleted.").into()).unwrap_or_else(|error| localized_format!("无法删除暂存文件：{error}", "Could not delete the temporary file: {error}")));
                                            });
                                        } >{move || if discarding.get().iter().any(|id| id == &id_for_label) { t("正在删除…", "Deleting…") } else { t("删除暂存", "Delete temporary copy") }}</button>
                                    </div>
                                </li>
                            }
                        } />
                    </ul>
                </section>

                <section class="remote-data-section" aria-labelledby="remote-clipboard-title">
                    <h3 id="remote-clipboard-title">{move || t("剪贴板", "Clipboard")}</h3>
                    <p class="remote-data-note">{move || t("文本不会显示在此面板或页面状态中。接收只暂存在内存 30 秒；复制和发送均由你点击后执行。", "Text is never displayed in this panel or page status. Received text stays in memory for 30 seconds. Copying and sending require your click.")}</p>
                    <div class="remote-data-actions">
                        <button class="secondary" type="button" disabled=move || !ready.get() || !approved.get()[2] || clipboard_busy.get() on:click=receive_clipboard>{move || t("接收远端剪贴板", "Receive remote clipboard")}</button>
                        <button class="secondary" type="button" disabled=move || !ready.get() || !approved.get()[2] || !pending_clipboard.get() || clipboard_busy.get() on:click=copy_clipboard>{move || t("复制到本机", "Copy locally")}</button>
                        <button class="secondary" type="button" disabled=move || !ready.get() || !approved.get()[3] || clipboard_busy.get() on:click=send_clipboard>{move || t("发送本机剪贴板", "Send local clipboard")}</button>
                    </div>
                </section>
                <p class="remote-data-message" aria-live="polite">{move || message.get()}</p>
            </div>
        </details>
    }
}

#[component]
fn Progress(
    progress: RwSignal<Option<BrowserFileProgress>>,
    busy: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <Show when=move || busy.get() || progress.get().is_some()>
            <div class="remote-data-progress" aria-live="polite">
                {move || progress.get().map(|value| format!("{}：{} / {}", phase_label(value.phase), format_bytes(value.confirmed_bytes), format_bytes(value.total_bytes))).unwrap_or_else(|| t("正在准备文件操作…", "Preparing file operation…").into())}
            </div>
        </Show>
    }
}

fn available_directions(run: &Rc<RemoteRun>) -> [bool; 4] {
    [
        run.files
            .borrow()
            .as_ref()
            .is_some_and(|files| files.has(WebRtcDataChannel::FileRead)),
        run.files
            .borrow()
            .as_ref()
            .is_some_and(|files| files.has(WebRtcDataChannel::FileWrite)),
        run.clipboard
            .borrow()
            .as_ref()
            .is_some_and(|clipboard| clipboard.has(WebRtcDataChannel::ClipboardRead)),
        run.clipboard
            .borrow()
            .as_ref()
            .is_some_and(|clipboard| clipboard.has(WebRtcDataChannel::ClipboardWrite)),
    ]
}

fn apply_approval(
    ui: ActionUi,
    available: RwSignal<[bool; 4]>,
    pending_clipboard: RwSignal<bool>,
    tasks: Tasks,
    index: usize,
    kind: WebRtcDataChannel,
    requested: bool,
) {
    let ActionUi {
        owner,
        ready,
        approved,
        ..
    } = ui;
    let allowed = requested && ready.get_untracked() && available.get_untracked()[index];
    if !allowed {
        tasks.cancel(kind);
    }
    if let Some(run) = owner.get_value() {
        run.set_data_consent(kind, allowed);
    }
    approved.update(|values| values[index] = allowed);
    if !allowed && kind == WebRtcDataChannel::ClipboardRead {
        if let Some(run) = owner.get_value()
            && let Some(clipboard) = run.clipboard.borrow().as_ref()
        {
            clipboard.clear();
        }
        pending_clipboard.set(false);
    }
}

fn start_roots(
    ui: ActionUi,
    tasks: Tasks,
    busy: RwSignal<bool>,
    roots: RwSignal<Vec<FileRoot>>,
    selected: RwSignal<String>,
    entries: RwSignal<Vec<DirectoryEntry>>,
    write: bool,
) {
    let ActionUi {
        owner,
        ready,
        approved,
        message,
    } = ui;
    let index = if write { 1 } else { 0 };
    let kind = if write {
        WebRtcDataChannel::FileWrite
    } else {
        WebRtcDataChannel::FileRead
    };
    if !ready.get_untracked() || !approved.get_untracked()[index] || busy.get_untracked() {
        return;
    }
    let Some(run) = owner.get_value() else {
        return;
    };
    let Some(files) = run.files.borrow().clone() else {
        return;
    };
    let token = tasks.begin(kind);
    busy.set(true);
    message.set(
        if write {
            t("正在读取远端接收位置…", "Loading remote upload locations…")
        } else {
            t(
                "正在读取远端可访问位置…",
                "Loading accessible remote locations…",
            )
        }
        .into(),
    );
    let consent = run.consent(kind, token.clone());
    spawn_local(async move {
        let result = files.roots(write, consent).await;
        if !token.get() {
            match result {
                Ok(found) => {
                    let first = found
                        .first()
                        .map(|root| root.root_id.clone())
                        .unwrap_or_default();
                    let _ = roots.try_set(found);
                    let _ = selected.try_set(first);
                    if !write {
                        let _ = entries.try_set(Vec::new());
                    }
                    let _ = message.try_set(
                        t(
                            "已加载被控设备实际提供的位置。",
                            "Loaded the locations provided by the remote device.",
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    let _ = message.try_set(error.to_string());
                }
            }
        }
        let _ = busy.try_set(false);
        tasks.finish(&token);
    });
}

fn start_browse(
    ui: ActionUi,
    tasks: Tasks,
    busy: RwSignal<bool>,
    entries: RwSignal<Vec<DirectoryEntry>>,
    directory: RwSignal<String>,
    root_id: String,
    path: String,
) {
    let ActionUi {
        owner,
        ready,
        approved,
        message,
    } = ui;
    if root_id.is_empty()
        || !ready.get_untracked()
        || !approved.get_untracked()[0]
        || busy.get_untracked()
    {
        return;
    }
    let Some(run) = owner.get_value() else {
        return;
    };
    let Some(files) = run.files.borrow().clone() else {
        return;
    };
    let kind = WebRtcDataChannel::FileRead;
    let token = tasks.begin(kind);
    busy.set(true);
    message.set(t("正在浏览被控设备目录…", "Browsing the remote folder…").into());
    let consent = run.consent(kind, token.clone());
    spawn_local(async move {
        let result = files.browse(root_id, path.clone(), consent).await;
        if !token.get() {
            match result {
                Ok(found) => {
                    let _ = directory.try_set(path);
                    let _ = entries.try_set(found);
                    let _ = message
                        .try_set(t("目录内容已加载；这里只显示被控设备返回的名称和大小。", "Folder loaded. Names and sizes are those returned by the remote device.").into());
                }
                Err(error) => {
                    let _ = message.try_set(error.to_string());
                }
            }
        }
        let _ = busy.try_set(false);
        tasks.finish(&token);
    });
}

fn start_download(
    ui: ActionUi,
    tasks: Tasks,
    busy: RwSignal<bool>,
    progress: RwSignal<Option<BrowserFileProgress>>,
    artifacts: RwSignal<Vec<BrowserFileArtifact>>,
    root_id: String,
    path: String,
) {
    let ActionUi {
        owner,
        ready,
        approved,
        message,
    } = ui;
    if root_id.is_empty()
        || path.trim().is_empty()
        || !ready.get_untracked()
        || !approved.get_untracked()[0]
        || busy.get_untracked()
    {
        return;
    }
    let Some(run) = owner.get_value() else {
        return;
    };
    let Some(files) = run.files.borrow().clone() else {
        return;
    };
    let kind = WebRtcDataChannel::FileRead;
    let token = tasks.begin(kind);
    busy.set(true);
    progress.set(None);
    message.set(
        t(
            "正在接收并校验远端文件…",
            "Receiving and verifying the remote file…",
        )
        .into(),
    );
    let consent = run.consent(kind, token.clone());
    let update: FileProgress = Rc::new(move |value| {
        let _ = progress.try_set(Some(value));
    });
    spawn_local(async move {
        let result = files.download(root_id, path, consent, update).await;
        // A failed local cleanup leaves a retryable artifact even after the
        // consent token has been cancelled; always refresh that inventory.
        let _ = artifacts.try_set(files.artifacts());
        if !token.get() {
            match result {
                Ok(_) => {
                    let _ = message.try_set(
                        t(
                            "文件已完整校验并放入本机私有暂存区。",
                            "File verified and stored in private local temporary storage.",
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    let _ = message.try_set(error.to_string());
                }
            }
        }
        let _ = busy.try_set(false);
        tasks.finish(&token);
    });
}

fn start_upload(
    ui: ActionUi,
    tasks: Tasks,
    busy: RwSignal<bool>,
    progress: RwSignal<Option<BrowserFileProgress>>,
    file: File,
    root_id: String,
    path: String,
) {
    let ActionUi {
        owner,
        ready,
        approved,
        message,
    } = ui;
    if root_id.is_empty()
        || path.trim().is_empty()
        || !ready.get_untracked()
        || !approved.get_untracked()[1]
        || busy.get_untracked()
    {
        return;
    }
    let Some(run) = owner.get_value() else {
        return;
    };
    let Some(files) = run.files.borrow().clone() else {
        return;
    };
    let kind = WebRtcDataChannel::FileWrite;
    let token = tasks.begin(kind);
    busy.set(true);
    progress.set(None);
    message.set(
        t(
            "正在校验并发送本机文件…",
            "Verifying and sending the local file…",
        )
        .into(),
    );
    let consent = run.consent(kind, token.clone());
    let update: FileProgress = Rc::new(move |value| {
        let _ = progress.try_set(Some(value));
    });
    spawn_local(async move {
        let result = files.upload(file, root_id, path, consent, update).await;
        if !token.get() {
            let _ = message.try_set(
                result
                    .map(|_| {
                        t(
                            "远端已确认文件完整接收。",
                            "The remote device confirmed receipt of the complete file.",
                        )
                        .into()
                    })
                    .unwrap_or_else(|error| error.to_string()),
            );
        }
        let _ = busy.try_set(false);
        tasks.finish(&token);
    });
}

async fn await_clipboard(waiting: ClipboardWaiter) -> Result<(), BrowserRpcError> {
    waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
}

fn phase_label(phase: FilePhase) -> &'static str {
    match phase {
        FilePhase::Preparing => t("准备文件", "Preparing file"),
        FilePhase::Transferring => t("已确认传输", "Transfer confirmed"),
        FilePhase::Verifying => t("校验文件", "Verifying file"),
        FilePhase::Complete => t("传输完成", "Transfer complete"),
        FilePhase::Cleaning => t("清理未完成传输", "Cleaning up incomplete transfer"),
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64 / 1024.0;
    let mut index = 0;
    while value >= 1024.0 && index + 1 < units.len() {
        value /= 1024.0;
        index += 1;
    }
    format!("{value:.1} {}", units[index])
}
