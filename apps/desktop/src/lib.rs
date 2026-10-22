//! Desktop binding: actual state belongs to the user daemon, never the window.
mod bridge;
mod browser_data;
mod browser_displays;
mod clipboard;
mod connection;
mod files;
mod host_notice;
mod icons;
mod layout_diagnostics;
#[cfg(test)]
mod layout_tests;
mod lists;
mod local_session_window;
mod management;
mod native_displays;
mod native_input;
mod native_network;
mod navigation;
pub mod picker;
mod privileged_input;
mod remote;
mod remote_flow;
mod request_task_dialog;
mod services;
pub mod theme;
mod tray;
mod widgets;

use bridge::{Bridge, InputLayoutUpdate, Notice, VideoUpdate};
use eframe::egui;
use nestlink_app_core::{
    Action, Authentication, BrowserHostStatus, NativeInputAction, NativeInputBinding,
    NativeInputLayout, NativeSessionCleanup, NativeSessionStatus, OperationId, OperationKind,
    OperationStatus, Page, Snapshot,
};
use nestlink_app_ipc::wire::{Command, ExitResult, SensitiveReply};
use std::collections::BTreeSet;
use std::{path::PathBuf, time::Duration};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Screen {
    Remote,
    Services,
    Devices,
    Security,
    Accounts,
    Network,
    Nodes,
    Audit,
    Server,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum VideoStatus {
    #[default]
    Idle,
    Connecting,
    WaitingForFrame,
    Streaming,
    Reconnecting,
}
struct VideoObservation {
    codec: u8,
    hardware: bool,
    layout: (u64, u32, u32),
    window: std::time::Instant,
    frames: u32,
    fps: Option<f64>,
    latest: std::time::Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum MessageTone {
    #[default]
    Neutral,
    Warning,
    Success,
    Danger,
}

#[derive(Default)]
struct Credentials {
    remember_login: bool,
    username: String,
    password: Zeroizing<String>,
    new_password: Zeroizing<String>,
}
impl Credentials {
    fn clear(&mut self) {
        self.username.clear();
        self.password.zeroize();
        self.new_password.zeroize();
    }
}

#[derive(Default)]
struct TrustForm {
    origin: String,
    loopback: bool,
}

#[derive(Clone)]
struct RemoteViewportTarget {
    request_id: String,
    connection_generation: u64,
}

struct RemoteWindowCleanup {
    target: RemoteViewportTarget,
    stop_submission: Option<u64>,
    revoke_submission: Option<u64>,
    stop_operation: Option<OperationId>,
    revoke_operation: Option<OperationId>,
    stop_status: Option<OperationStatus>,
    revoke_status: Option<OperationStatus>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoteViewportAction {
    None,
    Close,
    Retry,
}

pub struct DesktopApp {
    bridge: Bridge,
    directory: PathBuf,
    tokens: theme::Tokens,
    tray: Option<tray::Tray>,
    screen: Screen,
    workspace_attached: bool,
    english: bool,
    dark: bool,
    connected: bool,
    exiting: bool,
    hidden: bool,
    exit_confirmed: bool,
    generation: u64,
    credentials: Credentials,
    trust: TrustForm,
    sensitive: Option<SensitiveReply>,
    message: Option<String>,
    message_tone: MessageTone,
    pending_confirmation: Option<(String, Command)>,
    policy: Option<management::PolicyDraft>,
    service_panel: services::ServicePanel,
    device_name: String,
    registration_generation: Option<u64>,
    remote: remote::RemoteForm,
    file_panel: files::FilePanel,
    recovery_panel: files::recovery::RecoveryPanel,
    recovery_submission: Option<u64>,
    clipboard_panel: clipboard::ClipboardPanel,
    browser_data_panel: browser_data::BrowserDataPanel,
    network_panel: native_network::NativeNetworkPanel,
    network_submission: Option<u64>,
    privileged_panel: privileged_input::PrivilegedInputPanel,
    file_submission: Option<u64>,
    clipboard_submission: Option<u64>,
    browser_data_submission: Option<u64>,
    transfer_runtime: Option<String>,
    account_name: String,
    video_binding: Option<nestlink_app_ipc::NativeVideoBinding>,
    video_layout: Option<(u64, u32, u32)>,
    video_sequence: u64,
    video_texture: Option<egui::TextureHandle>,
    video_status: VideoStatus,
    video_observation: Option<VideoObservation>,
    native_control_enabled: bool,
    native_input_binding: Option<(u64, NativeInputBinding)>,
    native_pressed_keys: BTreeSet<u16>,
    native_pressed_buttons: BTreeSet<u8>,
    native_modifier_state: [bool; 4],
    native_ime_composing: bool,
    native_pointer_position: Option<(i32, i32)>,
    last_native_pointer_send: Option<std::time::Instant>,
    remote_viewport_open: bool,
    remote_tools_open: bool,
    remote_viewport_target: Option<RemoteViewportTarget>,
    remote_window_cleanup: Option<RemoteWindowCleanup>,
    remote_inspection_submission: Option<u64>,
    remote_inspection_completed: bool,
    remote_inspection_succeeded: bool,
    host_notice: host_notice::HostNoticeState,
    layout_diagnostics: layout_diagnostics::Recorder,
}
impl DesktopApp {
    pub fn new(
        creation: &eframe::CreationContext<'_>,
        directory: PathBuf,
        tokens: theme::Tokens,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        theme::apply(&creation.egui_ctx, &tokens, false);
        let message = if theme::fonts(&creation.egui_ctx)? {
            None
        } else {
            Some("请安装中文系统字体以显示全部文字 / Install a Chinese system font.".into())
        };
        let message_tone = if message.is_some() {
            MessageTone::Warning
        } else {
            MessageTone::Neutral
        };
        Ok(Self::from_parts(
            directory.clone(),
            tokens,
            Bridge::start(directory, creation.egui_ctx.clone()),
            tray::Tray::create(creation.egui_ctx.clone()).ok(),
            message,
            message_tone,
        ))
    }
    fn from_parts(
        directory: PathBuf,
        tokens: theme::Tokens,
        bridge: Bridge,
        tray: Option<tray::Tray>,
        message: Option<String>,
        message_tone: MessageTone,
    ) -> Self {
        Self {
            bridge,
            directory: directory.clone(),
            tokens,
            tray,
            screen: Screen::Server,
            workspace_attached: false,
            english: false,
            dark: false,
            connected: false,
            exiting: false,
            hidden: false,
            exit_confirmed: false,
            generation: 1,
            credentials: Credentials {
                remember_login: nestlink_platform_security::read_private(
                    &directory.join("remember-login.json"),
                    16,
                )
                .is_ok_and(|bytes| bytes.as_slice() == b"true"),
                ..Credentials::default()
            },
            trust: TrustForm::default(),
            sensitive: None,
            message,
            message_tone,
            pending_confirmation: None,
            policy: None,
            service_panel: services::ServicePanel::default(),
            device_name: String::new(),
            registration_generation: None,
            remote: remote::RemoteForm::default(),
            file_panel: files::FilePanel::default(),
            recovery_panel: files::recovery::RecoveryPanel::default(),
            recovery_submission: None,
            clipboard_panel: clipboard::ClipboardPanel::default(),
            browser_data_panel: browser_data::BrowserDataPanel::default(),
            network_panel: native_network::NativeNetworkPanel::default(),
            network_submission: None,
            privileged_panel: privileged_input::PrivilegedInputPanel::default(),
            file_submission: None,
            clipboard_submission: None,
            browser_data_submission: None,
            transfer_runtime: None,
            account_name: String::new(),
            video_binding: None,
            video_layout: None,
            video_sequence: 0,
            video_texture: None,
            video_status: VideoStatus::Idle,
            video_observation: None,
            native_control_enabled: false,
            native_input_binding: None,
            native_pressed_keys: BTreeSet::new(),
            native_pressed_buttons: BTreeSet::new(),
            native_modifier_state: [false; 4],
            native_ime_composing: false,
            native_pointer_position: None,
            last_native_pointer_send: None,
            remote_viewport_open: false,
            remote_tools_open: false,
            remote_viewport_target: None,
            remote_window_cleanup: None,
            remote_inspection_submission: None,
            remote_inspection_completed: false,
            remote_inspection_succeeded: false,
            host_notice: host_notice::HostNoticeState::default(),
            layout_diagnostics: layout_diagnostics::Recorder::default(),
        }
    }
    fn t(&self, zh: &'static str, en: &'static str) -> &'static str {
        if self.english { en } else { zh }
    }
    fn set_message(&mut self, message: String, tone: MessageTone) {
        self.message = Some(message);
        self.message_tone = tone;
    }
    fn send(&mut self, snapshot: &Snapshot, command: Command) -> bool {
        if !self.connected || !self.bridge.submit(snapshot.generation, command) {
            self.set_message(
                self.t(
                    "操作未送出，请检查守护进程连接或稍后再试。",
                    "The operation was not sent. Check the daemon connection or try again.",
                )
                .into(),
                MessageTone::Danger,
            );
            false
        } else {
            true
        }
    }
    fn action(&mut self, snapshot: &Snapshot, action: Action) {
        let _ = self.send(snapshot, Command::Submit { action });
    }
    fn load(&mut self, snapshot: &Snapshot, page: Page) {
        self.action(snapshot, Action::Load { page });
    }
    fn clear_private_view(&mut self, context: &egui::Context) {
        self.release_native_control();
        self.credentials.clear();
        self.sensitive.take();
        self.pending_confirmation.take();
        self.remote = remote::RemoteForm::default();
        self.remote_tools_open = false;
        self.service_panel = services::ServicePanel::default();
        self.file_panel.reconcile(None);
        self.recovery_panel.reconcile(None);
        self.recovery_submission = None;
        self.clipboard_panel.reconcile(None);
        self.browser_data_panel.disconnected();
        self.file_submission = None;
        self.clipboard_submission = None;
        self.browser_data_submission = None;
        self.policy = None;
        self.account_name.clear();
        self.clear_video();
        // Password edit state IDs rotate across generations. Discard the old
        // widget state as well as our owned zeroizing form values.
        widgets::clear_secret_widgets(context, self.generation);
    }
    fn clear_video(&mut self) {
        self.release_native_control();
        self.video_texture = None;
        self.video_binding = None;
        self.video_layout = None;
        self.video_sequence = 0;
        self.video_status = VideoStatus::Idle;
        self.video_observation = None;
    }
    fn release_native_control(&mut self) {
        if let Some((generation, binding)) = self.native_input_binding.take() {
            self.bridge.release_native_input(generation, binding);
        }
        self.native_control_enabled = false;
        self.native_pressed_keys.clear();
        self.native_pressed_buttons.clear();
        self.native_modifier_state = [false; 4];
        self.native_ime_composing = false;
        self.native_pointer_position = None;
        self.last_native_pointer_send = None;
    }

    fn queue_native_input(
        &mut self,
        generation: u64,
        binding: &NativeInputBinding,
        action: NativeInputAction,
    ) -> bool {
        if self
            .bridge
            .send_native_input(generation, binding.clone(), action)
        {
            true
        } else {
            self.release_native_control();
            self.set_message(
                self.t(
                    "输入事件队列已满，已释放远端按键。请重新启用控制。",
                    "The input queue is full. Remote keys were released; enable control again.",
                )
                .into(),
                MessageTone::Danger,
            );
            false
        }
    }

    fn release_native_inputs_for_text(
        &mut self,
        generation: u64,
        binding: &NativeInputBinding,
    ) -> bool {
        let keys = self.native_pressed_keys.iter().copied().collect::<Vec<_>>();
        for code in keys {
            if !self.queue_native_input(
                generation,
                binding,
                NativeInputAction::Key { code, down: false },
            ) {
                return false;
            }
            self.native_pressed_keys.remove(&code);
        }
        self.native_modifier_state = [false; 4];

        let buttons = self
            .native_pressed_buttons
            .iter()
            .copied()
            .collect::<Vec<_>>();
        if !buttons.is_empty() {
            let Some((x, y)) = self.native_pointer_position else {
                self.release_native_control();
                return false;
            };
            for button in buttons {
                if !self.queue_native_input(
                    generation,
                    binding,
                    NativeInputAction::Pointer {
                        button: Some(button),
                        down: false,
                        x,
                        y,
                    },
                ) {
                    return false;
                }
                self.native_pressed_buttons.remove(&button);
            }
        }
        true
    }

    fn queue_native_text(
        &mut self,
        generation: u64,
        binding: &NativeInputBinding,
        text: &str,
    ) -> bool {
        let Some(text) = native_input::clamp_text(text) else {
            return true;
        };
        self.release_native_inputs_for_text(generation, binding)
            && self.queue_native_input(generation, binding, NativeInputAction::Text(text))
    }

    fn update_native_modifiers(
        &mut self,
        generation: u64,
        binding: &NativeInputBinding,
        modifiers: egui::Modifiers,
    ) -> bool {
        const USAGES: [u16; 4] = [0xe0, 0xe1, 0xe2, 0xe3];
        for (index, pressed) in native_input::modifier_usages(modifiers)
            .into_iter()
            .enumerate()
        {
            if pressed != self.native_modifier_state[index] {
                self.native_modifier_state[index] = pressed;
                self.native_pressed_keys.insert(USAGES[index]);
                if !pressed {
                    self.native_pressed_keys.remove(&USAGES[index]);
                }
                if !self.queue_native_input(
                    generation,
                    binding,
                    NativeInputAction::Key {
                        code: USAGES[index],
                        down: pressed,
                    },
                ) {
                    return false;
                }
            }
        }
        true
    }

    fn video_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.add_space(16.);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            let connected = snapshot.native_session.data.as_ref().is_some_and(|session| {
                session.status == NativeSessionStatus::Connected
                    && self.remote_viewport_target.as_ref().is_some_and(|target| {
                        session.request_id == target.request_id
                            && session.connection_generation == target.connection_generation
                    })
            });
            let status = match (connected, self.video_status, self.video_texture.is_some()) {
                (false, _, _) => {
                    self.t("建立会话后将在此显示", "Start a session to view its screen")
                }
                (true, _, true) => self.t("正在接收画面", "Receiving video"),
                (true, VideoStatus::Connecting, _) => self.t("正在连接画面…", "Connecting screen…"),
                (true, VideoStatus::WaitingForFrame, _) => {
                    self.t("正在加载画面…", "Loading screen…")
                }
                (true, VideoStatus::Reconnecting, _) => self.t(
                    "画面暂时中断，正在恢复…",
                    "Screen interrupted; reconnecting…",
                ),
                (true, VideoStatus::Idle | VideoStatus::Streaming, _) => {
                    self.t("正在准备画面…", "Preparing video…")
                }
            };
            let runtime_id = self.bridge.runtime_id();
            let input = self.bridge.input_layout().filter(|input| {
                native_input_layout_is_current(
                    input,
                    snapshot,
                    runtime_id.as_deref(),
                    self.video_binding.as_ref(),
                    self.video_layout,
                )
            });
            if self.native_control_enabled
                && !input.as_ref().is_some_and(|input| {
                    self.native_input_binding.as_ref().is_some_and(
                        |(generation, binding)| {
                            *generation == input.ui_generation
                                && native_input_binding_matches(
                                    binding,
                                    &input.layout.binding,
                                )
                        },
                    )
                })
            {
                self.release_native_control();
            }
            let control_ready = input.is_some()
                && self.video_texture.is_some()
                && self.video_status == VideoStatus::Streaming;
            let control_was_enabled = self.native_control_enabled;
            let mut toggle_control = false;
            ui.horizontal_wrapped(|ui| {
                icons::badge(ui, icons::Icon::Keyboard, 28.);
                ui.label(egui::RichText::new(self.t("远程画面", "Remote screen")).strong());
                ui.small(status);
                if ui
                    .add_enabled(
                        control_ready || self.native_control_enabled,
                        egui::Button::new(if self.native_control_enabled {
                            self.t("停止控制", "Stop control")
                        } else {
                            self.t("启用键鼠控制", "Enable keyboard and mouse")
                        }),
                    )
                    .clicked()
                {
                    toggle_control = true;
                }
            });
            if toggle_control {
                if self.native_control_enabled {
                    self.release_native_control();
                } else if let Some(input) = &input {
                    self.native_control_enabled = true;
                    self.native_input_binding =
                        Some((input.ui_generation, input.layout.binding.clone()));
                }
            }
            if input.is_none() {
                ui.small(self.t(
                    "此会话未提供输入控制权限。",
                    "Input control is not authorized for this session.",
                ));
            } else if self.native_control_enabled {
                ui.small(self.t(
                    "点击画面后可使用本机键盘和鼠标；失去焦点时会释放按键。",
                    "Click the screen to use the local keyboard and mouse. Keys are released when focus is lost.",
                ));
            }
            let width = ui.available_width().max(1.);
            let height = (ui.available_height() - 12.).max(180.);
            let (rect, response) = ui.allocate_exact_size(
                egui::vec2(width, height),
                egui::Sense::click_and_drag(),
            );
            ui.painter().rect_filled(
                rect,
                self.tokens.shape.control,
                theme::color(&self.tokens.media.canvas),
            );
            let mut image_rect = None;
            if let (Some(texture), Some((_, image_width, image_height))) =
                (&self.video_texture, self.video_layout)
            {
                if image_width > 0 && image_height > 0 {
                    let image_size = egui::vec2(image_width as f32, image_height as f32);
                    let scale = (rect.width() / image_size.x).min(rect.height() / image_size.y);
                    let target_rect =
                        egui::Rect::from_center_size(rect.center(), image_size * scale);
                    ui.painter().image(
                        texture.id(),
                        target_rect,
                        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::Pos2::new(1., 1.)),
                    theme::color(&self.tokens.media.foreground),
                    );
                    image_rect = Some(target_rect);
                }
            } else {
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    status,
                    egui::FontId::proportional(self.tokens.typography.body),
                    theme::color(&self.tokens.media.foreground),
                );
            }
            if control_was_enabled && response.lost_focus() {
                self.release_native_control();
            }
            if response.clicked() && self.native_control_enabled {
                response.request_focus();
            }
            if self.native_control_enabled
                && let (Some(input), Some(image_rect), Some((generation, binding))) = (
                    input.as_ref(),
                    image_rect,
                    self.native_input_binding.as_ref(),
                )
                && generation == &input.ui_generation
                && native_input_binding_matches(binding, &input.layout.binding)
            {
                self.collect_native_input(
                    ui,
                    &response,
                    image_rect,
                    &input.layout,
                    *generation,
                    binding.clone(),
                );
            }
        });
    }

    fn collect_native_input(
        &mut self,
        ui: &mut egui::Ui,
        response: &egui::Response,
        image_rect: egui::Rect,
        layout: &NativeInputLayout,
        generation: u64,
        binding: NativeInputBinding,
    ) {
        let focused = response.has_focus();
        let events = ui.input(|input| input.events.clone());
        for (index, event) in events.iter().cloned().enumerate() {
            match event {
                egui::Event::MouseWheel { unit, delta, .. }
                    if self.native_control_enabled
                        && layout.scroll_supported
                        && response.hovered() =>
                {
                    let scale = match unit {
                        egui::MouseWheelUnit::Point => 3.0,
                        egui::MouseWheelUnit::Line => 120.0,
                        egui::MouseWheelUnit::Page => 1200.0,
                    };
                    let x = (-delta.x * scale).round().clamp(-12000.0, 12000.0) as i32;
                    let y = (delta.y * scale).round().clamp(-12000.0, 12000.0) as i32;
                    if (x != 0 || y != 0)
                        && !self.queue_native_input(
                            generation,
                            &binding,
                            NativeInputAction::Scroll { x, y },
                        )
                    {
                        return;
                    }
                }
                egui::Event::PointerMoved(position) if self.native_control_enabled => {
                    if let Some(point) =
                        native_input::pointer_to_logical(position, image_rect, layout)
                        && self.native_pointer_position != Some(point)
                        && self
                            .last_native_pointer_send
                            .is_none_or(|last| last.elapsed() >= Duration::from_millis(16))
                    {
                        self.native_pointer_position = Some(point);
                        self.last_native_pointer_send = Some(std::time::Instant::now());
                        if !self.queue_native_input(
                            generation,
                            &binding,
                            NativeInputAction::Pointer {
                                button: None,
                                down: false,
                                x: point.0,
                                y: point.1,
                            },
                        ) {
                            return;
                        }
                    }
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    modifiers,
                } if self.native_control_enabled => {
                    if !self.update_native_modifiers(generation, &binding, modifiers) {
                        return;
                    }
                    let usage = native_input::pointer_button(button);
                    let mapped_point = native_input::pointer_to_logical(pos, image_rect, layout);
                    let point = mapped_point.or(self.native_pointer_position);
                    let Some(point) = point else {
                        if !pressed && self.native_pressed_buttons.contains(&usage) {
                            self.release_native_control();
                            return;
                        }
                        continue;
                    };
                    if pressed {
                        if mapped_point.is_none() || !self.native_pressed_buttons.insert(usage) {
                            continue;
                        }
                    } else if !self.native_pressed_buttons.remove(&usage) {
                        continue;
                    }
                    self.native_pointer_position = Some(point);
                    if !self.queue_native_input(
                        generation,
                        &binding,
                        NativeInputAction::Pointer {
                            button: Some(usage),
                            down: pressed,
                            x: point.0,
                            y: point.1,
                        },
                    ) {
                        return;
                    }
                }
                egui::Event::Key {
                    key,
                    physical_key,
                    pressed,
                    repeat,
                    modifiers,
                } if self.native_control_enabled && focused => {
                    if self.native_ime_composing {
                        continue;
                    }
                    if !self.update_native_modifiers(generation, &binding, modifiers) {
                        return;
                    }
                    if native_input::key_produces_text(key)
                        && !native_input::has_shortcut_modifier(modifiers)
                    {
                        continue;
                    }
                    let Some(usage) = native_input::key_usage(physical_key.unwrap_or(key)) else {
                        continue;
                    };
                    if pressed {
                        if repeat || !self.native_pressed_keys.insert(usage) {
                            continue;
                        }
                    } else if !self.native_pressed_keys.remove(&usage) {
                        continue;
                    }
                    if !self.queue_native_input(
                        generation,
                        &binding,
                        NativeInputAction::Key {
                            code: usage,
                            down: pressed,
                        },
                    ) {
                        return;
                    }
                }
                egui::Event::Text(text) if self.native_control_enabled && focused => {
                    let from_shortcut = index
                        .checked_sub(1)
                        .and_then(|previous| events.get(previous))
                        .is_some_and(|previous| {
                            matches!(
                                previous,
                                egui::Event::Key {
                                    pressed: true,
                                    modifiers,
                                    ..
                                } if native_input::has_shortcut_modifier(*modifiers)
                            )
                        });
                    if self.native_ime_composing || from_shortcut {
                        continue;
                    }
                    if !self.queue_native_text(generation, &binding, &text) {
                        return;
                    }
                }
                egui::Event::Ime(egui::ImeEvent::Enabled)
                | egui::Event::Ime(egui::ImeEvent::Preedit(_)) => {
                    self.native_ime_composing = true;
                }
                egui::Event::Ime(egui::ImeEvent::Commit(text)) => {
                    self.native_ime_composing = true;
                    if self.native_control_enabled
                        && focused
                        && !self.queue_native_text(generation, &binding, &text)
                    {
                        return;
                    }
                }
                egui::Event::Ime(egui::ImeEvent::Disabled) => {
                    self.native_ime_composing = false;
                }
                egui::Event::PointerGone
                    if self.native_control_enabled
                        && (!self.native_pressed_keys.is_empty()
                            || !self.native_pressed_buttons.is_empty()) =>
                {
                    self.release_native_control();
                    return;
                }
                _ => {}
            }
        }
    }
    fn update_video(
        &mut self,
        context: &egui::Context,
        snapshot: &Snapshot,
        visible: bool,
        focused: bool,
    ) {
        let runtime_id = self.bridge.runtime_id();
        let session = snapshot.native_session.data.as_ref();
        let target_matches = self.remote_viewport_target.as_ref().is_some_and(|target| {
            session.is_some_and(|session| {
                session.request_id == target.request_id
                    && session.connection_generation == target.connection_generation
            })
        });
        let interested = self.connected
            && !self.exiting
            && self.remote_viewport_open
            && self.remote_window_cleanup.is_none()
            && visible
            && snapshot.authentication == Authentication::SignedIn
            && runtime_id.is_some()
            && target_matches
            && session.is_some_and(|session| session.status == NativeSessionStatus::Connected);
        self.bridge.set_video_interest(interested);
        self.bridge.set_input_interest(interested && focused);
        if !focused {
            self.release_native_control();
        }
        if !interested {
            self.release_native_control();
            self.clear_video();
            let _ = self.bridge.take_video_update();
            return;
        }
        if self.video_status == VideoStatus::Idle {
            self.video_status = VideoStatus::Connecting;
        }
        while let Some(update) = self.bridge.take_video_update() {
            match update {
                VideoUpdate::Connecting(binding) => {
                    if video_binding_is_current(&binding, snapshot, runtime_id.as_deref()) {
                        if self.video_binding.as_ref() != Some(&binding) {
                            self.clear_video();
                            self.video_binding = Some(binding);
                        }
                        self.video_status = VideoStatus::WaitingForFrame;
                    }
                }
                VideoUpdate::Message(nestlink_app_ipc::NativeVideoMessage::Layout(layout)) => {
                    let binding = &layout.binding;
                    if !video_layout_is_current(
                        binding,
                        snapshot,
                        runtime_id.as_deref(),
                        self.video_binding.as_ref(),
                        self.video_layout,
                        (layout.layout_epoch, layout.width, layout.height),
                    ) {
                        continue;
                    }
                    if self.video_binding.as_ref() != Some(binding) {
                        self.clear_video();
                        self.video_binding = Some(binding.clone());
                    }
                    let next = (layout.layout_epoch, layout.width, layout.height);
                    if self.video_layout.is_some_and(|current| current != next) {
                        self.release_native_control();
                        self.video_texture = None;
                        self.video_sequence = 0;
                    }
                    self.video_layout = Some(next);
                    self.video_status = VideoStatus::WaitingForFrame;
                }
                VideoUpdate::Message(nestlink_app_ipc::NativeVideoMessage::Frame(frame)) => {
                    let binding = &frame.binding;
                    if !video_frame_is_current(
                        &frame,
                        snapshot,
                        runtime_id.as_deref(),
                        self.video_binding.as_ref(),
                        self.video_layout,
                        self.video_sequence,
                    ) {
                        continue;
                    }
                    if self.video_binding.as_ref() != Some(binding) {
                        self.clear_video();
                        self.video_binding = Some(binding.clone());
                    }
                    let next = (frame.layout_epoch, frame.width, frame.height);
                    if self.video_layout.is_some_and(|current| current != next) {
                        self.release_native_control();
                        self.video_texture = None;
                        self.video_sequence = 0;
                    }
                    let Ok(width) = usize::try_from(frame.width) else {
                        continue;
                    };
                    let Ok(height) = usize::try_from(frame.height) else {
                        continue;
                    };
                    let Some(expected_bytes) = width
                        .checked_mul(height)
                        .and_then(|pixels| pixels.checked_mul(4))
                    else {
                        continue;
                    };
                    if width == 0 || height == 0 || frame.pixels.len() != expected_bytes {
                        continue;
                    }
                    let pixels = frame
                        .pixels
                        .chunks_exact(4)
                        .map(|bgra| {
                            egui::Color32::from_rgba_unmultiplied(
                                bgra[2], bgra[1], bgra[0], bgra[3],
                            )
                        })
                        .collect();
                    let image = egui::ColorImage::new([width, height], pixels);
                    if let Some(texture) = &mut self.video_texture {
                        texture.set(image, egui::TextureOptions::LINEAR);
                    } else {
                        self.video_texture = Some(context.load_texture(
                            "native-video",
                            image,
                            egui::TextureOptions::LINEAR,
                        ));
                    }
                    self.video_layout = Some(next);
                    self.video_sequence = frame.sequence;
                    self.video_status = VideoStatus::Streaming;
                    let now = std::time::Instant::now();
                    if self
                        .video_observation
                        .as_ref()
                        .is_none_or(|value| value.layout != next || value.codec != frame.codec)
                    {
                        self.video_observation = Some(VideoObservation {
                            codec: frame.codec,
                            hardware: frame.hardware_decode,
                            layout: next,
                            window: now,
                            frames: 0,
                            fps: None,
                            latest: now,
                        });
                    }
                    if let Some(value) = &mut self.video_observation {
                        value.hardware = frame.hardware_decode;
                        value.latest = now;
                        value.frames = value.frames.saturating_add(1);
                        let elapsed = now.duration_since(value.window).as_secs_f64();
                        if elapsed >= 1.0 {
                            value.fps = Some(f64::from(value.frames) / elapsed);
                            value.frames = 0;
                            value.window = now;
                        }
                    }
                }
                VideoUpdate::Message(nestlink_app_ipc::NativeVideoMessage::Closed(binding)) => {
                    if video_binding_is_current(&binding, snapshot, runtime_id.as_deref())
                        && self.video_binding.as_ref() == Some(&binding)
                    {
                        self.release_native_control();
                        self.video_texture = None;
                        self.video_layout = None;
                        self.video_sequence = 0;
                        self.video_status = VideoStatus::Reconnecting;
                    }
                }
                VideoUpdate::Disconnected(binding) => {
                    if binding.as_ref().is_none_or(|binding| {
                        video_binding_is_current(binding, snapshot, runtime_id.as_deref())
                            && self
                                .video_binding
                                .as_ref()
                                .is_none_or(|current| current == binding)
                    }) {
                        self.release_native_control();
                        self.video_texture = None;
                        self.video_layout = None;
                        self.video_sequence = 0;
                        if let Some(binding) = binding {
                            self.video_binding = Some(binding);
                        }
                        self.video_status = VideoStatus::Reconnecting;
                    }
                }
            }
        }
        if self.video_binding.as_ref().is_some_and(|binding| {
            !video_binding_is_current(binding, snapshot, runtime_id.as_deref())
        }) {
            self.clear_video();
            self.video_status = VideoStatus::Connecting;
        }
    }

    fn open_remote_viewport(&mut self, snapshot: &Snapshot, target: RemoteViewportTarget) {
        if self.remote_window_cleanup.is_some() {
            return;
        }
        self.remote_viewport_target = Some(target.clone());
        self.remote_window_cleanup = None;
        self.remote_viewport_open = true;
        self.clear_video();
        self.refresh_remote_request(snapshot, &target.request_id);
    }

    fn refresh_remote_request(&mut self, snapshot: &Snapshot, request_id: &str) {
        self.remote_inspection_submission = self.bridge.submit_tracked(
            snapshot.generation,
            Command::Submit {
                action: Action::InspectRemote {
                    request_id: request_id.to_owned(),
                },
            },
        );
        self.remote_inspection_completed = self.remote_inspection_submission.is_none();
        self.remote_inspection_succeeded = false;
        if self.remote_inspection_submission.is_none() {
            self.set_message(
                self.t(
                    "刷新访问状态未能排入守护进程队列。",
                    "Refreshing the access state could not be queued to the daemon.",
                )
                .into(),
                MessageTone::Danger,
            );
        }
    }

    fn show_remote_viewport(&mut self, context: &egui::Context, snapshot: &Snapshot) {
        if !self.remote_viewport_open {
            self.bridge.set_video_interest(false);
            self.bridge.set_input_interest(false);
            if self.native_control_enabled {
                self.release_native_control();
            }
            return;
        }

        let viewport_id = egui::ViewportId::from_hash_of("nestlink-remote-session");
        let builder = egui::ViewportBuilder::default()
            .with_title(self.t("NestLink 远程控制", "NestLink Remote Control"))
            .with_inner_size([1040., 760.])
            .with_min_inner_size([720., 520.]);
        let mut action = RemoteViewportAction::None;
        context.show_viewport_immediate(viewport_id, builder, |viewport, class| {
            if class == egui::ViewportClass::Immediate {
                if viewport.input(|input| input.viewport().close_requested()) {
                    viewport.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    action = RemoteViewportAction::Close;
                }
                let (visible, focused) = viewport.input(|input| {
                    let info = input.viewport();
                    (
                        info.visible().unwrap_or(true) && !info.minimized.unwrap_or(false),
                        input.focused,
                    )
                });
                self.update_video(viewport, snapshot, visible, focused);
                let mut viewport_ui = egui::Ui::new(
                    viewport.clone(),
                    egui::Id::new("nestlink-remote-session-ui"),
                    egui::UiBuilder::new()
                        .layer_id(egui::LayerId::background())
                        .max_rect(viewport.content_rect()),
                );
                viewport_ui.set_clip_rect(viewport.content_rect());
                egui::CentralPanel::default().show_inside(&mut viewport_ui, |ui| {
                    action = self.remote_viewport_contents(ui, snapshot);
                });
            } else {
                let mut open = self.remote_viewport_open;
                let (visible, focused) = viewport.input(|input| {
                    let info = input.viewport();
                    (
                        info.visible().unwrap_or(true) && !info.minimized.unwrap_or(false),
                        input.focused,
                    )
                });
                egui::Window::new(self.t("NestLink 远程控制", "NestLink Remote Control"))
                    .open(&mut open)
                    .default_size([1040., 760.])
                    .show(viewport, |ui| {
                        self.update_video(viewport, snapshot, visible, focused);
                        action = self.remote_viewport_contents(ui, snapshot);
                    });
                if !open {
                    action = RemoteViewportAction::Close;
                }
            }
        });

        match action {
            RemoteViewportAction::None => {}
            RemoteViewportAction::Close => self.begin_remote_viewport_close(snapshot),
            RemoteViewportAction::Retry => self.retry_remote_viewport_close(snapshot),
        }
    }

    fn remote_viewport_contents(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
    ) -> RemoteViewportAction {
        let fullscreen = ui.input(|input| input.viewport().fullscreen.unwrap_or(false));
        let mut fullscreen_change = ui.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::F11) {
                Some(!fullscreen)
            } else if fullscreen && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                Some(false)
            } else {
                None
            }
        });
        let target = self.remote_viewport_target.clone();
        let session = target.as_ref().and_then(|target| {
            snapshot.native_session.data.as_ref().filter(|session| {
                session.request_id == target.request_id
                    && session.connection_generation == target.connection_generation
            })
        });
        ui.horizontal_wrapped(|ui| {
            ui.heading(self.t("远程控制", "Remote control"));
            if icons::button(
                ui,
                icons::Icon::Settings,
                self.t("操作中心", "Control center"),
            )
            .clicked()
            {
                self.release_native_control();
                self.remote_tools_open = !self.remote_tools_open;
            }
            if ui
                .button(if fullscreen {
                    self.t("退出全屏 (Esc)", "Exit fullscreen (Esc)")
                } else {
                    self.t("全屏 (F11)", "Fullscreen (F11)")
                })
                .clicked()
            {
                fullscreen_change = Some(!fullscreen);
            }
            if let Some(target) = &target {
                let name = snapshot
                    .selected_request
                    .data
                    .as_ref()
                    .filter(|request| request.id == target.request_id)
                    .and_then(|request| {
                        snapshot
                            .devices
                            .data
                            .as_deref()?
                            .iter()
                            .find(|device| device.device.id == request.host_device_id)
                    })
                    .map(|device| device.device.name.as_str());
                if let Some(name) = name {
                    ui.strong(name);
                }
            }
            if let Some(session) = session {
                ui.label(match session.status {
                    NativeSessionStatus::Establishing => self.t("正在建立", "Establishing"),
                    NativeSessionStatus::Connected => self.t("已连接", "Connected"),
                    NativeSessionStatus::Stopping => self.t("正在停止", "Stopping"),
                    NativeSessionStatus::Stopped => self.t("已停止", "Stopped"),
                    NativeSessionStatus::Failed => self.t("会话失败", "Session failed"),
                });
            } else {
                ui.label(self.t("会话状态不可用", "Session state unavailable"));
            }
        });
        if let Some(fullscreen) = fullscreen_change {
            // Release held remote inputs before changing local window state.
            self.release_native_control();
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(fullscreen));
        }
        ui.separator();

        let mut action = RemoteViewportAction::None;
        if let Some(cleanup) = &self.remote_window_cleanup {
            ui.horizontal(|ui| {
                if cleanup.error.is_some() {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        self.t("清理未确认完成", "Cleanup is not confirmed"),
                    );
                } else {
                    ui.spinner();
                    ui.label(self.t(
                        "正在撤销访问并确认本地会话清理…",
                        "Revoking access and confirming local session cleanup…",
                    ));
                }
                if ui
                    .add_enabled(
                        cleanup.error.is_some() && self.connected,
                        egui::Button::new(self.t("重试清理", "Retry cleanup")),
                    )
                    .clicked()
                {
                    action = RemoteViewportAction::Retry;
                }
            });
            ui.small(format!(
                "{} · {}",
                self.t("本地会话", "Local session"),
                cleanup_phase(cleanup.stop_status, self.english)
            ));
            ui.small(format!(
                "{} · {}",
                self.t("访问撤销", "Access revocation"),
                cleanup_phase(cleanup.revoke_status, self.english)
            ));
            if let Some(error) = &cleanup.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
        } else if ui
            .button(self.t("结束会话并关闭窗口", "End session and close window"))
            .clicked()
        {
            action = RemoteViewportAction::Close;
        }

        ui.add_space(10.);
        if self.remote_tools_open && self.remote_window_cleanup.is_none() {
            let tools_width = (ui.available_width() * 0.38).clamp(260., 360.);
            egui::Panel::right("remote-session-tools")
                .exact_size(tools_width)
                .resizable(false)
                .show_inside(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("remote-tools-scroll")
                        .show(ui, |ui| {
                            ui.heading(self.t("操作中心", "Control center"));
                            if let Some(observed) = &self.video_observation {
                                ui.strong(self.t("连接与性能", "Connection and performance"));
                                ui.label(format!("{}: {}", self.t("实际编码", "Actual codec"), if observed.codec == 1 { "H.264 Baseline" } else { "VP8" }));
                                ui.label(format!("{}: {}", self.t("实际解码", "Actual decoder"), if observed.hardware { self.t("硬件", "Hardware") } else { self.t("软件", "Software") }));
                                let fps = observed.fps.filter(|_| observed.latest.elapsed() < Duration::from_secs(2))
                                    .map(|fps| format!("{fps:.1} fps")).unwrap_or_else(|| self.t("未观测", "Not observed").into());
                                ui.label(format!("{}: {fps}", self.t("画面上传帧率", "Texture upload rate")));
                                ui.label(format!("{} × {}", observed.layout.1, observed.layout.2));
                                ui.small(self.t("解码后经 CPU 像素上传呈现；此帧率不代表端到端输入时延。", "Decoded CPU pixels are uploaded for display. This rate does not measure input-to-picture latency."));
                                if ui.button(self.t("复制脱敏诊断", "Copy redacted diagnostics")).clicked() {
                                    let report = serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "codec": if observed.codec == 1 {"h264-baseline"} else {"vp8"}, "hardware_decode_observed": observed.hardware,
                                        "texture_upload_fps": observed.fps.filter(|_| observed.latest.elapsed() < Duration::from_secs(2)), "sample_age_ms": observed.latest.elapsed().as_millis(), "width": observed.layout.1, "height": observed.layout.2,
                                        "presentation": "cpu-bgra-texture-upload", "network_rtt_ms": null, "end_to_end_latency_ms": null});
                                    if let Ok(text) = serde_json::to_string_pretty(&report) { ui.ctx().copy_text(text); }
                                }
                                ui.separator();
                            }
                            ui.add_space(10.);
                            ui.horizontal(|ui| {
                                icons::badge(ui, icons::Icon::Monitor, 28.);
                                ui.strong(self.t("显示器", "Displays"));
                            });
                            self.native_display_panel(ui, snapshot);
                            ui.separator();
                            if let Some(request) =
                                snapshot.selected_request.data.as_ref().filter(|request| {
                                    target
                                        .as_ref()
                                        .is_some_and(|target| target.request_id == request.id)
                                })
                            {
                                ui.horizontal_wrapped(|ui| {
                                    icons::badge(ui, icons::Icon::Audio, 28.);
                                    ui.strong(self.t("音频", "Audio"));
                                    ui.label(
                                        if request.permissions.contains(
                                            &(nestlink_protocol::Permission::Audio as i32),
                                        ) {
                                            self.t(
                                                "已授权 · 使用本机系统音频设备",
                                                "Authorized · uses local system audio devices",
                                            )
                                        } else {
                                            self.t(
                                                "未授权，重新申请时可选择音频",
                                                "Not authorized; request Audio for a new session",
                                            )
                                        },
                                    );
                                });
                            }
                            self.transfer_panels(ui, snapshot);
                        });
                });
        }
        self.video_panel(ui, snapshot);
        action
    }

    fn begin_remote_viewport_close(&mut self, snapshot: &Snapshot) {
        if self.remote_window_cleanup.is_some() {
            return;
        }
        self.release_native_control();
        let Some(target) = self.remote_viewport_target.clone() else {
            self.remote_viewport_open = false;
            self.bridge.set_video_interest(false);
            self.bridge.set_input_interest(false);
            return;
        };
        let mut cleanup = RemoteWindowCleanup {
            target,
            stop_submission: None,
            revoke_submission: None,
            stop_operation: None,
            revoke_operation: None,
            stop_status: None,
            revoke_status: None,
            error: None,
        };
        if !self.connected {
            cleanup.error = Some(self.t(
                "守护进程已断开，无法确认会话清理或撤销结果。",
                "The daemon is disconnected; session cleanup and revocation cannot be confirmed.",
            ).into());
        } else {
            self.submit_close_stop(snapshot, &mut cleanup);
            if self.remote_inspection_completed {
                if self.remote_inspection_succeeded {
                    self.submit_close_revoke(snapshot, &mut cleanup);
                } else {
                    cleanup.error = Some(self.t(
                        "访问状态刷新失败，无法安全确认是否需要撤销。",
                        "The access state could not be refreshed, so revocation cannot be safely confirmed.",
                    ).into());
                }
            }
        }
        self.remote_window_cleanup = Some(cleanup);
        self.bridge.set_video_interest(false);
        self.bridge.set_input_interest(false);
    }

    fn submit_close_stop(&self, snapshot: &Snapshot, cleanup: &mut RemoteWindowCleanup) {
        let session = snapshot.native_session.data.as_ref().filter(|session| {
            session.request_id == cleanup.target.request_id
                && session.connection_generation == cleanup.target.connection_generation
        });
        match session.map(|session| session.status) {
            Some(NativeSessionStatus::Stopped | NativeSessionStatus::Failed)
                if session.is_some_and(|session| session_cleanup_succeeded(session)) =>
            {
                cleanup.stop_status = Some(OperationStatus::Succeeded);
            }
            Some(
                NativeSessionStatus::Establishing
                | NativeSessionStatus::Connected
                | NativeSessionStatus::Stopped
                | NativeSessionStatus::Failed,
            ) => {
                cleanup.stop_submission = self.bridge.submit_tracked(
                    snapshot.generation,
                    Command::Submit {
                        action: Action::StopNativeSession {
                            request_id: cleanup.target.request_id.clone(),
                            connection_generation: cleanup.target.connection_generation,
                        },
                    },
                );
                if cleanup.stop_submission.is_none() {
                    cleanup.error = Some(
                        self.t(
                            "停止会话操作未能排入守护进程队列。",
                            "The session stop could not be queued to the daemon.",
                        )
                        .into(),
                    );
                }
            }
            Some(NativeSessionStatus::Stopping) => {
                cleanup.stop_status = Some(OperationStatus::Succeeded);
            }
            None => {
                cleanup.error = Some(self.t(
                    "找不到此窗口对应的本机会话，无法确认本地清理。",
                    "The session for this window is missing, so local cleanup cannot be confirmed.",
                ).into());
            }
        }
    }

    fn submit_close_revoke(&self, snapshot: &Snapshot, cleanup: &mut RemoteWindowCleanup) {
        if remote_request_is_terminal(snapshot, &cleanup.target.request_id) {
            cleanup.revoke_status = Some(OperationStatus::Succeeded);
            return;
        }
        cleanup.revoke_submission = self.bridge.submit_tracked(
            snapshot.generation,
            Command::Submit {
                action: Action::RevokeRemote {
                    request_id: cleanup.target.request_id.clone(),
                },
            },
        );
        if cleanup.revoke_submission.is_none() {
            cleanup.error = Some(
                self.t(
                    "撤销访问操作未能排入守护进程队列。",
                    "The access revocation could not be queued to the daemon.",
                )
                .into(),
            );
        }
    }

    fn retry_remote_viewport_close(&mut self, snapshot: &Snapshot) {
        let Some(mut cleanup) = self.remote_window_cleanup.take() else {
            self.begin_remote_viewport_close(snapshot);
            return;
        };
        cleanup.error = None;
        cleanup.stop_submission = None;
        cleanup.revoke_submission = None;
        cleanup.stop_operation = None;
        cleanup.revoke_operation = None;
        cleanup.revoke_status = None;
        if !self.connected {
            cleanup.error = Some(
                self.t(
                    "守护进程已断开，无法重试清理。",
                    "The daemon is disconnected; cleanup cannot be retried.",
                )
                .into(),
            );
        } else {
            let request_id = cleanup.target.request_id.clone();
            self.refresh_remote_request(snapshot, &request_id);
            if self.remote_inspection_completed && !self.remote_inspection_succeeded {
                cleanup.error = Some(
                    self.t(
                        "访问状态刷新未能排入守护进程队列。",
                        "Refreshing the access state could not be queued to the daemon.",
                    )
                    .into(),
                );
            }
            if cleanup.stop_status != Some(OperationStatus::Succeeded)
                || snapshot
                    .native_session
                    .data
                    .as_ref()
                    .is_some_and(|session| {
                        session.request_id == cleanup.target.request_id
                            && session.connection_generation == cleanup.target.connection_generation
                            && !session_cleanup_succeeded(session)
                    })
            {
                self.submit_close_stop(snapshot, &mut cleanup);
            }
        }
        self.remote_window_cleanup = Some(cleanup);
    }

    fn update_remote_viewport_cleanup(&mut self, snapshot: &Snapshot, context: &egui::Context) {
        let english = self.english;
        let inspection_completed = self.remote_inspection_completed;
        let inspection_succeeded = self.remote_inspection_succeeded;
        let should_close = {
            let Some(cleanup) = self.remote_window_cleanup.as_mut() else {
                return;
            };
            if cleanup.revoke_submission.is_none() && cleanup.revoke_status.is_none() {
                if inspection_completed && inspection_succeeded {
                    if remote_request_is_terminal(snapshot, &cleanup.target.request_id) {
                        cleanup.revoke_status = Some(OperationStatus::Succeeded);
                    } else {
                        cleanup.revoke_submission = self.bridge.submit_tracked(
                            snapshot.generation,
                            Command::Submit {
                                action: Action::RevokeRemote {
                                    request_id: cleanup.target.request_id.clone(),
                                },
                            },
                        );
                        if cleanup.revoke_submission.is_none() {
                            cleanup.error = Some(if english {
                                "The access revocation could not be queued to the daemon.".into()
                            } else {
                                "撤销访问操作未能排入守护进程队列。".into()
                            });
                        }
                    }
                } else if inspection_completed {
                    cleanup.error.get_or_insert_with(|| {
                        if english {
                            "The access state could not be refreshed, so revocation cannot be safely confirmed.".into()
                        } else {
                            "访问状态刷新失败，无法安全确认是否需要撤销。".into()
                        }
                    });
                }
            }
            if let Some(status) = cleanup
                .stop_operation
                .and_then(|operation| snapshot_operation_status(snapshot, operation))
            {
                cleanup.stop_status = Some(status);
                if status != OperationStatus::Succeeded {
                    cleanup.error.get_or_insert_with(|| {
                        if english {
                            "The daemon reported that stopping the local session did not succeed."
                                .into()
                        } else {
                            "守护进程报告本地停止会话操作未成功。".into()
                        }
                    });
                }
            }
            if let Some(status) = cleanup
                .revoke_operation
                .and_then(|operation| snapshot_operation_status(snapshot, operation))
            {
                cleanup.revoke_status = Some(status);
                if status != OperationStatus::Succeeded {
                    cleanup.error.get_or_insert_with(|| {
                        if english {
                            "The daemon reported that access revocation did not succeed.".into()
                        } else {
                            "守护进程报告访问撤销操作未成功。".into()
                        }
                    });
                }
            }
            let session = snapshot.native_session.data.as_ref().filter(|session| {
                session.request_id == cleanup.target.request_id
                    && session.connection_generation == cleanup.target.connection_generation
            });
            if session.is_none() {
                cleanup.error.get_or_insert_with(|| {
                    if english {
                        "The session record for this window disappeared before cleanup could be confirmed.".into()
                    } else {
                        "此窗口对应的会话记录已消失，清理结果无法确认。".into()
                    }
                });
            }
            if let Some(session) = session
                && matches!(
                    session.status,
                    NativeSessionStatus::Stopped | NativeSessionStatus::Failed
                )
                && !session_cleanup_succeeded(session)
            {
                cleanup.stop_status = Some(OperationStatus::Failed);
                cleanup.error.get_or_insert_with(|| {
                    if english {
                        "The local session ended, but the daemon did not confirm successful resource cleanup.".into()
                    } else {
                        "本机会话已结束，但守护进程未确认资源清理成功。".into()
                    }
                });
            }
            let session_confirmed =
                session.is_some_and(|session| session_cleanup_succeeded(session));
            let request_confirmed =
                remote_request_is_terminal(snapshot, &cleanup.target.request_id);
            session_confirmed
                && request_confirmed
                && cleanup.stop_status == Some(OperationStatus::Succeeded)
                && cleanup.revoke_status == Some(OperationStatus::Succeeded)
        };
        if should_close {
            self.remote_window_cleanup = None;
            self.remote_viewport_target = None;
            self.remote_viewport_open = false;
            self.clear_video();
            self.bridge.set_video_interest(false);
            self.bridge.set_input_interest(false);
            context.send_viewport_cmd_to(
                egui::ViewportId::from_hash_of("nestlink-remote-session"),
                egui::ViewportCommand::Close,
            );
        }
    }

    fn notices(&mut self, context: &egui::Context) -> std::sync::Arc<Snapshot> {
        // Read the view after draining notices, so a new response delivered
        // between the two operations cannot be compared with an older view.
        let notices: Vec<_> = self.bridge.drain().collect();
        let snapshot = self.bridge.snapshot();
        self.privileged_panel
            .reconcile(self.bridge.runtime_id().as_deref(), snapshot.generation);
        if self.generation != snapshot.generation {
            self.clear_private_view(context);
            self.generation = snapshot.generation;
        }
        let connected_browser_host = snapshot.browser_host.data.as_ref().filter(|host| {
            host.status == BrowserHostStatus::Connected
                && host.host_view_authorized
                && host.binding.is_some()
        });
        let browser_data_binding = connected_browser_host.and_then(|host| host.binding.clone());
        let browser_data_view = connected_browser_host.map(|host| &host.data);
        if self.browser_data_panel.reconcile(
            browser_data_binding,
            snapshot.generation,
            browser_data_view,
        ) {
            self.browser_data_submission = None;
        }
        self.reconcile_transfer_panels(&snapshot);
        for notice in notices {
            match notice {
                Notice::PrivilegedInput {
                    submission_id,
                    runtime_id,
                    generation,
                    result,
                } => {
                    self.privileged_panel
                        .complete(submission_id, &runtime_id, generation, result);
                }
                Notice::NativeNetworkConfigured {
                    submission_id,
                    runtime_id,
                    result,
                } => {
                    if submission_id.is_some()
                        && submission_id == self.network_submission
                        && self.bridge.runtime_id().as_deref() == Some(runtime_id.as_str())
                    {
                        self.network_submission = None;
                        self.network_panel.complete(result);
                    }
                }
                Notice::NativeDownloadRecovery {
                    submission_id,
                    runtime_id,
                    generation,
                    result,
                } => {
                    if submission_id.is_some()
                        && submission_id == self.recovery_submission
                        && self.bridge.runtime_id().as_deref() == Some(runtime_id.as_str())
                        && snapshot.generation == generation
                    {
                        self.recovery_submission = None;
                        if let Some(task_id) = self.recovery_panel.apply(result) {
                            self.file_panel.track_recovered(task_id);
                        }
                    }
                }
                Notice::NativeFiles {
                    submission_id,
                    runtime_id,
                    binding,
                    generation,
                    result,
                } => {
                    if submission_id.is_some()
                        && submission_id == self.file_submission
                        && self.transfer_runtime.as_deref() == Some(runtime_id.as_str())
                    {
                        self.file_submission = None;
                        self.file_panel.apply(generation, &binding, result);
                    }
                }
                Notice::BrowserHostData {
                    submission_id,
                    binding,
                    generation,
                    result,
                } => {
                    if let Some(submission_id) = submission_id
                        && Some(submission_id) == self.browser_data_submission
                        && self.browser_data_panel.apply_reply(
                            &binding,
                            generation,
                            submission_id,
                            result,
                        )
                    {
                        self.browser_data_submission = None;
                    }
                }
                Notice::LocalServiceHostPreview {
                    submission_id,
                    preview,
                } => {
                    self.service_panel
                        .preview_reply(submission_id, preview, self.english);
                }
                Notice::LocalServiceHostStopped {
                    submission_id,
                    accepted,
                } => {
                    self.service_panel
                        .stop_reply(submission_id, accepted, self.english);
                }
                Notice::NativeClipboard {
                    submission_id,
                    generation,
                    result,
                } => {
                    if submission_id.is_some() && submission_id == self.clipboard_submission {
                        self.clipboard_submission = None;
                        self.clipboard_panel.apply_reply(generation, result);
                    }
                }
                Notice::Connected => {
                    self.connected = true;
                }
                Notice::Accepted {
                    submission_id,
                    operation_id,
                } => {
                    if let Some(cleanup) = &mut self.remote_window_cleanup {
                        if cleanup.stop_submission == Some(submission_id) {
                            cleanup.stop_operation = Some(operation_id);
                        } else if cleanup.revoke_submission == Some(submission_id) {
                            cleanup.revoke_operation = Some(operation_id);
                        }
                    }
                }
                Notice::Disconnected => {
                    self.privileged_panel.disconnected();
                    self.network_submission = None;
                    self.network_panel
                        .complete(Err(nestlink_app_core::NativeNetworkError::Unavailable));
                    self.recovery_submission = None;
                    self.recovery_panel.disconnected();
                    self.file_panel.disconnected();
                    self.clipboard_panel.disconnected();
                    self.browser_data_panel.disconnected();
                    self.service_panel.disconnected(self.english);
                    self.file_submission = None;
                    self.clipboard_submission = None;
                    self.browser_data_submission = None;
                    self.connected = false;
                    self.exiting = false;
                    self.clear_private_view(context);
                    self.remote_inspection_submission = None;
                    self.remote_inspection_completed = true;
                    self.remote_inspection_succeeded = false;
                    let cleanup_error = self.t(
                        "守护进程连接中断，操作结果无法确认。",
                        "The daemon connection was lost, so operation results are unknown.",
                    );
                    if let Some(cleanup) = &mut self.remote_window_cleanup {
                        cleanup.error = Some(cleanup_error.into());
                        cleanup.stop_submission = None;
                        cleanup.revoke_submission = None;
                        cleanup.stop_operation = None;
                        cleanup.revoke_operation = None;
                        if cleanup.stop_status != Some(OperationStatus::Succeeded) {
                            cleanup.stop_status = Some(OperationStatus::Failed);
                        }
                        if cleanup.revoke_status != Some(OperationStatus::Succeeded) {
                            cleanup.revoke_status = Some(OperationStatus::Failed);
                        }
                    }
                    self.set_message(self.t("与本用户守护进程的连接已断开。操作结果可能已提交，重连后请刷新查看。", "The user daemon disconnected. An operation may have committed; reconnect and refresh its state.").into(), MessageTone::Danger);
                    tray::restore(context);
                }
                Notice::Rejected {
                    submission_id,
                    reason,
                } => {
                    self.privileged_panel.rejected(submission_id);
                    if submission_id.is_some() && submission_id == self.network_submission {
                        self.network_submission = None;
                        self.network_panel.complete(Err(match reason {
                            nestlink_app_ipc::wire::Rejection::StaleGeneration => {
                                nestlink_app_core::NativeNetworkError::StaleGeneration
                            }
                            nestlink_app_ipc::wire::Rejection::Stopped => {
                                nestlink_app_core::NativeNetworkError::Stopped
                            }
                            _ => nestlink_app_core::NativeNetworkError::Unavailable,
                        }));
                    }
                    if let Some(submission_id) = submission_id {
                        self.service_panel.rejected(submission_id, self.english);
                    }
                    if submission_id.is_some() && submission_id == self.recovery_submission {
                        self.recovery_submission = None;
                        self.recovery_panel.disconnected();
                    }
                    if submission_id.is_some() && submission_id == self.file_submission {
                        self.file_submission = None;
                        self.file_panel.disconnected();
                    }
                    if submission_id.is_some() && submission_id == self.clipboard_submission {
                        self.clipboard_submission = None;
                        self.clipboard_panel.disconnected();
                    }
                    if let Some(id) = submission_id
                        && Some(id) == self.browser_data_submission
                    {
                        self.browser_data_submission = None;
                        self.browser_data_panel
                            .rejected(id, widgets::rejection(reason, self.english));
                    }
                    self.exiting = false;
                    let message = widgets::rejection(reason, self.english).to_owned();
                    self.remote_flow_rejected(submission_id, &message);
                    if let Some(submission_id) = submission_id
                        && self.remote_inspection_submission == Some(submission_id)
                    {
                        self.remote_inspection_submission = None;
                        self.remote_inspection_completed = true;
                        self.remote_inspection_succeeded = false;
                    }
                    if let Some(submission_id) = submission_id
                        && let Some(cleanup) = &mut self.remote_window_cleanup
                        && (cleanup.stop_submission == Some(submission_id)
                            || cleanup.revoke_submission == Some(submission_id))
                    {
                        cleanup.error = Some(message.clone());
                        if cleanup.stop_submission == Some(submission_id) {
                            cleanup.stop_status = Some(OperationStatus::Failed);
                        }
                        if cleanup.revoke_submission == Some(submission_id) {
                            cleanup.revoke_status = Some(OperationStatus::Failed);
                        }
                    }
                    self.set_message(message, MessageTone::Danger);
                }
                Notice::Exited(result) => {
                    self.exiting = false;
                    if result == ExitResult::Complete {
                        self.exit_confirmed = true;
                        self.clear_private_view(context);
                        context.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else {
                        tray::restore(context);
                        self.set_message(self.t("退出清理尚未确认完成。窗口保持可见，可再次检查退出。", "Shutdown cleanup is not confirmed. The window stays visible; you can check exit again.").into(), MessageTone::Danger);
                    }
                }
                Notice::Completed {
                    submission_id,
                    result,
                    sensitive,
                } => {
                    let operation_message = widgets::operation_message(&result, self.english);
                    if let Some(submission_id) = submission_id
                        && self.remote_inspection_submission == Some(submission_id)
                    {
                        self.remote_inspection_submission = None;
                        self.remote_inspection_completed = true;
                        self.remote_inspection_succeeded = result.status
                            == OperationStatus::Succeeded
                            && result.generation == snapshot.generation;
                    }
                    if let Some(submission_id) = submission_id
                        && let Some(cleanup) = &mut self.remote_window_cleanup
                    {
                        if cleanup.stop_submission == Some(submission_id) {
                            cleanup.stop_operation = Some(result.id);
                            cleanup.stop_status = Some(result.status);
                            if result.status != OperationStatus::Succeeded {
                                cleanup.error = Some(operation_message.clone());
                            }
                        } else if cleanup.revoke_submission == Some(submission_id) {
                            cleanup.revoke_operation = Some(result.id);
                            cleanup.revoke_status = Some(result.status);
                            if result.status != OperationStatus::Succeeded {
                                cleanup.error = Some(operation_message.clone());
                            }
                        }
                    }
                    if result.generation != snapshot.generation {
                        continue;
                    }
                    let flow_notice = self.remote_flow_completed(submission_id, &result);
                    if let Some(sensitive) = sensitive {
                        self.sensitive = Some(sensitive);
                        self.screen = Screen::Security;
                    }
                    let tone = match result.status {
                        OperationStatus::Succeeded => MessageTone::Success,
                        OperationStatus::Queued
                        | OperationStatus::Running
                        | OperationStatus::Cancelling => MessageTone::Warning,
                        OperationStatus::Failed
                        | OperationStatus::Cancelled
                        | OperationStatus::Superseded => MessageTone::Danger,
                    };
                    let enrolled_automatically = result.kind == OperationKind::EnrollDevice
                        && result.status == OperationStatus::Succeeded
                        && self.screen == Screen::Remote
                        && self.registration_generation == Some(result.generation);
                    if !flow_notice && result.kind != OperationKind::Load && !enrolled_automatically
                    {
                        self.set_message(operation_message, tone);
                    }
                    if result.status == OperationStatus::Succeeded
                        && result.kind == OperationKind::SignIn
                    {
                        self.load(&snapshot, Page::Devices);
                        self.load(&snapshot, Page::Requests);
                    }
                    if let nestlink_app_core::PublicOutput::Created { id } = result.output
                        && result.kind == OperationKind::RequestRemote
                    {
                        self.remote.selected = Some(id);
                    }
                }
            }
        }
        if self.connected
            && !self.workspace_attached
            && snapshot.authentication == Authentication::SignedIn
        {
            self.workspace_attached = true;
            self.screen = Screen::Remote;
        }
        self.poll_transfer_panels(&snapshot);
        snapshot
    }
    fn exit(&mut self, snapshot: &Snapshot, context: &egui::Context) {
        if self.connected && !self.exiting {
            self.remote_window_cleanup = None;
            self.remote_viewport_target = None;
            self.remote_viewport_open = false;
            context.send_viewport_cmd_to(
                egui::ViewportId::from_hash_of("nestlink-remote-session"),
                egui::ViewportCommand::Close,
            );
            self.clear_private_view(context);
            self.exiting = self.send(snapshot, Command::Exit);
            self.hidden = false;
            tray::restore(context);
        }
    }
    fn confirmations(&mut self, context: &egui::Context, snapshot: &Snapshot) {
        if self.pending_confirmation.is_none() {
            return;
        }
        let mut approved = false;
        let mut cancelled = false;
        egui::Modal::new(egui::Id::new("confirm-action")).show(context, |ui| {
            ui.set_width(420.);
            ui.heading(self.t("确认操作", "Confirm action"));
            if let Some((message, _)) = &self.pending_confirmation {
                ui.label(message);
            }
            ui.horizontal(|ui| {
                approved = ui.button(self.t("确认", "Confirm")).clicked();
                cancelled = ui.button(self.t("取消", "Cancel")).clicked();
            });
        });
        if approved {
            if let Some((_, command)) = self.pending_confirmation.take() {
                self.send(snapshot, command);
            }
        } else if cancelled || context.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.pending_confirmation.take();
        }
    }
}
impl eframe::App for DesktopApp {
    fn logic(&mut self, context: &egui::Context, frame: &mut eframe::Frame) {
        if nestlink_local_ipc::maintenance::DesktopInstance::take_activation(&self.directory) {
            self.hidden = false;
            tray::restore(context);
        }
        // An exclusive maintenance owner already fences new starts and will
        // request Exit from the exact authenticated daemon. Close every UI and
        // its owned workers without submitting a duplicate remote operation.
        if nestlink_local_ipc::maintenance::requested(&self.directory).unwrap_or(true) {
            self.clear_private_view(context);
            self.exit_confirmed = true;
            self.hidden = false;
            context.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let snapshot = self.notices(context);
        self.reconcile_remote_password_context(&snapshot);
        self.advance_local_enrollment(&snapshot);
        self.advance_remote_flow(&snapshot);
        self.update_host_notice(context, frame, &snapshot);
        if let Some(tray) = &self.tray {
            let actions = tray.actions();
            for action in actions {
                match action {
                    tray::TrayAction::Open => {
                        self.hidden = false;
                        tray::restore(context);
                    }
                    tray::TrayAction::Exit => self.exit(&snapshot, context),
                }
            }
        }
        if self.hidden && !self.tray.as_ref().is_some_and(tray::Tray::available) {
            self.hidden = false;
            tray::restore(context);
            self.set_message(
                self.t(
                    "托盘入口暂时不可用，已恢复窗口。",
                    "The tray is temporarily unavailable; the window was restored.",
                )
                .into(),
                MessageTone::Warning,
            );
        }
        if context.input(|input| input.viewport().close_requested()) && !self.exit_confirmed {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if self.tray.as_ref().is_some_and(tray::Tray::available) && !self.exiting {
                context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.hidden = true;
            } else {
                tray::restore(context);
                self.set_message(self.t("托盘入口不可用，窗口保持可见。请使用“退出程序”结束运行。", "The tray is unavailable, so the window stays visible. Use Exit program to stop.").into(), MessageTone::Warning);
            }
        }
        self.update_remote_viewport_cleanup(&snapshot, context);
        // Hidden windows still need to collect tray actions and cleanup replies.
        context.request_repaint_after(Duration::from_millis(250));
    }
    fn ui(&mut self, parent: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = parent.ctx().clone();
        let snapshot = self.bridge.snapshot();
        self.layout_diagnostics
            .begin_frame(snapshot.revision, self.remote.browser_host_details);
        if self.generation != snapshot.generation {
            self.clear_private_view(&context);
            self.generation = snapshot.generation;
        }
        parent.painter().rect_filled(
            parent.max_rect(),
            0.,
            context.global_style().visuals.panel_fill,
        );
        self.show_remote_viewport(&context, &snapshot);
        self.navigation(&context, parent, &snapshot);
        self.workspace_toolbar(parent, &snapshot);
        egui::Panel::bottom("operation-notification")
            .exact_size(60.)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(12, 8)))
            .show_inside(parent, |ui| {
                if let Some(message) = self.message.clone() {
                    let message_color = match self.message_tone {
                        MessageTone::Neutral => None,
                        MessageTone::Warning => {
                            let pair = &self.tokens.state.warning;
                            Some(theme::color(if self.dark {
                                &pair.dark
                            } else {
                                &pair.light
                            }))
                        }
                        MessageTone::Success => {
                            let pair = &self.tokens.state.success;
                            Some(theme::color(if self.dark {
                                &pair.dark
                            } else {
                                &pair.light
                            }))
                        }
                        MessageTone::Danger => {
                            let palette = if self.dark {
                                &self.tokens.dark
                            } else {
                                &self.tokens.light
                            };
                            Some(theme::color(&palette.danger))
                        }
                    };
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 86.).max(0.);
                        ui.allocate_ui_with_layout(
                            egui::vec2(width, 44.),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                ui.set_width(width);
                                egui::ScrollArea::vertical()
                                    .id_salt("operation-message-text")
                                    .max_height(44.)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        if let Some(color) = message_color {
                                            ui.colored_label(color, message);
                                        } else {
                                            ui.label(message);
                                        }
                                    });
                            },
                        );
                        if ui
                            .add_sized(
                                egui::vec2(76., 40.),
                                egui::Button::new(self.t("关闭", "Dismiss")),
                            )
                            .on_hover_text(self.t("关闭提示", "Dismiss message"))
                            .clicked()
                        {
                            self.message = None;
                            self.message_tone = MessageTone::Neutral;
                        }
                    });
                }
            });
        egui::Panel::bottom("operation-status")
            .exact_size(44.)
            .resizable(false)
            .frame(egui::Frame::new().inner_margin(2))
            .show_inside(parent, |ui| {
                ui.horizontal(|ui| {
                    ui.set_min_height(40.);
                    ui.small(self.t(
                        if self.connected {
                            "本用户守护进程已连接"
                        } else {
                            "守护进程未连接"
                        },
                        if self.connected {
                            "User daemon connected"
                        } else {
                            "User daemon disconnected"
                        },
                    ));
                    if snapshot.logout_confirmed == Some(false) {
                        ui.small(self.t(
                            "本地登录已清除，远端注销未确认。",
                            "Local login cleared; server logout unconfirmed.",
                        ));
                    }
                    if self.exiting {
                        ui.add(egui::Spinner::new().size(18.));
                        ui.small(self.t("正在清理并退出…", "Stopping and cleaning up…"));
                    }
                    if !self.connected && ui.button(self.t("重新连接", "Reconnect")).clicked() {
                        self.clear_private_view(&context);
                        self.bridge = Bridge::start(self.directory.clone(), context.clone());
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(context.global_style().visuals.panel_fill)
                    .inner_margin(self.tokens.layout.content_padding.round() as i8),
            )
            .show_inside(parent, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("workspace-scroll", self.screen))
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_enabled_ui(self.connected && !self.exiting, |ui| {
                            if self.screen == Screen::Server
                                || snapshot
                                    .server
                                    .as_ref()
                                    .is_none_or(|server| server.verified_health.is_none())
                            {
                                self.connection_page(ui, &snapshot);
                                if self.screen == Screen::Server {
                                    self.local_network_settings(ui, &snapshot);
                                }
                            } else if snapshot.authentication != Authentication::SignedIn {
                                self.sign_in_page(ui, &snapshot);
                            } else {
                                match self.screen {
                                    Screen::Remote => self.remote_page(ui, &snapshot),
                                    Screen::Services => self.services_page(ui, &snapshot),
                                    Screen::Devices => self.devices_page(ui, &snapshot),
                                    Screen::Security => self.security_page(ui, &snapshot),
                                    Screen::Accounts => self.accounts_page(ui, &snapshot),
                                    Screen::Network => self.network_page(ui, &snapshot),
                                    Screen::Nodes => self.nodes_page(ui, &snapshot),
                                    Screen::Audit => self.audit_page(ui, &snapshot),
                                    Screen::Server => {}
                                }
                            }
                        });
                    });
            });
        self.show_connection_task(&context, &snapshot);
        self.confirmations(&context, &snapshot);
        self.layout_diagnostics
            .finish_frame(&self.directory, &context);
    }
}

/// Verify installed diagnostic persistence without starting a GUI or session.
pub fn check_layout_diagnostics(directory: &std::path::Path) -> std::io::Result<()> {
    layout_diagnostics::storage_check(directory)
}

fn cleanup_phase(status: Option<OperationStatus>, english: bool) -> &'static str {
    match status {
        Some(OperationStatus::Succeeded) => {
            if english {
                "confirmed"
            } else {
                "已确认"
            }
        }
        Some(
            OperationStatus::Failed | OperationStatus::Cancelled | OperationStatus::Superseded,
        ) => {
            if english {
                "failed"
            } else {
                "失败"
            }
        }
        Some(OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling) => {
            if english {
                "in progress"
            } else {
                "处理中"
            }
        }
        None => {
            if english {
                "waiting"
            } else {
                "等待确认"
            }
        }
    }
}

fn snapshot_operation_status(
    snapshot: &Snapshot,
    operation: OperationId,
) -> Option<OperationStatus> {
    snapshot
        .operations
        .iter()
        .find(|result| result.id == operation)
        .map(|result| result.status)
        .or_else(|| {
            snapshot
                .events
                .iter()
                .find(|event| event.result.id == operation)
                .map(|event| event.result.status)
        })
}

fn session_cleanup_succeeded(session: &nestlink_app_core::NativeSessionView) -> bool {
    if !matches!(
        session.status,
        NativeSessionStatus::Stopped | NativeSessionStatus::Failed
    ) {
        return false;
    }
    match session.cleanup {
        Some(NativeSessionCleanup::NotAttached) => true,
        Some(NativeSessionCleanup::Succeeded) => session.stop_effects.is_some_and(|effects| {
            effects.cancel_channels
                && effects.release_inputs
                && effects.discard_queues
                && effects.close_allocations
        }),
        Some(NativeSessionCleanup::Failed) | None => false,
    }
}

fn remote_request_is_terminal(snapshot: &Snapshot, request_id: &str) -> bool {
    snapshot
        .selected_request
        .data
        .as_ref()
        .filter(|request| request.id == request_id)
        .map(|request| request.status.as_str())
        .or_else(|| {
            snapshot
                .requests
                .data
                .as_deref()?
                .iter()
                .find(|request| request.id == request_id)
                .map(|request| request.status.as_str())
        })
        .is_some_and(|status| matches!(status, "revoked" | "denied" | "expired"))
}

fn native_input_layout_is_current(
    input: &InputLayoutUpdate,
    snapshot: &Snapshot,
    runtime_id: Option<&str>,
    video_binding: Option<&nestlink_app_ipc::NativeVideoBinding>,
    video_layout: Option<(u64, u32, u32)>,
) -> bool {
    let binding = &input.layout.binding;
    let Some(session) = snapshot.native_session.data.as_ref() else {
        return false;
    };
    input.runtime_id.as_str() == runtime_id.unwrap_or_default()
        && input.ui_generation == snapshot.generation
        && video_binding.is_some_and(|video| {
            video_binding_is_current(video, snapshot, runtime_id)
                && video.request_id == binding.request_id
                && video.connection_generation == binding.connection_generation
                && video.source == binding.source
        })
        && session.status == NativeSessionStatus::Connected
        && binding.request_id == session.request_id
        && binding.connection_generation == session.connection_generation
        && binding.source == 0
        && binding.input_epoch > 0
        && binding.input_epoch <= i64::MAX as u64
        && binding.layout_epoch > 0
        && binding.layout_epoch <= i64::MAX as u64
        && video_layout.is_some_and(|(epoch, _, _)| epoch == binding.layout_epoch)
        && input.layout.width > 0
        && input.layout.height > 0
        && input.layout.width <= 32768
        && input.layout.height <= 32768
        && i64::from(input.layout.left) + i64::from(input.layout.width) <= i64::from(i32::MAX) + 1
        && i64::from(input.layout.top) + i64::from(input.layout.height) <= i64::from(i32::MAX) + 1
}

fn native_input_binding_matches(left: &NativeInputBinding, right: &NativeInputBinding) -> bool {
    left == right
}

fn video_binding_is_current(
    binding: &nestlink_app_ipc::NativeVideoBinding,
    snapshot: &Snapshot,
    runtime_id: Option<&str>,
) -> bool {
    binding.source == 0
        && runtime_id == Some(binding.runtime_id.as_str())
        && nestlink_protocol::valid_id(&binding.runtime_id)
        && nestlink_protocol::valid_id(&binding.request_id)
        && binding.ui_generation > 0
        && binding.ui_generation <= i64::MAX as u64
        && binding.connection_generation > 0
        && binding.connection_generation <= i64::MAX as u64
        && snapshot.generation == binding.ui_generation
        && snapshot
            .native_session
            .data
            .as_ref()
            .is_some_and(|session| {
                session.status == NativeSessionStatus::Connected
                    && session.request_id == binding.request_id
                    && session.connection_generation == binding.connection_generation
            })
}

fn video_layout_is_current(
    binding: &nestlink_app_ipc::NativeVideoBinding,
    snapshot: &Snapshot,
    runtime_id: Option<&str>,
    displayed_binding: Option<&nestlink_app_ipc::NativeVideoBinding>,
    displayed_layout: Option<(u64, u32, u32)>,
    candidate_layout: (u64, u32, u32),
) -> bool {
    let (layout_epoch, width, height) = candidate_layout;
    if !video_binding_is_current(binding, snapshot, runtime_id)
        || layout_epoch == 0
        || layout_epoch > i64::MAX as u64
        || !valid_video_geometry(width, height)
    {
        return false;
    }
    if displayed_binding == Some(binding)
        && displayed_layout.is_some_and(|(epoch, old_width, old_height)| {
            layout_epoch < epoch
                || (layout_epoch == epoch && (width != old_width || height != old_height))
        })
    {
        return false;
    }
    true
}

fn video_frame_is_current(
    frame: &nestlink_app_ipc::NativeVideoFrame,
    snapshot: &Snapshot,
    runtime_id: Option<&str>,
    displayed_binding: Option<&nestlink_app_ipc::NativeVideoBinding>,
    displayed_layout: Option<(u64, u32, u32)>,
    displayed_sequence: u64,
) -> bool {
    if !video_layout_is_current(
        &frame.binding,
        snapshot,
        runtime_id,
        displayed_binding,
        displayed_layout,
        (frame.layout_epoch, frame.width, frame.height),
    ) || frame.sequence == 0
        || frame.sequence > i64::MAX as u64
        || frame.pts_90khz > i64::MAX as u64
        || (displayed_binding == Some(&frame.binding) && frame.sequence <= displayed_sequence)
    {
        return false;
    }
    usize::try_from(frame.width)
        .ok()
        .and_then(|width| {
            usize::try_from(frame.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .is_some_and(|expected| frame.pixels.len() == expected)
}

fn valid_video_geometry(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= 8192
        && height <= 8192
        && u64::from(width)
            .checked_mul(u64::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .is_some_and(|bytes| bytes <= 64 * 1024 * 1024)
}

#[cfg(test)]
mod video_tests {
    use super::*;

    const RUNTIME_ID: &str = "00000000-0000-4000-8000-000000000001";
    const REQUEST_ID: &str = "00000000-0000-4000-8000-000000000002";

    fn connected_snapshot() -> Snapshot {
        let mut snapshot = Snapshot {
            generation: 7,
            ..Snapshot::default()
        };
        snapshot.native_session.data =
            Some(std::sync::Arc::new(nestlink_app_core::NativeSessionView {
                request_id: REQUEST_ID.into(),
                connection_generation: 9,
                lease_sequence: 4,
                status: NativeSessionStatus::Connected,
                host_view_authorized: false,
                path: Some(1),
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            }));
        snapshot
    }

    fn binding() -> nestlink_app_ipc::NativeVideoBinding {
        nestlink_app_ipc::NativeVideoBinding {
            runtime_id: RUNTIME_ID.into(),
            ui_generation: 7,
            request_id: REQUEST_ID.into(),
            connection_generation: 9,
            source: 0,
        }
    }

    fn input_layout() -> InputLayoutUpdate {
        InputLayoutUpdate {
            runtime_id: RUNTIME_ID.into(),
            ui_generation: 7,
            layout: NativeInputLayout {
                binding: NativeInputBinding {
                    request_id: REQUEST_ID.into(),
                    connection_generation: 9,
                    source: 0,
                    input_epoch: 3,
                    layout_epoch: 2,
                },
                left: -100,
                top: 0,
                width: 200,
                height: 100,
                scroll_supported: true,
            },
        }
    }

    #[test]
    fn input_layout_must_match_runtime_session_and_displayed_video_epoch() {
        let snapshot = connected_snapshot();
        let video = binding();
        let mut input = input_layout();
        assert!(native_input_layout_is_current(
            &input,
            &snapshot,
            Some(RUNTIME_ID),
            Some(&video),
            Some((2, 640, 480)),
        ));

        input.layout.binding.layout_epoch = 3;
        assert!(!native_input_layout_is_current(
            &input,
            &snapshot,
            Some(RUNTIME_ID),
            Some(&video),
            Some((2, 640, 480)),
        ));
        input.layout.binding.layout_epoch = 2;
        input.runtime_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(!native_input_layout_is_current(
            &input,
            &snapshot,
            Some(RUNTIME_ID),
            Some(&video),
            Some((2, 640, 480)),
        ));
    }

    fn frame(binding: nestlink_app_ipc::NativeVideoBinding) -> nestlink_app_ipc::NativeVideoFrame {
        nestlink_app_ipc::NativeVideoFrame {
            codec: 0,
            hardware_decode: false,
            binding,
            layout_epoch: 2,
            sequence: 7,
            pts_90khz: 630,
            width: 2,
            height: 1,
            pixels: Zeroizing::new(vec![0x7f; 8]),
        }
    }

    #[test]
    fn renderer_rejects_frames_from_old_runtime_generation_request_and_connection() {
        let snapshot = connected_snapshot();
        let runtime_id = Some(RUNTIME_ID);
        let binding = binding();
        assert!(video_binding_is_current(&binding, &snapshot, runtime_id));

        let mut old_runtime = binding.clone();
        old_runtime.runtime_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(!video_binding_is_current(
            &old_runtime,
            &snapshot,
            runtime_id
        ));
        assert!(!video_binding_is_current(
            &binding,
            &snapshot,
            Some("00000000-0000-4000-8000-000000000003")
        ));

        let mut old_ui = binding.clone();
        old_ui.ui_generation -= 1;
        assert!(!video_binding_is_current(&old_ui, &snapshot, runtime_id));

        let mut old_request = binding.clone();
        old_request.request_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(!video_binding_is_current(
            &old_request,
            &snapshot,
            runtime_id
        ));

        let mut old_connection = binding.clone();
        old_connection.connection_generation -= 1;
        assert!(!video_binding_is_current(
            &old_connection,
            &snapshot,
            runtime_id
        ));

        let mut other_source = binding;
        other_source.source = 1;
        assert!(!video_binding_is_current(
            &other_source,
            &snapshot,
            runtime_id
        ));
    }

    #[test]
    fn renderer_rejects_old_layout_old_sequence_and_wrong_dimensions() {
        let snapshot = connected_snapshot();
        let binding = binding();
        let runtime_id = Some(RUNTIME_ID);
        let current_layout = Some((3, 2, 1));
        assert!(!video_layout_is_current(
            &binding,
            &snapshot,
            runtime_id,
            Some(&binding),
            current_layout,
            (2, 2, 1),
        ));

        let mut old_layout = frame(binding.clone());
        old_layout.layout_epoch = 2;
        assert!(!video_frame_is_current(
            &old_layout,
            &snapshot,
            runtime_id,
            Some(&binding),
            current_layout,
            6,
        ));

        let mut old_sequence = frame(binding.clone());
        old_sequence.layout_epoch = 3;
        old_sequence.sequence = 6;
        assert!(!video_frame_is_current(
            &old_sequence,
            &snapshot,
            runtime_id,
            Some(&binding),
            current_layout,
            6,
        ));

        let mut wrong_dimensions = frame(binding.clone());
        wrong_dimensions.layout_epoch = 3;
        wrong_dimensions.width = 3;
        wrong_dimensions.pixels = Zeroizing::new(vec![0x7f; 12]);
        assert!(!video_frame_is_current(
            &wrong_dimensions,
            &snapshot,
            runtime_id,
            Some(&binding),
            current_layout,
            6,
        ));

        let mut next_layout = frame(binding.clone());
        next_layout.layout_epoch = 4;
        next_layout.sequence = 8;
        assert!(video_frame_is_current(
            &next_layout,
            &snapshot,
            runtime_id,
            Some(&binding),
            current_layout,
            7,
        ));
    }

    #[test]
    fn terminal_session_and_invalid_layout_cannot_keep_a_presentation() {
        let mut snapshot = connected_snapshot();
        let mut stopped = snapshot
            .native_session
            .data
            .as_ref()
            .map(|session| (**session).clone())
            .unwrap_or(nestlink_app_core::NativeSessionView {
                request_id: REQUEST_ID.into(),
                connection_generation: 9,
                lease_sequence: 4,
                status: NativeSessionStatus::Stopped,
                host_view_authorized: false,
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            });
        stopped.status = NativeSessionStatus::Stopped;
        snapshot.native_session.data = Some(std::sync::Arc::new(stopped));
        let binding = binding();
        assert!(!video_binding_is_current(
            &binding,
            &snapshot,
            Some(RUNTIME_ID)
        ));
        assert!(!video_layout_is_current(
            &binding,
            &connected_snapshot(),
            Some(RUNTIME_ID),
            Some(&binding),
            Some((3, 2, 1)),
            (4, 8192, 8192),
        ));
    }
}
