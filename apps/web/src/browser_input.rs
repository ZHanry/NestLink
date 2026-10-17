//! Permission-scoped browser input capture. This module only turns focused
//! browser events into bounded, layout-relative events; the WebRTC peer owns
//! authorization, epochs, sequencing and transport.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    rc::Rc,
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{
    CompositionEvent, Document, Event, EventTarget, HtmlElement, HtmlTextAreaElement,
    HtmlVideoElement, InputEvent, KeyboardEvent, PointerEvent, Window,
};

const POINTER_SAMPLE_MS: f64 = 16.0;
// WebRTC control is JSON capped at 4 KiB; this leaves room for worst-case
// escaping plus the input/layout/epoch envelope.
const INPUT_TEXT_BYTES: usize = 1800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserInputLayout {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}

impl BrowserInputLayout {
    fn valid(self) -> bool {
        self.width > 0
            && self.height > 0
            && self.width <= 32768
            && self.height <= 32768
            && self.left.checked_add_unsigned(self.width).is_some()
            && self.top.checked_add_unsigned(self.height).is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserInputEvent {
    Key {
        usage: u16,
        down: bool,
    },
    Pointer {
        button: Option<u8>,
        down: bool,
        x: i32,
        y: i32,
    },
    Text(String),
    ReleaseAll,
}

type InputSink = Rc<RefCell<Box<dyn FnMut(BrowserInputEvent)>>>;
type Listener = (EventTarget, &'static str, Closure<dyn FnMut(Event)>);

/// Captures input only while the video or text field is focused. Pointer motion
/// is coalesced at roughly 60 Hz; button transitions and key transitions are
/// delivered immediately and are released when focus or page visibility ends.
pub struct BrowserInputCapture {
    video: HtmlVideoElement,
    text: HtmlTextAreaElement,
    window: Window,
    listeners: Vec<Listener>,
    pointer_timer: i32,
    pointer_timer_handler: Closure<dyn FnMut()>,
    pressed_keys: Rc<RefCell<BTreeSet<u16>>>,
    pressed_buttons: Rc<RefCell<BTreeSet<u8>>>,
    pending_pointer: Rc<RefCell<Option<(i32, i32)>>>,
    last_pointer_sample: Rc<Cell<f64>>,
    sink: InputSink,
    layout: BrowserInputLayout,
}

impl BrowserInputCapture {
    pub fn attach(
        video: HtmlVideoElement,
        text: HtmlTextAreaElement,
        layout: BrowserInputLayout,
        sink: impl FnMut(BrowserInputEvent) + 'static,
    ) -> Result<Self, &'static str> {
        if !layout.valid() {
            return Err("invalid remote input layout");
        }
        let window = web_sys::window().ok_or("browser window unavailable")?;
        let document = window.document().ok_or("browser document unavailable")?;
        text.set_value("");
        video
            .dyn_ref::<HtmlElement>()
            .ok_or("video element unavailable")?
            .set_tab_index(0);

        let sink: InputSink = Rc::new(RefCell::new(Box::new(sink)));
        let pressed_keys = Rc::new(RefCell::new(BTreeSet::new()));
        let pressed_buttons = Rc::new(RefCell::new(BTreeSet::new()));
        let pending_pointer = Rc::new(RefCell::new(None));
        let last_pointer_sample = Rc::new(Cell::new(0.0));
        let mut capture = Self {
            video,
            text,
            window,
            listeners: Vec::new(),
            pointer_timer: 0,
            pointer_timer_handler: Closure::wrap(Box::new(|| {}) as Box<dyn FnMut()>),
            pressed_keys,
            pressed_buttons,
            pending_pointer,
            last_pointer_sample,
            sink,
            layout,
        };
        capture.install(&document)?;
        Ok(capture)
    }

    fn install(&mut self, document: &Document) -> Result<(), &'static str> {
        let composing = Rc::new(Cell::new(false));
        let sink = self.sink.clone();
        let video = self.video.clone();
        let layout = self.layout;
        let pressed_buttons = self.pressed_buttons.clone();
        let down = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<PointerEvent>() else {
                return;
            };
            let Some(button) = browser_button(event.button()) else {
                return;
            };
            let Some((x, y)) = pointer_coordinates(&video, layout, &event, false) else {
                return;
            };
            pressed_buttons.borrow_mut().insert(button);
            let _ = video.set_pointer_capture(event.pointer_id());
            let _ = video.focus();
            (sink.borrow_mut())(BrowserInputEvent::Pointer {
                button: Some(button),
                down: true,
                x,
                y,
            });
            event.prevent_default();
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "pointerdown", down)?;

        let sink = self.sink.clone();
        let video = self.video.clone();
        let layout = self.layout;
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let up = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<PointerEvent>() else {
                return;
            };
            let Some(button) = browser_button(event.button()) else {
                return;
            };
            if !pressed_buttons.borrow_mut().remove(&button) {
                return;
            }
            if let Some((x, y)) = pointer_coordinates(&video, layout, &event, true) {
                (sink.borrow_mut())(BrowserInputEvent::Pointer {
                    button: Some(button),
                    down: false,
                    x,
                    y,
                });
            } else {
                release_all(&sink, &pressed_keys, &pressed_buttons);
            }
            let _ = video.release_pointer_capture(event.pointer_id());
            event.prevent_default();
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "pointerup", up)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let cancelled = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "pointercancel", cancelled)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let cancelled = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "lostpointercapture", cancelled)?;

        let video = self.video.clone();
        let layout = self.layout;
        let pending = self.pending_pointer.clone();
        let movement = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<PointerEvent>() else {
                return;
            };
            if let Some(point) = pointer_coordinates(&video, layout, &event, false) {
                *pending.borrow_mut() = Some(point);
            }
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "pointermove", movement)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let keydown = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<KeyboardEvent>() else {
                return;
            };
            let Some(usage) = hid_usage(&event.code()) else {
                return;
            };
            if event.repeat() || !pressed_keys.borrow_mut().insert(usage) {
                return;
            }
            (sink.borrow_mut())(BrowserInputEvent::Key { usage, down: true });
            event.prevent_default();
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "keydown", keydown)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let keyup = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<KeyboardEvent>() else {
                return;
            };
            let Some(usage) = hid_usage(&event.code()) else {
                return;
            };
            if pressed_keys.borrow_mut().remove(&usage) {
                (sink.borrow_mut())(BrowserInputEvent::Key { usage, down: false });
                event.prevent_default();
            }
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "keyup", keyup)?;

        let just_composed = Rc::new(Cell::new(false));
        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let composing_for_keydown = composing.clone();
        let just_composed_for_keydown = just_composed.clone();
        let keydown = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<KeyboardEvent>() else {
                return;
            };
            let code = event.code();
            if !composing_for_keydown.get() && is_typing_key(&code) {
                just_composed_for_keydown.set(false);
            }
            let Some(usage) = hid_usage(&code) else {
                return;
            };
            let shortcut = event.ctrl_key() || event.alt_key() || event.meta_key();
            if (composing_for_keydown.get() || (!shortcut && is_typing_key(&code)))
                && !(0xe0..=0xe7).contains(&usage)
            {
                return;
            }
            if event.repeat() || !pressed_keys.borrow_mut().insert(usage) {
                return;
            }
            (sink.borrow_mut())(BrowserInputEvent::Key { usage, down: true });
            event.prevent_default();
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.text.clone().into(), "keydown", keydown)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let keyup = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<KeyboardEvent>() else {
                return;
            };
            let Some(usage) = hid_usage(&event.code()) else {
                return;
            };
            if pressed_keys.borrow_mut().remove(&usage) {
                (sink.borrow_mut())(BrowserInputEvent::Key { usage, down: false });
                event.prevent_default();
            }
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.text.clone().into(), "keyup", keyup)?;

        let composing_state = composing.clone();
        let composition_start = Closure::wrap(Box::new(move |_event: Event| {
            composing_state.set(true);
        }) as Box<dyn FnMut(Event)>);
        self.listen(
            self.text.clone().into(),
            "compositionstart",
            composition_start,
        )?;

        let sink = self.sink.clone();
        let text = self.text.clone();
        let composing_state = composing.clone();
        let composition_done = just_composed.clone();
        let composition_end = Closure::wrap(Box::new(move |event: Event| {
            let Ok(event) = event.dyn_into::<CompositionEvent>() else {
                return;
            };
            composing_state.set(false);
            composition_done.set(true);
            let value = event.data().unwrap_or_default();
            text.set_value("");
            let bounded = bounded_text(&value);
            if !bounded.is_empty() {
                (sink.borrow_mut())(BrowserInputEvent::Text(bounded));
            }
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.text.clone().into(), "compositionend", composition_end)?;

        let sink = self.sink.clone();
        let text = self.text.clone();
        let composing = composing.clone();
        let just_composed = just_composed.clone();
        let text_input = Closure::wrap(Box::new(move |event: Event| {
            let input_type = event
                .dyn_into::<InputEvent>()
                .map(|event| event.input_type())
                .unwrap_or_default();
            if !composing.get()
                && input_type.starts_with("insertText")
                && just_composed.replace(false)
            {
                text.set_value("");
                return;
            }
            let value = text.value();
            if value.is_empty() {
                return;
            }
            text.set_value("");
            if composing.get() {
                return;
            }
            let insertion = input_type.starts_with("insertText")
                || input_type.starts_with("insertReplacementText")
                || input_type == "insertFromPaste";
            let bounded = insertion.then(|| bounded_text(&value));
            if let Some(bounded) = bounded.filter(|value| !value.is_empty()) {
                (sink.borrow_mut())(BrowserInputEvent::Text(bounded));
            }
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.text.clone().into(), "input", text_input)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let focusout = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.video.clone().into(), "blur", focusout)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let focusout = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.text.clone().into(), "blur", focusout)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let window_blur = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.window.clone().into(), "blur", window_blur)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let hidden = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(document.clone().into(), "visibilitychange", hidden)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let pending_pointer = self.pending_pointer.clone();
        let fullscreen = Closure::wrap(Box::new(move |_event: Event| {
            // Esc can leave fullscreen without delivering a matching keyup.
            // Release owned input and discard coordinates sampled before the
            // viewport geometry changed.
            pending_pointer.borrow_mut().take();
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(document.clone().into(), "fullscreenchange", fullscreen)?;

        let sink = self.sink.clone();
        let pressed_keys = self.pressed_keys.clone();
        let pressed_buttons = self.pressed_buttons.clone();
        let pagehide = Closure::wrap(Box::new(move |_event: Event| {
            release_all(&sink, &pressed_keys, &pressed_buttons);
        }) as Box<dyn FnMut(Event)>);
        self.listen(self.window.clone().into(), "pagehide", pagehide)?;

        let pending = self.pending_pointer.clone();
        let last_sample = self.last_pointer_sample.clone();
        let sink = self.sink.clone();
        self.pointer_timer_handler = Closure::wrap(Box::new(move || {
            let Some((x, y)) = pending.borrow_mut().take() else {
                return;
            };
            let now = web_sys::window()
                .and_then(|window| window.performance())
                .map(|performance| performance.now())
                .unwrap_or(f64::INFINITY);
            if now - last_sample.get() < POINTER_SAMPLE_MS {
                *pending.borrow_mut() = Some((x, y));
                return;
            }
            last_sample.set(now);
            (sink.borrow_mut())(BrowserInputEvent::Pointer {
                button: None,
                down: false,
                x,
                y,
            });
        }) as Box<dyn FnMut()>);
        self.pointer_timer = self
            .window
            .set_interval_with_callback_and_timeout_and_arguments_0(
                self.pointer_timer_handler.as_ref().unchecked_ref(),
                16,
            )
            .map_err(|_| "could not schedule pointer input")?;
        Ok(())
    }

    fn listen(
        &mut self,
        target: EventTarget,
        name: &'static str,
        handler: Closure<dyn FnMut(Event)>,
    ) -> Result<(), &'static str> {
        target
            .add_event_listener_with_callback(name, handler.as_ref().unchecked_ref())
            .map_err(|_| "could not register browser input listener")?;
        self.listeners.push((target, name, handler));
        Ok(())
    }

    pub fn release(&self) {
        release_all(&self.sink, &self.pressed_keys, &self.pressed_buttons);
        self.pending_pointer.borrow_mut().take();
    }
}

impl Drop for BrowserInputCapture {
    fn drop(&mut self) {
        self.release();
        self.window.clear_interval_with_handle(self.pointer_timer);
        for (target, name, handler) in self.listeners.drain(..) {
            let _ =
                target.remove_event_listener_with_callback(name, handler.as_ref().unchecked_ref());
        }
    }
}

fn release_all(
    sink: &InputSink,
    pressed_keys: &RefCell<BTreeSet<u16>>,
    pressed_buttons: &RefCell<BTreeSet<u8>>,
) {
    let had_pressed = !pressed_keys.borrow().is_empty() || !pressed_buttons.borrow().is_empty();
    pressed_keys.borrow_mut().clear();
    pressed_buttons.borrow_mut().clear();
    if had_pressed {
        (sink.borrow_mut())(BrowserInputEvent::ReleaseAll);
    }
}

fn pointer_coordinates(
    video: &HtmlVideoElement,
    layout: BrowserInputLayout,
    event: &PointerEvent,
    clamp: bool,
) -> Option<(i32, i32)> {
    let rect = video.get_bounding_client_rect();
    let video_width = f64::from(video.video_width());
    let video_height = f64::from(video.video_height());
    if rect.width() <= 0.0 || rect.height() <= 0.0 || video_width <= 0.0 || video_height <= 0.0 {
        return None;
    }
    // Match object-fit: contain so black bars around the remote frame never
    // inject clicks into the edges of the host display.
    let scale = (rect.width() / video_width).min(rect.height() / video_height);
    let rendered_width = video_width * scale;
    let rendered_height = video_height * scale;
    let left = rect.left() + (rect.width() - rendered_width) / 2.0;
    let top = rect.top() + (rect.height() - rendered_height) / 2.0;
    let mut x = f64::from(event.client_x()) - left;
    let mut y = f64::from(event.client_y()) - top;
    if clamp {
        x = x.clamp(0.0, rendered_width - f64::EPSILON);
        y = y.clamp(0.0, rendered_height - f64::EPSILON);
    } else if x < 0.0 || y < 0.0 || x >= rendered_width || y >= rendered_height {
        return None;
    }
    let x = i64::from(layout.left)
        + ((x / rendered_width * f64::from(layout.width)).floor() as i64)
            .clamp(0, i64::from(layout.width) - 1);
    let y = i64::from(layout.top)
        + ((y / rendered_height * f64::from(layout.height)).floor() as i64)
            .clamp(0, i64::from(layout.height) - 1);
    Some((x as i32, y as i32))
}

fn browser_button(button: i16) -> Option<u8> {
    match button {
        0 => Some(1),
        1 => Some(2),
        2 => Some(3),
        3 => Some(4),
        4 => Some(5),
        _ => None,
    }
}

fn is_typing_key(code: &str) -> bool {
    code.starts_with("Key")
        || code.starts_with("Digit")
        || (code.starts_with("Numpad") && code != "NumpadEnter")
        || matches!(
            code,
            "Space"
                | "Minus"
                | "Equal"
                | "BracketLeft"
                | "BracketRight"
                | "Backslash"
                | "IntlBackslash"
                | "Semicolon"
                | "Quote"
                | "Backquote"
                | "Comma"
                | "Period"
                | "Slash"
        )
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn bounded_text(value: &str) -> String {
    let safe: String = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect();
    truncate_utf8(&safe, INPUT_TEXT_BYTES)
}

fn hid_usage(code: &str) -> Option<u16> {
    let bytes = code.as_bytes();
    if bytes.len() == 4 && bytes.starts_with(b"Key") && bytes[3].is_ascii_uppercase() {
        return Some(u16::from(bytes[3] - b'A') + 4);
    }
    if bytes.len() == 6 && bytes.starts_with(b"Digit") && (b'1'..=b'9').contains(&bytes[5]) {
        return Some(u16::from(bytes[5] - b'1') + 0x1e);
    }
    if code == "Digit0" {
        return Some(0x27);
    }
    if let Some(number) = code
        .strip_prefix('F')
        .and_then(|value| value.parse::<u8>().ok())
        && (1..=12).contains(&number)
    {
        return Some(0x39 + u16::from(number));
    }
    Some(match code {
        "Enter" | "NumpadEnter" => 0x28,
        "Escape" => 0x29,
        "Backspace" => 0x2a,
        "Tab" => 0x2b,
        "Space" => 0x2c,
        "Minus" => 0x2d,
        "Equal" => 0x2e,
        "BracketLeft" => 0x2f,
        "BracketRight" => 0x30,
        "Backslash" => 0x31,
        "IntlBackslash" => 0x64,
        "Semicolon" => 0x33,
        "Quote" => 0x34,
        "Backquote" => 0x35,
        "Comma" => 0x36,
        "Period" => 0x37,
        "Slash" => 0x38,
        "CapsLock" => 0x39,
        "PrintScreen" => 0x46,
        "ScrollLock" => 0x47,
        "Pause" => 0x48,
        "Insert" => 0x49,
        "Home" => 0x4a,
        "PageUp" => 0x4b,
        "Delete" => 0x4c,
        "End" => 0x4d,
        "PageDown" => 0x4e,
        "ArrowRight" => 0x4f,
        "ArrowLeft" => 0x50,
        "ArrowDown" => 0x51,
        "ArrowUp" => 0x52,
        "NumLock" => 0x53,
        "NumpadDivide" => 0x54,
        "NumpadMultiply" => 0x55,
        "NumpadSubtract" => 0x56,
        "NumpadAdd" => 0x57,
        "Numpad1" => 0x59,
        "Numpad2" => 0x5a,
        "Numpad3" => 0x5b,
        "Numpad4" => 0x5c,
        "Numpad5" => 0x5d,
        "Numpad6" => 0x5e,
        "Numpad7" => 0x5f,
        "Numpad8" => 0x60,
        "Numpad9" => 0x61,
        "Numpad0" => 0x62,
        "NumpadDecimal" => 0x63,
        "ContextMenu" => 0x65,
        "NumpadEqual" => 0x67,
        "F13" => 0x68,
        "F14" => 0x69,
        "F15" => 0x6a,
        "F16" => 0x6b,
        "F17" => 0x6c,
        "F18" => 0x6d,
        "F19" => 0x6e,
        "F20" => 0x6f,
        "F21" => 0x70,
        "F22" => 0x71,
        "F23" => 0x72,
        "F24" => 0x73,
        "ControlLeft" => 0xe0,
        "ShiftLeft" => 0xe1,
        "AltLeft" => 0xe2,
        "MetaLeft" => 0xe3,
        "ControlRight" => 0xe4,
        "ShiftRight" => 0xe5,
        "AltRight" => 0xe6,
        "MetaRight" => 0xe7,
        _ => return None,
    })
}
