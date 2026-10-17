//! Explicit tool-only two-display capture and recording input. No OS adapter.
use nestlink_protocol::native_displays::DisplayDescriptor;
use nestlink_remote::input::{Button, InputAction, InputDevice, InputLayout, PlatformInput};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn displays() -> Vec<DisplayDescriptor> {
    vec![
        DisplayDescriptor {
            source: 3,
            left: 0,
            top: 0,
            width: 320,
            height: 180,
            label: "Owned red display / 测试红屏".into(),
        },
        DisplayDescriptor {
            source: 8,
            left: -256,
            top: -32,
            width: 256,
            height: 144,
            label: "Owned blue display / 测试蓝屏".into(),
        },
    ]
}

struct Facts {
    frames: BTreeMap<u32, usize>,
    flushes: usize,
    events: Vec<Value>,
    held: BTreeSet<Button>,
    selected: Option<u32>,
    resets: usize,
    input_dropped: bool,
    output: File,
    capture_output: File,
    capture_events: usize,
}

pub struct OwnedMultiDisplay(Mutex<Facts>);
impl OwnedMultiDisplay {
    pub fn new(evidence: &Path) -> io::Result<Arc<Self>> {
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(evidence.join("multidisplay-input.jsonl"))?;
        let capture_output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(evidence.join("multidisplay-capture.jsonl"))?;
        Ok(Arc::new(Self(Mutex::new(Facts {
            frames: BTreeMap::new(),
            flushes: 0,
            events: Vec::new(),
            held: BTreeSet::new(),
            selected: None,
            resets: 0,
            input_dropped: false,
            output,
            capture_output,
            capture_events: 0,
        }))))
    }

    pub fn descriptor(&self) -> Value {
        json!({"enabled":true,"displays":displays(),"initial_source":8,
            "expected_decoded_rgb_red_blue":{"3":[210,40],"8":[40,210]},
            "local_approval":"Explicit multi-display fixture CLI; only synthetic pixels and recording InputDevice",
            "user_desktop_or_files_accessed":false})
    }

    pub fn frame(&self, source: u32) {
        let mut facts = lock(&self.0);
        let count = facts.frames.entry(source).or_default();
        *count += 1;
        let event = json!({"kind":"captured_frame","source":source,"count":count});
        let _ = Self::append_capture(&mut facts, event);
    }

    pub fn capture_source(&self, source: u32) {
        let mut facts = lock(&self.0);
        let _ = Self::append_capture(
            &mut facts,
            json!({"kind":"capture_source_polled","source":source}),
        );
    }

    pub fn flush(&self) {
        lock(&self.0).flushes += 1;
    }

    pub fn input_device(self: &Arc<Self>) -> OwnedMultiInput {
        OwnedMultiInput(self.clone())
    }

    fn append(facts: &mut Facts, event: Value) -> io::Result<()> {
        if facts.events.len() >= 512 {
            return Err(io::Error::other(
                "multi-display input recording budget exceeded",
            ));
        }
        writeln!(facts.output, "{event}")?;
        facts.output.flush()?;
        facts.events.push(event);
        Ok(())
    }

    fn append_capture(facts: &mut Facts, event: Value) -> io::Result<()> {
        if facts.capture_events >= 512 {
            return Err(io::Error::other(
                "multi-display capture recording budget exceeded",
            ));
        }
        writeln!(facts.capture_output, "{event}")?;
        facts.capture_output.flush()?;
        facts.capture_events += 1;
        Ok(())
    }

    pub fn finish(&self, evidence: &Path, core_clean: bool) -> io::Result<bool> {
        let facts = lock(&self.0);
        let sources = displays();
        let pointers = sources.iter().all(|display| {
            facts.events.iter().any(|event| {
                event["kind"] == "pointer"
                    && event["source"] == display.source
                    && event["x"].as_i64().is_some_and(|x| {
                        x >= i64::from(display.left)
                            && x < i64::from(display.left) + i64::from(display.width)
                    })
                    && event["y"].as_i64().is_some_and(|y| {
                        y >= i64::from(display.top)
                            && y < i64::from(display.top) + i64::from(display.height)
                    })
            })
        });
        let held_release = facts.events.iter().any(|event| event["kind"] == "release");
        let selected_sources: Vec<u64> = facts
            .events
            .iter()
            .filter(|event| event["kind"] == "select_source")
            .filter_map(|event| event["source"].as_u64())
            .collect();
        let both_selected = sources
            .iter()
            .all(|display| selected_sources.contains(&u64::from(display.source)));
        let expected_selection_order = selected_sources == [8, 3, 8, 3];
        let both_captured = sources
            .iter()
            .all(|display| facts.frames.get(&display.source).copied().unwrap_or(0) > 0);
        let passed = core_clean
            && both_selected
            && expected_selection_order
            && both_captured
            && pointers
            && held_release
            && facts.held.is_empty()
            && facts.input_dropped
            && facts.resets > 0
            && facts.flushes >= 3;
        let result = json!({"scope":"Owned synthetic two-display WebRTC and recording input; no physical OS acceptance",
            "passed":passed,"source_frames":facts.frames,"capture_flushes":facts.flushes,
            "input_events":facts.events.len(),"selected_sources":selected_sources,
            "expected_selection_order":expected_selection_order,
            "pointer_in_each_approved_geometry":pointers,"held_input_released":held_release,
            "held_buttons":facts.held.len(),"input_resets":facts.resets,"input_device_dropped":facts.input_dropped,
            "core_cleanup_succeeded":core_clean,"user_desktop_or_files_accessed":false});
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(evidence.join("multidisplay-result.json"))?;
        serde_json::to_writer_pretty(&mut output, &result)?;
        writeln!(output)?;
        Ok(passed)
    }
}

pub struct OwnedMultiInput(Arc<OwnedMultiDisplay>);
impl InputDevice for OwnedMultiInput {
    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        let approved = displays().into_iter().any(|display| {
            display.source == source
                && (display.left, display.top, display.width, display.height)
                    == (layout.left, layout.top, layout.width, layout.height)
        });
        let mut facts = lock(&self.0.0);
        if !approved || !facts.held.is_empty() {
            return Err(io::Error::other(
                "selection did not release held input or used an unapproved display",
            ));
        }
        facts.selected = Some(source);
        OwnedMultiDisplay::append(
            &mut facts,
            json!({"kind":"select_source","source":source,
            "left":layout.left,"top":layout.top,"width":layout.width,"height":layout.height,"held_buttons":0}),
        )
    }

    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let mut facts = lock(&self.0.0);
        let source = facts
            .selected
            .ok_or_else(|| io::Error::other("input source was not selected"))?;
        let event = match input {
            PlatformInput::Action(InputAction::Key { code, down }) => {
                let button = Button::Key(*code);
                if *down {
                    facts.held.insert(button);
                } else {
                    facts.held.remove(&button);
                }
                json!({"kind":"key","code":code,"down":down,"source":source})
            }
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                if let Some(button) = button {
                    let button = Button::Pointer(*button);
                    if *down {
                        facts.held.insert(button);
                    } else {
                        facts.held.remove(&button);
                    }
                }
                json!({"kind":"pointer","button":button,"down":down,"x":x,"y":y,"source":source})
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                json!({"kind":"text","text":text,"source":source})
            }
            PlatformInput::Release(button) => {
                facts.held.remove(&button);
                match button {
                    Button::Key(code) => {
                        json!({"kind":"release","button_type":"key","code":code,"source":source})
                    }
                    Button::Pointer(code) => {
                        json!({"kind":"release","button_type":"pointer","code":code,"source":source})
                    }
                }
            }
        };
        OwnedMultiDisplay::append(&mut facts, event)
    }

    fn reset(&mut self) -> io::Result<()> {
        let mut facts = lock(&self.0.0);
        facts.resets += 1;
        OwnedMultiDisplay::append(&mut facts, json!({"kind":"reset"}))
    }
}
impl Drop for OwnedMultiInput {
    fn drop(&mut self) {
        lock(&self.0.0).input_dropped = true;
    }
}
