//! Bounded numeric geometry evidence; never includes labels or session data.
use eframe::egui;
use std::{
    collections::VecDeque,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, PartialEq)]
pub(super) struct Geometry {
    pub content: egui::Rect,
    pub close: egui::Rect,
    pub stop: egui::Rect,
    pub sizing_pass: bool,
}

#[derive(Default)]
pub(super) struct Recorder {
    last: Option<(egui::Rect, egui::Rect, Geometry)>,
    samples: VecDeque<serde_json::Value>,
    last_write: Option<Instant>,
    dirty: bool,
}

impl Recorder {
    pub(super) fn record(
        &mut self,
        directory: &Path,
        context: &egui::Context,
        window: egui::Rect,
        geometry: Geometry,
    ) {
        if directory.as_os_str().is_empty() {
            return;
        }
        let viewport = context.content_rect();
        let rectangles = [
            viewport,
            window,
            geometry.content,
            geometry.close,
            geometry.stop,
        ];
        if rectangles.iter().any(|rect| !rect.is_finite()) {
            return;
        }
        let pressed = context.input(|input| input.pointer.any_pressed());
        let released = context.input(|input| input.pointer.any_released());
        let current = (viewport, window, geometry);
        if self.last != Some(current) || pressed || released {
            let coords = |r: egui::Rect| [r.min.x, r.min.y, r.max.x, r.max.y];
            self.samples.push_back(serde_json::json!({
                "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_millis() as u64),
                "pixels_per_point": context.pixels_per_point(),
                "viewport": coords(viewport), "window": coords(window),
                "content": coords(geometry.content), "close": coords(geometry.close), "stop": coords(geometry.stop),
                "sizing_pass": geometry.sizing_pass, "pointer_pressed": pressed, "pointer_released": released,
            }));
            while self.samples.len() > 96 {
                self.samples.pop_front();
            }
            self.last = Some(current);
            self.dirty = true;
        }
        if self.dirty
            && self
                .last_write
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            let bytes: Vec<u8> = self
                .samples
                .iter()
                .flat_map(|sample| {
                    let mut line = sample.to_string().into_bytes();
                    line.push(b'\n');
                    line
                })
                .collect();
            if bytes.len() <= 65_536
                && nestlink_platform_security::replace_private_metadata(
                    &directory.join("local-session-layout.jsonl"),
                    &bytes,
                )
                .is_ok()
            {
                self.dirty = false;
            }
            self.last_write = Some(Instant::now());
        }
    }
}
