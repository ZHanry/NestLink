//! Bounded layout evidence, including skipped frames and persistence failures.
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

#[derive(Clone, Copy)]
pub(super) enum Surface {
    LocalSession,
    RequestTask,
}
impl Surface {
    fn index(self) -> usize {
        match self {
            Self::LocalSession => 0,
            Self::RequestTask => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::LocalSession => "local_session",
            Self::RequestTask => "request_task",
        }
    }
}

#[derive(Default)]
pub(super) struct Recorder {
    last: [Option<(egui::Rect, egui::Rect, Geometry, f32)>; 2],
    last_buttons: [Option<serde_json::Value>; 2],
    samples: VecDeque<serde_json::Value>,
    last_write: Option<Instant>,
    last_heartbeat: Option<Instant>,
    dirty: bool,
    frames: u64,
    revision: u64,
    requested: bool,
    request_task_requested: bool,
    records: u64,
    invalid_geometry: u64,
    empty_directory: u64,
    last_write_error: Option<serde_json::Value>,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| t.as_millis().try_into().unwrap_or(u64::MAX))
}
fn coordinates(rect: egui::Rect) -> Option<[f32; 4]> {
    rect.is_finite()
        .then_some([rect.min.x, rect.min.y, rect.max.x, rect.max.y])
}
impl Recorder {
    fn push(&mut self, mut value: serde_json::Value) {
        value["unix_ms"] = unix_ms().into();
        value["frame"] = self.frames.into();
        value["revision"] = self.revision.into();
        self.samples.push_back(value);
        while self.samples.len() > 96 {
            self.samples.pop_front();
        }
        self.dirty = true;
    }
    pub(super) fn begin_frame(&mut self, revision: u64, requested: bool) {
        self.frames = self.frames.saturating_add(1);
        self.revision = revision;
        self.requested = requested;
    }
    pub(super) fn request_task_requested(&mut self, requested: bool) {
        self.request_task_requested = requested;
    }
    pub(super) fn finish_frame(&mut self, directory: &Path, context: &egui::Context) {
        if self
            .last_heartbeat
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.push(serde_json::json!({
                "event":"frame_heartbeat", "version":env!("CARGO_PKG_VERSION"),
                "viewport_id":format!("{:?}",context.viewport_id()),
                "viewport":coordinates(context.content_rect()), "pixels_per_point":context.pixels_per_point(),
                "dialog_requested":self.requested,"geometry_records":self.records,
                "request_task_requested":self.request_task_requested,
                "invalid_geometry":self.invalid_geometry,"empty_directory":self.empty_directory,
                "last_write_error":self.last_write_error,
            }));
            self.last_heartbeat = Some(Instant::now());
        }
        self.flush(directory);
    }
    pub(super) fn buttons(
        &mut self,
        context: &egui::Context,
        close: &egui::Response,
        stop: &egui::Response,
    ) {
        self.buttons_for(Surface::LocalSession, context, close, stop);
    }
    pub(super) fn buttons_for(
        &mut self,
        surface: Surface,
        context: &egui::Context,
        close: &egui::Response,
        stop: &egui::Response,
    ) {
        let details = serde_json::json!({
            "event":"button_geometry", "viewport_id":format!("{:?}",context.viewport_id()),
            "surface":surface.name(),
            "pixels_per_point":context.pixels_per_point(),
            "close_id":format!("{:016x}",close.id.value()),"close_rect":coordinates(close.rect),
            "close_interact_rect":coordinates(close.interact_rect),"close_enabled":close.enabled(),
            "stop_id":format!("{:016x}",stop.id.value()),"stop_rect":coordinates(stop.rect),
            "stop_interact_rect":coordinates(stop.interact_rect),"stop_enabled":stop.enabled(),
        });
        let pressed = context.input(|input| input.pointer.any_pressed());
        let released = context.input(|input| input.pointer.any_released());
        if self.last_buttons[surface.index()].as_ref() != Some(&details) || pressed || released {
            self.last_buttons[surface.index()] = Some(details.clone());
            self.push(details);
        }
        if pressed || released {
            self.push(serde_json::json!({
                "event":"pointer","pressed":pressed,"released":released,
                "surface":surface.name(),
                "position":context.input(|input| input.pointer.interact_pos()).map(|p|[p.x,p.y]),
                "close_clicked":close.clicked(),"stop_clicked":stop.clicked(),
                "close_contains_pointer":close.contains_pointer(),"stop_contains_pointer":stop.contains_pointer(),
            }));
        }
    }
    pub(super) fn record(
        &mut self,
        directory: &Path,
        context: &egui::Context,
        window: egui::Rect,
        geometry: Geometry,
    ) {
        self.record_for(Surface::LocalSession, directory, context, window, geometry);
    }
    pub(super) fn record_for(
        &mut self,
        surface: Surface,
        directory: &Path,
        context: &egui::Context,
        window: egui::Rect,
        geometry: Geometry,
    ) {
        self.records = self.records.saturating_add(1);
        let viewport = context.content_rect();
        let rectangles = [
            viewport,
            window,
            geometry.content,
            geometry.close,
            geometry.stop,
        ];
        if let Some(index) = rectangles.iter().position(|rect| !rect.is_finite()) {
            self.invalid_geometry = self.invalid_geometry.saturating_add(1);
            if self.invalid_geometry == 1 {
                self.push(serde_json::json!({"event":"geometry_rejected","rectangle_index":index,"surface":surface.name()}));
            }
            self.flush(directory);
            return;
        }
        let pressed = context.input(|input| input.pointer.any_pressed());
        let released = context.input(|input| input.pointer.any_released());
        let current = (viewport, window, geometry, context.pixels_per_point());
        if self.last[surface.index()] != Some(current) || pressed || released {
            self.push(serde_json::json!({
                "event":"window_geometry","viewport_id":format!("{:?}",context.viewport_id()),
                "surface":surface.name(),
                "pixels_per_point":context.pixels_per_point(),"viewport":coordinates(viewport),"window":coordinates(window),
                "content":coordinates(geometry.content),"close":coordinates(geometry.close),"stop":coordinates(geometry.stop),
                "sizing_pass":geometry.sizing_pass,"pointer_pressed":pressed,"pointer_released":released,
            }));
            self.last[surface.index()] = Some(current);
        }
        self.flush(directory);
    }
    fn flush(&mut self, directory: &Path) {
        if directory.as_os_str().is_empty() {
            self.empty_directory = self.empty_directory.saturating_add(1);
            return;
        }
        if !self.dirty
            || self
                .last_write
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        let bytes = loop {
            let bytes: Vec<u8> = self
                .samples
                .iter()
                .flat_map(|sample| {
                    let mut line = sample.to_string().into_bytes();
                    line.push(b'\n');
                    line
                })
                .collect();
            if bytes.len() <= 65_536 {
                break bytes;
            }
            self.samples.pop_front();
        };
        match nestlink_platform_security::replace_private_metadata(
            &directory.join("local-session-layout.jsonl"),
            &bytes,
        ) {
            Ok(_) => self.dirty = false,
            Err(error) => {
                let detail = serde_json::json!({"event":"write_failed","os_code":error.raw_os_error(),"kind":format!("{:?}",error.kind())});
                self.last_write_error = Some(detail.clone());
                self.push(detail);
            }
        }
        self.last_write = Some(Instant::now());
    }
}
pub(crate) fn storage_check(directory: &Path) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"unix_ms":unix_ms(),"kind":"layout_storage_check"}),
    )?;
    let path = directory.join("desktop-diagnostics-check.json");
    nestlink_platform_security::replace_private_metadata(&path, &bytes)?;
    if nestlink_platform_security::read_private(&path, 4096)?.as_slice() != bytes.as_slice() {
        return Err(std::io::Error::other("diagnostic storage readback differs"));
    }
    Ok(())
}
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nestlink-layout-{}-{}-{sequence}",
                std::process::id(),
                unix_ms()
            ));
            nestlink_platform_security::new_private_directory(&path)
                .expect("private test directory");
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn heartbeat_exists_without_dialog_and_invalid_geometry_is_explained() {
        let directory = Directory::new();
        storage_check(&directory.0).expect("storage readback");
        let context = egui::Context::default();
        let mut recorder = Recorder::default();
        let _ = context.run_ui(Default::default(), |ui| {
            recorder.begin_frame(7, false);
            recorder.finish_frame(&directory.0, ui.ctx());
            recorder.last_write = None;
            recorder.record(
                &directory.0,
                ui.ctx(),
                egui::Rect::NOTHING,
                Geometry {
                    content: egui::Rect::NOTHING,
                    close: egui::Rect::NOTHING,
                    stop: egui::Rect::NOTHING,
                    sizing_pass: false,
                },
            );
        });
        let output = std::fs::read_to_string(directory.0.join("local-session-layout.jsonl"))
            .expect("layout log");
        assert!(output.contains("frame_heartbeat"));
        assert!(output.contains("geometry_rejected"));
        assert!(recorder.invalid_geometry >= 1);
    }
    #[test]
    fn write_failure_survives_until_successful_readback() {
        let directory = Directory::new();
        let path = directory.0.join("local-session-layout.jsonl");
        std::fs::create_dir(&path).expect("block metadata target with a directory");
        let mut recorder = Recorder::default();
        recorder.push(serde_json::json!({"event":"test"}));
        recorder.flush(&directory.0);
        assert!(recorder.last_write_error.is_some());
        assert!(recorder.dirty);
        std::fs::remove_dir(&path).expect("release target");
        recorder.last_write = None;
        recorder.flush(&directory.0);
        assert!(!recorder.dirty);
        assert!(
            std::fs::read_to_string(&path)
                .expect("recovered log")
                .contains("write_failed")
        );
        recorder.flush(Path::new(""));
        assert_eq!(recorder.empty_directory, 1);
    }
}
