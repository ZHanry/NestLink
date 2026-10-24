//! Glue between exact compressed IPC epochs and the UI-owned native presenter.
use super::*;
use bridge::{CompressedContext, CompressedVideoFeedback, CompressedVideoUpdate};
use gpu_presenter::{AccessUnit, Event, Presenter};

pub(super) struct GpuVideo {
    enabled: bool,
    diagnostics: super::gpu_diagnostics::Recorder,
    context: Option<CompressedContext>,
    presenter: Option<Presenter>,
    retiring: Option<(CompressedContext, Presenter)>,
    pending: Option<AccessUnit>,
    pending_prepare: Option<(CompressedContext, u32, u32)>,
    generation: u64,
    pub submitted: bool,
    pub submitted_count: u64,
    pub converted_count: u64,
    pub last_submitted_qpc: Option<u64>,
}
impl Default for GpuVideo {
    fn default() -> Self {
        Self {
            diagnostics: super::gpu_diagnostics::Recorder::default(),
            enabled: std::env::var_os("NESTLINK_DESKTOP_GPU_PRESENT").is_some_and(|v| v == "1"),
            context: None,
            presenter: None,
            retiring: None,
            pending: None,
            pending_prepare: None,
            generation: 0,
            submitted: false,
            submitted_count: 0,
            converted_count: 0,
            last_submitted_qpc: None,
        }
    }
}
impl GpuVideo {
    #[cfg(test)]
    pub(super) fn layout_active_presenter() -> Self {
        Self {
            enabled: true,
            presenter: Some(Presenter::new(
                nestlink_media_codec::VideoConfig {
                    width: 640,
                    height: 480,
                    fps: 30,
                    bitrate_kbps: 4000,
                },
                1,
                gpu_presenter::test_context(),
            )),
            submitted: true,
            ..Self::default()
        }
    }
    pub fn stop(&mut self) {
        self.pending = None;
        self.pending_prepare = None;
        self.submitted = false;
        if let Some(mut presenter) = self.presenter.take() {
            presenter.stop();
            if let Some(context) = self.context.take() {
                self.retiring = Some((context, presenter));
            }
        }
    }
    pub fn paint(&self, ui: &egui::Ui, rect: egui::Rect) {
        if let Some(presenter) = &self.presenter {
            presenter.paint(ui, rect, false);
        }
    }
    pub fn has_diagnostics(&self) -> bool {
        self.diagnostics.has_observations()
    }
    pub fn diagnostics_export(&self) -> Option<serde_json::Value> {
        self.diagnostics
            .has_observations()
            .then(|| self.diagnostics.export())
    }
    pub fn active(&self) -> bool {
        self.presenter.is_some()
    }
    pub fn ready(&self) -> bool {
        self.submitted && self.presenter.as_ref().is_some_and(Presenter::visible)
    }
}
impl DesktopApp {
    pub(super) fn poll_gpu_cleanup(&mut self, context: &egui::Context) {
        if let Some((binding, presenter)) = &mut self.gpu_video.retiring {
            context.request_repaint_after(Duration::from_millis(16));
            let joined = presenter.join_if_finished();
            if let Some(value) = presenter.observation() {
                self.gpu_video.diagnostics.observe(binding, value, joined);
            }
            if joined {
                self.gpu_video
                    .diagnostics
                    .track_terminal(presenter.observation_handle());
            }
            if joined
                && self
                    .bridge
                    .compressed_feedback(CompressedVideoFeedback::Stopped {
                        context: binding.clone(),
                        joined: true,
                    })
            {
                self.gpu_video.retiring = None;
            }
        }
        if let (Some(binding), Some(presenter)) =
            (&self.gpu_video.context, &self.gpu_video.presenter)
            && let Some(value) = presenter.observation()
        {
            self.gpu_video.diagnostics.observe(binding, value, false);
        }
        self.gpu_video.diagnostics.read_terminal(&self.directory);
        self.gpu_video.diagnostics.flush(&self.directory);
        if self.gpu_video.diagnostics.needs_flush() {
            context.request_repaint_after(Duration::from_secs(1));
        }
    }
    pub(super) fn update_gpu_video(
        &mut self,
        context: &egui::Context,
        snapshot: &Snapshot,
        interested: bool,
        viewport_class: egui::ViewportClass,
    ) -> bool {
        self.poll_gpu_cleanup(context);
        let gpu = &mut self.gpu_video;
        // Embedded egui windows share the root HWND. Only a real native remote
        // viewport may discover/create the child surface; otherwise use CPU.
        let interested = interested && viewport_class == egui::ViewportClass::Immediate;
        self.bridge
            .enable_compressed_video(gpu.enabled && interested);
        if !gpu.enabled || !interested {
            let was_active = gpu.active();
            gpu.stop();
            if was_active {
                self.release_native_control();
            }
            return false;
        }
        context.request_repaint_after(Duration::from_millis(16));
        if gpu.presenter.is_some() && !self.bridge.compressed_authorized() {
            gpu.stop();
            self.release_native_control();
            return true;
        }
        let runtime = self.bridge.runtime_id();
        if gpu.context.as_ref().is_some_and(|binding| {
            !compressed_current(
                binding,
                snapshot,
                runtime.as_deref(),
                self.bridge.native_displays().as_ref(),
            )
        }) {
            gpu.stop();
            self.release_native_control();
            return true;
        }
        let mut release_input = false;
        let mut failed = false;
        if gpu.retiring.is_none()
            && let Some((binding, width, height)) = gpu.pending_prepare.take()
        {
            if !compressed_current(
                &binding,
                snapshot,
                runtime.as_deref(),
                self.bridge.native_displays().as_ref(),
            ) {
                failed = true;
            } else {
                release_input = true;
                gpu.generation = gpu.generation.checked_add(1).unwrap_or(0);
                if gpu.generation == 0 {
                    failed = true;
                } else {
                    gpu.presenter = match Presenter::for_context(
                        width,
                        height,
                        gpu.generation,
                        binding.clone(),
                    ) {
                        Ok(presenter) => Some(presenter.with_terminal_sink(
                            super::gpu_diagnostics::TerminalSink::new(&self.directory, &binding),
                        )),
                        Err(_) => {
                            failed = true;
                            None
                        }
                    };
                    self.video_texture = None;
                    self.video_observation = None;
                    self.video_binding = Some(nestlink_app_ipc::NativeVideoBinding {
                        runtime_id: binding.binding.runtime_id.clone(),
                        ui_generation: binding.binding.ui_generation,
                        request_id: binding.binding.request_id.clone(),
                        connection_generation: binding.binding.connection_generation,
                        source: binding.binding.source,
                    });
                    self.video_layout = Some((binding.layout_epoch, width, height));
                    self.video_status = VideoStatus::WaitingForFrame;
                    gpu.context = Some(binding);
                }
            }
        }
        if let Some(presenter) = &mut gpu.presenter {
            presenter.authority_deadline(self.bridge.compressed_authority_deadline());
            for (event_context, event) in presenter.poll() {
                let Some(binding) = gpu.context.clone() else {
                    failed = true;
                    break;
                };
                if event_context.as_ref() != &binding {
                    failed = true;
                    break;
                }
                match event {
                    Event::Prepared => {
                        if !self
                            .bridge
                            .compressed_feedback(CompressedVideoFeedback::Prepared {
                                context: binding,
                            })
                        {
                            failed = true;
                        }
                    }
                    Event::Decoded {
                        delivery_sequence,
                        native_sequence,
                        pts_90khz,
                    } => {
                        if !self
                            .bridge
                            .compressed_feedback(CompressedVideoFeedback::Decoded {
                                context: binding,
                                delivery_sequence,
                                native_sequence,
                                pts_90khz,
                            })
                        {
                            failed = true;
                        }
                    }
                    Event::Presented {
                        submitted_qpc,
                        gpu_converted,
                    } => {
                        if gpu_converted {
                            gpu.converted_count = gpu.converted_count.saturating_add(1);
                        }
                        if let Some(qpc) = submitted_qpc {
                            gpu.submitted = true;
                            gpu.submitted_count = gpu.submitted_count.saturating_add(1);
                            gpu.last_submitted_qpc = Some(qpc);
                            self.video_status = VideoStatus::Streaming;
                        }
                    }
                    Event::Failed(error) => {
                        eprintln!("NestLink GPU presenter fallback: {error}");
                        failed = true;
                    }
                    Event::Exited => {
                        failed = true;
                    }
                }
            }
        }
        if failed {
            gpu.enabled = false;
            gpu.stop();
            self.bridge.enable_compressed_video(false);
            self.release_native_control();
            return false;
        }
        if let Some(unit) = gpu.pending.take() {
            let Some(presenter) = &gpu.presenter else {
                gpu.enabled = false;
                self.bridge.enable_compressed_video(false);
                return false;
            };
            if let Err(unit) = presenter.submit(unit) {
                gpu.pending = Some(unit);
                return true;
            }
        }
        // One producer FIFO; never replace an unaccepted compressed reference.
        for _ in 0..10 {
            let Some(update) = self.bridge.take_compressed_update() else {
                break;
            };
            match update {
                CompressedVideoUpdate::Stopped => {
                    release_input = true;
                    gpu.stop();
                    break;
                }
                CompressedVideoUpdate::Preparing {
                    context: binding,
                    width,
                    height,
                } => {
                    if !compressed_current(
                        &binding,
                        snapshot,
                        runtime.as_deref(),
                        self.bridge.native_displays().as_ref(),
                    ) || !valid_video_geometry(width, height)
                    {
                        failed = true;
                        break;
                    }
                    if gpu.context.as_ref() == Some(&binding) {
                        continue;
                    }
                    release_input = true;
                    gpu.stop();
                    // Do not accumulate a second GPU/device owner while an old driver is stuck.
                    if gpu.retiring.is_some() {
                        gpu.pending_prepare = Some((binding, width, height));
                        break;
                    }
                    gpu.generation = gpu.generation.checked_add(1).unwrap_or(0);
                    if gpu.generation == 0 {
                        failed = true;
                        break;
                    }
                    gpu.presenter = match Presenter::for_context(
                        width,
                        height,
                        gpu.generation,
                        binding.clone(),
                    ) {
                        Ok(presenter) => Some(presenter.with_terminal_sink(
                            super::gpu_diagnostics::TerminalSink::new(&self.directory, &binding),
                        )),
                        Err(_) => {
                            failed = true;
                            None
                        }
                    };
                    gpu.context = Some(binding.clone());
                    self.video_texture = None;
                    self.video_observation = None;
                    self.video_binding = Some(nestlink_app_ipc::NativeVideoBinding {
                        runtime_id: binding.binding.runtime_id.clone(),
                        ui_generation: binding.binding.ui_generation,
                        request_id: binding.binding.request_id.clone(),
                        connection_generation: binding.binding.connection_generation,
                        source: binding.binding.source,
                    });
                    self.video_layout = Some((binding.layout_epoch, width, height));
                    self.video_status = VideoStatus::WaitingForFrame;
                }
                CompressedVideoUpdate::AccessUnit {
                    context: binding,
                    delivery_sequence,
                    native_sequence,
                    pts_90khz,
                    due_qpc,
                    not_after_qpc,
                    keyframe,
                    payload,
                } => {
                    if gpu.context.as_ref() != Some(&binding)
                        || !self.bridge.compressed_authorized()
                        || (delivery_sequence == 1 && !keyframe)
                    {
                        failed = true;
                        break;
                    }
                    let Some(presenter) = &gpu.presenter else {
                        failed = true;
                        break;
                    };
                    let owner_context = presenter.context();
                    if owner_context.as_ref() != &binding {
                        failed = true;
                        break;
                    }
                    let unit = AccessUnit {
                        context: owner_context,
                        delivery_sequence,
                        native_sequence,
                        pts_90khz,
                        due_qpc,
                        not_after_qpc,
                        payload,
                    };
                    if let Err(unit) = presenter.submit(unit) {
                        gpu.pending = Some(unit);
                        break;
                    }
                }
            }
        }
        if failed {
            gpu.enabled = false;
            gpu.stop();
            self.bridge.enable_compressed_video(false);
            self.release_native_control();
            return false;
        }
        if let Some(presenter) = &gpu.presenter {
            presenter.authority_deadline(self.bridge.compressed_authority_deadline());
        }
        let active = gpu.active() || gpu.pending_prepare.is_some() || gpu.retiring.is_some();
        if release_input {
            self.release_native_control();
        }
        active
    }
}
fn compressed_current(
    context: &CompressedContext,
    snapshot: &Snapshot,
    runtime: Option<&str>,
    displays: Option<&nestlink_app_core::NativeDisplayState>,
) -> bool {
    let binding = &context.binding;
    context.validate().is_ok()
        && runtime == Some(binding.runtime_id.as_str())
        && snapshot.generation == binding.ui_generation
        && snapshot.native_session.data.as_ref().is_some_and(|s| {
            s.status == NativeSessionStatus::Connected
                && s.request_id == binding.request_id
                && s.connection_generation == binding.connection_generation
        })
        && displays
            .filter(|d| {
                d.format_epoch == context.format_epoch && d.format_sha256 == context.format_sha256
            })
            .and_then(|d| d.selected.as_ref())
            .is_some_and(|selected| {
                selected.source == binding.source
                    && selected.layout_epoch == context.layout_epoch
                    && selected.sequence == context.selection_sequence
                    && selected.catalog.revision == context.catalog_revision
                    && selected.catalog.sha256 == context.catalog_sha256
                    && selected.catalog.request_id == binding.request_id
                    && selected.catalog.connection_generation == binding.connection_generation
            })
}
