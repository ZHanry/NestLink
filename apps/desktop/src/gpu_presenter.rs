//! UI-owned child window and a bounded, cancellation-owned MF/D3D worker.
use crate::bridge::CompressedContext;
use crate::gpu_diagnostics::{ReceiverObservation, TerminalSink};
use eframe::egui;
use nestlink_media_codec::{GpuH264Presenter, GpuVideoSurface, VideoConfig};
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) fn gpu_config(
    context: &CompressedContext,
    width: u32,
    height: u32,
) -> io::Result<VideoConfig> {
    context.validate().map_err(io::Error::other)?;
    if width == 0
        || height == 0
        || width > 8192
        || height > 8192
        || !width.is_multiple_of(2)
        || !height.is_multiple_of(2)
        || u64::from(width) * u64::from(height) * 4 > 64 * 1024 * 1024
    {
        return Err(io::Error::other(
            "GPU requires bounded even visible geometry",
        ));
    }
    let (fps, bitrate_kbps) =
        if let Some(format) = context.video_format().map_err(io::Error::other)? {
            if format.width != width
                || format.height != height
                || format.frame_rate.denominator != 1
                || !(1..=120).contains(&format.frame_rate.numerator)
            {
                return Err(io::Error::other(
                    "confirmed format is not executable by the GPU owner",
                ));
            }
            (format.frame_rate.numerator, format.max_kbps)
        } else {
            // Legacy local defaults are never an executable negotiated-format receipt.
            (30, 4000)
        };
    if !(64..=100_000).contains(&bitrate_kbps) {
        return Err(io::Error::other("GPU bitrate is outside executable bounds"));
    }
    Ok(VideoConfig {
        width,
        height,
        fps,
        bitrate_kbps,
    })
}

pub struct AccessUnit {
    pub context: Arc<CompressedContext>,
    pub delivery_sequence: u64,
    pub native_sequence: u64,
    pub pts_90khz: u64,
    pub due_qpc: u64,
    pub not_after_qpc: u64,
    pub payload: Zeroizing<Vec<u8>>,
}
pub enum Event {
    Prepared,
    Decoded {
        delivery_sequence: u64,
        native_sequence: u64,
        pts_90khz: u64,
    },
    Presented {
        submitted_qpc: Option<u64>,
        gpu_converted: bool,
    },
    Failed(String),
    Exited,
}
struct PaintState {
    generation: u64,
    active: bool,
    surface: Option<GpuVideoSurface>,
    failure: Option<String>,
    authority_deadline: u64,
}
pub struct Presenter {
    paint: Arc<Mutex<PaintState>>,
    cancel: Arc<AtomicBool>,
    queued_bytes: Arc<AtomicU64>,
    queued_units: Arc<AtomicU64>,
    worker: Option<thread::JoinHandle<ReceiverObservation>>,
    observation: Arc<Mutex<ReceiverObservation>>,
    terminal_sink: Option<TerminalSink>,
    input: Option<mpsc::SyncSender<AccessUnit>>,
    events: Option<mpsc::Receiver<Event>>,
    config: VideoConfig,
    context: Arc<CompressedContext>,
    failure_reported: bool,
    visible: Arc<AtomicBool>,
}
impl Presenter {
    pub fn for_context(
        width: u32,
        height: u32,
        generation: u64,
        context: CompressedContext,
    ) -> io::Result<Self> {
        Ok(Self::new(
            gpu_config(&context, width, height)?,
            generation,
            context,
        ))
    }
    pub fn context(&self) -> Arc<CompressedContext> {
        self.context.clone()
    }
    pub fn observation_handle(&self) -> Arc<Mutex<ReceiverObservation>> {
        self.observation.clone()
    }
    pub fn new(config: VideoConfig, generation: u64, context: CompressedContext) -> Self {
        let VideoConfig { width, height, .. } = config;
        Self {
            paint: Arc::new(Mutex::new(PaintState {
                generation,
                active: true,
                surface: None,
                failure: None,
                authority_deadline: 0,
            })),
            cancel: Arc::new(AtomicBool::new(false)),
            queued_bytes: Arc::new(AtomicU64::new(0)),
            queued_units: Arc::new(AtomicU64::new(0)),
            worker: None,
            terminal_sink: None,
            observation: Arc::new(Mutex::new(ReceiverObservation {
                generation,
                width,
                height,
                ..ReceiverObservation::default()
            })),
            input: None,
            events: None,
            config,
            context: Arc::new(context),
            failure_reported: false,
            visible: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn with_terminal_sink(mut self, sink: TerminalSink) -> Self {
        self.terminal_sink = Some(sink);
        self
    }
    /// Call only in the real native remote viewport. No GL/D3D interop occurs.
    pub fn paint(&self, ui: &egui::Ui, rect: egui::Rect, overlay_blocked: bool) {
        let state = self.paint.clone();
        let visible = self.visible.clone();
        let context = ui.ctx().clone();
        let layer = ui.layer_id();
        let generation = state.lock().map(|s| s.generation).unwrap_or(0);
        let blocked = overlay_blocked || !ui.clip_rect().contains_rect(rect);
        ui.painter().add(egui::PaintCallback {
            rect,
            callback: Arc::new(egui_glow::CallbackFn::new(move |info, _| {
                let overlay = egui::Popup::is_any_open(&context)
                    || context.memory(|memory| {
                        memory.top_modal_layer().is_some()
                            || memory.areas().visible_layer_ids().iter().any(|candidate| {
                                candidate.order > layer.order
                                    && memory
                                        .area_rect(candidate.id)
                                        .is_some_and(|area| area.intersects(rect))
                            })
                    });
                let Ok(mut state) = state.lock() else {
                    return;
                };
                if state.generation != generation
                    || !state.active
                    || blocked
                    || overlay
                    || !info.clip_rect.contains_rect(info.viewport)
                {
                    visible.store(false, Ordering::Release);
                    if let Some(surface) = &state.surface {
                        surface.revoke();
                    }
                    return;
                }
                if state.surface.is_none() && state.failure.is_none() {
                    match GpuVideoSurface::discover(generation, info.screen_size_px) {
                        Ok(surface) => state.surface = Some(surface),
                        Err(error) => state.failure = Some(error.to_string()),
                    }
                }
                if let Some(surface) = &state.surface {
                    surface.set_authority_deadline(state.authority_deadline);
                    if state.authority_deadline == 0 {
                        visible.store(false, Ordering::Release);
                        surface.revoke();
                        return;
                    }
                    let viewport = info.viewport_in_pixels();
                    let result = surface.place(
                        viewport.left_px,
                        viewport.top_px,
                        viewport.width_px.max(0) as u32,
                        viewport.height_px.max(0) as u32,
                        true,
                    );
                    visible.store(result.is_ok(), Ordering::Release);
                    if let Err(error) = result {
                        state.failure = Some(error.to_string());
                    }
                }
            })),
        });
    }
    pub fn observation(&self) -> Option<ReceiverObservation> {
        let mut value = self.observation.try_lock().ok()?.clone();
        value.revoked = self.cancel.load(Ordering::Acquire);
        Some(value)
    }
    pub fn visible(&self) -> bool {
        self.visible.load(Ordering::Acquire)
    }
    pub fn authority_deadline(&self, deadline_qpc: u64) {
        if let Ok(mut state) = self.paint.lock() {
            state.authority_deadline = deadline_qpc;
            if let Some(surface) = &state.surface {
                surface.set_authority_deadline(deadline_qpc);
            }
        }
    }
    pub fn poll(&mut self) -> Vec<(Arc<CompressedContext>, Event)> {
        let mut result = Vec::new();
        if !self.failure_reported
            && let Ok(state) = self.paint.lock()
            && let Some(error) = &state.failure
        {
            result.push(Event::Failed(error.clone()));
            self.failure_reported = true;
        }
        if self.worker.is_none()
            && !self.cancel.load(Ordering::Acquire)
            && self
                .paint
                .lock()
                .is_ok_and(|state| state.authority_deadline > 0)
        {
            let surface = self
                .paint
                .lock()
                .ok()
                .and_then(|state| state.surface.clone());
            if let Some(surface) = surface {
                let (tx, rx) = mpsc::sync_channel(8);
                let (event_tx, event_rx) = mpsc::sync_channel(32);
                let cancel = self.cancel.clone();
                let bytes = self.queued_bytes.clone();
                let units = self.queued_units.clone();
                let config = self.config;
                let owner_context = self.context.clone();
                let observation = self.observation.clone();
                let mut observed = self
                    .observation
                    .lock()
                    .map(|value| value.clone())
                    .unwrap_or_default();
                match thread::Builder::new()
                    .name("nestlink-gpu-presenter".into())
                    .spawn(move || {
                        observed.worker_started = true;
                        let outcome = run(
                            surface,
                            (config, owner_context),
                            rx,
                            &event_tx,
                            &cancel,
                            (&bytes, &units),
                            (&mut observed, &observation),
                        );
                        if let Err(error) = outcome {
                            observed.failed = true;
                            let _ = event_tx.try_send(Event::Failed(error.to_string()));
                        }
                        let _ = event_tx.try_send(Event::Exited);
                        // The returned snapshot is consumed only after a real join.
                        // Intermediate try_lock publication can skip a sample,
                        // but never loses the worker's cumulative final facts.
                        observed
                    }) {
                    Ok(worker) => {
                        self.worker = Some(worker);
                        self.input = Some(tx);
                        self.events = Some(event_rx);
                    }
                    Err(error) => result.push(Event::Failed(error.to_string())),
                }
            }
        }
        if let Some(events) = &self.events {
            result.extend(events.try_iter());
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && !result
                .iter()
                .any(|event| matches!(event, Event::Exited | Event::Failed(_)))
        {
            result.push(Event::Exited);
        }
        result
            .into_iter()
            .map(|event| (self.context.clone(), event))
            .collect()
    }
    pub fn submit(&self, unit: AccessUnit) -> Result<(), AccessUnit> {
        if unit.context != self.context {
            return Err(unit);
        }
        let Some(input) = &self.input else {
            return Err(unit);
        };
        let length = unit.payload.len() as u64;
        if length == 0 || length > 8 * 1024 * 1024 || self.cancel.load(Ordering::Acquire) {
            return Err(unit);
        }
        if self
            .queued_units
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 8).then_some(count + 1)
            })
            .is_err()
        {
            return Err(unit);
        }
        if self
            .queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(length)
                    .filter(|next| *next <= 32 * 1024 * 1024)
            })
            .is_err()
        {
            self.queued_units.fetch_sub(1, Ordering::AcqRel);
            return Err(unit);
        }
        match input.try_send(unit) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.queued_bytes.fetch_sub(length, Ordering::AcqRel);
                self.queued_units.fetch_sub(1, Ordering::AcqRel);
                Err(match error {
                    mpsc::TrySendError::Full(v) | mpsc::TrySendError::Disconnected(v) => v,
                })
            }
        }
    }
    pub fn stop(&mut self) {
        self.visible.store(false, Ordering::Release);
        self.cancel.store(true, Ordering::Release);
        self.input = None;
        if let Ok(mut state) = self.paint.lock() {
            state.active = false;
            if let Some(surface) = &state.surface {
                surface.revoke();
                surface.set_authority_deadline(0);
            }
        }
    }
    pub fn join_if_finished(&mut self) -> bool {
        if self
            .worker
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            && let Some(worker) = self.worker.take()
        {
            record_join(
                &self.observation,
                worker.join(),
                self.cancel.load(Ordering::Acquire),
                self.terminal_sink.as_ref(),
            );
        }
        if self.worker.is_none()
            && self.cancel.load(Ordering::Acquire)
            && let Ok(state) = self.paint.lock()
            && let Some(surface) = &state.surface
        {
            surface.detach();
        }
        self.worker.is_none()
    }
}
impl Drop for Presenter {
    fn drop(&mut self) {
        self.stop();
        if self.join_if_finished() {
            return;
        }
        if let Some(worker) = self.worker.take() {
            // Retain the join owner even when UI closes while a driver call runs.
            let pending = Arc::new(Mutex::new(Some(worker)));
            let owned = pending.clone();
            let observation = self.observation.clone();
            let terminal_sink = self.terminal_sink.clone();
            let cancel = self.cancel.clone();
            if thread::Builder::new()
                .name("nestlink-gpu-cleanup".into())
                .spawn(move || {
                    let worker = owned.lock().ok().and_then(|mut value| value.take());
                    if let Some(worker) = worker {
                        record_join(
                            &observation,
                            worker.join(),
                            cancel.load(Ordering::Acquire),
                            terminal_sink.as_ref(),
                        );
                    }
                })
                .is_err()
            {
                std::mem::forget(pending);
            }
        }
    }
}
fn record_join(
    shared: &Arc<Mutex<ReceiverObservation>>,
    result: thread::Result<ReceiverObservation>,
    revoked: bool,
    sink: Option<&TerminalSink>,
) {
    let mut final_value = match result {
        Ok(value) => value,
        Err(_) => {
            let mut value = shared.lock().map(|value| value.clone()).unwrap_or_default();
            value.failed = true;
            value.worker_panicked = true;
            value
        }
    };
    final_value.worker_joined = true;
    final_value.revoked = revoked;
    final_value.terminal_write_pending = sink.is_some();
    final_value.terminal_write_durable = None;
    if let Ok(mut value) = shared.lock() {
        *value = final_value.clone();
    }
    // The durable consumer is retained with the same JoinHandle in Drop; it
    // does not depend on another UI frame or an IPC feedback acknowledgement.
    if let Some(sink) = sink {
        sink.enqueue(final_value, shared.clone());
    }
}
fn run(
    surface: GpuVideoSurface,
    target: (VideoConfig, Arc<CompressedContext>),
    input: mpsc::Receiver<AccessUnit>,
    events: &mpsc::SyncSender<Event>,
    cancel: &AtomicBool,
    queued: (&AtomicU64, &AtomicU64),
    telemetry: (&mut ReceiverObservation, &Mutex<ReceiverObservation>),
) -> io::Result<()> {
    let (bytes, units) = queued;
    let (observed, observation) = telemetry;
    let (config, owner_context) = target;
    let expected = gpu_config(&owner_context, config.width, config.height)?;
    if config.fps != expected.fps || config.bitrate_kbps != expected.bitrate_kbps {
        return Err(io::Error::other(
            "GPU worker target differs from confirmed format",
        ));
    }
    let mut decoder = GpuH264Presenter::with_config(&surface, config)?;
    observed.decoder_opened = true;
    observed.qpc_frequency = nestlink_media_codec::gpu_qpc()
        .ok()
        .map(|(_, frequency)| frequency);
    events
        .try_send(Event::Prepared)
        .map_err(|_| io::Error::other("GPU event owner unavailable"))?;
    let mut front = None;
    let mut pending = VecDeque::new();
    let mut progress = Instant::now();
    while !cancel.load(Ordering::Acquire) {
        if front.is_none() {
            front = input.try_recv().ok();
        }
        let step = if let Some(unit) = &front {
            if unit.context != owner_context {
                return Err(io::Error::other(
                    "GPU input belongs to another format owner",
                ));
            }
            decoder.submit_scheduled(
                unit.native_sequence,
                unit.pts_90khz,
                &unit.payload,
                unit.due_qpc,
                unit.not_after_qpc,
            )?
        } else {
            decoder.poll()?
        };
        if step.accepted
            && let Some(unit) = front.take()
        {
            if pending.is_empty() {
                progress = Instant::now();
            }
            observed.accepted = observed.accepted.saturating_add(1);
            observed.last_accepted_pts = Some(unit.pts_90khz);
            pending.push_back((
                unit.delivery_sequence,
                unit.native_sequence,
                unit.payload.len() as u64,
            ));
        }
        if let Some((sequence, pts_90khz)) = step.decoded {
            let Some((delivery_sequence, native_sequence, length)) = pending.pop_front() else {
                return Err(io::Error::other("unbound GPU output"));
            };
            if native_sequence != sequence {
                return Err(io::Error::other("GPU output sequence mismatch"));
            }
            observed.decoded = observed.decoded.saturating_add(1);
            observed.last_decoded_pts = Some(pts_90khz);
            bytes.fetch_sub(length, Ordering::AcqRel);
            units.fetch_sub(1, Ordering::AcqRel);
            events
                .try_send(Event::Decoded {
                    delivery_sequence,
                    native_sequence,
                    pts_90khz,
                })
                .map_err(|_| io::Error::other("GPU event queue exhausted"))?;
            progress = Instant::now();
        }
        if let Some(picture) = step.picture {
            observed.retired = observed.retired.saturating_add(1);
            observed.last_retired_pts = Some(picture.pts_90khz);
            if picture.gpu_converted {
                observed.converted = observed.converted.saturating_add(1);
            }
            if let Some(qpc) = picture.submitted_qpc {
                observed.submitted = observed.submitted.saturating_add(1);
                observed.last_submitted_qpc = Some(qpc);
                observed.last_submitted_pts = Some(picture.pts_90khz);
            }
            events
                .try_send(Event::Presented {
                    submitted_qpc: picture.submitted_qpc,
                    gpu_converted: picture.gpu_converted,
                })
                .map_err(|_| io::Error::other("GPU event queue exhausted"))?;
        }
        // Diagnostic contention never blocks media or changes delivery credit.
        if let Ok(mut value) = observation.try_lock() {
            *value = observed.clone();
        }
        if (!pending.is_empty() || front.is_some()) && progress.elapsed() > Duration::from_secs(2) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "GPU decoder progress deadline",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
    surface.revoke();
    Ok(())
}

#[cfg(test)]
pub(super) fn test_context() -> CompressedContext {
    CompressedContext {
        ipc_version: 2,
        catalog_sha256: [1; 32],
        format_epoch: 0,
        format_sha256: [0; 32],
        format: None,
        binding: nestlink_app_ipc::compressed_video::NativeCompressedBinding {
            runtime_id: "runtime".into(),
            ui_generation: 1,
            request_id: "request".into(),
            connection_generation: 1,
            source: 1,
            stream_id: [1; 16],
            stream_epoch: 1,
        },
        catalog_revision: 1,
        selection_sequence: 1,
        layout_epoch: 1,
        decode_epoch: 1,
        configuration_id: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unit(sequence: u64, bytes: usize) -> AccessUnit {
        AccessUnit {
            context: Arc::new(test_context()),
            delivery_sequence: sequence,
            native_sequence: sequence,
            pts_90khz: sequence * 3000,
            due_qpc: 0,
            not_after_qpc: 0,
            payload: Zeroizing::new(vec![1; bytes]),
        }
    }
    #[test]
    fn confirmed_gpu_target_preserves_rate_and_rejects_odd_fractional_or_foreign_geometry()
    -> Result<(), Box<dyn std::error::Error>> {
        use nestlink_app_ipc::compressed_video::WireVideoFormat;
        use nestlink_protocol::media_format::{FrameRate, VideoFormat};
        let mut context = test_context();
        let format = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(60, 1)?, 3000)?;
        context.format_epoch = 1;
        context.format_sha256 = format.digest()?;
        context.format = Some(WireVideoFormat::new(format)?);
        let config = gpu_config(&context, 640, 480)?;
        assert_eq!(
            (config.width, config.height, config.fps, config.bitrate_kbps),
            (640, 480, 60, 3000)
        );
        assert!(gpu_config(&context, 321, 241).is_err());
        assert!(gpu_config(&context, 642, 480).is_err());
        let fractional =
            VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30000, 1001)?, 3000)?;
        context.format_sha256 = fractional.digest()?;
        context.format = Some(WireVideoFormat::new(fractional)?);
        assert!(gpu_config(&context, 640, 480).is_err());
        for bitrate_kbps in [1, 100_001] {
            let mut out_of_bounds = format;
            out_of_bounds.max_kbps = bitrate_kbps;
            context.format_sha256 = out_of_bounds.digest()?;
            context.format = Some(WireVideoFormat::new(out_of_bounds)?);
            assert!(gpu_config(&context, 640, 480).is_err());
        }
        let legacy = gpu_config(&test_context(), 640, 480)?;
        assert_eq!((legacy.fps, legacy.bitrate_kbps), (30, 4000));
        assert!(gpu_config(&test_context(), 321, 241).is_err());
        Ok(())
    }
    #[test]
    fn accepted_reference_does_not_refund_decoder_credit() -> io::Result<()> {
        let mut presenter =
            Presenter::new(gpu_config(&test_context(), 640, 480)?, 1, test_context());
        let (tx, rx) = mpsc::sync_channel(8);
        presenter.input = Some(tx);
        for field in 0..3 {
            let mut foreign = unit(1, 16);
            match field {
                0 => Arc::make_mut(&mut foreign.context).format_epoch += 1,
                1 => Arc::make_mut(&mut foreign.context).format_sha256[0] ^= 1,
                _ => Arc::make_mut(&mut foreign.context).catalog_sha256[0] ^= 1,
            }
            assert!(presenter.submit(foreign).is_err());
        }
        assert_eq!(presenter.queued_units.load(Ordering::Acquire), 0);
        for sequence in 1..=8 {
            assert!(presenter.submit(unit(sequence, 16)).is_ok());
        }
        let _accepted = rx.recv().map_err(io::Error::other)?;
        // Removing an AU from transport is not decoder output. The ninth is retained.
        let rejected = presenter
            .submit(unit(9, 16))
            .err()
            .ok_or_else(|| io::Error::other("credit refunded at acceptance"))?;
        assert_eq!(rejected.native_sequence, 9);
        assert_eq!(presenter.queued_units.load(Ordering::Acquire), 8);
        presenter.stop();
        assert!(presenter.submit(unit(10, 16)).is_err());
        Ok(())
    }
    #[test]
    fn cancelled_worker_is_not_reported_joined_early() -> io::Result<()> {
        let mut presenter =
            Presenter::new(gpu_config(&test_context(), 640, 480)?, 1, test_context());
        let (done, wait) = mpsc::channel();
        presenter.worker = Some(thread::spawn(move || {
            let _ = wait.recv();
            ReceiverObservation {
                generation: 1,
                worker_started: true,
                decoder_opened: true,
                accepted: 1,
                decoded: 1,
                last_accepted_pts: Some(0),
                last_decoded_pts: Some(0),
                ..ReceiverObservation::default()
            }
        }));
        presenter.stop();
        assert!(!presenter.join_if_finished());
        assert!(
            !presenter
                .observation()
                .ok_or_else(|| io::Error::other("observation unavailable"))?
                .worker_joined
        );
        done.send(()).map_err(io::Error::other)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while !presenter.join_if_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(presenter.join_if_finished());
        let final_value = presenter
            .observation()
            .ok_or_else(|| io::Error::other("final observation unavailable"))?;
        assert!(final_value.worker_joined && final_value.revoked);
        assert_eq!(final_value.last_decoded_pts, Some(0));
        assert_eq!(final_value.accepted, 1);
        assert_eq!(final_value.decoded, 1);
        assert_eq!(final_value.submitted, 0);
        Ok(())
    }
}
