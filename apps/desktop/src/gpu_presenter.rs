//! UI-owned child window and a bounded, cancellation-owned MF/D3D worker.
use eframe::egui;
use nestlink_media_codec::{GpuH264Presenter, GpuVideoSurface};
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

pub struct AccessUnit {
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
    worker: Option<thread::JoinHandle<()>>,
    input: Option<mpsc::SyncSender<AccessUnit>>,
    events: Option<mpsc::Receiver<Event>>,
    config: (u32, u32),
    failure_reported: bool,
    visible: Arc<AtomicBool>,
}
impl Presenter {
    pub fn new(width: u32, height: u32, generation: u64) -> Self {
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
            input: None,
            events: None,
            config: (width, height),
            failure_reported: false,
            visible: Arc::new(AtomicBool::new(false)),
        }
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
    pub fn poll(&mut self) -> Vec<Event> {
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
                let (width, height) = self.config;
                match thread::Builder::new()
                    .name("nestlink-gpu-presenter".into())
                    .spawn(move || {
                        let outcome = run(
                            surface,
                            (width, height),
                            rx,
                            &event_tx,
                            &cancel,
                            &bytes,
                            &units,
                        );
                        if let Err(error) = outcome {
                            let _ = event_tx.try_send(Event::Failed(error.to_string()));
                        }
                        let _ = event_tx.try_send(Event::Exited);
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
    }
    pub fn submit(&self, unit: AccessUnit) -> Result<(), AccessUnit> {
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
            let _ = worker.join();
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
            if thread::Builder::new()
                .name("nestlink-gpu-cleanup".into())
                .spawn(move || {
                    let worker = owned.lock().ok().and_then(|mut value| value.take());
                    if let Some(worker) = worker {
                        let _ = worker.join();
                    }
                })
                .is_err()
            {
                std::mem::forget(pending);
            }
        }
    }
}
fn run(
    surface: GpuVideoSurface,
    size: (u32, u32),
    input: mpsc::Receiver<AccessUnit>,
    events: &mpsc::SyncSender<Event>,
    cancel: &AtomicBool,
    bytes: &AtomicU64,
    units: &AtomicU64,
) -> io::Result<()> {
    let mut decoder = GpuH264Presenter::new(&surface, size.0, size.1, 30)?;
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
            events
                .try_send(Event::Presented {
                    submitted_qpc: picture.submitted_qpc,
                    gpu_converted: picture.gpu_converted,
                })
                .map_err(|_| io::Error::other("GPU event queue exhausted"))?;
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
mod tests {
    use super::*;
    fn unit(sequence: u64, bytes: usize) -> AccessUnit {
        AccessUnit {
            delivery_sequence: sequence,
            native_sequence: sequence,
            pts_90khz: sequence * 3000,
            due_qpc: 0,
            not_after_qpc: 0,
            payload: Zeroizing::new(vec![1; bytes]),
        }
    }
    #[test]
    fn accepted_reference_does_not_refund_decoder_credit() -> io::Result<()> {
        let mut presenter = Presenter::new(640, 480, 1);
        let (tx, rx) = mpsc::sync_channel(8);
        presenter.input = Some(tx);
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
        let mut presenter = Presenter::new(640, 480, 1);
        let (done, wait) = mpsc::channel();
        presenter.worker = Some(thread::spawn(move || {
            let _ = wait.recv();
        }));
        presenter.stop();
        assert!(!presenter.join_if_finished());
        done.send(()).map_err(io::Error::other)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while !presenter.join_if_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(presenter.join_if_finished());
        Ok(())
    }
}
