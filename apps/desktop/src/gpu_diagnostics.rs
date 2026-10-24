//! Scalar observations from the real receiver worker, never synthetic probes.
use crate::bridge::CompressedContext;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum IoKind {
    Terminal,
    Report,
    Read,
}
struct IoJob {
    kind: IoKind,
    run: Box<dyn FnOnce() + Send>,
    cancel: Box<dyn FnOnce() + Send>,
}
struct BackgroundIo {
    queue: Arc<(Mutex<VecDeque<IoJob>>, Condvar)>,
    // Retained for the process lifetime, never one thread per UI frame/worker.
    _worker: std::thread::JoinHandle<()>,
}
static DROPPED_WRITES: AtomicU64 = AtomicU64::new(0);
impl BackgroundIo {
    fn new() -> std::io::Result<Self> {
        let queue = Arc::new((Mutex::new(VecDeque::<IoJob>::new()), Condvar::new()));
        let owned = queue.clone();
        let worker = std::thread::Builder::new()
            .name("nestlink-gpu-diagnostics-io".into())
            .spawn(move || {
                loop {
                    let job = {
                        let (lock, wake) = &*owned;
                        let mut jobs = lock.lock().unwrap_or_else(|poison| poison.into_inner());
                        while jobs.is_empty() {
                            jobs = wake.wait(jobs).unwrap_or_else(|poison| poison.into_inner());
                        }
                        jobs.pop_front()
                    };
                    let Some(job) = job else {
                        continue;
                    };
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.run)).is_err() {
                        (job.cancel)();
                    }
                }
            })?;
        Ok(Self {
            queue,
            _worker: worker,
        })
    }
    fn submit(&self, job: IoJob) {
        let evicted = {
            let (lock, wake) = &*self.queue;
            let mut jobs = lock.lock().unwrap_or_else(|poison| poison.into_inner());
            let position = if job.kind != IoKind::Terminal {
                jobs.iter().position(|old| old.kind == job.kind)
            } else if jobs
                .iter()
                .filter(|old| old.kind == IoKind::Terminal)
                .count()
                >= 16
            {
                jobs.iter().position(|old| old.kind == IoKind::Terminal)
            } else {
                None
            };
            let evicted = position.and_then(|index| jobs.remove(index));
            jobs.push_back(job);
            wake.notify_one();
            evicted
        };
        if let Some(job) = evicted {
            DROPPED_WRITES.fetch_add(1, Ordering::Relaxed);
            (job.cancel)();
        }
    }
}
fn background_io() -> Option<&'static BackgroundIo> {
    static WRITER: OnceLock<Option<BackgroundIo>> = OnceLock::new();
    WRITER.get_or_init(|| BackgroundIo::new().ok()).as_ref()
}
#[derive(Clone, Copy, Default)]
struct CommitState {
    finished: bool,
    failed: bool,
    durable: Option<bool>,
}
struct ReadSnapshot {
    terminal: Option<serde_json::Value>,
    host: Option<serde_json::Value>,
}
fn queue_write(
    path: PathBuf,
    bytes: Vec<u8>,
    kind: IoKind,
    complete: impl Fn(CommitState) + Send + Sync + 'static,
) {
    let complete = Arc::new(complete);
    let Some(writer) = background_io() else {
        complete(CommitState {
            finished: true,
            failed: true,
            durable: None,
        });
        return;
    };
    let cancelled = complete.clone();
    writer.submit(IoJob {
        kind,
        run: Box::new(move || {
            let result = nestlink_platform_security::replace_private_metadata(&path, &bytes);
            complete(CommitState {
                finished: true,
                failed: result.is_err(),
                durable: result.ok().map(|commit| {
                    matches!(commit, nestlink_platform_security::MetadataCommit::Durable)
                }),
            });
        }),
        cancel: Box::new(move || {
            cancelled(CommitState {
                finished: true,
                failed: true,
                durable: None,
            })
        }),
    });
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiverObservation {
    pub generation: u64,
    pub width: u32,
    pub height: u32,
    pub worker_started: bool,
    pub decoder_opened: bool,
    pub accepted: u64,
    pub decoded: u64,
    pub retired: u64,
    pub converted: u64,
    pub submitted: u64,
    pub last_accepted_pts: Option<u64>,
    pub last_decoded_pts: Option<u64>,
    pub last_retired_pts: Option<u64>,
    pub last_submitted_pts: Option<u64>,
    pub last_submitted_qpc: Option<u64>,
    pub qpc_frequency: Option<u64>,
    pub failed: bool,
    pub revoked: bool,
    pub worker_joined: bool,
    pub worker_panicked: bool,
    pub terminal_write_failed: bool,
    pub terminal_write_pending: bool,
    pub terminal_write_durable: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    source: u32,
    connection_generation: u64,
    stream_epoch: u64,
    catalog_revision: u64,
    selection_sequence: u64,
    layout_epoch: u64,
    decode_epoch: u64,
    configuration_id: u64,
}
impl Scope {
    fn new(context: &CompressedContext) -> Self {
        Self {
            source: context.binding.source,
            connection_generation: context.binding.connection_generation,
            stream_epoch: context.binding.stream_epoch,
            catalog_revision: context.catalog_revision,
            selection_sequence: context.selection_sequence,
            layout_epoch: context.layout_epoch,
            decode_epoch: context.decode_epoch,
            configuration_id: context.configuration_id,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalReceipt {
    schema: u32,
    written_unix_ms: u128,
    scope: Scope,
    receiver: ReceiverObservation,
}
#[derive(Clone)]
pub(super) struct TerminalSink {
    directory: PathBuf,
    scope: Scope,
}
impl TerminalSink {
    pub fn new(directory: &Path, context: &CompressedContext) -> Self {
        Self {
            directory: directory.to_path_buf(),
            scope: Scope::new(context),
        }
    }
    /// Called by the actual join consumer, including the retained Drop owner.
    /// It never touches the encoder/decoder, pixels, IPC payload or authorization.
    fn bytes(&self, mut receiver: ReceiverObservation) -> std::io::Result<Vec<u8>> {
        // The file cannot attest the outcome of its own later atomic commit.
        receiver.terminal_write_durable = None;
        receiver.terminal_write_pending = true;
        if !receiver.worker_joined {
            return Err(std::io::Error::other("GPU terminal owner has not joined"));
        }
        let bytes = serde_json::to_vec(&TerminalReceipt {
            schema: 1,
            written_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |value| value.as_millis()),
            scope: self.scope.clone(),
            receiver,
        })?;
        if bytes.len() > 16_384 {
            return Err(std::io::Error::other("GPU terminal receipt exceeds budget"));
        }
        Ok(bytes)
    }
    #[cfg(test)]
    fn write(
        &self,
        receiver: ReceiverObservation,
    ) -> std::io::Result<nestlink_platform_security::MetadataCommit> {
        nestlink_platform_security::replace_private_metadata(
            &self.directory.join("native-gpu-receiver-terminal.json"),
            &self.bytes(receiver)?,
        )
    }
    pub fn enqueue(&self, receiver: ReceiverObservation, shared: Arc<Mutex<ReceiverObservation>>) {
        let update = move |state: CommitState| {
            if let Ok(mut value) = shared.lock() {
                value.terminal_write_failed = state.failed;
                value.terminal_write_pending = false;
                value.terminal_write_durable = state.durable;
            }
        };
        match self.bytes(receiver) {
            Ok(bytes) => queue_write(
                self.directory.join("native-gpu-receiver-terminal.json"),
                bytes,
                IoKind::Terminal,
                update,
            ),
            Err(_) => update(CommitState {
                finished: true,
                failed: true,
                durable: None,
            }),
        }
    }
}

/// Persisted history contains no request/runtime/stream IDs or frame payloads.
/// Generation is local to this receiver and never used to authorize anything.
#[derive(Default)]
pub(super) struct Recorder {
    samples: VecDeque<serde_json::Value>,
    terminal: Option<serde_json::Value>,
    historical_terminal_receipt: Option<serde_json::Value>,
    terminal_observed_live: bool,
    local_host: Option<serde_json::Value>,
    last_sample: Option<Instant>,
    // Private equality key only: identifiers never enter a serialized value.
    last_terminal_observed: Option<(CompressedContext, u64)>,
    last_write: Option<Instant>,
    last_terminal_read: Option<Instant>,
    dirty: bool,
    write_failed: bool,
    write_durable: Option<bool>,
    pending_write: Option<Arc<Mutex<CommitState>>>,
    pending_read: Option<Arc<Mutex<Option<ReadSnapshot>>>>,
    terminal_completion: Option<Arc<Mutex<ReceiverObservation>>>,
}
impl Recorder {
    pub fn track_terminal(&mut self, shared: Arc<Mutex<ReceiverObservation>>) {
        self.terminal_completion = Some(shared);
    }
    pub fn observe(
        &mut self,
        context: &CompressedContext,
        value: ReceiverObservation,
        terminal: bool,
    ) {
        if terminal {
            let key = (context.clone(), value.generation);
            if self.last_terminal_observed.as_ref() == Some(&key) {
                if let Ok(updated) = serde_json::to_value(&value)
                    && let Some(receiver) = self
                        .terminal
                        .as_mut()
                        .and_then(|terminal| terminal.get_mut("receiver"))
                    && *receiver != updated
                {
                    *receiver = updated;
                    self.dirty = true;
                }
                return;
            }
            self.last_terminal_observed = Some(key);
        }
        if !terminal
            && self
                .last_sample
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        let sample = serde_json::json!({
            "source": context.binding.source,
            "connection_generation": context.binding.connection_generation,
            "stream_epoch": context.binding.stream_epoch,
            "catalog_revision": context.catalog_revision,
            "selection_sequence": context.selection_sequence,
            "layout_epoch": context.layout_epoch,
            "decode_epoch": context.decode_epoch,
            "configuration_id": context.configuration_id,
            "sampled_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|value| value.as_millis()),
            "gpu_dxgi_picture_observed": value.converted > 0,
            "receiver": value,
        });
        if terminal {
            self.terminal = Some(sample.clone());
            self.terminal_observed_live = true;
        }
        self.samples.push_back(sample);
        while self.samples.len() > 64 {
            self.samples.pop_front();
        }
        self.last_sample = Some(Instant::now());
        self.dirty = true;
    }
    pub fn has_observations(&self) -> bool {
        !self.samples.is_empty() || self.terminal.is_some() || self.local_host.is_some()
    }
    pub fn export(&self) -> serde_json::Value {
        let mut report = serde_json::json!({
            "schema": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "presentation": "native-d3d11-mf",
            "decoder_backend_contract": "mf-d3d11-aware",
            "dimensions_are_configured": true,
            "scope": "receiver-only-live-product",
            "counts_cover_successfully_returned_steps_only": true,
            "decoder_open_success_is_not_a_decoded_picture": true,
            "scanout_verified": false,
            "performance_qualified": false,
            "host_capture_backend": null,
            "host_encoder_hardware": null,
            "host_adapter_luid": null,
            "host_pts": null,
            "write_failed": self.write_failed,
            "previous_write_durable": self.write_durable,
            "write_pending": self.pending_write.is_some(),
            "dropped_persistence_jobs": DROPPED_WRITES.load(Ordering::Relaxed),
            "latest_terminal": self.terminal,
            "latest_terminal_origin": if self.terminal_observed_live { "observed-in-this-recorder" } else { "historical-disk-receipt" },
            "historical_terminal_receipt": self.historical_terminal_receipt,
            "local_host_observation": self.local_host,
            "samples": self.samples,
        });
        // Bound the exact pretty representation consumed by Copy as well as
        // compact persistence. Trimming affects sparse history, not join proof.
        while serde_json::to_vec_pretty(&report).is_ok_and(|bytes| bytes.len() > 65_536) {
            if let Some(samples) = report["samples"].as_array_mut()
                && !samples.is_empty()
            {
                samples.remove(0);
                continue;
            }
            let mut trimmed = false;
            for key in ["samples", "terminal_receipts"] {
                if let Some(records) = report["local_host_observation"][key].as_array_mut()
                    && !records.is_empty()
                {
                    records.remove(0);
                    trimmed = true;
                    break;
                }
            }
            if !trimmed {
                break;
            } // Fixed scalar envelope + one typed terminal is below budget.
        }
        report
    }
    /// Strict typed input keeps a modified local file from injecting arbitrary
    /// strings/identifiers into the explicit redacted export. Historical receipt
    /// is diagnostic only and is never installed as a current media binding.
    pub fn read_terminal(&mut self, directory: &Path) {
        if let Some(pending) = &self.pending_read {
            let snapshot = pending.lock().ok().and_then(|mut value| value.take());
            if let Some(snapshot) = snapshot {
                self.pending_read = None;
                if let Some(value) = snapshot.terminal {
                    self.ingest_terminal(value);
                }
                if let Some(host) = snapshot.host
                    && self.local_host.as_ref() != Some(&host)
                {
                    self.local_host = Some(host);
                    self.dirty = true;
                }
            } else {
                return;
            }
        }
        if self
            .last_terminal_read
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_terminal_read = Some(Instant::now());
        let Some(reader) = background_io() else {
            return;
        };
        let result = Arc::new(Mutex::new(None));
        self.pending_read = Some(result.clone());
        let cancelled = result.clone();
        let directory = directory.to_path_buf();
        reader.submit(IoJob {
            kind: IoKind::Read,
            run: Box::new(move || {
                let mut snapshot = Recorder::default();
                snapshot.read_terminal_sync(&directory);
                if let Ok(mut value) = result.lock() {
                    *value = Some(ReadSnapshot {
                        terminal: snapshot.historical_terminal_receipt,
                        host: snapshot.local_host,
                    });
                }
            }),
            cancel: Box::new(move || {
                if let Ok(mut value) = cancelled.lock() {
                    *value = Some(ReadSnapshot {
                        terminal: None,
                        host: None,
                    });
                }
            }),
        });
    }
    fn ingest_terminal(&mut self, value: serde_json::Value) {
        if self.historical_terminal_receipt.as_ref() != Some(&value) {
            if !self.terminal_observed_live {
                self.terminal = Some(value.clone());
            }
            self.historical_terminal_receipt = Some(value);
            self.dirty = true;
        }
    }
    fn read_terminal_sync(&mut self, directory: &Path) {
        if self
            .last_terminal_read
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_terminal_read = Some(Instant::now());
        self.read_host(directory);
        let Ok(bytes) = nestlink_platform_security::read_private(
            &directory.join("native-gpu-receiver-terminal.json"),
            16_384,
        ) else {
            return;
        };
        let Ok(receipt) = serde_json::from_slice::<TerminalReceipt>(&bytes) else {
            return;
        };
        if receipt.schema != 1 || !receipt.receiver.worker_joined {
            return;
        }
        if let Ok(value) = serde_json::to_value(receipt) {
            // Wall-clock timestamps and redacted epochs cannot establish an
            // order across recorder/session lifetimes. Disk history must never
            // replace a terminal witnessed by this live recorder.
            self.ingest_terminal(value);
        }
    }
    fn read_host(&mut self, directory: &Path) {
        let Ok(bytes) = nestlink_platform_security::read_private(
            &directory.join("native-gpu-host.json"),
            65_536,
        ) else {
            return;
        };
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return;
        };
        if raw["schema"].as_u64() != Some(1) {
            return;
        }
        // Copy only bounded scalar fields. Never echo arbitrary strings, keys,
        // identities or structures from a local file into the redacted export.
        fn record(raw: &serde_json::Value) -> serde_json::Value {
            let mut out = serde_json::Map::new();
            for name in [
                "owner",
                "connection_generation",
                "capture_generation",
                "source",
                "configured_width",
                "configured_height",
                "target_fps",
                "adapter_luid",
                "captures",
                "cached_captures",
                "accepted",
                "encoded_outputs",
                "last_accepted_pts",
                "last_output_pts",
                "pipeline_failures",
            ] {
                out.insert(name.into(), serde_json::json!(raw[name].as_u64()));
            }
            for name in [
                "encoder_hardware",
                "failed",
                "stop_requested",
                "cleanup_ok",
                "worker_joined",
                "join_panicked",
            ] {
                out.insert(name.into(), serde_json::json!(raw[name].as_bool()));
            }
            let backend = raw["capture_backend"].as_str().filter(|value| {
                matches!(
                    *value,
                    "gpu-dxgi-duplication" | "gpu-wgc" | "cpu-dxgi-readback" | "cpu-gdi"
                )
            });
            out.insert("capture_backend".into(), serde_json::json!(backend));
            let sps = raw["actual_stream_sps"]
                .as_array()
                .filter(|values| values.len() == 3)
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
                        .collect::<Option<Vec<_>>>()
                });
            out.insert("actual_stream_sps".into(), serde_json::json!(sps));
            out.into()
        }
        let records = |key: &str, maximum: usize| {
            raw[key]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .rev()
                        .take(maximum)
                        .rev()
                        .map(record)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let value = serde_json::json!({
            "scope": "local-host-live-product-not-remote-host", "written_unix_ms": raw["written_unix_ms"].as_u64(),
            "daemon_started_unix_ms": raw["daemon_started_unix_ms"].as_u64(),
            "dropped_observations": raw["dropped_observations"].as_u64(),
            "previous_write_failed": raw["previous_write_failed"].as_bool(),
            "previous_write_durable": raw["previous_write_durable"].as_bool(),
            "samples": records("samples", 16), "terminal_receipts": records("terminal_receipts", 8),
        });
        if self.local_host.as_ref() != Some(&value) {
            self.local_host = Some(value);
            self.dirty = true;
        }
    }
    pub fn needs_flush(&self) -> bool {
        self.dirty
            || self.pending_write.is_some()
            || self.pending_read.is_some()
            || self.terminal_completion.is_some()
    }
    pub fn flush(&mut self, directory: &Path) {
        if let Some(shared) = &self.terminal_completion {
            let observation = shared.lock().ok().map(|value| value.clone());
            if let Some(observation) = observation.filter(|value| !value.terminal_write_pending) {
                if let Ok(value) = serde_json::to_value(observation)
                    && let Some(receiver) = self
                        .terminal
                        .as_mut()
                        .and_then(|terminal| terminal.get_mut("receiver"))
                {
                    *receiver = value;
                    self.dirty = true;
                }
                self.terminal_completion = None;
            }
        }
        if let Some(pending) = &self.pending_write {
            let status = pending.lock().ok().map(|value| *value);
            if let Some(status) = status.filter(|value| value.finished) {
                self.write_failed = status.failed;
                self.write_durable = status.durable;
                self.dirty |= status.failed;
                self.pending_write = None;
            } else {
                return;
            }
        }
        if !self.dirty
            || self
                .last_write
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_write = Some(Instant::now());
        // Size is bounded even if a future scalar field is added. The terminal
        // receipt is kept separately so a heartbeat cannot evict cleanup proof.
        let bytes = loop {
            let mut report = self.export();
            // Persisted bytes cannot attest their own later commit. Live Copy
            // reads the actual retained completion instead of this flag.
            report["write_pending"] = serde_json::json!(true);
            let Ok(bytes) = serde_json::to_vec(&report) else {
                self.write_failed = true;
                self.write_durable = None;
                return;
            };
            if bytes.len() <= 65_536 {
                break bytes;
            }
            if self.samples.pop_front().is_none() {
                self.write_failed = true;
                self.write_durable = None;
                return;
            }
        };
        let status = Arc::new(Mutex::new(CommitState::default()));
        let completion = status.clone();
        self.pending_write = Some(status);
        self.dirty = false;
        queue_write(
            directory.join("native-gpu-receiver.json"),
            bytes,
            IoKind::Report,
            move |result| {
                if let Ok(mut value) = completion.lock() {
                    *value = result;
                }
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_ipc::compressed_video::NativeCompressedBinding;

    #[test]
    fn slow_writer_bounds_backlog_and_retains_terminal_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let writer = BackgroundIo::new()?;
        let (started, observed_start) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        writer.submit(IoJob {
            kind: IoKind::Report,
            run: Box::new(move || {
                let _ = started.send(());
                let _ = wait_release.recv();
            }),
            cancel: Box::new(|| panic!("running write cannot be evicted")),
        });
        observed_start.recv_timeout(Duration::from_secs(5))?;
        let (terminal, observed_terminal) = std::sync::mpsc::channel();
        for index in 0..16 {
            let terminal = terminal.clone();
            writer.submit(IoJob {
                kind: IoKind::Terminal,
                run: Box::new(move || {
                    let _ = terminal.send(index);
                }),
                cancel: Box::new(|| panic!("terminal queue is within budget")),
            });
        }
        let (cancelled, observed_cancelled) = std::sync::mpsc::channel();
        writer.submit(IoJob {
            kind: IoKind::Report,
            run: Box::new(|| panic!("stale report")),
            cancel: Box::new(move || {
                let _ = cancelled.send(());
            }),
        });
        writer.submit(IoJob {
            kind: IoKind::Report,
            run: Box::new(|| {}),
            cancel: Box::new(|| {}),
        });
        observed_cancelled.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(
            writer
                .queue
                .0
                .lock()
                .map_err(|_| std::io::Error::other("test queue poisoned"))?
                .len(),
            17
        );
        assert!(observed_terminal.try_recv().is_err());
        release.send(())?;
        for index in 0..16 {
            assert_eq!(
                observed_terminal.recv_timeout(Duration::from_secs(5))?,
                index
            );
        }
        Ok(())
    }

    #[test]
    fn failed_background_commit_reports_unknown_durability()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir()
            .join(format!("missing-gpu-parent-{}", uuid::Uuid::new_v4()))
            .join("report.json");
        let (finished, observed) = std::sync::mpsc::channel();
        queue_write(path, b"{}".to_vec(), IoKind::Report, move |status| {
            let _ = finished.send(status);
        });
        let status = observed.recv_timeout(Duration::from_secs(5))?;
        assert!(status.finished);
        assert!(status.failed);
        assert_eq!(status.durable, None);
        Ok(())
    }

    #[test]
    fn terminal_completion_is_consumed_after_presenter_is_gone() {
        let mut recorder = Recorder::default();
        recorder.observe(
            &context(),
            ReceiverObservation {
                generation: 1,
                worker_joined: true,
                terminal_write_pending: true,
                ..ReceiverObservation::default()
            },
            true,
        );
        let completion = Arc::new(Mutex::new(ReceiverObservation {
            generation: 1,
            worker_joined: true,
            terminal_write_failed: true,
            ..ReceiverObservation::default()
        }));
        recorder.track_terminal(completion);
        // Prevent a report write; this test isolates retained completion intake.
        recorder.last_write = Some(Instant::now());
        recorder.flush(Path::new("unused"));
        assert!(recorder.terminal_completion.is_none());
        let report = recorder.export();
        assert_eq!(
            report["latest_terminal"]["receiver"]["terminal_write_pending"],
            false
        );
        assert_eq!(
            report["latest_terminal"]["receiver"]["terminal_write_failed"],
            true
        );
        assert!(report["latest_terminal"]["receiver"]["terminal_write_durable"].is_null());
    }

    fn context() -> CompressedContext {
        CompressedContext {
            binding: NativeCompressedBinding {
                runtime_id: "private-runtime-marker".into(),
                request_id: "private-request-marker".into(),
                ui_generation: 1,
                connection_generation: 2,
                source: 3,
                stream_id: [0x41; 16],
                stream_epoch: 4,
            },
            catalog_revision: 5,
            selection_sequence: 6,
            layout_epoch: 7,
            decode_epoch: 8,
            configuration_id: 9,
        }
    }

    #[test]
    fn private_session_key_distinguishes_equal_redacted_scopes() -> std::io::Result<()> {
        let original = context();
        let mut recorder = Recorder::default();
        let terminal = ReceiverObservation {
            generation: 1,
            worker_joined: true,
            ..ReceiverObservation::default()
        };
        recorder.observe(&original, terminal.clone(), true);
        for index in 0..4 {
            let mut next = original.clone();
            match index {
                0 => next.binding.runtime_id = "another-private-runtime".into(),
                1 => next.binding.request_id = "another-private-request".into(),
                2 => next.binding.ui_generation += 1,
                _ => next.binding.stream_id = [0x42; 16],
            }
            assert!(Scope::new(&original) == Scope::new(&next));
            recorder.observe(&next, terminal.clone(), true);
            recorder.observe(&next, terminal.clone(), true);
        }
        assert_eq!(recorder.samples.len(), 5);
        let encoded = serde_json::to_string(&recorder.export())?;
        for private in [
            "private-runtime",
            "private-request",
            "stream_id",
            "ui_generation",
        ] {
            assert!(!encoded.contains(private));
        }
        Ok(())
    }

    #[test]
    fn disk_history_cannot_replace_a_live_terminal() -> std::io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("nestlink-gpu-order-{}", uuid::Uuid::new_v4()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let context = context();
        let sink = TerminalSink::new(&directory, &context);
        sink.write(ReceiverObservation {
            generation: 1,
            worker_joined: true,
            ..ReceiverObservation::default()
        })?;
        let mut recorder = Recorder::default();
        recorder.read_terminal_sync(&directory);
        assert_eq!(
            recorder.export()["latest_terminal"]["receiver"]["generation"],
            1
        );
        // A newer terminal was witnessed, but its terminal-file write failed:
        // the old disk receipt remains readable on every subsequent UI poll.
        recorder.observe(
            &context,
            ReceiverObservation {
                generation: 2,
                worker_joined: true,
                terminal_write_failed: true,
                ..ReceiverObservation::default()
            },
            true,
        );
        recorder.last_terminal_read = None;
        recorder.read_terminal_sync(&directory);
        assert_eq!(
            recorder.export()["latest_terminal"]["receiver"]["generation"],
            2
        );
        // Even a later-written receipt has no trustworthy cross-session order;
        // retain it as explicitly historical without replacing the live fact.
        sink.write(ReceiverObservation {
            generation: 99,
            worker_joined: true,
            ..ReceiverObservation::default()
        })?;
        recorder.last_terminal_read = None;
        recorder.read_terminal_sync(&directory);
        let report = recorder.export();
        assert_eq!(report["latest_terminal"]["receiver"]["generation"], 2);
        assert_eq!(
            report["latest_terminal_origin"],
            "observed-in-this-recorder"
        );
        assert_eq!(
            report["historical_terminal_receipt"]["receiver"]["generation"],
            99
        );
        std::fs::remove_file(directory.join("native-gpu-receiver-terminal.json"))?;
        std::fs::remove_dir(directory)?;
        Ok(())
    }

    #[test]
    fn joined_receipt_survives_recorder_recreation() -> std::io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("nestlink-gpu-receipt-{}", uuid::Uuid::new_v4()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let sink = TerminalSink {
            directory: directory.clone(),
            scope: Scope {
                source: 3,
                connection_generation: 2,
                stream_epoch: 4,
                catalog_revision: 5,
                selection_sequence: 6,
                layout_epoch: 7,
                decode_epoch: 8,
                configuration_id: 9,
            },
        };
        assert!(sink.write(ReceiverObservation::default()).is_err());
        sink.write(ReceiverObservation {
            worker_joined: true,
            accepted: 1,
            last_accepted_pts: Some(0),
            ..ReceiverObservation::default()
        })?;
        drop(sink);
        let mut recreated = Recorder::default();
        recreated.read_terminal_sync(&directory);
        let report = recreated.export();
        assert!(recreated.has_observations());
        assert_eq!(report["latest_terminal"]["receiver"]["worker_joined"], true);
        assert_eq!(
            report["latest_terminal"]["receiver"]["last_accepted_pts"],
            0
        );
        assert_eq!(report["latest_terminal"]["scope"]["source"], 3);
        assert_eq!(
            report["latest_terminal"]["receiver"]["terminal_write_pending"],
            true
        );
        assert!(report["latest_terminal"]["receiver"]["terminal_write_durable"].is_null());
        std::fs::remove_file(directory.join("native-gpu-receiver-terminal.json"))?;
        std::fs::remove_dir(directory)?;
        Ok(())
    }

    #[test]
    fn bounded_history_preserves_terminal_and_redacts_identity() -> std::io::Result<()> {
        let context = CompressedContext {
            binding: NativeCompressedBinding {
                runtime_id: "private-runtime-marker".into(),
                request_id: "private-request-marker".into(),
                ui_generation: 1,
                connection_generation: 2,
                source: 3,
                stream_id: [0x41; 16],
                stream_epoch: 4,
            },
            catalog_revision: 5,
            selection_sequence: 6,
            layout_epoch: 7,
            decode_epoch: 8,
            configuration_id: 9,
        };
        let mut recorder = Recorder::default();
        let terminal = ReceiverObservation {
            generation: 1,
            worker_started: true,
            worker_joined: true,
            revoked: true,
            ..ReceiverObservation::default()
        };
        recorder.observe(&context, terminal.clone(), true);
        for _ in 0..100 {
            recorder.observe(&context, terminal.clone(), true);
        }
        assert_eq!(recorder.samples.len(), 1);
        for generation in 2..200 {
            recorder.last_sample = None;
            recorder.observe(
                &context,
                ReceiverObservation {
                    generation,
                    ..ReceiverObservation::default()
                },
                false,
            );
        }
        assert_eq!(recorder.samples.len(), 64);
        let report = recorder.export();
        assert_eq!(report["latest_terminal"]["receiver"]["generation"], 1);
        assert_eq!(report["latest_terminal"]["receiver"]["worker_joined"], true);
        let encoded = serde_json::to_string(&report)?;
        assert!(encoded.len() <= 65_536);
        assert!(serde_json::to_vec_pretty(&report)?.len() <= 65_536);
        assert!(!encoded.contains("private-runtime-marker"));
        assert!(!encoded.contains("private-request-marker"));
        assert!(!encoded.contains("stream_id"));
        Ok(())
    }
}
