//! Daemon consumer of real Windows host-owner observations; never probes.
use nestlink_platform_capture::{HostObservation, HostObservationSink};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
struct Event {
    owner: u64,
    connection_generation: u64,
    fact: HostObservation,
}
#[derive(Default)]
struct Mailbox {
    latest: Option<Event>,
    terminal: VecDeque<Event>,
}
fn mailbox() -> &'static Mutex<Mailbox> {
    static VALUE: OnceLock<Mutex<Mailbox>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(Mailbox::default()))
}
static DROPPED: AtomicU64 = AtomicU64::new(0);
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Periodic production does no I/O and never waits for a diagnostic reader.
/// The join consumer uses the short metadata-only lock so its terminal fact is
/// retained; daemon file I/O is always outside that lock. Saturation is counted.
pub fn observer(connection_generation: u64) -> HostObservationSink {
    let owner = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
    let terminal_sent = AtomicBool::new(false);
    Arc::new(move |fact| {
        if terminal_sent.load(Ordering::Acquire) {
            return;
        }
        let mut state = if fact.worker_joined {
            match mailbox().lock() {
                Ok(value) => value,
                Err(_) => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        } else {
            match mailbox().try_lock() {
                Ok(value) => value,
                Err(_) => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };
        let event = Event {
            owner,
            connection_generation,
            fact,
        };
        state.latest = Some(event);
        if fact.worker_joined {
            if state.terminal.len() == 16 {
                state.terminal.pop_front();
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            state.terminal.push_back(event);
            terminal_sent.store(true, Ordering::Release);
        }
    })
}
fn scalar_event(event: Event) -> serde_json::Value {
    let f = event.fact;
    let backend = match f.capture_backend {
        Some(1) => Some("gpu-dxgi-duplication"),
        Some(2) => Some("gpu-wgc"),
        Some(3) => Some("cpu-dxgi-readback"),
        Some(4) => Some("cpu-gdi"),
        _ => None,
    };
    serde_json::json!({
        "owner": event.owner, "connection_generation": event.connection_generation,
        "capture_generation": f.generation, "source": f.source,
        "configured_width": f.width, "configured_height": f.height, "target_fps": f.target_fps,
        "capture_backend": backend, "adapter_luid": f.adapter_luid,
        "encoder_hardware": f.encoder_hardware, "actual_stream_sps": f.actual_sps,
        "captures": f.captures, "cached_captures": f.cached_captures,
        "accepted": f.accepted, "encoded_outputs": f.encoded_outputs,
        "last_accepted_pts": f.last_accepted_pts, "last_output_pts": f.last_output_pts,
        "pipeline_failures": f.pipeline_failures,
        "failed": f.failed, "stop_requested": f.stop_requested,
        "cleanup_ok": f.cleanup_ok, "worker_joined": f.worker_joined, "join_panicked": f.join_panicked,
    })
}
/// One bounded blocking write may run at a time. Histories remain owned here
/// while it runs, so terminal facts arriving meanwhile enter the next report.
pub struct Recorder {
    directory: PathBuf,
    samples: VecDeque<serde_json::Value>,
    terminals: VecDeque<serde_json::Value>,
    last_write: Option<Instant>,
    write_failed: bool,
    write_durable: Option<bool>,
    started_unix_ms: u128,
    writer: Option<
        tokio::task::JoinHandle<std::io::Result<nestlink_platform_security::MetadataCommit>>,
    >,
    dirty: bool,
}
impl Recorder {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            samples: VecDeque::new(),
            terminals: VecDeque::new(),
            last_write: None,
            write_failed: false,
            write_durable: None,
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |v| v.as_millis()),
            writer: None,
            dirty: false,
        }
    }
    async fn consume_writer(&mut self) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        match writer.await {
            Ok(Ok(commit)) => {
                self.write_failed = false;
                self.write_durable = Some(matches!(
                    commit,
                    nestlink_platform_security::MetadataCommit::Durable
                ));
            }
            Ok(Err(_)) | Err(_) => {
                self.write_failed = true;
                self.write_durable = None;
                self.dirty = true;
            }
        }
    }
    pub fn write_failed(&self) -> bool {
        self.write_failed
    }
    pub async fn flush(&mut self, final_flush: bool) {
        // A stopped facade may have quarantined its owner. Consume finished
        // joins even if no later session opens another capture.
        if nestlink_platform_capture::reap_finished_host_workers().is_err() {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        if self
            .writer
            .as_ref()
            .is_some_and(|writer| final_flush || writer.is_finished())
        {
            self.consume_writer().await;
            // A quarantined worker may have finished while shutdown awaited
            // storage. Collect its real join before taking the final mailbox.
            if final_flush && nestlink_platform_capture::reap_finished_host_workers().is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let (latest, terminal) = {
            let mut state = if final_flush {
                match mailbox().lock() {
                    Ok(state) => state,
                    Err(_) => {
                        self.write_failed = true;
                        self.write_durable = None;
                        return;
                    }
                }
            } else {
                let Ok(state) = mailbox().try_lock() else {
                    return;
                };
                state
            };
            (
                state.latest.take(),
                state.terminal.drain(..).collect::<Vec<_>>(),
            )
        };
        if let Some(latest) = latest {
            self.samples.push_back(scalar_event(latest));
            self.dirty = true;
        }
        for event in terminal {
            self.terminals.push_back(scalar_event(event));
            self.dirty = true;
        }
        while self.samples.len() > 64 {
            self.samples.pop_front();
        }
        while self.terminals.len() > 16 {
            self.terminals.pop_front();
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        // Keep draining into bounded history during a slow write. Never queue
        // another blocking task or wait for storage in the daemon control loop.
        if self.writer.is_some() || !self.dirty {
            return;
        }
        if !final_flush
            && self
                .last_write
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        let bytes = loop {
            let report = serde_json::json!({
                "schema": 1, "scope": "local-host-live-product", "daemon_started_unix_ms": self.started_unix_ms,
                "written_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |v| v.as_millis()),
                "synthetic_probe_counted": false, "counts_cover_successfully_returned_steps_only": true,
                "scanout_verified": false, "performance_qualified": false, "driver_internal_readback": null,
                "transport_sent_frames": null, "receiver_decoded_frames": null,
                "dropped_observations": DROPPED.load(Ordering::Acquire), "previous_write_failed": self.write_failed, "previous_write_durable": self.write_durable,
                "samples": self.samples, "terminal_receipts": self.terminals,
            });
            let Ok(bytes) = serde_json::to_vec(&report) else {
                self.write_failed = true;
                self.write_durable = None;
                return;
            };
            if bytes.len() <= 65_536 {
                break bytes;
            }
            if self.samples.pop_front().is_none() {
                if self.terminals.pop_front().is_none() {
                    self.write_failed = true;
                    self.write_durable = None;
                    return;
                }
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        };
        self.last_write = Some(Instant::now());
        self.dirty = false;
        let path = self.directory.join("native-gpu-host.json");
        self.writer = Some(tokio::task::spawn_blocking(move || {
            nestlink_platform_security::replace_private_metadata(&path, &bytes)
        }));
        if final_flush {
            // Shutdown explicitly consumes the real commit result; dropping a
            // JoinHandle is never treated as a completed or durable write.
            self.consume_writer().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_storage_never_waits_on_tick_and_final_flush_retains_terminals()
    -> std::io::Result<()> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        let mut recorder = Recorder::new(directory.clone());
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let pending = tokio::spawn(async move {
            held.await.map_err(std::io::Error::other)?;
            Ok(nestlink_platform_security::MetadataCommit::Visible)
        });
        let writer_id = pending.id();
        recorder.writer = Some(pending);
        observer(33)(HostObservation {
            worker_joined: true,
            accepted: 9,
            last_accepted_pts: Some(0),
            cleanup_ok: Some(true),
            ..HostObservation::default()
        });

        // This I/O operation cannot finish until we release it. A control-loop
        // tick must still drain terminal metadata and return with that SAME
        // task retained, without queuing a second writer.
        tokio::time::timeout(Duration::from_secs(1), recorder.flush(false))
            .await
            .map_err(std::io::Error::other)?;
        assert_eq!(
            recorder.writer.as_ref().map(|writer| writer.id()),
            Some(writer_id)
        );
        assert!(
            recorder
                .terminals
                .iter()
                .any(|event| event["accepted"] == 9)
        );
        assert!(recorder.dirty);
        release
            .send(())
            .map_err(|_| std::io::Error::other("held writer disappeared"))?;
        recorder.flush(true).await;
        assert!(recorder.writer.is_none());
        assert!(!recorder.write_failed());
        let bytes = nestlink_platform_security::read_private(
            &directory.join("native-gpu-host.json"),
            65_536,
        )?;
        let report: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["previous_write_durable"], false);
        assert!(
            report["terminal_receipts"]
                .as_array()
                .is_some_and(|events| {
                    events
                        .iter()
                        .any(|event| event["accepted"] == 9 && event["last_accepted_pts"] == 0)
                })
        );

        // A failed in-flight write must not consume later terminal facts or
        // claim durability. Final shutdown retries the retained full report
        // and consumes that retry's actual commit result.
        recorder.writer = Some(tokio::spawn(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture write denied",
            ))
        }));
        observer(34)(HostObservation {
            worker_joined: true,
            accepted: 10,
            cleanup_ok: Some(true),
            ..HostObservation::default()
        });
        recorder.flush(true).await;
        assert!(recorder.writer.is_none());
        assert!(!recorder.write_failed());
        assert!(!recorder.dirty);
        let bytes = nestlink_platform_security::read_private(
            &directory.join("native-gpu-host.json"),
            65_536,
        )?;
        let report: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["previous_write_failed"], true);
        assert!(report["previous_write_durable"].is_null());
        let events = report["terminal_receipts"].as_array();
        for accepted in [9, 10] {
            assert!(events.is_some_and(|events| {
                events
                    .iter()
                    .any(|event| event["accepted"] == accepted && event["worker_joined"] == true)
            }));
        }
        Ok(())
    }

    #[test]
    fn scalar_event_preserves_zero_pts_and_unknowns() {
        let value = scalar_event(Event {
            owner: 1,
            connection_generation: 2,
            fact: HostObservation {
                capture_backend: Some(99),
                last_accepted_pts: Some(0),
                worker_joined: true,
                ..HostObservation::default()
            },
        });
        assert!(value["capture_backend"].is_null());
        assert!(value["encoder_hardware"].is_null());
        assert!(value["adapter_luid"].is_null());
        assert!(value["last_output_pts"].is_null());
        assert_eq!(value["last_accepted_pts"], 0);
        assert_eq!(value["worker_joined"], true);
    }
}
