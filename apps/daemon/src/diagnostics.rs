//! A bounded private diagnostic ring containing fixed labels and timings only.
mod export;
pub(crate) mod service;
pub(crate) use export::{ExportArgs, run_export};
use nestlink_app_core::BrowserHostDiagnostic;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn browser_host_sink(directory: PathBuf) -> Arc<dyn Fn(BrowserHostDiagnostic) + Send + Sync> {
    let serial = Mutex::new(());
    Arc::new(move |event| {
        let Ok(_guard) = serial.lock() else {
            return;
        };
        let path = directory.join("browser-host-diagnostics.jsonl");
        let mut records = match nestlink_platform_security::read_private(&path, 65_536) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return,
        };
        let line = serde_json::json!({
            "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_millis() as u64),
            "stage": format!("{:?}", event.stage), "source": format!("{:?}", event.source),
            "elapsed_ms": event.elapsed_ms,
            "request_sha256": event.request_sha256.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "connection_generation": event.connection_generation,
            "peer_timeline": event.timeline,
            "peer_reason": event.peer.map(|peer| format!("{:?}", peer.reason)),
            "peer_io_kind": event.peer.and_then(|peer| peer.io_error_kind).map(|kind| format!("{kind:?}")),
            "peer_elapsed_ms": event.peer.map(|peer| peer.elapsed_ms),
        }).to_string();
        while records.len() + line.len() + 1 > 65_536 {
            if let Some(end) = records.iter().position(|byte| *byte == b'\n') {
                records.drain(..=end);
            } else {
                records.clear();
                break;
            }
        }
        records.extend_from_slice(line.as_bytes());
        records.push(b'\n');
        let _ = nestlink_platform_security::replace_private_metadata(&path, &records);
    })
}
