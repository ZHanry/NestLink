//! CLI observations of the original local proxy owner. No lease, address,
//! username, target, application bytes or free-form error enters this file.
use nestlink_protocol::diagnostics::request_hash;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, path::PathBuf, time::Instant};

pub(super) const FILE: &str = "private-service-diagnostics.jsonl";
pub(super) const LIMIT: usize = 65_536;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    SelectionStarted,
    SelectionValidated,
    ListenerStarting,
    ListenerReady,
    StopRequested,
    CleanupPending,
    CleanupFailed,
    Stopped,
    OperationFailed,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StopCause {
    UserStop,
    Deadline,
    OwnerEnded,
    Maintenance,
    LoginChanged,
    InspectionFailed,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalEntry {
    Socks,
    Native,
    Raw,
}

/// Each value is copied from the original joined SDK owner's physical receipt.
/// Unknown counters stay absent; the CLI does not infer successful deliveries.
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct Counters {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub cleanup_failures: u64,
    pub forwarded_datagrams: Option<u64>,
    pub discarded_datagrams: Option<u64>,
    pub endpoint_closed: Option<bool>,
    pub native_endpoint_removed: Option<bool>,
    pub credentials_removed: Option<bool>,
}
impl From<&nestlink_sdk::services::LocalProxyStopReport> for Counters {
    fn from(report: &nestlink_sdk::services::LocalProxyStopReport) -> Self {
        Self {
            accepted_connections: report.accepted_connections,
            completed_connections: report.completed_connections,
            rejected_connections: report.rejected_connections,
            failed_connections: report.failed_connections,
            cleanup_failures: report.cleanup_failures,
            forwarded_datagrams: Some(report.forwarded_datagrams),
            discarded_datagrams: Some(report.discarded_datagrams),
            credentials_removed: Some(report.credentials_removed),
            ..Default::default()
        }
    }
}
impl From<&nestlink_sdk::services::NativeStreamStopReport> for Counters {
    fn from(report: &nestlink_sdk::services::NativeStreamStopReport) -> Self {
        Self {
            accepted_connections: report.accepted_connections,
            completed_connections: report.completed_connections,
            rejected_connections: report.rejected_connections,
            failed_connections: report.failed_connections,
            cleanup_failures: report.cleanup_failures,
            native_endpoint_removed: Some(report.endpoint_removed),
            ..Default::default()
        }
    }
}
#[cfg(any(target_os = "linux", windows))]
impl From<&nestlink_sdk::services::RawProxyStopReport> for Counters {
    fn from(report: &nestlink_sdk::services::RawProxyStopReport) -> Self {
        Self {
            accepted_connections: report.accepted_connections,
            completed_connections: report.completed_connections,
            rejected_connections: report.rejected_connections,
            failed_connections: report.failed_connections,
            cleanup_failures: report.cleanup_failures,
            forwarded_datagrams: Some(report.forwarded_datagrams),
            discarded_datagrams: Some(report.discarded_datagrams),
            endpoint_closed: Some(report.socket_closed),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct Event {
    pub operation_sha256: String,
    pub service_sha256: String,
    pub space_sha256: String,
    pub sequence: u64,
    pub elapsed_ms: u64,
    pub local_entry: LocalEntry,
    /// Explicit user selection only, never an observed successful path.
    pub selected_relay_count: usize,
    pub stage: Stage,
    pub stop_cause: Option<StopCause>,
    pub counters: Option<Counters>,
}
pub(crate) struct Recorder {
    directory: PathBuf,
    started: Instant,
    event: Event,
    terminal: bool,
    warned: bool,
}
impl Recorder {
    pub(crate) fn new(
        directory: PathBuf,
        service: &str,
        space: &str,
        local_entry: LocalEntry,
        selected_relay_count: usize,
    ) -> Self {
        let mut recorder = Self {
            directory,
            started: Instant::now(),
            terminal: false,
            warned: false,
            event: Event {
                operation_sha256: request_hash(nestlink_auth::token().expose()),
                service_sha256: request_hash(service),
                space_sha256: request_hash(space),
                sequence: 0,
                elapsed_ms: 0,
                local_entry,
                selected_relay_count,
                stage: Stage::SelectionStarted,
                stop_cause: None,
                counters: None,
            },
        };
        recorder.observe(Stage::SelectionStarted);
        recorder
    }
    pub(crate) fn observe(&mut self, stage: Stage) {
        if self.terminal {
            return;
        }
        self.event.sequence = self.event.sequence.saturating_add(1);
        self.event.elapsed_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.event.stage = stage;
        self.terminal = matches!(
            stage,
            Stage::Stopped | Stage::CleanupFailed | Stage::OperationFailed
        );
        if self.append().is_err() && !self.warned {
            eprintln!("private_service_diagnostics_unavailable=true");
            self.warned = true;
        }
    }
    pub(crate) fn stopping(&mut self, cause: StopCause) {
        self.event.stop_cause = Some(cause);
        self.observe(Stage::StopRequested);
    }
    pub(crate) fn finish(&mut self, counters: Counters, failed: bool) {
        self.event.counters = Some(counters);
        self.observe(if failed {
            Stage::CleanupFailed
        } else {
            Stage::Stopped
        });
    }
    fn append(&self) -> std::io::Result<()> {
        let path = self.directory.join(FILE);
        let previous = match nestlink_platform_security::read_private(&path, LIMIT as u64) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let line = serde_json::to_vec(&self.event)?;
        let bytes = bounded_append(&previous, &line)?;
        match nestlink_platform_security::replace_private_metadata(&path, &bytes)? {
            nestlink_platform_security::MetadataCommit::Durable => Ok(()),
            nestlink_platform_security::MetadataCommit::Visible => Err(std::io::Error::other(
                "diagnostic visible; durability unconfirmed",
            )),
        }
    }
}
impl Drop for Recorder {
    fn drop(&mut self) {
        if !self.terminal {
            self.observe(Stage::OperationFailed);
        }
    }
}
fn bounded_append(previous: &[u8], line: &[u8]) -> std::io::Result<Vec<u8>> {
    if line.len() >= LIMIT {
        return Err(std::io::Error::other("diagnostic event exceeds limit"));
    }
    let mut records = previous
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|record| record.last() == Some(&b'\n'))
        .collect::<VecDeque<_>>();
    let mut total = records.iter().map(|record| record.len()).sum::<usize>();
    while total + line.len() + 1 > LIMIT
        || records.len() >= nestlink_protocol::diagnostics::TIMELINE_EVENT_LIMIT
    {
        let Some(record) = records.pop_front() else {
            break;
        };
        total -= record.len();
    }
    let mut bytes = Vec::with_capacity(total + line.len() + 1);
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes.extend_from_slice(line);
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_history_keeps_complete_newest_records_and_no_partial_prefix() -> std::io::Result<()>
    {
        let mut bytes = Vec::new();
        for index in 0..1000 {
            bytes = bounded_append(&bytes, format!("{{\"sequence\":{index}}}").as_bytes())?;
        }
        assert!(bytes.len() <= LIMIT);
        let records = bytes
            .split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(
            records.len(),
            nestlink_protocol::diagnostics::TIMELINE_EVENT_LIMIT
        );
        assert_eq!(
            records.last().copied(),
            Some(b"{\"sequence\":999}".as_slice())
        );
        assert!(bounded_append(&[], &vec![b'x'; LIMIT]).is_err());
        Ok(())
    }
    #[test]
    fn failed_selection_is_retained_without_target_login_or_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        {
            let _recorder = Recorder::new(
                directory.clone(),
                "secret-service",
                "secret-space",
                LocalEntry::Socks,
                2,
            );
        }
        let bytes = nestlink_platform_security::read_private(&directory.join(FILE), LIMIT as u64)?;
        let encoded = std::str::from_utf8(&bytes)?;
        assert!(!encoded.contains("secret-service"));
        assert!(!encoded.contains("secret-space"));
        assert!(encoded.contains("operation_failed"));
        assert!(encoded.contains(&request_hash("secret-service")));
        assert!(!encoded.contains("observed_route"));
        assert!(encoded.contains("\"counters\":null"));
        Ok(())
    }
}
