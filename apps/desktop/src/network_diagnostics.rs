//! Read-only history of the existing Core projection. Never serialize a whole
//! Snapshot: it also contains account data, device names and local consent.
use nestlink_app_core::{NativeSessionStatus, Snapshot};
use nestlink_protocol::diagnostics::{TIMELINE_EVENT_LIMIT, request_hash};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::Path,
    time::{Duration, Instant},
};

const FILE_LIMIT: usize = 256 * 1024;

#[derive(Default)]
pub(super) struct Recorder {
    events: VecDeque<Value>,
    last_state: Option<Value>,
    last_sample: Option<Instant>,
    last_write: Option<Instant>,
    started: Option<Instant>,
    latest_terminal: Option<Value>,
    sequence: u64,
    dropped: u64,
    dirty: bool,
    persistence_error: Option<&'static str>,
}

fn projection(snapshot: &Snapshot, connected: bool) -> Option<(Value, Value, bool)> {
    if !connected {
        return Some((json!({"event":"daemon_disconnected"}), Value::Null, false));
    }
    let Some(session) = snapshot.native_session.data.as_ref() else {
        return snapshot.native_session.error.as_ref().map(|failure| (
            json!({"event":"native_connection_failed","core_generation":snapshot.generation,
                "request_sha256":snapshot.selected_request.data.as_ref().map(|request| request_hash(&request.id)),
                "failure":failure}), Value::Null, true,
        ));
    };
    let terminal = matches!(
        session.status,
        NativeSessionStatus::Stopped | NativeSessionStatus::Failed
    );
    let state = json!({
        "event":"native_session",
        "request_sha256":request_hash(&session.request_id),
        "core_generation":snapshot.generation,
        "connection_generation":session.connection_generation,
        "lease_sequence":session.lease_sequence,
        "status":session.status,
        "observed_route":match session.path {Some(1)=>Some("direct"),Some(2)=>Some("relay"),_=>None},
        "stop_reason":session.stop_reason,
        "cleanup":session.cleanup,
        "failure":session.failure,
    });
    let quality = session.quality.as_ref().filter(|quality| {
        session.status == NativeSessionStatus::Connected && quality.original_binding.as_ref()
            .is_none_or(|binding| binding.business_generation == session.connection_generation)
    }).map(|quality| json!({
        "transport":quality.transport,"candidate_kind":quality.candidate_kind,
        "network_generation":(quality.network_generation != 0).then_some(quality.network_generation),
        "bilateral_ice":quality.bilateral_ice,
        "binding":quality.original_binding.as_ref().map(|binding| json!({
            "business_grant_sha256":binding.business_grant_sha256,
            "business_generation":binding.business_generation,
            "path_grant_sha256":binding.path_grant_id.as_deref().map(request_hash),
            "transport_group":binding.transport_group,"route_binding":binding.route_binding,
        })),
        "rtt_us":quality.rtt_us,"smoothed_rtt_change_us":quality.smoothed_rtt_change_us,
        "packet_window":quality.packet_window,"business_tx":quality.business_tx,
        "available_bytes_per_second":quality.available_bytes_per_second,"cost":quality.cost,
        "mtu":null,"queue_delay_us":null,"outer_vpn_route":null,
    })).unwrap_or(Value::Null);
    Some((state, quality, terminal))
}

impl Recorder {
    pub(super) fn has_observations(&self) -> bool {
        !self.events.is_empty()
    }

    pub(super) fn observe(&mut self, snapshot: &Snapshot, connected: bool, directory: &Path) {
        self.observe_at(snapshot, connected, Instant::now());
        self.flush(directory);
    }

    fn observe_at(&mut self, snapshot: &Snapshot, connected: bool, now: Instant) {
        let Some((state, quality, terminal)) = projection(snapshot, connected) else {
            return;
        };
        // A disconnected desktop may retain a stale IPC snapshot. Record the
        // source loss once; never sample that snapshot as live measurements.
        if !connected && self.events.is_empty() {
            return;
        }
        let changed = self.last_state.as_ref() != Some(&state);
        if !changed
            && (terminal
                || !connected
                || self
                    .last_sample
                    .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(1)))
        {
            return;
        }
        self.sequence = self.sequence.saturating_add(1);
        let started = *self.started.get_or_insert(now);
        let elapsed_ms =
            u64::try_from(now.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX);
        let event = json!({"sequence":self.sequence,"elapsed_ms":elapsed_ms,"state":state,"quality":quality});
        if terminal {
            self.latest_terminal = Some(event.clone());
        }
        self.events.push_back(event);
        while self.events.len() > TIMELINE_EVENT_LIMIT {
            self.events.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.last_state = Some(state);
        self.last_sample = Some(now);
        self.dirty = true;
    }

    pub(super) fn export(&self) -> Value {
        json!({
            "schema_version":1,"version":env!("CARGO_PKG_VERSION"),
            "source":"desktop_observation_of_original_core_session",
            "scope":"native_connection_history",
            "events":self.events,"dropped_events":self.dropped,
            "latest_terminal":self.latest_terminal,"persistence_error":self.persistence_error,
            "semantics":{
                "sequence":"local ordering; not a cross-machine clock or latency",
                "elapsed_ms":"monotonic time since this desktop's first diagnostic observation",
                "quality":"last locally received Core observation; historical after source loss or stop",
                "packet_window":"newly declared losses may belong to earlier sends; not a loss probability",
                "business_tx":"accepted local payload, not delivery rate or available bandwidth",
                "authorization":"observations do not grant access; configured routes are not exported as actual routes",
            },
        })
    }

    fn flush(&mut self, directory: &Path) {
        if !self.dirty
            || directory.as_os_str().is_empty()
            || self
                .last_write
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_write = Some(Instant::now());
        self.persistence_error = None;
        match serde_json::to_vec(&self.export()) {
            Ok(bytes) if bytes.len() <= FILE_LIMIT => {
                match nestlink_platform_security::replace_private_metadata(
                    &directory.join("native-network-diagnostics.json"),
                    &bytes,
                ) {
                    Ok(commit) => {
                        self.dirty = false;
                        self.persistence_error = match commit {
                            nestlink_platform_security::MetadataCommit::Durable => None,
                            nestlink_platform_security::MetadataCommit::Visible => {
                                Some("visible_durability_unconfirmed")
                            }
                        };
                    }
                    Err(_) => self.persistence_error = Some("private_file_unavailable"),
                }
            }
            _ => self.persistence_error = Some("bounded_report_unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_core::{NativeSessionView, Section};
    use std::sync::Arc;

    fn snapshot() -> Snapshot {
        Snapshot {
            native_session: Section {
                data: Some(Arc::new(NativeSessionView {
                    request_id: "private-raw-request-id".into(),
                    connection_generation: 7,
                    lease_sequence: 1,
                    status: NativeSessionStatus::Connected,
                    host_view_authorized: false,
                    path: Some(2),
                    quality: None,
                    stop_reason: None,
                    stop_effects: None,
                    cleanup: None,
                    failure: None,
                })),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn failure_survives_snapshot_removal_and_bounded_history_without_exporting_private_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut recorder = Recorder::default();
        let mut snapshot = snapshot();
        let at = Instant::now();
        recorder.observe_at(&snapshot, true, at);
        Arc::make_mut(
            snapshot
                .native_session
                .data
                .as_mut()
                .ok_or("missing session")?,
        )
        .status = NativeSessionStatus::Failed;
        recorder.observe_at(&snapshot, true, at);
        let terminal = recorder.latest_terminal.clone();
        snapshot.native_session.data = None;
        recorder.observe_at(&snapshot, false, at);
        for index in 0..(TIMELINE_EVENT_LIMIT + 5) {
            snapshot = self::snapshot();
            snapshot.generation = index as u64 + 2;
            recorder.observe_at(&snapshot, true, at);
        }
        assert_eq!(recorder.latest_terminal, terminal);
        assert_eq!(recorder.events.len(), TIMELINE_EVENT_LIMIT);
        assert!(recorder.dropped > 0);
        let encoded = serde_json::to_string(&recorder.export())?;
        assert!(!encoded.contains("private-raw-request-id"));
        assert!(!encoded.contains("private_network_prefixes"));
        assert!(encoded.contains(&request_hash("private-raw-request-id")));
        assert!(encoded.len() < FILE_LIMIT);
        Ok(())
    }

    #[test]
    fn unknown_quality_stays_null_and_disconnected_ipc_is_never_resampled()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut recorder = Recorder::default();
        let snapshot = snapshot();
        let at = Instant::now();
        recorder.observe_at(&snapshot, true, at);
        assert!(recorder.events.front().ok_or("missing event")?["quality"].is_null());
        recorder.observe_at(&snapshot, false, at);
        recorder.observe_at(&snapshot, false, at + Duration::from_secs(20));
        assert_eq!(recorder.events.len(), 2);
        assert_eq!(
            recorder.events.back().ok_or("missing source-loss event")?["state"]["event"],
            "daemon_disconnected"
        );
        Ok(())
    }

    #[test]
    fn export_hashes_grant_ids_and_omits_management_addresses_and_local_consent()
    -> Result<(), Box<dyn std::error::Error>> {
        use nestlink_app_core::{
            NativePathObservationBindingView, NativePathQualityView, ServerView,
        };
        use nestlink_protocol::api::{CandidateKind, Transport};
        let mut snapshot = snapshot();
        snapshot.server = Some(ServerView {
            origin: "https://secret-management.example/credential".into(),
            deployment_id: "private-deployment".into(),
            approved_issuer: [1; 32],
            verified_health: None,
            error: None,
        });
        snapshot.native_network.private_network_prefixes = vec!["192.168.99.0/24".into()];
        Arc::make_mut(
            snapshot
                .native_session
                .data
                .as_mut()
                .ok_or("missing session")?,
        )
        .quality = Some(NativePathQualityView {
            transport: Transport::Quic,
            candidate_kind: CandidateKind::Relay,
            network_generation: 0,
            bilateral_ice: false,
            original_binding: Some(NativePathObservationBindingView {
                business_grant_sha256: [3; 32],
                business_generation: 7,
                path_grant_id: Some("private-path-grant-id".into()),
                transport_group: Some([4; 32]),
                route_binding: Some([5; 32]),
            }),
            rtt_us: None,
            smoothed_rtt_change_us: None,
            packet_window: None,
            business_tx: None,
            available_bytes_per_second: None,
            cost: None,
        });
        let mut recorder = Recorder::default();
        recorder.observe_at(&snapshot, true, Instant::now());
        let report = recorder.export();
        let encoded = serde_json::to_string(&report)?;
        for private in [
            "private-path-grant-id",
            "private-raw-request-id",
            "secret-management",
            "private-deployment",
            "192.168.99",
        ] {
            assert!(!encoded.contains(private));
        }
        assert!(encoded.contains(&request_hash("private-path-grant-id")));
        assert!(report["events"][0]["quality"]["rtt_us"].is_null());
        assert!(report["events"][0]["quality"]["network_generation"].is_null());
        Ok(())
    }
}
