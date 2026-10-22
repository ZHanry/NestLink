//! Per-peer counters at the ICE socket and validation boundaries. No payloads.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use webrtc::ice::{
    candidate::CandidateType,
    udp_network::{ConnectivityEvent, ConnectivityObserver, SocketObservation, SocketStage},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IceIngressCounters {
    pub datagrams_received: u64,
    pub receive_errors: u64,
    pub stun_decode_rejected: u64,
    pub binding_requests_received: u64,
    pub binding_responses_received: u64,
    pub role_rejected: u64,
    pub username_rejected: u64,
    pub integrity_rejected: u64,
    pub unknown_remote_response: u64,
    pub send_errors: u64,
    #[serde(default)]
    pub port_discovery_probes: u64,
    #[serde(default)]
    pub port_discovery_authenticated: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IceIngressSnapshot {
    pub direct: IceIngressCounters,
    pub relay: IceIngressCounters,
    #[serde(default)]
    pub sockets: SocketSnapshot,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SocketSnapshot {
    pub candidates: [Option<SocketDiagnostic>; 16],
    pub dropped_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SocketDiagnostic {
    pub candidate_key: u64,
    pub kind: CandidateType,
    pub port: u16,
    pub ipv6: bool,
    pub first_event_ms: u64,
    pub last_event_ms: u64,
    pub receiver_spawned_ms: Option<u64>,
    pub receiver_ready_ms: Option<u64>,
    pub receiver_exit: Option<SocketStage>,
    pub receiver_exit_ms: Option<u64>,
    pub datagrams_received: u64,
    pub sends_accepted: u64,
    pub short_sends: u64,
    pub send_errors: u64,
    pub first_error: Option<SocketObservation>,
    pub first_error_ms: Option<u64>,
    pub last_error: Option<SocketObservation>,
    pub last_error_ms: Option<u64>,
    pub last_lifecycle_stage: SocketStage,
}

pub(super) struct IngressRecorder {
    attached: AtomicBool,
    counters: [[AtomicU64; 12]; 2],
    sockets: Mutex<SocketSnapshot>,
    started: std::time::Instant,
}

impl Default for IngressRecorder {
    fn default() -> Self {
        Self::new(std::time::Instant::now())
    }
}

impl IngressRecorder {
    pub(super) fn new(started: std::time::Instant) -> Self {
        Self {
            attached: AtomicBool::new(false),
            counters: Default::default(),
            sockets: Mutex::new(SocketSnapshot::default()),
            started,
        }
    }
}

impl IngressRecorder {
    pub(super) fn observer(self: &Arc<Self>) -> ConnectivityObserver {
        self.attached.store(true, Ordering::Relaxed);
        let recorder = self.clone();
        Arc::new(move |kind, event| {
            if let ConnectivityEvent::Socket(event) = event {
                recorder.socket_event(kind, event);
                return;
            }
            let path = usize::from(kind == CandidateType::Relay);
            let index = match event {
                ConnectivityEvent::DatagramReceived => 0,
                ConnectivityEvent::ReceiveError => 1,
                ConnectivityEvent::StunDecodeRejected => 2,
                ConnectivityEvent::BindingRequestReceived => 3,
                ConnectivityEvent::BindingResponseReceived => 4,
                ConnectivityEvent::RoleRejected => 5,
                ConnectivityEvent::UsernameRejected => 6,
                ConnectivityEvent::IntegrityRejected => 7,
                ConnectivityEvent::UnknownRemoteResponse => 8,
                ConnectivityEvent::SendError => 9,
                ConnectivityEvent::PortDiscoveryProbe => 10,
                ConnectivityEvent::PortDiscoveryAuthenticated => 11,
                ConnectivityEvent::Socket(_) => return,
            };
            recorder.counters[path][index].fetch_add(1, Ordering::Relaxed);
        })
    }

    fn socket_event(&self, kind: CandidateType, event: SocketObservation) {
        let elapsed_ms = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let mut sockets = self
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = sockets
            .candidates
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.candidate_key == event.candidate_key))
            .or_else(|| sockets.candidates.iter().position(Option::is_none));
        let Some(index) = index else {
            sockets.dropped_events = sockets.dropped_events.saturating_add(1);
            return;
        };
        let entry = sockets.candidates[index].get_or_insert(SocketDiagnostic {
            candidate_key: event.candidate_key,
            kind,
            port: event.port,
            ipv6: event.ipv6,
            first_event_ms: elapsed_ms,
            last_event_ms: elapsed_ms,
            receiver_spawned_ms: None,
            receiver_ready_ms: None,
            receiver_exit: None,
            receiver_exit_ms: None,
            datagrams_received: 0,
            sends_accepted: 0,
            short_sends: 0,
            send_errors: 0,
            first_error: None,
            first_error_ms: None,
            last_error: None,
            last_error_ms: None,
            last_lifecycle_stage: event.stage,
        });
        entry.last_event_ms = elapsed_ms;
        match event.stage {
            SocketStage::DatagramReceived => {
                entry.datagrams_received = entry.datagrams_received.saturating_add(1)
            }
            SocketStage::SendAccepted => {
                entry.sends_accepted = entry.sends_accepted.saturating_add(1)
            }
            SocketStage::SendShort => entry.short_sends = entry.short_sends.saturating_add(1),
            SocketStage::SendError => entry.send_errors = entry.send_errors.saturating_add(1),
            stage => {
                entry.last_lifecycle_stage = stage;
                if stage == SocketStage::ReceiverSpawned {
                    entry.receiver_spawned_ms.get_or_insert(elapsed_ms);
                }
                if stage == SocketStage::ReceiverReady {
                    entry.receiver_ready_ms.get_or_insert(elapsed_ms);
                }
                if matches!(
                    stage,
                    SocketStage::ReceiveError
                        | SocketStage::ReceiverClosed
                        | SocketStage::ReceiverClosedBeforeStart
                        | SocketStage::ReceiverAborted
                        | SocketStage::MissingConnection
                ) {
                    entry.receiver_exit.get_or_insert(stage);
                    entry.receiver_exit_ms.get_or_insert(elapsed_ms);
                }
            }
        }
        if event.error.is_some() {
            entry.first_error.get_or_insert(event);
            entry.first_error_ms.get_or_insert(elapsed_ms);
            entry.last_error = Some(event);
            entry.last_error_ms = Some(elapsed_ms);
        }
    }

    pub(super) fn snapshot(&self) -> Option<IceIngressSnapshot> {
        if !self.attached.load(Ordering::Relaxed) {
            return None;
        }
        let read = |path: usize| {
            let values = &self.counters[path];
            let at = |index: usize| values[index].load(Ordering::Relaxed);
            IceIngressCounters {
                datagrams_received: at(0),
                receive_errors: at(1),
                stun_decode_rejected: at(2),
                binding_requests_received: at(3),
                binding_responses_received: at(4),
                role_rejected: at(5),
                username_rejected: at(6),
                integrity_rejected: at(7),
                unknown_remote_response: at(8),
                send_errors: at(9),
                port_discovery_probes: at(10),
                port_discovery_authenticated: at(11),
            }
        };
        Some(IceIngressSnapshot {
            direct: read(0),
            relay: read(1),
            sockets: *self
                .sockets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_events_do_not_erase_first_failure_and_socket_evidence_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        use webrtc::ice::udp_network::{SocketError, SocketErrorCode, SocketErrorLayer};
        let recorder = Arc::new(IngressRecorder::default());
        let observe = recorder.observer();
        let first = SocketObservation {
            candidate_key: 1,
            port: 54321,
            ipv6: false,
            stage: SocketStage::ReceiveError,
            error: Some(SocketError {
                layer: SocketErrorLayer::Io,
                code: SocketErrorCode::Io,
                os_code: Some(10054),
            }),
        };
        observe(CandidateType::Host, ConnectivityEvent::Socket(first));
        observe(
            CandidateType::Host,
            ConnectivityEvent::Socket(SocketObservation {
                stage: SocketStage::ReceiverClosed,
                error: None,
                ..first
            }),
        );
        for candidate_key in 2..=30 {
            observe(
                CandidateType::Host,
                ConnectivityEvent::Socket(SocketObservation {
                    candidate_key,
                    ..first
                }),
            );
        }
        let snapshot = recorder.snapshot().ok_or("observer missing")?;
        let initial = snapshot.sockets.candidates[0].ok_or("first socket missing")?;
        assert_eq!(initial.first_error, Some(first));
        assert_eq!(initial.receiver_exit, Some(SocketStage::ReceiveError));
        assert_eq!(snapshot.sockets.dropped_events, 14);
        assert_eq!(snapshot.sockets.candidates.iter().flatten().count(), 16);
        let serialized = serde_json::to_vec(&snapshot)?;
        assert!(
            serialized.len() < 32_768,
            "socket snapshot exceeds private record budget"
        );
        let mut legacy = serde_json::to_value(snapshot)?;
        legacy
            .as_object_mut()
            .ok_or("object missing")?
            .remove("sockets");
        let decoded: IceIngressSnapshot = serde_json::from_value(legacy)?;
        assert_eq!(decoded.sockets, SocketSnapshot::default());
        Ok(())
    }

    #[test]
    fn absent_observer_is_unknown_and_each_peer_retains_its_own_counters() {
        let first = Arc::new(IngressRecorder::default());
        let second = Arc::new(IngressRecorder::default());
        assert!(first.snapshot().is_none());
        let observe = first.observer();
        observe(
            CandidateType::ServerReflexive,
            ConnectivityEvent::UsernameRejected,
        );
        observe(CandidateType::Relay, ConnectivityEvent::DatagramReceived);
        observe(CandidateType::Relay, ConnectivityEvent::SendError);
        assert_eq!(
            first.snapshot().map(|s| s.direct.username_rejected),
            Some(1)
        );
        assert_eq!(
            first.snapshot().map(|s| s.relay.datagrams_received),
            Some(1)
        );
        assert_eq!(first.snapshot().map(|s| s.relay.send_errors), Some(1));
        assert!(second.snapshot().is_none());
    }
}
