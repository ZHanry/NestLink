//! Per-peer counters at the ICE socket and validation boundaries. No payloads.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use webrtc::ice::{
    candidate::CandidateType,
    udp_network::{ConnectivityEvent, ConnectivityObserver},
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
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IceIngressSnapshot {
    pub direct: IceIngressCounters,
    pub relay: IceIngressCounters,
}

#[derive(Default)]
pub(super) struct IngressRecorder {
    attached: AtomicBool,
    counters: [[AtomicU64; 10]; 2],
}

impl IngressRecorder {
    pub(super) fn observer(self: &Arc<Self>) -> ConnectivityObserver {
        self.attached.store(true, Ordering::Relaxed);
        let recorder = self.clone();
        Arc::new(move |kind, event| {
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
            };
            recorder.counters[path][index].fetch_add(1, Ordering::Relaxed);
        })
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
            }
        };
        Some(IceIngressSnapshot {
            direct: read(0),
            relay: read(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
