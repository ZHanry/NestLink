//! Local monotonic browser observations retained after peer teardown.
#[cfg(target_arch = "wasm32")]
mod wasm {
    use nestlink_protocol::{
        api::SignalPayload,
        diagnostics::{
            ConnectionFailure, ConnectionObservation, ConnectionStage, ConnectionTimeline,
            SignalSummary,
        },
    };
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    pub struct BrowserConnectionDiagnostics {
        started_ms: f64,
        timeline: Rc<RefCell<ConnectionTimeline>>,
    }
    fn monotonic_ms() -> Option<f64> {
        web_sys::window()?
            .performance()
            .map(|clock| clock.now())
            .filter(|now| now.is_finite() && *now >= 0.0)
    }
    impl BrowserConnectionDiagnostics {
        pub fn new(request: &str, generation: u64, local: &str, remote: &str) -> Self {
            let mut timeline =
                ConnectionTimeline::new(request, generation, js_sys::Date::now() as u64);
            timeline.local_device_sha256 =
                Some(nestlink_protocol::diagnostics::request_hash(local));
            timeline.remote_device_sha256 =
                Some(nestlink_protocol::diagnostics::request_hash(remote));
            Self {
                started_ms: monotonic_ms().unwrap_or(f64::NAN),
                timeline: Rc::new(RefCell::new(timeline)),
            }
        }
        pub fn snapshot(&self) -> ConnectionTimeline {
            self.timeline.borrow().clone()
        }
        pub fn mark(&self, stage: ConnectionStage) {
            self.observe(stage, None, None);
        }
        pub fn mark_once(&self, stage: ConnectionStage) {
            if !self
                .timeline
                .borrow()
                .events
                .iter()
                .any(|event| event.stage == stage)
            {
                self.mark(stage);
            }
        }
        pub fn signal(&self, stage: ConnectionStage, payload: &SignalPayload) {
            self.observe(stage, Some(SignalSummary::from_payload(payload)), None);
        }
        pub fn failure(&self, failure: ConnectionFailure) {
            let stage = self
                .timeline
                .borrow()
                .events
                .iter()
                .rev()
                .find(|event| event.stage != ConnectionStage::Stopped)
                .map_or(ConnectionStage::PeerCreated, |event| event.stage);
            self.observe(stage, None, Some(failure));
        }
        fn observe(
            &self,
            stage: ConnectionStage,
            signal: Option<SignalSummary>,
            failure: Option<ConnectionFailure>,
        ) {
            let Some(now) = monotonic_ms() else {
                return;
            };
            let elapsed = now - self.started_ms;
            if !elapsed.is_finite() || elapsed < 0.0 {
                return;
            }
            self.timeline.borrow_mut().observe(ConnectionObservation {
                elapsed_ms: elapsed as u64,
                stage,
                signal,
                failure,
            });
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use wasm::BrowserConnectionDiagnostics;
