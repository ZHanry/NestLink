//! A window follows only a proved successor of its original daemon session.
use crate::{DesktopApp, RemoteViewportTarget};
use nestlink_app_core::{Authentication, Lifecycle, NativeSessionStatus, Snapshot};

pub(super) struct ViewportOwner {
    runtime_id: String,
    generation: u64,
    request_id: String,
    first_observed_generation: u64,
    chain_origin_generation: u64,
}

impl ViewportOwner {
    pub(super) fn new(
        snapshot: &Snapshot,
        target: &RemoteViewportTarget,
        runtime_id: Option<String>,
    ) -> Option<Self> {
        let session = snapshot.native_session.data.as_ref()?;
        let origin = session.recovery_chain_origin_generation
            .unwrap_or(session.connection_generation);
        if snapshot.authentication != Authentication::SignedIn
            || snapshot.lifecycle != Lifecycle::Running
            || snapshot.native_offline.is_some()
            || session.request_id != target.request_id
            || session.connection_generation != target.connection_generation
            || session.status != NativeSessionStatus::Connected
            || session.host_view_authorized
            || session.failure.is_some()
            || session.stop_reason.is_some()
            || origin == 0
            || origin > session.connection_generation
        {
            return None;
        }
        Some(Self {
            runtime_id: runtime_id.filter(|id| !id.is_empty())?,
            generation: snapshot.generation,
            request_id: target.request_id.clone(),
            first_observed_generation: target.connection_generation,
            chain_origin_generation: origin,
        })
    }

    fn proved_successor(
        &self,
        target: &RemoteViewportTarget,
        snapshot: &Snapshot,
        runtime_id: Option<&str>,
    ) -> Option<RemoteViewportTarget> {
        if runtime_id != Some(self.runtime_id.as_str())
            || snapshot.generation != self.generation
            || snapshot.lifecycle != Lifecycle::Running
            || snapshot.authentication != Authentication::SignedIn
            || snapshot.native_offline.is_some()
        {
            return None;
        }
        let session = snapshot.native_session.data.as_ref()?;
        if target.request_id != self.request_id
            || target.connection_generation < self.first_observed_generation
            || session.request_id != self.request_id
            || session.host_view_authorized
            || session.recovery_chain_origin_generation != Some(self.chain_origin_generation)
            || target.connection_generation >= session.connection_generation
        {
            return None;
        }
        Some(RemoteViewportTarget {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        })
    }

    fn successor(
        &self,
        target: &RemoteViewportTarget,
        snapshot: &Snapshot,
        runtime_id: Option<&str>,
    ) -> Option<RemoteViewportTarget> {
        let successor = self.proved_successor(target, snapshot, runtime_id)?;
        let session = snapshot.native_session.data.as_ref()?;
        (session.status == NativeSessionStatus::Connected
            && session.failure.is_none()
            && session.stop_reason.is_none()).then_some(successor)
    }
}

impl DesktopApp {
    pub(super) fn follow_recovered_viewport(&mut self, snapshot: &Snapshot) {
        if !self.connected || !self.remote_viewport_open {
            return;
        }
        if self.remote_window_cleanup.is_some() {
            self.follow_recovered_cleanup(snapshot);
            return;
        }
        let Some(target) = self.remote_viewport_target.as_ref() else {
            return;
        };
        let Some(owner) = self.remote_viewport_owner.as_ref() else {
            return;
        };
        let runtime = self.bridge.runtime_id();
        let Some(successor) = owner.successor(target, snapshot, runtime.as_deref()) else {
            return;
        };
        // The core already joined the old platform owners before proving this
        // generation. Release the window's old input binding and presentation
        // before changing its target; source selection and input stay explicit.
        self.bridge.set_video_interest(false);
        self.bridge.set_input_interest(false);
        self.clear_video();
        self.remote_viewport_target = Some(successor.clone());
        self.remote_tools_open = true;
        self.refresh_remote_request(snapshot, &successor.request_id);
    }

    pub(super) fn follow_recovered_cleanup(&mut self, snapshot: &Snapshot) {
        if !self.connected || !self.remote_viewport_open {
            return;
        }
        let Some(cleanup) = self.remote_window_cleanup.as_ref() else {
            return;
        };
        let Some(owner) = self.remote_viewport_owner.as_ref() else {
            return;
        };
        let runtime = self.bridge.runtime_id();
        let Some(successor) = owner.proved_successor(&cleanup.target, snapshot, runtime.as_deref()) else {
            return;
        };
        let Some(mut cleanup) = self.remote_window_cleanup.take() else {
            return;
        };
        // Close may race the actor's already committed successor. Keep the
        // original request revocation, but wait for and stop the proved current
        // owner. Delayed old-generation stop replies no longer own this slot.
        cleanup.target = successor.clone();
        cleanup.stop_submission = None;
        cleanup.stop_operation = None;
        cleanup.stop_status = None;
        self.remote_viewport_target = Some(successor);
        self.bridge.set_video_interest(false);
        self.bridge.set_input_interest(false);
        self.clear_video();
        self.submit_close_stop(snapshot, &mut cleanup);
        self.remote_window_cleanup = Some(cleanup);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use nestlink_app_core::{NativeSessionCleanup, NativeSessionStopReason, NativeSessionView};
    use std::sync::Arc;

    fn connected() -> Snapshot {
        let mut snapshot = Snapshot {
            generation: 7,
            authentication: Authentication::SignedIn,
            ..Snapshot::default()
        };
        snapshot.native_session.data = Some(Arc::new(NativeSessionView {
            request_id: "original-request".into(),
            connection_generation: 10,
            lease_sequence: 5,
            recovery_chain_origin_generation: Some(9),
            status: NativeSessionStatus::Connected,
            host_view_authorized: false,
            path: Some(2),
            quality: None,
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }));
        snapshot
    }

    #[test]
    fn only_the_original_observed_recovery_chain_can_move_an_existing_window() {
        let target = RemoteViewportTarget {
            request_id: "original-request".into(),
            connection_generation: 9,
        };
        let mut initial = connected();
        let session = Arc::make_mut(initial.native_session.data.as_mut().expect("session"));
        session.connection_generation = 9;
        session.recovery_chain_origin_generation = None;
        let owner = ViewportOwner::new(&initial, &target, Some("original-runtime".into())).expect("owner");
        let snapshot = connected();
        let next = owner
            .successor(&target, &snapshot, Some("original-runtime"))
            .expect("exact successor");
        assert_eq!(next.connection_generation, 10);
        assert!(owner.successor(&next, &snapshot, Some("original-runtime")).is_none());
        assert!(owner.successor(&target, &snapshot, None).is_none());
        assert!(owner.successor(&target, &snapshot, Some("new-runtime")).is_none());
        for mode in 0..12 {
            let mut altered = snapshot.clone();
            let session = Arc::make_mut(altered.native_session.data.as_mut().expect("session"));
            match mode {
                0 => session.recovery_chain_origin_generation = None,
                1 => session.recovery_chain_origin_generation = Some(8),
                2 => session.connection_generation = 9,
                3 => session.request_id = "another-request".into(),
                4 => session.status = NativeSessionStatus::Establishing,
                5 => session.status = NativeSessionStatus::Stopped,
                6 => session.host_view_authorized = true,
                7 => session.stop_reason = Some(NativeSessionStopReason::Revoked),
                8 => altered.generation += 1,
                9 => altered.authentication = Authentication::SignedOut,
                10 => altered.lifecycle = Lifecycle::Stopping,
                _ => session.failure = Some(nestlink_app_core::Failure {
                    kind: nestlink_app_core::FailureKind::NativeSessionUnavailable,
                    code: None,
                    status: None,
                }),
            }
            assert!(owner.successor(&target, &altered, Some("original-runtime")).is_none());
        }
        let mut backwards = connected();
        Arc::make_mut(backwards.native_session.data.as_mut().expect("session")).connection_generation = 9;
        assert!(owner.successor(&next, &backwards, Some("original-runtime")).is_none());
        let mut second = connected();
        Arc::make_mut(second.native_session.data.as_mut().expect("session")).connection_generation = 11;
        // Both sequential observation and a coalesced snapshot retain the
        // window's original owner. A counter increase without its root cannot.
        assert_eq!(owner.successor(&next, &second, Some("original-runtime")).expect("second").connection_generation, 11);
        assert_eq!(owner.successor(&target, &second, Some("original-runtime")).expect("skipped intermediate snapshot").connection_generation, 11);
        let reopened_owner = ViewportOwner::new(&snapshot, &next, Some("original-runtime".into())).expect("owner opened after recovery");
        assert!(reopened_owner.successor(&next, &second, Some("original-runtime")).is_some());
        assert!(reopened_owner.successor(&target, &second, Some("original-runtime")).is_none());
        let other = RemoteViewportTarget { request_id: "another-request".into(), ..target };
        assert!(owner.successor(&other, &second, Some("original-runtime")).is_none());
        Arc::make_mut(second.native_session.data.as_mut().expect("session")).recovery_chain_origin_generation = Some(10);
        assert!(owner.successor(&next, &second, Some("original-runtime")).is_none());
    }

    #[test]
    fn recovering_requires_completed_cleanup_and_remains_noninteractive() {
        let mut snapshot = connected();
        let session = Arc::make_mut(snapshot.native_session.data.as_mut().expect("session"));
        session.status = NativeSessionStatus::Establishing;
        session.stop_reason = Some(NativeSessionStopReason::NetworkChanged);
        session.cleanup = Some(NativeSessionCleanup::Succeeded);
        assert!(session.is_recovering());
        assert_ne!(session.status, NativeSessionStatus::Connected);
        session.cleanup = Some(NativeSessionCleanup::Failed);
        assert!(!session.is_recovering());
        session.cleanup = Some(NativeSessionCleanup::Succeeded);
        session.stop_reason = Some(NativeSessionStopReason::Revoked);
        assert!(!session.is_recovering());
        session.stop_reason = None;
        assert!(!session.is_recovering());
    }
}
