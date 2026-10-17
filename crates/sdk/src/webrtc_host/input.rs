//! Input envelopes may cross the HTTP permit refresh in either direction.
//! Only permits installed by the real, proved lease enter these two windows.
use super::WebRtcHostError;
use nestlink_identity::VerifiedPermit;
use nestlink_protocol::{
    Permission, SCHEMA_VERSION,
    webrtc::{MAX_WEBRTC_CONTROL_BYTES, WebRtcControl},
};
use nestlink_remote::{RuntimeClock, StopReport};
use nestlink_session::ClockSample;
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::sync::watch;

const INPUT_PERMIT_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct InputPermitWindow {
    permit: VerifiedPermit,
    // Exact original monotonic deadline, independent of a caller clock origin.
    // Never recomputed on refresh, queueing or packet arrival.
    deadline: Instant,
}

impl InputPermitWindow {
    fn check(&self, now: ClockSample) -> Result<(), WebRtcHostError> {
        let claims = self.permit.claims();
        claims.validate()?;
        if !claims.permissions.contains(&(Permission::Input as i32))
            || Instant::now() >= self.deadline
            || now.unix_ms < claims.issued_at_unix_ms
            || now.unix_ms >= claims.expires_at_unix_ms
        {
            return Err(WebRtcHostError::Permit);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct InputPermitWindows {
    current: InputPermitWindow,
    previous: Option<InputPermitWindow>,
}

impl InputPermitWindows {
    /// The caller obtains this deadline from the live lease for this digest.
    pub(super) fn new(permit: VerifiedPermit, deadline: Instant) -> Result<Self, WebRtcHostError> {
        permit.claims().validate()?;
        if !permit
            .claims()
            .permissions
            .contains(&(Permission::Input as i32))
        {
            return Err(WebRtcHostError::Permit);
        }
        Ok(Self {
            current: InputPermitWindow { permit, deadline },
            previous: None,
        })
    }

    /// Publish only after the actual lease has accepted the verified renewal.
    pub(super) fn advance(
        &self,
        permit: VerifiedPermit,
        deadline: Instant,
    ) -> Result<Self, WebRtcHostError> {
        if permit.digest() == self.current.permit.digest() {
            // Repeated GETs cannot extend either retained original deadline.
            return Ok(self.clone());
        }
        let old = self.current.permit.claims();
        let new = permit.claims();
        let mut expected = old.clone();
        expected.lease_sequence = new.lease_sequence;
        expected.issued_at_unix_ms = new.issued_at_unix_ms;
        expected.expires_at_unix_ms = new.expires_at_unix_ms;
        if self.current.permit.issuer() != permit.issuer()
            || &expected != new
            || old.lease_sequence.checked_add(1) != Some(new.lease_sequence)
            || new.issued_at_unix_ms < old.issued_at_unix_ms
        {
            return Err(WebRtcHostError::Permit);
        }
        let mut windows = Self::new(permit, deadline)?;
        windows.previous = Some(self.current.clone());
        Ok(windows)
    }

    fn select(
        &self,
        sequence: u64,
        retired_before: u64,
        now: ClockSample,
    ) -> Result<Option<InputPermitWindow>, WebRtcHostError> {
        self.current.check(now)?;
        if sequence < retired_before {
            return Err(WebRtcHostError::Permit);
        }
        let window = if sequence == self.current.permit.claims().lease_sequence {
            Some(&self.current)
        } else {
            self.previous
                .as_ref()
                .filter(|window| window.permit.claims().lease_sequence == sequence)
        };
        if let Some(window) = window {
            window.check(now)?;
            return Ok(Some(window.clone()));
        }
        if self.current.permit.claims().lease_sequence.checked_add(1) == Some(sequence) {
            return Ok(None);
        }
        Err(WebRtcHostError::Permit)
    }
}

pub(super) struct InputPermitResolver {
    windows: watch::Receiver<Option<InputPermitWindows>>,
    cancel: watch::Receiver<bool>,
    stopped: watch::Receiver<Option<StopReport>>,
    clock: RuntimeClock,
    retired_before: u64,
}

pub(super) struct ResolvedInput {
    pub(super) control: WebRtcControl,
    pub(super) guard: InputApplyGuard,
}

pub(super) struct InputApplyGuard {
    window: InputPermitWindow,
    windows: watch::Receiver<Option<InputPermitWindows>>,
    cancel: watch::Receiver<bool>,
    stopped: watch::Receiver<Option<StopReport>>,
    clock: RuntimeClock,
    retired_before: u64,
}

fn check_watches(
    windows: &watch::Receiver<Option<InputPermitWindows>>,
    cancel: &watch::Receiver<bool>,
    stopped: &watch::Receiver<Option<StopReport>>,
) -> Result<(), WebRtcHostError> {
    if windows.has_changed().is_err()
        || cancel.has_changed().is_err()
        || stopped.has_changed().is_err()
        || *cancel.borrow()
        || stopped.borrow().is_some()
    {
        return Err(WebRtcHostError::Closed);
    }
    Ok(())
}

impl InputApplyGuard {
    pub(super) fn original_deadlines(&self) -> (Instant, u64) {
        (
            self.window.deadline,
            self.window.permit.claims().expires_at_unix_ms,
        )
    }

    /// Recheck in the blocking injection task, before entering current authority.
    pub(super) fn check(&self) -> Result<(), WebRtcHostError> {
        check_watches(&self.windows, &self.cancel, &self.stopped)?;
        let windows = self
            .windows
            .borrow()
            .clone()
            .ok_or(WebRtcHostError::Permit)?;
        let window = windows
            .select(
                self.window.permit.claims().lease_sequence,
                self.retired_before,
                self.clock.sample()?,
            )?
            .ok_or(WebRtcHostError::Permit)?;
        if window.permit.digest() != self.window.permit.digest()
            || window.deadline != self.window.deadline
        {
            return Err(WebRtcHostError::Permit);
        }
        Ok(())
    }
}

impl InputPermitResolver {
    pub(super) fn new(
        windows: watch::Receiver<Option<InputPermitWindows>>,
        cancel: watch::Receiver<bool>,
        stopped: watch::Receiver<Option<StopReport>>,
        clock: RuntimeClock,
    ) -> Self {
        Self {
            windows,
            cancel,
            stopped,
            clock,
            retired_before: 0,
        }
    }

    /// Wake an idle input worker on shutdown, sender closure or authority change.
    pub(super) async fn changed(&mut self) -> Result<(), WebRtcHostError> {
        tokio::select! {
            biased;
            result = self.cancel.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
            result = self.stopped.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
            result = self.windows.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
        }
        check_watches(&self.windows, &self.cancel, &self.stopped)
    }

    /// Input sequence stays in InputController across all renewals. This extra
    /// watermark prevents old leases from returning with a larger input sequence.
    pub(super) fn input_event_applied(&mut self, lease_sequence: u64) {
        self.retired_before = self.retired_before.max(lease_sequence);
    }

    pub(super) async fn resolve(&mut self, bytes: &[u8]) -> Result<ResolvedInput, WebRtcHostError> {
        if bytes.is_empty() || bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(invalid_input());
        }
        let control: WebRtcControl = serde_json::from_slice(bytes).map_err(|_| invalid_input())?;
        let (schema, session, generation, sequence) = match &control {
            WebRtcControl::InputEvent {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                ..
            }
            | WebRtcControl::InputReleaseAll {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                ..
            } => (
                *schema_version,
                session_id,
                *connection_generation,
                *lease_sequence,
            ),
            _ => return Err(invalid_input()),
        };
        let mut wait_deadline = Instant::now()
            .checked_add(INPUT_PERMIT_WAIT_TIMEOUT)
            .ok_or_else(invalid_input)?;
        let mut waiting_for_refresh = false;
        loop {
            check_watches(&self.windows, &self.cancel, &self.stopped)?;
            // A publication and timer can both be ready after a delayed poll.
            // Check the retained budget before accepting that publication.
            if waiting_for_refresh && Instant::now() >= wait_deadline {
                return Err(WebRtcHostError::Permit);
            }
            let windows = self
                .windows
                .borrow_and_update()
                .clone()
                .ok_or(WebRtcHostError::Permit)?;
            let claims = windows.current.permit.claims();
            if schema != SCHEMA_VERSION
                || session != &claims.session_id
                || generation != claims.connection_generation
            {
                return Err(invalid_input());
            }
            let sampled_at = Instant::now();
            let now = self.clock.sample()?;
            if let Some(window) = windows.select(sequence, self.retired_before, now)? {
                // Validate against an actual signed permit, never edited claims.
                let control = WebRtcControl::decode_validated(bytes, window.permit.claims())?;
                return Ok(ResolvedInput {
                    control,
                    guard: InputApplyGuard {
                        window,
                        windows: self.windows.clone(),
                        cancel: self.cancel.clone(),
                        stopped: self.stopped.clone(),
                        clock: self.clock.clone(),
                        retired_before: self.retired_before,
                    },
                });
            }
            // Exactly the next sequence may wait for the signed HTTP refresh.
            // Neither repeated publications nor packets restart this budget.
            let wall_deadline = sampled_at
                .checked_add(Duration::from_millis(
                    claims.expires_at_unix_ms.saturating_sub(now.unix_ms),
                ))
                .ok_or(WebRtcHostError::Permit)?;
            wait_deadline = wait_deadline
                .min(windows.current.deadline)
                .min(wall_deadline);
            waiting_for_refresh = true;
            let wait = wait_deadline
                .checked_duration_since(Instant::now())
                .ok_or(WebRtcHostError::Permit)?;
            tokio::select! {
                biased;
                result = self.cancel.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
                result = self.stopped.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
                result = self.windows.changed() => result.map_err(|_| WebRtcHostError::Closed)?,
                _ = tokio::time::sleep(wait) => return Err(WebRtcHostError::Permit),
            }
        }
    }
}

fn invalid_input() -> WebRtcHostError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "input envelope is outside its proved permit binding",
    )
    .into()
}
