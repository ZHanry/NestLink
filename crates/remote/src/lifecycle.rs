//! A weakly owned supervisor observes facts even while all business I/O is idle.
use crate::{RemoteError, RuntimeClock, permission};
use nestlink_identity::VerifiedPermit;
use nestlink_platform_network::{NetworkState, Reason};
use nestlink_protocol::{Path, Permission};
use nestlink_session::{Session, SessionState, StopEffects, StopReason};
use nestlink_transport_stream::Channel;
use nestlink_transport_stream::owner::TaskOwner;
use std::{
    io,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// Platform cleanup and contended session locks are synchronous. Let a
/// multithreaded Tokio executor replace this worker while it waits; otherwise
/// concurrent channel checks can occupy every worker needed to release a
/// platform operation. Isolated current-thread media runtimes keep their
/// existing synchronous boundary.
fn blocking_lifecycle<T>(operation: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|runtime| runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

/// Capture the generation used to construct the endpoint, not a fresh baseline
/// after the handshake. Closed observers and stale generations fail closed.
#[derive(Clone)]
pub struct NetworkBinding {
    receiver: watch::Receiver<NetworkState>,
    generation: u64,
}
impl NetworkBinding {
    pub fn new(
        receiver: watch::Receiver<NetworkState>,
        generation: u64,
    ) -> Result<Self, RemoteError> {
        let binding = Self {
            receiver,
            generation,
        };
        if generation == 0 || generation > i64::MAX as u64 || binding.reason().is_some() {
            return Err(RemoteError::Stopped);
        }
        Ok(binding)
    }
    fn reason(&self) -> Option<StopReason> {
        let state = *self.receiver.borrow();
        if self.receiver.has_changed().is_err()
            || !state.available
            || state.generation != self.generation
        {
            Some(if state.reason == Reason::Resumed {
                StopReason::Suspended
            } else {
                StopReason::NetworkChanged
            })
        } else {
            None
        }
    }
}

/// Synchronous, bounded platform cleanup. Implementations must not reenter the
/// lease or wait on Tokio; async transport/allocation teardown has its own task.
pub trait StopHandler: Send + 'static {
    /// Bounded platform facts checked even when business I/O is idle.
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn stop(&mut self, reason: StopReason, effects: StopEffects) -> io::Result<()>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupStatus {
    NotAttached,
    Succeeded,
    Failed(io::ErrorKind),
}
/// A report records required effects and attached synchronous cleanup. It does
/// not certify external allocations or OS effects for adapters not attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReport {
    pub reason: StopReason,
    pub effects: StopEffects,
    pub cleanup: CleanupStatus,
}
/// Read-only local facts from a stopped session, including the latest renewed
/// permit and its original monotonic deadline. This is not new authorization.
pub struct ReconnectionBudget {
    permit: VerifiedPermit,
    deadline: Instant,
}
impl ReconnectionBudget {
    pub fn permit(&self) -> &VerifiedPermit {
        &self.permit
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}
pub struct SessionLifecycle {
    pub stop: watch::Receiver<Option<StopReason>>,
    pub network: Option<NetworkBinding>,
    pub resources: Option<Box<dyn StopHandler>>,
    /// Local carrier facts published before an adapter closes its inner I/O.
    pub carrier: Option<watch::Receiver<Option<io::ErrorKind>>>,
}
impl SessionLifecycle {
    pub fn new(stop: watch::Receiver<Option<StopReason>>) -> Self {
        Self {
            stop,
            network: None,
            resources: None,
            carrier: None,
        }
    }
}
struct Managed {
    renewal_peer_deadline: Option<u64>,
    session: Session,
    handlers: Vec<Box<dyn StopHandler>>,
    report: Option<StopReport>,
    recovery_forbidden: bool,
    carrier_released: bool,
    input_attached: bool,
    capture_attached: bool,
    audio_attached: [bool; 2],
}
#[derive(Clone, Copy)]
pub(crate) enum AudioDirection {
    Capture = 0,
    Playback = 1,
}
impl Managed {
    fn effective_deadline_ms(&self) -> u64 {
        self.renewal_peer_deadline
            .map_or(self.session.deadline_ms(), |d| {
                d.min(self.session.deadline_ms())
            })
    }

    fn finish(&mut self) -> Option<StopReport> {
        if self.report.is_some() {
            return None;
        }
        let SessionState::Stopped(reason) = self.session.state() else {
            return None;
        };
        let effects = self.session.stop(reason);
        let mut cleanup = if self.handlers.is_empty() {
            CleanupStatus::NotAttached
        } else {
            CleanupStatus::Succeeded
        };
        blocking_lifecycle(|| {
            for handler in &mut self.handlers {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler.stop(reason, effects)
                }));
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.kind()),
                    Err(_) => Some(io::ErrorKind::Other),
                };
                if let Some(kind) = failure
                    && !matches!(cleanup, CleanupStatus::Failed(_))
                {
                    cleanup = CleanupStatus::Failed(kind);
                }
            }
        });
        let report = StopReport {
            reason,
            effects,
            cleanup,
        };
        self.report = Some(report);
        Some(report)
    }
}
struct Inner {
    managed: Mutex<Managed>,
    path: Path,
    clock: RuntimeClock,
    stop: watch::Receiver<Option<StopReason>>,
    network: Option<NetworkBinding>,
    carrier: Option<watch::Receiver<Option<io::ErrorKind>>>,
    updates: watch::Sender<u64>,
    reports: watch::Sender<Option<StopReport>>,
    input_permits: watch::Sender<Option<VerifiedPermit>>,
    task: Mutex<Option<TaskOwner>>,
}
impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, Managed>, RemoteError> {
        match self.managed.try_lock() {
            Ok(managed) => Ok(managed),
            Err(TryLockError::Poisoned(_)) => Err(RemoteError::Stopped),
            Err(TryLockError::WouldBlock) => {
                blocking_lifecycle(|| self.managed.lock()).map_err(|_| RemoteError::Stopped)
            }
        }
    }
    fn reconcile(&self, managed: &mut Managed) {
        if matches!(managed.session.state(), SessionState::Stopped(_)) {
            // Publish terminal revocation before any synchronous platform
            // cleanup. Observers must never reenter this lease from callbacks.
            self.input_permits.send_replace(None);
        }
        if let Some(report) = managed.finish() {
            self.reports.send_replace(Some(report));
            self.updates.send_modify(|v| *v = v.saturating_add(1));
        }
    }
    // Pure state observation for the execution-fenced commit. In particular,
    // this must never call StopHandler::check/stop or reconcile platform owners.
    fn check_renewal_state(&self, managed: &mut Managed) -> Result<(), RemoteError> {
        if let Some(reason) = (*self.stop.borrow())
            .or_else(|| {
                self.stop
                    .has_changed()
                    .is_err()
                    .then_some(StopReason::Revoked)
            })
            .or_else(|| self.network.as_ref().and_then(NetworkBinding::reason))
            .or_else(|| self.carrier.as_ref().and_then(|carrier| carrier_stop_reason(carrier, managed.carrier_released)))
        {
            if !reconnection_is_allowed(reason) {
                managed.recovery_forbidden = true;
            }
            managed.session.stop(reason);
        }
        match self.clock.sample() {
            Ok(now) => {
                if managed
                    .renewal_peer_deadline
                    .is_some_and(|d| now.monotonic_ms >= d)
                {
                    managed.recovery_forbidden = true;
                    managed.session.stop(StopReason::Expired);
                }
                managed.session.check_clock(now).map_err(RemoteError::from)
            }
            Err(error) => {
                managed.recovery_forbidden = true;
                managed.session.stop(StopReason::ClockInvalid);
                Err(error.into())
            }
        }
    }
    fn check(&self, managed: &mut Managed) -> Result<(), RemoteError> {
        let external = *self.stop.borrow();
        if let Some(reason) = external
            .or_else(|| {
                self.stop
                    .has_changed()
                    .is_err()
                    .then_some(StopReason::Revoked)
            })
            .or_else(|| self.network.as_ref().and_then(NetworkBinding::reason))
            .or_else(|| self.carrier.as_ref().and_then(|carrier| carrier_stop_reason(carrier, managed.carrier_released)))
        {
            if !reconnection_is_allowed(reason) {
                managed.recovery_forbidden = true;
            }
            managed.session.stop(reason);
        }
        if !matches!(managed.session.state(), SessionState::Stopped(_)) {
            for handler in &mut managed.handlers {
                let checked =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.check()));
                if !matches!(checked, Ok(Ok(()))) {
                    managed.recovery_forbidden = true;
                    managed.session.stop(StopReason::PlatformChanged);
                    break;
                }
            }
        }
        let result = match self.clock.sample() {
            Ok(now) => {
                if managed
                    .renewal_peer_deadline
                    .is_some_and(|d| now.monotonic_ms >= d)
                {
                    managed.recovery_forbidden = true;
                    managed.session.stop(StopReason::Expired);
                }
                managed.session.check_clock(now).map_err(RemoteError::from)
            }
            Err(error) => {
                managed.recovery_forbidden = true;
                managed.session.stop(StopReason::ClockInvalid);
                Err(error.into())
            }
        };
        if let SessionState::Stopped(reason) = managed.session.state()
            && !reconnection_is_allowed(reason)
        {
            managed.recovery_forbidden = true;
        }
        self.reconcile(managed);
        result
    }
}

fn carrier_stop_reason(carrier: &watch::Receiver<Option<io::ErrorKind>>, released: bool) -> Option<StopReason> {
    let failure = *carrier.borrow();
    if failure.is_none() && !released && carrier.has_changed().is_err() {
        return Some(StopReason::Revoked);
    }
    failure.map(|kind| match kind {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut => StopReason::TransportLost,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => StopReason::ProtocolViolation,
        _ => StopReason::Revoked,
    })
}

fn reconnection_is_allowed(reason: StopReason) -> bool {
    matches!(
        reason,
        StopReason::NetworkChanged | StopReason::TransportLost
    )
}
impl Drop for Inner {
    fn drop(&mut self) {
        let managed = self
            .managed
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        managed.session.stop(StopReason::ExplicitExit);
        self.input_permits.send_replace(None);
        if let Some(report) = managed.finish() {
            self.reports.send_replace(Some(report));
        }
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.request_close();
        }
    }
}

/// Separate from all data queues. No task holds a strong ownership cycle.
#[derive(Clone)]
pub struct LeaseControl {
    inner: Arc<Inner>,
}
impl LeaseControl {
    /// Bounded local media authority for a same-machine receipt. Observation
    /// never extends the signed lease and is rechecked at every media chunk.
    pub fn media_authority_remaining(
        &self,
        channel: Channel,
        generation: u64,
    ) -> Result<Duration, RemoteError> {
        self.check_media_binding(channel, generation)?;
        self.remaining()
    }
    /// Attach the common lifecycle to a session already proved over another
    /// authenticated carrier (for example WebRTC's reliable control channel).
    /// A setup permit opens lifecycle supervision only. Every business/capture
    /// attachment remains denied until a running lease has been installed.
    pub fn from_proved_session(
        session: Session,
        path: Path,
        clock: RuntimeClock,
        lifecycle: SessionLifecycle,
    ) -> Result<Self, RemoteError> {
        Self::new_inner(session, path, clock, lifecycle, true)
    }

    pub(crate) fn new(
        session: Session,
        path: Path,
        clock: RuntimeClock,
        lifecycle: SessionLifecycle,
    ) -> Result<Self, RemoteError> {
        Self::new_inner(session, path, clock, lifecycle, false)
    }

    fn new_inner(
        mut session: Session,
        path: Path,
        clock: RuntimeClock,
        lifecycle: SessionLifecycle,
        allow_setup: bool,
    ) -> Result<Self, RemoteError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        session.check_clock(clock.sample()?)?;
        if allow_setup && session.is_setup_authorization() {
            session.check_proved_setup(path, clock.monotonic_ms())?;
        } else {
            session.authorize(Permission::View, path, clock.monotonic_ms())?;
        }
        let (updates, _) = watch::channel(0);
        let (reports, _) = watch::channel(None);
        let (input_permits, _) = watch::channel(None);
        let control = Self {
            inner: Arc::new(Inner {
                managed: Mutex::new(Managed {
                    renewal_peer_deadline: None,
                    session,
                    handlers: lifecycle.resources.into_iter().collect(),
                    report: None,
                    recovery_forbidden: false,
                    carrier_released: false,
                    input_attached: false,
                    capture_attached: false,
                    audio_attached: [false; 2],
                }),
                path,
                clock,
                stop: lifecycle.stop,
                network: lifecycle.network,
                carrier: lifecycle.carrier,
                updates,
                reports,
                input_permits,
                task: Mutex::new(None),
            }),
        };
        control.remaining()?;
        let weak = Arc::downgrade(&control.inner);
        let mut updates = control.subscribe_updates();
        let mut stop = control.inner.stop.clone();
        let mut network = control.inner.network.clone();
        let task = runtime.spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else { break; };
                let lease = LeaseControl { inner };
                let Ok(remaining) = lease.remaining() else { break; };
                drop(lease);
                tokio::select! {
                    biased;
                    _=stop.changed()=>{},
                    _=async { match &mut network { Some(binding) => { let _ = binding.receiver.changed().await; }, None => std::future::pending().await } }=>{},
                    _=updates.changed()=>{},
                    _=tokio::time::sleep(remaining.min(Duration::from_millis(250)))=>{},
                }
            }
        });
        *control
            .inner
            .task
            .lock()
            .map_err(|_| RemoteError::Stopped)? = Some(TaskOwner::new(task));
        Ok(control)
    }
    pub(crate) async fn wait_supervisor_stopped(
        &self,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let task = self
            .inner
            .task
            .lock()
            .map_err(|_| io::Error::other("lease supervisor owner poisoned"))?
            .clone();
        if let Some(task) = task {
            task.close_and_wait(deadline).await?;
        }
        Ok(())
    }
    pub fn subscribe_stopped(&self) -> watch::Receiver<Option<StopReport>> {
        self.inner.reports.subscribe()
    }
    /// A successful transport-owner receipt precedes releasing its failure
    /// sender. Its later sender Drop is cleanup, while any recorded failure
    /// remains authoritative. A live or unsuccessfully closed owner has no
    /// such exemption from fail-closed observer loss.
    pub(crate) fn transport_owner_released(&self) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        if managed.report.is_none() {
            return Err(RemoteError::Stopped);
        }
        managed.carrier_released = true;
        Ok(())
    }
    /// Original signed Input permits accepted by this actual proved lease.
    /// Poll this outside InputDevice/StopHandler callbacks: it is observation,
    /// never authority to prolong the current local deadline or revive None.
    pub fn subscribe_input_permits(
        &self,
    ) -> Result<watch::Receiver<Option<VerifiedPermit>>, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let permit = managed
            .session
            .current_input_permit(self.inner.path, self.inner.clock.monotonic_ms());
        self.inner.reconcile(&mut managed);
        let permit = permit?;
        self.inner.input_permits.send_replace(Some(permit));
        Ok(self.inner.input_permits.subscribe())
    }
    pub fn reconnection_budget(&self) -> Result<ReconnectionBudget, RemoteError> {
        let managed = self.inner.lock()?;
        if self.inner.stop.has_changed().is_err()
            || self.inner.stop.borrow().is_some()
            || self.inner.network.as_ref().is_some_and(|network| {
                network.receiver.has_changed().is_err()
                    || network
                        .reason()
                        .is_some_and(|reason| reason != StopReason::NetworkChanged)
            })
            || self
                .inner
                .carrier
                .as_ref()
                .and_then(|carrier| carrier_stop_reason(carrier, managed.carrier_released))
                .is_some_and(|reason| reason != StopReason::TransportLost)
            || managed.recovery_forbidden
            || managed
                .report
                .is_none_or(|report| matches!(report.cleanup, CleanupStatus::Failed(_)))
        {
            return Err(RemoteError::Stopped);
        }
        if managed.renewal_peer_deadline.is_some() {
            return Err(RemoteError::Stopped);
        }
        let permit = managed
            .session
            .reconnection_permit(self.inner.clock.sample()?)?;
        Ok(ReconnectionBudget {
            permit,
            deadline: self
                .inner
                .clock
                .start
                .checked_add(Duration::from_millis(managed.effective_deadline_ms()))
                .ok_or(RemoteError::Stopped)?,
        })
    }
    pub(crate) fn subscribe_updates(&self) -> watch::Receiver<u64> {
        self.inner.updates.subscribe()
    }
    pub fn remaining(&self) -> Result<Duration, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        Ok(Duration::from_millis(
            managed
                .effective_deadline_ms()
                .saturating_sub(self.inner.clock.monotonic_ms()),
        ))
    }
    /// Observe the effective deadline of this live proved lease, including its
    /// original carrier ceiling and any pending peer renewal limit. Reading it
    /// grants no permission and cannot extend the lease or authorize recovery.
    pub fn current_deadline(&self) -> Result<Instant, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        self.inner
            .clock
            .start
            .checked_add(Duration::from_millis(managed.effective_deadline_ms()))
            .ok_or(RemoteError::Stopped)
    }
    pub(crate) fn authorize(&self, channel: Channel) -> Result<(), RemoteError> {
        self.operation(permission(channel)?, || Ok(()))
    }
    pub fn current_native_permit(&self) -> Result<VerifiedPermit, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        Ok(managed.session.current_verified_permit().clone())
    }
    pub(crate) fn native_renewal_required(&self) -> Result<bool, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        Ok(managed.session.binding().media.is_some())
    }
    pub fn renewal_clock(&self) -> Result<nestlink_session::ClockSample, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        Ok(self.inner.clock.sample()?)
    }
    pub(crate) fn transport_binding(&self) -> Result<([u8; 32], u64, Vec<Channel>), RemoteError> {
        use prost::Message;
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let mut transcript = managed.session.proof_transcript();
        // The permit digest binds deployment, resource, both keys, capability
        // and policy. Each endpoint's random proof challenge differs. Capture
        // this binding once, before renewal changes the permit digest.
        transcript.challenge.clear();
        let mut channels = Vec::new();
        for channel in super::queues::CHANNELS {
            match managed.session.authorize(
                permission(channel)?,
                self.inner.path,
                self.inner.clock.monotonic_ms(),
            ) {
                Ok(()) => channels.push(channel),
                Err(error) if error.code == nestlink_protocol::ErrorCode::PermissionRequired => {}
                Err(error) => {
                    self.inner.reconcile(&mut managed);
                    return Err(error.into());
                }
            }
        }
        Ok((
            nestlink_identity::digest(&transcript.encode_to_vec()),
            transcript.connection_generation,
            channels,
        ))
    }
    /// Read the original monotonic deadline only for the exact permit that
    /// currently authorizes Input on this live proved lease. This cannot renew,
    /// recover, grant a channel or turn a decoded input envelope into authority.
    pub fn input_permit_deadline(&self, permit: &VerifiedPermit) -> Result<Instant, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let authorized = managed.session.authorize(
            Permission::Input,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        );
        self.inner.reconcile(&mut managed);
        authorized?;
        if managed.session.proof_transcript().permit_sha256.as_slice() != permit.digest() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "input deadline does not match the current verified permit",
            )
            .into());
        }
        self.inner
            .clock
            .start
            .checked_add(Duration::from_millis(managed.effective_deadline_ms()))
            .ok_or(RemoteError::Stopped)
    }

    /// Serializes synchronous platform operations with stop/cleanup. This is
    /// deliberately private so business callers cannot hold the session lock.
    pub(crate) fn operation<T>(
        &self,
        permission: Permission,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, RemoteError> {
        self.operation_with_generation(permission, None, operation)
    }
    /// Revalidate a decoded/encoded media delivery against this exact session.
    /// The check is its authorization linearization point; previously handed
    /// out bytes cannot be recalled. Codecs must run outside this call, and
    /// consumers must discard queued output when subscribe_stopped fires.
    /// This intentionally exposes no caller-controlled closure under the lease.
    pub fn check_media_binding(
        &self,
        channel: Channel,
        generation: u64,
    ) -> Result<(), RemoteError> {
        if !matches!(channel, Channel::Video | Channel::Audio) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a media channel").into());
        }
        self.check_channel_binding(channel, generation)
    }
    /// Read a signed capability only from this currently authorized media lease.
    pub fn media_capability(&self, capability: &str) -> Result<bool, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::View,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        Ok(managed.session.negotiated_capability(capability))
    }
    /// Exact format scope from the verified permit under the current View lease.
    pub fn media_formats(
        &self,
    ) -> Result<Option<nestlink_protocol::media_format::FormatSet>, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::View,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        Ok(managed.session.media_formats()?)
    }
    /// Backend identity from the generation-bound local executable evidence.
    pub fn local_media_backend(
        &self,
        direction: nestlink_protocol::media_authority::MediaDirection,
    ) -> Result<Option<String>, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::View,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        match managed.session.local_media_binding() {
            Some(binding) if binding.local_direction() == direction => {
                Ok(Some(binding.backend().to_owned()))
            }
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local media direction differs",
            )
            .into()),
            None => Ok(None),
        }
    }
    /// Recheck a delivered business frame against its original session. Control
    /// is reserved for the connection handshake and cannot be delivered here.
    pub fn check_channel_binding(
        &self,
        channel: Channel,
        generation: u64,
    ) -> Result<(), RemoteError> {
        self.operation_with_generation(permission(channel)?, Some(generation), || Ok(()))
    }
    /// Captures only an already-authorized original clipboard session. The
    /// result is a public binding, never a fresh local consent or permission.
    pub fn clipboard_session_id(
        &self,
        channel: Channel,
        generation: u64,
    ) -> Result<String, RemoteError> {
        if !matches!(channel, Channel::ClipboardRead | Channel::ClipboardWrite) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "not a clipboard channel").into(),
            );
        }
        self.check_channel_binding(channel, generation)?;
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        if managed.session.binding().connection_generation != generation {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard generation mismatch",
            )
            .into());
        }
        Ok(managed.session.binding().session_id.clone())
    }
    pub fn check_clipboard_binding(
        &self,
        session_id: &str,
        channel: Channel,
        generation: u64,
    ) -> Result<(), RemoteError> {
        if self.clipboard_session_id(channel, generation)? != session_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard session mismatch",
            )
            .into());
        }
        Ok(())
    }
    pub(crate) fn file_resume_binding(
        &self,
        generation: u64,
    ) -> Result<nestlink_session::SessionBinding, RemoteError> {
        self.check_channel_binding(Channel::FileRead, generation)?;
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let mut binding = managed.session.binding().clone();
        // Rebinding permits a new connection, never a new resource, principal,
        // key, policy or capability. New permission is still checked separately.
        binding.connection_generation = 0;
        Ok(binding)
    }
    pub(crate) fn file_pause_allowed(&self) -> bool {
        // A first transport-stop report is historical, not continuing consent.
        // Check the original deadline, current outside stop/clock/cleanup facts
        // and the current network observer before retaining a partial handle.
        self.reconnection_budget().is_ok()
    }
    fn operation_with_generation<T>(
        &self,
        permission: Permission,
        generation: Option<u64>,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let authorization =
            managed
                .session
                .authorize(permission, self.inner.path, self.inner.clock.monotonic_ms());
        self.inner.reconcile(&mut managed);
        authorization?;
        if generation.is_some_and(|generation| {
            generation != managed.session.proof_transcript().connection_generation
        }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media connection generation mismatch",
            )
            .into());
        }
        operation().map_err(RemoteError::from)
    }
    pub(crate) fn audio_operation<T>(
        &self,
        generation: u64,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, RemoteError> {
        self.operation_with_generation(Permission::Audio, Some(generation), operation)
    }
    pub(crate) fn attach_audio(
        &self,
        generation: u64,
        direction: AudioDirection,
        handler: Box<dyn StopHandler>,
    ) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::Audio,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        let index = direction as usize;
        if managed.audio_attached[index]
            || managed.handlers.len() >= 8
            || managed.session.proof_transcript().connection_generation != generation
        {
            return Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "audio binding rejected").into(),
            );
        }
        managed.handlers.push(handler);
        managed.audio_attached[index] = true;
        Ok(())
    }
    pub(crate) fn attach_input(
        &self,
        generation: u64,
        handler: Box<dyn StopHandler>,
    ) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::Input,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        if managed.input_attached
            || managed.handlers.len() >= 8
            || managed.session.proof_transcript().connection_generation != generation
        {
            return Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "input binding rejected").into(),
            );
        }
        managed.handlers.push(handler);
        managed.input_attached = true;
        Ok(())
    }
    pub(crate) fn attach_capture(
        &self,
        generation: u64,
        handler: Box<dyn StopHandler>,
    ) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        managed.session.authorize(
            Permission::View,
            self.inner.path,
            self.inner.clock.monotonic_ms(),
        )?;
        if managed.capture_attached
            || managed.handlers.len() >= 8
            || managed.session.proof_transcript().connection_generation != generation
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture binding rejected",
            )
            .into());
        }
        managed.handlers.push(handler);
        managed.capture_attached = true;
        Ok(())
    }
    pub fn stop(&self, reason: StopReason) -> Result<StopEffects, RemoteError> {
        let mut managed = self.inner.lock()?;
        if !reconnection_is_allowed(reason) {
            managed.recovery_forbidden = true;
        }
        let effects = managed.session.stop(reason);
        self.inner.reconcile(&mut managed);
        Ok(effects)
    }
    /// Stop an active lease from an owned-resource destructor. Once another
    /// stop reason has won, teardown notifications from dropping channel/task
    /// guards are cleanup only and cannot change reconnection eligibility.
    pub fn stop_if_running(&self, reason: StopReason) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        if matches!(managed.session.state(), SessionState::Stopped(_)) {
            return Ok(());
        }
        let observed_stop = (*self.inner.stop.borrow())
            .or_else(|| {
                self.inner
                    .stop
                    .has_changed()
                    .is_err()
                    .then_some(StopReason::Revoked)
            })
            .or_else(|| self.inner.network.as_ref().and_then(NetworkBinding::reason))
            .or_else(|| self.inner.carrier.as_ref().and_then(|carrier| carrier_stop_reason(carrier, managed.carrier_released)));
        if let Some(observed) = observed_stop {
            if !reconnection_is_allowed(observed) {
                managed.recovery_forbidden = true;
            }
            managed.session.stop(observed);
            self.inner.reconcile(&mut managed);
            return Ok(());
        }
        if !reconnection_is_allowed(reason) {
            managed.recovery_forbidden = true;
        }
        managed.session.stop(reason);
        self.inner.reconcile(&mut managed);
        Ok(())
    }
    /// Refresh validated local evidence inside the still-live signed scope.
    /// The application separately controls actual execution owner stop/join.
    pub fn refresh_local_media_binding(
        &self,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: nestlink_session::EndpointRole,
    ) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        let sample = self.inner.clock.sample()?;
        let result = managed
            .session
            .refresh_local_media_binding(frozen, local, role, sample)
            .map_err(RemoteError::from);
        self.inner.reconcile(&mut managed);
        result?;
        self.inner.check(&mut managed)
    }
    /// Lock order is execution fence, then managed session. No I/O or await
    /// may run inside either lock. Binding, permit and input observers commit
    /// as one transition; stop/expiry are checked again under the session lock.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_with_local_media(
        &self,
        permit: VerifiedPermit,
        request_started_ms: u64,
        expected_sequence: u64,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: nestlink_session::EndpointRole,
        execution: &dyn crate::native_renewal::NativeExecutionFence,
    ) -> Result<(), RemoteError> {
        self.renew_with_local_media_pending(
            permit,
            request_started_ms,
            expected_sequence,
            frozen,
            local,
            role,
            false,
            execution,
        )
    }
    /// Controller commits remain capped by the previous peer lease until an
    /// authenticated Applied acknowledgement completes this exact sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_with_local_media_pending(
        &self,
        permit: VerifiedPermit,
        request_started_ms: u64,
        expected_sequence: u64,
        frozen: &nestlink_protocol::media_authority::FrozenMediaScope,
        local: &nestlink_protocol::media_authority::MediaAnnouncement,
        role: nestlink_session::EndpointRole,
        await_peer: bool,
        execution: &dyn crate::native_renewal::NativeExecutionFence,
    ) -> Result<(), RemoteError> {
        // Handler checks and their possible cleanup happen before acquiring
        // execution currentness. Never hold a registry fence across callbacks.
        {
            let mut managed = self.inner.lock()?;
            self.inner.check(&mut managed)?;
        }
        let mut permit = Some(permit);
        let mut outcome = None;
        let mut calls = 0usize;
        let fenced = execution.with_current(&mut || {
            calls = calls.saturating_add(1);
            if calls != 1 || outcome.is_some() {
                return Err(io::Error::other("execution fence repeated operation"));
            }
            let result = (|| {
                // A competing cleanup may hold managed while entering the
                // registry. Never wait for it while holding the registry fence.
                let mut managed = self
                    .inner
                    .managed
                    .try_lock()
                    .map_err(|_| RemoteError::Stopped)?;
                self.inner.check_renewal_state(&mut managed)?;
                let permit = permit
                    .take()
                    .ok_or_else(|| io::Error::other("renewal already consumed"))?;
                let observed = permit.clone();
                let old_peer_deadline = managed.effective_deadline_ms();
                if managed.renewal_peer_deadline.is_some() {
                    return Err(RemoteError::Stopped);
                }
                managed.session.renew_with_local_media(
                    permit,
                    request_started_ms,
                    expected_sequence,
                    frozen,
                    local,
                    role,
                    self.inner.clock.sample()?,
                )?;
                managed.renewal_peer_deadline = await_peer.then_some(old_peer_deadline);
                self.inner.check_renewal_state(&mut managed)?;
                self.inner.input_permits.send_replace(
                    observed
                        .claims()
                        .permissions
                        .contains(&(Permission::Input as i32))
                        .then_some(observed),
                );
                self.inner.updates.send_modify(|v| *v = v.saturating_add(1));
                Ok(())
            })();
            outcome = Some(result);
            Ok(())
        });
        // The fence is released on all branches before native cleanup runs.
        let result = match fenced {
            _ if calls != 1 => {
                Err(io::Error::other("execution fence must invoke exactly once").into())
            }
            Err(error) => Err(error.into()),
            Ok(()) => outcome.unwrap_or_else(|| {
                Err(io::Error::other("execution fence skipped operation").into())
            }),
        };
        let mut managed = self.inner.lock()?;
        if result.is_err() {
            managed.recovery_forbidden = true;
            managed.session.stop(StopReason::PlatformChanged);
        }
        // Outside-stop/expiry may have won immediately after the fenced commit.
        let final_state = self.inner.check_renewal_state(&mut managed);
        self.inner.reconcile(&mut managed);
        result?;
        final_state
    }
    pub fn acknowledge_native_renewal(&self, sequence: u64) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        if managed.renewal_peer_deadline.is_none()
            || managed
                .session
                .current_verified_permit()
                .claims()
                .lease_sequence
                != sequence
        {
            return Err(RemoteError::Stopped);
        }
        managed.renewal_peer_deadline = None;
        self.inner.updates.send_modify(|v| *v = v.saturating_add(1));
        Ok(())
    }
    pub fn renew(
        &self,
        permit: VerifiedPermit,
        request_started_ms: u64,
    ) -> Result<(), RemoteError> {
        let mut managed = self.inner.lock()?;
        self.inner.check(&mut managed)?;
        if managed.renewal_peer_deadline.is_some() {
            return Err(RemoteError::Stopped);
        }
        let observed = permit.clone();
        let result = managed
            .session
            .renew(permit, request_started_ms, self.inner.clock.sample()?)
            .map_err(RemoteError::from);
        self.inner.reconcile(&mut managed);
        if result.is_ok() {
            if observed
                .claims()
                .permissions
                .contains(&(Permission::Input as i32))
            {
                self.inner.input_permits.send_replace(Some(observed));
            } else {
                self.inner.input_permits.send_replace(None);
            }
            self.inner.updates.send_modify(|v| *v = v.saturating_add(1));
        }
        result
    }
}
