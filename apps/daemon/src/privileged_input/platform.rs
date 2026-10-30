use super::*;
use nestlink_app_core::{
    Authentication, BrowserHostStatus, Lifecycle, NativeSessionStatus, Snapshot,
};
use nestlink_privileged::{
    TrustPins,
    windows::{BrokerClient, BrokerInput},
    wire::BrokerState,
};
use nestlink_remote::{
    LeaseControl,
    input::{InputDevice, InputEpoch, InputLayout, PlatformInput},
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, PartialEq, Eq)]
struct Context {
    generation: u64,
    deployment_id: String,
    issuer: [u8; 32],
    host_device_id: String,
    host_key_sha256: [u8; 32],
}
impl Context {
    fn from_snapshot(snapshot: &Snapshot, idle: bool) -> Result<Self, PrivilegedInputError> {
        if snapshot.lifecycle != Lifecycle::Running {
            return Err(PrivilegedInputError::Stopped);
        }
        if snapshot.authentication != Authentication::SignedIn {
            return Err(PrivilegedInputError::Unauthorized);
        }
        if idle
            && (snapshot.native_session.data.as_ref().is_some_and(|view| {
                matches!(
                    view.status,
                    NativeSessionStatus::Establishing
                        | NativeSessionStatus::Connected
                        | NativeSessionStatus::Stopping
                )
            }) || snapshot.browser_host.data.as_ref().is_some_and(|view| {
                matches!(
                    view.status,
                    BrowserHostStatus::Establishing
                        | BrowserHostStatus::Connected
                        | BrowserHostStatus::Stopping
                )
            }))
        {
            return Err(PrivilegedInputError::Busy);
        }
        let server = snapshot
            .server
            .as_ref()
            .ok_or(PrivilegedInputError::Unauthorized)?;
        let installation = snapshot
            .installation
            .as_ref()
            .ok_or(PrivilegedInputError::Unauthorized)?;
        if server.error.is_some() || server.verified_health.is_none() {
            return Err(PrivilegedInputError::Unauthorized);
        }
        let value = Self {
            generation: snapshot.generation,
            deployment_id: server.deployment_id.clone(),
            issuer: server.approved_issuer,
            host_device_id: installation.device_id.clone(),
            host_key_sha256: installation.public_key_sha256,
        };
        value
            .pins()
            .validate()
            .map_err(|_| PrivilegedInputError::Unauthorized)?;
        Ok(value)
    }
    fn pins(&self) -> TrustPins {
        TrustPins {
            issuer: self.issuer,
            deployment_id: self.deployment_id.clone(),
            host_device_id: self.host_device_id.clone(),
            host_key_sha256: self.host_key_sha256,
        }
    }
}

struct State {
    status: PrivilegedInputStatus,
    context: Option<Context>,
    client: Option<BrokerClient>,
}
struct Control {
    generation: u64,
    action: PrivilegedInputAction,
    reply: oneshot::Sender<PrivilegedInputResult>,
}
pub struct PrivilegedInput {
    state: Arc<Mutex<State>>,
    commands: mpsc::Sender<Control>,
    receiver: Mutex<Option<mpsc::Receiver<Control>>>,
}
impl PrivilegedInput {
    pub fn new() -> Arc<Self> {
        let (commands, receiver) = mpsc::channel(8);
        Arc::new(Self {
            state: Arc::new(Mutex::new(State {
                status: status(PrivilegedInputState::Disabled),
                context: None,
                client: None,
            })),
            commands,
            receiver: Mutex::new(Some(receiver)),
        })
    }
    pub fn spawn_monitor(self: &Arc<Self>, core: CoreHandle) -> PrivilegedInputTask {
        let (stop, receiver) = watch::channel(false);
        let manager = self.clone();
        let commands = self.receiver.lock().ok().and_then(|mut value| value.take());
        PrivilegedInputTask {
            stop,
            failure: None,
            task: Some(tokio::spawn(async move {
                let commands = commands.ok_or_else(|| {
                    io::Error::other("privileged input owner was already started")
                })?;
                manager.run(core, commands, receiver).await
            })),
        }
    }
    /// Called after mutual proof, before attaching InputController. No lease is
    /// retained in the platform adapter or its independent renewal worker.
    pub fn open(
        &self,
        lease: &LeaseControl,
        epoch: InputEpoch,
        layout: InputLayout,
    ) -> io::Result<Option<RenewingBrokerInput>> {
        let client = {
            let state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("privileged input owner poisoned"))?;
            match state.status.state {
                PrivilegedInputState::Disabled => return Ok(None),
                PrivilegedInputState::Ready | PrivilegedInputState::Active => {
                    state.client.clone().ok_or_else(unavailable)?
                }
                _ => return Err(unavailable()),
            }
        };
        let permits = lease.subscribe_input_permits().map_err(io::Error::other)?;
        RenewingBrokerInput::open(client, permits, epoch, layout).map(Some)
    }
    fn observed(&self) -> PrivilegedInputResult {
        self.state
            .lock()
            .map(|state| state.status)
            .map_err(|_| PrivilegedInputError::Unavailable)
    }
    fn set(
        &self,
        value: PrivilegedInputStatus,
        context: Option<Context>,
        client: Option<BrokerClient>,
    ) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("privileged input owner poisoned"))?;
        state.status = value;
        state.context = context;
        state.client = client;
        Ok(())
    }
    async fn disarm(&self) -> io::Result<()> {
        let client = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("privileged input owner poisoned"))?;
            state.context = None;
            // Disable only after the broker's authenticated cleanup result.
            state.status.state = PrivilegedInputState::Starting;
            state.client.take()
        };
        let result = match client {
            Some(client) => tokio::task::spawn_blocking(move || client.stop_user())
                .await
                .map_err(io::Error::other)?,
            None => Ok(()),
        };
        let failed_before = self.observed().map_or(true, |value| value.cleanup_failed);
        let failed = result.is_err() || failed_before;
        self.set(
            PrivilegedInputStatus {
                state: if failed {
                    PrivilegedInputState::Failed
                } else {
                    PrivilegedInputState::Disabled
                },
                cleanup_failed: failed,
            },
            None,
            None,
        )?;
        if failed {
            Err(io::Error::other(
                "privileged input cleanup did not confirm completion",
            ))
        } else {
            Ok(())
        }
    }
    async fn run(
        self: Arc<Self>,
        core: CoreHandle,
        mut commands: mpsc::Receiver<Control>,
        mut stop: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let mut observed = core.observe();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut launch: Option<JoinHandle<io::Result<BrokerClient>>> = None;
        let mut launch_context: Option<Context> = None;
        let mut cancelled = false;
        let mut closing = false;
        let mut cleanup_failed = false;
        loop {
            let snapshot = core.snapshot();
            closing |= *stop.borrow() || snapshot.lifecycle != Lifecycle::Running;
            let current = Context::from_snapshot(&snapshot, false).ok();
            if launch.is_some() && (closing || current != launch_context) {
                cancelled = true;
            }
            let invalid = {
                let state = self.state.lock().map_err(|_| unavailable())?;
                state.client.is_some() && (closing || state.context != current)
            };
            if invalid {
                cleanup_failed |= self.disarm().await.is_err();
            }
            if closing && launch.is_none() {
                cleanup_failed |= self.disarm().await.is_err();
                return if cleanup_failed {
                    Err(io::Error::other("privileged input owner cleanup failed"))
                } else {
                    Ok(())
                };
            }
            tokio::select! {
                biased;
                result = async { match launch.as_mut() { Some(task) => task.await, None => std::future::pending().await } } => {
                    launch.take();
                    let context = launch_context.take();
                    let result = result.map_err(io::Error::other).and_then(|value| value);
                    match result {
                        Ok(client) if !cancelled && !closing && context == Context::from_snapshot(&core.snapshot(), false).ok() => {
                            self.set(status(PrivilegedInputState::Ready), context, Some(client))?;
                        },
                        Ok(client) => {
                            let clean = tokio::task::spawn_blocking(move || client.stop_user()).await.map_err(io::Error::other)?;
                            cleanup_failed |= clean.is_err();
                            self.set(PrivilegedInputStatus { state: if clean.is_ok() { PrivilegedInputState::Disabled } else { PrivilegedInputState::Failed }, cleanup_failed }, None, None)?;
                        },
                        Err(_) => {
                            self.set(status(PrivilegedInputState::Failed), None, None)?;
                        },
                    };
                    cancelled = false;
                },
                control = commands.recv(), if !closing => {
                    let Some(control) = control else { closing = true; continue; };
                    match control.action {
                        PrivilegedInputAction::Status => { let _ = control.reply.send(self.observed()); },
                        PrivilegedInputAction::Start => {
                            let context = Context::from_snapshot(&core.snapshot(), true);
                            let result = if core.snapshot().generation != control.generation { Err(PrivilegedInputError::StaleGeneration) }
                                else if launch.is_some() || self.observed().is_ok_and(|value| !matches!(value.state, PrivilegedInputState::Disabled | PrivilegedInputState::Failed)) { Err(PrivilegedInputError::Busy) }
                                else if cleanup_failed || self.observed().is_ok_and(|value| value.cleanup_failed) { Err(PrivilegedInputError::Cleanup) }
                                else { context };
                            match result {
                                Err(error) => { let _ = control.reply.send(Err(error)); },
                                Ok(context) => {
                                    self.set(status(PrivilegedInputState::Starting), Some(context.clone()), None)?;
                                    let pins = context.pins();
                                    launch_context = Some(context);
                                    launch = Some(tokio::task::spawn_blocking(move || BrokerClient::launch(pins)));
                                    // The human UAC operation stays owned by this
                                    // actor. IPC remains responsive for Stop/Exit.
                                    let _ = control.reply.send(self.observed());
                                },
                            }
                        },
                        PrivilegedInputAction::Stop => {
                            if launch.is_some() {
                                cancelled = true;
                                let _ = control.reply.send(self.observed());
                            } else {
                                cleanup_failed |= self.disarm().await.is_err();
                                let _ = control.reply.send(if cleanup_failed { Err(PrivilegedInputError::Cleanup) } else { self.observed() });
                            }
                        },
                    }
                },
                changed = observed.changed() => { if changed.is_err() { closing = true; } },
                changed = stop.changed() => { if changed.is_err() { closing = true; } },
                _ = tick.tick() => {
                    let client = self.state.lock().map_err(|_| unavailable())?.client.clone();
                    if let Some(client) = client {
                        match client.observed_state() {
                            Ok(BrokerState::Active) => { self.state.lock().map_err(|_| unavailable())?.status.state = PrivilegedInputState::Active; },
                            Ok(BrokerState::Idle) => { self.state.lock().map_err(|_| unavailable())?.status.state = PrivilegedInputState::Ready; },
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                            _ => {
                                cleanup_failed |= self.disarm().await.is_err();
                                let mut state = self.state.lock().map_err(|_| unavailable())?;
                                state.status.state = PrivilegedInputState::Failed;
                            },
                        }
                    }
                },
            }
        }
    }
}
impl LocalPrivilegedInputHandler for PrivilegedInput {
    fn handle(
        &self,
        _core: CoreHandle,
        generation: u64,
        action: PrivilegedInputAction,
    ) -> PrivilegedInputFuture<'_> {
        Box::pin(async move {
            let (reply, receive) = oneshot::channel();
            self.commands
                .try_send(Control {
                    generation,
                    action,
                    reply,
                })
                .map_err(|_| PrivilegedInputError::Busy)?;
            receive
                .await
                .map_err(|_| PrivilegedInputError::Unavailable)?
        })
    }
}
fn status(state: PrivilegedInputState) -> PrivilegedInputStatus {
    PrivilegedInputStatus {
        state,
        cleanup_failed: false,
    }
}
fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "privileged input is unavailable",
    )
}

pub struct RenewingBrokerInput {
    input: BrokerInput,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
    cleanup: Option<Result<(), io::ErrorKind>>,
}
impl RenewingBrokerInput {
    fn open(
        client: BrokerClient,
        mut permits: watch::Receiver<Option<nestlink_identity::VerifiedPermit>>,
        epoch: InputEpoch,
        layout: InputLayout,
    ) -> io::Result<Self> {
        let initial = permits
            .borrow_and_update()
            .clone()
            .ok_or_else(unavailable)?;
        let input = client.authorize(initial.signed_envelope(), epoch, layout)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::Builder::new()
            .name("nestlink-privileged-renew".into())
            .spawn(move || {
                let mut sequence = initial.claims().lease_sequence;
                let result = loop {
                    if stopped.load(Ordering::Acquire) {
                        break Ok(());
                    }
                    match permits.has_changed() {
                        Ok(true) => {
                            let next = permits.borrow_and_update().clone();
                            let Some(permit) = next else {
                                break Ok(());
                            };
                            if permit.claims().lease_sequence > sequence {
                                if let Err(error) = client.renew(permit.signed_envelope()) {
                                    break if matches!(
                                        client.observed_state(),
                                        Ok(BrokerState::Stopped)
                                    ) {
                                        Ok(())
                                    } else {
                                        Err(error)
                                    };
                                }
                                sequence = permit.claims().lease_sequence;
                            }
                        }
                        Ok(false) => {}
                        Err(_) => break Ok(()),
                    }
                    thread::sleep(Duration::from_millis(20));
                };
                // EOF/None is terminal. Never read the lease in this worker: Core
                // may be holding it while synchronously joining platform cleanup.
                let clean = client.revoke();
                clean.and(result)
            })?;
        Ok(Self {
            input,
            stop,
            worker: Some(worker),
            cleanup: None,
        })
    }
}
impl InputDevice for RenewingBrokerInput {
    fn check(&mut self) -> io::Result<()> {
        if self.stop.load(Ordering::Acquire)
            || self
                .worker
                .as_ref()
                .is_none_or(|worker| worker.is_finished())
        {
            return Err(unavailable());
        }
        self.input.check()
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.input.begin_reset()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        if self.cleanup.is_none() {
            let worker = match self.worker.take() {
                Some(worker) => worker
                    .join()
                    .map_err(|_| io::Error::other("privileged renewal worker failed"))
                    .and_then(|result| result),
                None => Ok(()),
            };
            let input = self.input.reset();
            self.cleanup = Some(worker.and(input).map_err(|error| error.kind()));
        }
        self.cleanup
            .unwrap_or(Err(io::ErrorKind::Other))
            .map_err(io::Error::from)
    }
    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        self.input.select_source(source, layout)
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        self.input.inject(input)
    }
}
impl Drop for RenewingBrokerInput {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_app_core::{AppCore, InstallationView, Limits, ServerView, ShutdownState};

    fn signed_in() -> Snapshot {
        Snapshot {
            authentication: Authentication::SignedIn,
            server: Some(ServerView {
                origin: "https://nestlink.test".into(),
                deployment_id: "11111111-1111-4111-8111-111111111111".into(),
                approved_issuer: [1; 32],
                error: None,
                verified_health: Some(nestlink_protocol::api::HealthResponse {
                    product: "NestLink".into(),
                    version: "15.0.0".into(),
                    api_base: "/api/v3".into(),
                    alpn: "nestlink".into(),
                    deployment_id: "11111111-1111-4111-8111-111111111111".into(),
                    security_epoch: 1,
                    permit_issuer: "public".into(),
                    node_policy_issuer: "public".into(),
                    native_ice_version: 0,
                }),
            }),
            installation: Some(InstallationView {
                device_id: "22222222-2222-4222-8222-222222222222".into(),
                public_key_sha256: [2; 32],
            }),
            ..Snapshot::default()
        }
    }

    #[test]
    fn context_requires_verified_server_sign_in_and_exact_installation_pins() {
        let mut snapshot = signed_in();
        assert!(Context::from_snapshot(&snapshot, true).is_ok());
        snapshot.authentication = Authentication::SignedOut;
        assert_eq!(
            Context::from_snapshot(&snapshot, true).err(),
            Some(PrivilegedInputError::Unauthorized)
        );
        snapshot.authentication = Authentication::SignedIn;
        if let Some(server) = &mut snapshot.server {
            server.verified_health = None;
        }
        assert_eq!(
            Context::from_snapshot(&snapshot, true).err(),
            Some(PrivilegedInputError::Unauthorized)
        );
        snapshot = signed_in();
        if let Some(installation) = &mut snapshot.installation {
            installation.public_key_sha256 = [0; 32];
        }
        assert!(Context::from_snapshot(&snapshot, true).is_err());
    }

    #[tokio::test]
    async fn status_and_rejected_start_do_not_launch_uac_and_owner_joins()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut core = AppCore::start(Limits::default())?;
        let manager = PrivilegedInput::new();
        let mut owner = manager.spawn_monitor(core.handle());
        let generation = core.handle().snapshot().generation;
        assert_eq!(
            manager
                .handle(core.handle(), generation, PrivilegedInputAction::Status)
                .await,
            Ok(status(PrivilegedInputState::Disabled))
        );
        assert_eq!(
            manager
                .handle(core.handle(), generation, PrivilegedInputAction::Start)
                .await
                .err(),
            Some(PrivilegedInputError::Unauthorized)
        );
        assert_eq!(
            manager
                .handle(core.handle(), generation + 1, PrivilegedInputAction::Start)
                .await
                .err(),
            Some(PrivilegedInputError::StaleGeneration)
        );
        owner.request_stop();
        tokio::time::timeout(Duration::from_secs(1), owner.join()).await??;
        assert_eq!(
            core.shutdown(Duration::from_secs(2)).await,
            ShutdownState::Complete
        );
        Ok(())
    }
}
