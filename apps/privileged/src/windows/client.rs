#![allow(unsafe_code)]
use super::{
    installation::{self, Installation},
    security::{self, Handle, Peer},
    server,
};
use crate::{
    TrustPins,
    wire::{
        self, BrokerAction, BrokerError, BrokerState, Command, Grant, Reply, ReplyValue, Request,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_platform_input::{InputCapabilities, NativeInput};
use nestlink_remote::input::{InputAction, InputDevice, InputEpoch, InputLayout, PlatformInput};
use rand_core::{OsRng, RngCore};
use std::{
    io,
    mem::size_of,
    os::windows::io::AsRawHandle,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use windows_sys::Win32::{
    System::Threading::GetProcessId,
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

struct Job {
    command: Command,
    deadline: Instant,
    reply: SyncSender<wire::Result<ReplyValue>>,
}
struct State {
    grant: Option<Grant>,
    sequence: u64,
    cleaned: bool,
}
struct Shared {
    aborted: AtomicBool,
    clean_stopped: AtomicBool,
    observed: AtomicU8,
    failure: Mutex<Option<BrokerError>>,
}
impl Shared {
    fn abort(&self, error: BrokerError) -> BrokerError {
        if let Ok(mut failure) = self.failure.lock() {
            // Cleanup is sticky even when a later disconnect/timeout races it.
            if failure.is_none() || error == BrokerError::Cleanup {
                *failure = Some(error);
            }
        }
        self.aborted.store(true, Ordering::Release);
        error
    }
    fn failure(&self) -> Option<BrokerError> {
        self.failure.lock().ok().and_then(|value| *value)
    }
    fn observe(&self, reply: &ReplyValue) {
        let state = match reply {
            ReplyValue::State { value } => Some(value.state),
            ReplyValue::Granted { .. } | ReplyValue::Renewed { .. } | ReplyValue::Applied {} => {
                Some(BrokerState::Active)
            }
            ReplyValue::Revoked {} => Some(BrokerState::Idle),
            ReplyValue::Stopped {} => Some(BrokerState::Stopped),
            _ => None,
        };
        if let Some(state) = state {
            self.observed.store(
                match state {
                    BrokerState::Idle => 0,
                    BrokerState::Active => 1,
                    BrokerState::Stopped => 2,
                },
                Ordering::Release,
            );
        }
    }
}
struct Inner {
    jobs: SyncSender<Job>,
    shared: Arc<Shared>,
    state: Mutex<State>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
#[derive(Clone)]
pub struct BrokerClient {
    inner: Arc<Inner>,
}

impl BrokerClient {
    /// Explicit user action only: launches the protected sibling broker via UAC.
    /// It never elevates or respawns the daemon. All pipe I/O owns a separate
    /// runtime/thread, so synchronous InputDevice calls cannot reenter Core.
    pub fn launch(pins: TrustPins) -> io::Result<Self> {
        pins.validate()?;
        let (jobs, receiver) = mpsc::sync_channel(8);
        let (started, wait_started) = mpsc::sync_channel(1);
        let shared = Arc::new(Shared {
            aborted: AtomicBool::new(false),
            clean_stopped: AtomicBool::new(false),
            observed: AtomicU8::new(0),
            failure: Mutex::new(None),
        });
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("nestlink-privileged-ipc".into())
            .spawn(move || {
                let result = worker(pins, receiver, started, &worker_shared);
                if let Err(error) = result {
                    worker_shared.abort(error);
                }
                worker_shared.aborted.store(true, Ordering::Release);
            })?;
        // ShellExecute's UAC prompt is a human operation. The subsequent owned
        // process/pipe startup is separately bounded to ten seconds by launch().
        let started = wait_started
            .recv()
            .map_err(|_| io::Error::from(BrokerError::Stopped))
            .and_then(|result| result);
        if let Err(error) = started {
            shared.aborted.store(true, Ordering::Release);
            let _ = worker.join();
            return Err(error);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                jobs,
                shared,
                state: Mutex::new(State {
                    grant: None,
                    sequence: 0,
                    cleaned: true,
                }),
                worker: Mutex::new(Some(worker)),
            }),
        })
    }
    fn call(&self, command: Command, budget: Duration) -> wire::Result<ReplyValue> {
        if self.inner.shared.aborted.load(Ordering::Acquire) {
            return Err(self.inner.shared.failure().unwrap_or(BrokerError::Stopped));
        }
        let (reply, receive) = mpsc::sync_channel(1);
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or(BrokerError::Timeout)?;
        self.inner
            .jobs
            .try_send(Job {
                command,
                deadline,
                reply,
            })
            .map_err(|_| BrokerError::Busy)?;
        match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(ReplyValue::Denied {
                code: BrokerError::Cleanup,
            })) => Err(self.inner.shared.abort(BrokerError::Cleanup)),
            Ok(result) => result,
            Err(_) => {
                // Cancel the whole owned channel. No timed-out input may remain
                // queued for later execution; EOF makes the server release it.
                Err(self.inner.shared.abort(BrokerError::Timeout))
            }
        }
    }
    pub fn authorize(
        &self,
        signed_permit: &[u8],
        epoch: InputEpoch,
        layout: InputLayout,
    ) -> io::Result<BrokerInput> {
        if signed_permit.is_empty()
            || signed_permit.len() > nestlink_protocol::PERMIT_BYTES as usize
        {
            return Err(BrokerError::Protocol.into());
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::from(BrokerError::Stopped))?;
        if state.grant.is_some() {
            return Err(BrokerError::Busy.into());
        }
        let result = self.call(
            Command::Authorize {
                signed_permit: URL_SAFE_NO_PAD.encode(signed_permit),
                connection_generation: epoch.connection,
                input_epoch: epoch.input,
                layout_epoch: epoch.layout,
                layout: layout.into(),
            },
            wire::CONSENT_BUDGET + Duration::from_secs(5),
        )?;
        let grant = match result {
            ReplyValue::Granted { grant } => grant,
            ReplyValue::Denied { code } => return Err(code.into()),
            _ => return Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        };
        if grant.binding.connection_generation != epoch.connection
            || grant.binding.input_epoch != epoch.input
            || grant.binding.layout_epoch != epoch.layout
            || grant.layout != layout.into()
        {
            return Err(self.inner.shared.abort(BrokerError::Epoch).into());
        }
        state.grant = Some(grant);
        state.sequence = 0;
        state.cleaned = false;
        Ok(BrokerInput {
            client: self.clone(),
            layout,
            terminal: false,
            cleanup: None,
        })
    }
    pub fn renew(&self, signed_permit: &[u8]) -> io::Result<()> {
        if signed_permit.is_empty()
            || signed_permit.len() > nestlink_protocol::PERMIT_BYTES as usize
        {
            return Err(BrokerError::Protocol.into());
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::from(BrokerError::Stopped))?;
        let nonce = state
            .grant
            .as_ref()
            .ok_or(BrokerError::Authorization)?
            .nonce;
        match self.call(
            Command::Renew {
                nonce,
                signed_permit: URL_SAFE_NO_PAD.encode(signed_permit),
            },
            wire::IO_BUDGET,
        )? {
            ReplyValue::Renewed { binding } => {
                let grant = state.grant.as_mut().ok_or(BrokerError::Authorization)?;
                let mut expected = grant.binding.clone();
                expected.lease_sequence = binding.lease_sequence;
                if binding != expected || binding.lease_sequence <= grant.binding.lease_sequence {
                    state.grant = None;
                    return Err(self.inner.shared.abort(BrokerError::Epoch).into());
                }
                grant.binding = binding;
                Ok(())
            }
            ReplyValue::Denied { code } => {
                // Retain the nonce until Revoke/StopUser acknowledges cleanup.
                Err(code.into())
            }
            _ => Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        }
    }
    pub fn status(&self) -> io::Result<wire::Status> {
        match self.call(Command::Status {}, wire::IO_BUDGET)? {
            ReplyValue::State { value } => {
                if value.cleanup_failed {
                    Err(self.inner.shared.abort(BrokerError::Cleanup).into())
                } else {
                    Ok(value)
                }
            }
            ReplyValue::Denied { code } => Err(code.into()),
            _ => Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        }
    }
    /// Nonblocking local observation. It cannot prolong or grant a lease and
    /// never queues a Status behind an outstanding local consent dialog.
    pub fn observed_state(&self) -> io::Result<BrokerState> {
        if let Some(error) = self.inner.shared.failure() {
            return Err(error.into());
        }
        if self.inner.shared.clean_stopped.load(Ordering::Acquire) {
            return Ok(BrokerState::Stopped);
        }
        if self.inner.shared.aborted.load(Ordering::Acquire) {
            return Err(BrokerError::Stopped.into());
        }
        match self.inner.shared.observed.load(Ordering::Acquire) {
            0 => Ok(BrokerState::Idle),
            1 => Ok(BrokerState::Active),
            2 => Ok(BrokerState::Stopped),
            _ => Err(BrokerError::Protocol.into()),
        }
    }
    pub fn stop_user(&self) -> io::Result<()> {
        let response = if self.inner.shared.clean_stopped.load(Ordering::Acquire) {
            self.inner
                .shared
                .failure()
                .map_or(Ok(ReplyValue::Stopped {}), Err)
        } else {
            self.call(Command::StopUser {}, wire::IO_BUDGET)
        };
        if let Ok(mut state) = self.inner.state.try_lock() {
            state.grant = None;
            state.cleaned = matches!(&response, Ok(ReplyValue::Stopped {}));
        }
        let result = match response {
            Ok(ReplyValue::Stopped {}) => Ok(()),
            Ok(ReplyValue::Denied { code }) => Err(code.into()),
            Err(code) => Err(code.into()),
            _ => Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        };
        if result.is_err() {
            self.inner.shared.aborted.store(true, Ordering::Release);
        }
        if let Ok(mut worker) = self.inner.worker.lock()
            && let Some(worker) = worker.take()
            && worker.join().is_err()
        {
            return Err(self.inner.shared.abort(BrokerError::Cleanup).into());
        }
        result
    }
    pub fn revoke(&self) -> io::Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::from(BrokerError::Stopped))?;
        if self.inner.shared.clean_stopped.load(Ordering::Acquire) {
            state.grant = None;
            state.cleaned = true;
            return self
                .inner
                .shared
                .failure()
                .map_or(Ok(()), |error| Err(error.into()));
        }
        let Some(grant) = state.grant.take() else {
            return match self.inner.shared.failure() {
                Some(error) => Err(error.into()),
                None if self.inner.shared.aborted.load(Ordering::Acquire) => {
                    Err(BrokerError::Stopped.into())
                }
                None if state.cleaned => Ok(()),
                None => Err(self.inner.shared.abort(BrokerError::Cleanup).into()),
            };
        };
        match self.call(Command::Revoke { nonce: grant.nonce }, wire::IO_BUDGET)? {
            ReplyValue::Revoked {} => {
                state.cleaned = true;
                Ok(())
            }
            ReplyValue::Denied {
                code: BrokerError::Authorization,
            } => {
                // An already-expired platform grant may have been cleaned by the
                // server watchdog. Confirm its actual idle state before success.
                let status = self.status()?;
                if status.state == BrokerState::Active {
                    Err(self.inner.shared.abort(BrokerError::Cleanup).into())
                } else {
                    state.cleaned = true;
                    Ok(())
                }
            }
            ReplyValue::Denied { .. } => Err(self.inner.shared.abort(BrokerError::Cleanup).into()),
            _ => Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        }
    }
    fn input(&self, action: Option<BrokerAction>) -> io::Result<()> {
        if action.is_none() && self.inner.shared.clean_stopped.load(Ordering::Acquire) {
            return self
                .inner
                .shared
                .failure()
                .map_or(Ok(()), |error| Err(error.into()));
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::from(BrokerError::Stopped))?;
        state.sequence = state
            .sequence
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(BrokerError::Replay)?;
        let release = action.is_none();
        if release && state.grant.is_none() && state.cleaned {
            if let Some(error) = self.inner.shared.failure() {
                return Err(error.into());
            }
            return if self.inner.shared.aborted.load(Ordering::Acquire) {
                Err(BrokerError::Stopped.into())
            } else {
                Ok(())
            };
        }
        let grant = state.grant.as_ref().ok_or(BrokerError::Authorization)?;
        let command = match action {
            Some(action) => Command::Input {
                nonce: grant.nonce,
                binding: grant.binding.clone(),
                sequence: state.sequence,
                action,
            },
            None => Command::ReleaseAll {
                nonce: grant.nonce,
                binding: grant.binding.clone(),
                sequence: state.sequence,
            },
        };
        match self.call(command, wire::IO_BUDGET)? {
            ReplyValue::Applied {} if !release => Ok(()),
            ReplyValue::Released {} if release => Ok(()),
            ReplyValue::Denied { code } => Err(code.into()),
            _ => Err(self.inner.shared.abort(BrokerError::Protocol).into()),
        }
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        if !self.shared.aborted.load(Ordering::Acquire) {
            let (reply, receive) = mpsc::sync_channel(1);
            let deadline = Instant::now() + wire::IO_BUDGET;
            if self
                .jobs
                .try_send(Job {
                    command: Command::StopUser {},
                    deadline,
                    reply,
                })
                .is_ok()
            {
                let _ = receive.recv_timeout(wire::IO_BUDGET);
            }
        }
        self.shared.aborted.store(true, Ordering::Release);
        if let Ok(worker) = self.worker.get_mut()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

pub struct BrokerInput {
    client: BrokerClient,
    layout: InputLayout,
    terminal: bool,
    cleanup: Option<std::result::Result<(), BrokerError>>,
}
impl NativeInput for BrokerInput {
    fn layout(&self) -> InputLayout {
        self.layout
    }
    fn capabilities(&self) -> InputCapabilities {
        InputCapabilities {
            physical_keys: true,
            pointer_buttons: true,
            text_commit: true,
        }
    }
}
impl InputDevice for BrokerInput {
    fn check(&mut self) -> io::Result<()> {
        if self.terminal {
            return Err(BrokerError::Stopped.into());
        }
        if self.client.status()?.state != BrokerState::Active {
            self.terminal = true;
            return Err(BrokerError::Authorization.into());
        }
        Ok(())
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.terminal = true;
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.terminal = true;
        if self.cleanup.is_none() {
            self.cleanup = Some(self.client.revoke().map_err(|_| BrokerError::Cleanup));
        }
        self.cleanup
            .unwrap_or(Err(BrokerError::Cleanup))
            .map_err(io::Error::from)
    }
    fn select_source(&mut self, _: u32, layout: InputLayout) -> io::Result<()> {
        if layout != self.layout {
            return Err(BrokerError::Layout.into());
        }
        self.check()
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        if let PlatformInput::Release(_) = input {
            // InputController uses this path for its owned-button cleanup. The
            // broker releases the complete owned set without moving the pointer.
            return self.client.input(None);
        }
        if self.terminal {
            return Err(BrokerError::Stopped.into());
        }
        let action = match input {
            PlatformInput::Action(InputAction::Key { code, down }) => BrokerAction::Key {
                code: *code,
                down: *down,
            },
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                BrokerAction::Pointer {
                    button: *button,
                    down: *down,
                    x: *x,
                    y: *y,
                }
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                BrokerAction::Text { text: text.clone() }
            }
            PlatformInput::Release(_) => return Err(BrokerError::Protocol.into()),
        };
        self.client.input(Some(action))
    }
}
impl Drop for BrokerInput {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

fn worker(
    pins: TrustPins,
    jobs: Receiver<Job>,
    started: SyncSender<io::Result<()>>,
    shared: &Shared,
) -> wire::Result<()> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(error) => {
            let _ = started.send(Err(error));
            return Err(BrokerError::Io);
        }
    };
    let connection = runtime.block_on(launch(&pins));
    let (mut pipe, peer, installation) = match connection {
        Ok(value) => value,
        Err(error) => {
            let _ = started.send(Err(error));
            return Err(BrokerError::Authorization);
        }
    };
    if started.send(Ok(())).is_err() {
        return Err(BrokerError::Stopped);
    }
    let mut id = 0u64;
    let outcome = loop {
        if shared.aborted.load(Ordering::Acquire) {
            break Err(BrokerError::Stopped);
        }
        let job = match jobs.recv_timeout(Duration::from_millis(500)) {
            Ok(job) => Some(job),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break Ok(()),
        };
        id = match id.checked_add(1).filter(|value| *value <= i64::MAX as u64) {
            Some(value) => value,
            None => break Err(BrokerError::Replay),
        };
        if let Some(job) = job {
            let stop = matches!(job.command, Command::StopUser {});
            let response = runtime.block_on(exchange(
                &mut pipe,
                &peer,
                id,
                job.command,
                job.deadline,
                shared,
            ));
            let failure = response.as_ref().err().copied();
            if stop && matches!(&response, Ok(ReplyValue::Stopped {})) {
                // Publish only the authenticated cleanup acknowledgement, before
                // waking callers. A later InputDevice reset may then be idempotent.
                shared.clean_stopped.store(true, Ordering::Release);
            }
            let _ = job.reply.send(response);
            if let Some(error) = failure {
                break Err(error);
            }
            if stop {
                break Ok(());
            }
        } else {
            let result = runtime.block_on(exchange(
                &mut pipe,
                &peer,
                id,
                Command::Status {},
                Instant::now() + wire::IO_BUDGET,
                shared,
            ));
            match result {
                Ok(ReplyValue::State { value }) if !value.cleanup_failed => {}
                Ok(ReplyValue::State { .. }) => break Err(BrokerError::Cleanup),
                Ok(_) => break Err(BrokerError::Protocol),
                Err(error) => break Err(error),
            }
        }
    };
    drop(pipe);
    drop(peer);
    drop(installation);
    for pending in jobs.try_iter() {
        let _ = pending.reply.send(Err(BrokerError::Stopped));
    }
    outcome
}

async fn exchange(
    pipe: &mut NamedPipeClient,
    peer: &Peer,
    id: u64,
    command: Command,
    deadline: Instant,
    shared: &Shared,
) -> wire::Result<ReplyValue> {
    peer.alive().map_err(|_| BrokerError::Stopped)?;
    if Instant::now() >= deadline {
        return Err(BrokerError::Timeout);
    }
    let request = Request {
        version: wire::VERSION,
        id,
        command,
    };
    let operation = async {
        wire::write(pipe, &request).await?;
        let reply: Reply = wire::read(pipe).await?;
        if reply.version != wire::VERSION || reply.id != id {
            return Err(BrokerError::Protocol);
        }
        Ok(reply.result)
    };
    let cancellation = async {
        loop {
            if shared.aborted.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let result = tokio::select! {
        biased;
        _ = cancellation => Err(BrokerError::Stopped),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation) => result.map_err(|_| BrokerError::Timeout)?,
    };
    if let Ok(reply) = &result {
        shared.observe(reply);
    }
    result
}

async fn launch(pins: &TrustPins) -> io::Result<(NamedPipeClient, Peer, Installation)> {
    let installation = Installation::current("nestlink-daemon.exe")?;
    let current = Peer::open(std::process::id())?;
    if !current.is_normal() || !security::same_image(&current.image, &installation.daemon()) {
        return Err(security::denied());
    }
    let mut nonce = [0; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| security::denied())?;
    let nonce = installation::hex(&nonce);
    let pipe_name = server::pipe_name(current.pid, &nonce)?;
    let verb = security::text("runas")?;
    let file = security::wide(installation.broker().as_os_str())?;
    let directory = security::wide(installation.directory.as_os_str())?;
    let arguments = security::text(&format!(
        "--daemon-pid {} --startup-nonce {} --deployment {} --issuer {} --host {} --host-key {}",
        current.pid,
        nonce,
        pins.deployment_id,
        installation::hex(&pins.issuer),
        pins.host_device_id,
        installation::hex(&pins.host_key_sha256)
    ))?;
    let mut execution = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: arguments.as_ptr(),
        lpDirectory: directory.as_ptr(),
        nShow: SW_HIDE,
        ..SHELLEXECUTEINFOW::default()
    };
    // SAFETY: fixed runas verb, exact protected executable, and bounded public
    // UUID/hex-only arguments. There is no shell/command string from a request.
    if unsafe { ShellExecuteExW(&mut execution) } == 0 || execution.hProcess.is_null() {
        return Err(security::denied());
    }
    let handle = Handle(execution.hProcess);
    // SAFETY: ShellExecuteEx transferred this concrete owned child process handle.
    let pid = unsafe { GetProcessId(handle.0) };
    let peer = Peer::from_handle(handle, pid)?;
    if !peer.is_broker()
        || !peer.same_login(&current)
        || !security::same_image(&peer.image, &installation.broker())
    {
        return Err(security::denied());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        peer.alive()?;
        match ClientOptions::new().open(&pipe_name) {
            Ok(pipe) => {
                let actual = security::pipe_peer(pipe.as_raw_handle().cast(), false)?;
                if actual.pid != peer.pid
                    || actual.creation != peer.creation
                    || !actual.is_broker()
                    || !actual.same_login(&current)
                    || !security::same_image(&actual.image, &installation.broker())
                {
                    return Err(security::denied());
                }
                return Ok((pipe, peer, installation));
            }
            Err(error)
                if matches!(error.raw_os_error(), Some(2 | 231)) && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(_) => return Err(security::denied()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopped_client(clean: bool, failure: Option<BrokerError>) -> BrokerClient {
        let (jobs, _receiver) = mpsc::sync_channel(1);
        BrokerClient {
            inner: Arc::new(Inner {
                jobs,
                shared: Arc::new(Shared {
                    aborted: AtomicBool::new(true),
                    clean_stopped: AtomicBool::new(clean),
                    observed: AtomicU8::new(if clean { 2 } else { 0 }),
                    failure: Mutex::new(failure),
                }),
                state: Mutex::new(State {
                    grant: None,
                    sequence: 0,
                    cleaned: clean,
                }),
                worker: Mutex::new(None),
            }),
        }
    }

    #[test]
    fn acknowledged_user_stop_allows_idempotent_owned_input_cleanup() -> io::Result<()> {
        let client = stopped_client(true, None);
        client.stop_user()?;
        client.revoke()?;
        client.input(None)?;
        assert_eq!(client.observed_state()?, BrokerState::Stopped);
        assert!(
            client
                .input(Some(BrokerAction::Text {
                    text: "after stop".into()
                }))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn eof_or_timeout_cannot_be_reported_as_acknowledged_cleanup() {
        for failure in [None, Some(BrokerError::Timeout), Some(BrokerError::Io)] {
            let client = stopped_client(false, failure);
            assert!(client.revoke().is_err());
            assert!(client.input(None).is_err());
            assert!(client.stop_user().is_err());
        }
    }

    #[test]
    fn acknowledged_revoke_can_race_core_release_all_without_false_cleanup_failure()
    -> io::Result<()> {
        let client = stopped_client(false, None);
        client.inner.shared.aborted.store(false, Ordering::Release);
        client
            .inner
            .state
            .lock()
            .map_err(|_| BrokerError::Stopped)?
            .cleaned = true;
        client.revoke()?;
        client.input(None)?;
        assert!(
            client
                .input(Some(BrokerAction::Text {
                    text: "after revoke".into()
                }))
                .is_err()
        );
        client.inner.shared.aborted.store(true, Ordering::Release);
        Ok(())
    }

    #[test]
    fn cleanup_failure_remains_sticky_after_disconnect_and_clean_stop_marker() {
        let client = stopped_client(true, Some(BrokerError::Cleanup));
        client.inner.shared.abort(BrokerError::Io);
        assert_eq!(client.inner.shared.failure(), Some(BrokerError::Cleanup));
        assert!(client.stop_user().is_err());
        assert!(client.revoke().is_err());
        assert!(client.input(None).is_err());
    }
}
