//! A bounded client bridge. The window owns no SDK, network recovery or permissions.
use eframe::egui;
use nestlink_app_core::{
    LocalServiceHostPreview, NativeDisplayRequest, NativeDisplayState, NativeInputAction,
    NativeInputBinding, NativeInputLayout, NativeSessionBinding, OperationId, Snapshot,
};
use nestlink_app_ipc::{
    Client, NativeInputClient, NativeVideoBinding, NativeVideoMessage, VideoClient,
    wire::{Command, ExitResult, Reply, Response, SensitiveReply},
};
use std::{
    collections::VecDeque,
    io,
    path::{Path, PathBuf},
    process::{Child, Command as Process},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::Duration,
};

const DAEMON_STARTUP_BUDGET: Duration = Duration::from_secs(10);
const VIDEO_STATE_POLL: Duration = Duration::from_millis(50);
const VIDEO_RETRY_DELAY: Duration = Duration::from_secs(1);
const INPUT_STATE_POLL: Duration = Duration::from_millis(100);
const INPUT_RETRY_DELAY: Duration = Duration::from_millis(250);
const INPUT_QUEUE_CAPACITY: usize = 128;

pub enum Notice {
    Connected,
    PrivilegedInput {
        submission_id: Option<u64>,
        runtime_id: String,
        generation: u64,
        result: nestlink_app_ipc::privileged_input::PrivilegedInputResult,
    },
    NativeNetworkConfigured {
        submission_id: Option<u64>,
        runtime_id: String,
        result:
            Result<nestlink_app_core::NativeNetworkSettings, nestlink_app_core::NativeNetworkError>,
    },
    Accepted {
        submission_id: u64,
        operation_id: OperationId,
    },
    Completed {
        submission_id: Option<u64>,
        result: nestlink_app_core::OperationResult,
        sensitive: Option<SensitiveReply>,
    },
    Rejected {
        submission_id: Option<u64>,
        reason: nestlink_app_ipc::wire::Rejection,
    },
    Exited(ExitResult),
    NativeDownloadRecovery {
        submission_id: Option<u64>,
        runtime_id: String,
        generation: u64,
        result: nestlink_protocol::file_recovery::DownloadRecoveryReply,
    },
    NativeFiles {
        submission_id: Option<u64>,
        runtime_id: String,
        binding: nestlink_app_core::NativeSessionBinding,
        generation: u64,
        result: nestlink_app_ipc::files::NativeFileReply,
    },
    BrowserHostData {
        submission_id: Option<u64>,
        binding: nestlink_app_core::BrowserHostBinding,
        generation: u64,
        result: nestlink_app_ipc::browser_data::BrowserHostDataReply,
    },
    LocalServiceHostPreview {
        submission_id: u64,
        preview: LocalServiceHostPreview,
    },
    LocalServiceHostStopped {
        submission_id: u64,
        accepted: bool,
    },
    NativeClipboard {
        submission_id: Option<u64>,
        generation: u64,
        result: Reply,
    },
    Disconnected,
}
pub enum VideoUpdate {
    Connecting(NativeVideoBinding),
    Message(NativeVideoMessage),
    Disconnected(Option<NativeVideoBinding>),
}
#[derive(Clone)]
pub struct InputLayoutUpdate {
    pub runtime_id: String,
    pub ui_generation: u64,
    pub layout: NativeInputLayout,
}
struct QueuedInput {
    generation: u64,
    binding: NativeInputBinding,
    action: NativeInputAction,
}
#[derive(Clone)]
struct InputRelease {
    generation: u64,
    binding: NativeInputBinding,
}
#[derive(Default)]
struct DisplayMailbox {
    state: Option<NativeDisplayState>,
    local_pending: Option<NativeDisplayRequest>,
}
type SharedDisplays = Arc<Mutex<DisplayMailbox>>;
struct NativeMediaContext {
    runtime_id: Arc<Mutex<Option<String>>>,
    displays: SharedDisplays,
}
struct InputWorkerContext {
    directory: PathBuf,
    snapshot: Arc<Mutex<Arc<Snapshot>>>,
    layout_state: Arc<Mutex<Option<InputLayoutUpdate>>>,
    displays: SharedDisplays,
    context: egui::Context,
    runtime_id: Arc<Mutex<Option<String>>>,
}
struct QueuedCommand {
    submission_id: u64,
    generation: u64,
    command: Command,
}
pub struct Bridge {
    #[cfg(test)]
    layout_commands: Option<Receiver<QueuedCommand>>,
    #[cfg(test)]
    layout_notices: Option<SyncSender<Notice>>,
    commands: SyncSender<QueuedCommand>,
    next_submission_id: AtomicU64,
    notices: Receiver<Notice>,
    snapshot: Arc<Mutex<Arc<Snapshot>>>,
    displays: SharedDisplays,
    video_update: Arc<Mutex<Option<VideoUpdate>>>,
    video_interest: tokio::sync::watch::Sender<bool>,
    video_stop: tokio::sync::watch::Sender<bool>,
    runtime_id: Arc<Mutex<Option<String>>>,
    video_thread: Option<std::thread::JoinHandle<()>>,
    input_commands: tokio::sync::mpsc::Sender<QueuedInput>,
    input_interest: tokio::sync::watch::Sender<bool>,
    input_stop: tokio::sync::watch::Sender<bool>,
    input_release: tokio::sync::watch::Sender<Option<InputRelease>>,
    input_layout: Arc<Mutex<Option<InputLayoutUpdate>>>,
    input_thread: Option<std::thread::JoinHandle<()>>,
}
impl Bridge {
    /// Layout tests render the real workspace without starting a daemon or media workers.
    #[cfg(test)]
    pub(crate) fn for_layout(snapshot: Snapshot) -> Self {
        let (commands, _) = mpsc::sync_channel(16);
        let (layout_notices, notices) = mpsc::sync_channel(32);
        Self {
            layout_commands: None,
            layout_notices: Some(layout_notices),
            commands,
            next_submission_id: AtomicU64::new(1),
            notices,
            snapshot: Arc::new(Mutex::new(Arc::new(snapshot))),
            displays: Arc::new(Mutex::new(DisplayMailbox::default())),
            video_update: Arc::new(Mutex::new(None)),
            video_interest: tokio::sync::watch::channel(false).0,
            video_stop: tokio::sync::watch::channel(false).0,
            runtime_id: Arc::new(Mutex::new(None)),
            video_thread: None,
            input_commands: tokio::sync::mpsc::channel(INPUT_QUEUE_CAPACITY).0,
            input_interest: tokio::sync::watch::channel(false).0,
            input_stop: tokio::sync::watch::channel(false).0,
            input_release: tokio::sync::watch::channel(None).0,
            input_layout: Arc::new(Mutex::new(None)),
            input_thread: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn layout_snapshot(&mut self, snapshot: Snapshot) {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(snapshot);
    }
    #[cfg(test)]
    pub(crate) fn layout_enable_commands(&mut self) {
        let (commands, receiver) = mpsc::sync_channel(16);
        self.commands = commands;
        self.layout_commands = Some(receiver);
    }
    #[cfg(test)]
    pub(crate) fn layout_submission(&self) -> Option<(u64, Command)> {
        self.layout_commands
            .as_ref()?
            .try_recv()
            .ok()
            .map(|queued| (queued.submission_id, queued.command))
    }
    #[cfg(test)]
    pub(crate) fn layout_notice(&self, notice: Notice) {
        let Some(sender) = self.layout_notices.as_ref() else {
            panic!("layout notice channel is unavailable");
        };
        sender
            .try_send(notice)
            .unwrap_or_else(|_| panic!("layout notice queue full"));
    }

    pub fn start(directory: PathBuf, context: egui::Context) -> Self {
        let (commands, incoming) = mpsc::sync_channel(16);
        let (outgoing, notices) = mpsc::sync_channel(32);
        let snapshot = Arc::new(Mutex::new(Arc::new(Snapshot::default())));
        let video_update = Arc::new(Mutex::new(None));
        let (video_interest, video_interest_rx) = tokio::sync::watch::channel(false);
        let (video_stop, video_stop_rx) = tokio::sync::watch::channel(false);
        let (input_commands, input_command_rx) = tokio::sync::mpsc::channel(INPUT_QUEUE_CAPACITY);
        let (input_interest, input_interest_rx) = tokio::sync::watch::channel(false);
        let (input_stop, input_stop_rx) = tokio::sync::watch::channel(false);
        let (input_release, input_release_rx) = tokio::sync::watch::channel(None);
        let runtime_id = Arc::new(Mutex::new(None));
        let displays = Arc::new(Mutex::new(DisplayMailbox::default()));
        let main_displays = displays.clone();
        let video_displays = displays.clone();
        let input_displays = displays.clone();
        let main_runtime_id = runtime_id.clone();
        let video_runtime_id = runtime_id.clone();
        let shared = snapshot.clone();
        let video_snapshot = snapshot.clone();
        let video_events = video_update.clone();
        let video_directory = directory.clone();
        let video_context = context.clone();
        let input_runtime_id = runtime_id.clone();
        let input_snapshot = snapshot.clone();
        let input_directory = directory.clone();
        let input_context = context.clone();
        let input_layout = Arc::new(Mutex::new(None));
        let input_layout_worker = input_layout.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let finished = match runtime {
                Ok(runtime) => runtime.block_on(run(
                    directory,
                    context.clone(),
                    incoming,
                    outgoing.clone(),
                    shared.clone(),
                    NativeMediaContext {
                        runtime_id: main_runtime_id.clone(),
                        displays: main_displays.clone(),
                    },
                )),
                Err(_) => Err(io::Error::other("UI IPC runtime could not start")),
            };
            if let Ok(mut current) = main_runtime_id.lock() {
                *current = None;
            }
            if finished.is_err() {
                if let Ok(mut view) = shared.lock() {
                    *view = Arc::new(Snapshot::default());
                }
                let _ = outgoing.try_send(Notice::Disconnected);
                context.request_repaint();
            }
        });
        let video_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(runtime) = runtime {
                runtime.block_on(run_video(
                    video_directory,
                    video_snapshot,
                    video_events,
                    video_interest_rx,
                    video_stop_rx,
                    video_context,
                    NativeMediaContext {
                        runtime_id: video_runtime_id,
                        displays: video_displays,
                    },
                ));
            }
        });
        let input_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(runtime) = runtime {
                runtime.block_on(run_input(
                    InputWorkerContext {
                        directory: input_directory,
                        snapshot: input_snapshot,
                        layout_state: input_layout_worker,
                        displays: input_displays,
                        context: input_context,
                        runtime_id: input_runtime_id,
                    },
                    input_command_rx,
                    input_interest_rx,
                    input_stop_rx,
                    input_release_rx,
                ));
            }
        });
        Self {
            #[cfg(test)]
            layout_commands: None,
            #[cfg(test)]
            layout_notices: None,
            commands,
            next_submission_id: AtomicU64::new(1),
            notices,
            snapshot,
            video_update,
            displays,
            video_interest,
            video_stop,
            runtime_id,
            video_thread: Some(video_thread),
            input_commands,
            input_interest,
            input_stop,
            input_release,
            input_layout,
            input_thread: Some(input_thread),
        }
    }
    pub fn native_displays(&self) -> Option<NativeDisplayState> {
        let mailbox = self.displays.lock().ok()?;
        let mut state = mailbox.state.clone()?;
        if mailbox.local_pending.is_some() {
            state.pending = mailbox.local_pending.clone();
        }
        let snapshot = self.snapshot();
        let session = snapshot.native_session.data.as_ref()?;
        if session.status != nestlink_app_core::NativeSessionStatus::Connected
            || !state.catalog.as_ref().is_some_and(|catalog| {
                catalog.request_id == session.request_id
                    && catalog.connection_generation == session.connection_generation
            })
        {
            return None;
        }
        Some(state)
    }
    pub fn select_native_display(&self, generation: u64, source: u32) -> bool {
        let Some(state) = self.native_displays() else {
            return false;
        };
        if state.is_host || state.pending.is_some() || !state.approved_sources.contains(&source) {
            return false;
        }
        let Some(selected) = state.selected else {
            return false;
        };
        if source == selected.source {
            return true;
        }
        let Some(sequence) = selected
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
        else {
            return false;
        };
        let request = NativeDisplayRequest {
            catalog: selected.catalog,
            sequence,
            source,
        };
        let binding = NativeSessionBinding {
            request_id: request.catalog.request_id.clone(),
            connection_generation: request.catalog.connection_generation,
        };
        if let Some(layout) = self.input_layout() {
            self.release_native_input(generation, layout.layout.binding);
        }
        if !self.submit(
            generation,
            Command::SelectNativeDisplay {
                binding,
                request: request.clone(),
            },
        ) {
            return false;
        }
        if let Ok(mut mailbox) = self.displays.lock() {
            mailbox.local_pending = Some(request);
        }
        if let Ok(mut layout) = self.input_layout.lock() {
            *layout = None;
        }
        if let Ok(mut update) = self.video_update.lock() {
            *update = Some(VideoUpdate::Disconnected(None));
        }
        true
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_else(|_| Arc::new(Snapshot::default()))
    }
    /// Capture the generation from the view that produced this click, before
    /// entering the queue. Reading a newer view at dequeue would relabel an
    /// action intended for a different account/server.
    pub fn submit(&self, generation: u64, command: Command) -> bool {
        self.submit_tracked(generation, command).is_some()
    }
    pub fn submit_tracked(&self, generation: u64, command: Command) -> Option<u64> {
        let submission_id = self.next_submission_id.fetch_add(1, Ordering::Relaxed);
        self.commands
            .try_send(QueuedCommand {
                submission_id,
                generation,
                command,
            })
            .ok()
            .map(|()| submission_id)
    }
    pub fn drain(&self) -> impl Iterator<Item = Notice> + '_ {
        self.notices.try_iter()
    }

    pub fn set_video_interest(&self, interested: bool) {
        self.video_interest.send_if_modified(|current| {
            if *current == interested {
                false
            } else {
                *current = interested;
                true
            }
        });
    }

    pub fn runtime_id(&self) -> Option<String> {
        self.runtime_id
            .lock()
            .ok()
            .and_then(|runtime_id| runtime_id.clone())
    }

    pub fn take_video_update(&self) -> Option<VideoUpdate> {
        self.video_update
            .lock()
            .ok()
            .and_then(|mut update| update.take())
    }

    pub fn set_input_interest(&self, interested: bool) {
        self.input_interest.send_if_modified(|current| {
            if *current == interested {
                false
            } else {
                *current = interested;
                true
            }
        });
    }

    pub fn input_layout(&self) -> Option<InputLayoutUpdate> {
        self.input_layout
            .lock()
            .ok()
            .and_then(|layout| layout.clone())
    }

    pub fn send_native_input(
        &self,
        generation: u64,
        binding: NativeInputBinding,
        action: NativeInputAction,
    ) -> bool {
        self.input_commands
            .try_send(QueuedInput {
                generation,
                binding,
                action,
            })
            .is_ok()
    }

    pub fn release_native_input(&self, generation: u64, binding: NativeInputBinding) {
        self.input_release.send_replace(Some(InputRelease {
            generation,
            binding,
        }));
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.video_interest.send_replace(false);
        self.video_stop.send_replace(true);
        self.input_interest.send_replace(false);
        if let Some(layout) = self.input_layout() {
            self.release_native_input(layout.ui_generation, layout.layout.binding.clone());
        }
        self.input_stop.send_replace(true);
        if let Some(worker) = self.input_thread.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.video_thread.take() {
            let _ = worker.join();
        }
        clear_video_update(&self.video_update);
    }
}
fn launch_daemon(directory: &Path) -> io::Result<Child> {
    let executable = std::env::current_exe()?.with_file_name(if cfg!(windows) {
        "nestlink-daemon.exe"
    } else {
        "nestlink-daemon"
    });
    let mut process = Process::new(executable);
    process.arg("--state-dir").arg(directory);
    process.env("NESTLINK_LOCAL_GUI_PID", std::process::id().to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The user daemon has no console UI and runs at the caller's privilege.
        process.creation_flags(0x0800_0000);
    }
    process
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}
async fn connect(directory: &Path) -> io::Result<Client> {
    match Client::connect(directory).await {
        Ok(client) => return Ok(client),
        Err(error) if error.is_transient_connect() => {}
        Err(nestlink_app_ipc::Error::Transport(_)) => {
            // Authentication and protocol failures never rotate keys or spawn
            // a sibling that could bypass an existing trust decision.
            return Err(io::Error::other("existing daemon could not authenticate"));
        }
        Err(_) => return Err(io::Error::other("existing daemon response invalid")),
    }
    // Share admission across the spawn-to-IPC handoff. A maintenance owner
    // cannot enter between this check and a real daemon singleton being held.
    let _startup = nestlink_local_ipc::maintenance::StartupPermit::acquire(directory)
        .map_err(io::Error::other)?;
    let mut child = launch_daemon(directory)?;
    let deadline = tokio::time::Instant::now() + DAEMON_STARTUP_BUDGET;
    let mut child_running = true;
    loop {
        match tokio::time::timeout_at(deadline, Client::connect(directory)).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(error)) if error.is_transient_connect() => {}
            Ok(Err(nestlink_app_ipc::Error::Transport(_))) => {
                return Err(io::Error::other("existing daemon could not authenticate"));
            }
            Ok(Err(_)) => return Err(io::Error::other("existing daemon response invalid")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "user daemon startup exceeded its budget",
                ));
            }
        }
        if child_running {
            // Another UI process may have won the singleton lock and still be
            // publishing its endpoint. Reap our losing sibling, but keep
            // trying until the bounded deadline instead of failing that race.
            child_running = child.try_wait()?.is_none();
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            _ = tokio::time::sleep_until(deadline) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "user daemon startup exceeded its budget",
                ));
            }
        }
    }
}
fn apply(
    response: Response,
    submission_id: Option<u64>,
    completed: Option<OperationId>,
    notices: &SyncSender<Notice>,
    snapshot: &Arc<Mutex<Arc<Snapshot>>>,
    pending: &mut VecDeque<(OperationId, Option<u64>)>,
    context: &egui::Context,
) -> bool {
    let response_generation = response.snapshot.generation;
    let response_runtime_id = response.runtime_id;
    if let Ok(mut value) = snapshot.lock() {
        *value = response.snapshot;
    }
    let mut finished = false;
    match response.result {
        Reply::PrivilegedInput { generation, result } => {
            let _ = notices.try_send(Notice::PrivilegedInput {
                submission_id,
                runtime_id: response_runtime_id,
                generation,
                result,
            });
        }
        Reply::NativeNetworkConfigured { result } => {
            let _ = notices.try_send(Notice::NativeNetworkConfigured {
                submission_id,
                runtime_id: response_runtime_id,
                result,
            });
        }
        Reply::NativeDownloadRecovery { generation, result } => {
            let _ = notices.try_send(Notice::NativeDownloadRecovery {
                submission_id,
                runtime_id: response_runtime_id,
                generation,
                result,
            });
        }
        Reply::NativeFiles {
            binding,
            generation,
            result,
        } => {
            let _ = notices.try_send(Notice::NativeFiles {
                submission_id,
                runtime_id: response_runtime_id,
                binding,
                generation,
                result,
            });
        }
        Reply::BrowserHostData {
            binding,
            generation,
            result,
        } => {
            let _ = notices.try_send(Notice::BrowserHostData {
                submission_id,
                binding,
                generation,
                result,
            });
        }
        Reply::LocalServiceHostPreview { preview } => {
            if let Some(submission_id) = submission_id {
                let _ = notices.try_send(Notice::LocalServiceHostPreview {
                    submission_id,
                    preview,
                });
            }
        }
        Reply::LocalServiceHostStopped { accepted } => {
            if let Some(submission_id) = submission_id {
                let _ = notices.try_send(Notice::LocalServiceHostStopped {
                    submission_id,
                    accepted,
                });
            }
        }
        result @ (Reply::NativeClipboardStatus { .. }
        | Reply::NativeClipboardDirectionsSet { .. }
        | Reply::NativeClipboardActionResult { .. }
        | Reply::NativeClipboardRejected { .. }) => {
            let _ = notices.try_send(Notice::NativeClipboard {
                submission_id,
                generation: response_generation,
                result,
            });
        }
        Reply::Accepted { operation } => {
            pending.push_back((operation, submission_id));
            if let Some(submission_id) = submission_id {
                let _ = notices.try_send(Notice::Accepted {
                    submission_id,
                    operation_id: operation,
                });
            }
        }
        Reply::Completed {
            operation,
            sensitive,
        } => {
            let tracked_submission = submission_id.or_else(|| {
                pending
                    .iter()
                    .find(|(id, _)| *id == operation.id)
                    .and_then(|(_, submission)| *submission)
            });
            pending.retain(|(pending, _)| *pending != operation.id);
            // Delivery is one consumption. A hidden/slow UI cannot create an
            // unbounded secret cache; dropping a full notice clears its secrets.
            let _ = notices.try_send(Notice::Completed {
                submission_id: tracked_submission,
                result: operation,
                sensitive,
            });
        }
        Reply::Rejected { reason } => {
            let tracked_submission = submission_id.or_else(|| {
                completed.and_then(|completed| {
                    pending
                        .iter()
                        .find(|(id, _)| *id == completed)
                        .and_then(|(_, submission)| *submission)
                })
            });
            if let Some(completed) = completed {
                pending.retain(|(id, _)| *id != completed);
            }
            let _ = notices.try_send(Notice::Rejected {
                submission_id: tracked_submission,
                reason,
            });
        }
        Reply::Exited { result } => {
            finished = result == ExitResult::Complete;
            let _ = notices.try_send(Notice::Exited(result));
        }
        _ => {}
    }
    context.request_repaint();
    finished
}
async fn run(
    directory: PathBuf,
    context: egui::Context,
    incoming: Receiver<QueuedCommand>,
    outgoing: SyncSender<Notice>,
    snapshot: Arc<Mutex<Arc<Snapshot>>>,
    media: NativeMediaContext,
) -> io::Result<()> {
    let NativeMediaContext {
        runtime_id,
        displays,
    } = media;
    let mut client = connect(&directory).await?;
    if let Ok(mut current) = runtime_id.lock() {
        *current = Some(client.runtime_id().to_owned());
    }
    let response = client
        .request(0, Command::Snapshot)
        .await
        .map_err(io::Error::other)?;
    let mut pending = VecDeque::new();
    apply(
        response,
        None,
        None,
        &outgoing,
        &snapshot,
        &mut pending,
        &context,
    );
    let _ = outgoing.try_send(Notice::Connected);
    let mut interval = tokio::time::interval(Duration::from_millis(350));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // Commands and completion polling share one authenticated ordered stream.
        // We do not replay mutations after a broken response.
        for _ in 0..16 {
            let command = match incoming.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            };
            let response = client
                .request(command.generation, command.command)
                .await
                .map_err(io::Error::other)?;
            if apply(
                response,
                Some(command.submission_id),
                None,
                &outgoing,
                &snapshot,
                &mut pending,
                &context,
            ) {
                return Ok(());
            }
        }
        let operations: Vec<_> = pending.iter().map(|(operation, _)| *operation).collect();
        for operation in operations {
            let response = client
                .request(0, Command::Completion { operation })
                .await
                .map_err(io::Error::other)?;
            apply(
                response,
                None,
                Some(operation),
                &outgoing,
                &snapshot,
                &mut pending,
                &context,
            );
        }
        let response = client
            .request(0, Command::Snapshot)
            .await
            .map_err(io::Error::other)?;
        apply(
            response,
            None,
            None,
            &outgoing,
            &snapshot,
            &mut pending,
            &context,
        );
        let current = snapshot.lock().ok().map(|view| view.clone());
        let binding = current
            .as_ref()
            .and_then(|view| view.native_session.data.as_ref())
            .filter(|session| session.status == nestlink_app_core::NativeSessionStatus::Connected)
            .map(|session| NativeSessionBinding {
                request_id: session.request_id.clone(),
                connection_generation: session.connection_generation,
            });
        if let Some(binding) = binding {
            let response = client
                .request(
                    0,
                    Command::GetNativeDisplays {
                        binding: binding.clone(),
                    },
                )
                .await
                .map_err(io::Error::other)?;
            if let Reply::NativeDisplays {
                binding: returned,
                state,
            } = response.result
                && returned == binding
            {
                if let Ok(mut mailbox) = displays.lock() {
                    if mailbox.local_pending.as_ref().is_some_and(|request| {
                        state.as_ref().is_none_or(|state| {
                            state.catalog.as_ref() != Some(&request.catalog)
                                || state.pending.as_ref() == Some(request)
                                || state
                                    .selected
                                    .as_ref()
                                    .is_some_and(|selected| selected.sequence >= request.sequence)
                        })
                    }) {
                        mailbox.local_pending = None;
                    }
                    mailbox.state = state;
                }
                context.request_repaint();
            }
        } else if let Ok(mut mailbox) = displays.lock() {
            *mailbox = DisplayMailbox::default();
        }
        interval.tick().await;
    }
}

#[derive(Clone, PartialEq, Eq)]
struct VideoTarget {
    runtime_id: String,
    ui_generation: u64,
    request_id: String,
    connection_generation: u64,
    source: u32,
    layout_epoch: u64,
}

fn video_target(
    snapshot: &Arc<Mutex<Arc<Snapshot>>>,
    runtime_id: &Arc<Mutex<Option<String>>>,
    interested: bool,
    displays: &SharedDisplays,
) -> Option<VideoTarget> {
    if !interested {
        return None;
    }
    let runtime_id = runtime_id.lock().ok()?.clone()?;
    let view = snapshot
        .lock()
        .map(|snapshot| snapshot.clone())
        .unwrap_or_else(|_| Arc::new(Snapshot::default()));
    let session = view.native_session.data.as_ref()?;
    if session.status != nestlink_app_core::NativeSessionStatus::Connected {
        return None;
    }
    if session.host_view_authorized {
        return None;
    }
    let mailbox = displays.lock().ok()?;
    if mailbox.local_pending.is_some() {
        return None;
    }
    let state = mailbox.state.as_ref()?;
    if state.pending.is_some() {
        return None;
    }
    let selected = state.selected.as_ref()?;
    if selected.catalog.request_id != session.request_id
        || selected.catalog.connection_generation != session.connection_generation
    {
        return None;
    }
    Some(VideoTarget {
        runtime_id,
        ui_generation: view.generation,
        request_id: session.request_id.clone(),
        connection_generation: session.connection_generation,
        source: selected.source,
        layout_epoch: selected.layout_epoch,
    })
}

impl VideoTarget {
    fn matches_message(&self, message: &NativeVideoMessage) -> bool {
        match message {
            NativeVideoMessage::Layout(layout) => {
                self.matches_binding(&layout.binding) && layout.layout_epoch == self.layout_epoch
            }
            NativeVideoMessage::Frame(frame) => {
                self.matches_binding(&frame.binding) && frame.layout_epoch == self.layout_epoch
            }
            NativeVideoMessage::Closed(binding) => self.matches_binding(binding),
        }
    }
    fn matches_binding(&self, binding: &NativeVideoBinding) -> bool {
        binding.runtime_id == self.runtime_id
            && binding.ui_generation == self.ui_generation
            && binding.request_id == self.request_id
            && binding.connection_generation == self.connection_generation
            && binding.source == self.source
    }
}

fn publish_video(
    updates: &Arc<Mutex<Option<VideoUpdate>>>,
    context: &egui::Context,
    update: VideoUpdate,
) {
    if let Ok(mut current) = updates.lock() {
        *current = Some(update);
        context.request_repaint();
    }
}

fn clear_video_update(updates: &Arc<Mutex<Option<VideoUpdate>>>) {
    if let Ok(mut current) = updates.lock() {
        let _ = current.take();
    }
}

/// Owns one binary stream at a time. Receive futures stay pinned while the
/// lightweight state poll runs, so a snapshot check never cancels a partial
/// frame and then tries to reuse the poisoned connection.
async fn run_video(
    directory: PathBuf,
    snapshot: Arc<Mutex<Arc<Snapshot>>>,
    updates: Arc<Mutex<Option<VideoUpdate>>>,
    mut interested: tokio::sync::watch::Receiver<bool>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    context: egui::Context,
    media: NativeMediaContext,
) {
    let NativeMediaContext {
        runtime_id,
        displays,
    } = media;
    loop {
        if *stopped.borrow() {
            clear_video_update(&updates);
            return;
        }
        let Some(target) = video_target(&snapshot, &runtime_id, *interested.borrow(), &displays)
        else {
            clear_video_update(&updates);
            tokio::select! {
                biased;
                changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                changed = interested.changed() => if changed.is_err() { return; },
                _ = tokio::time::sleep(VIDEO_STATE_POLL) => {},
            }
            continue;
        };

        let open = VideoClient::open(
            &directory,
            target.ui_generation,
            target.request_id.clone(),
            target.connection_generation,
            target.source,
        );
        tokio::pin!(open);
        let opened = loop {
            if *stopped.borrow() {
                return;
            }
            tokio::select! {
                biased;
                changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                changed = interested.changed() => if changed.is_err() { return; },
                result = &mut open => break Some(result),
                _ = tokio::time::sleep(VIDEO_STATE_POLL) => {
                    if video_target(&snapshot, &runtime_id, *interested.borrow(),&displays).as_ref() != Some(&target) {
                        break None;
                    }
                }
            }
        };
        let Some(opened) = opened else {
            continue;
        };
        let mut client = match opened {
            Ok(client)
                if target.matches_binding(client.binding())
                    && video_target(&snapshot, &runtime_id, *interested.borrow(), &displays)
                        .as_ref()
                        == Some(&target) =>
            {
                client
            }
            Ok(client) => {
                publish_video(
                    &updates,
                    &context,
                    VideoUpdate::Disconnected(Some(client.binding().clone())),
                );
                continue;
            }
            Err(_) => {
                publish_video(&updates, &context, VideoUpdate::Disconnected(None));
                tokio::select! {
                    biased;
                    changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                    changed = interested.changed() => if changed.is_err() { return; },
                    _ = tokio::time::sleep(VIDEO_RETRY_DELAY) => {},
                }
                continue;
            }
        };

        let binding = client.binding().clone();
        publish_video(&updates, &context, VideoUpdate::Connecting(binding.clone()));
        let mut stream_ended = false;
        while !stream_ended {
            let receive = client.receive();
            tokio::pin!(receive);
            loop {
                if *stopped.borrow()
                    || video_target(&snapshot, &runtime_id, *interested.borrow(), &displays)
                        .as_ref()
                        != Some(&target)
                {
                    stream_ended = true;
                    break;
                }
                tokio::select! {
                    biased;
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            stream_ended = true;
                            break;
                        }
                    }
                    changed = interested.changed() => {
                        if changed.is_err() {
                            stream_ended = true;
                            break;
                        }
                    }
                    result = &mut receive => {
                        match result {
                            Ok(NativeVideoMessage::Closed(_)) => {
                                stream_ended = true;
                            }
                            Ok(message) => {
                                if target.matches_message(&message) && video_target(&snapshot,&runtime_id,*interested.borrow(),&displays).as_ref()==Some(&target) {
                                    publish_video(&updates,&context,VideoUpdate::Message(message));
                                } else {
                                    stream_ended=true;
                                }
                            },
                            Err(_) => stream_ended = true,
                        }
                        break;
                    }
                    _ = tokio::time::sleep(VIDEO_STATE_POLL) => {}
                }
            }
        }
        publish_video(&updates, &context, VideoUpdate::Disconnected(Some(binding)));
        if *stopped.borrow() {
            return;
        }
        if video_target(&snapshot, &runtime_id, *interested.borrow(), &displays).as_ref()
            == Some(&target)
        {
            tokio::select! {
                biased;
                changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                changed = interested.changed() => if changed.is_err() { return; },
                _ = tokio::time::sleep(VIDEO_RETRY_DELAY) => {},
            }
        }
    }
}

async fn run_input(
    worker: InputWorkerContext,
    mut commands: tokio::sync::mpsc::Receiver<QueuedInput>,
    mut interested: tokio::sync::watch::Receiver<bool>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    mut releases: tokio::sync::watch::Receiver<Option<InputRelease>>,
) {
    let InputWorkerContext {
        directory,
        snapshot,
        layout_state,
        displays,
        context,
        runtime_id,
    } = worker;
    let mut client: Option<NativeInputClient> = None;
    let mut target: Option<VideoTarget> = None;
    let mut layout: Option<NativeInputLayout> = None;
    let mut poll = tokio::time::interval(INPUT_STATE_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *stopped.borrow() {
            if let (Some(target), Some(layout)) = (&target, &layout) {
                let released = release_input_client(&mut client, target, layout).await;
                if !released {
                    client.take();
                }
            }
            clear_input_layout(&layout_state, &context);
            return;
        }

        let desired = input_target(&snapshot, &runtime_id, *interested.borrow(), &displays);
        if desired != target {
            if let (Some(previous), Some(previous_layout)) = (&target, &layout)
                && !release_input_client(&mut client, previous, previous_layout).await
            {
                client.take();
            }
            while commands.try_recv().is_ok() {}
            target = desired;
            layout = None;
            clear_input_layout(&layout_state, &context);
            if target.is_none() {
                client.take();
            }
        }

        let Some(current_target) = target.clone() else {
            tokio::select! {
                biased;
                changed = stopped.changed() => { let _ = changed; },
                changed = interested.changed() => if changed.is_err() { return; },
                _ = tokio::time::sleep(INPUT_STATE_POLL) => {},
            }
            continue;
        };

        if client.is_none() {
            match NativeInputClient::connect(&directory).await {
                Ok(connected) if connected.runtime_id() == current_target.runtime_id => {
                    client = Some(connected);
                }
                _ => {
                    clear_input_layout(&layout_state, &context);
                    tokio::select! {
                        biased;
                        changed = stopped.changed() => { let _ = changed; },
                        changed = interested.changed() => if changed.is_err() { return; },
                        _ = tokio::time::sleep(INPUT_RETRY_DELAY) => {},
                    }
                    continue;
                }
            }
        }

        if layout.is_none() {
            let fetched = match client.as_mut() {
                Some(connection) => {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        connection.layout(
                            current_target.ui_generation,
                            current_target.request_id.clone(),
                            current_target.connection_generation,
                            current_target.source,
                        ),
                    )
                    .await
                }
                None => continue,
            };
            match fetched {
                Ok(Ok(Some(next))) if input_layout_matches(&next, &current_target) => {
                    publish_input_layout(
                        &layout_state,
                        &context,
                        Some(InputLayoutUpdate {
                            runtime_id: current_target.runtime_id.clone(),
                            ui_generation: current_target.ui_generation,
                            layout: next.clone(),
                        }),
                    );
                    layout = Some(next);
                }
                Ok(Ok(None)) => clear_input_layout(&layout_state, &context),
                _ => {
                    client.take();
                    clear_input_layout(&layout_state, &context);
                }
            }
            if layout.is_none() {
                tokio::select! {
                    biased;
                    changed = stopped.changed() => { let _ = changed; },
                    changed = interested.changed() => if changed.is_err() { return; },
                    _ = tokio::time::sleep(INPUT_RETRY_DELAY) => {},
                }
            }
            continue;
        }

        if releases.has_changed().unwrap_or(false) {
            let pending = releases.borrow_and_update().clone();
            if let (Some(pending), Some(current_layout)) = (pending, layout.as_ref())
                && pending.generation == current_target.ui_generation
                && input_binding_matches(&pending.binding, &current_layout.binding)
            {
                let result = match client.as_mut() {
                    Some(connection) => {
                        tokio::time::timeout(
                            Duration::from_secs(2),
                            connection.release(pending.generation, pending.binding),
                        )
                        .await
                    }
                    None => continue,
                };
                while commands.try_recv().is_ok() {}
                if !matches!(result, Ok(Ok(()))) {
                    client.take();
                    layout = None;
                    clear_input_layout(&layout_state, &context);
                }
                continue;
            }
        }

        tokio::select! {
            biased;
            changed = stopped.changed() => { let _ = changed; },
            changed = interested.changed() => if changed.is_err() { return; },
            changed = releases.changed() => { let _ = changed; },
            command = commands.recv() => {
                let Some(command) = command else {
                    clear_input_layout(&layout_state, &context);
                    return;
                };
                let Some(current_layout) = layout.as_ref() else { continue; };
                if command.generation != current_target.ui_generation
                    || !input_binding_matches(&command.binding, &current_layout.binding)
                    || input_target(&snapshot, &runtime_id, *interested.borrow(),&displays).as_ref()
                        != Some(&current_target)
                {
                    continue;
                }
                let result = match client.as_mut() {
                    Some(connection) => tokio::time::timeout(
                        Duration::from_secs(2),
                        connection.send(command.generation, command.binding, command.action),
                    )
                    .await,
                    None => continue,
                };
                if !matches!(result, Ok(Ok(()))) {
                    // Closing the authenticated connection makes app-ipc::serve
                    // release the exact last binding if this send stalled.
                    client.take();
                    layout = None;
                    clear_input_layout(&layout_state, &context);
                }
            }
            _ = poll.tick() => {
                let fetched = match client.as_mut() {
                    Some(connection) => tokio::time::timeout(
                        Duration::from_secs(2),
                        connection.layout(
                            current_target.ui_generation,
                            current_target.request_id.clone(),
                            current_target.connection_generation,
                            current_target.source,
                        ),
                    )
                    .await,
                    None => continue,
                };
                match fetched {
                    Ok(Ok(Some(next))) if input_layout_matches(&next, &current_target) => {
                        let changed = layout.as_ref().is_some_and(|previous| {
                            !input_binding_matches(&previous.binding, &next.binding)
                                || previous.left != next.left
                                || previous.top != next.top
                                || previous.width != next.width
                                || previous.height != next.height
                        });
                        if changed {
                            if let Some(previous) = layout.as_ref()
                                && !release_input_client(&mut client, &current_target, previous).await
                            {
                                client.take();
                            }
                            layout = Some(next.clone());
                            publish_input_layout(
                                &layout_state,
                                &context,
                                Some(InputLayoutUpdate {
                                    runtime_id: current_target.runtime_id.clone(),
                                    ui_generation: current_target.ui_generation,
                                    layout: next,
                                }),
                            );
                        }
                    }
                    Ok(Ok(None)) => {
                        if let Some(previous) = layout.as_ref()
                            && !release_input_client(&mut client, &current_target, previous).await
                        {
                            client.take();
                        }
                        layout = None;
                        clear_input_layout(&layout_state, &context);
                    }
                    _ => {
                        client.take();
                        layout = None;
                        clear_input_layout(&layout_state, &context);
                    }
                }
            }
        }
    }
}

fn input_target(
    snapshot: &Arc<Mutex<Arc<Snapshot>>>,
    runtime_id: &Arc<Mutex<Option<String>>>,
    interested: bool,
    displays: &SharedDisplays,
) -> Option<VideoTarget> {
    video_target(snapshot, runtime_id, interested, displays)
}

fn input_layout_matches(layout: &NativeInputLayout, target: &VideoTarget) -> bool {
    layout.binding.request_id == target.request_id
        && layout.binding.connection_generation == target.connection_generation
        && layout.binding.source == target.source
        && layout.binding.input_epoch > 0
        && layout.binding.input_epoch <= i64::MAX as u64
        && layout.binding.layout_epoch == target.layout_epoch
        && layout.binding.layout_epoch > 0
        && layout.binding.layout_epoch <= i64::MAX as u64
        && layout.width > 0
        && layout.height > 0
        && layout.width <= 32768
        && layout.height <= 32768
        && i64::from(layout.left) + i64::from(layout.width) <= i64::from(i32::MAX) + 1
        && i64::from(layout.top) + i64::from(layout.height) <= i64::from(i32::MAX) + 1
}

fn input_binding_matches(left: &NativeInputBinding, right: &NativeInputBinding) -> bool {
    left.request_id == right.request_id
        && left.connection_generation == right.connection_generation
        && left.source == right.source
        && left.input_epoch == right.input_epoch
        && left.layout_epoch == right.layout_epoch
}

async fn release_input_client(
    client: &mut Option<NativeInputClient>,
    target: &VideoTarget,
    layout: &NativeInputLayout,
) -> bool {
    let Some(client) = client.as_mut() else {
        return true;
    };
    matches!(
        tokio::time::timeout(
            Duration::from_millis(750),
            client.release(target.ui_generation, layout.binding.clone()),
        )
        .await,
        Ok(Ok(()))
    )
}

fn publish_input_layout(
    layouts: &Arc<Mutex<Option<InputLayoutUpdate>>>,
    context: &egui::Context,
    layout: Option<InputLayoutUpdate>,
) {
    if let Ok(mut current) = layouts.lock() {
        *current = layout;
        context.request_repaint();
    }
}

fn clear_input_layout(layouts: &Arc<Mutex<Option<InputLayoutUpdate>>>, context: &egui::Context) {
    publish_input_layout(layouts, context, None);
}

#[cfg(test)]
mod video_bridge_tests {
    use super::*;
    use nestlink_app_core::{NativeSessionStatus, NativeSessionView, Section};
    use zeroize::Zeroizing;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const RUNTIME_ID: &str = "00000000-0000-4000-8000-000000000001";
    const REQUEST_ID: &str = "00000000-0000-4000-8000-000000000002";

    fn binding() -> NativeVideoBinding {
        NativeVideoBinding {
            runtime_id: RUNTIME_ID.into(),
            ui_generation: 7,
            request_id: REQUEST_ID.into(),
            connection_generation: 9,
            source: 0,
        }
    }

    fn terminal_snapshot() -> Snapshot {
        Snapshot {
            native_session: Section {
                data: Some(Arc::new(NativeSessionView {
                    request_id: REQUEST_ID.into(),
                    connection_generation: 9,
                    lease_sequence: 4,
                    status: NativeSessionStatus::Stopped,
                    host_view_authorized: false,
                    path: None,
                    stop_reason: Some(nestlink_app_core::NativeSessionStopReason::Revoked),
                    stop_effects: None,
                    cleanup: None,
                    failure: None,
                })),
                ..Section::default()
            },
            ..Snapshot::default()
        }
    }

    fn connected_snapshot() -> Snapshot {
        let mut snapshot = terminal_snapshot();
        let session = snapshot
            .native_session
            .data
            .as_ref()
            .map(|session| (**session).clone())
            .unwrap_or(NativeSessionView {
                request_id: REQUEST_ID.into(),
                connection_generation: 9,
                lease_sequence: 4,
                status: NativeSessionStatus::Connected,
                host_view_authorized: false,
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            });
        snapshot.native_session.data = Some(Arc::new(NativeSessionView {
            status: NativeSessionStatus::Connected,
            ..session
        }));
        snapshot
    }

    fn queued_frame() -> VideoUpdate {
        VideoUpdate::Message(NativeVideoMessage::Frame(
            nestlink_app_ipc::NativeVideoFrame {
                codec: 0,
                hardware_decode: false,
                binding: binding(),
                layout_epoch: 2,
                sequence: 1,
                pts_90khz: 90,
                width: 1,
                height: 1,
                pixels: Zeroizing::new(vec![0x7f; 4]),
            },
        ))
    }

    #[test]
    fn video_target_requires_the_exact_confirmed_catalogue_source_and_epoch() -> TestResult {
        let mut current = connected_snapshot();
        current.generation = 7;
        let snapshot = Arc::new(Mutex::new(Arc::new(current)));
        let runtime = Arc::new(Mutex::new(Some(RUNTIME_ID.into())));
        let displays = Arc::new(Mutex::new(DisplayMailbox::default()));
        assert!(video_target(&snapshot, &runtime, true, &displays).is_none());
        let key = nestlink_app_core::DisplayCatalogKey {
            request_id: REQUEST_ID.into(),
            connection_generation: 9,
            revision: 1,
            sha256: [9; 32],
        };
        let selected = nestlink_app_core::DisplaySelection {
            catalog: key.clone(),
            source: 77,
            sequence: 2,
            layout_epoch: 2,
            input_epoch: 2,
        };
        displays.lock().map_err(|_| "fixture poisoned")?.state = Some(NativeDisplayState {
            is_host: false,
            catalog: Some(key.clone()),
            displays: Vec::new(),
            local_approval_required: false,
            approved_sources: vec![42, 77],
            initial_source: Some(42),
            catalog_acknowledged: true,
            selected: Some(selected),
            pending: None,
        });
        let target =
            video_target(&snapshot, &runtime, true, &displays).ok_or("missing confirmed target")?;
        assert_eq!((target.source, target.layout_epoch), (77, 2));
        displays
            .lock()
            .map_err(|_| "fixture poisoned")?
            .local_pending = Some(NativeDisplayRequest {
            catalog: key,
            sequence: 3,
            source: 42,
        });
        assert!(video_target(&snapshot, &runtime, true, &displays).is_none());
        displays
            .lock()
            .map_err(|_| "fixture poisoned")?
            .local_pending = None;
        if let Some(state) = displays
            .lock()
            .map_err(|_| "fixture poisoned")?
            .state
            .as_mut()
        {
            state
                .selected
                .as_mut()
                .ok_or("no selection")?
                .catalog
                .connection_generation += 1;
        }
        assert!(video_target(&snapshot, &runtime, true, &displays).is_none());
        Ok(())
    }
    #[test]
    fn video_messages_from_retired_layouts_are_never_published() {
        let target = VideoTarget {
            runtime_id: RUNTIME_ID.into(),
            ui_generation: 7,
            request_id: REQUEST_ID.into(),
            connection_generation: 9,
            source: 0,
            layout_epoch: 3,
        };
        let VideoUpdate::Message(message) = queued_frame() else {
            panic!("fixture missing frame")
        };
        assert!(!target.matches_message(&message));
        let NativeVideoMessage::Frame(mut frame) = message else {
            panic!("fixture wrong message")
        };
        frame.layout_epoch = 3;
        assert!(target.matches_message(&NativeVideoMessage::Frame(frame)));
    }
    #[test]
    fn video_mailbox_replaces_old_frames_and_clear_discards_the_latest_message() {
        let mailbox = Arc::new(Mutex::new(None));
        let context = egui::Context::default();
        publish_video(&mailbox, &context, VideoUpdate::Connecting(binding()));
        publish_video(&mailbox, &context, queued_frame());
        publish_video(
            &mailbox,
            &context,
            VideoUpdate::Disconnected(Some(binding())),
        );
        assert!(matches!(
            mailbox.lock().ok().and_then(|mut mailbox| mailbox.take()),
            Some(VideoUpdate::Disconnected(Some(_)))
        ));

        publish_video(&mailbox, &context, queued_frame());
        clear_video_update(&mailbox);
        assert!(mailbox.lock().is_ok_and(|mailbox| mailbox.is_none()));
    }

    #[tokio::test]
    async fn revoked_or_terminal_session_clears_the_pending_frame_mailbox() -> TestResult {
        let mailbox = Arc::new(Mutex::new(Some(queued_frame())));
        let snapshot = Arc::new(Mutex::new(Arc::new(terminal_snapshot())));
        let runtime_id = Arc::new(Mutex::new(Some(RUNTIME_ID.to_owned())));
        let (interest, interest_rx) = tokio::sync::watch::channel(true);
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let context = egui::Context::default();
        let worker = tokio::spawn(run_video(
            PathBuf::new(),
            snapshot,
            mailbox.clone(),
            interest_rx,
            stop_rx,
            context,
            NativeMediaContext {
                runtime_id,
                displays: Arc::new(Mutex::new(DisplayMailbox::default())),
            },
        ));

        tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if mailbox.lock().is_ok_and(|mailbox| mailbox.is_none()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        stop.send_replace(true);
        worker.await?;
        drop(interest);
        Ok(())
    }

    #[tokio::test]
    async fn hidden_window_interest_does_not_open_or_retain_a_video_subscription() -> TestResult {
        let mailbox = Arc::new(Mutex::new(Some(queued_frame())));
        let snapshot = Arc::new(Mutex::new(Arc::new(connected_snapshot())));
        let runtime_id = Arc::new(Mutex::new(Some(RUNTIME_ID.to_owned())));
        let (interest, interest_rx) = tokio::sync::watch::channel(false);
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(run_video(
            PathBuf::new(),
            snapshot,
            mailbox.clone(),
            interest_rx,
            stop_rx,
            egui::Context::default(),
            NativeMediaContext {
                runtime_id,
                displays: Arc::new(Mutex::new(DisplayMailbox::default())),
            },
        ));
        tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if mailbox.lock().is_ok_and(|mailbox| mailbox.is_none()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        tokio::time::sleep(VIDEO_STATE_POLL * 2).await;
        assert!(mailbox.lock().is_ok_and(|mailbox| mailbox.is_none()));
        stop.send_replace(true);
        worker.await?;
        drop(interest);
        Ok(())
    }
}
