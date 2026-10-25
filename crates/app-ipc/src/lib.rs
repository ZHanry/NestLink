//! Typed normal-user daemon IPC. Remote business rules remain in app-core/SDK.
pub mod browser_data;
pub mod clipboard;
pub mod compressed_video;
pub mod files;
pub mod privileged_input;
mod video;
pub mod wire {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol-spec/application-ipc.rs"
    ));
}
use nestlink_app_core::{
    CoreHandle, NativeInputAction, NativeInputBinding, NativeInputLayout, SubmitError, Ticket,
};
use nestlink_local_ipc::LocalStream;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::sync::{mpsc, oneshot};
pub use video::{
    NativeVideoBinding, NativeVideoFrame, NativeVideoLayout, NativeVideoMessage, VideoClient,
};
use wire::*;

pub struct ExitRequest {
    pub reply: oneshot::Sender<ExitResult>,
    pub delivered: oneshot::Receiver<()>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] nestlink_local_ipc::Error),
    #[error("daemon response does not match this request or runtime")]
    Protocol,
}
impl Error {
    /// Whether a failed initial daemon connection can plausibly succeed after
    /// the daemon is started or its endpoint is republished.
    pub fn is_transient_connect(&self) -> bool {
        match self {
            Self::Transport(
                nestlink_local_ipc::Error::Timeout | nestlink_local_ipc::Error::Stopped,
            ) => true,
            Self::Transport(nestlink_local_ipc::Error::Io(error)) => matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable
            ),
            Self::Transport(
                nestlink_local_ipc::Error::Authentication
                | nestlink_local_ipc::Error::Protocol
                | nestlink_local_ipc::Error::AlreadyRunning
                | nestlink_local_ipc::Error::Maintenance,
            )
            | Self::Protocol => false,
        }
    }
}

pub struct Client {
    connection: LocalStream,
    sequence: u64,
    failed: bool,
}
impl Client {
    pub async fn connect(directory: &Path) -> Result<Self, Error> {
        Ok(Self {
            connection: LocalStream::connect(directory).await?,
            sequence: 1,
            failed: false,
        })
    }
    pub fn runtime_id(&self) -> &str {
        self.connection.runtime_id()
    }
    /// A failed command is never automatically replayed on a new connection.
    /// Loss of an acknowledgement can mean the remote transaction committed.
    pub async fn request(
        &mut self,
        expected_generation: u64,
        command: Command,
    ) -> Result<Response, Error> {
        if self.failed {
            return Err(Error::Protocol);
        }
        // Cancellation or a lost acknowledgement must not reuse the stream or
        // retransmit an operation whose server transaction may have committed.
        self.failed = true;
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1).ok_or(Error::Protocol)?;
        let request = Request {
            version: nestlink_local_ipc::VERSION,
            runtime_id: self.connection.runtime_id().to_owned(),
            sequence,
            expected_generation,
            command,
        };
        self.connection.send(&request).await?;
        let response: Response = self.connection.receive().await?;
        if response.version != nestlink_local_ipc::VERSION
            || response.sequence != sequence
            || response.runtime_id != self.connection.runtime_id()
        {
            return Err(Error::Protocol);
        }
        self.failed = false;
        Ok(response)
    }
}

/// One authenticated local IPC connection dedicated to native input. It uses
/// the same bounded JSON framing and generation/session checks as normal UI
/// commands; the daemon drops and releases its exact binding when this client
/// disappears.
pub struct NativeInputClient {
    client: Client,
}
impl NativeInputClient {
    pub async fn connect(directory: &Path) -> Result<Self, Error> {
        Ok(Self {
            client: Client::connect(directory).await?,
        })
    }

    pub fn runtime_id(&self) -> &str {
        self.client.runtime_id()
    }

    pub async fn layout(
        &mut self,
        ui_generation: u64,
        request_id: String,
        connection_generation: u64,
        source: u32,
    ) -> Result<Option<NativeInputLayout>, Error> {
        let response = self
            .client
            .request(
                ui_generation,
                Command::GetNativeInputLayout {
                    request_id: request_id.clone(),
                    connection_generation,
                    source,
                },
            )
            .await?;
        if response.snapshot.generation != ui_generation
            || !response
                .snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == nestlink_app_core::NativeSessionStatus::Connected
                        && session.request_id == request_id
                        && session.connection_generation == connection_generation
                })
        {
            return Err(Error::Protocol);
        }
        match response.result {
            Reply::NativeInputLayout { layout } => {
                if layout.as_ref().is_some_and(|layout| {
                    layout.binding.request_id != request_id
                        || layout.binding.connection_generation != connection_generation
                        || layout.binding.source != source
                        || !valid_native_input_layout(layout)
                }) {
                    Err(Error::Protocol)
                } else {
                    Ok(layout)
                }
            }
            _ => Err(Error::Protocol),
        }
    }

    pub async fn send(
        &mut self,
        ui_generation: u64,
        binding: NativeInputBinding,
        action: NativeInputAction,
    ) -> Result<(), Error> {
        let response = self
            .client
            .request(ui_generation, Command::SendNativeInput { binding, action })
            .await?;
        if response.snapshot.generation != ui_generation
            || !matches!(response.result, Reply::NativeInputAccepted)
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }

    pub async fn release(
        &mut self,
        ui_generation: u64,
        binding: NativeInputBinding,
    ) -> Result<(), Error> {
        let response = self
            .client
            .request(ui_generation, Command::ReleaseNativeInput { binding })
            .await?;
        if response.snapshot.generation != ui_generation
            || !matches!(response.result, Reply::NativeInputReleased)
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
}

fn valid_native_input_layout(layout: &NativeInputLayout) -> bool {
    let binding = &layout.binding;
    binding.input_epoch > 0
        && binding.input_epoch <= i64::MAX as u64
        && binding.layout_epoch > 0
        && binding.layout_epoch <= i64::MAX as u64
        && layout.width > 0
        && layout.height > 0
        && layout.width <= 32768
        && layout.height <= 32768
        && i64::from(layout.left) + i64::from(layout.width) <= i64::from(i32::MAX) + 1
        && i64::from(layout.top) + i64::from(layout.height) <= i64::from(i32::MAX) + 1
}

fn rejection(error: SubmitError) -> Reply {
    Reply::Rejected {
        reason: match error {
            SubmitError::Stopped => Rejection::Stopped,
            SubmitError::Capacity => Rejection::Capacity,
            SubmitError::Invalid => Rejection::Invalid,
            SubmitError::StaleGeneration => Rejection::StaleGeneration,
        },
    }
}
fn accept(ticket: Result<Ticket, SubmitError>, tickets: &mut HashMap<u64, Ticket>) -> Reply {
    match ticket {
        Ok(ticket) => {
            let operation = ticket.id();
            tickets.insert(operation.get(), ticket);
            Reply::Accepted { operation }
        }
        Err(error) => rejection(error),
    }
}

fn valid_native_input(action: &NativeInputAction, layout: &NativeInputLayout) -> bool {
    match action {
        NativeInputAction::Key { code, .. } => (4..=0xe7).contains(code),
        NativeInputAction::Pointer { button, down, x, y } => {
            let right = i64::from(layout.left) + i64::from(layout.width);
            let bottom = i64::from(layout.top) + i64::from(layout.height);
            (button.is_some() || !down)
                && button.is_none_or(|button| (1..=5).contains(&button))
                && i64::from(*x) >= i64::from(layout.left)
                && i64::from(*x) < right
                && i64::from(*y) >= i64::from(layout.top)
                && i64::from(*y) < bottom
        }
        NativeInputAction::Scroll { x, y } => {
            layout.scroll_supported && nestlink_protocol::valid_scroll(*x, *y)
        }
        NativeInputAction::Text(text) => {
            !text.is_empty()
                && text.len() <= 1_800
                && !text.chars().any(|character| {
                    character.is_control() && character != '\n' && character != '\t'
                })
        }
    }
}

fn same_input_binding(left: &NativeInputBinding, right: &NativeInputBinding) -> bool {
    left.request_id == right.request_id
        && left.connection_generation == right.connection_generation
        && left.source == right.source
        && left.input_epoch == right.input_epoch
        && left.layout_epoch == right.layout_epoch
}

type InputReleaseScheduler = Arc<dyn Fn(NativeInputBinding) + Send + Sync>;

/// Retains the exact input binding while this local IPC connection owns it.
/// The synchronous Drop hook schedules cleanup if the serve future itself is
/// aborted; the async finish path awaits Core's own bounded send budget.
struct ActiveNativeInput {
    core: CoreHandle,
    binding: Option<NativeInputBinding>,
    schedule_release: InputReleaseScheduler,
}
impl ActiveNativeInput {
    fn new(core: CoreHandle) -> Self {
        let runtime = tokio::runtime::Handle::current();
        let cleanup_core = core.clone();
        let schedule_release: InputReleaseScheduler = Arc::new(move |binding| {
            let core = cleanup_core.clone();
            let runtime = runtime.clone();
            let cleanup = async move {
                let _ = core.release_native_input(&binding).await;
            };
            // A destructor must not unwind if the runtime is already shutting
            // down. In that case daemon shutdown owns terminal lease cleanup.
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.spawn(cleanup)));
        });
        Self::with_scheduler(core, schedule_release)
    }

    fn with_scheduler(core: CoreHandle, schedule_release: InputReleaseScheduler) -> Self {
        Self {
            core,
            binding: None,
            schedule_release,
        }
    }

    fn track(&mut self, binding: NativeInputBinding) {
        self.binding = Some(binding);
    }

    fn clear_if_matches(&mut self, binding: &NativeInputBinding) {
        if self.binding.as_ref() == Some(binding) {
            self.binding = None;
        }
    }

    async fn release(&mut self) {
        let Some(binding) = self.binding.clone() else {
            return;
        };
        if self.core.release_native_input(&binding).await.is_ok() {
            self.clear_if_matches(&binding);
        }
    }
}
impl Drop for ActiveNativeInput {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            (self.schedule_release)(binding);
        }
    }
}

/// The TLS layer already caps connections; this task additionally caps retained
/// replies. A client owns only the tickets it submitted on this connection.
pub async fn serve(
    connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
) -> Result<(), Error> {
    serve_with_files(connection, core, exit, None).await
}

pub async fn serve_with_files(
    connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    files: Option<Arc<dyn files::LocalFileHandler>>,
) -> Result<(), Error> {
    serve_with_handlers(connection, core, exit, files, None, None).await
}

pub async fn serve_with_browser_data(
    connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    files: Option<Arc<dyn files::LocalFileHandler>>,
    browser_data: Option<Arc<dyn browser_data::LocalBrowserHostDataHandler>>,
) -> Result<(), Error> {
    serve_with_handlers(connection, core, exit, files, browser_data, None).await
}

pub async fn serve_with_local_handlers(
    connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    files: Option<Arc<dyn files::LocalFileHandler>>,
    browser_data: Option<Arc<dyn browser_data::LocalBrowserHostDataHandler>>,
    privileged_input: Option<Arc<dyn privileged_input::LocalPrivilegedInputHandler>>,
) -> Result<(), Error> {
    serve_with_handlers(
        connection,
        core,
        exit,
        files,
        browser_data,
        privileged_input,
    )
    .await
}

async fn serve_with_handlers(
    connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    files: Option<Arc<dyn files::LocalFileHandler>>,
    browser_data: Option<Arc<dyn browser_data::LocalBrowserHostDataHandler>>,
    privileged_input: Option<Arc<dyn privileged_input::LocalPrivilegedInputHandler>>,
) -> Result<(), Error> {
    let mut active_input = ActiveNativeInput::new(core.clone());
    let result = serve_requests(
        connection,
        core,
        exit,
        &mut active_input,
        files,
        browser_data,
        privileged_input,
    )
    .await;
    // Core owns the reliable send budget. Do not wrap ReleaseAll in a shorter
    // timeout: cancellation of Core's future aborts its lease as a safety net.
    active_input.release().await;
    result
}

async fn serve_requests(
    mut connection: LocalStream,
    core: CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    active_input: &mut ActiveNativeInput,
    files: Option<Arc<dyn files::LocalFileHandler>>,
    browser_data: Option<Arc<dyn browser_data::LocalBrowserHostDataHandler>>,
    privileged_input: Option<Arc<dyn privileged_input::LocalPrivilegedInputHandler>>,
) -> Result<(), Error> {
    let mut tickets = HashMap::<u64, Ticket>::new();
    let mut expected_sequence = 1_u64;
    loop {
        let request: Request = connection.receive().await?;
        if request.version != nestlink_local_ipc::VERSION
            || request.runtime_id != connection.runtime_id()
            || request.sequence != expected_sequence
        {
            return Err(Error::Protocol);
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or(Error::Protocol)?;
        let snapshot = core.snapshot();
        let generation = snapshot.generation;
        let mut exit_delivery = None;
        let mut video_stream = None;
        let mut compressed_control = None;
        let mut compressed_data = None;
        let mut result = if request.command.mutates() && request.expected_generation != generation {
            Reply::Rejected {
                reason: Rejection::StaleGeneration,
            }
        } else {
            match request.command {
                Command::OpenNativeCompressedVideo { open } => {
                    let binding = NativeVideoBinding {
                        runtime_id: connection.runtime_id().to_owned(),
                        ui_generation: request.expected_generation,
                        request_id: open.request_id,
                        connection_generation: open.connection_generation,
                        source: open.source,
                    };
                    if open.ui_generation != request.expected_generation {
                        Reply::Rejected {
                            reason: Rejection::Invalid,
                        }
                    } else {
                        match compressed_video::open(&core, binding) {
                            Ok((context, _width, _height, ticket, active)) => {
                                compressed_control = Some((context.clone(), ticket, active));
                                Reply::CompressedVideoOpened { context, ticket }
                            }
                            Err(_) => Reply::Rejected {
                                reason: Rejection::Invalid,
                            },
                        }
                    }
                }
                Command::OpenNativeCompressedData { ticket } => {
                    match compressed_video::take_ticket(
                        ticket,
                        connection.runtime_id(),
                        request.expected_generation,
                    ) {
                        Ok(data) => {
                            compressed_data = Some(data);
                            Reply::CompressedDataOpened
                        }
                        Err(_) => Reply::Rejected {
                            reason: Rejection::Invalid,
                        },
                    }
                }
                Command::Snapshot => Reply::Snapshot,
                Command::PrivilegedInput { action } => Reply::PrivilegedInput {
                    generation: request.expected_generation,
                    result: match privileged_input.as_ref() {
                        Some(handler) => {
                            handler
                                .handle(core.clone(), request.expected_generation, action)
                                .await
                        }
                        None => Err(privileged_input::PrivilegedInputError::Unsupported),
                    },
                },
                Command::ConfigureNativeNetwork {
                    expected_revision,
                    settings,
                } => Reply::NativeNetworkConfigured {
                    result: core
                        .configure_native_network(
                            request.expected_generation,
                            expected_revision,
                            settings,
                        )
                        .await,
                },
                Command::NativeDownloadRecovery { action } => {
                    let result = match files.as_ref() {
                        Some(handler) => {
                            handler
                                .recovery(core.clone(), request.expected_generation, action)
                                .await
                        }
                        None => files::DownloadRecoveryReply::Refused {
                            reason: "Local download recovery is unavailable".into(),
                        },
                    };
                    Reply::NativeDownloadRecovery {
                        generation: request.expected_generation,
                        result,
                    }
                }
                Command::NativeFiles { binding, action } => {
                    let result = if let Some(handler) = files.as_ref() {
                        handler
                            .handle(
                                core.clone(),
                                binding.clone(),
                                request.expected_generation,
                                action,
                            )
                            .await
                    } else {
                        files::NativeFileReply::Refused {
                            reason: "Local file services are unavailable".into(),
                        }
                    };
                    Reply::NativeFiles {
                        binding,
                        generation: request.expected_generation,
                        result,
                    }
                }
                Command::BrowserHostData { binding, action } => {
                    let result = if let Some(handler) = browser_data.as_ref() {
                        handler
                            .handle(
                                core.clone(),
                                binding.clone(),
                                request.expected_generation,
                                action,
                            )
                            .await
                    } else {
                        browser_data::BrowserHostDataReply::Refused {
                            reason: "Browser-host data services are unavailable".into(),
                        }
                    };
                    Reply::BrowserHostData {
                        binding,
                        generation: request.expected_generation,
                        result,
                    }
                }
                Command::ApproveBrowserHostDisplays {
                    binding,
                    catalog,
                    sources,
                    initial_source,
                } => Reply::BrowserHostDisplaysApproved {
                    result: core
                        .approve_browser_host_displays(
                            binding,
                            request.expected_generation,
                            catalog,
                            sources,
                            initial_source,
                        )
                        .await,
                },
                Command::GetLocalServiceLeaseObservation {
                    request: observation_request,
                } => match core
                    .local_service_lease_observation(
                        connection.runtime_id().to_owned(),
                        request.expected_generation,
                        observation_request,
                    )
                    .await
                {
                    Ok(observation) => Reply::LocalServiceLeaseObservation { observation },
                    Err(error) => rejection(error),
                },
                Command::PreviewLocalServiceHost {
                    service_id,
                    service_revision,
                    definition_sha256,
                    expected_snapshot_revision,
                    protocol,
                    address,
                    backend_tls,
                } => match core
                    .preview_local_service_host(nestlink_app_core::LocalServiceHostRequest {
                        runtime_id: connection.runtime_id().to_owned(),
                        expected_generation: request.expected_generation,
                        expected_snapshot_revision,
                        service_id,
                        service_revision,
                        definition_sha256,
                        protocol,
                        address,
                        backend_tls,
                    })
                    .await
                {
                    Ok(preview) => Reply::LocalServiceHostPreview { preview },
                    Err(error) => rejection(error),
                },
                Command::StartLocalServiceHost { preview_nonce } => {
                    if tickets.len() >= 16 {
                        Reply::Rejected {
                            reason: Rejection::Capacity,
                        }
                    } else {
                        accept(
                            core.start_local_service_host_for_generation(
                                connection.runtime_id().to_owned(),
                                request.expected_generation,
                                preview_nonce,
                            ),
                            &mut tickets,
                        )
                    }
                }
                Command::StopLocalServiceHost => match core
                    .stop_local_service_host(
                        connection.runtime_id().to_owned(),
                        request.expected_generation,
                    )
                    .await
                {
                    Ok(accepted) => Reply::LocalServiceHostStopped { accepted },
                    Err(error) => rejection(error),
                },
                Command::GetNativeClipboardStatus => clipboard::status(&core),
                Command::SetNativeClipboardDirections {
                    binding,
                    read,
                    write,
                } => clipboard::set_directions(&core, binding, read, write).await,
                Command::RunNativeClipboardAction { binding, action } => {
                    clipboard::action(&core, binding, action).await
                }
                Command::Connect { server } => {
                    if tickets.len() >= 24 {
                        Reply::Rejected {
                            reason: Rejection::Capacity,
                        }
                    } else {
                        accept(
                            core.switch_server_for_generation(request.expected_generation, server),
                            &mut tickets,
                        )
                    }
                }
                Command::Submit { action } => {
                    if tickets.len() >= 16 {
                        Reply::Rejected {
                            reason: Rejection::Capacity,
                        }
                    } else {
                        accept(
                            core.submit_for_generation(request.expected_generation, action),
                            &mut tickets,
                        )
                    }
                }
                Command::GetNativeDisplays { binding } => {
                    let state = core.native_displays(&binding).ok();
                    Reply::NativeDisplays { binding, state }
                }
                Command::ApproveNativeDisplays {
                    binding,
                    catalog,
                    sources,
                    initial_source,
                } => {
                    match core.approve_native_displays(&binding, &catalog, sources, initial_source)
                    {
                        Ok(state) => Reply::NativeDisplays {
                            binding,
                            state: Some(state),
                        },
                        Err(_) => Reply::Rejected {
                            reason: Rejection::Invalid,
                        },
                    }
                }
                Command::SelectNativeDisplay { binding, request } => {
                    match core.select_native_display(&binding, request).await {
                        Ok(state) => Reply::NativeDisplays {
                            binding,
                            state: Some(state),
                        },
                        Err(_) => Reply::Rejected {
                            reason: Rejection::Invalid,
                        },
                    }
                }
                Command::OpenNativeVideo {
                    request_id,
                    connection_generation,
                    source,
                } => {
                    let snapshot = core.snapshot();
                    let session_matches =
                        snapshot
                            .native_session
                            .data
                            .as_ref()
                            .is_some_and(|session| {
                                session.status == nestlink_app_core::NativeSessionStatus::Connected
                                    && session.request_id == request_id
                                    && session.connection_generation == connection_generation
                            });
                    let binding = NativeVideoBinding {
                        runtime_id: connection.runtime_id().to_owned(),
                        ui_generation: request.expected_generation,
                        request_id,
                        connection_generation,
                        source,
                    };
                    if session_matches && video::authorized_layout(&core, &binding).is_ok() {
                        video_stream = Some(binding);
                        Reply::VideoStreamOpened {
                            connection_generation,
                            source,
                        }
                    } else {
                        Reply::Rejected {
                            reason: Rejection::Invalid,
                        }
                    }
                }
                Command::GetNativeInputLayout {
                    request_id,
                    connection_generation,
                    source,
                } => {
                    let layout = core.native_input_layout().ok().flatten().filter(|layout| {
                        layout.binding.request_id == request_id
                            && layout.binding.connection_generation == connection_generation
                            && layout.binding.source == source
                            && snapshot
                                .native_session
                                .data
                                .as_ref()
                                .is_some_and(|session| {
                                    session.status
                                        == nestlink_app_core::NativeSessionStatus::Connected
                                        && session.request_id == request_id
                                        && session.connection_generation == connection_generation
                                })
                    });
                    Reply::NativeInputLayout { layout }
                }
                Command::SendNativeInput { binding, action } => {
                    let session_matches =
                        snapshot
                            .native_session
                            .data
                            .as_ref()
                            .is_some_and(|session| {
                                session.status == nestlink_app_core::NativeSessionStatus::Connected
                                    && session.request_id == binding.request_id
                                    && session.connection_generation
                                        == binding.connection_generation
                            });
                    let layout = core.native_input_layout().ok().flatten();
                    let layout_matches = layout
                        .as_ref()
                        .is_some_and(|layout| same_input_binding(&layout.binding, &binding));
                    if session_matches
                        && layout_matches
                        && layout
                            .as_ref()
                            .is_some_and(|layout| valid_native_input(&action, layout))
                    {
                        // Track before awaiting: even if the send fails or the
                        // client disconnects, the wrapper releases this exact
                        // route before the local connection task exits.
                        active_input.track(binding.clone());
                        match core.send_native_input(&binding, action).await {
                            Ok(()) => Reply::NativeInputAccepted,
                            Err(_) => Reply::Rejected {
                                reason: Rejection::Invalid,
                            },
                        }
                    } else {
                        Reply::Rejected {
                            reason: Rejection::Invalid,
                        }
                    }
                }
                Command::ReleaseNativeInput { binding } => {
                    let session_matches =
                        snapshot
                            .native_session
                            .data
                            .as_ref()
                            .is_some_and(|session| {
                                session.status == nestlink_app_core::NativeSessionStatus::Connected
                                    && session.request_id == binding.request_id
                                    && session.connection_generation
                                        == binding.connection_generation
                            });
                    if session_matches {
                        active_input.track(binding.clone());
                        match core.release_native_input(&binding).await {
                            Ok(()) => {
                                active_input.clear_if_matches(&binding);
                                Reply::NativeInputReleased
                            }
                            Err(_) => Reply::Rejected {
                                reason: Rejection::Invalid,
                            },
                        }
                    } else {
                        Reply::Rejected {
                            reason: Rejection::Invalid,
                        }
                    }
                }
                Command::Logout => {
                    if tickets.len() >= 24 {
                        Reply::Rejected {
                            reason: Rejection::Capacity,
                        }
                    } else {
                        accept(
                            core.logout_for_generation(request.expected_generation),
                            &mut tickets,
                        )
                    }
                }
                Command::Cancel { operation } => {
                    if !tickets.contains_key(&operation.get()) {
                        Reply::Rejected {
                            reason: Rejection::UnknownOperation,
                        }
                    } else {
                        match core.cancel_for_generation(request.expected_generation, operation) {
                            Ok(ticket) => match ticket.wait_for_generation().await {
                                Ok(Ok(accepted)) => Reply::Cancelled { accepted },
                                Ok(Err(error)) => rejection(error),
                                Err(_) => rejection(SubmitError::Stopped),
                            },
                            Err(error) => rejection(error),
                        }
                    }
                }
                Command::Completion { operation } => match tickets.get_mut(&operation.get()) {
                    None => Reply::Rejected {
                        reason: Rejection::UnknownOperation,
                    },
                    Some(ticket) => match ticket.try_complete() {
                        Ok(None) => Reply::Pending { operation },
                        Err(_) => {
                            tickets.remove(&operation.get());
                            Reply::Rejected {
                                reason: Rejection::Stopped,
                            }
                        }
                        Ok(Some(mut completion)) => {
                            tickets.remove(&operation.get());
                            let sensitive = completion
                                .take_sensitive()
                                .map(|material| match material {});
                            Reply::Completed {
                                operation: completion.result,
                                sensitive,
                            }
                        }
                    },
                },
                Command::Exit => {
                    let (reply, waiting) = oneshot::channel();
                    let (delivered, delivery) = oneshot::channel();
                    match exit.try_send(ExitRequest {
                        reply,
                        delivered: delivery,
                    }) {
                        Ok(()) => {
                            exit_delivery = Some(delivered);
                            Reply::Exited {
                                result: waiting.await.unwrap_or(ExitResult::Failed),
                            }
                        }
                        Err(_) => Reply::Rejected {
                            reason: Rejection::Capacity,
                        },
                    }
                }
            }
        };
        let snapshot = core.snapshot();
        if let Reply::Completed {
            operation,
            sensitive,
        } = &mut result
            && operation.generation != snapshot.generation
        {
            sensitive.take();
        }
        let response = Response {
            version: nestlink_local_ipc::VERSION,
            runtime_id: connection.runtime_id().to_owned(),
            sequence: request.sequence,
            snapshot,
            result,
        };
        let sent = connection.send(&response).await;
        if let Some(delivered) = exit_delivery {
            let _ = delivered.send(());
        }
        sent?;
        if let Some((context, ticket, active)) = compressed_control {
            return compressed_video::serve_control(connection, core, context, ticket, active)
                .await;
        }
        if let Some((context, active)) = compressed_data {
            return compressed_video::serve_data(connection, core, context, active).await;
        }
        if let Some(binding) = video_stream {
            return video::serve_video_stream(connection, core, binding).await;
        }
    }
}

#[cfg(test)]
mod input_cleanup_tests {
    use super::*;
    use nestlink_app_core::{AppCore, Limits, ShutdownState};
    use std::time::Duration;

    #[tokio::test]
    async fn aborting_serve_owner_schedules_release_of_its_exact_binding()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut app = AppCore::start(Limits::default())?;
        let handle = app.handle();
        let binding = NativeInputBinding {
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            connection_generation: 2,
            source: 0,
            input_epoch: 3,
            layout_epoch: 4,
        };
        let (scheduled, mut releases) = mpsc::unbounded_channel();
        let schedule: InputReleaseScheduler = Arc::new(move |binding| {
            let _ = scheduled.send(binding);
        });
        let owned_binding = binding.clone();
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut owner = ActiveNativeInput::with_scheduler(handle, schedule);
            owner.track(owned_binding);
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });

        started.await?;
        task.abort();
        let task_result = task.await;
        assert!(task_result.is_err_and(|error| error.is_cancelled()));
        let released = tokio::time::timeout(Duration::from_secs(1), releases.recv())
            .await
            .map_err(|_| "drop cleanup was not scheduled")?
            .ok_or("drop cleanup sender closed")?;
        assert_eq!(released, binding);
        assert_eq!(
            app.shutdown(Duration::from_secs(2)).await,
            ShutdownState::Complete
        );
        Ok(())
    }
}
